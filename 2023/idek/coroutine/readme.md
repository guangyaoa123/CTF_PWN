# PWN/Coroutine

## Description

C++20 introduced coroutines, can they be used safely?
`nc coroutine.chal.idek.team 1337`


## Coroutine
This challenge is on C++ coroutines that are introduced in C++ 20. I suggest to read up on the [documentation](https://en.cppreference.com/w/cpp/language/coroutines) and get familiarize with coroutines before reading further.

In any case, here are the important points:
1. Coroutines are function that can be suspended and resume later.
2. Coroutines are stackless, obviously? cause the stack frame will be erase by other functions.
3. Information about the state of the coroutine is stored in a coroutine handler. I.E. local variables, parameters. Heap allocated local variables wtf -.-.
4. Coroutines are functions that contains the co_await, co_yield and co_return expression or implements `co_await` operator.
5. If we look at the disassembly of the compiled binary, any coroutine will have 3 functions under the same function symbol, which I am guessing is for `await_ready`, `await_resume` and `await_suspend` respectively.
6. Coroutines differ from threads: a program with coroutines execute sequentially and support multiple concurrent functions (by suspending and resuming coroutine functions), while a program spawning threads executes multiple parallel threads. In other words, a program with coroutines schedule its own execution of coroutines.

## Code analysis
Thankfully, source code is given. I will cover only the important functions, so lets drive right into it.

The main function is responsible for setting up everything. It first creates the `io_context` struct on the stack then pass the `io_context` to `server` function.

# io_context
In the `io_context` struct, there are 2 `vectors` (`reads_` and `writes_`) which holds our suspended coroutines. In the `run_until_done` function, it calls `load_flag`, then loops through `reads_` and `writes_` that are ready for IO and resume each coroutine.
It also contains some helper functions such as `add_write`, `add_read` and `cancel` to help modify the `reads_` and `writes_` coroutine vector. `io_context` is the 'scheduler' for the program.

# client_loop
In the `server` function, it initialize the sockets for the connection and listens for connections. It then calls `client_loop`, which is the main part of this challenge. 


Here we can see that it calls `RecvAsync` to receive input from us then calls `SendAllAsyncNewline` to echo it back to us. Hmmmm, why is the way receive and send being called differently? 


Lets take a look at the `RecvAsync` class first. The constructor of `RecvAsync` declared a co_await operator, which will make it a coroutine. Here we see 3 functions (`await_ready`, `await_suspend`, `await_resume`). `await_ready` is the first function to be called when co_await `RecvAsync` is called. If `await_ready` returns false, it will call `await_suspend`, else it will call `await_resume`. `await_resume` is also called when the coroutine is resumed externally by `io_context` for example. 

`await_ready` tries to recv from the socket, if successful, it will return true, else (no data have been entered through the proxy) it returns false and calls `await_suspend` which will store the coroutine handler to `io_context` (which then resumes the coroutine via `run_until_done`). In the challenge, `await_suspend` will always be called since it is very likely for the `recv` at `await_ready` to fail (it is unlikely for proxy.py to win the race since we are from a remote connection).

However, the same cannot be said for `SendAsync`. `SendAsync` has roughly the same code as `RecvAsync`, just switching `recv` to `send`. `await_suspend` in `SendAsync` is unlikely to be called since `send` is likely to be successful, unless ....., `proxy.py''s receive buffer is full, which we have control over.

Note that `SendAsync` is being called differently from `client_loop`. It first calls `SendAllAsyncNewline` which does not seems like a coroutine (see point 4 above), but it calls `SendAllAsync` which is a coroutine. It also allocates a `buffer2` which is on the stack, copy the content from `RecvAsync` to `buffer2`, and pass `buffer2` to `SendAllAsync` then to `SendAsync`.

What this means is that, `SendAsync` sends data from the stack and `RecvAsync` recv data to the heap (which is then copy to the stack in `SendAllAsyncNewLine`. Lets verify this is a debugger. 


On top of this, since `SendAllAsync` is called not as a coroutine in `SendAllAsyncNewline`, `SendAllAsyncNewline` ends up calling the `await_ready` function of `SendAllAsync`. This means `SendAllAsyncNewLine` could return to `client_loop` before the `send` was completed, through suspending `SendAsync`. This allows the next `RecvAsync` to be processed before the previous `send` finishes, and multiple send could be on hold at the same time if the `proxy.py` receive buffer is full. 

Now it become obvious, since data is sent from the stack, which is always at the same address, there is a possibility of data overwriting. We can make use of `RecvAsync` to set the buffer size of the current `SendAsync` (by sending a N length string from `proxy.py`), and make `SendAsync` suspend so we can call `RecvAsync` again. We repeat this again, to queue at least 2 `SendAsync` into the `writes_` vector in the `io_context`, there after we drain the `writes_` vector twice (by receiving data from `proxy.py`, thereby making send free again), the first time to print garbage since `RecvAsync` would have cleared the flag in the stack, the second time to call `load_flag` and print out the flag.

## Exploit Script

```
from pwn import *
import time
#context.log_level = 'debug'
p = remote("coroutine.chal.idek.team", 1337)

def conn():
    p.recvuntil(b"> ")
    p.sendline(b"1")

def set_rcv(size):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.recvuntil(b"> ")
    p.sendline(str(size).encode('utf-8'))

def send_str(string):
    p.recvuntil(b"> ")
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(string)

def recv(size):
    #p.recvuntil(b"> ")
    p.sendline(b"5")
    #p.recvuntil(b"> ")
    p.sendline(str(size).encode('utf-8'))

set_rcv(8)
conn()

for i in range(8):
    send_str(b"A" * 512)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
p.interactive()

```