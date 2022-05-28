## Space Pirate Retribution

Checksec Output:

![image](https://user-images.githubusercontent.com/24536991/170826930-e3da879c-dbbe-41e6-8939-c46cd93de803.png)
	
This challenge is a fairly simple buffer overflow challenge.

Running the binary present us with 2 options.
1. Show Missile (`show_missile()`)
2. Change target's location (`missile_launcher()`)

The `show_missile()` function only prints information and is not very interesting.
The `missile_launcher()` function contains a buffer overflow vulnerability on line 24.

![image](https://user-images.githubusercontent.com/24536991/170827036-bf38b422-eefa-4f8c-8753-5e76e5328816.png)

However, Full RELRO is enabled and we need to leak some address so that we can construct a ROP chain. We can see that line 21 and 22 reads our input and echoes back to us. Since `read()` does not add a NULL byte at the end of the user input, we can leak some values off the stack. To do this, we set a breakpoint right before the `read()` at line 21 executes and examine the stack.

![image](https://user-images.githubusercontent.com/24536991/170827469-b9e79924-4885-4235-b7bf-4e8d6e84cbbe.png)

We can see that the 0x20 bytes buffer `local_38` is actually filled with the binary RIP addresses. We can leak one of this address and calculate the binary base address. Thus, the exploit can be done in 3 steps:

1. Leak the binary base
2. Construct an ROP chain to print a libc address off the GOT table and calculate the libc base. This is just a POP RDI gadget -> printf gadget
3. After leaking the libc address, we can return the execution flow back to `missile_launcher()` to overwrite the return address to our one_gadget in libc.

The first ROP chain is POP_RDI -> printf -> `missile_launcher()`. The printf gadget can be found at the end of the `show_missile()` function since this function only calls `printf` and `puts`. Here we will leak the libc address by setting RDI to point to one of the GOT table entries, calculate the libc base and return control to `missile_launcher()` so we can control execution once again. 

Fortunately, one of the one_gadget only requires RAX to be NULL. Once the 2nd `missile_launcher()` is called, we craft the second ROP chain to be XOR RAX RAX -> one_gadget to pop our shell. There isn't any POP RAX or XOR RAX RAX in the binary itself, but there is plenty in the libc library.
