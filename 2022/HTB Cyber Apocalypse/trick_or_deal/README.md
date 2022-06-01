
## Trick or Deal

Checksec:

![image](https://user-images.githubusercontent.com/24536991/171424466-954f0b78-5017-46d6-a73d-b3bced229ebb.png)

This challenge has a classic use-after-free (UAF) vulnerability. We first take a look at the `main` function.

![image](https://user-images.githubusercontent.com/24536991/171424905-7f38a169-9fa0-4cfd-9394-e07c081958f3.png)

There are 2 important functions here: `update_weapons()` and `menu()`.

![image](https://user-images.githubusercontent.com/24536991/171425219-b32ce366-9f27-41c0-958d-d823a45a5210.png)

`update_weapon()` calls `malloc()` and stores the pointer in `storage`. It also writes to the chunk some string and the address of `printStorage()` at the end of the chunk (which is later called in `menu()`). `printStorage()` prints a string from the `storage` variable.

![image](https://user-images.githubusercontent.com/24536991/171425935-5dffb601-b0a5-4f2e-8f35-189b6ec387ff.png)

There are 4 options in the `menu()` function:
1. Calls the `printStorage()` function that is stored in `storage`.  This is our 'use' function.
2. Calls `buy()`. There isn't any vulnerability here.
3. Calls `make_offer()`. Basically `malloc()` a user specified size chunk and write to the chunk.
4. Calls `steal()`. Free `storage`. This is our 'free' function.

There isn't any code to set 'storage' to null and we can continue to use `storage` after we free it. This is where UAF comes in.

Before we can exploit the vulnerability, we need to leak the base address of the binary. We can do this by trying to free `storage` and allocating the chunk again. Then we write a string long enough to the newly allocated chunk so that there isn't any null byte between the function pointer and the string at the `storage` chunk. We then call `printStorage()` to leak the content of `storage` which includes the address of `printStorage()`.

The UAF vulnerability here can be exploited as follows:
1. Call `steal()` to free `storage`.
2. `make_offer()` to allocate the chunk just freed and write a string long enough to the newly allocated chunk so that there isn't any null byte between the `printStorage()` pointer and the string at the `storage` chunk.
3. Call the `printStorage()` function that is stored in `storage` to leak the contents of `storage` which include the address of `printStorage()`. 
4. Call `steal()` to free `storage` again.
5. `make_offer()` to allocate the chunk just freed and overwrite the function pointer at the end of the `storage` chunk. The challenge provides us with the win function: `unlock_storage()` which we can use.
6. Call the now overwritten `printStorage` function that is stored in `storage` to pop a shell.

