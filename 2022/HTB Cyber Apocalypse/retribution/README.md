## Space Pirate Retribution

Checksec Output:
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
	
Running the binary present us with 2 options.
1. Show Missile (show_missile())
2. Change target's location (missile_launcher())

The `show_missile()` function only prints information and is not very interesting.
The `missile_launcher()` function is 