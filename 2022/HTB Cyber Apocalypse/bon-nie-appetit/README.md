
## Bon-nie-appetit
Checksec:

![image](https://user-images.githubusercontent.com/24536991/170828622-f9ffaeb2-c6a7-4ccb-a24f-17cc50911e0c.png)

There are 5 choices available in the challenge.

![image](https://user-images.githubusercontent.com/24536991/170828651-ce3bec8a-b947-4081-81eb-6fc562da4eff.png)

Each order is actually stored in the heap, in a malloced chunk, and the pointer to the chunk is stored in a local array in the `main()` stack frame.
We first look through each function of the binary,

![image](https://user-images.githubusercontent.com/24536991/170829159-7770c928-6c5d-4dfd-97ae-4b840e7c63e5.png)

### Leak 
The `new_order()` function `malloc()` a chunk with a user-controlled size and writes user input of specified size into the malloced chunk. This means that if the size of the user data in the chunk is 24 bytes long, and we write 24 bytes of characters, the resulting data will not have a null byte at the end. 

This means that we can leak the `SIZE` of the next chunk via `show_order()`.

### Vulnerability

![image](https://user-images.githubusercontent.com/24536991/170829119-56400929-e779-4642-8037-28598dfa0842.png)

The `edit_order()` function looks very suspicious. It actually uses `strlen()` to determine the number of bytes to read from the user and write into the chunk. This means that the length calculated in `new_order()` is not the same as in `edit_order()`. In fact, since there is no NULL byte added in when the order is created, the result from `strlen()` could be larger than the actual size of the user data in the chunk which could allow us to modify the size of the next chunk. This allows us to resize the next chunk to make it larger, free it which results in overlapping chunks. Since tcache is enabled, the freed chunk will end up in the tcache bin. We can craft out the following chunk in the heap by calling `new_order()`.

|offset | CHUNK   | chunk size |

|0x00  | chunk A |   0x20 |

|0x20  | chunk B |   0x20 |

|0x40  | chunk C |   0x20 |


We use chunk A to overwrite the `SIZE` of chunk B to a larger value, for instance 0x80. 


offset| CHUNK   | chunk size

0x00  | chunk A |   0x20

0x20  | chunk B |   **0x80**

0x40  | chunk C |   0x20

Do the following steps:

1. Free chunk C. 
2. If we free chunk B and allocate it again, we can see that chunk B overlaps with chunk C.

Now we can write legitimately write into the FD and BK pointers of chunk C. This is basically a tcache poisoning attack. Note that this not only allows us to overwrite onto the next chunk, it also allows us to leak the FD and BK pointers by exploiting the same leak vulnerability as discussed above. We can temporary overwrite the SIZE field so that our input string reaches the FD pointer when we call `new_order()`. Then we use `show_order()` to leak the FD pointer.

However, we still need to leak a libc address to complete our exploit. This can be done by putting a chunk onto the unsorted bin. The top most chunk of the unsorted bin will contain a pointer to the `main_arena` in the `FD` pointer. We can create 8 chunk of a fixed size, say 0x100, and free all 8 of them. 7 of the chunk will fill the tcache bin and the last chunk will end up in the unsorted bin.  


To sum up, the exploit can be done with the following steps:
1. Create 7 chunks of size 0x100. This 7 chunks will fill the tcache bin.
2. Create 2 chunks of size 0x20. The first chunk (A) will be used to increase the size of the second chunk (B). 
3. Create 2 more chunks of size 0x100. The first chunk (C) will end up in unsorted bin. The second chunk (D) prevents the consolidation of chunk C with the remaining unallocated chunk.
4. Free the chunks created in step 1. Now the tcache bin for size 0x100 is filled.
5. Edit chunk A created in step 2 to increase the size of chunk B.
6. Free chunk B and chunk C. 

Heap layout now

offset| CHUNK               | chunk size

0x00  | chunk A (allocated) |   0x20

0x20  | chunk B (Free)      |   **0x80** (modified size)

0x40  | chunk C (Free)      |   0x100

7. Now chunk C is in the unsorted bin. Create a chunk of 0x80 size. Chunk B will be used to service the request. Now you can leak the libc address off chunk C's FD pointer via Chunk B. Here we can calculate the address of `malloc_hook` and our one_gadget.
8. Restore Chunk C size by editing chunk B.
9. Set up the layout again, this time with chunk C in the tcache bin. Ensure that chunk C is the last chunk in the tcache bin and the tcache bin have at least 2 chunks.
10. Allocate and use Chunk B to modify the FD pointer of chunk C to address of `malloc_hook`.
11. Call malloc twice to malloc a chunk at `malloc_hook`.
12. Write address of one_gadget to allocated chunk.
13. Call malloc to pop shell.
