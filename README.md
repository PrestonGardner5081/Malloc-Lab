# Project 2: Malloclab

### Group Members
- Esha Tayade, ezt5175
- Preston Gardner, ptg5081

### Introduction

In this project we write a C code for memory allocators, we implement malloc, free and then realloc. We achieved this by keeping a track of the free nodes explicitly. When we allocate memory or take pieces of blocks we already allocated, there may be blocks we don't automatically use. For this reason, we keep track of the free nodes.

### Data Structures

This list of free nodes is a doubly linked list and each free node that we kept track of had its own metadata, which consistes of two boundary tags on each side that stores the size of the node that is being freed, and addresses of the next & previous free nodes. This metadata is written only in the physical memory space and stored in C a data structure 

### Design

For the purpose of reusability and ease of access while debugging, we define multiple helper functions like alloc(), getnode(), tag_to_size(). We call these functions multiple times throughout our code, for example the most useful helper functions is getnode()- accepts the pointer pointing to the current node and returns the size, next address, previous address and if the node was free or allocated.


Malloc()-  This function allocates unused space for objects whose size in bytes is passed but the actual data is unknown. We find the needed space by traversing through the list and find a space that can fit the data of specified bytes. A helper function alloc() is called in malloc() which  walks through a variety of conditions to keep the free list intact also helps change the free block state by updating its metadata.

Free()-  function in our project deallocates a block of memory previously allocated using calloc, malloc or realloc functions, making it available for further allocations. This function starts off by checking the validity of the pointer that is passed and if it exists inside the heap, if those conditions satisfy, we proceed to run the four cases which would help determine the way splice and coalesce would work on the freed blocks. The four cases are as follows-
Inserting a new node at the beginning of the list
Inserting a new node when the previous node is a free node 
When the next node is a free node
When the node that needs to be added is surrounded by free nodes on both side

Realloc() – this function changes the size of the allocated memory, it covers both increase and decrease in size of the allocated memory. 

Checkheap()- In this heaper checker we traverse through the list to get all the accessible nodes and then we traverse through the entire heap looking for blocks ( allocated or free) and for each block found we check if the valid bits match the status of the node. For every free node we check if the pointers pointing to the previous and next nodes are also free. If the node is free check if it exists in the heap and if we have the data to access/ modify it.

### Issues that we faced 
Even after passing the first checkpoint our code went through major changes as we tried to go through all the tracefiles. The biggest curve we faced was trying to understand the multiple cases in coalescing. Even with the heap checker the extensive trace cases made is cumbersome to point exactly where the program had a segmentation fault before we considered these edge cases. 








