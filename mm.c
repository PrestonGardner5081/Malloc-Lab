/*
 * mm.c
 *
 * Name: [FILL IN]
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read malloclab.pdf carefully and in its entirety before beginning.
 *
 */
//  test puush 
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
//#define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16
// Overhead for allocated space
#define ALLOC_BOUDARY_SIZE 16
//word size
#define WORD_SIZE sizeof(void*)
//address in root
static void *root;
//root pointer
static void *root_addr;
//pointer to last pointer in list
static void *lastFree;

struct free_node
{
    void *next_addr;
    void *prev_addr;
    uint64_t size;  
    bool valid;
};

typedef struct free_node free_node; 

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

static uint64_t tag_to_size(uint64_t bound_tag){
    return bound_tag & -2;
}

static bool is_allocated(uint64_t bound_tag){
    return bound_tag & 1;
}

static free_node get_node(void *ptr){
    free_node node;
    uint64_t lower_tag = mem_read(ptr - WORD_SIZE, WORD_SIZE);
    node.size = tag_to_size(lower_tag);
    uint64_t upper_tag = mem_read(ptr + node.size, WORD_SIZE);
    //valid tells us if the node is a valid free node otherwise known as unallocated
    node.valid = !is_allocated(lower_tag) && !is_allocated(upper_tag);
    node.next_addr = (void *)mem_read(ptr, WORD_SIZE);
    node.prev_addr = (void *)mem_read(ptr + WORD_SIZE, WORD_SIZE);

    return node; 
}

static void *find_space(uint64_t size){
    void *ptr = root;
    uint64_t cur_size = 0;

    while(ptr != (void *)0){
        free_node cur_node = get_node(ptr); 

        if(cur_node.size >= size){
            break;
        }

        ptr = cur_node.next_addr;
    }

    return ptr; 
}

static void add_node(void *ptr, uint64_t size){
    void *next = root;
    root = ptr;
    //update actual root 
    mem_write(root_addr, (uint64_t)root, WORD_SIZE);
    //next node prev_addr = current node
    mem_write(next + WORD_SIZE, (uint64_t)ptr, WORD_SIZE);
    //current node next_addr = next node
    mem_write(ptr, (uint64_t)next, WORD_SIZE);
    //current node prev_addr = null
    mem_write(ptr + WORD_SIZE, 0, WORD_SIZE);
    //set size for lower tag
    mem_write(ptr - WORD_SIZE, size, WORD_SIZE);
    //set size for upper size
    mem_write(ptr + size, size, WORD_SIZE);
}

/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    /* IMPLEMENT THIS */

    // adds enough space for root and one free block of size 2 * word size
    mem_sbrk(WORD_SIZE * 5);

    //initialize root
    root_addr = mem_heap_lo();
    uint64_t size = 2 * WORD_SIZE;
    void *first_node = root_addr + size;
    root = first_node;
    mem_write(root_addr, (uint64_t)root, WORD_SIZE);
    //initialize first node
    mem_write(first_node, 0, WORD_SIZE);
    mem_write(first_node + WORD_SIZE, 0, WORD_SIZE);
    mem_write(first_node - WORD_SIZE, size, WORD_SIZE);
    mem_write(first_node + size, size, WORD_SIZE);

    //FIXME
    mem_sbrk(4 * WORD_SIZE);
    add_node(root_addr + 6*WORD_SIZE, 2*WORD_SIZE);
    
    free_node fNode = get_node(root_addr + 2 * WORD_SIZE);
    printf("size %ld\n", fNode.size);
    printf("prev %p\n", fNode.prev_addr);
    printf("next %p\n", fNode.next_addr);
    printf("valid %d\n\n", fNode.valid);
    free_node nNode = get_node(root);
    printf("size %ld\n", nNode.size);
    printf("prev %p\n", nNode.prev_addr);
    printf("next %p\n", nNode.next_addr);
    printf("valid %d\n", nNode.valid);

    printf("ptr to free space %p\n", find_space(32));
    printf("\nuse me to stop exec\n");
    //FIXME
    
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    /* IMPLEMENT THIS */
    uint64_t corrected_size = (uint64_t)align(size); 

    //FIXME
    printf("corrected_size: %ld", corrected_size);
    //FIXME

    return NULL;
}

/*
 * free
 */
void free(void* ptr)
{
    // void* tmp = mem_read(ptr,sizeof(void*));
    
    // mem_write(ptr,tmp,wordSize);
    
    /* IMPLEMENT THIS */
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    /* IMPLEMENT THIS */
    return NULL;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
    /* Write code to check heap invariants here */
    /* IMPLEMENT THIS */
#endif /* DEBUG */
    return true;
}
