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
//root pointer
static void *root;
//pointer to last pointer in list
static void *lastFree;

struct free_node
{
    void *next_addr;
    void *prev_addr;
    uint64_t size;  
    bool valid;
};

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}
//passes a boundary tag and returns the size i.e removes masked bit 
static uint64_t tag_to_size(uint64_t bound_tag){     
    return bound_tag & -2;
}
//
static bool is_allocated(uint64_t bound_tag){
    return bound_tag & 1;
}

static void add_node(void *ptr, void *next, void *prev, uint64_t size){
    mem_write(ptr, (uint64_t)next, WORD_SIZE);
    mem_write(ptr + WORD_SIZE, (uint64_t)prev, WORD_SIZE);
    mem_write(ptr - WORD_SIZE, size, WORD_SIZE);
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

    //initialize first node

    //initialize root
    root = mem_heap_lo();
    void *first_node = root + 2*WORD_SIZE;
    mem_write(root, (uint64_t)first_node, WORD_SIZE);
    //initialize first node
    add_node(first_node, NULL, root, WORD_SIZE * 2);

    printf("\nuse me to stop exec\n");//FIXME
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    /* IMPLEMENT THIS */

    return NULL;
}

/*
 * free
 */
void free(void* ptr)
{
    // void* tmp = mem_read(ptr,sizeof(void*));
    
    // mem_write(ptr,tmp,wordSize);
    
       

    void* tmp = mem_read(ptr,sizeof(void*));
    root=ptr;
    mem_write(ptr,tmp,WORD_SIZE);
    //next=tmp
    mem_write(ptr,tmp,NULL);
      
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
