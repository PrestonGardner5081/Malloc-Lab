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
#define WORD_SIZE sizeof(void *)
//root pointer
static void *root;
//root pointer
static void *root_addr;
//pointer to last pointer in list
static void *lastFree;
//May have to manually keep track of last byte

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
    return ALIGNMENT * ((x + ALIGNMENT - 1) / ALIGNMENT);
}
//passes a boundary tag and returns the size i.e removes masked bit
static uint64_t tag_to_size(uint64_t bound_tag)
{
    return bound_tag & -2;
}
//passes a boundary tag and returns the TRUE if it is allocated and FALSE if its free
static bool is_allocated(uint64_t bound_tag)
{
    return bound_tag & 1;
}
//adds a new node also gives us the address of the next node
static void add_node(void *ptr, uint64_t size)
{
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
//Returns size, next, prev and valid
static free_node get_node(void *ptr)
{
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
static void *add_space(uint64_t size){
    void *ptr;
    void *prg_break = mem_heap_hi() + 1;
    uint64_t last_tag = mem_read(prg_break - WORD_SIZE, WORD_SIZE);

    // printf("WORD_SIZE: %ld\n", WORD_SIZE);

    if(is_allocated(last_tag)){
        ptr = prg_break + WORD_SIZE;
        mem_sbrk(size + 2 * WORD_SIZE);
        add_node(ptr, size);
    }
    else{
        uint64_t last_size = tag_to_size(last_tag);
        ptr = prg_break - last_size - WORD_SIZE;
        mem_sbrk(size-last_size);
        //update lower size tag
        mem_write(ptr-WORD_SIZE, size, WORD_SIZE);
        //update upper size tag
        mem_write(prg_break-WORD_SIZE, size, WORD_SIZE);
    }

    return ptr;
}

static void set_next(void *ptr, void *next){
    mem_write(ptr, (uint64_t)next, WORD_SIZE);
}

static void set_prev(void *ptr, void *prev){
    mem_write(ptr + WORD_SIZE, (uint64_t)prev, WORD_SIZE);
}

static void splice(void *ptr){
    free_node node = get_node(ptr);
    set_next(node.prev_addr, node.next_addr);
    set_prev(node.next_addr, node.prev_addr);
    
}

static void set_bound_tags(void *ptr, uint64_t size, bool free){
    uint64_t tag = size;
    if(!free){
        tag = size | 1; 
    }
    mem_write(ptr - WORD_SIZE, tag, WORD_SIZE);
    mem_write(ptr + size, tag, WORD_SIZE);
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


static void add_space_root(){
    void *new_node = mem_heap_hi() + 1 + WORD_SIZE;
    mem_sbrk(4*WORD_SIZE);
    set_next(new_node, NULL);
    set_prev(new_node, NULL);
    set_bound_tags(new_node, 2*WORD_SIZE, true);
    root = new_node;
    mem_write(root_addr, (uint64_t)root, WORD_SIZE);
    // FIXME
    // free_node test_f = get_node(new_node);     
    // printf("\nuse me to stop exec\n");
    // FIXME
}

static void alloc(void *space, uint64_t size){
    free_node free_space = get_node(space);
    uint64_t new_node_size = free_space.size - size - WORD_SIZE; 

    if(free_space.size == size || new_node_size < 2*WORD_SIZE){
        if(free_space.prev_addr == NULL){
            add_space_root();
        }
        else if(free_space.next_addr != NULL){
            splice(space);
        }
        else{
            set_next(free_space.prev_addr, NULL);
        }
        set_bound_tags(space, size, false);

        // FIXME
        // free_node test_a = get_node(space);     
        // printf("\nuse me to stop exec\n");
        // FIXME
    }
    else{
        void *new_free = space + size + 2 * WORD_SIZE;
        set_next(new_free, free_space.next_addr);
        set_prev(new_free, free_space.prev_addr);
        set_bound_tags(space, size, false);
        set_bound_tags(new_free, new_node_size, true);

        //FIXME
        // free_node test_new = get_node(new_free);
        // free_node test_a = get_node(space);
        // printf("\nuse me to stop exec\n");
        //FIXME
    }
}

static void print_node_list(){
    void *ptr = root;
    uint64_t cur_size = 0;

    while(ptr != (void *)0){
        free_node cur_node = get_node(ptr); 

        printf("node: %p\n\n", ptr);
        printf("size %ld\n", cur_node.size);
        printf("prev %p\n", cur_node.prev_addr);
        printf("next %p\n", cur_node.next_addr);
        printf("valid %d\n", cur_node.valid);

        ptr = cur_node.next_addr;
    }
}
void coalesce(void *ptr)
{

    free_node curr = get_node(ptr);
    void *nextptr = (ptr + curr.size + 2 * WORD_SIZE);
    void *prevptr = (ptr - (curr.size + 2 * WORD_SIZE));
    // printf("next ptr %p\n",nextptr);
    // printf("prev ptr %p\n",prevptr);
    while (curr.next_addr == NULL)
    {
        if (get_node(ptr).valid && get_node(nextptr).valid)
        {
            curr.size += (get_node(nextptr).size + 2 * WORD_SIZE);
        }
        if (get_node(ptr).valid && get_node(prevptr).valid)
        { //IF THINGS GO WRONG FIX THIS BY remvoving//get_node(ptr).valid
            curr.size += (get_node(prevptr).size + 2 * WORD_SIZE);
        }
        if (get_node(ptr).valid && get_node(nextptr).valid && get_node(prevptr).valid)
        {
            curr.size += (get_node(nextptr).size + get_node(prevptr).size + 2 * WORD_SIZE);
        }

        //set_next(ptr, curr.next_addr);
    }
}

/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    /* IMPLEMENT THIS */
    // adds enough space for root and one free block of size 2 * word size
    mem_sbrk(WORD_SIZE);

    //initialize root
    root_addr = mem_heap_lo();
    //initialize first node
    add_space_root();

    //FIXME

    // mm_malloc(32);
    // //add_space(32);
    // mm_malloc(64);
    // //add_space(64);
    // mm_malloc(128);

    // printf("\nuse me to stop exec\n");
    //FIXME
    
    return true;
}

/*
 * malloc
 */
void *malloc(size_t size)
{
    /* IMPLEMENT THIS */
    if(size == 0){
        return NULL; 
    }
    uint64_t corrected_size = (uint64_t)align(size); 
    void *space = find_space(corrected_size);
    if(space == NULL){
        space = add_space(corrected_size);
    }

    alloc(space, corrected_size);

    //FIXME
    // printf("ptr to free space %p\n", space);
    // printf("corrected_size: %ld", corrected_size);
    //print_node_list();
    //printf("\nuse me to stop exec\n");
    //FIXME

    return space;
}

/*
 * free
 */
void free(void *ptr)
{
    if(ptr==NULL){return;}
    free_node fnode = get_node(ptr);
    //free_node node_n = get_node(fnode.next_addr);
    //free_node node_p = get_node(fnode.prev_addr);
    bool next_free;
    //check if next block is prg break
    if((ptr + fnode.size + WORD_SIZE + WORD_SIZE) < mem_heap_hi()){
        next_free = is_allocated(mem_read(ptr + fnode.size + WORD_SIZE, WORD_SIZE));

    }
    else
        next_free = false;

    //check if prev block is root
    bool prev_free;
    if(ptr - 2 * WORD_SIZE == root_addr)
        prev_free = is_allocated(mem_read(ptr - 2 * WORD_SIZE, WORD_SIZE));
    else
        prev_free = false;

    //case 1
    if (fnode.valid)
    {
        return;
    }
    //case 4
    else if (!next_free && !prev_free)
    {
        add_node(ptr, fnode.size);
        splice(ptr + fnode.size + 2 * WORD_SIZE);
        splice(ptr - (fnode.size + 2 * WORD_SIZE));
        coalesce(ptr);
    }
    //case 2
    else if (!next_free)
    {
        add_node(ptr, fnode.size);
        splice(ptr + fnode.size + 2 * WORD_SIZE);
        coalesce(ptr);
    }
    //case 3
    else if (!prev_free)
    {
        add_node(ptr, fnode.size);
        splice(ptr - (fnode.size + 2 * WORD_SIZE));
        coalesce(ptr);
    } 
    
}

/*
 * realloc
 */
void *realloc(void *oldptr, size_t size)
{
    uint64_t corrected_size = (uint64_t)align(size);
    free_node node=get_node(oldptr);
    if(node.size==corrected_size){return oldptr;}
    if(oldptr==NULL){return malloc(corrected_size);}
    if(corrected_size==0 ){ free(oldptr); return NULL;}
    //increase
    if(node.size< corrected_size){
        void *newptr=malloc(corrected_size);
        memcpy(newptr,oldptr,node.size);
        free(oldptr);
        return newptr;
    }
    //decrease
    else
    
    if((node.size-corrected_size)<4*node.size){ return oldptr;}
    else{
        uint64_t free_size= (node.size-corrected_size-2*WORD_SIZE);
        void* free_ptr=(oldptr+corrected_size+2*WORD_SIZE);
        set_bound_tags(free_ptr,free_size,true);
        set_bound_tags(oldptr, corrected_size, false);
        free(free_ptr);
        return oldptr;
    }
    return NULL;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void *calloc(size_t nmemb, size_t size)
{
    void *ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr)
    {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void *p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void *p)
{
    size_t ip = (size_t)p;
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
