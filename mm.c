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
// #define DEBUG

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
//count num commands given FIXME
int command_count = 4; //FIXME
//debug log file FIXME
FILE *log_fp;

struct free_node
{
    void *cur_addr;
    void *next_addr;
    void *prev_addr;
    uint64_t size;
    bool valid;
};

typedef struct free_node free_node; 

/*writes given value to root global var and to root addr*/
static void set_root(void *ptr){
    root = ptr;
    mem_write(root_addr, (uint64_t)root, WORD_SIZE);
}

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

static free_node get_node(void *ptr){
    free_node node;
    node.cur_addr = ptr;

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

    while(ptr != (void *)0){
        free_node cur_node = get_node(ptr); 

        if(cur_node.size >= size){
            break;
        }
        if(ptr == cur_node.next_addr || cur_node.next_addr > mem_heap_hi()){
            dbg_printf();
            return (void *)0;
        }
        ptr = cur_node.next_addr;
    }

    return ptr; 
}



static void set_next(void *ptr, void *next){
    mem_write(ptr, (uint64_t)next, WORD_SIZE);
}

static void set_prev(void *ptr, void *prev){
    mem_write(ptr + WORD_SIZE, (uint64_t)prev, WORD_SIZE);
}


static void set_bound_tags(void *ptr, uint64_t size, bool free){
    uint64_t tag = size;
    if(!free){
        tag = size | 1; 
    }
    mem_write(ptr - WORD_SIZE, tag, WORD_SIZE);
    mem_write(ptr + size, tag, WORD_SIZE);
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

static void overwrite_node(void *ptr, uint64_t size){
    set_prev(ptr, NULL);
    free_node cur_node = get_node(ptr);
    
    //if the node is not last 
    if(cur_node.next_addr != 0)
        set_prev(cur_node.next_addr, ptr);

    //IF FIRST IN LIST 
    if(root == ptr){
        set_next(ptr, cur_node.next_addr);
    }   
    else{
        void *next = root;
        root = ptr;
        //update actual root 
        mem_write(root_addr, (uint64_t)root, WORD_SIZE);
        set_next(ptr, next);
    }

    set_bound_tags(ptr, size, true);
}

static void *add_space(uint64_t size){
    void *ptr;
    void *prg_break = mem_heap_hi() + 1;
    uint64_t last_tag = mem_read(prg_break - WORD_SIZE, WORD_SIZE);

    // printf("WORD_SIZE: %ld\n", WORD_SIZE);
    //last block is allocated, add new free node at end of heap
    if(is_allocated(last_tag)){
        ptr = prg_break + WORD_SIZE;
        void *sbrk_status = mem_sbrk(size + 2 * WORD_SIZE);
        if(sbrk_status == (void *)-1){
            return sbrk_status;
        }
        add_node(ptr, size);
    }
    //last block is free node, extend prg brk and update metadata 
    else{
        uint64_t last_size = tag_to_size(last_tag);
        ptr = prg_break - last_size - WORD_SIZE;
        void *sbrk_status = mem_sbrk(size-last_size);
        //update lower size tag
        if(sbrk_status == (void *)-1){
            return sbrk_status;
        }
        mem_write(ptr-WORD_SIZE, size, WORD_SIZE);
        //update upper size tag
        mem_write(prg_break-WORD_SIZE, size, WORD_SIZE);
    }

    return ptr;
}

static bool add_space_root(){
    void *new_node = mem_heap_hi() + 1 + WORD_SIZE;
    void *sbrk_status = mem_sbrk(4*WORD_SIZE);
    if(sbrk_status == (void *)-1){
        return false;
    }
    set_next(new_node, (void *)0);
    set_prev(new_node, (void *)0);
    set_bound_tags(new_node, 2*WORD_SIZE, true);
    root = new_node;
    mem_write(root_addr, (uint64_t)root, WORD_SIZE);
    // FIXME
    // free_node test_f = get_node(new_node);     
    // printf("\nuse me to stop exec\n");
    // FIXME
    return false;
}

static void alloc_splice(void *ptr){
    free_node node = get_node(ptr);
    
    //only node in free list
    if(node.prev_addr == 0 && node.next_addr == 0){
        return;
    }
    //node is first in free list
    else if(node.prev_addr == 0){
        set_prev(node.next_addr, NULL);
        set_root(node.next_addr);
    }
    //node is last in free list
    else if(node.next_addr == 0){
        set_next(node.prev_addr, NULL);
    }
    //node is floating in list
    else{
        set_next(node.prev_addr, node.next_addr);
        set_prev(node.next_addr, node.prev_addr);
    }
}

//simple splice for the many cases in free
static void free_splice(void *ptr){
    free_node node = get_node(ptr);
    if(node.next_addr && node.prev_addr){
        set_prev(node.next_addr, node.prev_addr);
        set_next(node.prev_addr, node.next_addr);
    }
}

static void alloc(void *space, uint64_t size){
    free_node free_space = get_node(space);
    int new_node_size = free_space.size - size - 2*WORD_SIZE; 

    //add node if free_space is the only node and if node needs to be overwritten
    if((size == free_space.size ||  new_node_size < (int)(2*WORD_SIZE))&& free_space.prev_addr == NULL && free_space.next_addr == NULL){
        add_space_root();
        size = free_space.size;    
    }
    //if node is not the only in the list but will be overwritten, splice it
    else if(size == free_space.size ||  new_node_size < (int)(2*WORD_SIZE)){
        alloc_splice(space);
        size = free_space.size;
    }
    //else split node
    else{
        void *new_node = space + size + 2*WORD_SIZE;
        set_next(new_node, free_space.next_addr);
        set_prev(new_node, free_space.prev_addr);
        set_bound_tags(new_node, new_node_size, true);

        //if not only node in free list
        if(!(free_space.prev_addr == 0 && free_space.next_addr == 0)){
            //first node in list
            if(free_space.prev_addr == 0){
                set_root(new_node);
                set_prev(free_space.next_addr, new_node);
            }
            //last node in list
            else if(free_space.next_addr == 0)
                set_next(free_space.prev_addr, NULL);
            //floating
            else{
                set_next(free_space.prev_addr, new_node);
                set_prev(free_space.next_addr, new_node);
            }
        }
        else
            set_root(new_node);
    }
    set_bound_tags(space, size, false);
}

static void print_node_list(){
    void *ptr = root;

    while(ptr != (void *)0){
        free_node cur_node = get_node(ptr); 

        printf("node: %p\n", cur_node.cur_addr);
        printf("size %ld\n", cur_node.size);
        printf("prev %p\n", cur_node.prev_addr);
        printf("next %p\n", cur_node.next_addr);
        printf("valid %d\n", cur_node.valid);

        ptr = cur_node.next_addr;
    }
}

static void print_blocks(char *func, int count, uint64_t c_size){
    log_fp = fopen("debug_log.txt", "a+");
    void *cur_ptr = mem_heap_lo() + 8;
    // void *ptr = root;
    // void *nodes[100];
    // uint8_t f_nodes_count = 0;

    //make a list of free nodes by traversing list
    // while(ptr != (void *)0){
    //     free_node cur_node = get_node(ptr); 
    //     nodes[f_nodes_count] = ptr;
    //     ptr = cur_node.next_addr;
    //     f_nodes_count++;
    // }

    fprintf(log_fp, "\n\n\nFUNCTION: %s COMMAND#: %d SIZE: %ld", func, count, c_size);
    fprintf(log_fp, "\nRoot read: %p, root: %p\n root_addr: %p, heap lo: %p\n", (void *)mem_read(root_addr, 8), root, root_addr, mem_heap_lo());
    //check every word to see if its a tag, if it is print metadata 
    while(cur_ptr < mem_heap_hi() - WORD_SIZE - 1){
        uint64_t size = tag_to_size(mem_read(cur_ptr, WORD_SIZE));
        bool open_valid = !is_allocated(mem_read(cur_ptr, WORD_SIZE));
        void *close_addr = cur_ptr + size + WORD_SIZE;
        if(close_addr > mem_heap_hi()){
            cur_ptr += WORD_SIZE;
            continue;
        }
        uint64_t close_tag = tag_to_size(mem_read(close_addr, WORD_SIZE));
        bool close_valid = !is_allocated(mem_read(close_addr, WORD_SIZE));
        if(close_tag == size && size > 0){
            if(close_valid != open_valid){
                fprintf(log_fp, "\n\nFound block at %p\n but the valid bit does not match", cur_ptr + WORD_SIZE);
                fprintf(log_fp, "size: %ld\n", size);
            }
            else{
                fprintf(log_fp, "\nFound block at %p\n free?: %d\n", cur_ptr + WORD_SIZE, open_valid);
                if(open_valid){
                    free_node node = get_node(cur_ptr + WORD_SIZE);
                    fprintf(log_fp, "next: %p\n", node.next_addr);
                    if(node.next_addr != 0 && (mem_heap_hi() < node.next_addr || node.next_addr < mem_heap_lo()))
                        fprintf(log_fp, "**WARNING: ADDR OUT OF BOUNDS**\n");
                    fprintf(log_fp, "prev: %p\n", node.prev_addr);
                    if(node.prev_addr != 0 && (mem_heap_hi() < node.prev_addr || node.prev_addr < mem_heap_lo()))
                        fprintf(log_fp, "**WARNING: ADDR OUT OF BOUNDS**\n"); 
                }
                fprintf(log_fp, "size: %ld\n", size);
            }
            // if(open_valid){ 
            //     bool is_in_list = false;
            //     void *node_ptr = cur_ptr + WORD_SIZE; 
            //     for(int i = 0; i < 100; i++){
            //         if(node_ptr == nodes[i]){
            //             is_in_list = true;
            //             break;
            //         }
            //     }
            //     if(!is_in_list){
            //         fprintf(log_fp, "**WARNING: NODE IS NOT IN LIST**\n");
            //     }
            // }
            cur_ptr += size + 2*WORD_SIZE;
        }
        else
            cur_ptr += WORD_SIZE;
    }
    fprintf(log_fp, "PRG BRK %p\n", mem_heap_hi() + 1);
    fprintf(log_fp, "END TRAVERSE COMMAND#: %d FUNCTION: %s SIZE: %ld", count, func, c_size);
    fclose(log_fp);
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
    log_fp = fopen("debug_log.txt", "w+");
    fclose(log_fp);

    // FIXME

    // mm_malloc(32);
    // //add_space(32);
    // mm_malloc(64);
    // //add_space(64);
    // mm_malloc(128);

    // printf("\nuse me to stop exec\n");
    // // FIXME
    return true;
}

/*
 * malloc
 */
void *malloc(size_t size)
{
    command_count += 1; //FIXME
    // printf("\n%d\n", command_count);
    /* IMPLEMENT THIS */
    if(size == 0){
        return NULL; 
    }
    uint64_t corrected_size = (uint64_t)align(size); 
    void *space = find_space(corrected_size);
    if(space == NULL){
        space = add_space(corrected_size);
    }
    //FIXME
    // free_node space_node = get_node(space);
    // printf("\n%p\n",space_node.next_addr);
    //FIXME

    alloc(space, corrected_size);

    //FIXME
    // printf("ptr to free space %p\n", space);
    // printf("corrected_size: %ld", corrected_size);
    //print_node_list();
    //printf("\nuse me to stop exec\n");
    // print_blocks("malloc",command_count, corrected_size);
    //FIXME
    return space;
}

static bool validate_size(uint64_t size){
    if(size > mem_heapsize())
        return false;
    return true; 
}

/*
 * free
 */
void free(void *ptr)
{
    // command_count++;//FIXME
    // // printf("\n%d\n", command_count);
    // if(ptr==NULL){return;}
    // free_node fnode = get_node(ptr);
    // // free_node node_n = get_node(fnode.next_addr);
    // // free_node node_p = get_node(fnode.prev_addr);
    // bool next_free;
    // free_node next_node = {NULL, NULL, NULL, 0, false};
    // free_node prev_node = {NULL, NULL, NULL, 0, false};
    // //check if next block is prg break
    // if((ptr + fnode.size + WORD_SIZE + WORD_SIZE) < mem_heap_hi()){
    //     if(validate_size(mem_read(ptr + fnode.size + WORD_SIZE, WORD_SIZE))){
    //         next_node = get_node(ptr + fnode.size + 2*WORD_SIZE); 
    //         next_free = next_node.valid;
    //     }
    //     else
    //         next_free = false;
    // }
    // else
    //     next_free = false;

    // //check if prev block is root
    // bool prev_free;
    // if(ptr - 2 * WORD_SIZE > root_addr){
    //     void *bound_tag = ptr - 2 * WORD_SIZE;
    //     uint64_t prev_size = tag_to_size(mem_read(bound_tag, WORD_SIZE));
    //     if(validate_size(prev_size)){
    //         prev_node = get_node(bound_tag - prev_size);
    //         prev_free = prev_node.valid;    
    //     }   
    //     else
    //         prev_free = false;
    // }
    // else
    //     prev_free = false;

    // if (fnode.valid)
    // {
    //     return;
    // }
    // //case 4
    // else if (next_free && prev_free)
    // {
    //     void *new_addr = prev_node.cur_addr;
    //     //prev and next blocks are only nodes in list
    //     if((!next_node.next_addr && !prev_node.prev_addr) || (!next_node.prev_addr && !prev_node.next_addr)){
    //         set_root(new_addr);
    //         set_next(new_addr,NULL);
	// 	    set_prev(new_addr,NULL);
    //     }
    //     //prev and next blocks are adjacent in free list
    //     else if(prev_node.next_addr == next_node.cur_addr || prev_node.prev_addr == next_node.cur_addr){
    //         //next node is last in list
    //         if(!next_node.next_addr){
    //             set_next(prev_node.prev_addr, NULL);

    //             set_prev(root, new_addr);
    //             set_next(new_addr, root);
    //             set_prev(new_addr,NULL);
    //             set_root(new_addr);
    //         }
    //         //prev node last in list
    //         else if(!prev_node.next_addr){
    //             set_next(next_node.prev_addr, NULL);

    //             set_prev(root, new_addr);
    //             set_next(new_addr, root);
    //             set_prev(new_addr,NULL);
    //             set_root(new_addr);
    //         }
    //         //next node is first in list
    //         else if(!next_node.prev_addr){
    //             set_root(new_addr);
    //             set_prev(new_addr,NULL);
    //         }
    //         //prev node is first in list
    //         else if(!prev_node.prev_addr){
    //             set_prev(next_node.next_addr, new_addr);
    //             set_next(new_addr, next_node.next_addr);
    //             set_prev(new_addr, NULL);
    //         }
    //         else{
    //             //... -> next -> prev -> ... 
    //             if(prev_node.prev_addr == next_node.cur_addr){
    //                 set_next(next_node.prev_addr, prev_node.next_addr);
    //                 set_prev(prev_node.next_addr, next_node.prev_addr);
                    
    //                 set_prev(root, new_addr);
    //                 set_next(new_addr, root);
    //                 set_prev(new_addr,NULL);
    //                 set_root(new_addr);
    //             }
    //             //... -> prev -> next -> ... 
    //             else if(prev_node.next_addr == next_node.cur_addr){
    //                 set_next(prev_node.prev_addr, next_node.next_addr);
    //                 set_prev(next_node.next_addr, prev_node.prev_addr);
                   
    //                 set_prev(root, new_addr);
    //                 set_next(new_addr, root);
    //                 set_prev(new_addr,NULL);
    //                 set_root(new_addr);
    //             }
    //         }
    //     }
    //     //nodes are floating randomly in list
    //     else{
            
    //         alloc_splice(prev_node.cur_addr);
            
    //         alloc_splice(next_node.cur_addr);

    //         set_prev(root, new_addr);
    //         set_next(new_addr, root);
    //         set_prev(new_addr,NULL);
    //         set_root(new_addr);
    //     }
    //     set_bound_tags(new_addr, fnode.size + next_node.size + prev_node.size + 4*WORD_SIZE, true);
    // }
    // //case 2
    // else if (next_free)
    // {
    //     // void *new_addr = ptr;
    //     // //next node is only node, only resize and move data to ptr
    //     // if(!next_node.next_addr && !next_node.prev_addr){
    //     //     set_root(new_addr);
    //     //     set_next(new_addr,NULL);
	// 	//     set_prev(new_addr,NULL);
    //     // }
    //     // //next node is first node
    //     // else if(!next_node.prev_addr){
    //     //     set_prev(root, new_addr);
    //     //     set_next(new_addr, next_node.next_addr);
    //     //     set_prev(new_addr,NULL);
    //     //     set_root(new_addr);
    //     // }
    //     // //next node is last node
    //     // else if(!next_node.next_addr){
    //     //     set_next(next_node.prev_addr, NULL);

    //     //     set_prev(root, new_addr);
    //     //     set_next(new_addr, root);
    //     //     set_prev(new_addr,NULL);
    //     //     set_root(new_addr);
    //     // }
    //     // else{
    //     //     free_splice(next_node.cur_addr);

    //     //     set_prev(root, new_addr);
    //     //     set_next(new_addr, root);
    //     //     set_prev(new_addr,NULL);
    //     //     set_root(new_addr);
    //     // }

    //     // set_bound_tags(new_addr, fnode.size + next_node.size + 2*WORD_SIZE, true);
    // }
    // //case 3
    // else if (prev_free)
    // {
    //     // void *new_addr = prev_node.cur_addr;

    //     // //if prev is only node in list simply resize, mode to beginning of list
    //     // if(!prev_node.next_addr && !prev_node.prev_addr){
    //     //     set_root(new_addr);
    //     //     set_next(new_addr, NULL);//FIXME?
    //     //     set_prev(new_addr, NULL);//FIXME?
    //     // }
    //     // //prev_node is first in list
    //     // else if(!prev_node.prev_addr){

    //     // }
    //     // //prev node is last node: remove from end of list, resize, move to beginning of list
    //     // else if(!prev_node.next_addr){
    //     //     //remove from end of list
    //     //     set_next(prev_node.prev_addr, NULL);
            
    //     //     set_prev(root, new_addr);
    //     //     set_next(new_addr, root);
    //     //     set_prev(new_addr,NULL);
    //     //     set_root(new_addr);
    //     // }
    //     // //otherwise splice the node out, resize, move to beginning of list
    //     // else{
    //     //     free_splice(prev_node.cur_addr);

    //     //     set_prev(root, new_addr);
    //     //     set_next(new_addr, root);
    //     //     set_prev(new_addr,NULL);
    //     //     set_root(new_addr);
    //     // }
    //     // set_bound_tags(prev_node.cur_addr, fnode.size + prev_node.size + 2*WORD_SIZE, true);
    // }
    // //case 1
    // else{
    //     set_prev(root, ptr);
    //     set_next(ptr, root);
    //     set_prev(ptr,NULL);
    //     set_root(ptr);
    //     set_bound_tags(ptr, fnode.size, true);
    // }


    //FIXME
    // print_blocks("free",command_count, fnode.size);   
    //FIXME
}

/*
 * realloc
 */
void *realloc(void *oldptr, size_t size)
{
    command_count += 1; //FIXME
    uint64_t corrected_size = (uint64_t)align(size);
    free_node node=get_node(oldptr);
    if(node.size==corrected_size){return oldptr;}
    if(oldptr==NULL){
        command_count -= 1;
        return malloc(corrected_size);
    }
    if(corrected_size==0 ){
        free(oldptr);
        command_count -= 1;//FIXME
        //FIXME
        // print_blocks("realloc",command_count, size);   
        //FIXME
        return NULL;
    }
    //increase
    if(node.size< corrected_size){
        void *newptr=malloc(corrected_size);
        memcpy(newptr,oldptr,node.size);
        free(oldptr);
        command_count -= 1;//FIXME
        //FIXME
        // print_blocks("realloc",command_count,size);   
        //FIXME
        return newptr;
    }
    //decrease
    else if((node.size-corrected_size)<4*WORD_SIZE){ 
        //FIXME
        // print_blocks("realloc",command_count, size);   
        //FIXME
        return oldptr;
    }
    else{
        uint64_t free_size= (node.size-corrected_size-2*WORD_SIZE);
        void* free_ptr=(oldptr+corrected_size+2*WORD_SIZE);
        set_bound_tags(free_ptr,free_size,true);
        set_bound_tags(oldptr, corrected_size, false);
        free(free_ptr);
        command_count -= 1;//FIXME
        //FIXME
        // print_blocks("realloc",command_count, size);   
        //FIXME
        return oldptr;
    }
    // else
    //     return oldptr;
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
    command_count -= 1;
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
    void *cur_ptr = mem_heap_lo() + 8;
    void *ptr = root;
    void *nodes[10000];
    bool heap_status = true;
    uint16_t f_nodes_count = 0;

    //make a list of free nodes by traversing list
    while(ptr != (void *)0){
        free_node cur_node = get_node(ptr); 
        nodes[f_nodes_count] = ptr;
        if(cur_node.next_addr > mem_heap_hi()){
            dbg_printf("NODE %p HAS INVALID NEXT ADDR %p", cur_ptr, cur_node.next_addr);
            return false;
        }
        ptr = cur_node.next_addr;
        f_nodes_count++;
        if(f_nodes_count > 10000){
            dbg_printf("\nMORE THAN 10K NODES,\n INCREASE MAX NODES OR INFINITE LOOPING");
            return false;
        }
    }

    while(cur_ptr < mem_heap_hi() - WORD_SIZE - 1){
        uint64_t size = tag_to_size(mem_read(cur_ptr, WORD_SIZE));
        bool open_valid = !is_allocated(mem_read(cur_ptr, WORD_SIZE));
        void *close_addr = cur_ptr + size + WORD_SIZE;
        if(close_addr > mem_heap_hi()){
            cur_ptr += WORD_SIZE;
            continue;
        }
        uint64_t close_tag = tag_to_size(mem_read(close_addr, WORD_SIZE));
        bool close_valid = !is_allocated(mem_read(close_addr, WORD_SIZE));
        if(close_tag == size && size > 0){
            //check if valid bits match
            if(close_valid != open_valid){
                dbg_printf("\n\nFound block at %p\n but the valid bit does not match", cur_ptr + WORD_SIZE);
                heap_status = false;
            }
            //check if next and prev addr are valid
            else if(open_valid){
                free_node node = get_node(cur_ptr);
                if(node.next_addr != 0){ 
                    if(node.next_addr < mem_heap_lo() || node.next_addr > mem_heap_hi()){
                        dbg_printf("NODE %p HAS INVALID NEXT ADDR %p", cur_ptr, node.next_addr);
                        heap_status = false;
                    }
                    else{
                        free_node next_node = get_node(node.next_addr);
                        if(!next_node.valid){
                            dbg_printf("NODE %p NEXT ADDR POINTS TO INVALID NODE %p", cur_ptr, node.next_addr);
                            heap_status = false;        
                        }
                    }
                }
                if(node.prev_addr != 0){ 
                    if(node.prev_addr < mem_heap_lo() || node.prev_addr > mem_heap_hi()){
                        dbg_printf("NODE %p HAS INVALID PREV ADDR %p", cur_ptr, node.prev_addr);
                        heap_status = false;
                    }
                    else{
                        free_node prev_node = get_node(node.prev_addr);
                        if(!prev_node.valid){
                            dbg_printf("NODE %p PREV ADDR POINTS TO INVALID NODE %p", cur_ptr, node.next_addr);
                            heap_status = false;        
                        }
                    }
                }
            }
            //is node in list?
            if(open_valid){ 
                bool is_in_list = false;
                void *node_ptr = cur_ptr + WORD_SIZE; 
                for(int i = 0; i < 100; i++){
                    if(node_ptr == nodes[i]){
                        is_in_list = true;
                        break;
                    }
                }
                if(!is_in_list){
                    dbg_printf("**WARNING: NODE %p IS NOT IN LIST**\n", node_ptr);
                    heap_status = false;
                }
            }
        }    
    }
    return heap_status;
#endif /* DEBUG */
    return true;
}
