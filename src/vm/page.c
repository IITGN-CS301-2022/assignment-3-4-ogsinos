#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static unsigned hash_page(const struct hash_elem* e, void *aux){
    struct sp_entry *spe = hash_entry(e,struct sp_entry,elem);
    return hash_int((int)spe->uv_add);
}

static bool page_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux){
    struct sp_entry *spa = hash_entry(a,struct sp_entry,elem);
    struct sp_entry *spb = hash_entry(b,struct sp_entry,elem);
    return spa->uv_add < spb->uv_add;
}

static void action_page(struct hash_elem* e, void *aux){
    struct sp_entry *spe = hash_entry(e,struct sp_entry,elem);
    if(spe->loaded){
        f_free(pagedir_get_page(thread_current()->pagedir,spe->uv_add));
        pagedir_clear_page(thread_current()->pagedir,spe->uv_add);
    }
    free(spe);
}

void pt_init(struct hash *sp){
    // printf("hehe2\n");
    hash_init(sp,hash_page,page_comp,NULL);
}

struct sp_entry* get_spe(void* uv_add){
    struct sp_entry spe;
    // printf("malloc done\n");
    spe.uv_add = pg_round_down(uv_add);
    // printf("round done\n");
    struct hash_elem* e = hash_find(&thread_current()->sp,&spe.elem);
    if(e == false) return NULL;
    return hash_entry(e,struct sp_entry,elem);
}

void pt_destroy(struct hash* sp){
    hash_destroy(sp,action_page);
}

bool load_page(struct sp_entry* spe){
    bool success = false;
    spe->pinned = true;
    // printf("spe type1 %d\n",spe->type);
    if(spe->loaded) return success;
    // printf("spe type2 %d",spe->type);
    switch(spe->type){
        case FILE:
            success =load_file(spe);
            break;
        case SWAP:
            success =load_swap(spe);
            break;
        case MMAP:
            success =load_file(spe);
            break;
        default:
            break;
    }
    return success;
}

bool load_swap(struct sp_entry *spe){
    uint8_t* frame = f_alloc(PAL_USER,spe);
    if(frame == false) return false;
    if(!install_page(spe->uv_add,frame,spe->can_write)){
        f_free(frame);
        return false;
    }
    swap_in(spe->swap_index,spe->uv_add);
    spe->loaded =true;
    return true;
}

bool load_file(struct sp_entry* spe){
    enum palloc_flags flags  = PAL_USER;
    if(spe->read_bytes == 0) flags |= PAL_ZERO;
    uint8_t* frame = f_alloc(flags,spe);
    if(!frame) return false;
    if(spe->read_bytes){
        lock_acquire(&file_mutex);
        if((int)spe->read_bytes != file_read_at(spe->file,frame,spe->read_bytes,spe->offset)){
            lock_release(&file_mutex);
            f_free(frame);
            return false;
        }
        lock_release(&file_mutex);
        memset(frame+spe->read_bytes,0,spe->zero_bytes);
    }
    if(!install_page(spe->uv_add,frame,spe->can_write)){
        f_free(frame);
        return false;
    }
    spe->loaded = true;
    return true;
}

bool pt_add(struct file* file,int32_t offset, uint8_t *user_page, uint32_t read_bytes,uint32_t zero_bytes,bool can_write){
    struct sp_entry *spe = malloc(sizeof(struct sp_entry));
    if(!spe) return false;
    spe->file = file;
    spe->offset = offset;
    spe->uv_add = user_page;
    spe->read_bytes = read_bytes;
    spe->loaded = false;
    spe->zero_bytes = zero_bytes;
    spe->can_write = can_write;
    spe->type = FILE;
    spe->pinned = false;
    // printf("hehe2\n");
    if (hash_insert(&thread_current()->sp,&spe->elem) == NULL) return true;
    // printf("hehe2\n");
    return false;
}

bool pt_add_mmap(struct file* file,int32_t offset, uint8_t *user_page, uint32_t read_bytes,uint32_t zero_bytes){
    struct sp_entry *spe = malloc(sizeof(struct sp_entry));
    if(!spe) return false;
    spe->file = file;
    spe->offset = offset;
    spe->uv_add = user_page;
    spe->read_bytes = read_bytes;
    spe->loaded = false;
    spe->zero_bytes = zero_bytes;
    spe->can_write = true;
    spe->type = MMAP;
    spe->pinned = false;
    if(!process_add_mmap(spe)){
        free(spe);
        return false;
    }
    if(hash_insert(&thread_current()->sp,&spe->elem)){
        spe->type = HASH_ERROR;
        return false;
    }
    return true;
}

bool stack_grow(void* uv_add){
    if((size_t)(PHYS_BASE-pg_round_down(uv_add)) > MAX_STACK_SIZE) return false;
    struct sp_entry *spen = malloc(sizeof(struct sp_entry));
    if(spen == false) return false;
    spen->uv_add = pg_round_down(uv_add);
    spen->loaded = true;
    spen->can_write = true;
    spen->type = SWAP;
    spen->pinned = true;
    uint8_t *frame = f_alloc(PAL_USER,spen);
    if(!frame){
        free(spen);
        return false;
    }
    if(!install_page(spen->uv_add,frame,spen->can_write)){
        free(spen);
        f_free(frame);
        return false;
    }
    if(intr_context()) spen->pinned = false;
    if (hash_insert(&thread_current()->sp,&spen->elem) == NULL)return true;
    return false;
}
