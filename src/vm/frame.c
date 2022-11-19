#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

void ft_init () {
    list_init(&ft);
    lock_init(&ft_mutex);
}

void *f_alloc (enum palloc_flags flags, struct sp_entry *spe) {
    if ((flags & PAL_USER) == 0) return NULL;
    void *frame = palloc_get_page(flags);
    if (frame) {
        ft_add(frame, spe);
    } else {
        while (!frame) {
            frame = f_evict(flags);
        }
        if (!frame) {
            PANIC("Swap Full!!!!");
        }
        ft_add(frame, spe);
    }
    return frame;
}

void f_free (void *frame) {
    lock_acquire(&ft_mutex);
    struct list_elem *ele = list_begin(&ft);

    while (ele != list_end(&ft)) {
        struct ft_entry *fe = list_entry(ele, struct ft_entry, elem);
        if (fe->frame == frame) {
            list_remove(ele);
            free(fe);
            palloc_free_page(frame);
            break;
        }
        ele = list_next(ele);
    }

    lock_release(&ft_mutex);
}

void *f_evict (enum palloc_flags flags) {
    lock_acquire(&ft_mutex);
    struct list_elem *ele = list_begin(&ft);

    while (true) {
        struct ft_entry *fe = list_entry(ele, struct ft_entry, elem);
        if (!fe->spe->pinned) {
            struct thread *t = fe->thread;
            if (pagedir_is_accessed(t->pagedir, fe->spe->uv_add)) {
                pagedir_set_accessed(t->pagedir, fe->spe->uv_add, false);
            } else {
                if (pagedir_is_dirty(t->pagedir, fe->spe->uv_add) || fe->spe->type == SWAP) {
                    if (fe->spe->type == MMAP) {
                        lock_acquire(&file_mutex);
                        file_write_at(fe->spe->file, fe->frame, fe->spe->read_bytes, fe->spe->offset);
                        lock_release(&file_mutex);
                    } else {
                        fe->spe->type = SWAP;
                        fe->spe->swap_index = swap_out(fe->frame);
                    }
                }
                fe->spe->loaded = false;
                list_remove(&fe->elem);
                pagedir_clear_page(t->pagedir, fe->spe->uv_add);
                palloc_free_page(fe->frame);
                free(fe);
                lock_release(&ft_mutex);
                return palloc_get_page(flags); 
            }
        }
        ele = list_next(ele);
        if (ele == list_end(&ft)) ele = list_begin(&ft);
    }
}

void ft_add (void *frame, struct sp_entry *spe) {
    struct ft_entry *fe = malloc(sizeof(struct ft_entry));
    fe->frame = frame;
    fe->spe = spe;
    fe->thread = thread_current();
    lock_acquire(&ft_mutex);
    list_push_back(&ft, &fe->elem);
    lock_release(&ft_mutex);
}
