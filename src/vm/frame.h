#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include <stdbool.h>
#include <stdint.h>
#include <list.h>

struct lock ft_mutex;
struct list ft;
struct ft_entry {
    struct list_elem elem;
    void *frame;
    struct thread *thread;
    struct sp_entry *spe;
};

void ft_init (void);
void *f_alloc (enum palloc_flags flags, struct sp_entry *spe);
void f_free (void *frame);
void *f_evict (enum palloc_flags flags);
void ft_add (void *frame, struct sp_entry *spe);

#endif