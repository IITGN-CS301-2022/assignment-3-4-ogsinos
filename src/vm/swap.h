#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

#define SWAP_RELEASED 0
#define SWAP_ACQUIRED 1
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock swap_mutex;
struct block *swap_block;
struct bitmap *swap_bmap;

void swap_init (void);
size_t swap_out (void *frame);
void swap_in (size_t used_idx, void *frame);

#endif