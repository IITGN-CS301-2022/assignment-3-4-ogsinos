#include "vm/swap.h"

void swap_init (void) {
    swap_block = block_get_role(BLOCK_SWAP);
    if (!swap_block) return;
    swap_bmap = bitmap_create(block_size(swap_block)/SECTORS_PER_PAGE);
    if (!swap_bmap) return;
    bitmap_set_all(swap_bmap, SWAP_RELEASED);
    lock_init(&swap_mutex);
}

size_t swap_out (void *frame) {
    if (!swap_block || !swap_bmap) PANIC("NO SWAP PARTITION!!!!");
    lock_acquire(&swap_mutex);
    size_t free_idx = bitmap_scan_and_flip(swap_bmap, 0, 1, SWAP_RELEASED);
    if (free_idx == BITMAP_ERROR) PANIC("SWAP PARTITION FULL!!!!");
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write(swap_block, free_idx * SECTORS_PER_PAGE + i, (uint8_t *) frame + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_mutex);
    return free_idx;
}

void swap_in (size_t used_idx, void *frame) {
    if (!swap_block || !swap_bmap) return;
    lock_acquire(&swap_mutex);
    if (bitmap_test(swap_bmap, used_idx) == SWAP_RELEASED) PANIC("SWAP IN A FREE BLOCK!!!!");
    bitmap_flip(swap_bmap, used_idx);
    for (size_t i = 0; i < SECTORS_PER_PAGE;  i++) {
        block_read(swap_block, used_idx * SECTORS_PER_PAGE + i, (uint8_t *) frame + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_mutex);
}