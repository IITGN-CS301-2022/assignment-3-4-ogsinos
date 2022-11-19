#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"

enum spe_type
  {
    FILE,
    SWAP,
    MMAP,
    HASH_ERROR
  };

#define MAX_STACK_SIZE (1<<23)

struct sp_entry{
    enum spe_type type;
    void* uv_add;
    bool can_write;
    bool loaded;
    bool pinned;

    struct file* file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    size_t swap_index;
    struct hash_elem elem;

};

void pt_init(struct hash *sp);
void pt_destroy(struct hash *sp);
// bool load_mmap(struct sp_entry *spe);
bool load_page(struct sp_entry *spe);
bool load_swap(struct sp_entry *spe);
bool load_file(struct sp_entry *spe);
bool pt_add(struct file* file,int32_t offset, uint8_t *user_page, uint32_t read_bytes,uint32_t zero_bytes,bool can_write);
bool pt_add_mmap(struct file* file,int32_t offset, uint8_t *user_page, uint32_t read_bytes,uint32_t zero_bytes);
bool stack_grow(void* uv_add);
struct sp_entry* get_spe(void* uv_add);

#endif
