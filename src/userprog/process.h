#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct mmap_file {
    struct list_elem elem;
    struct sp_entry *spe;
    int mapid;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);
bool process_add_mmap (struct sp_entry *spe);
void process_remove_mmap (int map);

#endif /* userprog/process.h */
