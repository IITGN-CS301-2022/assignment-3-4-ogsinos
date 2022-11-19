#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"

#define USER_VADDR_BOTTOM ((void*) 0x08048000)
#define STACK_HEURISTIC 32

struct lock file_mutex;

struct sp_entry* address_check(const void *address, void *esp);
void syscall_init (void);
void halt (void);
void exit(int status);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
/* Remove all files */
void close_all_fd (struct list *fd_list);

int mmap (int fd, void *addr);
void munmap (int map);

#endif /* userprog/syscall.h */
