#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/frame.h"
#include "vm/page.h"

void one_arg(struct intr_frame *f, int syscall_num, void *args);
void two_arg(struct intr_frame *f, int syscall_num, void *args);
void three_arg(struct intr_frame *f, int syscall_num, void *args);
static void syscall_handler (struct intr_frame *f);
void check_valid_buffer (void* buffer, unsigned size, void* esp,bool to_write);
void check_valid_string (const void* str, void* esp);
void unpin_ptr (void* vaddr);
void unpin_string (void* str);
void unpin_buffer (void* buffer, unsigned size);

struct sp_entry* 
address_check(const void *address, void *esp)
{
  if(!is_user_vaddr(address) || address < USER_VADDR_BOTTOM) {
    // printf("fail\n");
    exit(-1);
  }
  bool load = false;
  // printf("here\n");
  struct sp_entry *spe = get_spe((void *) address);
  // printf("spe done\n");
  if (spe) {
    load_page(spe);
    load = spe->loaded;
  } else if (address >= esp - STACK_HEURISTIC) {
    // printf("grow stack\n");
    load = stack_grow((void *) address);
  }
  if (!load) exit(-1);
  // printf("loaded\n");
  return spe;
}

void 
one_arg(struct intr_frame *f, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  // address_check((const void*)argv);
  switch (syscall_num)
  {
    case SYS_EXIT:
      exit(argv);
      break;
    case SYS_EXEC:
      address_check((const void*)argv, f->esp);
      check_valid_string((const void*) argv,f->esp);
      f->eax = exec((const char*) argv);
      unpin_string((void*)argv);
      // printf("done\n");
      break;
    case SYS_WAIT:
      f->eax = wait(argv);
      break;
    case SYS_REMOVE:
      address_check((const void*)argv, f->esp);
      check_valid_string((const void*) argv,f->esp);
      f->eax = remove((const char*) argv);
      unpin_string((void*)argv);
      break;
    case SYS_OPEN:
    // printf("hey\n");
      address_check((const void*)argv, f->esp);
      // printf("hey\n");
      check_valid_string((const void*) argv,f->esp);
      // printf("hey\n");
      f->eax = open((const char*) argv);
      // printf("hey\n");
      unpin_string((void*)argv);
      // printf("hey\n");
      break;
    case SYS_FILESIZE:
      f->eax = filesize(argv);
      break;
    case SYS_TELL:
      f->eax = tell(argv);
      break;
    case SYS_CLOSE:
      close(argv);
      break;
    case SYS_MUNMAP:
      munmap(argv);
      break;
    default:
      // printf("hey\n");
      exit(-1);
      break;
  }
}

void 
two_arg(struct intr_frame *f, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  int argv1 = *((int*)args);
  args += 4;
  // address_check((const void*)argv);
  // address_check((const void*)argv1);
  switch (syscall_num)
  {
    case SYS_CREATE:
      address_check((const void*)argv, f->esp);
      check_valid_string((const void*) argv,f->esp);
      f->eax = create((const char*)argv,(unsigned) argv1);
      unpin_string((void*)argv);
      break;
    case SYS_SEEK:
      seek(argv,(unsigned)argv1);
      break;
    case SYS_MMAP:
      f->eax = mmap(argv, (void *)argv1);
      break;
    default:
      exit(-1);
      break;
  }
}

void 
three_arg(struct intr_frame *f, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  int argv1 = *((int*)args);
  args += 4;
  int argv2 = *((int*)args);
  args += 4;
  // printf("%p %d\n",&argv,argv);
  // printf("%p %s\n",&argv1,(char *)argv1);
  // printf("%p %d\n",&argv2,argv2);
  // address_check((const void*)argv);
  // printf("hehe\n");
  // printf("here 1\n");
  address_check((const void*)argv1, f->esp);
  void *temp = ((void*)argv1) + argv2;
  address_check((const void*)temp, f->esp);
  // printf("here\n");
  // address_check((const void*)argv2);
  // address_check((const void*)0xc0000000);
  switch (syscall_num)
  {
    case SYS_WRITE:
    // printf("here\n");
      check_valid_buffer((void*)argv1,(unsigned)argv2,f->esp,false);
      // printf("about to..\n");
      f->eax = write(argv, (void*)argv1,(unsigned)argv2);
      unpin_buffer((void*)argv1,(unsigned)argv2);
      // printf("yo1\n");
      break;
    case SYS_READ:
      // printf("here\n");
      check_valid_buffer((void*)argv1,(unsigned)argv2,f->esp,false);
      // printf("here\n");
      f->eax = read(argv, (void*)argv1,(unsigned)argv2);
      // unpin_buffer((void*)argv1,(unsigned)argv2);
      break;
    default:
      exit(-1);
      break;
  }
  // printf("yo2\n");
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_mutex);
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call!\n");
  int syscall_num = 0;
  address_check((const void *)f->esp, f->esp);
  // printf("Syscall\n");
  // printf("%p %d\n",f->esp,*((int *)f->esp));
  void *args = f->esp;
  syscall_num = *((int *)f->esp);
  args += 4;
  //printf("%p %s\n",args,((char*)args));
  address_check((const void*)args, f->esp);
  switch (syscall_num)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT: case SYS_EXEC: case SYS_WAIT: case SYS_REMOVE: case SYS_OPEN: case SYS_FILESIZE: case SYS_TELL: case SYS_CLOSE: case SYS_MUNMAP:
      one_arg(f,syscall_num,args);
      break;
    case SYS_CREATE: case SYS_SEEK: case SYS_MMAP:
      two_arg(f,syscall_num,args);
      break;
    case SYS_WRITE: case SYS_READ:
      three_arg(f,syscall_num,args);
      break;
    default:
      exit(-1);
      break;
  }
  // printf("hello\n");
  unpin_ptr(f->esp);
  // printf("yo\n");
}

void
halt (void) 
{
  shutdown_power_off();
}

void
exit (int status)
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);

  struct child *baby = search_child(cur->tid, &(cur->parent->children_list));
  baby->exit_status = status;
  if (status == -1)
  {
    baby->cur_status = CHILD_KILLED;
  } 
  else 
  {
    baby->cur_status = CHILD_EXITED;
  }

  thread_exit();
}

tid_t
exec (const char *cmd_line)
{
  struct thread *cur = thread_current();
  tid_t pid = -1;
  pid = process_execute(cmd_line);
// printf("process executed\n");
  struct child *baby = search_child(pid, &(cur->children_list));
  if(baby == NULL) return -1;
  // printf("search done\n");
  sema_down(&baby->child_thread->sema_load);
  // if(!baby) return -1;
  // printf("done right\n");
  if (!baby->loaded)
  {
    return -1;
  }
  else
  {
    return pid;
  }
}

int
wait (tid_t pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
{
  lock_acquire(&file_mutex);
  bool val = filesys_create(file, initial_size);
  lock_release(&file_mutex);
  return val;
}

bool 
remove (const char *file)
{
  lock_acquire(&file_mutex);
  bool val = filesys_remove(file);
  lock_release(&file_mutex);
  return val;
}

int 
open (const char *file)
{
  int val = -1;
  struct thread *cur = thread_current();
  // printf("OPEN\n");
  lock_acquire(&file_mutex);
  struct file *f_open = filesys_open(file);
  lock_release(&file_mutex);
  // if(!f_open) return -1;
  // printf("fopen %d\n",f_open);
  if (f_open)
  {
    // printf("ok\n");
    cur->fd_length ++;
    val = cur->fd_length;
    struct file_descriptor *fd_element = (struct file_descriptor *)malloc(sizeof(struct file_descriptor));
    fd_element->fd = val;
    fd_element->fd_file = f_open;
    list_push_back(&cur->fd_list, &fd_element->fd_elem);
  }
  // else 
  // {
  //   printf("not ok\n");
  // }
  // printf("%d\n",val);
  return val;
}

int 
filesize (int fd)
{
  // struct file *f = search_fd(fd)->fd_file;
  lock_acquire(&file_mutex);
  struct file *f = search_fd(fd)->fd_file;
  // printf("file found\n");
  if(!f){
    lock_release(&file_mutex);
    return -1;
  }
  int val = file_length(f);
  lock_release(&file_mutex);
  return val;
}

int 
read (int fd, void *buffer, unsigned size)
{
  int val = -1;
  // printf("fd %d\n",fd);
  if (fd == 0)
  {
    val = input_getc();
  }
  else if (fd > 0)
  {
    struct file_descriptor *fd_element = search_fd(fd);
    // printf("pass\n");
    if (fd_element == NULL || buffer == NULL)
    {
      return -1;
    }
    // printf("pass\n");
    struct file *f = fd_element->fd_file;
    lock_acquire(&file_mutex);
    val = file_read(f, buffer, size);
    // printf("pass2 size %d %d\n",val,size);
    lock_release(&file_mutex);

    // if (val < (int)size && val != 0)
    // {
    //   val = -1;
    // }
  }
  // printf("pass3 %d\n",val);
  return val;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  // printf("yo\n");
  uint8_t *buf = (uint8_t *)buffer;
  int val = -1;
  // printf("fd %d\n",fd);
  if (fd == 1)
  {
    putbuf((char *)buf, size);
    // printf("%d\n",size);
    return (int)size;
  }
  else{
    // printf("fd not 1\n");
    struct file_descriptor *fd_element = search_fd(fd);
    if (fd_element == NULL || buffer == NULL)
    {
      return -1;
    }

    struct file *f = fd_element->fd_file;
    lock_acquire(&file_mutex);
    val = file_write(f, buffer, size);
    lock_release(&file_mutex);
  }
  // printf("write done\n");

  return val;
}

void 
seek (int fd, unsigned position)
{
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  file_seek(f,position);
  lock_release(&file_mutex);
}

unsigned
tell (int fd)
{
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return -1;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  unsigned val = file_tell(f);
  lock_release(&file_mutex);
  return val;
}

void 
close (int fd)
{
  // printf("hello %d\n", fd);
  if (fd < 0) return;
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  file_close(f);
  lock_release(&file_mutex);
  list_remove(&fd_element->fd_elem);
}

void 
close_all_fd (struct list *fd_list)
{
  // printf("yo");
  struct list_elem *e;
  while (!list_empty(fd_list))
  {
    e = list_pop_front(fd_list);
    struct file_descriptor *fd_element = list_entry(e, struct file_descriptor, fd_elem);
    file_close(fd_element->fd_file);
    list_remove(e);
    free(fd_element);
  }
}

int mmap (int fd, void *addr) {
  struct file_descriptor *fd_prev = search_fd(fd);
  struct file *file_prev = fd_prev->fd_file;
   if (!file_prev) return -1;
   if (!is_user_vaddr(addr)) return -1;
   if (addr < USER_VADDR_BOTTOM) return -1;
   if (((uint32_t) addr % PGSIZE) != 0) return -1;
   struct file *file = file_reopen(file_prev);
   if (!file) return -1;
   if (file_length(file_prev) == 0) return -1;
   
   thread_current()->mapid ++;
   int32_t ofs = 0;
   uint32_t read_bytes = file_length(file);
   while (read_bytes > 0) {
     uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
     uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
     if (!pt_add_mmap(file, ofs, addr, page_read_bytes, page_zero_bytes)) 
     {
       munmap(thread_current()->mapid);
       return -1;
     }
     read_bytes -= page_read_bytes;
     ofs += page_read_bytes;
     addr += PGSIZE;
   }
   return thread_current()->mapid;
}

void munmap (int map) {
  process_remove_mmap(map);
}



void check_valid_buffer (void* buffer, unsigned size, void* esp, bool to_write){
  char* local_buffer = (char *) buffer;
  unsigned i = 0;
  // printf("size %d\n",size);
  while (i < size){
    // printf("%d\n",i);
      struct sp_entry *spe = address_check((const void*) local_buffer, esp);
      // printf("check passed %d\n",i);
      if (spe){
	if (to_write){
        	if (!spe->can_write) {
          // printf("problem\n");
          		exit(-1);
        	}
	}
      }
    i ++;
    local_buffer++;
  }
}

void check_valid_string (const void* str, void* esp){
  address_check(str, esp);
  while (* (char *) str != 0){
      str = (char *) str + 1;
      address_check(str, esp);
  }
}

void unpin_ptr (void* vaddr){
  struct sp_entry *spe = get_spe(vaddr);
  if (spe) spe->pinned = false;
}

void unpin_string (void* str){
  unpin_ptr(str);
  while (* (char *) str != 0){
      str = (char *) str + 1;
      unpin_ptr(str);
  }
}

void unpin_buffer (void* buffer, unsigned size){
  char* local_buffer = (char *) buffer;
  unsigned i = 0; 
  while (i < size){
      unpin_ptr(local_buffer);
      local_buffer++;
      i ++;
  }
}
