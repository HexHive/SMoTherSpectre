#include <sys/mman.h>
#include <sys/stat.h>        
#include <sys/types.h>
#include <fcntl.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "synch.h"

#define SHMEM_FILENAME "smotherspectre_poc_shm"

void synch_create() {

  int shm_fd = shm_open(SHMEM_FILENAME, O_CREAT | O_CLOEXEC | O_EXCL | O_RDWR, 
                        S_IRUSR | S_IWUSR);
  VERIFY(shm_fd >= 0, "Shared memory open failed");

  size_t shm_sz = 2 * sizeof(unsigned long int);
  VERIFY(ftruncate(shm_fd, shm_sz) != -1, "Ftruncate failed");

  void *shmem = mmap(NULL, shm_sz, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  VERIFY(shmem != MAP_FAILED, "Shared memory mmap failed");

  /* Initialize shared memory with zeroes */
  memset(shmem, 0, shm_sz);
}

int synch_connect(synch *s) {

  int shm_fd = shm_open(SHMEM_FILENAME, O_RDWR, 0);
  VERIFY(shm_fd >= 0, "Shared memory open failed");

  /* Then mmap area */
  size_t shm_sz = 2 * sizeof(unsigned long int);
  s->base = mmap(NULL, shm_sz, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  VERIFY(s->base != MAP_FAILED, "Shared memory re-mmap failed");
}

void synch_destroy() {
  VERIFY(shm_unlink(SHMEM_FILENAME) == 0, "Shared memory unlink failed");
}

void synch_sync(synch *s){
  unsigned long int *addr = s->base;

  asm volatile(
      "lock incl %[addr];"
      "again%=:;"
      "movl %[addr], %%eax;"
      "andl $1, %%eax;"
      "jne again%=;"
      : [addr] "+m" (addr[0])
      :
      : "memory", "rax"
    );
  asm volatile(
      "lock incl %[addr];"
      "again%=:;"
      "movl %[addr], %%eax;"
      "andl $1, %%eax;"
      "jne again%=;"
      : [addr] "+m" (addr[1])
      :
      : "memory", "rax"
    );
}