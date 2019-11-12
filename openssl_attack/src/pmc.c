#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "pmc.h"
#include "util.h"


/************ Utils to read/write msr files **********************/
void write_to_IA32_PERF_GLOBAL_CTRL(int msr_fd, uint64_t val)
{
  VERIFY(pwrite(msr_fd, &val, sizeof(val), 0x38F) == sizeof(val), 
         "write_to_IA32_PERF_GLOBAL_CTRL");
}

void write_to_IA32_PMCi(int msr_fd, int i, uint64_t val)
{
  VERIFY(pwrite(msr_fd, &val, sizeof(val), 0xC1 + i) == sizeof(val), 
         "write_to_IA32_PMCi");
}

uint64_t read_IA32_PMCi(int msr_fd, int i)
{
  uint64_t toret = -1;
  VERIFY(pread(msr_fd, &toret, sizeof(toret), 0xC1 + i) == sizeof(toret), 
               "read_IA32_PMCi");

  return toret;
}

void write_to_IA32_PERFEVTSELi(int msr_fd, int i, uint64_t val)
{
  VERIFY(pwrite(msr_fd, &val, sizeof(val), 0x186 + i) == sizeof(val),
                "write_to_IA32_PERFEVTSELi");
}
/***********************************************************/

volatile int msr_fd;

void setup_pmc(int core, counter *programmables, size_t n_programmables)
{

  char msr_path[] = "/dev/cpu/*/msr";                                     
  msr_path[9] = '0' + core;                                          
  msr_fd = open(msr_path, O_RDWR);                                            
  VERIFY(msr_fd >= 0, "open");                                                       
                                                                            
  /* DISABLE ALL COUNTERS */                                              
  write_to_IA32_PERF_GLOBAL_CTRL(msr_fd, 0ull);                               
                                                                          
  /* PROGRAM ALL PMCs */                                                  
  unsigned i;
  for (i = 0; i < n_programmables; i++)    
      write_to_IA32_PERFEVTSELi(msr_fd, i, programmables[i].hexcode);           
                                                                          
  int rv = lseek(msr_fd, 0x38F, SEEK_SET);                                       
  VERIFY(rv == 0x38F, "lseek");                                                      
}


__attribute__((always_inline)) 
inline void zero_pmc(size_t n_programmables){
#if USE_PMC
  unsigned i;
  for(i = 0; i < n_programmables; i++)   
    write_to_IA32_PMCi(msr_fd, i, 0ull);   
#endif
}


__attribute__((always_inline)) 
inline void start_pmc() {
#if USE_PMC
  uint64_t val = 15ull | (7ull << 32);
  asm("mov %[write],     %%eax;"
      "mov %[fd],        %%edi;"
      "mov %[val],       %%rsi;"
      "mov $8,           %%edx;"
      "syscall;"
      :
      : [write] "i" (SYS_write),
        [val]   "r" (&val),
        [fd]    "m" (msr_fd)
      : "eax", "edi", "rsi", "edx");
#endif
}


__attribute__((always_inline)) 
inline void stop_pmc() {
#if USE_PMC
  uint64_t val = 0;
  asm("mov %[write],     %%eax;"
      "mov %[fd],        %%edi;"
      "mov %[val],       %%rsi;"
      "mov $8,           %%edx;"
      "syscall;"
      :
      : [write] "i" (SYS_write),
        [val]   "r" (&val),
        [fd]    "m" (msr_fd)
      : "eax", "edi", "rsi", "edx");
#endif
}


void dump_stats(counter *programmables, size_t n_programmables)  {
  unsigned i;
  for (i = 0; i < n_programmables; i++)    
      printf(",%s=%9ld", programmables[i].name, read_IA32_PMCi(msr_fd, i)); 
}


void get_stats(uint64_t *ctrs, size_t n_programmables){
  unsigned i;
  for(i = 0; i < n_programmables; i++)
    ctrs[i] = read_IA32_PMCi(msr_fd, i);
}