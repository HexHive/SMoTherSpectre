#ifndef PMC_H
#define PMC_H

#include <sys/types.h>
#include <sys/syscall.h>
#include <stdint.h>

typedef struct
{
  uint64_t hexcode;
  const char *name;
} counter;

void setup_pmc(int core, counter *programmables, size_t n_programmables);
void zero_pmc(size_t n_programmables);
void dump_stats(counter *programmables, size_t n_programmables);
void get_stats(uint64_t *ctrs, size_t n_programmables);

void start_pmc();
void stop_pmc();

#endif /* PMC_H */