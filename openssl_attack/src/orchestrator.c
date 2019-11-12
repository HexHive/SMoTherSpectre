#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "synch.h"
#include "util.h"

int main(int argc, char **argv) {
  int nprocs;
  pid_t pida, pidv, pid, status;
  char core[2] = {'0', 0};

  nprocs = get_nprocs();
  printf("%p \n", main);

  /* Create shmem for synchronization */
  synch_create();

  /* Launch attacker */
  pida = fork();
  VERIFY(pida >= 0, "Forking attacker failed");
  if(pida == 0){
    core[0] = '0' + CORE0;
    /* Child exec's attacker process */
    char *args[] = {"attack", "a", core, NULL};
    VERIFY(execv("./attack", args) != -1, "Executing attacker failed");
  }

  /* Launch victim */
  pidv = fork();
  VERIFY(pidv >= 0, "Forking victim failed");
  if(pidv == 0){
    core[0] = '0' + CORE1;
    /* Child exec's victim process */
    char *args[] = {"victim", "v", core, NULL};
    VERIFY(execv("./victim", args) != -1, "Executing victim failed");
  }
  
  /* Assuming clean exit */
  pid = waitpid(pida, &status, 0);
  pid = waitpid(pidv, &status, 0);

  synch_destroy();

}