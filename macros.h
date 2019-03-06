#define NOP "nop;"
#define NOP1 NOP
#define NOP2 NOP1 NOP1
#define NOP4 NOP2 NOP2
#define NOP8 NOP4 NOP4
#define NOP16 NOP8 NOP8
#define NOP32 NOP16 NOP16
#define NOP64 NOP32 NOP32
#define NOP128 NOP64 NOP64
#define NOP256 NOP128 NOP128
#define NOP512 NOP256 NOP256
#define NOP1024 NOP512 NOP512
#define NOP2048 NOP1024 NOP1024
#define NOP4096 NOP2048 NOP2048

#define JMPNEXT \
    asm("cmp    %%rax,%%rax;" \
        "jle label%=;" \
        "label%=:;" \
        : : :);
        
#define JMPNEXT1 JMPNEXT
#define JMPNEXT2 JMPNEXT1 JMPNEXT1
#define JMPNEXT4 JMPNEXT2 JMPNEXT2
#define JMPNEXT8 JMPNEXT4 JMPNEXT4
#define JMPNEXT16 JMPNEXT8 JMPNEXT8
#define JMPNEXT32 JMPNEXT16 JMPNEXT16
#define JMPNEXT64 JMPNEXT32 JMPNEXT32
#define JMPNEXT128 JMPNEXT64 JMPNEXT64
#define JMPNEXT256 JMPNEXT128 JMPNEXT128
#define JMPNEXT512 JMPNEXT256 JMPNEXT256
#define JMPNEXT1024 JMPNEXT512 JMPNEXT512
#define JMPNEXT2048 JMPNEXT1024 JMPNEXT1024
#define JMPNEXT4096 JMPNEXT2048 JMPNEXT2048

#define SET_GP_REGISTERS(source) asm ( \
      "mov %0, %%r8;"  \
      "mov %1, %%r9;"  \
      "mov %2, %%r10;" \
      "mov %3, %%r11;" \
      "mov %4, %%rbx;" \
      "mov %5, %%rcx;" \
      : \
      : "r" ((source)[0]), "r"((source)[1]), "r"((source)[2]), \
        "r"((source)[3]), "r"((source)[4]), "r"((source)[5]) \
      : "r8", "r9", "r10", "r11", "rbx", "rcx" \
      );

#define CRC32_all asm volatile( \
        "crc32 %%r8, %%r8;" \
        "crc32 %%r9, %%r9;" \
        "crc32 %%r10, %%r10;" \
        "crc32 %%r11, %%r11;" \
        "crc32 %%rbx, %%rbx;" \
        "crc32 %%rcx, %%rcx;" \
        ::: "r8", "r9", "r10", "r11", "rbx", "rcx");

#define CRC321 CRC32_all
#define CRC322 CRC321 CRC321
#define CRC324 CRC322 CRC322
#define CRC328 CRC324 CRC324
#define CRC3216 CRC328 CRC328
#define CRC3232 CRC3216 CRC3216
#define CRC3264 CRC3232 CRC3232
#define CRC32128 CRC3264 CRC3264
#define CRC32256 CRC32128 CRC32128
#define CRC32512 CRC32256 CRC32256
#define CRC321024 CRC32512 CRC32512
#define CRC322048 CRC321024 CRC321024
#define CRC324096 CRC322048 CRC322048

#define OR_all asm volatile( \
    "or %%r9, %%r8;" \
    "or %%r10, %%r9;" \
    "or %%r11, %%r10;" \
    "or %%r8, %%r11;" \
    "or %%rbx, %%r9;" \
    "or %%rcx, %%r10;" \
    ::: "r8", "r9", "r10", "r11", "rbx", "rcx");

#define OR1 OR_all
#define OR2 OR1 OR1
#define OR4 OR2 OR2
#define OR8 OR4 OR4
#define OR16 OR8 OR8
#define OR32 OR16 OR16
#define OR64 OR32 OR32
#define OR128 OR64 OR64
#define OR256 OR128 OR128
#define OR512 OR256 OR256
#define OR1024 OR512 OR512
#define OR2048 OR1024 OR1024
#define OR4096 OR2048 OR2048
