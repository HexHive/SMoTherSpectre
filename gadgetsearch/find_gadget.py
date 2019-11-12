#!/usr/bin/env python

import os
import sys
import pdb
import numpy
import distorm3
import subprocess
import threading
# import Queue
import multiprocessing as mp
from operator import itemgetter
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class

iaca_start = ''.join([chr(x) for x in (0xbb, 0x6f, 0x00, 0x00, 0x00, 0x64, 0x67, 0x90)])
iaca_end = ''.join([chr(x) for x in (0xbb, 0xde, 0x00, 0x00, 0x00, 0x64, 0x67, 0x90)])
install_dir = os.path.dirname(os.path.abspath(__file__))

flag_ops = ['AAA', 'AAD', 'AAM', 'AAS', 'ADC', 'ADCX', 'ADD', 'ADOX', 'AND', 
            'ANDN', 'ARPL', 'BEXTR', 'BLSI', 'BLSMSK', 'BLSR', 'BSF', 'BSR', 
            'BT', 'BTC', 'BTR', 'BTS', 'BZHI', 'CMP', 'CMPS', 
            'CMPSB', 'CMPSW', 'CMPSD', 'CMPSQ', 'DAA', 'DAS', 'DEC', 'JMP', 
            'KORTESTW', 'KORTESTB', 'KORTESTQ', 'KORTESTD', 'LAR', 'LSL', 
            'LZCNT', 'MUL', 'NEG', 'OR', 'POPCNT', 'PTEST', 'RCL', 'RCR', 
            'ROL', 'ROR', 'SAHF', 'SAL', 'SAR', 'SHL', 'SHR', 'SBB', 'SCAS', 
            'SCASB', 'SCASW', 'SCASD', 'SAL', 'SAR', 'SHL', 'SHR', 'SHLD', 
            'SAL', 'SAR', 'SHL', 'SHR', 'SHRD', 'STAC', 'STC', 'STD', 'STI', 
            'SUB', 'TEST', 'TZCNT', 'VTESTPD', 'VTESTPS', 'XADD', 'XOR', 'XTEST']

unwanted_flag_ops = ['CLC', 'CLD']

jmp_ops = ['JNO', 'JB', 'JAE', 'JZ', 'JNZ', 'JBE', 'JA', 'JS', 'JNS', 'JP', 'JNP', 
            'JL', 'JGE', 'JLE', 'JG']

code_dict = {}
q = []
r = []

def backtrack_jmp(jmp_off):
    targets = [jmp_off]
    setters = set([])

    # print "Looking for source for ", code_dict[jmp_off], " at offset ", jmp_off

    for prev_offset in range(jmp_off - 1, jmp_off - 100, -1):
        if prev_offset < 0: break
        if not prev_offset in code_dict.keys(): continue

        prev_insn = code_dict[prev_offset]
        if not (prev_offset + prev_insn.size) in targets: continue
        
        # print prev_offset, targets, prev_insn

        if prev_insn.mnemonic in flag_ops:
            setters.add(prev_offset)
        else:
            targets.append(prev_offset)

    seqs = []
    for setter in setters:
        seq = []
        # print "Code to jump: "
        while setter != jmp_off:
            insn = code_dict[setter]
            # print hex(insn.address), ":", insn
            setter += insn.size
            seq.append(insn)
        seq.append(code_dict[jmp_off])
        # print hex(jmp_off), ":", code_dict[jmp_off]
        seqs.append(seq)
    return seqs

def print_valid_code(code):
    offset = 0
    while offset < len(code):
        for insn in distorm3.DecomposeGenerator(offset, code[offset:], distorm3.Decode64Bits, distorm3.DF_STOP_ON_FLOW_CONTROL):
            print offset, " : ", insn
            offset += insn.size

def get_port_uv(s_off, offset, code, id):
    # create kernel for iaca
    insns = distorm3.Decompose(s_off, code[offset:], distorm3.Decode64Bits, distorm3.DF_STOP_ON_FLOW_CONTROL)
    if len(insns) == 1: return numpy.zeros(8), 0
    f = open("/tmp/smother.kernel" + str(id), "w")
    f.write(iaca_start)
    for insn in insns[:-1]:
        f.write(insn.instructionBytes)
    f.write(iaca_end)
    f.close()
    # run iaca
    try:
        iaca_stats = subprocess.check_output([os.path.join(install_dir,"iaca"), "-reduceout", "/tmp/smother.kernel" + str(id)], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print "exitcode", e.returncode, "output:", e.output
        return numpy.zeros(8), 0
    # parse iaca output
    port_fingerprint = numpy.zeros(8)
    for line in iaca_stats.split("\n"):
        line = line.split()
        if len(line) > 1 and line[1] == "Cycles":
            port_fingerprint[0] = float(line[3])
            port_fingerprint[1] = float(line[6])
            port_fingerprint[2] = float(line[8])
            port_fingerprint[3] = float(line[11])
            port_fingerprint[4] = float(line[14])
            port_fingerprint[5] = float(line[16])
            port_fingerprint[6] = float(line[18])
            port_fingerprint[7] = float(line[20])
            break
    return port_fingerprint, len(insns)-1

def build_code_dict(code, section, dwarfinfo):
    s_off = section['sh_offset']
    # print_valid_code(code)

    print hex(len(code))
    ## Create a dictionary of valid instructions at all offsets
    for offset in range(len(code)): 
        if offset & 0xfff == 0:
            print hex(offset)
        if code_dict.has_key(offset): continue
        for insn in distorm3.DecomposeGenerator(s_off + offset, code[offset:], distorm3.Decode64Bits, distorm3.DF_STOP_ON_FLOW_CONTROL):
            if insn.valid:
                code_dict[offset] = insn
            offset += insn.size

def process_thread(arg):
    (s_off, idx, code, work_q) = arg
    print "Thread ", idx, " started"
    ret_q = []
    for (jmp_off, jmp_insn) in work_q:
        
        ## For each jump instruction with an immediate target
        ## . find the instruction which set the flag
        ## . rank the gadget for port usage of target and fallthrough 
        print hex(jmp_off), " : ", hex(jmp_insn.address), ": ", jmp_insn
        pf1, pf1size = get_port_uv(s_off, jmp_off+jmp_insn.size, code, idx)
        pf2, pf2size = get_port_uv(s_off, jmp_insn.operands[0].value - s_off, code, idx)
        if pf1size < 3 or pf2size < 3 or pf1size > 80 or pf2size > 80: continue
        
        # Get preceding sequence which sets branch
        seqs = backtrack_jmp(jmp_off)

        # first ranking: port utilization (higher -> better)
        port_utilization = numpy.sum(numpy.abs(pf1-pf2))
        # second ranking: branch length difference (lower -> better)
        length_difference = abs(pf1size-pf2size)
        # third ranking: memory port (2,3,4,7) usage (lower -> better)
        mem_usage = sum([pf1[i] + pf2[i] for i in (2,3,4,7)])

        # print "Processing seqs done on thread ", idx
        for seq in seqs:
            ret_q.append(((port_utilization, length_difference, mem_usage), (pf1, pf1size), (pf2, pf2size), seq))
    print "Thread ", idx, " quitting"
    return ret_q

def process_jumps(section, code):
    s_off = section['sh_offset']
    num_cores = mp.cpu_count()
    core_num = 0
    iterable_q = []
    for i in range (0, num_cores - 1):
        iterable_q.append((s_off, i, code, []))

    print "Processing start"
    comp_cond_branch_fingerprints = []
    # Split list of jumps among threads
    for jmp_off, jmp_insn in code_dict.items():
        if not jmp_insn.mnemonic in jmp_ops: continue
        if jmp_insn.operands[0].type != "Immediate": continue
        target_addr = jmp_insn.operands[0].value
        if (target_addr < s_off) or (target_addr - s_off >= len(code)): continue

        iterable_q[core_num][3].append((jmp_off, jmp_insn))        
        core_num = (core_num + 1) % (num_cores - 1)
        
    #Parallelize work
    pool = mp.Pool(processes = num_cores - 1)
    ret_qs = pool.map(process_thread, iterable_q)
    pool.close()
    pool.join()

    for ret_q in ret_qs:
        for seq in ret_q:
            comp_cond_branch_fingerprints.append(seq)

    # compute rank product
    max_length_difference = max([length_difference for ((port_utilization, length_difference, mem_usage), (pf1, pf1size), (pf2, pf2size), seq) in comp_cond_branch_fingerprints])
    max_mem_usage = max([mem_usage for ((port_utilization, length_difference, mem_usage), (pf1, pf1size), (pf2, pf2size), seq) in comp_cond_branch_fingerprints])
    comp_cond_branch_utilization = list()
    for ((port_utilization, length_difference, mem_usage), (pf1, pf1size), (pf2, pf2size), seq) in comp_cond_branch_fingerprints:
        rank = (port_utilization*(max_length_difference-length_difference)*(max_mem_usage-mem_usage))**(1.0/3)
        comp_cond_branch_utilization.append((rank, (pf1, pf1size), (pf2, pf2size), seq))
    print "Gadgets:", len(comp_cond_branch_utilization)
    comp_cond_branch_utilization = sorted(comp_cond_branch_utilization, key=itemgetter(0))
    for rank, (pf1, pf1size), (pf2, pf2size), seq in comp_cond_branch_utilization:
        if rank != 0.0:
            print "-------------------------"
            for insn in seq:
                print hex(insn.address), insn
            print "Length branch 1:", pf1size, "utilization:", pf1
            print "Length branch 2:", pf2size, "utilization:", pf2
            print "Rank:", rank

def main():
    with open(sys.argv[1], 'rb') as f:

        elffile = ELFFile(f)
        dwarfinfo = None
        if elffile.has_dwarf_info():
            dwarfinfo = elffile.get_dwarf_info()

        for section in elffile.iter_sections():
            if section.name.startswith('.text'):
                print "**** Found text section at", hex(section["sh_offset"]), "****"
                code = section.data()
                # code = code[0xf0000:0x100000]
                #reg_indirect, mem_indirect = find_bti(code, section, dwarfinfo)
                #print "Found", reg_indirect, "register and", mem_indirect, "memory indirect control flow transfers"
                build_code_dict(code, section, dwarfinfo)
                process_jumps(section, code)

if __name__ == '__main__':
    main()
