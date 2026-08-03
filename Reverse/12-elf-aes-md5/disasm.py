#!/usr/bin/env python3
"""Disassemble key functions to determine AES mode and key derivation."""
import struct
import sys
from capstone import *

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ELF_PATH = r'C:\Users\j520x\.local\share\TeleAgent\TeleAgent的工作空间\.temp\re3'

with open(ELF_PATH, 'rb') as f:
    data = f.read()

def va_to_offset(va):
    if 0x400000 <= va < 0x400000 + 0x2CF4:
        return va - 0x400000
    elif 0x602E10 <= va < 0x602E10 + 0x350:
        return va - 0x600000
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def disasm_func(name, va, max_size=0x300):
    off = va_to_offset(va)
    code = data[off:off+max_size]
    print(f"\n{'='*80}")
    print(f"FUNCTION: {name} @ 0x{va:08X} (file offset 0x{off:X})")
    print(f"{'='*80}")
    for insn in md.disasm(code, va):
        print(f"  0x{insn.address:08X}: {insn.bytes.hex():<24s} {insn.mnemonic:<12s} {insn.op_str}")
    print()

# 1. The check function calls 0x400a71 and 0x40196e
# Let's see what's at these addresses

# 0x400a71 - might be AES key expansion/init
disasm_func("sub_400A71 (AES init/key expansion)", 0x400A71, 0x200)

# 0x40196e - the encryption function called twice on input halves
disasm_func("sub_40196E (encrypt 16 bytes)", 0x40196E, 0x100)

# 3. sub_40207B - key derivation via MD5
disasm_func("sub_40207B (key derivation)", 0x40207B, 0x1A0)

# 4. Also check sub_401828 (AES Encrypt) and sub_401A04 (AES-CBC Encrypt)
# to understand which one sub_40196E calls
disasm_func("sub_401828 (AES Encrypt block)", 0x401828, 0xA0)

# 5. Also sub_401A04 - AES-CBC
disasm_func("sub_401A04 (AES-CBC Encrypt)", 0x401A04, 0x90)

# 6. sub_401A90 - AES-CBC Decrypt
disasm_func("sub_401A90 (AES-CBC Decrypt)", 0x401A90, 0xB0)
