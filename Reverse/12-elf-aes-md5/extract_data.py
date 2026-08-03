#!/usr/bin/env python3
"""Extract all key data from re3 ELF and decode self-modifying code."""
import struct
import hashlib
import sys
from capstone import *

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ELF_PATH = r'C:\Users\j520x\.local\share\TeleAgent\TeleAgent的工作空间\.temp\re3'

with open(ELF_PATH, 'rb') as f:
    data = f.read()

# VA to file offset mapping:
# Code segment: VA 0x400000 -> offset 0x0
# Data segment: VA 0x602E10 -> offset 0x2E10  => VA - 0x600000 = offset

def va_to_offset(va):
    if 0x400000 <= va < 0x400000 + 0x2CF4:
        return va - 0x400000
    elif 0x602E10 <= va < 0x602E10 + 0x350:
        return va - 0x600000
    else:
        return None

print("=" * 80)
print("1. EXTRACTING AES S-BOX (byte_4023A0, 256 bytes)")
print("=" * 80)
off = va_to_offset(0x4023A0)
sbox = list(data[off:off+256])
print(f"File offset: 0x{off:X}")
print(f"First 32 bytes: {sbox[:32]}")
print(f"Full S-box: {bytes(sbox).hex()}")

print("\n" + "=" * 80)
print("2. EXTRACTING AES INV S-BOX (byte_4024A0, 256 bytes)")
print("=" * 80)
off = va_to_offset(0x4024A0)
inv_sbox = list(data[off:off+256])
print(f"File offset: 0x{off:X}")
print(f"First 32 bytes: {inv_sbox[:32]}")
print(f"Full InvS-box: {bytes(inv_sbox).hex()}")

# Verify S-box / InvS-box relationship
sbox_ok = all(inv_sbox[sbox[i]] == i for i in range(256))
print(f"S-box/InvS-box consistency: {sbox_ok}")

# Check if it's standard AES S-box
std_sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
print(f"Standard AES S-box match: {sbox == std_sbox}")

print("\n" + "=" * 80)
print("3. EXTRACTING AES RCON (byte_4025A0)")
print("=" * 80)
off = va_to_offset(0x4025A0)
rcon = list(data[off:off+32])  # Read more than needed
print(f"File offset: 0x{off:X}")
print(f"Rcon data: {rcon[:16]}")

print("\n" + "=" * 80)
print("4. EXTRACTING MD5 T TABLE (dword_4025C0, 64 x 4 bytes)")
print("=" * 80)
off = va_to_offset(0x4025C0)
md5_t = []
for i in range(64):
    val = struct.unpack_from('<I', data, off + i*4)[0]
    md5_t.append(val)
print(f"File offset: 0x{off:X}")
print(f"First 8 T values: {[hex(x) for x in md5_t[:8]]}")
# Standard MD5 T table
std_md5_t = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]
print(f"Standard MD5 T table match: {md5_t == std_md5_t}")

print("\n" + "=" * 80)
print("5. EXTRACTING MD5 SHIFT TABLE (dword_4026C0, 64 x 4 bytes)")
print("=" * 80)
off = va_to_offset(0x4026C0)
md5_s = []
for i in range(64):
    val = struct.unpack_from('<I', data, off + i*4)[0]
    md5_s.append(val)
print(f"File offset: 0x{off:X}")
print(f"Shift values: {md5_s}")
std_md5_s = [
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
]
print(f"Standard MD5 shift table match: {md5_s == std_md5_s}")

print("\n" + "=" * 80)
print("6. EXTRACTING KEY DERIVATION SOURCE DATA")
print("=" * 80)

# unk_6030C0 - source 1, 53 bytes
off = va_to_offset(0x6030C0)
src1 = data[off:off+53]
print(f"unk_6030C0 (53 bytes, file offset 0x{off:X}):")
print(f"  Hex: {src1.hex()}")
print(f"  ASCII: {src1.decode('ascii', errors='replace')}")

# unk_603100 - source 2, 20 bytes
off = va_to_offset(0x603100)
src2 = data[off:off+20]
print(f"unk_603100 (20 bytes, file offset 0x{off:X}):")
print(f"  Hex: {src2.hex()}")
print(f"  ASCII: {src2.decode('ascii', errors='replace')}")

# unk_603120 - source 3, 64 bytes
off = va_to_offset(0x603120)
src3 = data[off:off+64]
print(f"unk_603120 (64 bytes, file offset 0x{off:X}):")
print(f"  Hex: {src3.hex()}")
print(f"  ASCII: {src3.decode('ascii', errors='replace')}")

print("\n" + "=" * 80)
print("7. COMPUTING AES KEY (sub_40207B logic)")
print("=" * 80)

# sub_40207B logic:
# v2 = MD5(unk_603120, 0x40=64)   -> 16 bytes
# v3 = MD5(unk_603100, 0x14=20)   -> 16 bytes
# v4 = MD5(unk_6030C0, 0x35=53)   -> 16 bytes
# v5 = MD5(dword_4025C0, 0x100=256) -> 16 bytes  (MD5 T table itself, 64*4=256 bytes)
# output = MD5(v2, 0x40=64) -> 16 bytes (final AES key)

v2 = hashlib.md5(src3).digest()  # MD5(64 bytes)
v3 = hashlib.md5(src2).digest()  # MD5(20 bytes)
v4 = hashlib.md5(src1).digest()  # MD5(53 bytes)

# v5 = MD5(dword_4025C0, 256 bytes) - MD5 T table raw data
off_t = va_to_offset(0x4025C0)
t_table_raw = data[off_t:off_t+256]
v5 = hashlib.md5(t_table_raw).digest()

print(f"v2 = MD5(src3) = {v2.hex()}")
print(f"v3 = MD5(src2) = {v3.hex()}")
print(f"v4 = MD5(src1) = {v4.hex()}")
print(f"v5 = MD5(T_table) = {v5.hex()}")

# Final key: MD5(v2, 64 bytes) — but v2 is only 16 bytes
# Wait... the decompiled code says MD5(v2, 0x40=64)
# Maybe v2 points to a buffer that includes v2, v3, v4, v5 (16*4 = 64 bytes)?
# Let's try: the output address is unk_603170, and the derivation might write
# v2,v3,v4,v5 sequentially to a buffer, then MD5 that 64-byte buffer

# Option A: MD5 of v2 alone (treating 64 as an error or meaning 16)
key_option_a = hashlib.md5(v2).digest()
print(f"\nOption A: MD5(v2, 16 bytes) = {key_option_a.hex()}")

# Option B: MD5 of v2||v3||v4||v5 (64 bytes total)
combined = v2 + v3 + v4 + v5
key_option_b = hashlib.md5(combined).digest()
print(f"Option B: MD5(v2||v3||v4||v5, 64 bytes) = {key_option_b.hex()}")

# Option C: Maybe the buffer at the output address is filled with v2 (padded to 64)
# Or maybe the function writes v2 to output, then MD5(output, 64) where output
# is a larger buffer that was pre-filled

# Let's also check: maybe unk_603170 is actually in .data (not BSS) and has pre-initialized content
# .data: addr=0x603080, size=0xE0 -> covers 0x603080 to 0x603160
# .bss: addr=0x603160, size=0x20 -> covers 0x603160 to 0x603180
# 0x603170 is in .bss, so it's zero-initialized at startup

# But wait - the key derivation function sub_40207B takes &unk_603170 as argument
# and fills it. Let me reconsider: maybe the function stores v2,v3,v4,v5 sequentially
# starting at the output address, creating a 64-byte buffer, then MD5s that.

print(f"\nOption C: If v2,v3,v4,v5 stored at output buffer then MD5(buffer, 64):")
print(f"  Same as Option B: {key_option_b.hex()}")

print("\n" + "=" * 80)
print("8. DECODING SELF-MODIFYING CODE (sub_402219, 224 bytes XOR 0x99)")
print("=" * 80)

# sub_402219 is at VA 0x402219
# Looking at main: the decode loop XORs 0xDF+1 = 0xE0 = 224 bytes starting at sub_402219
off_smc = va_to_offset(0x402219)
smc_encoded = data[off_smc:off_smc+224]
smc_decoded = bytes(b ^ 0x99 for b in smc_encoded)

print(f"File offset: 0x{off_smc:X}")
print(f"Encoded first 16 bytes: {smc_encoded[:16].hex()}")
print(f"Decoded first 16 bytes: {smc_decoded[:16].hex()}")

# Check if decoded starts with valid x86-64 instructions
print(f"\nDecoded (hex dump):")
for i in range(0, len(smc_decoded), 16):
    hex_str = ' '.join(f'{b:02x}' for b in smc_decoded[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in smc_decoded[i:i+16])
    print(f"  0x{0x402219+i:08X}: {hex_str:<48s} {ascii_str}")

# Disassemble decoded code
print(f"\nDisassembly of decoded function:")
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for insn in md.disasm(smc_decoded, 0x402219):
    print(f"  0x{insn.address:08X}: {insn.bytes.hex():<20s} {insn.mnemonic:<10s} {insn.op_str}")

print("\n" + "=" * 80)
print("9. ALSO CHECK: What's around the sub_402219 area in the original ELF")
print("=" * 80)
# Let's also see what the main function looks like around the call to decode
# and check the exact decode loop
off_main = va_to_offset(0x402126)
main_code = data[off_main:off_main+0xF0]  # ~240 bytes should cover main
print(f"main function at 0x402126, disassembly:")
for insn in md.disasm(main_code, 0x402126):
    print(f"  0x{insn.address:08X}: {insn.bytes.hex():<20s} {insn.mnemonic:<10s} {insn.op_str}")
    if insn.mnemonic == 'ret' or (insn.mnemonic == 'leave' and insn.address > 0x402180):
        break

print("\n" + "=" * 80)
print("10. DUMP .data SECTION (0x603080 - 0x603160, 224 bytes)")
print("=" * 80)
off_data = va_to_offset(0x603080)
data_section = data[off_data:off_data+0xE0]
for i in range(0, len(data_section), 16):
    va = 0x603080 + i
    hex_str = ' '.join(f'{b:02x}' for b in data_section[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_section[i:i+16])
    print(f"  0x{va:08X}: {hex_str:<48s} {ascii_str}")
