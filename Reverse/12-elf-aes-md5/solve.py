#!/usr/bin/env python3
"""Solve re3: AES-128-ECB decryption with MD5-derived key."""
import struct
import hashlib
import sys
from Crypto.Cipher import AES

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

print("=" * 60)
print("STEP 1: Extract key derivation source data")
print("=" * 60)

# Source 1: unk_6030C0, 53 bytes
off = va_to_offset(0x6030C0)
src1 = data[off:off+53]
print(f"src1 (unk_6030C0, 53 bytes): {src1.hex()}")

# Source 2: unk_603100, 20 bytes
off = va_to_offset(0x603100)
src2 = data[off:off+20]
print(f"src2 (unk_603100, 20 bytes): {src2.hex()}")

# Source 3: unk_603120, 64 bytes (Base64 alphabet)
off = va_to_offset(0x603120)
src3 = data[off:off+64]
print(f"src3 (unk_603120, 64 bytes): {src3.hex()}")
print(f"  ASCII: {src3.decode('ascii')}")

# Source 4: MD5 T table (dword_4025C0, 256 bytes raw)
off = va_to_offset(0x4025C0)
src4 = data[off:off+256]
print(f"src4 (dword_4025C0, 256 bytes): {src4[:32].hex()}...")

print("\n" + "=" * 60)
print("STEP 2: Compute MD5 chain (sub_40207B)")
print("=" * 60)

# The key derivation function stores results sequentially in a buffer:
# [rbp-0x50]: MD5(src3, 64)     -> v2 (16 bytes)
# [rbp-0x40]: MD5(src2, 20)     -> v3 (16 bytes)
# [rbp-0x30]: MD5(src1, 53)     -> v4 (16 bytes)
# [rbp-0x20]: MD5(src4, 256)    -> v5 (16 bytes)
# Then: MD5(buffer[0:64], 64)   -> AES key (16 bytes)

v2 = hashlib.md5(src3).digest()
v3 = hashlib.md5(src2).digest()
v4 = hashlib.md5(src1).digest()
v5 = hashlib.md5(src4).digest()

print(f"v2 = MD5(src3) = {v2.hex()}")
print(f"v3 = MD5(src2) = {v3.hex()}")
print(f"v4 = MD5(src1) = {v4.hex()}")
print(f"v5 = MD5(src4) = {v5.hex()}")

buffer_64 = v2 + v3 + v4 + v5
print(f"\nCombined buffer (64 bytes): {buffer_64.hex()}")

aes_key = hashlib.md5(buffer_64).digest()
print(f"AES key = MD5(buffer) = {aes_key.hex()}")

print("\n" + "=" * 60)
print("STEP 3: Extract target ciphertext (0x6030A0, 32 bytes)")
print("=" * 60)

off = va_to_offset(0x6030A0)
ciphertext = data[off:off+32]
print(f"Ciphertext: {ciphertext.hex()}")
print(f"  Block 1: {ciphertext[:16].hex()}")
print(f"  Block 2: {ciphertext[16:].hex()}")

print("\n" + "=" * 60)
print("STEP 4: AES-128-ECB Decryption")
print("=" * 60)

cipher = AES.new(aes_key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(f"Plaintext (hex): {plaintext.hex()}")
print(f"Plaintext (ASCII): {plaintext.decode('ascii', errors='replace')}")

# Check if it looks like a flag
try:
    flag = plaintext.decode('ascii')
    print(f"\nFLAG: {flag}")
except:
    print(f"\nPlaintext doesn't decode as clean ASCII, trying other interpretations...")
    # Maybe the AES implementation uses a different state layout?
    # Let's also try with the key as the raw bytes in different orders

    # Try: maybe the buffer order is different
    # Or maybe it's just MD5(v2) (only first 16 bytes hashed)
    for desc, key_attempt in [
        ("MD5(v2 only)", hashlib.md5(v2).digest()),
        ("MD5(v2||v3||v4||v5)", hashlib.md5(v2 + v3 + v4 + v5).digest()),
        ("MD5(v5||v4||v3||v2)", hashlib.md5(v5 + v4 + v3 + v2).digest()),
        ("v2 directly", v2),
        ("v3 directly", v3),
        ("v4 directly", v4),
        ("v5 directly", v5),
    ]:
        cipher2 = AES.new(key_attempt, AES.MODE_ECB)
        pt = cipher2.decrypt(ciphertext)
        try:
            pt_ascii = pt.decode('ascii')
            printable = all(32 <= b < 127 for b in pt)
            print(f"  {desc}: {pt_ascii} {'(printable!)' if printable else ''}")
        except:
            print(f"  {desc}: {pt.hex()} (non-ASCII)")

print("\n" + "=" * 60)
print("STEP 5: Verify - encrypt the plaintext and compare")
print("=" * 60)

cipher_verify = AES.new(aes_key, AES.MODE_ECB)
encrypted = cipher_verify.encrypt(plaintext)
print(f"Re-encrypted: {encrypted.hex()}")
print(f"Target:       {ciphertext.hex()}")
print(f"Match: {encrypted == ciphertext}")
