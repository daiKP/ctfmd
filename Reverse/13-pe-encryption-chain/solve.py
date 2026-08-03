#!/usr/bin/env python3
"""Solve re4.exe - with corrected target (include null byte from strcpy)."""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Corrected target: Buf1[5] + v11[0..3]("<xh\0") + v11[4..23]
# The null terminator from strcpy(v11, "<xh") is part of the target!
target = bytes([
    0xE8, 0x80, 0x84, 0x08, 0x18,       # Buf1[0..4] = {-24, 0x80, -124, 8, 24}
    0x3C, 0x78, 0x68, 0x00,               # v11[0..3] = "<xh\0" (strcpy null terminator!)
    0x70, 0x7C, 0x94, 0xC8, 0xE0, 0x10,   # v11[4..9] = {112, 124, -108, -56, -32, 16}
    0xEC, 0xB4, 0xAC, 0x68, 0xA8, 0x0C,   # v11[10..15] = {-20, -76, -84, 104, -88, 12}
    0x1C, 0x90, 0xCC, 0x54, 0x3C, 0x14,   # v11[16..21] = {28, -112, -52, 84, 60, 20}
    0xDC, 0x30                             # v11[22..23] = {-36, 48}
])

KEY = b"NewStarCTF"

# Build multiply-by-52 reverse map
mul52_map = {}
for x in range(256):
    val = (x * 52) % 256
    if val not in mul52_map:
        mul52_map[val] = []
    mul52_map[val].append(x)

def forward_caesar(byte_val):
    b = byte_val & 0xFF
    if 0x41 <= b <= 0x5A:
        return (b - 52) % 26 + 65
    elif 0x61 <= b <= 0x7A:
        return (b - 89) % 26 + 97
    elif 0x30 <= b <= 0x39:
        return (b - 45) % 10 + 48
    return b

def reverse_caesar(byte_val):
    b = byte_val & 0xFF
    results = []
    for orig in range(0x41, 0x5B):  # A-Z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x61, 0x7B):  # a-z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x30, 0x3A):  # 0-9
        if forward_caesar(orig) == b:
            results.append(orig)
    return results

print(f"Target ({len(target)} bytes): {target.hex()}")
print()

flag_bytes = []
for i in range(len(target)):
    t = target[i]
    solutions = []
    
    if t not in mul52_map:
        print(f"  Position {i:2d}: 0x{t:02X} -> NO stage4 solution!")
        flag_bytes.append(ord('?'))
        continue
    
    for s4 in mul52_map[t]:
        s3 = (~s4) & 0xFF           # reverse NOT
        s2 = (s3 - KEY[i % len(KEY)]) & 0xFF  # reverse add key
        candidates = reverse_caesar(s2)
        for c in candidates:
            if (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39):
                solutions.append(c)
    
    if len(solutions) == 1:
        flag_bytes.append(solutions[0])
        ch = chr(solutions[0])
        print(f"  Position {i:2d}: 0x{t:02X} -> '{ch}'")
    elif len(solutions) > 1:
        # Prefer letters
        letters = [s for s in solutions if (0x41 <= s <= 0x5A) or (0x61 <= s <= 0x7A)]
        pick = (letters or solutions)[0]
        flag_bytes.append(pick)
        print(f"  Position {i:2d}: 0x{t:02X} -> '{chr(pick)}' (candidates: {[chr(s) for s in solutions]})")
    else:
        print(f"  Position {i:2d}: 0x{t:02X} -> NO SOLUTION!")
        flag_bytes.append(ord('?'))

flag = bytes(flag_bytes).decode('ascii', errors='replace')
print(f"\nFlag: {flag}")
print(f"Full flag: flag{{{flag}}}")

# Verification
print("\n--- Verification ---")
data = list(flag_bytes)
for i in range(len(data)):
    data[i] = forward_caesar(data[i])
for i in range(len(data)):
    data[i] = (data[i] + KEY[i % len(KEY)]) & 0xFF
for i in range(len(data)):
    data[i] = (~data[i]) & 0xFF
for i in range(len(data)):
    data[i] = (data[i] * 52) & 0xFF

encrypted = bytes(data)
print(f"Encrypted: {encrypted.hex()}")
print(f"Target:    {target.hex()}")
print(f"Match: {encrypted == target}")

if encrypted != target:
    for i in range(len(target)):
        if encrypted[i] != target[i]:
            print(f"  Mismatch at position {i}: got 0x{encrypted[i]:02X}, expected 0x{target[i]:02X}")
