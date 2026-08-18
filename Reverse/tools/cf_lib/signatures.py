#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — 密码算法常量签名数据库
========================================

CTF 逆向辅助工具：定义密码算法的常量签名。
每种签名包含：算法名、常量字节序列、偏移/对齐约束、描述。

作者：CTF 解题笔记本项目
版本：1.0
"""

import struct

# ============================================================
# AES S-box (256 bytes)
# ============================================================
AES_SBOX = bytes([
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
])

# AES Inverse S-box (256 bytes)
AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
])

# AES Rcon (11 entries, 4 bytes each, but only first byte matters)
AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])

# AES GF(2^8) multiplication tables (used by T-tables)
# T-tables 0 (1024 bytes each)
AES_T0 = b''.join(struct.pack('>I', val) for val in [
    0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
    0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
])  # 前 4 项足以指纹

# ============================================================
# DES / 3DES 常量
# ============================================================
# DES IP (Initial Permutation) table, stored as 6-bit index values packed in bytes
# More reliable: DES S-boxes (8 boxes × 64 entries)
DES_SBOX1 = bytes([
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
])

DES_SBOX2 = bytes([
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
])

# DES PC-1 (Permuted Choice 1) - 8 bytes
# DES per-round shift schedule as a pattern
DES_KEY_SHIFT = bytes([1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1])

# ============================================================
# MD5 常量
# ============================================================
# MD5 init values (4 × 4 bytes, little-endian)
MD5_INIT = struct.pack('<4I', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

# MD5 T table (64 × 4 bytes, little-endian) — 前 8 项作为签名
MD5_T = struct.pack('<8I', 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                           0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501)

# MD5 shift table (64 × 4 bytes or bytes) — 作为 64 个 uint32
MD5_SHIFT_U32 = struct.pack('<16I', 7, 12, 17, 22, 7, 12, 17, 22,
                                   7, 12, 17, 22, 7, 12, 17, 22)

# ============================================================
# SHA-1 常量
# ============================================================
# SHA-1 init (5 × 4 bytes, big-endian)
SHA1_INIT = struct.pack('>5I', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# SHA-1 K constants (4 values)
SHA1_K = struct.pack('>4I', 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)

# ============================================================
# SHA-256 常量
# ============================================================
# SHA-256 init (8 × 4 bytes, big-endian)
SHA256_INIT = struct.pack('>8I', 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

# SHA-256 K table (64 × 4 bytes, big-endian) — 前 8 项作为签名
SHA256_K = struct.pack('>8I', 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                              0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)

# ============================================================
# SHA-512 常量
# ============================================================
# SHA-512 init (8 × 8 bytes, big-endian)
SHA512_INIT = struct.pack('>8Q', 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)

# SHA-512 K table (80 × 8 bytes, big-endian) — 前 4 项作为签名
SHA512_K = struct.pack('>4Q', 0x428a2f98d728ae22, 0x7137449123ef65cd,
                             0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc)

# ============================================================
# SHA-384 常量
# ============================================================
SHA384_INIT = struct.pack('>8Q', 0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                 0x9159015a3070dd17, 0x152fecd8f70e5939,
                                 0x67332667ffc00b31, 0x8eb44a8768581511,
                                 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4)

# ============================================================
# SHA-224 常量
# ============================================================
SHA224_INIT = struct.pack('>8I', 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                                   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4)

# ============================================================
# CRC32 多项式
# ============================================================
# CRC32 reverse polynomial (most common: 0xEDB88320)
CRC32_POLY_LE = struct.pack('<I', 0xEDB88320)
CRC32_POLY_BE = struct.pack('>I', 0x04C11DB7)

# CRC32 table first 4 entries (little-endian, reverse poly)
CRC32_TABLE_FIRST4 = struct.pack('<4I', 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)

# ============================================================
# TEA / XTEA / XXTEA
# ============================================================
TEA_DELTA = struct.pack('>I', 0x9E3779B9)

# ============================================================
# RC5 / RC6
# ============================================================
RC5_P32 = struct.pack('<I', 0xB7E15163)
RC5_Q32 = struct.pack('<I', 0x9E3779B9)
RC5_P16 = struct.pack('<H', 0xB7E1)
RC5_Q16 = struct.pack('<H', 0x9E37)

# ============================================================
# Blowfish 常量
# ============================================================
# Blowfish P-array (18 entries), 前 4 项 (big-endian)
BLOWFISH_P_FIRST4 = struct.pack('>4I', 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)

# Blowfish S-box 0 first 4 entries (big-endian)
BLOWFISH_S0_FIRST4 = struct.pack('>4I', 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7)

# ============================================================
# CAST5 / CAST-128
# ============================================================
CAST5_S1_FIRST4 = struct.pack('>4I', 0x30FB40D4, 0x9FA0FF9B, 0x6BECCD2F, 0x3F258C7A)

# ============================================================
# ChaCha20 / Salsa20
# ============================================================
# ChaCha20 constants: "expand 32-byte k" as 4 uint32 (little-endian)
CHACHA20_CONST = struct.pack('<4I', 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

# Salsa20 same constants
SALSA20_CONST = CHACHA20_CONST  # same sigma constants

# ============================================================
# Serpent
# ============================================================
# Serpent S-box is input-indexed; use phi constant instead
SERPENT_PHI = struct.pack('>I', 0x9E3779B9)  # same as TEA delta, different context

# ============================================================
# Twofish
# ============================================================
# Twofish MDS matrix multiply constant / key S-box fingerprint
# Q-permutation tables (0 and 1), each 256 entries
# Use first 8 bytes of Q0 as fingerprint
TWOFISH_Q0_FIRST8 = bytes([0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76])

# ============================================================
# Camellia
# ============================================================
CAMELLIA_SIGMA1 = struct.pack('>2I', 0xA09E667F, 0x3BCC908B)
CAMELLIA_SIGMA2 = struct.pack('>2I', 0xB67AE858, 0x4CAA73B2)

# ============================================================
# SEED (Korean block cipher)
# ============================================================
SEED_SBOX0_FIRST4 = bytes([0xA9, 0x85, 0x8F, 0x0B])

# ============================================================
# Whirlpool
# ============================================================
# Whirlpool S-box first 8 bytes
WHIRLPOOL_SBOX_FIRST8 = bytes([0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F])

# ============================================================
# HMAC constants
# ============================================================
HMAC_IPAD = bytes([0x36] * 8)  # 8 consecutive 0x36
HMAC_OPAD = bytes([0x5c] * 8)  # 8 consecutive 0x5c

# ============================================================
# RIPEMD-160
# ============================================================
RIPEMD160_INIT = struct.pack('<5I', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# ============================================================
# SM3 (Chinese national hash)
# ============================================================
SM3_IV = struct.pack('>8I', 0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                              0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)

# SM3 T constants: T0=0x79CC4519 in rounds 0-15, T1=0x7A879D8A in rounds 16-63
SM3_T0 = struct.pack('>I', 0x79CC4519)
SM3_T1 = struct.pack('>I', 0x7A879D8A)

# ============================================================
# SM4 (Chinese national block cipher)
# ============================================================
SM4_SBOX = bytes([
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x4B,
])

# SM4 FK constants
SM4_FK = struct.pack('>3I', 0xA3B1BAC6, 0x56AA3350, 0x677D9197)  # 3 of 4 (4th: 0xB27022DC)

# SM4 CK constants (32 × 4 bytes), 前 4 项
SM4_CK_FIRST4 = struct.pack('>4I', 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269)

# ============================================================
# RC4 KSA pattern (no constant, detected by disasm)
# ============================================================
# RC4 has no fixed constants, detected via disasm pattern:
# for i in 0..255: S[i] = i
# This is a sequence: 00 01 02 03 ... FF in memory
RC4_IDENTITY_SBOX = bytes(range(256))  # 00 01 02 ... FF


# ============================================================
# 签名注册表
# ============================================================

class CryptoSignature:
    """单个密码算法常量签名"""

    def __init__(self, algo, component, pattern, length=None,
                 byte_order=None, alignment=1, confidence='high',
                 description=''):
        self.algo = algo              # 算法名，如 'AES'
        self.component = component    # 组件名，如 'S-box'
        self.pattern = pattern        # bytes，要搜索的字节序列
        self.length = length or len(pattern)
        self.byte_order = byte_order  # 'le' / 'be' / None
        self.alignment = alignment    # 对齐要求（1/2/4/8 字节）
        self.confidence = confidence  # 'high' / 'medium' / 'low'
        self.description = description

    def __repr__(self):
        return f'<CryptoSignature {self.algo}/{self.component} len={self.length} conf={self.confidence}>'


# 所有签名的注册列表
SIGNATURES: list[CryptoSignature] = [
    # === AES ===
    CryptoSignature('AES', 'S-box', AES_SBOX, confidence='high',
                   description='AES 正向 S 盒，256 字节，确定性极高'),
    CryptoSignature('AES', 'Inverse S-box', AES_INV_SBOX, confidence='high',
                   description='AES 逆向 S 盒，256 字节'),
    CryptoSignature('AES', 'Rcon', AES_RCON, confidence='medium',
                   description='AES 密钥扩展 Rcon 常量（10 字节）'),
    CryptoSignature('AES', 'T-table-0', AES_T0, confidence='high',
                   description='AES T-table 0 前 4 项（优化实现）'),

    # === DES / 3DES ===
    CryptoSignature('DES', 'S-box-1', DES_SBOX1, confidence='high',
                   description='DES S 盒 1（64 字节）'),
    CryptoSignature('DES', 'S-box-2', DES_SBOX2, confidence='high',
                   description='DES S 盒 2（64 字节）'),
    CryptoSignature('DES', 'Key-shift', DES_KEY_SHIFT, confidence='medium',
                   description='DES 密钥移位表（16 字节）'),

    # === MD5 ===
    CryptoSignature('MD5', 'Init', MD5_INIT, confidence='high',
                   description='MD5 初始化向量（16 字节，小端）'),
    CryptoSignature('MD5', 'T-table', MD5_T, confidence='high',
                   description='MD5 T 表前 8 项（32 字节，小端）'),
    CryptoSignature('MD5', 'Shift-table-u32', MD5_SHIFT_U32, confidence='medium',
                   description='MD5 移位表前 16 项（64 字节，小端 uint32）'),

    # === SHA-1 ===
    CryptoSignature('SHA-1', 'Init', SHA1_INIT, confidence='high',
                   description='SHA-1 初始化向量（20 字节，大端）'),
    CryptoSignature('SHA-1', 'K-constants', SHA1_K, confidence='high',
                   description='SHA-1 K 常量（16 字节，大端）'),

    # === SHA-256 ===
    CryptoSignature('SHA-256', 'Init', SHA256_INIT, confidence='high',
                   description='SHA-256 初始化向量（32 字节，大端）'),
    CryptoSignature('SHA-256', 'K-table', SHA256_K, confidence='high',
                   description='SHA-256 K 表前 8 项（32 字节，大端）'),

    # === SHA-512 ===
    CryptoSignature('SHA-512', 'Init', SHA512_INIT, confidence='high',
                   description='SHA-512 初始化向量（64 字节，大端）'),
    CryptoSignature('SHA-512', 'K-table', SHA512_K, confidence='high',
                   description='SHA-512 K 表前 4 项（32 字节，大端）'),

    # === SHA-384 ===
    CryptoSignature('SHA-384', 'Init', SHA384_INIT, confidence='high',
                   description='SHA-384 初始化向量（64 字节，大端）'),

    # === SHA-224 ===
    CryptoSignature('SHA-224', 'Init', SHA224_INIT, confidence='high',
                   description='SHA-224 初始化向量（32 字节，大端）'),

    # === CRC32 ===
    CryptoSignature('CRC32', 'Poly-LE', CRC32_POLY_LE, confidence='medium',
                   description='CRC32 反射多项式 0xEDB88320（小端）'),
    CryptoSignature('CRC32', 'Poly-BE', CRC32_POLY_BE, confidence='medium',
                   description='CRC32 标准多项式 0x04C11DB7（大端）'),
    CryptoSignature('CRC32', 'Table-first4', CRC32_TABLE_FIRST4, confidence='high',
                   description='CRC32 查找表前 4 项'),

    # === TEA / XTEA / XXTEA ===
    CryptoSignature('TEA/XTEA/XXTEA', 'Delta', TEA_DELTA, confidence='high',
                   description='TEA 系列黄金分割常量 0x9E3779B9（大端）'),
    CryptoSignature('TEA/XTEA/XXTEA', 'Delta-LE', struct.pack('<I', 0x9E3779B9), confidence='high',
                   description='TEA 系列黄金分割常量 0x9E3779B9（小端）'),

    # === RC5 / RC6 ===
    CryptoSignature('RC5/RC6', 'P32', RC5_P32, confidence='high',
                   description='RC5/RC6 常量 P32=0xB7E15163（小端）'),
    CryptoSignature('RC5/RC6', 'P32-BE', struct.pack('>I', 0xB7E15163), confidence='high',
                   description='RC5/RC6 常量 P32=0xB7E15163（大端）'),
    CryptoSignature('RC5/RC6', 'Q32', RC5_Q32, confidence='high',
                   description='RC5/RC6 常量 Q32=0x9E3779B9（小端）'),

    # === Blowfish ===
    CryptoSignature('Blowfish', 'P-array', BLOWFISH_P_FIRST4, confidence='high',
                   description='Blowfish P-array 前 4 项（16 字节，大端）'),
    CryptoSignature('Blowfish', 'S-box-0', BLOWFISH_S0_FIRST4, confidence='high',
                   description='Blowfish S-box 0 前 4 项（16 字节，大端）'),

    # === CAST5 ===
    CryptoSignature('CAST5/CAST-128', 'S-box-1', CAST5_S1_FIRST4, confidence='medium',
                   description='CAST5 S-box 1 前 4 项（16 字节，大端）'),

    # === ChaCha20 / Salsa20 — 见下方 _chacha_sigs ===
]

# ChaCha20 / Salsa20 签名
_chacha_sigs = [
    CryptoSignature('ChaCha20', 'Sigma-const', CHACHA20_CONST, confidence='high',
                   description='ChaCha20 常量 "expand 32-byte k"（16 字节，小端）'),
    CryptoSignature('Salsa20', 'Sigma-const', SALSA20_CONST, confidence='high',
                   description='Salsa20 常量 "expand 32-byte k"（16 字节，小端）'),
]

# Fix: Twofish, Camellia, SEED, Whirlpool, RIPEMD-160, SM3, SM4, HMAC
_extra_sigs = [
    CryptoSignature('Twofish', 'Q-perm-0', TWOFISH_Q0_FIRST8, confidence='medium',
                   description='Twofish Q 置换表 0 前 8 字节'),
    CryptoSignature('Camellia', 'Sigma-1', CAMELLIA_SIGMA1, confidence='medium',
                   description='Camellia Sigma1 常量（8 字节，大端）'),
    CryptoSignature('SEED', 'S-box-0', SEED_SBOX0_FIRST4, confidence='medium',
                   description='SEED S-box 0 前 4 字节'),
    CryptoSignature('Whirlpool', 'S-box', WHIRLPOOL_SBOX_FIRST8, confidence='medium',
                   description='Whirlpool S-box 前 8 字节'),
    CryptoSignature('RIPEMD-160', 'Init', RIPEMD160_INIT, confidence='high',
                   description='RIPEMD-160 初始化向量（20 字节，小端）'),
    CryptoSignature('SM3', 'IV', SM3_IV, confidence='high',
                   description='SM3 初始向量（32 字节，大端）'),
    CryptoSignature('SM3', 'T0', SM3_T0, confidence='medium',
                   description='SM3 轮常量 T0=0x79CC4519（大端）'),
    CryptoSignature('SM3', 'T1', SM3_T1, confidence='medium',
                   description='SM3 轮常量 T1=0x7A879D8A（大端）'),
    CryptoSignature('SM4', 'S-box', SM4_SBOX, confidence='high',
                   description='SM4 S 盒（256 字节）'),
    CryptoSignature('SM4', 'FK', SM4_FK, confidence='medium',
                   description='SM4 系统参数 FK 前 3 项（大端）'),
    CryptoSignature('SM4', 'CK', SM4_CK_FIRST4, confidence='medium',
                   description='SM4 固定参数 CK 前 4 项（大端）'),
    CryptoSignature('HMAC', 'iPad', HMAC_IPAD, confidence='low',
                   description='HMAC 内填充 ipad=0x36 重复'),
    CryptoSignature('HMAC', 'oPad', HMAC_OPAD, confidence='low',
                   description='HMAC 外填充 opad=0x5c 重复'),
]

# 清理注册表：移除 placeholder，添加 ChaCha20 和额外签名
SIGNATURES = [s for s in SIGNATURES if isinstance(s, CryptoSignature)]
SIGNATURES.extend(_chacha_sigs)
SIGNATURES.extend(_extra_sigs)

# ============================================================
# 签名索引 — 按算法分组，便于聚合检测结果
# ============================================================
ALGORITHM_INDEX: dict[str, list[int]] = {}
for _i, _sig in enumerate(SIGNATURES):
    ALGORITHM_INDEX.setdefault(_sig.algo, []).append(_i)


def get_signatures_by_algo(algo: str) -> list[CryptoSignature]:
    """获取指定算法的所有签名"""
    indices = ALGORITHM_INDEX.get(algo, [])
    return [SIGNATURES[i] for i in indices]


def get_all_algorithms() -> list[str]:
    """获取所有已注册算法名"""
    return list(ALGORITHM_INDEX.keys())


def create_signature_lookup() -> dict[bytes, CryptoSignature]:
    """创建 pattern → signature 的快速查找字典
    注意：只保留长度 >= 4 的 pattern，避免短模式误报"""
    lookup = {}
    for sig in SIGNATURES:
        if len(sig.pattern) >= 4:
            lookup[sig.pattern] = sig
    return lookup
