#!/usr/bin/env python3
"""
仿射密码 (Affine Cipher) 解密
题目: e(x) = 11x + 6 (mod 26)
密文: welcylk
flag为base64形式

加密公式: E(x) = (a*x + b) mod m, 其中 a=11, b=6, m=26
解密公式: D(y) = a_inv * (y - b) mod m
  - a_inv 是 a 模 m 的乘法逆元，用扩展欧几里得算法求解
  - gcd(a, m) = 1 是仿射密码可解的必要条件
"""

import base64

# ===== 仿射密码参数 =====
a, b, m = 11, 6, 26
CIPHERTEXT = 'welcylk'


def extended_gcd(a, m):
    """
    扩展欧几里得算法 (Extended Euclidean Algorithm)
    返回 (gcd, x, y) 使得 a*x + m*y = gcd(a, m)
    当 gcd=1 时，x 即为 a 模 m 的乘法逆元
    """
    if a == 0:
        return m, 0, 1
    g, x1, y1 = extended_gcd(m % a, a)
    x = y1 - (m // a) * x1
    y = x1
    return g, x, y


def mod_inverse(a, m):
    """求 a 模 m 的乘法逆元"""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f'{a} 和 {m} 不互素，不存在模逆元')
    return x % m


def affine_decrypt(ciphertext, a, b, m=26):
    """仿射密码解密: D(y) = a_inv * (y - b) mod m"""
    a_inv = mod_inverse(a, m)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.lower()) - ord('a')
            x = (a_inv * (y - b)) % m
            result.append(chr(x + ord('a')))
        else:
            result.append(ch)
    return ''.join(result)


def affine_encrypt(plaintext, a, b, m=26):
    """仿射密码加密: E(x) = (a*x + b) mod m"""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.lower()) - ord('a')
            y = (a * x + b) % m
            result.append(chr(y + ord('a')))
        else:
            result.append(ch)
    return ''.join(result)


def main():
    print(f'仿射密码: E(x) = {a}x + {b} (mod {m})')
    print(f'密文: {CIPHERTEXT}')
    print()

    # Step 1: 求模逆元
    a_inv = mod_inverse(a, m)
    g = extended_gcd(a, m)[0]
    print(f'[1] 扩展欧几里得算法:')
    print(f'    gcd({a}, {m}) = {g} (必须为1，否则不可解)')
    print(f'    {a} 的模逆元 a_inv = {a_inv}')
    print(f'    验证: {a} * {a_inv} mod {m} = {(a * a_inv) % m}')
    print(f'    解密公式: D(y) = {a_inv} * (y - {b}) mod {m}')
    print()

    # Step 2: 解密
    plaintext = affine_decrypt(CIPHERTEXT, a, b, m)
    print(f'[2] 解密:')
    print(f'    密文: {CIPHERTEXT}')
    print(f'    明文: {plaintext}')
    print()

    # Step 3: 验证（加密回密文）
    verify = affine_encrypt(plaintext, a, b, m)
    print(f'[3] 加密验证:')
    print(f'    明文: {plaintext}')
    print(f'    加密: {verify}')
    print(f'    匹配: {verify == CIPHERTEXT}')
    print()

    # Step 4: Base64 编码
    flag_b64 = base64.b64encode(plaintext.encode()).decode()
    print(f'[4] Base64 编码:')
    print(f'    明文: {plaintext}')
    print(f'    Base64: {flag_b64}')
    print()
    print(f'Flag: flag{{{flag_b64}}}')


if __name__ == '__main__':
    main()
