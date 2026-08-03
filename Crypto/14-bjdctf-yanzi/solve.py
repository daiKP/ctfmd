#!/usr/bin/env python3
"""
[BJDCTF 2nd] 燕言燕语-y1ng
Hex 解码 + 维吉尼亚密码解密
"""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ====== 题目数据 ======
hex_str = '79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20'

# ====== Step 1: Hex 解码 ======
decoded = bytes.fromhex(hex_str).decode('ascii')
print(f'[1] Hex 解码: {repr(decoded)}')
# => 'yanzi ZJQ{xilzv_iqssuhoc_suzjg} '

# 前缀 "yanzi"（燕子拼音）= 维吉尼亚密钥
# 后面 "ZJQ{...}" = 密文，格式类似 BJD{...}

key = 'yanzi'
cipher = decoded.strip().split(' ', 1)[1]  # 取空格后的部分
print(f'    密钥: {key}')
print(f'    密文: {cipher}')

# ====== Step 2: 维吉尼亚解密 ======
# 解密公式: plain[i] = (cipher[i] - key[i]) mod 26
# 跳过非字母字符（{ } _ 等），密钥仅对字母位置推进

def vigenere_decrypt(ciphertext, key):
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch.lower()) - ord('a')
            k = ord(key[ki % len(key)].lower()) - ord('a')
            p = (c - k) % 26
            result.append(chr(p + ord('a')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

plaintext = vigenere_decrypt(cipher, key)
print(f'[2] 维吉尼亚解密: {plaintext}')

# ====== Step 3: 验证 ======
def vigenere_encrypt(plaintext, key):
    result = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            p = ord(ch.lower()) - ord('a')
            k = ord(key[ki % len(key)].lower()) - ord('a')
            c = (p + k) % 26
            result.append(chr(c + ord('a')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

verified = vigenere_encrypt(plaintext, key)
print(f'[3] 验证加密: {verified}')
print(f'    匹配: {verified == cipher.lower()}')

print(f'\nFlag: {plaintext}')
