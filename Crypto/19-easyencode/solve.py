#!/usr/bin/env python3
"""
第19题: easyencode (Crypto - 多层编码)
===================
题目文件: easyencode.zip (ZIP加密)
Flag: Dest0g3{Deoding_1s_e4sy_4_U}

编码链路 (5层):
  1. ZIP密码加密 (密码: 100861, 6位数字暴力破解)
  2. 摩斯电码 (Morse Code) → hex字符串
  3. Hex解码 → \uXXXX Unicode转义序列
  4. Unicode转义解码 → Base64 + URL编码混合字符串
  5. URL解码(%3D→=) → Base64解码 → flag

知识点:
  - ZIP暴力破解 (ZipCrypto传统加密, 非AES)
  - 摩斯电码 (数字0-9 + 字母C)
  - Hex编码 → ASCII
  - \uXXXX Unicode转义序列
  - URL编码 (%3D = '=')
  - Base64编码
"""

import zipfile, re, base64, urllib.parse, itertools, string

# ============ 配置 ============
ZIP_PATH = r"easyencode.zip"
ZIP_PASSWORD = b"100861"

# ============ Step 0: ZIP暴力破解 ============
def crack_zip(zip_path, max_digits=6):
    """暴力破解6位纯数字密码"""
    print(f"[0] 暴力破解ZIP密码 (最多{max_digits}位数字)...")
    with zipfile.ZipFile(zip_path, 'r') as z:
        for length in range(1, max_digits + 1):
            for combo in itertools.product('0123456789', repeat=length):
                pwd = ''.join(combo).encode()
                try:
                    z.setpassword(pwd)
                    z.read(z.namelist()[0])
                    print(f"    密码找到: {pwd.decode()}")
                    return pwd
                except:
                    continue
    return None

# ============ Step 1: 摩斯电码解码 ============
MORSE_CODE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
}

def morse_decode(text):
    """摩斯电码解码"""
    words = text.strip().split(' ')
    return ''.join(MORSE_CODE.get(w, f'[{w}]') for w in words)

# ============ Step 2: Hex解码 ============
def hex_decode(hex_str):
    """Hex字符串 → ASCII文本"""
    clean = re.sub(r'[^0-9A-Fa-f]', '', hex_str)
    return bytes.fromhex(clean).decode('ascii')

# ============ Step 3: Unicode转义解码 ============
def unicode_unescape(text):
    """解码 \\uXXXX 转义序列"""
    return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)

# ============ Step 4: URL解码 ============
def url_decode(text):
    """URL百分号解码"""
    return urllib.parse.unquote(text)

# ============ Step 5: Base64解码 ============
def base64_decode(text):
    """Base64解码"""
    return base64.b64decode(text).decode('utf-8')

# ============ 主流程 ============
def solve():
    # Step 0: 解压 (密码已知)
    print(f"\n[1] 解压ZIP (密码: {ZIP_PASSWORD.decode()})...")
    with zipfile.ZipFile(ZIP_PATH, 'r') as z:
        z.setpassword(ZIP_PASSWORD)
        morse_text = z.read('encode.txt').decode('utf-8')
    print(f"    读取 encode.txt ({len(morse_text)} bytes)")

    # Step 1: 摩斯电码 → hex字符串
    print(f"\n[2] 摩斯电码解码...")
    hex_str = morse_decode(morse_text)
    print(f"    结果: {hex_str[:80]}...")
    print(f"    长度: {len(hex_str)}")

    # Step 2: Hex解码 → \uXXXX Unicode转义
    print(f"\n[3] Hex解码...")
    unicode_escaped = hex_decode(hex_str)
    print(f"    结果: {unicode_escaped[:80]}...")
    print(f"    长度: {len(unicode_escaped)}")

    # Step 3: Unicode转义解码 → Base64+URL编码
    print(f"\n[4] Unicode转义解码...")
    b64_url_encoded = unicode_unescape(unicode_escaped)
    print(f"    结果: {b64_url_encoded}")

    # Step 4: URL解码
    print(f"\n[5] URL解码...")
    b64_str = url_decode(b64_url_encoded)
    print(f"    结果: {b64_str}")

    # Step 5: Base64解码 → flag
    print(f"\n[6] Base64解码...")
    flag = base64_decode(b64_str)
    print(f"    FLAG: {flag}")
    
    return flag

if __name__ == '__main__':
    flag = solve()
    print(f"\n{'='*50}")
    print(f"FLAG: {flag}")
    print(f"{'='*50}")
