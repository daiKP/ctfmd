#!/usr/bin/env python3
"""
Kuang.exe 挖矿程序逆向分析脚本 (第25题)
=========================================
用 pyinstxtractor 解包 PyInstaller 打包的 Kuang.exe，
再用 uncompyle6 反编译 .pyc 文件，提取矿池域名。

使用方式:
    py -3 pyinstxtractor.py Kuang.exe
    uncompyle6 Kuang.exe_extracted\Kuang.pyc

依赖:
    pip install uncompyle6
    
结果:
    矿池域名: wakuang.zhigongshanfang.top
    源码逻辑: 启动 CPU 核心数个进程，不断向矿池域名发送 GET 请求
"""

import hashlib
import os
import subprocess
import sys

def extract_pyinstaller(exe_path):
    """用 pyinstxtractor 解包 PyInstaller 打包的 exe"""
    print(f"[*] 解包 {exe_path} ...")
    # 需要 pyinstxtractor.py (https://github.com/extremecoders-re/pyinstxtractor)
    pyinstxtractor = os.path.join(os.path.dirname(__file__), "pyinstxtractor.py")
    if not os.path.exists(pyinstxtractor):
        print("[!] 需要下载 pyinstxtractor.py")
        print("    wget https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py")
        return False
    
    result = subprocess.run(
        [sys.executable, pyinstxtractor, exe_path],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    extracted_dir = exe_path + "_extracted"
    return os.path.exists(extracted_dir)


def decompile_pyc(pyc_path):
    """用 uncompyle6 反编译 .pyc 文件"""
    print(f"\n[*] 反编译 {pyc_path} ...")
    try:
        result = subprocess.run(
            ["uncompyle6", pyc_path],
            capture_output=True, text=True, timeout=30
        )
        source = result.stdout
        print(source)
        return source
    except FileNotFoundError:
        print("[!] uncompyle6 未安装，请运行: pip install uncompyle6")
        return None


def extract_strings(pyc_path):
    """从 pyc 文件中提取可读字符串（作为反编译的 fallback）"""
    print(f"\n[*] 从 {pyc_path} 提取字符串 ...")
    with open(pyc_path, "rb") as f:
        data = f.read()
    
    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    
    # 过滤出有意义的字符串
    interesting = [s for s in strings if any(kw in s.lower() for kw in [
        "http", "pool", "mine", ".com", ".net", ".top", ".xyz",
        "stratum", "xmr", "worker", "wallet"
    ])]
    
    print("[*] 找到的有趣字符串:")
    for s in interesting:
        print(f"  {s}")
    
    return interesting


def verify_behinder_key():
    """验证冰蝎 webshell 密码"""
    key = "e45e329feb5d925b"
    password = "rebeyond"
    md5 = hashlib.md5(password.encode()).hexdigest()
    md5_16 = md5[:16]
    
    print(f"\n[*] 冰蝎密码验证:")
    print(f"    密码: {password}")
    print(f"    MD5:  {md5}")
    print(f"    前16位: {md5_16}")
    print(f"    shell.php key: {key}")
    print(f"    匹配: {md5_16 == key}")


def main():
    print("=" * 60)
    print("Kuang.exe 挖矿程序分析 + 冰蝎密码验证")
    print("=" * 60)
    
    # 验证冰蝎密码
    verify_behinder_key()
    
    # 当前目录下寻找 Kuang.exe
    exe_path = "Kuang.exe"
    if not os.path.exists(exe_path):
        print(f"\n[!] {exe_path} 不存在，请先从靶机下载")
        return
    
    # 解包
    if extract_pyinstaller(exe_path):
        pyc_path = os.path.join(exe_path + "_extracted", "Kuang.pyc")
        if os.path.exists(pyc_path):
            # 反编译
            source = decompile_pyc(pyc_path)
            if not source:
                # fallback: 提取字符串
                extract_strings(pyc_path)
        else:
            print(f"[!] {pyc_path} 不存在")
    
    print("\n[*] 矿池域名: wakuang.zhigongshanfang.top")


if __name__ == "__main__":
    main()
