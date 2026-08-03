#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF 应急响应第24题：Redis 未授权访问应急响应
靶机：192.168.234.128 (defend/defend)

用法：
    py -3 ir_scan.py              # 完整扫描
    py -3 ir_scan.py --summary    # 仅输出答案摘要
"""

import paramiko
import sys
import argparse

HOST = "192.168.234.128"
USER = "defend"
PASS = "defend"

# ============================================================
# 扫描命令清单
# ============================================================
COMMANDS = [
    # --- 登录记录 ---
    ("last -50", "last -50 2>/dev/null | head -50"),
    ("lastlog", "lastlog 2>/dev/null"),

    # --- bash_history ---
    ("root .bash_history", "echo defend | sudo -S cat /root/.bash_history 2>/dev/null"),
    ("defend .bash_history", "cat /home/defend/.bash_history 2>/dev/null"),

    # --- rc.local（攻击者用vim编辑过）---
    ("rc.local 内容", "echo defend | sudo -S cat /etc/rc.d/rc.local 2>/dev/null"),
    ("rc.local stat", "echo defend | sudo -S stat /etc/rc.d/rc.local 2>/dev/null"),

    # --- Redis 配置 ---
    ("redis.conf 关键配置", "echo defend | sudo -S grep -E '^(bind|protected-mode|requirepass|port|dir|dbfilename|save|appendonly)' /etc/redis.conf 2>/dev/null"),
    ("redis.conf flag", "echo defend | sudo -S grep -n 'flag' /etc/redis.conf 2>/dev/null"),

    # --- Redis RDB 文件 ---
    ("dump.rdb strings (var/lib)", "echo defend | sudo -S strings /var/lib/redis/dump.rdb 2>/dev/null"),
    ("dump.rdb strings (home)", "strings /home/defend/dump.rdb 2>/dev/null"),

    # --- SSH authorized_keys ---
    ("root authorized_keys", "echo defend | sudo -S cat /root/.ssh/authorized_keys 2>/dev/null"),
    ("root .ssh 目录", "echo defend | sudo -S ls -la /root/.ssh/ 2>/dev/null"),

    # --- 日志 ---
    ("secure Mar 18 Accepted", 'echo defend | sudo -S grep "Mar 18" /var/log/secure 2>/dev/null | grep -E "(Accepted|Failed|Disconnect)" | head -30'),
    ("redis.log Accepted", 'echo defend | sudo -S grep "Accepted" /var/log/redis/redis.log 2>/dev/null'),

    # --- crontab ---
    ("root crontab", "echo defend | sudo -S crontab -l 2>/dev/null"),
    ("/var/spool/cron/", "echo defend | sudo -S ls -la /var/spool/cron/ 2>/dev/null"),
    ("/etc/crontab", "echo defend | sudo -S cat /etc/crontab 2>/dev/null"),

    # --- 全局 flag 搜索 ---
    ("grep flag{ 全局", "echo defend | sudo -S grep -rl 'flag{' / --include='*.conf' --include='*.sh' --include='*.txt' --include='*history*' 2>/dev/null | head -20"),

    # --- 目录列表 ---
    ("/root/ 目录", "echo defend | sudo -S ls -la /root/ 2>/dev/null"),
    ("/home/defend/ 目录", "ls -la /home/defend/ 2>/dev/null"),
]


def run_cmd(ssh, cmd, timeout=15):
    """执行远程命令并返回输出"""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return out, err


def full_scan():
    """执行完整扫描"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[*] 连接 {HOST}...")
    ssh.connect(HOST, port=22, username=USER, password=PASS, timeout=10)
    print("[+] SSH连接成功\n")

    for title, cmd in COMMANDS:
        print(f"=== {title} ===")
        out, err = run_cmd(ssh, cmd)
        if out.strip():
            print(out)
        if err.strip() and 'password' not in err.lower():
            print(f"[stderr] {err}")
        print()

    ssh.close()
    print("[*] SSH连接已关闭")


def summary():
    """输出答案摘要"""
    print("=" * 60)
    print("  Redis 未授权访问应急响应 - 答案摘要")
    print("=" * 60)
    print()
    print(f"  靶机：{HOST} (CentOS 7, Redis 3.2.12)")
    print()
    print("  【攻击者IP】")
    print(f"    192.168.75.129")
    print(f"    证据：last/lastlog/secure日志 三重确认")
    print(f"    - last: root pts/1 192.168.75.129 Mon Mar 18 20:23")
    print(f"    - secure: Accepted publickey for root from 192.168.75.129")
    print(f"    - redis.log: Accepted 192.168.75.129:54766 (Redis连接)")
    print()
    print("  【Flag 1】")
    print(f"    flag{{thisismybaby}}")
    print(f"    来源：/root/.bash_history (echo flag{{thisismybaby}})")
    print()
    print("  【Flag 2】")
    print(f"    flag{{kfcvme50}}")
    print(f"    来源：/etc/rc.d/rc.local (注释行)")
    print(f"    写入时间：2024-03-18 20:24:27 (攻击者root会话期间)")
    print()
    print("  【Flag 3】")
    print(f"    flag{{P@ssW0rd_redis}}")
    print(f"    来源：/etc/redis.conf 第1行注释")
    print()
    print("  【攻击链】")
    print(f"    1. Redis bind 0.0.0.0 + protected-mode no → 未授权访问")
    print(f"    2. 攻击者通过Redis写入SSH公钥到authorized_keys")
    print(f"    3. SSH暴力破解root失败（PAM uid>=1000限制）")
    print(f"    4. 使用写入的公钥免密SSH登录root成功")
    print(f"    5. root会话中编辑rc.local写入flag + echo flag")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Redis IR Scan")
    parser.add_argument("--summary", action="store_true", help="仅输出答案摘要")
    args = parser.parse_args()

    if args.summary:
        summary()
    else:
        full_scan()
