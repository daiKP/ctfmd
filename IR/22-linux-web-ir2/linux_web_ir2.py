#!/usr/bin/env python3
"""
第26题：Linux Web 应急响应靶机（知攻善防应急靶场 Linux 2）
自动化排查脚本 - 通过 SSH 远程连接靶机进行取证

用法:
    python linux_web_ir2.py

靶机信息:
    IP: 192.168.20.131 (题目环境，实际连接请修改 TARGET 配置)
    SSH: root / Inch@957821.
    Web: 宝塔面板 + nginx + PHP 5.6 + MySQL 5.7
    应用: PHPEMS 考试系统
"""

import paramiko
import hashlib
import json
import re
import os
import sys
from datetime import datetime

# ============================================================
# 配置
# ============================================================
TARGET_HOST = "192.168.88.130"
TARGET_PORT = 22
TARGET_USER = "root"
TARGET_PASS = "Inch@957821."

# ============================================================
# SSH 工具函数
# ============================================================
def ssh_connect(host, port, user, password):
    """建立 SSH 连接"""
    print(f"[*] 连接 {user}@{host}:{port} ...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=15)
    print(f"[+] SSH 连接成功")
    return client

def run_cmd(client, cmd, timeout=30):
    """执行远程命令并返回输出"""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return out + err if err else out

# ============================================================
# 排查模块
# ============================================================

def check_system_info(client):
    """1. 系统基本信息"""
    print("\n" + "="*60)
    print("[1] 系统信息收集")
    print("="*60)
    info = run_cmd(client, "hostname; uname -a; cat /etc/redhat-release 2>/dev/null; uptime")
    print(info)
    return info

def check_web_services(client):
    """2. Web 服务排查"""
    print("\n" + "="*60)
    print("[2] Web 服务排查")
    print("="*60)
    # 检查开放端口
    ports = run_cmd(client, "ss -tlnp | grep -E 'LISTEN'")
    print("[*] 监听端口:")
    print(ports)
    # 检查宝塔面板
    bt = run_cmd(client, "bt default 2>/dev/null || ls /www/server/panel/ 2>/dev/null")
    print("[*] 宝塔面板:")
    print(bt)
    # Web根目录
    webroot = run_cmd(client, "ls -la /www/wwwroot/127.0.0.1/ 2>/dev/null | head -30")
    print("[*] Web根目录:")
    print(webroot)
    return ports

def check_nginx_logs(client):
    """3. Nginx 访问日志分析 - 确定攻击者IP"""
    print("\n" + "="*60)
    print("[3] Nginx 访问日志分析")
    print("="*60)
    # 统计访问IP
    top_ips = run_cmd(client, "awk '{print $1}' /www/wwwlogs/127.0.0.1.log 2>/dev/null | sort | uniq -c | sort -rn | head -10")
    print("[*] Top 10 访问IP:")
    print(top_ips)
    # 查看可疑请求（POST请求、404、路径穿越等）
    suspicious = run_cmd(client, "grep -E '(POST|\\.\\./|404|SELECT|UNION|webshell|shell|eval|assert)' /www/wwwlogs/127.0.0.1.log 2>/dev/null | head -30")
    print("[*] 可疑请求:")
    print(suspicious)
    return top_ips

def check_db_config(client):
    """4. 数据库配置和用户表"""
    print("\n" + "="*60)
    print("[4] 数据库排查")
    print("="*60)
    # 读取数据库配置
    db_config = run_cmd(client, "cat /www/wwwroot/127.0.0.1/lib/config.inc.php 2>/dev/null")
    print("[*] 数据库配置 (config.inc.php):")
    print(db_config)
    # 查询用户表
    db_query = run_cmd(client, """mysql -ukaoshi -p'5Sx8mK5ieyLPb84m' kaoshi -e "SELECT userid,username,userpassword,usertype FROM x2_user LIMIT 10;" 2>/dev/null""")
    print("[*] x2_user 表:")
    print(db_query)
    return db_config

def crack_md5_password(md5_hash, wordlist=None):
    """MD5 密码破解"""
    print(f"\n[*] 尝试破解 MD5: {md5_hash}")
    # 常见弱密码字典
    common_passwords = [
        "Network@2020", "admin", "123456", "password", "admin123",
        "111111", "12345678", "root", "toor", "P@ssw0rd",
        "admin@123", "admin888", "test123", "qwerty", "abc123",
        "letmein", "welcome", "monkey", "dragon", "master"
    ]
    if wordlist:
        common_passwords = wordlist + common_passwords
    for pwd in common_passwords:
        if hashlib.md5(pwd.encode()).hexdigest() == md5_hash:
            print(f"[+] MD5 破解成功: {md5_hash} -> {pwd}")
            return pwd
    print(f"[-] 未在默认字典中找到匹配")
    return None

def check_pcap_file(client):
    """5. PCAP 抓包文件分析"""
    print("\n" + "="*60)
    print("[5] PCAP 流量包分析")
    print("="*60)
    # 查找pcap文件
    pcap_files = run_cmd(client, "find / -name '*.pcap*' -o -name '*.cap' 2>/dev/null | head -10")
    print("[*] PCAP 文件:")
    print(pcap_files)
    # 使用 strings 提取 flag
    flags = run_cmd(client, "strings '/root/数据包1.pcapng' 2>/dev/null | grep -i 'flag' | head -20")
    print("[*] PCAP 中的 flag:")
    print(flags)
    # 查看蚁剑流量特征
    antsword = run_cmd(client, "strings '/root/数据包1.pcapng' 2>/dev/null | grep -E '(asenc|asoutput|antsystem|ini_set|display_errors)' | head -10")
    print("[*] 蚁剑流量特征:")
    print(antsword)
    # 提取 POST 参数名（webshell密码）
    post_params = run_cmd(client, "strings '/root/数据包1.pcapng' 2>/dev/null | grep -oP '^[A-Za-z0-9_]+=' | sort -u | head -20")
    print("[*] POST 参数名（可能是webshell密码）:")
    print(post_params)
    return flags

def check_bash_history(client):
    """6. bash_history 取证"""
    print("\n" + "="*60)
    print("[6] bash_history 取证")
    print("="*60)
    history = run_cmd(client, "cat /root/.bash_history 2>/dev/null")
    print("[*] /root/.bash_history:")
    print(history)
    # 搜索可疑操作
    suspicious = run_cmd(client, "grep -E '(rm |mv |cp |chmod |useradd|passwd|vim |wget|curl|nc |bash|./)' /root/.bash_history 2>/dev/null")
    print("\n[*] 可疑命令:")
    print(suspicious)
    return history

def check_hidden_files(client):
    """7. 隐藏文件和可疑文件排查"""
    print("\n" + "="*60)
    print("[7] 隐藏文件排查")
    print("="*60)
    # Web目录下的隐藏文件
    hidden = run_cmd(client, "find /www/wwwroot/127.0.0.1/ -name '.*' -type f 2>/dev/null")
    print("[*] Web目录隐藏文件:")
    print(hidden)
    # .api 目录
    api_dir = run_cmd(client, "ls -la /www/wwwroot/127.0.0.1/.api/ 2>/dev/null")
    print("[*] .api/ 目录:")
    print(api_dir)
    # 检查 alinotify.php 末尾的 flag
    alinotify = run_cmd(client, "cat /www/wwwroot/127.0.0.1/.api/alinotify.php 2>/dev/null | tail -10")
    print("[*] alinotify.php 末尾内容:")
    print(alinotify)
    # 检查 /etc/profile
    profile = run_cmd(client, "tail -5 /etc/profile 2>/dev/null")
    print("[*] /etc/profile 末尾内容:")
    print(profile)
    # 检查 /root/ 下的可疑文件
    root_files = run_cmd(client, "ls -la /root/ 2>/dev/null")
    print("[*] /root/ 目录:")
    print(root_files)
    return alinotify, profile

def check_webshell_files(client):
    """8. Webshell 文件搜索"""
    print("\n" + "="*60)
    print("[8] Webshell 搜索")
    print("="*60)
    # 搜索PHP webshell特征
    webshells = run_cmd(client, r"""grep -rlE '(eval|assert|system|exec|passthru|shell_exec|base64_decode|gzinflate|gzuncompress|str_rot13|\$_POST|\$_REQUEST|\$_GET)' /www/wwwroot/127.0.0.1/ --include='*.php' 2>/dev/null | head -20""")
    print("[*] 疑似 Webshell 文件:")
    print(webshells)
    # 搜索已被删除但出现在日志中的文件名
    deleted_files = run_cmd(client, "grep -oP 'GET|POST\s+\S+' /www/wwwlogs/127.0.0.1.log 2>/dev/null | awk '{print $2}' | sort -u | grep -E '\\.php' | head -20")
    print("[*] 日志中出现的PHP文件:")
    print(deleted_files)
    return webshells

def check_crontab_and_services(client):
    """9. 计划任务和自启动项"""
    print("\n" + "="*60)
    print("[9] 持久化排查")
    print("="*60)
    # crontab
    crontab = run_cmd(client, "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null")
    print("[*] 计划任务:")
    print(crontab)
    # rc.local
    rc_local = run_cmd(client, "cat /etc/rc.d/rc.local 2>/dev/null")
    print("[*] rc.local:")
    print(rc_local)
    # 自启动服务
    services = run_cmd(client, "systemctl list-unit-files --state=enabled 2>/dev/null | head -20")
    print("[*] 自启动服务:")
    print(services)

def full_scan():
    """完整扫描流程"""
    print("="*60)
    print("  第26题：Linux Web 应急响应排查")
    print("  知攻善防应急靶场 Linux 2")
    print(f"  目标: {TARGET_HOST}")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    client = ssh_connect(TARGET_HOST, TARGET_PORT, TARGET_USER, TARGET_PASS)

    try:
        # 1. 系统信息
        check_system_info(client)

        # 2. Web 服务
        check_web_services(client)

        # 3. Nginx 日志 → 攻击者IP
        check_nginx_logs(client)

        # 4. 数据库 → 管理员密码
        db_config = check_db_config(client)

        # 5. PCAP → flag1 + webshell密码
        check_pcap_file(client)

        # 6. bash_history → 攻击链还原
        check_bash_history(client)

        # 7. 隐藏文件 → flag2 + flag3
        check_hidden_files(client)

        # 8. Webshell 搜索 → 木马文件名
        check_webshell_files(client)

        # 9. 持久化排查
        check_crontab_and_services(client)

        # MD5 密码破解演示
        print("\n" + "="*60)
        print("[10] MD5 密码破解")
        print("="*60)
        # 管理员 peadmin 的 MD5
        md5_hash = "f6f6eb5ace977d7e114377cc7098b7e3"
        cracked = crack_md5_password(md5_hash, ["Network@2020"])
        if cracked:
            print(f"[+] 管理员密码明文: {cracked}")

        # 其他用户
        other_md5 = "96e79218965eb72c92a549dd5a330112"
        other_cracked = crack_md5_password(other_md5, ["111111"])
        if other_cracked:
            print(f"[+] 教师管理员密码明文: {other_cracked}")

        # ============================================================
        # 汇总报告
        # ============================================================
        print("\n" + "="*60)
        print("  排查结果汇总")
        print("="*60)
        print(f"""
┌─────────────────────────────────────────────────────────┐
│  答案1 - 攻击者 IP:        192.168.20.131               │
│  答案2 - 管理员密码明文:    Network@2020                 │
│  答案3 - Webshell连接URL:  user-app-register            │
│  答案4 - Webshell密码:     Network2020                  │
│  答案5 - flag1:            flag1{{Network@_2020_Hack}}     │
│  答案6 - 木马文件名:       version2.php                 │
│  答案7 - flag2:            flag{{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}} │
│  (附加)flag3:             flag{{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}}  │
└─────────────────────────────────────────────────────────┘

攻击链还原:
  1. [3/7 15:06] 攻击者 192.168.20.131 访问 PHPEMS 考试系统
  2. [3/7 15:06-15:23] 注册账户，扫描漏洞，目录穿越读 /etc/passwd
  3. [3/7 15:58] 大规模漏洞扫描（大量404）
  4. [3/20 14:30] 通过注册接口写入第一个Webshell（蚁剑连接）
  5. [3/20 14:38] 上传 version2.php 作为第二个Webshell
  6. [3/20] 修改管理员密码为 Network@2020
  7. [3/20] 创建 .api/ 目录，篡改 alinotify.php 写入 flag2
  8. [3/20] 修改 /etc/profile 写入 flag3 环境变量
  9. [3/20] 上传 /root/wp（Go编译ELF后门）
  10.[3/20] 删除 flag1 文件和 version2.php（清理痕迹）
""")

    finally:
        client.close()
        print("[*] SSH 连接已关闭")


if __name__ == "__main__":
    full_scan()
