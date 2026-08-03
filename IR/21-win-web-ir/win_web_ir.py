#!/usr/bin/env python3
"""
Windows Web 应急响应靶机排查脚本 (第25题)
============================================
靶机: http://192.168.88.129/ (EMLOG pro 2.2.0 + phpstudy)
目的: 找出攻击者IP、隐藏账户、Webshell密码、矿池域名

使用方式:
    需要先通过 EMLOG 后台上传恶意插件获取 RCE
    然后通过 webshell 执行以下排查命令

答案:
    1. 攻击者 IP: 192.168.126.1
    2. 隐藏账户: hack168$
    3. Webshell密码: rebeyond (冰蝎默认密码)
    4. 矿池域名: wakuang.zhigongshanfang.top
"""

import requests
import sys

# Webshell URL (通过 EMLOG 插件上传部署)
WEBSHELL_URL = "http://192.168.88.129/content/plugins/sys_helper/sys_helper.php"

def exec_cmd(cmd):
    """通过 webshell 执行命令"""
    r = requests.post(WEBSHELL_URL, data={"action": "exec", "cmd": cmd}, timeout=30)
    return r.text.strip()


def check_hidden_accounts():
    """检查隐藏账户 ($ 结尾的账户 net user 不可见)"""
    print("=" * 60)
    print("[*] 检查隐藏账户")
    print("=" * 60)

    # 方法1: WMI 查询 (可以看到 $ 结尾的隐藏账户)
    result = exec_cmd(
        'powershell -Command "Get-WmiObject Win32_UserAccount | '
        'Select-Object Name,SID,Disabled | Format-Table -AutoSize"'
    )
    print(result)

    # 方法2: 检查 Administrators 组成员
    result = exec_cmd(
        'powershell -Command "Get-LocalGroupMember -Group Administrators | '
        'Select-Object Name,SID,PrincipalSource | Format-Table -AutoSize"'
    )
    print("\n[*] Administrators 组成员:")
    print(result)

    # 方法3: 检查注册表 SAM 中的隐藏账户
    result = exec_cmd(
        r'powershell -Command "Get-ChildItem ''HKLM:\SAM\SAM\Domains\Account\Users\Names'' 2>$null"'
    )
    print("\n[*] 注册表 SAM 账户列表:")
    print(result)


def check_attacker_ip():
    """从安全日志中提取攻击者 IP"""
    print("\n" + "=" * 60)
    print("[*] 从安全日志提取攻击者 IP")
    print("=" * 60)

    # 检查登录失败事件 (Event ID 4625)
    result = exec_cmd(
        'powershell -Command "Get-WinEvent -FilterHashtable @{LogName=''Security'';Id=4625} '
        '-MaxEvents 20 | Select-Object TimeCreated,Message | Format-List"'
    )
    print("[*] 登录失败事件 (4625):")
    print(result)

    # 检查登录成功事件 (Event ID 4624) - 关注网络登录
    result = exec_cmd(
        'powershell -Command "Get-WinEvent -FilterHashtable @{LogName=''Security'';Id=4624} '
        '-MaxEvents 20 | Select-Object TimeCreated,Message | Format-List"'
    )
    print("\n[*] 登录成功事件 (4624):")
    print(result)


def check_webshell():
    """检查 Webshell 文件和密码"""
    print("\n" + "=" * 60)
    print("[*] 检查 Webshell")
    print("=" * 60)

    # 检查 Defender 威胁检测
    result = exec_cmd(
        'powershell -Command "Get-MpThreat | Select-Object ThreatName,SeverityID | Format-List"'
    )
    print("[*] Defender 检测到的威胁:")
    print(result)

    # 检查 Defender 隔离文件
    result = exec_cmd(
        '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -ListAll 2>nul'
    )
    print("\n[*] Defender 隔离文件列表:")
    print(result)

    # 恢复隔离的 webshell 文件
    result = exec_cmd(
        '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -All 2>&1'
    )
    print("\n[*] 恢复隔离文件:")
    print(result)

    # 读取恢复的 shell.php
    result = exec_cmd(
        'powershell -Command "Type C:\\phpstudy_pro\\WWW\\content\\plugins\\tips\\shell.php 2>$null"'
    )
    print("\n[*] shell.php 内容:")
    print(result)


def check_mining():
    """排查挖矿程序"""
    print("\n" + "=" * 60)
    print("[*] 排查挖矿程序")
    print("=" * 60)

    # 检查可疑用户桌面
    result = exec_cmd(r'dir /b /s C:\Users\hack168$\Desktop\ 2>nul')
    print("[*] hack168$ 用户桌面文件:")
    print(result)

    # 检查可疑进程
    result = exec_cmd('tasklist /svc | findstr /i "kuang"')
    print("\n[*] 挖矿进程:")
    print(result)

    # 网络连接
    result = exec_cmd('netstat -ano | findstr ESTABLISHED')
    print("\n[*] 当前网络连接:")
    print(result)


def main():
    print("Windows Web 应急响应排查工具 (第25题)")
    print(f"靶机: {WEBSHELL_URL}")
    print()

    check_hidden_accounts()
    check_attacker_ip()
    check_webshell()
    check_mining()

    print("\n" + "=" * 60)
    print("[*] 答案汇总")
    print("=" * 60)
    print("1. 攻击者 IP:     192.168.126.1")
    print("2. 隐藏账户:      hack168$")
    print("3. Webshell密码:  rebeyond (冰蝎默认密码)")
    print("4. 矿池域名:      wakuang.zhigongshanfang.top")


if __name__ == "__main__":
    main()
