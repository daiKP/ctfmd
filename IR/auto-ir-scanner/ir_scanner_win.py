#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Automated Incidence Response Scanner
============================================
Connects to a remote Windows host via WinRM (pypsrp), runs 18 scanning
modules to collect forensic information for CTF IR competitions and
real-world security investigations.

Architecture mirrors the Linux ir_scanner.py v1.2 — same module
structure, same helper methods, same report/json/html output.
All commands are PowerShell equivalents.

Usage:
    python ir_scanner_win.py -H 192.168.88.129 -U Administrator -P password
    python ir_scanner_win.py -H 192.168.88.129 -U Administrator -P password --json report.json --report report.html
    python ir_scanner_win.py -H 192.168.88.129 -U Administrator -P password --modules 1,2,3
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime

from pypsrp.client import Client as WinRMClient


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
   _      ___ ____ ___   ____ ___  ____ _   _ _____ ___   ____ ___  _
  | | /| / / __ `__ \ / __ `__ \/ __ `/ / / / ___/ _ `/ / __ `__ \/ /
  | |/ |/ / / / / / // / / / / / /_/ / /_/ / /  / /_/ / / / / / / / /
  |__/|__/_/ /_/ /_//_/ /_/ /_/\__,_/\__,_/_/   \__,_(_)_/ /_/ /_/_/
    Windows IR Scanner  -  18 Modules  -  v1.0
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
    9:  ('scan_powershell_history', 'PowerShell 历史'),
    10: ('scan_web_logs',        'Web 访问日志'),
    11: ('scan_webshell',        'Webshell 检测'),
    12: ('scan_database',        '数据库与配置'),
    13: ('scan_rdp_security',    'RDP 与远程安全'),
    14: ('scan_pcap',            '流量包分析'),
    15: ('scan_malware',         '恶意软件检测'),
    16: ('scan_rootkit',         'Rootkit/驱动检测'),
    17: ('scan_windows_defender','Windows Defender'),
    18: ('generate_report',      '综合报告'),
}

SEV_ICON = {
    'HIGH':   ('[!]', 'red'),
    'MEDIUM': ('[?]', 'yellow'),
    'LOW':    ('[*]', 'cyan'),
    'INFO':   ('[+]', 'green'),
}

# ============================================================
# Windows 默认合法注册表自启动项白名单
# 这些是 Windows 系统默认的自启动项, 不需要告警
# ============================================================
DEFAULT_AUTORUN_WHITELIST = {
    # HKLM Run
    'SecurityHealth', 'WindowsDefender', 'RtHDVCpl', 'RavTRAY',
    'NvBackend', 'ShadowPlay', 'AdobeAAMUpdater-1.0',
    'Adobe ARM', 'AdobeGCInvoker-1.0', 'QuickTime Task',
    'SunJavaUpdateSched', 'Adobe Reader Speed Launcher',
    'Adobe Acrobat Speed Launcher', 'iTunesHelper',
    'APSDaemon', 'VMware Tools', 'VMwareTray', 'VMwareUser',
    'vmware-tray.exe', 'ShStatEXE', 'Onenote', 'OfficeSyncProcess',
    # HKCU Run
    'OneDrive', 'Skype', 'Discord', 'Steam', 'EpicGamesLauncher',
    'Spotify', 'MicrosoftEdgeAutoLaunch', 'Teams',
    # Winlogon
    'Shell', 'Userinit', 'Explorer.exe',
}# ============================================================
# Windows 默认合法服务白名单 (常见系统服务, 不需要告警)
# ============================================================
DEFAULT_SERVICES_WHITELIST = {
    'AarSvc', 'AJRouter', 'ALG', 'AppIDSvc', 'Appinfo', 'AppMgmt',
    'AppReadiness', 'AppXSvc', 'AudioEndpointBuilder', 'Audiosrv',
    'AxInstSV', 'BDESVC', 'BFE', 'BITS', 'BrokerInfrastructure',
    'Browser', 'BthAvctpSvc', 'bthserv', 'camsvc', 'CDPSvc',
    'CertPropSvc', 'CiaSvc', 'CscService', 'DcomLaunch', 'dcsvc',
    'Dhcp', 'DiagTrack', 'Dnscache', 'DoSvc', 'DPS', 'DsmSVC',
    'DsSvc', 'DusmSvc', 'Eaphost', 'EFS', 'EntAppSvc', 'EventLog',
    'EventSystem', 'Fax', 'fdPHost', 'FDResPub', 'fhsvc', 'FontCache',
    'FontCache3.0.0.0', 'FrameServer', 'GoogleChromeElevationService',
    'gpsvc', 'hidserv', 'HvHost', 'IEEtwCollectorService', 'IKEEXT',
    'InstallService', 'iphlpsvc', 'IsmSvc', 'KeyIso', 'KsecRlg',
    'KtmRm', 'LanmanServer', 'LanmanWorkstation', 'lfsvc', 'LicenseManager',
    'LLRService', 'lltdsvc', 'LMHosts', 'LxpSvc', 'MessagingService',
    'MicrosoftEdgeElevationService', 'MSDTC', 'MSiSCSI', 'msiserver',
    'MpsSvc', 'MSMQ', 'MSSQL$SQLEXPRESS', 'MSSQLServer', 'napagent',
    'NcaSvc', 'NcbService', 'Netbt', 'Netlogon', 'Netman', 'netprofm',
    'NetSetupSvc', 'NetTcpPortSharing', 'NlaSvc', 'nsi', 'nsi',
    'OfflineFiles', 'OneSyncSvc', 'PcaSvc', 'PeerDistSvc', 'PerfHost',
    'PhoneSvc', 'PLA', 'PlugPlay', 'PNRPAutoReg', 'PNRPsvc',
    'PolicyAgent', 'Power', 'PrintNotify', 'ProfSvc', 'PushToInstall',
    'QWAVE', 'RasAuto', 'RasMan', 'RemoteAccess', 'RemoteRegistry',
    'RetailDemo', 'RmSvc', 'RpcEptMapper', 'RpcLocator', 'RpcSs',
    'SamSs', 'SCardSvr', 'ScDeviceEnum', 'Schedule', 'SCPolicySvc',
    'SDRSVC', 'seclogon', 'SENS', 'Sense', 'SensorDataService',
    'SensorService', 'SensrSvc', 'SessionEnv', 'SgrmBroker', 'SharedAccess',
    'ShellHWDetection', 'shpamsvc', 'Smphost', 'SmsRouter', 'SNMPTRAP',
    'Spooler', 'sppsvc', 'SSDPSRV', 'sshsvc', 'SstpSvc', 'StateRepository',
    'StiSvc', 'StorSvc', 'svsvc', 'SwPrv', 'SysMain', 'SystemEventsBroker',
    'TabletInputService', 'TapiSrv', 'TermService', 'Themes',
    'TieringEngineService', 'TimeBrokerSvc', 'TlntSvr', 'TMosInfo',
    'TrkWks', 'TrustedInstaller', 'tzautoupdate', 'UevAgentService',
    'UI0Detect', 'UmRdpService', 'upnphost', 'UserDataSvc', 'UserManager',
    'UsoSvc', 'VaultSvc', 'vds', 'vmicheartbeat', 'vmickvpexchange',
    'vmicguestinterface', 'vmicshutdown', 'vmicrdv', 'vmicvmsession',
    'vmicvss', 'VSS', 'vssvc', 'W32Time', 'WaaaSMService', 'WbioSrvc',
    'WalletService', 'Wcmsvc', 'WdiServiceHost', 'WdiSystemHost',
    'WdNisSvc', 'WebClient', 'Wecsvc', 'WEPHOSTSVC', 'wercplsupport',
    'WerSvc', 'WiaRpc', 'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt',
    'WinRM', 'Wlansvc', 'wlidsvc', 'wmiApSrv', 'WMPNetworkSvc',
    'Wms', 'WMSVC', 'WpcMonSvc', 'WpnService', 'WpnUserService',
    'wuauserv', 'WwanSvc', 'XblAuthManager', 'XblGameSave',
    'XboxGipSvc', 'XboxNetApiSvc', 'BcastDVRUserService',
    'CDPUserSvc', 'Cortana', 'DeviceAssociationService',
    'DevicesFlowUserSvc', 'DmEnrollmentSvc', 'DoSvc', 'DPS',
    'embeddedmode', 'ESEHBSvc', 'Esent', 'GameInputSvc',
    'GraphicsPerfSvc', 'HvHost', 'IISADMIN', 'IKEEXT',
    'ImHost', 'InstallService', 'InventorySvc', 'lfsvc',
    'LxssManager', 'McpManagementService', 'MozillaMaintenance',
    'MSMQTriggers', 'NaturalAuthentication', 'Ndu', 'Netman',
    'NetTcpPortSharing', 'OpenSSHd', 'PerceptionSimulation',
    'PrintWorkflowUserSvc', 'ProgramCompatibilityAssistantService',
    'RasMan', 'RemoteRegistry', 'RetailDemo', 'RSoPProv',
    'sacsvr', 'SCardSvr', 'ScDeviceEnum', 'SensrSvc',
    'SessionEnv', 'SharedRealitySvc', 'SmsRouter', 'SpatialService',
    'spectrum', 'sppsvc', 'SSDPSRV', 'stisvc', 'StorSvc',
    'svsvc', 'swprv', 'SysMain', 'TBSSvc', 'Telephony',
    'Themes', 'TieringEngineService', 'TimeBrokerSvc', 'TroubleshootingSvc',
    'TrustedInstaller', 'tzautoupdate', 'UmRdpService', 'UniscribeService',
    'upnphost', 'UserDataSvc', 'UserManager', 'UsoSvc',
    'VSS', 'W32Time', 'WbioSrvc', 'Wcmsvc',
    'WdiServiceHost', 'WdiSystemHost', 'WdNisSvc', 'WebClient',
    'Wecsvc', 'WEPHOSTSVC', 'wercplsupport', 'WerSvc',
    'WiaRpc', 'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt',
    'WinRM', 'Wlansvc', 'wlidsvc', 'wmiApSrv',
    'WMPNetworkSvc', 'Wms', 'WMSVC', 'WpcMonSvc',
    'WpnService', 'wuauserv', 'WwanSvc',
}

# Windows 默认安全端口白名单
SAFE_PORTS = {
    '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
    '21': 'FTP', '3389': 'RDP', '445': 'SMB',
    '135': 'RPC', '139': 'NetBIOS', '1433': 'SQL Server',
    '3306': 'MySQL', '5432': 'PostgreSQL',
    '808': 'WinRM HTTP', '5985': 'WinRM HTTP', '5986': 'WinRM HTTPS',
    '143': 'IMAP', '110': 'POP3', '25': 'SMTP',
    '53': 'DNS', '161': 'SNMP', '162': 'SNMP Trap',
    '6379': 'Redis', '27017': 'MongoDB', '9042': 'Cassandra',
    '9200': 'Elasticsearch', '11211': 'Memcached',
}

DB_PORTS = {
    '3306': 'MySQL', '5432': 'PostgreSQL',
    '6379': 'Redis', '27017': 'MongoDB',
    '9200': 'Elasticsearch', '11211': 'Memcached',
    '9042': 'Cassandra', '5984': 'CouchDB',
    '1433': 'SQL Server', '1521': 'Oracle',
}
# ============================================================
# 核心扫描器
# ============================================================
class IRScanner:
    """Windows 应急响应扫描器"""

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
        self._is_admin = None

    # ---------- 基础连接 ----------
    def connect(self):
        print(C.cyan("[*] 连接 %s:%s (WinRM) ..." % (self.host, self.port)))
        self.client = WinRMClient(
            self.host, username=self.user, password=self.password,
            auth='ntlm', ssl=False, port=self.port,
            connection_timeout=self.timeout,
        )
        # 验证连接
        try:
            stdout, stderr, rc = self.client.execute_cmd('whoami')
            if rc != 0:
                raise ConnectionError("WinRM 认证失败: %s" % stderr)
            print(C.green("[+] WinRM 连接成功 (用户: %s)\n" % stdout.strip()))
        except Exception as e:
            raise ConnectionError("WinRM 连接失败: %s" % e)
        # 检查管理员权限
        admin_check = self.run('powershell -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"')
        self._is_admin = 'True' in admin_check.strip()
        if self._is_admin:
            print(C.green("[+] 管理员权限确认\n"))
        else:
            print(C.yellow("[!] 当前用户非管理员, 部分检查可能受限\n"))

    def close(self):
        self.scan_duration = time.time() - self.start_time
        if self.client:
            self.client.close()
            self.client = None
        print(C.cyan("\n[*] WinRM 连接已关闭 (扫描耗时 %.1fs)" % self.scan_duration))

    @staticmethod
    def _strip_clixml(text):
        """去除 WinRM 下 PowerShell 的 CLIXML 序列化噪音

        PowerShell 在 WinRM 的 stderr 流中输出进度/警告信息时，
       会序列化成 #< CLIXML <Objs ...> 格式，需要过滤。
        """
        if not text:
            return text
        # 去除 #< CLIXML ... </Objs> 整块
        text = re.sub(r'#<\s*CLIXML\s*<Objs.*?</Objs>', '', text, flags=re.DOTALL)
        # 去除残留的 CLIXML 片段
        text = re.sub(r'#<\s*CLIXML\s*', '', text)
        # 去除 <Objs ...> ... </Objs> 残块 (无 #< CLIXML 前缀的)
        text = re.sub(r'<Objs\s+Version=.*?</Objs>', '', text, flags=re.DOTALL)
        return text.strip()

    def run(self, cmd, timeout=None, encoding='gbk'):
        """执行远程命令 (通过 WinRM execute_cmd), 返回合并后的 stdout+stderr 文本

        WinRM cmd.exe 输出默认为 GBK 编码 (中文 Windows),
        PowerShell 通过 ps() 方法调用时设 encoding='utf-8'。
        """
        if not self.client:
            return ''
        try:
            stdout, stderr, rc = self.client.execute_cmd(cmd)
            out = stdout.decode(encoding, errors='replace') if isinstance(stdout, bytes) else (stdout or '')
            err = stderr.decode(encoding, errors='replace') if isinstance(stderr, bytes) else (stderr or '')
        except Exception as e:
            return "[error] %s" % e
        # 过滤 CLIXML 噪音
        out = self._strip_clixml(out)
        err = self._strip_clixml(err)
        if err:
            kept = []
            for line in err.splitlines():
                low = line.lower()
                if 'password' in low and 'wrong' not in low:
                    continue
                if low.strip().startswith('sorry, try again'):
                    continue
                kept.append(line)
            err = '\n'.join(kept).strip()
        merged = out
        if err:
            merged += ('\n' if merged else '') + err
        return merged

    def ps(self, cmd, timeout=None):
        """包装 PowerShell 命令并执行

        使用 -EncodedCommand (UTF-16LE Base64) 避免多层引号转义问题。
        WinRM → cmd.exe → powershell.exe 三层嵌套下传统转义不可靠。
        前置 chcp 65001 + [Console]::OutputEncoding 设置确保所有输出 UTF-8。
        """
        ps_script = (
            "chcp 65001 > $null; "
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            "$OutputEncoding=[System.Text.Encoding]::UTF8; "
            + cmd
        )
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
        return self.run('powershell -NoProfile -EncodedCommand ' + encoded, timeout=timeout, encoding='utf-8')

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
        out = self.ps(cmd)
        k = key or label
        self.results.setdefault(modkey, {})[k] = out
        self._pr(label, out, max_lines=lines)
        return out

    def _do_raw(self, modkey, label, cmd, key=None, lines=50):
        """运行原始命令 (非 PowerShell) -> 打印 -> 存储"""
        out = self.run(cmd)
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

    def _is_admin_user(self):
        if self._is_admin is not None:
            return self._is_admin
        return False

    def _detect_webroot(self):
        """自动探测 Windows Web 根目录"""
        roots = []
        # IIS 默认路径
        check_paths = [
            r'C:\inetpub\wwwroot',
            r'C:\phpstudy_pro\WWW',
            r'C:\phpStudy\WWW',
            r'C:\wamp\www',
            r'C:\xampp\htdocs',
            r'C:\laragon\www',
            r'C:\UPUPW_AP\htdocs',
            r'C:\nginx\html',
            r'C:\www',
            r'C:\web',
        ]
        for p in check_paths:
            cmd = 'Test-Path "%s"' % p
            out = self.ps(cmd)
            if 'True' in out.strip():
                roots.append(p)

        # IIS 站点物理路径
        iis_paths = self.ps(
            'Get-WebSite | Select-Object name, @{N="Path";E={$_.physicalPath}} | Format-Table -AutoSize'
        )
        for line in iis_paths.splitlines():
            for known in ['C:\\', 'D:\\', 'E:\\']:
                if known in line:
                    m = re.search(r'([A-Z]:\\[^\s]+)', line)
                    if m:
                        path = m.group(1).rstrip()
                        if path not in roots:
                            roots.append(path)

        if self.webroot:
            w = self.webroot.rstrip('\\')
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
        self._do(mk, '系统信息', 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | Format-List')
        self._do(mk, '完整 systeminfo', 'systeminfo | Select-String -Pattern "OS|System|Boot|Install|Domain|Network" | Select-Object -First 20')
        self._do(mk, '运行时间/启动时间',
                 '$os = Get-CimInstance Win32_OperatingSystem; $uptime = (Get-Date) - $os.LastBootUpTime; Write-Output ("启动时间: " + $os.LastBootUpTime); Write-Output ("运行时长: " + $uptime.Days + "天 " + $uptime.Hours + "小时 " + $uptime.Minutes + "分钟")')
        self._do(mk, '当前时间', 'Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"')
        self._do(mk, 'CPU 信息', 'Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List')
        self._do(mk, '内存信息', 'Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum | ForEach-Object { Write-Output ("总内存: " + [math]::Round($_.Sum/1GB,2) + " GB") }; Get-CimInstance Win32_OperatingSystem | ForEach-Object { Write-Output ("可用: " + [math]::Round($_.FreePhysicalMemory/1MB,2) + " GB") }')
        self._do(mk, '磁盘信息', 'Get-Volume | Where-Object {$_.DriveLetter} | Select-Object DriveLetter,FileSystemLabel,FileSystem,@{N="SizeGB";E={[math]::Round($_.Size/1GB,1)}},@{N="FreeGB";E={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-Table -AutoSize')
        self._do(mk, 'IP 配置', 'ipconfig /all')
        # 容器/虚拟机检测
        virt = self.ps(
            'Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model | Format-List; '
            '(Get-WmiObject Win32_BIOS).SerialNumber'
        )
        self.results.setdefault(mk, {})['virtualization'] = virt
        self._pr('虚拟化检测', virt)
        is_vm = bool(re.search(r'VMware|VirtualBox|Hyper-V|Xen|KVM|QEMU|Parallels', virt, re.I))
        if is_vm:
            self._find('INFO', '虚拟机', '检测到运行在虚拟机环境中', virt[:200])

    # ============================================================
    # 模块 02: 网络连接与端口
    # ============================================================
    def scan_network(self):
        mk = 'network'
        self._do(mk, '监听端口', 'Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize')
        self._do(mk, '所有 TCP 连接', 'Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize')
        self._do(mk, 'UDP 端口', 'Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize')
        self._do(mk, 'netstat -ano', 'netstat -ano')
        self._do(mk, '网卡接口', 'Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | Format-Table -AutoSize')
        self._do(mk, '路由表', 'route print')
        self._do(mk, 'DNS 配置', 'Get-DnsClientServerAddress | Format-Table -AutoSize')
        self._do(mk, 'hosts 文件', 'Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts')
        self._do(mk, '防火墙规则', 'Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile | Sort-Object Direction | Format-Table -AutoSize')
        self._do(mk, 'ARP 表', 'arp -a')

        # 危险端口检测
        listen = self.results.get(mk, {}).get('监听端口', '') + self.results.get(mk, {}).get('netstat -ano', '')
        danger_ports = {
            '6379': 'Redis', '27017': 'MongoDB', '9200': 'Elasticsearch',
            '11211': 'Memcached', '5900': 'VNC', '3306': 'MySQL',
            '1433': 'SQL Server', '3389': 'RDP',
        }
        for port, svc in danger_ports.items():
            for line in listen.splitlines():
                if not re.search(r'\b' + port + r'\b', line):
                    continue
                # 本地回环
                if re.search(r'127\.0\.0\.1|::1|\[::1\]', line):
                    self._find('LOW', '暴露服务',
                               '%s 端口 %s 仅本地监听' % (svc, port), line.strip())
                    break
                # 对外监听
                if re.search(r'0\.0\.0\.0|\*|::', line):
                    self._find('HIGH', '暴露服务',
                               '%s 端口 %s 对外监听' % (svc, port), line.strip())
                    break

        # hosts 劫持检测
        hosts = self.results.get(mk, {}).get('hosts 文件', '')
        COMMON_DOMAINS = re.compile(
            r'(github\.com|google\.com|baidu\.com|aliyun\.com|'
            r'cloud\.tencent|docker\.com|npmjs\.org|pypi\.org)', re.I)
        for line in hosts.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if COMMON_DOMAINS.search(line):
                self._find('HIGH', 'DNS 劫持',
                           'hosts 文件中发现域名劫持条目', line)

        # 异常连接数
        conn = self.results.get(mk, {}).get('所有 TCP 连接', '')
        est = len(re.findall(r'Established', conn, re.I))
        if est > 200:
            self._find('MEDIUM', '网络', 'ESTABLISHED 连接数异常(%d)' % est, conn[:200])

    # ============================================================
    # 模块 03: 用户与登录记录
    # ============================================================
    def scan_users(self):
        mk = 'users'
        self._do(mk, '本地用户', 'Get-LocalUser | Select-Object Name,Enabled,Description,LastLogon | Format-Table -AutoSize')
        self._do(mk, 'WMI 用户 (含隐藏)', 'Get-WmiObject Win32_UserAccount | Select-Object Name,SID,Disabled,Lockout,PasswordExpires | Format-Table -AutoSize')
        self._do(mk, '管理员组成员', 'Get-LocalGroupMember -Group Administrators | Select-Object Name,SID,PrincipalSource | Format-Table -AutoSize')
        self._do(mk, '所有组', 'Get-LocalGroup | Format-Table -AutoSize')
        self._do(mk, '注册表 SAM 账户', "Get-ChildItem 'HKLM:\\SAM\\SAM\\Domains\\Account\\Users\\Names' -ErrorAction SilentlyContinue | Select-Object Name")
        self._do(mk, '登录会话', 'query user 2>$null; qwinsta 2>$null')
        self._do(mk, '登录失败事件 4625',
                 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} -MaxEvents 50 | Select-Object TimeCreated,Message | Format-List')
        self._do(mk, '登录成功事件 4624',
                 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} -MaxEvents 50 | Select-Object TimeCreated,Message | Format-List')
        self._do(mk, '7天内新建用户',
                 'Get-LocalUser | Where-Object {$_.WhenCreated -gt (Get-Date).AddDays(-7)} | Select-Object Name,WhenCreated,Enabled | Format-Table -AutoSize')
        self._do(mk, '密码策略', 'net accounts')
        self._do(mk, '用户主目录', 'Get-ChildItem C:\\Users -Directory | Select-Object Name,LastWriteTime | Format-Table -AutoSize')

        # 隐藏账户检测 ($ 结尾)
        wmi_users = self.results.get(mk, {}).get('WMI 用户 (含隐藏)', '')
        hidden_accts = []
        for line in wmi_users.splitlines():
            m = re.search(r'(\S*\$)\s', line)
            if m:
                hidden_accts.append(line.strip())

        netuser_out = self.results.get(mk, {}).get('本地用户', '')
        wmi_names = set()
        for line in wmi_users.splitlines():
            m = re.match(r'\s*(\S+)\s', line)
            if m:
                wmi_names.add(m.group(1).lower())
        netuser_names = set()
        for line in netuser_out.splitlines():
            # 跳过表头
            if 'Name' in line and 'Enabled' in line:
                continue
            parts = line.split()
            if parts and parts[0] not in ('Name', ''):
                netuser_names.add(parts[0].lower())
        # WMI 可见但 net user 不可见的 → 隐藏
        for wn in sorted(wmi_names - netuser_names):
            if wn.endswith('$'):
                self._find('HIGH', '隐藏账户',
                           '发现隐藏账户 ($结尾, net user 不可见): %s' % wn, wmi_users[:300])

        # 多管理员检测
        admins = self.results.get(mk, {}).get('管理员组成员', '')
        admin_count = len([l for l in admins.splitlines() if l.strip() and 'Name' not in l and '--' not in l])
        if admin_count > 3:
            self._find('MEDIUM', '权限提升',
                       '管理员组成员数量异常(%d)' % admin_count, admins[:300])

        # 7天内新建用户
        newu = self.results.get(mk, {}).get('7天内新建用户', '')
        if newu.strip() and 'Name' not in newu.split('\n')[0]:
            self._find('MEDIUM', '新建账户', '7天内新增用户账户', newu[:300])

        # 登录失败IP统计
        fail_events = self.results.get(mk, {}).get('登录失败事件 4625', '')
        ip_counts = {}
        for line in fail_events.splitlines():
            m = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', line)
            if m:
                ip = m.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1]):
            if cnt > 50:
                self._find('HIGH', '暴力破解',
                           'IP %s 登录失败 %d 次(暴力破解)' % (ip, cnt),
                           fail_events[:300])
            elif cnt > 10:
                self._find('MEDIUM', '暴力破解',
                           'IP %s 登录失败 %d 次' % (ip, cnt), '')
    # ============================================================
    # 模块 04: 进程排查
    # ============================================================
    def scan_processes(self):
        mk = 'processes'
        self._do(mk, 'CPU Top20',
                 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id,ProcessName,CPU,@{N="MemMB";E={[math]::Round($_.WorkingSet/1MB,1)}},Path | Format-Table -AutoSize')
        self._do(mk, '内存 Top20',
                 'Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 20 Id,ProcessName,@{N="MemMB";E={[math]::Round($_.WorkingSet/1MB,1)}},Path | Format-Table -AutoSize')
        self._do(mk, '所有进程', 'Get-Process | Select-Object Id,ProcessName,Path | Format-Table -AutoSize')
        self._do(mk, '进程树', 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-Table -AutoSize')
        self._do(mk, 'tasklist /svc', 'tasklist /svc')

        # 挖矿进程检测
        mining = self.ps(
            'Get-Process | Where-Object {$_.ProcessName -match "xmrig|minerd|kdevtmpfsi|kinsing|nicehash|cpuminer|stratum|kuang|miner"} | Select-Object Id,ProcessName,Path | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['mining'] = mining
        self._pr('挖矿进程检测', mining)

        # 可疑进程 (反弹Shell/后门)
        susp = self.ps(
            'Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -match "powershell.*-enc|cmd.*/c|certutil.*-decode|bitsadmin.*http|mshta|wscript.*shell|cscript.*shell|rundll32.*http|regsvr32.*http|iex.*new-object|downloadstring|downloadfile|invoke-expression"} | Select-Object ProcessId,Name,CommandLine | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['suspicious'] = susp
        self._pr('可疑进程', susp)

        # 无路径/无签名进程
        no_path = self.ps(
            'Get-Process | Where-Object {!$_.Path -and $_.ProcessName -ne "Idle" -and $_.ProcessName -ne "System"} | Select-Object Id,ProcessName | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['no_path'] = no_path
        self._pr('无路径进程', no_path)

        # 临时目录可执行文件
        tmpexe = self.ps(
            'Get-ChildItem -Path C:\\Users\\*\\AppData\\Local\\Temp,C:\\Windows\\Temp -Filter *.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['temp_executables'] = tmpexe
        self._pr('临时目录可执行文件', tmpexe, max_lines=30)

        # 网络连接关联进程
        net_procs = self.ps(
            'Get-NetTCPConnection -State Established | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{PID=$_.OwningProcess;Process=$p.ProcessName;Remote="$($_.RemoteAddress):$($_.RemotePort)";Local="$($_.LocalAddress):$($_.LocalPort)"} } | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['network_connections'] = net_procs
        self._pr('网络连接关联进程', net_procs, max_lines=40)

        if mining.strip() and 'Get-Process' not in mining.split('\n')[0]:
            self._find('HIGH', '挖矿', '发现挖矿相关进程', mining[:300])
        if susp.strip() and 'Get-CimInstance' not in susp.split('\n')[0]:
            self._find('HIGH', '反弹Shell', '发现可疑反弹Shell/后门进程', susp[:300])
        if tmpexe.strip() and 'FullName' not in tmpexe.split('\n')[0]:
            self._find('MEDIUM', '临时可执行', '临时目录存在可执行文件', tmpexe[:300])

    # ============================================================
    # 模块 05: 计划任务
    # ============================================================
    def scan_scheduled_tasks(self):
        mk = 'scheduled_tasks'
        self._do(mk, '所有计划任务', 'Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author | Format-Table -AutoSize')
        self._do(mk, '正在运行的任务', 'Get-ScheduledTask | Where-Object {$_.State -eq "Running"} | Select-Object TaskName,TaskPath | Format-Table -AutoSize')
        self._do(mk, 'schtasks /query', 'schtasks /query /fo TABLE /v | Select-Object -First 80')
        self._do(mk, '就绪状态任务', 'Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath,Author | Format-Table -AutoSize')

        # 可疑计划任务检测
        all_tasks = self.results.get(mk, {}).get('所有计划任务', '')
        all_tasks += self.results.get(mk, {}).get('schtasks /query', '')
        pat = re.compile(
            r'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|'
            r'regsvr32|certutil|bitsadmin|download|http|mimikatz|'
            r'\\Temp\\|\\tmp\\', re.I)
        suspicious_tasks = []
        for line in all_tasks.splitlines():
            if pat.search(line):
                suspicious_tasks.append(line.strip())

        if suspicious_tasks:
            self._find('HIGH', '计划任务',
                       '计划任务中存在可疑命令',
                       '\n'.join(suspicious_tasks[:10]))

        # 检查非 Microsoft 作者的任务
        non_ms_tasks = []
        for line in all_tasks.splitlines():
            if 'Microsoft' not in line and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    non_ms_tasks.append(line.strip())
        if len(non_ms_tasks) > 20:
            self._find('MEDIUM', '计划任务',
                       '存在较多非 Microsoft 计划任务(%d)' % len(non_ms_tasks),
                       '\n'.join(non_ms_tasks[:10]))

    # ============================================================
    # 模块 06: 启动项与持久化
    # ============================================================
    def scan_startup(self):
        mk = 'startup'
        # 注册表自启动项
        self._do(mk, 'HKLM Run',
                 r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List")
        self._do(mk, 'HKLM RunOnce',
                 r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List")
        self._do(mk, 'HKCU Run',
                 r"Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List")
        self._do(mk, 'HKCU RunOnce',
                 r"Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List")
        self._do(mk, 'HKLM Winlogon',
                 r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object Shell,Userinit,Taskman,GinaDLL,VmApplet | Format-List")
        self._do(mk, '启动项文件夹',
                 r"Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup','C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup' -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime | Format-Table -AutoSize")
        self._do(mk, '服务列表',
                 'Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize')
        self._do(mk, 'WMI 启动命令',
                 r"Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | Format-Table -AutoSize")
        self._do(mk, 'Winlogon Userinit',
                 r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).Userinit")
        self._do(mk, 'Image File Execution Options',
                 r"Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | Select-Object Name")

        # 分析所有启动项数据
        all_startup = ' '.join(str(v) for v in self.results.get(mk, {}).values())
        if re.search(r'flag\{|ctf\{|FLAG\{', all_startup):
            self._find('HIGH', 'Flag', '启动项中发现 flag{}', all_startup[:300])

        # 可疑启动命令
        susp_patterns = re.compile(
            r'powershell.*-enc|cmd\.exe.*/c|certutil|bitsadmin|mshta|'
            r'rundll32.*http|regsvr32.*http|downloadstring|'
            r'invoke-expression|iex\(|\\Temp\\|\\tmp\\', re.I)
        for data in self.results.get(mk, {}).values():
            if susp_patterns.search(str(data)):
                self._find('HIGH', '持久化',
                           '启动项中存在可疑命令', str(data)[:300])
                break

        # Image File Execution Options (Debugger 劫持)
        ifeo = self.results.get(mk, {}).get('Image File Execution Options', '')
        if 'Debugger' in ifeo:
            self._find('HIGH', '持久化',
                       'Image File Execution Options 中存在 Debugger 劫持', ifeo[:300])

        # Winlogon Shell 被篡改
        winlogon = self.results.get(mk, {}).get('HKLM Winlogon', '')
        if winlogon:
            m = re.search(r'Shell\s*:\s*(\S+)', winlogon)
            if m and 'explorer.exe' not in m.group(1).lower():
                self._find('HIGH', '持久化',
                           'Winlogon Shell 被篡改: %s' % m.group(1), winlogon[:300])

        # 可疑服务
        svcs = self.results.get(mk, {}).get('服务列表', '')
        svc_names = set()
        for line in svcs.splitlines():
            parts = line.split()
            if parts and parts[0] not in ('Name', ''):
                svc_names.add(parts[0].lower())
        unknown_svcs = svc_names - {s.lower() for s in DEFAULT_SERVICES_WHITELIST}
        if len(unknown_svcs) > 15:
            self._find('MEDIUM', '服务异常',
                       '发现较多非默认服务(%d)' % len(unknown_svcs),
                       '\n'.join(sorted(unknown_svcs)[:10]))
    # ============================================================
    # 模块 07: 文件系统异常
    # ============================================================
    def scan_filesystem(self):
        mk = 'filesystem'
        # 近期修改文件 (限定深度, 排除 Windows/Program Files)
        self._do(mk, '7天内修改文件 (C盘)',
                 'Get-ChildItem -Path C:\\ -Depth 4 -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.FullName -notmatch "Windows\\\\|Program Files|ProgramData|\\$Recycle|node_modules"} | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 80 | Format-Table -AutoSize',
                 lines=80)
        self._do(mk, '24小时内修改文件',
                 'Get-ChildItem -Path C:\\ -Depth 4 -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1) -and $_.FullName -notmatch "Windows\\\\|Program Files|\\$Recycle|node_modules"} | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 60 | Format-Table -AutoSize',
                 lines=60)

        # 临时目录可疑文件
        self._do(mk, 'Temp 目录文件',
                 'Get-ChildItem -Path C:\\Windows\\Temp,C:\\Users\\*\\AppData\\Local\\Temp -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 40 | Format-Table -AutoSize',
                 lines=40)

        # 可执行文件排查
        self._do(mk, '用户目录可执行文件',
                 'Get-ChildItem -Path C:\\Users -Filter *.exe -Recurse -Depth 5 -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch "AppData\\\\Local\\\\Microsoft|Program Files"} | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize',
                 lines=40)
        self._do(mk, '可疑脚本文件',
                 'Get-ChildItem -Path C:\\Users,C:\\Windows\\Temp -Recurse -Depth 4 -Include *.ps1,*.bat,*.cmd,*.vbs,*.js -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch "Program Files|ProgramData"} | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 40 | Format-Table -AutoSize',
                 lines=40)

        # ADS (Alternate Data Streams) 检测 (限深度)
        self._do(mk, 'NTFS 数据流检测',
                 'Get-ChildItem -Path C:\\Users,C:\\Windows\\Temp -Recurse -Depth 3 -File -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ":`$DATA" -and $_.Stream -ne "Zone.Identifier"} | Select-Object FileName,Stream | Format-Table -AutoSize',
                 lines=30)

        # 隐藏文件
        self._do(mk, '隐藏文件 (C盘根+用户目录)',
                 'Get-ChildItem -Path C:\\,C:\\Users -Force -Hidden -ErrorAction SilentlyContinue | Where-Object {$_.Name -notmatch "^\\.|desktop.ini"} | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize',
                 lines=40)

        # 磁盘空间
        self._do(mk, '磁盘空间', 'Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{N="UsedGB";E={[math]::Round($_.Used/1GB,1)}},@{N="FreeGB";E={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize')

        # 文件完整性 — sfc /verifyonly 太慢(分钟级), 用快速签名验证替代
        self._do(mk, '系统关键文件签名',
                 'Get-Item C:\\Windows\\System32\\cmd.exe,C:\\Windows\\System32\\powershell.exe,C:\\Windows\\System32\\netsh.exe,C:\\Windows\\System32\\taskmgr.exe -ErrorAction SilentlyContinue | Get-AuthenticodeSignature | Select-Object Path,Status | Format-Table -AutoSize')

        # 分析
        all_fs = ' '.join(str(v) for v in self.results.get(mk, {}).values())
        if re.search(r'flag\{|ctf\{|FLAG\{', all_fs):
            self._find('HIGH', 'Flag', '文件系统中发现 flag{}', '')

        # 临时目录可执行
        tmpraw = self.results.get(mk, {}).get('Temp 目录文件', '')
        if tmpraw.strip() and '.exe' in tmpraw.lower():
            self._find('MEDIUM', '恶意文件', '临时目录存在可执行文件', tmpraw[:300])

    # ============================================================
    # 模块 08: 隐藏 Flag 搜索
    # ============================================================
    def scan_hidden_flags(self):
        mk = 'hidden_flags'
        # Select-String flag{ 搜索常见位置
        ctf_paths = [
            r'C:\Windows\System32\drivers\etc\hosts',
            r'C:\Windows\System32\drivers\etc\services',
            r'C:\Windows\win.ini',
            r'C:\Windows\System.ini',
            r'C:\Windows\panther\unattend.xml',
        ]
        for p in ctf_paths:
            content = self.ps('Get-Content "%s" -ErrorAction SilentlyContinue' % p)
            if not content.strip():
                continue
            self.results.setdefault(mk, {})[p] = content
            self._pr(p, content)
            hits = re.findall(r'(?:flag|ctf|FLAG|CTF|key|KEY)\{[^}]+\}', content)
            if hits:
                for h in hits:
                    self._find('HIGH', 'Flag', '在 %s 发现 %s' % (p, h), content[:200])

        # 全局 flag 搜索 (限深度)
        self._do(mk, 'flag{} 搜索 (用户目录+Temp)',
                 r'Get-ChildItem -Path C:\\Users,C:\\Windows\\Temp -Recurse -Depth 5 -File -Include *.txt,*.log,*.ini,*.cfg,*.conf,*.xml,*.json,*.bat,*.ps1,*.cmd,*.vbs -ErrorAction SilentlyContinue | Select-String -Pattern "flag\{|ctf\{|FLAG\{" | Select-Object -First 30 | Format-Table -AutoSize',
                 lines=30)

        # 注册表 flag 搜索 (限定关键路径, 避免全注册表递归导致超时)
        self._do(mk, '注册表 flag 搜索 (关键路径)',
                 r'reg query "HKLM\SOFTWARE" /s /f "flag{" /t REG_SZ 2>&1 | Select-String "flag\{" | Select-Object -First 10',
                 lines=10)
        self._do(mk, '注册表 flag 搜索 (HKCU)',
                 r'reg query "HKCU\SOFTWARE" /s /f "flag{" /t REG_SZ 2>&1 | Select-String "flag\{" | Select-Object -First 10',
                 lines=10)

        # Web 目录 flag
        if self.webroots:
            for wr in self.webroots:
                flag_search = self.ps(
                    'Get-ChildItem -Path "%s" -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern "flag\\{|ctf\\{|FLAG\\{" | Select-Object Path,LineNumber,Line | Format-Table -AutoSize' % wr
                )
                self.results.setdefault(mk, {})['flag:' + wr] = flag_search
                self._pr('Web 目录 flag: %s' % wr, flag_search, max_lines=30)
                if flag_search.strip():
                    self._find('HIGH', 'Flag', 'Web 目录 %s 中发现 flag' % wr, flag_search[:300])

        # 用户桌面文件
        self._do(mk, '用户桌面文件',
                 'Get-ChildItem -Path C:\\Users\\*\\Desktop -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize',
                 lines=30)

    # ============================================================
    # 模块 09: PowerShell 历史
    # ============================================================
    def scan_powershell_history(self):
        mk = 'powershell_history'
        # PowerShell 历史文件
        hist_path = self.ps(
            '(Get-PSReadlineOption).HistorySavePath'
        )
        self.results.setdefault(mk, {})['history_path'] = hist_path.strip()
        self._pr('历史文件路径', hist_path)

        if hist_path.strip():
            content = self.ps(
                'Get-Content "%s" -ErrorAction SilentlyContinue | Select-Object -Last 200' % hist_path.strip()
            )
            self.results.setdefault(mk, {})['history_content'] = content
            self._pr('PowerShell 历史记录', content, max_lines=120)

            # 可疑命令检测
            susp_patterns = re.compile(
                r'powershell.*-enc|certutil.*decode|bitsadmin|mshta|'
                r'downloadstring|downloadfile|invoke-expression|iex\(|'
                r'new-object.*net\.webclient|wget|curl|'
                r'reg\s+add|net\s+user\s+.*/add|net\s+localgroup|'
                r'schtasks.*/create|wmic\s+process|'
                r'enable.*rdp|reg.*TerminalServer|'
                r'set-MpPreference.*-Disable|Add-MpPreference.*-Exclusion|'
                r'flag\{|base64', re.I)
            for line in content.splitlines():
                line = line.strip()
                if susp_patterns.search(line):
                    self._find('MEDIUM', '历史命令',
                               'PowerShell 历史含可疑命令: %s' % line[:100],
                               line[:200])

        # 事件日志中的 PowerShell 执行 (4104/400/800)
        self._do(mk, 'PowerShell 脚本块日志',
                 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational";Id=4104} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List',
                 lines=80)
        self._do(mk, 'PowerShell 经典日志',
                 'Get-WinEvent -FilterHashtable @{LogName="Windows PowerShell";Id=400} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List',
                 lines=60)

        # 命令行进程历史 (4688)
        self._do(mk, '进程创建事件 4688',
                 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List',
                 lines=80)
    # ============================================================
    # 模块 10: Web 访问日志
    # ============================================================
    def scan_web_logs(self):
        mk = 'web_logs'
        # IIS 日志位置
        log_dirs = [
            r'C:\inetpub\logs\LogFiles',
            r'C:\phpstudy_pro\Extensions\nginx*\logs',
            r'C:\phpStudy\nginx\logs',
            r'C:\nginx\logs',
            r'C:\wamp\bin\apache\*\logs',
            r'C:\xampp\apache\logs',
            r'C:\laragon\bin\apache\*\logs',
        ]

        # 搜索日志文件
        log_files = self.ps(
            '$dirs = @("C:\\inetpub\\logs\\LogFiles","C:\\phpstudy_pro","C:\\phpStudy","C:\\nginx","C:\\xampp","C:\\wamp","C:\\laragon"); '
            'foreach($d in $dirs){ if(Test-Path $d){ Get-ChildItem -Path $d -Recurse -Include *.log,*.txt -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "access|error|log|u_ex"} | Select-Object -First 20 FullName,Length,LastWriteTime } } | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['log_files'] = log_files
        self._pr('日志文件', log_files)

        # 解析日志文件 (取前5个)
        file_paths = re.findall(r'(\S:\\[^\s]+\.log)', log_files)
        for f in file_paths[:5]:
            # 日志基本信息
            self._pr('日志: %s' % f, self.ps(
                r'if(Test-Path "%s"){ $f = Get-Item "%s"; Write-Output ("大小: " + [math]::Round($f.Length/1KB,1) + " KB"); Write-Output ("修改: " + $f.LastWriteTime); $lines = Get-Content "%s" -ErrorAction SilentlyContinue; Write-Output ("总行: " + $lines.Count); Write-Output "-- Top10 请求URL --"; $lines | Select-String "GET |POST " | ForEach-Object { if($_ -match "(GET|POST) (\S+)"){$matches[2]} } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Count,Name; Write-Output "-- 可疑请求 --"; $lines | Select-String -Pattern "eval|assert|shell|cmd|union|select|\.asp\.|\.php\.|antsword|whoami" | Select-Object -First 20 } ' % (f, f, f)))

            log_content = self.ps(
                'Get-Content "%s" -Tail 50 -ErrorAction SilentlyContinue' % f
            )
            self.results.setdefault(mk, {})[f] = log_content
            if re.search(r'eval|assert|shell|antsword|union|/etc/passwd|cmd\.exe', log_content, re.I):
                self._find('HIGH', 'Web 攻击', '日志 %s 含攻击/Webshell 请求' % f, log_content[:300])

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

            # PHP Webshell 特征
            php_sh = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -Include *.php -File -ErrorAction SilentlyContinue | Select-String -Pattern "eval\\(|assert\\(|system\\(|exec\\(|passthru\\(|shell_exec\\(|base64_decode\\(|`$_POST\\[|`$_REQUEST\\[|preg_replace.*/e|create_function" | Select-Object Path,LineNumber,Line | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['php_webshell'] = php_sh
            self._pr('PHP Webshell 候选', php_sh, max_lines=40)

            # ASP/ASPX Webshell
            asp_sh = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -Include *.asp,*.aspx,*.ashx -File -ErrorAction SilentlyContinue | Select-String -Pattern "eval|execute|Server\\.CreateObject|System\\.Diagnostics|Process\\.Start" | Select-Object Path,LineNumber,Line | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['asp_webshell'] = asp_sh
            self._pr('ASP/ASPX Webshell 候选', asp_sh, max_lines=30)

            # JSP Webshell
            jsp_sh = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -Include *.jsp -File -ErrorAction SilentlyContinue | Select-String -Pattern "Runtime\\.getRuntime|ProcessBuilder|exec\\(" | Select-Object Path,LineNumber,Line | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['jsp_webshell'] = jsp_sh
            self._pr('JSP Webshell 候选', jsp_sh, max_lines=20)

            # 一句话木马
            oneliner = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -Include *.php,*.asp,*.aspx -File -ErrorAction SilentlyContinue | Select-String -Pattern "<\\?php @eval|<\\?php eval|@eval\\($" | Select-Object Path,LineNumber,Line | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['oneliner'] = oneliner
            self._pr('一句话木马检测', oneliner)

            # 近期修改的 Web 文件
            recent_web = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 30 | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['recent_files'] = recent_web
            self._pr('近期修改的 Web 文件', recent_web, max_lines=30)

            # 异常扩展名
            anom_ext = self.ps(
                'Get-ChildItem -Path "%s" -Recurse -Include *.phtml,*.pht,*.php5,*.phar,*.asp;jpg,*.php;jpg -File -ErrorAction SilentlyContinue | Select-Object FullName | Format-Table -AutoSize' % wr
            )
            self.results.setdefault(mk + ':' + wr, {})['anom_ext'] = anom_ext
            self._pr('异常扩展名', anom_ext)

            if (php_sh.strip() or asp_sh.strip() or oneliner.strip()) and 'Path' not in php_sh.split('\n')[0]:
                combined = php_sh + asp_sh + oneliner
                self._find('HIGH', 'Webshell',
                           '在 %s 发现 Webshell 文件' % wr, combined[:300])
            if recent_web.strip() and 'FullName' not in recent_web.split('\n')[0]:
                self._find('MEDIUM', 'Web',
                           '%s 近30天有新文件' % wr, recent_web[:300])

    # ============================================================
    # 模块 12: 数据库与配置
    # ============================================================
    def scan_database(self):
        mk = 'database'
        # MySQL 服务/配置
        self._do(mk, 'MySQL 服务状态',
                 'Get-Service | Where-Object {$_.Name -match "mysql|mariadb"} | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize')
        self._do(mk, 'SQL Server 服务',
                 'Get-Service | Where-Object {$_.Name -match "MSSQL|SQLServer"} | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize')
        self._do(mk, '数据库进程',
                 'Get-Process | Where-Object {$_.ProcessName -match "mysql|sqlservr|postgres|mongo|redis"} | Select-Object Id,ProcessName,Path | Format-Table -AutoSize')

        # 数据库配置文件搜索 (限深度, 避免全盘递归)
        self._do(mk, 'MySQL 配置文件',
                 'Get-ChildItem -Path C:\\ -Depth 3 -Include my.ini,my.cnf -File -ErrorAction SilentlyContinue | Select-Object -First 10 FullName | Format-Table -AutoSize')
        self._do(mk, 'phpStudy 配置',
                 'Get-ChildItem -Path C:\\phpstudy_pro,C:\\phpStudy -Include *.ini,*.conf -Recurse -Depth 5 -ErrorAction SilentlyContinue | Select-Object -First 20 FullName | Format-Table -AutoSize')

        # Web 应用配置文件 (含凭据)
        cfg_files_found = []
        cfg_names = ['config.php', 'database.php', 'db.php', 'conn.php',
                     'wp-config.php', 'config.inc.php', 'common.php',
                     '.env', 'application.yml', 'application.properties',
                     'settings.py', 'config.yml', 'config.json']
        if self.webroots:
            for wr in self.webroots:
                for cf in cfg_names:
                    fname = os.path.basename(cf)
                    res = self.ps(
                        'Get-ChildItem -Path "%s" -Recurse -Filter %s -File -ErrorAction SilentlyContinue | Select-Object -First 5 FullName | Format-Table -AutoSize' % (wr, fname)
                    )
                    for line in res.splitlines():
                        m = re.match(r'(\S:\\.*)', line.strip())
                        if m:
                            cfg_files_found.append(m.group(1))
        cfg_files_found = list(dict.fromkeys(cfg_files_found))[:20]
        self.results.setdefault(mk, {})['config_files'] = '\n'.join(cfg_files_found)
        self._pr('配置文件', '\n'.join(cfg_files_found))

        # 读取配置文件中的凭据
        creds = []
        for cf in cfg_files_found:
            content = self.ps('Get-Content "%s" -ErrorAction SilentlyContinue' % cf)
            self.results.setdefault(mk, {})[cf] = content
            self._pr('配置: %s' % cf, content, max_lines=40)
            for m in re.finditer(
                    r'(DB_|MYSQL_|DATABASE_|PASSWORD|PASSWD|PWD|SECRET|'
                    r'db_password|password)\s*[=:]\s*[\'"]?([^\'"\s;,]+)',
                    content, re.I):
                creds.append('%s = %s @ %s' % (m.group(1), m.group(2), cf))
        if creds:
            self._find('MEDIUM', '凭据泄露',
                       '配置文件中发现数据库凭据',
                       ' | '.join(creds)[:300])

        # Redis 配置
        redis_paths = self.ps(
            'Get-ChildItem -Path C:\\ -Depth 3 -Include redis.conf,redis.windows.conf -File -ErrorAction SilentlyContinue | Select-Object -First 5 FullName | Format-Table -AutoSize'
        )
        if redis_paths.strip():
            for line in redis_paths.splitlines():
                m = re.match(r'(\S:\\.*)', line.strip())
                if m:
                    rc = self.ps('Get-Content "%s" -ErrorAction SilentlyContinue' % m.group(1))
                    self.results.setdefault(mk, {})['redis_conf'] = rc
                    self._pr('Redis 配置', rc, max_lines=60)
                    # 检查 Redis 安全
                    bind0 = bool(re.search(r'^bind\s+0\.0\.0\.0', rc, re.M))
                    prot_no = bool(re.search(r'^protected-mode\s+no', rc, re.M))
                    no_pass = not re.search(r'^requirepass\s+\S+', rc, re.M)
                    if bind0 and no_pass:
                        self._find('HIGH', 'Redis',
                                   'Redis bind 0.0.0.0 且无密码(未授权)', rc[:300])
                    if prot_no and no_pass:
                        self._find('HIGH', 'Redis',
                                   'Redis protected-mode=no 且无密码', rc[:300])
    # ============================================================
    # 模块 13: RDP 与远程安全
    # ============================================================
    def scan_rdp_security(self):
        mk = 'rdp_security'
        # RDP 配置
        self._do(mk, 'RDP 状态',
                 r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections")
        self._do(mk, 'RDP 端口',
                 r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).PortNumber")
        self._do(mk, 'RDP NLA 设置',
                 r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication")
        self._do(mk, 'RDP 安全层',
                 r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).SecurityLayer")
        self._do(mk, '防火墙 RDP 规则',
                 'Get-NetFirewallRule -DisplayName "*远程桌面*","*Remote Desktop*" -ErrorAction SilentlyContinue | Select-Object DisplayName,Enabled,Direction,Action | Format-Table -AutoSize')

        # 登录成功/失败事件
        self._do(mk, '登录失败统计 (4625 IP)',
                 r'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object { $_.Message } | Select-String -Pattern "([0-9]{1,3}\.){3}[0-9]{1,3}" -AllMatches | ForEach-Object { $_.Matches.Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 15 | Format-Table Count,Name')

        self._do(mk, '外部成功登录',
                 r'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object { $_.Message -notmatch "127\.0\.0\.1|::1|NT AUTHORITY" } | Select-Object -First 20 TimeCreated,Message | Format-List')

        # RDP 相关服务
        self._do(mk, '远程相关服务',
                 'Get-Service | Where-Object {$_.Name -match "TermService|UmRdpService|SessionEnv|RemoteRegistry"} | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize')

        # WinRM 配置
        self._do(mk, 'WinRM 配置',
                 'winrm get winrm/config 2>&1 | Select-Object -First 30')

        # 分析 RDP 安全
        rdp_status = self.results.get(mk, {}).get('RDP 状态', '')
        if '0' in rdp_status.strip():
            self._find('MEDIUM', 'RDP', 'RDP 已启用 (fDenyTSConnections=0)', '')

        rdp_port = self.results.get(mk, {}).get('RDP 端口', '')
        if rdp_port.strip() and rdp_port.strip() != '3389':
            self._find('INFO', 'RDP', 'RDP 端口非默认: %s' % rdp_port.strip(), '')

        nla = self.results.get(mk, {}).get('RDP NLA 设置', '')
        if '0' in nla.strip():
            self._find('MEDIUM', 'RDP', 'RDP NLA 未启用 (安全风险)', '')

        # 暴力破解检测
        fail_stats = self.results.get(mk, {}).get('登录失败统计 (4625 IP)', '')
        for line in fail_stats.splitlines():
            m = re.match(r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                cnt = int(m.group(1))
                if cnt > 50:
                    self._find('HIGH', '暴力破解',
                               'IP %s 登录失败 %d 次(暴力破解)' % (m.group(2), cnt),
                               line)
                elif cnt > 10:
                    self._find('MEDIUM', '暴力破解',
                               'IP %s 登录失败 %d 次' % (m.group(2), cnt), line)

    # ============================================================
    # 模块 14: 流量包分析
    # ============================================================
    def scan_pcap(self):
        mk = 'pcap'
        pcap_files = self.ps(
            'Get-ChildItem -Path C:\\ -Depth 4 -Include *.pcap,*.pcapng,*.cap -File -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,Length,LastWriteTime | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['pcap_files'] = pcap_files
        self._pr('Pcap 文件', pcap_files)

        for f in re.findall(r'(\S:\\[^\s]+\.(?:pcap|pcapng|cap))', pcap_files)[:10]:
            self._pr('Pcap: %s' % f, self.ps(
                'if(Test-Path "%s"){ $fi = Get-Item "%s"; Write-Output ("大小: " + [math]::Round($fi.Length/1KB,1) + " KB") }' % (f, f)))
            # 使用 Select-String 搜索 flag/webshell 特征
            info = self.ps(
                '$content = Get-Content "%s" -Encoding Byte -TotalCount 100000 -ErrorAction SilentlyContinue; '
                '$text = [System.Text.Encoding]::ASCII.GetString($content); '
                'Write-Output "-- flag --"; '
                r'$text | Select-String -Pattern "flag\{|ctf\{" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 5; '
                'Write-Output "-- Webshell特征 --"; '
                '$text | Select-String -Pattern "asenc|asoutput|antsystem|base64_decode|eval|rebeyond" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 10; '
                'Write-Output "-- HTTP请求 --"; '
                '$text | Select-String -Pattern "GET /|POST /|Host: " -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 10' % f
            )
            self.results.setdefault(mk, {})[f] = info
            self._pr('分析: %s' % f, info, max_lines=60)
            if re.search(r'flag\{|ctf\{', info, re.I):
                self._find('HIGH', 'Flag', 'Pcap %s 中发现 flag' % f, info[:300])
            if re.search(r'asenc|asoutput|antsystem|base64_decode|eval\(|assert|rebeyond', info, re.I):
                self._find('HIGH', 'Webshell', 'Pcap %s 中发现 Webshell 流量特征' % f, info[:300])

    # ============================================================
    # 模块 15: 恶意软件检测
    # ============================================================
    def scan_malware(self):
        mk = 'malware'
        # 可疑可执行文件 (排除系统目录, 限深度)
        self._do(mk, '可疑可执行文件',
                 'Get-ChildItem -Path C:\\Users,C:\\Windows\\Temp,C:\\Temp -Recurse -Depth 5 -Include *.exe,*.dll,*.vbs,*.js,*.ps1 -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch "AppData\\\\Local\\\\Microsoft|Program Files|Windows\\\\System32"} | Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 40 | Format-Table -AutoSize',
                 lines=40)

        # 挖矿程序/配置
        self._do(mk, '挖矿程序检测',
                 'Get-Process | Where-Object {$_.ProcessName -match "xmrig|minerd|kdevtmpfsi|kinsing|nicehash|cpuminer|stratum|kuang|miner|crypto"} | Select-Object Id,ProcessName,Path | Format-Table -AutoSize')

        mining_cfg = self.ps(
            'Get-ChildItem -Path C:\\ -Depth 4 -Include config.json,pools.txt,*.toml -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch "Program Files|Windows|AppData"} | Select-String -Pattern "stratum|pool|wallet|xmrig|cryptonight" | Select-Object -First 10 Path,Line | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['mining_config'] = mining_cfg
        self._pr('挖矿配置文件', mining_cfg)

        # 挖矿网络连接 (常见矿池端口)
        mining_net = self.ps(
            'Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {$_.RemotePort -in 3333,5555,7777,14444,14433,45700} | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{PID=$_.OwningProcess;Process=$p.ProcessName;Remote="$($_.RemoteAddress):$($_.RemotePort)"} } | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['mining_network'] = mining_net
        self._pr('挖矿网络连接', mining_net)

        # 后门文件名检测 (限深度)
        backdoor_names = self.ps(
            'Get-ChildItem -Path C:\\ -Depth 4 -Include shell*,cmd*,c99*,r57*,b374k*,wso*,backdoor*,trojan*,hack* -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch "Program Files|Windows\\\\System32"} | Select-Object -First 20 FullName | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['backdoor_names'] = backdoor_names
        self._pr('后门文件名检测', backdoor_names, max_lines=20)

        # Run/RunOnce 中的可疑项 (也在这里检查)
        autorun_susp = self.ps(
            r'$paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"); foreach($p in $paths){ $items = Get-ItemProperty $p -ErrorAction SilentlyContinue; if($items){ $items.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object { if($_.Value -match "http|download|powershell|cmd\.exe|certutil|bitsadmin|\\Temp\\") { Write-Output ("[" + $p + "] " + $_.Name + " = " + $_.Value) } } } }'
        )
        self.results.setdefault(mk, {})['autorun_suspicious'] = autorun_susp
        self._pr('可疑自启动项', autorun_susp)

        # DLL 注入检测
        dll_inject = self.ps(
            'Get-Process | ForEach-Object { try { $_.Modules | Where-Object {$_.FileName -match "Temp|Downloads|Users"} | Select-Object @{N="Process";E={$_.ProcessName}},FileName } } catch {} | Select-Object -First 30 | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['dll_injection'] = dll_inject
        self._pr('可疑 DLL 注入', dll_inject, max_lines=30)

        # 可疑计划任务文件
        task_files = self.ps(
            r'Get-ChildItem -Path C:\\Windows\\System32\\Tasks -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "powershell|cmd\.exe|http|download|certutil" | Select-Object -First 20 Path,Line | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['malicious_tasks'] = task_files
        self._pr('可疑计划任务', task_files, max_lines=20)

        if min(j.strip() for j in [mining_cfg, mining_net]):
            self._find('HIGH', '挖矿', '发现挖矿配置或网络连接', mining_cfg + mining_net[:300])
        if backdoor_names.strip():
            self._find('MEDIUM', '后门', '发现可疑后门文件名', backdoor_names[:300])
        if autorun_susp.strip():
            self._find('HIGH', '持久化', '自启动项中存在可疑命令', autorun_susp[:300])
        if dll_inject.strip() and 'Process' not in dll_inject.split('\n')[0]:
            self._find('MEDIUM', 'DLL注入', '发现可疑 DLL 注入', dll_inject[:300])

    # ============================================================
    # 模块 16: Rootkit / 驱动检测
    # ============================================================
    def scan_rootkit(self):
        mk = 'rootkit'
        # 已加载驱动
        self._do(mk, '已加载驱动',
                 'Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq "Running"} | Select-Object Name,DisplayName,PathName | Format-Table -AutoSize',
                 lines=60)

        # 驱动文件签名验证
        self._do(mk, '未签名/无效签名驱动',
                 'Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq "Running"} | ForEach-Object { $sig = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue; if($sig.Status -ne "Valid"){ [PSCustomObject]@{Driver=$_.Name;Path=$_.PathName;SigStatus=$sig.Status} } } | Format-Table -AutoSize',
                 lines=30)

        # 可疑驱动文件 (非系统目录, 限深度)
        self._do(mk, '非系统目录驱动',
                 'Get-ChildItem -Path C:\\ -Depth 4 -Include *.sys -File -ErrorAction SilentlyContinue | Where-Object {$_.DirectoryName -notmatch "Windows\\\\System32\\\\drivers"} | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize',
                 lines=30)

        # 隐藏进程检测 (tasklist vs Get-Process)
        self._do(mk, 'tasklist 进程数', 'tasklist /fo csv | Measure-Object | Select-Object Count')
        self._do(mk, 'Get-Process 进程数', 'Get-Process | Measure-Object | Select-Object Count')

        # WMI 检查
        self._do(mk, 'WMI 安全', 'Get-WmiObject -Namespace root -Class __SystemSecurity -ErrorAction SilentlyContinue | Select-Object -First 5')

        # 可疑服务 (无路径/临时目录路径)
        susp_services = self.ps(
                 r'Get-CimInstance Win32_Service | Where-Object {$_.PathName -match "Temp|Downloads|Users|AppData" -or $_.PathName -match "powershell.*-enc|cmd\.exe.*/c|certutil"} | Select-Object Name,DisplayName,PathName,State | Format-Table -AutoSize'
        )
        self.results.setdefault(mk, {})['suspicious_services'] = susp_services
        self._pr('可疑服务', susp_services)

        # 检测无签名驱动
        unsigned = self.results.get(mk, {}).get('未签名/无效签名驱动', '')
        if unsigned.strip() and 'Driver' not in unsigned.split('\n')[0]:
            self._find('HIGH', 'Rootkit', '发现未签名/无效签名驱动', unsigned[:300])
        if susp_services.strip():
            self._find('HIGH', 'Rootkit', '发现可疑服务 (临时/用户目录路径)', susp_services[:300])

        # 非系统目录驱动文件
        nonsys_drv = self.results.get(mk, {}).get('非系统目录驱动', '')
        if nonsys_drv.strip() and 'FullName' not in nonsys_drv.split('\n')[0]:
            self._find('MEDIUM', 'Rootkit', '发现非系统目录的驱动文件', nonsys_drv[:300])

    # ============================================================
    # 模块 17: Windows Defender
    # ============================================================
    def scan_windows_defender(self):
        mk = 'windows_defender'
        # Defender 服务状态
        self._do(mk, 'Defender 服务',
                 'Get-Service | Where-Object {$_.Name -match "Defender|WdNisSvc"} | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize')

        # Defender 偏好设置
        self._do(mk, 'Defender 配置',
                 'Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,DisableIOAVProtection,DisableEmailScanning,ExclusionPath,ExclusionProcess,ExclusionExtension | Format-List')

        # 检测到的威胁
        self._do(mk, 'Defender 威胁历史',
                 'Get-MpThreatDetection | Select-Object ThreatID,DetectionID,InitialDetectionTime,Resources | Format-Table -AutoSize',
                 lines=40)
        self._do(mk, 'Defender 威胁列表',
                 'Get-MpThreat | Select-Object ThreatName,SeverityID,IsActive | Format-Table -AutoSize')

        # 隔离区文件列表
        self._do_raw(mk, 'Defender 隔离文件列表',
                     '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -ListAll 2>&1')

        # 恢复所有隔离文件
        self._do_raw(mk, 'Defender 恢复隔离文件',
                     '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -All 2>&1')

        # Defender 日志
        self._do(mk, 'Defender 运行日志',
                 'Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List',
                 lines=60)

        # 分析
        pref = self.results.get(mk, {}).get('Defender 配置', '')
        if 'DisableRealtimeMonitoring' in pref and 'True' in pref:
            self._find('HIGH', 'Defender', 'Defender 实时保护已禁用', pref[:200])
        if 'ExclusionPath' in pref and re.search(r'[A-Z]:\\', pref):
            self._find('MEDIUM', 'Defender', 'Defender 存在排除路径', pref[:300])

        threats = self.results.get(mk, {}).get('Defender 威胁列表', '')
        if threats.strip() and 'ThreatName' not in threats.split('\n')[0]:
            self._find('HIGH', '恶意软件', 'Defender 检测到威胁', threats[:300])

        # 恢复的隔离文件
        restored = self.results.get(mk, {}).get('Defender 恢复隔离文件', '')
        if restored.strip() and 'no items' not in restored.lower() and 'Add-MpPreference' not in restored:
            self._find('INFO', 'Defender', 'Defender 隔离区有文件已恢复', restored[:300])
    # ============================================================
    # 智能异常分析 (基线对比)
    # ============================================================
    def analyze_anomalies(self):
        """后置智能异常分析: 对比内置基线, 自动发现异常"""
        self._sec(99, '智能异常分析 (基线对比)')
        print(C.cyan('  [>] 对所有采集数据与内置正常基线进行对比分析...\n'))

        # ===== 1. 用户与权限分析 =====
        print(C.bold('  > 用户与权限分析'))
        local_users = self.results.get('users', {}).get('本地用户', '')
        wmi_users = self.results.get('users', {}).get('WMI 用户 (含隐藏)', '')
        admins = self.results.get('users', {}).get('管理员组成员', '')

        DEFAULT_USERS = {
            'Administrator', 'DefaultAccount', 'WDAGUtilityAccount',
            'Guest', 'SYSTEM', 'TrustedInstaller',
        }

        # 非默认用户检测
        all_user_lines = wmi_users + '\n' + local_users
        found_users = set()
        for line in all_user_lines.splitlines():
            m = re.match(r'\s*(\S+)\s', line)
            if m and m.group(1) not in ('Name', ''):
                found_users.add(m.group(1))
        non_default = found_users - DEFAULT_USERS
        if len(non_default) > 3:
            print(C.yellow('    [?] 非默认用户 (%d): %s' % (
                len(non_default), ', '.join(sorted(non_default)[:10]))))

        # 隐藏账户 ($ 结尾)
        for u in found_users:
            if u.endswith('$') and u not in DEFAULT_USERS:
                self._find('HIGH', '隐藏账户',
                           '发现隐藏账户 ($结尾): %s' % u,
                           'net user 不可见, WMI 可见')

        # 被禁用的 Administrator
        for line in local_users.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'Administrator' and 'False' in line:
                self._find('LOW', '账户安全',
                           'Administrator 账户被禁用', line.strip())
                break

        # 多管理员
        admin_lines = [l for l in admins.splitlines()
                       if l.strip() and 'Name' not in l and '--' not in l
                       and 'SID' not in l]
        if len(admin_lines) > 3:
            self._find('MEDIUM', '权限提升',
                       '管理员组异常 (%d 个成员)' % len(admin_lines),
                       admins[:300])
        else:
            print(C.green('    [+] 管理员组正常 (%d)' % len(admin_lines)))

        # ===== 2. 网络端口基线分析 =====
        print(C.bold('\n  > 网络端口分析'))
        listen_raw = self.results.get('network', {}).get('监听端口', '')
        listen_raw += self.results.get('network', {}).get('netstat -ano', '')

        known_ports = set()
        unknown_ports = set()
        db_exposed = []

        for line in listen_raw.splitlines():
            if 'Listen' not in line and 'LISTENING' not in line:
                continue
            m = re.search(r':(\d+)\s', line)
            if not m:
                m = re.search(r'\s(\d+)\s', line)
            if not m:
                continue
            port = m.group(1)

            if port in DB_PORTS:
                if re.search(r'0\.0\.0\.0|::|\*', line):
                    db_exposed.append('%s (%s) 对外监听' % (port, DB_PORTS[port]))
                else:
                    known_ports.add('%s (%s, 本地)' % (port, DB_PORTS[port]))
            elif port in SAFE_PORTS or port in ('135', '139', '445', '5040'):
                known_ports.add('%s (%s)' % (port, SAFE_PORTS.get(port, 'System')))
            else:
                unknown_ports.add('%s -> %s' % (port, line.strip()))

        if known_ports:
            print(C.green('    [+] 已知服务端口: ' + ', '.join(sorted(known_ports)[:15])))
        if db_exposed:
            for d in db_exposed:
                self._find('HIGH', '端口暴露',
                           '数据库/缓存对外监听: %s' % d, d)
        if unknown_ports:
            self._find('MEDIUM', '端口异常',
                       '发现非标准端口 (%d 个)' % len(unknown_ports),
                       '\n'.join(list(unknown_ports)[:10]))
        elif not db_exposed:
            print(C.green('    [+] 未发现异常端口'))

        # ===== 3. hosts 文件 DNS 劫持检测 =====
        print(C.bold('\n  > hosts 文件分析'))
        hosts = self.results.get('network', {}).get('hosts 文件', '')
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
                       'hosts 文件中发现域名劫持条目',
                       '\n'.join(hijack_entries))
        else:
            print(C.green('    [+] hosts 文件无域名劫持'))

        # ===== 4. RDP 配置基线分析 =====
        print(C.bold('\n  > RDP 配置分析'))
        rdp_enabled = self.results.get('rdp_security', {}).get('RDP 状态', '')
        rdp_nla = self.results.get('rdp_security', {}).get('RDP NLA 设置', '')
        rdp_sec = self.results.get('rdp_security', {}).get('RDP 安全层', '')

        rdp_issues = []
        if rdp_enabled.strip() == '0':
            rdp_issues.append('RDP 已启用 (fDenyTSConnections=0)')
        if rdp_nla.strip() == '0':
            rdp_issues.append('NLA 未启用 (网络安全风险)')
        if rdp_sec.strip() == '0':
            rdp_issues.append('安全层=0 (最低安全)')

        if rdp_issues:
            self._find('MEDIUM', 'RDP 配置',
                       'RDP 安全配置存在弱项', '\n'.join(rdp_issues))
        elif rdp_enabled.strip() == '1':
            print(C.green('    [+] RDP 已禁用'))
        else:
            print('    [-] RDP 配置数据不完整')

        # ===== 5. Defender 配置分析 =====
        print(C.bold('\n  > Defender 配置分析'))
        def_pref = self.results.get('windows_defender', {}).get('Defender 配置', '')
        def_issues = []
        if 'DisableRealtimeMonitoring' in def_pref:
            m = re.search(r'DisableRealtimeMonitoring\s*:\s*(\S+)', def_pref)
            if m and m.group(1).lower() == 'true':
                def_issues.append('实时保护已禁用')
        if 'ExclusionPath' in def_pref:
            m = re.search(r'ExclusionPath\s*:\s*\{?(.+?)\}?\s*$', def_pref, re.M)
            if m and m.group(1).strip():
                def_issues.append('存在排除路径 (可能屏蔽恶意文件)')

        if def_issues:
            self._find('MEDIUM', 'Defender',
                       'Defender 配置存在安全弱项', '\n'.join(def_issues))
        else:
            print(C.green('    [+] Defender 配置正常'))

        # ===== 6. 启动项白名单分析 =====
        print(C.bold('\n  > 启动项白名单分析'))
        hklm_run = self.results.get('startup', {}).get('HKLM Run', '')
        hkcu_run = self.results.get('startup', {}).get('HKCU Run', '')
        all_run = hklm_run + '\n' + hkcu_run
        unknown_autoruns = []
        for line in all_run.splitlines():
            m = re.match(r'\s*(\S+)\s*:\s*(.+)', line)
            if m and m.group(1) not in DEFAULT_AUTORUN_WHITELIST \
                    and m.group(1) not in ('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'):
                unknown_autoruns.append(line.strip())

        if unknown_autoruns:
            self._find('MEDIUM', '启动项异常',
                       '发现非默认自启动项 (%d)' % len(unknown_autoruns),
                       '\n'.join(unknown_autoruns[:10]))
        else:
            print(C.green('    [+] 自启动项在白名单内'))

        # ===== 7. 攻击链推断 =====
        print(C.bold('\n  > 攻击链推断'))
        cats = set(f['category'] for f in self.findings)
        attack_steps = []
        if '暴力破解' in cats:
            attack_steps.append('暴力破解')
        if 'Web 攻击' in cats or 'Webshell' in cats:
            attack_steps.append('Web 渗透/Webshell')
        if '隐藏账户' in cats or '后门账户' in cats or '反弹Shell' in cats:
            attack_steps.append('后门植入')
        if '持久化' in cats or '计划任务' in cats or '启动项异常' in cats:
            attack_steps.append('持久化')
        if '挖矿' in cats:
            attack_steps.append('挖矿伪装')
        if 'DLL注入' in cats or 'Rootkit' in cats:
            attack_steps.append('Rootkit/注入')
        if 'Defender' in cats:
            attack_steps.append('安全软件禁用')

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
            'is_admin': bool(self._is_admin),
            'webroots': self.webroots,
            'risk_score': score,
            'risk_level': level,
            'severity_counts': counts,
            'total_findings': len(self.findings),
        }

        box_w = 62
        print("\n" + "+" + "-" * box_w + "+")
        title = "  Windows 应急响应扫描报告"
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

    # ============================================================
    # 文件输出
    # ============================================================
    def save_json(self, filepath):
        payload = {
            'meta': self.results.get('__meta__', {
                'target': '%s:%s' % (self.host, self.port),
                'user': self.user,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration_sec': round(self.scan_duration, 1),
            }),
            'modules': {k: v for k, v in self.results.items() if k != '__meta__'},
            'findings': self.findings,
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

        mod_key_map = {
            1: 'system_info', 2: 'network', 3: 'users', 4: 'processes',
            5: 'scheduled_tasks', 6: 'startup', 7: 'filesystem',
            8: 'hidden_flags', 9: 'powershell_history', 10: 'web_logs',
            11: 'webshell', 12: 'database', 13: 'rdp_security',
            14: 'pcap', 15: 'malware', 16: 'rootkit', 17: 'windows_defender',
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

        html = '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows 应急响应扫描报告 - {target}</title>
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
<h1>Windows 应急响应扫描报告</h1>
<div class="meta">
<table>
<tr><td class="k">目标主机</td><td>{target}</td>
    <td class="k">登录用户</td><td>{user}</td></tr>
<tr><td class="k">扫描时间</td><td>{scantime}</td>
    <td class="k">扫描耗时</td><td>{duration} 秒</td></tr>
<tr><td class="k">是否管理员</td><td>{isadmin}</td>
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
<p style="color:#8b949e;margin-top:30px;text-align:center">
Generated by Windows IR Scanner v1.0 &middot; {scantime}</p>
</body></html>'''.format(
            target=esc(meta.get('target', '%s:%s' % (self.host, self.port))),
            user=esc(self.user),
            scantime=meta.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            duration=meta.get('duration_sec', round(self.scan_duration, 1)),
            isadmin='是' if meta.get('is_admin') else '否',
            webroots=esc(', '.join(meta.get('webroots', self.webroots)) or '未检测'),
            score=score, level=level,
            high=counts.get('HIGH', 0), medium=counts.get('MEDIUM', 0),
            low=counts.get('LOW', 0), info=counts.get('INFO', 0),
            total=len(self.findings),
            findrows=''.join(find_rows) or '<tr><td colspan="5" style="text-align:center;color:#8b949e">无发现</td></tr>',
            modcards=''.join(mod_cards) or '<i>无模块数据</i>',
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
            if any(m in range(7, 14) for m in mod_nums):
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
        description="Windows 自动化应急响应扫描器 (18 模块, WinRM/pypsrp)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('-H', '--host', required=True, help='目标主机 IP')
    parser.add_argument('-p', '--port', type=int, default=5985, help='WinRM 端口 (默认 5985)')
    parser.add_argument('-U', '--user', required=True, help='用户名 (如 Administrator)')
    parser.add_argument('-P', '--password', required=True, help='密码')
    parser.add_argument('--webroot', help='指定 Web 根目录 (可多个, 逗号分隔)')
    parser.add_argument('--timeout', type=int, default=60, help='WinRM/命令超时秒数 (默认 60)')
    parser.add_argument('--json', metavar='FILE', help='输出 JSON 报告到文件')
    parser.add_argument('--report', metavar='FILE', help='输出 HTML 报告到文件')
    parser.add_argument('--modules', help='仅运行指定模块 (逗号分隔, 如 1,2,3,8)')
    args = parser.parse_args()

    banner()

    wr = args.webroot
    if wr and ',' in wr:
        wr = wr.split(',')[0].strip()

    scanner = IRScanner(
        host=args.host, port=args.port, user=args.user,
        password=args.password, webroot=wr, timeout=args.timeout,
    )

    if args.webroot and ',' in args.webroot:
        extra = [w.strip() for w in args.webroot.split(',') if w.strip()][1:]
        scanner.webroots = extra

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