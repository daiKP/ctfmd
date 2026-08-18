#!/usr/bin/env python3
"""
CTF 目录扫描工具 (web_dir_scanner.py)
=====================================
竞赛中快速扫描 Web 目录和敏感文件，支持：
1. 自定义字典 / 内置常用路径
2. 多线程并发
3. 状态码智能过滤
4. 响应大小对比去重
5. 递归扫描

核心依赖: requests, concurrent.futures

使用方式:
  python web_dir_scanner.py -u "http://target.com/" -t 20
  python web_dir_scanner.py -u "http://target.com/" -w custom_wordlist.txt
  python web_dir_scanner.py -u "http://target.com/" --ext php,bak,txt --recursive

比赛时只需替换目标 URL 即可。
"""

import argparse
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)

# ============================================================
# 内置常用字典
# ============================================================

COMMON_DIRS = [
    # 管理后台
    'admin', 'administrator', 'admin/login', 'manage', 'management',
    'backend', 'dashboard', 'cp', 'controlpanel', 'system',
    # 常见目录
    'backup', 'backups', 'old', 'test', 'tmp', 'temp', 'cache',
    'config', 'conf', 'data', 'db', 'database', 'sql',
    'upload', 'uploads', 'file', 'files', 'download',
    'api', 'api/v1', 'api/v2', 'swagger', 'docs', 'doc',
    'static', 'assets', 'images', 'img', 'css', 'js',
    'include', 'includes', 'lib', 'libs', 'src',
    'log', 'logs', 'runtime', 'debug',
    # 框架特征
    'wp-admin', 'wp-content', 'wp-login.php',
    'phpmyadmin', 'pma', 'mysql', 'phpinfo.php',
    '.git', '.svn', '.env', '.ds_store',
    'WEB-INF', 'META-INF',
    # 常见文件
    'index.php.bak', 'index.php~', 'index.php.swp',
    'config.php.bak', 'db.php.bak', 'conn.php.bak',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml',
    '.htaccess', 'web.config', 'package.json', 'composer.json',
    'flag', 'flag.txt', 'flag.php',
]

COMMON_EXTENSIONS = ['', '.php', '.html', '.htm', '.txt', '.bak', '.zip', '.tar.gz', '.sql']

# ============================================================
# 扫描器
# ============================================================

class DirScanner:
    """多线程目录扫描器"""

    def __init__(self, base_url, threads=10, timeout=10,
                 extensions=None, cookies=None, headers=None,
                 proxy=None, recursive=False, max_depth=2):
        self.base_url = base_url.rstrip('/') + '/'
        self.threads = threads
        self.timeout = timeout
        self.extensions = extensions or ['']
        self.recursive = recursive
        self.max_depth = max_depth
        self.results = []
        self.lock = threading.Lock()
        self.scanned = set()

        self.session = requests.Session()
        self.session.mount('http://', HTTPAdapter(pool_connections=threads, pool_maxsize=threads * 2))
        self.session.mount('https://', HTTPAdapter(pool_connections=threads, pool_maxsize=threads * 2))

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if cookies:
            self.session.headers['Cookie'] = cookies
        if headers:
            self.session.headers.update(headers)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        # 基准响应（用于过滤自定义 404 页面）
        self.baseline_404 = None
        self.baseline_size = None
        self._init_baseline()

    def _init_baseline(self):
        """获取基准响应，用于检测自定义 404"""
        # 请求一个一定不存在的路径
        test_path = f"not_exist_{int(time.time())}.html"
        try:
            resp = self.session.get(
                urljoin(self.base_url, test_path),
                timeout=self.timeout,
                allow_redirects=False
            )
            self.baseline_404 = resp.status_code
            self.baseline_size = len(resp.text)
        except:
            pass

    def _is_real_found(self, resp, path):
        """
        判断路径是否真实存在。
        过滤自定义 404、软 404。
        """
        if resp is None:
            return False

        # 状态码判断
        if resp.status_code in (200, 301, 302, 403):
            # 403 可能是存在但禁止访问
            if resp.status_code == 403:
                return True

            # 过滤自定义 404: 状态码 200 但内容与基准 404 相同
            if self.baseline_404 == 200 and self.baseline_size:
                if abs(len(resp.text) - self.baseline_size) < 50:
                    return False

            return True

        return False

    def scan_path(self, path):
        """扫描单个路径"""
        for ext in self.extensions:
            full_path = path + ext
            url = urljoin(self.base_url, full_path)

            if url in self.scanned:
                continue
            self.scanned.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if self._is_real_found(resp, full_path):
                    with self.lock:
                        self.results.append({
                            'url': url,
                            'status': resp.status_code,
                            'size': len(resp.text),
                            'path': full_path,
                        })
                        status_str = f"{resp.status_code}"
                        size_str = f"{len(resp.text)}B"
                        print(f"  [{status_str:>3s}] {size_str:>8s}  {url}")

                        # 如果是目录且递归开启
                        if self.recursive and resp.status_code in (200, 301, 302):
                            if not full_path.endswith('/'):
                                # 尝试加 /
                                pass  # 递归扫描由外层控制
            except requests.RequestException:
                pass
            except Exception:
                pass

    def scan(self, wordlist):
        """执行扫描"""
        print(f"[*] 目标: {self.base_url}")
        print(f"[*] 线程数: {self.threads}")
        print(f"[*] 字典大小: {len(wordlist)}")
        print(f"[*] 扩展名: {self.extensions}")
        print(f"[*] 基准404: status={self.baseline_404}, size={self.baseline_size}")
        print(f"{'='*60}")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_path, path): path for path in wordlist}
            for future in as_completed(futures):
                future.result()

        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[*] 扫描完成: {len(self.results)} 个结果, 耗时 {elapsed:.1f}s")

        return self.results

    def scan_recursive(self, wordlist, depth=1):
        """递归扫描"""
        self.scan(wordlist)

        if depth >= self.max_depth:
            return self.results

        # 收集发现的目录
        found_dirs = [r['path'] for r in self.results
                      if r['status'] in (200, 301, 302) and not '.' in r['path'].rstrip('/')]

        if found_dirs:
            print(f"\n[*] 递归扫描第 {depth+1} 层...")
            for d in found_dirs:
                # 构造新字典
                new_wordlist = [f"{d}/{w}" for w in wordlist]
                self.scan(new_wordlist)

        return self.results


# ============================================================
# 字典加载
# ============================================================

def load_wordlist(filepath):
    """从文件加载字典"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] 字典文件不存在: {filepath}")
        return []

def get_default_wordlist():
    """获取内置字典"""
    return COMMON_DIRS


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='CTF 目录扫描工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用内置字典
  python web_dir_scanner.py -u "http://target.com/"

  # 自定义字典和线程
  python web_dir_scanner.py -u "http://target.com/" -w wordlist.txt -t 30

  # 指定扩展名
  python web_dir_scanner.py -u "http://target.com/" --ext php,bak,txt

  # 递归扫描
  python web_dir_scanner.py -u "http://target.com/" --recursive --depth 3

  # 带认证
  python web_dir_scanner.py -u "http://target.com/" --cookies "session=abc123"
        """
    )

    parser.add_argument('-u', '--url', required=True, help='目标 URL')
    parser.add_argument('-w', '--wordlist', help='自定义字典文件路径')
    parser.add_argument('-t', '--threads', type=int, default=10, help='线程数 (默认 10)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时 (秒)')
    parser.add_argument('--ext', help='扩展名，逗号分隔 (如 php,bak,txt)')
    parser.add_argument('--cookies', help='Cookie 字符串')
    parser.add_argument('--proxy', help='HTTP 代理')
    parser.add_argument('--recursive', action='store_true', help='递归扫描子目录')
    parser.add_argument('--depth', type=int, default=2, help='递归深度 (默认 2)')

    args = parser.parse_args()

    # 加载字典
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            print("[!] 字典为空，使用内置字典")
            wordlist = get_default_wordlist()
    else:
        wordlist = get_default_wordlist()
        print("[*] 使用内置字典 (添加 -w 可指定自定义字典)")

    # 解析扩展名
    extensions = ['']
    if args.ext:
        extensions = ['']
        for e in args.ext.split(','):
            e = e.strip()
            if not e.startswith('.'):
                e = '.' + e
            extensions.append(e)
        # 也保留无扩展名
        if '' not in extensions:
            extensions.insert(0, '')

    # 创建扫描器
    scanner = DirScanner(
        base_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        extensions=extensions,
        cookies=args.cookies,
        proxy=args.proxy,
        recursive=args.recursive,
        max_depth=args.depth,
    )

    # 执行扫描
    if args.recursive:
        results = scanner.scan_recursive(wordlist, depth=1)
    else:
        results = scanner.scan(wordlist)

    # 输出汇总
    if results:
        print(f"\n[+] 发现 {len(results)} 个有效路径:")
        for r in sorted(results, key=lambda x: x['status']):
            print(f"    [{r['status']}] {r['url']}")
    else:
        print("\n[-] 未发现有效路径")


if __name__ == '__main__':
    main()
