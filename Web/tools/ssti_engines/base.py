"""
CTF 解题工具 — SSTI 引擎基类
用途: 定义各引擎模块的统一接口，面向 CTF 竞赛的 SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

每个引擎模块继承 BaseEngine 并实现以下属性/方法:
  - name: 引擎标识
  - rce_chains: RCE 利用链列表
  - file_read_chains: 文件读取链列表
  - detect_payloads: 检测 payload
  - fingerprints: 引擎指纹
  - bypass_strategies: WAF 绕过策略列表
  - template_tags: 模板标签元组 (如 ('{{', '}}', '{%', '%}') )
  - error_keywords: 引擎特有的错误关键词
  - probe_waf(toolkit): WAF 探测逻辑
  - build_rce_payload(cmd, toolkit): 构造 RCE payload
  - build_file_payload(filepath, toolkit): 构造文件读取 payload
  - info_gathering(toolkit): 信息收集
  - sanitize_cmd_for_space(cmd, waf_filters): 空格替代
"""


class BaseEngine:
    """引擎基类 — 各引擎子类填充数据和方法"""

    name = 'base'
    template_tags = ('{{', '}}', '{%', '%}')
    error_keywords = [
        'Internal Server Error', 'Traceback', 'TypeError',
        'AttributeError', 'NameError', 'not defined', 'SyntaxError',
        'TemplateSyntaxError',
    ]

    # 子类覆盖以下属性
    rce_chains = []
    file_read_chains = []
    detect_payloads = []
    fingerprints = []
    bypass_strategies = []

    def __init__(self):
        self.filtered_keywords = set()
        self.waf_filters = set()

    # ---- WAF 探测 ----

    def probe_waf(self, toolkit):
        """
        WAF 探测入口。子类应实现具体探测逻辑。
        返回: (filters_set, filtered_keywords_set)
        """
        return set(), set()

    def select_bypass(self, waf_filters):
        """根据探测到的过滤规则选择最佳绕过策略"""
        if not self.bypass_strategies:
            return None
        # 精确匹配
        for strategy in self.bypass_strategies:
            if strategy['filters'] == waf_filters:
                return strategy
        # 子集匹配: 策略 filters ⊆ waf_filters，选覆盖最多的
        best = None
        best_coverage = 0
        for strategy in self.bypass_strategies:
            if not strategy['filters']:
                continue
            if not strategy['filters'].issubset(waf_filters):
                continue
            covered = len(strategy['filters'])
            if covered > best_coverage:
                best = strategy
                best_coverage = covered
        return best or self.bypass_strategies[0]

    # ---- Payload 构造 ----

    def build_rce_payload(self, cmd, toolkit=None):
        """
        构造 RCE payload。默认实现:
        1. 若 working_chain 是已验证的静态链 (含 CMD), 直接使用
        2. 若 working_bypass 有字符串 rce 模板 (含 CMD), 使用该模板
        3. 回退到 rce_chains[0]
        返回: (payload, extra_params) 或 (None, None)
        """
        # 1. 已验证的静态链
        wc = getattr(toolkit, 'working_chain', None) if toolkit else None
        if wc and isinstance(wc, str) and 'CMD' in wc:
            extra = None
            strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
            if strategy and strategy.get('extra_params'):
                extra = {k: v.replace('CMD', cmd) if v == 'CMD' else v
                         for k, v in strategy['extra_params'].items()}
            return wc.replace('CMD', cmd), extra

        # 2. bypass 策略模板
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and isinstance(strategy.get('rce'), str) and 'CMD' in strategy['rce']:
            rce = strategy['rce'].replace('CMD', cmd)
            extra = strategy.get('extra_params')
            if extra:
                extra = {k: v.replace('CMD', cmd) if v == 'CMD' else v
                         for k, v in extra.items()}
            return rce, extra

        # 3. 默认: 第一条链
        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """
        构造文件读取 payload。默认实现:
        1. 若 working_bypass 有字符串 file_read 模板 (含 FILEPATH), 使用该模板
        2. 回退到 file_read_chains[0]
        返回: (payload, extra_params) 或 (None, None)
        """
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and strategy.get('file_read') and 'FILEPATH' in str(strategy['file_read']):
            return strategy['file_read'].replace('FILEPATH', filepath), None

        for chain in self.file_read_chains:
            return chain.replace('FILEPATH', filepath), None
        return None, None

    # ---- 命令预处理 ----

    def sanitize_cmd_for_space(self, cmd, waf_filters=None):
        """
        当空格被 WAF 过滤时，将命令转换为不含空格的等价形式。
        子类可覆盖以实现引擎特定的处理。
        """
        if not waf_filters or 'space' not in waf_filters:
            return cmd
        parts = cmd.split(' ')
        if len(parts) == 2 and parts[0] in ('cat', 'tac', 'head', 'tail', 'sort'):
            return f'{parts[0]}<{parts[1]}'
        return cmd.replace(' ', '\t')

    def sanitize_cmd_for_keywords(self, cmd, filtered_keywords=None):
        """
        当命令本身含被过滤关键字时，寻找替代命令。
        子类可覆盖以实现引擎特定的处理。
        """
        if not filtered_keywords:
            return cmd
        cmd_replacements = {
            'cat': ['tac', 'head -100', 'sort', 'strings'],
            'find': ['ls -R'],
        }
        words = cmd.split()
        if not words:
            return cmd
        first_word = words[0]
        for kw, alternatives in cmd_replacements.items():
            if kw in filtered_keywords and kw in first_word:
                for alt in alternatives:
                    if not any(fw in alt for fw in filtered_keywords):
                        words[0] = alt
                        return ' '.join(words)
        return cmd

    # ---- 信息收集 ----

    def info_gathering(self, toolkit):
        """
        信息收集。子类应实现具体逻辑。
        toolkit: SSTIToolkit 实例，提供 send_and_clean / exec_cmd 等方法
        """
        print(f"\n  [*] 引擎 {self.name} 信息收集 — 使用默认实现")
        if toolkit.working_chain:
            output = toolkit.exec_cmd('id')
            if output:
                print(f"      {output[:300]}")

    # ---- 输出验证 ----

    def is_rce_output(self, text, cmd, toolkit=None):
        """
        判断响应是否包含有效的 RCE 输出。
        子类可覆盖以实现引擎特定的判断逻辑。
        """
        if not text or len(text) < 2:
            return False
        from .utils import is_waf_blocked
        if is_waf_blocked(text):
            return False
        # 排除模板标签残留
        for tag in self.template_tags:
            if tag[0] in text:  # tag 是 ('{{','}}') 对，检查开标签
                return False
        # 排除错误信息
        for kw in self.error_keywords:
            if kw in text:
                return False
        if cmd == 'id':
            return 'uid=' in text or 'gid=' in text
        # 与基准页面比较
        if toolkit:
            baseline = toolkit._get_baseline()
            if baseline and baseline == text.strip():
                return False
        return len(text) > 0
