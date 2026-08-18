#!/usr/bin/env python3
"""
CTF 解题工具 — PHP 代码审计辅助工具
====================================
用途: 面向 CTF 竞赛的 PHP 源码审计辅助
场景: 竞赛平台源码题 / 代码审计练习

功能模块:
1. 危险函数扫描：扫描 PHP 源码中的危险函数调用
2. 过滤分析：分析输入过滤逻辑，识别绕过路径
3. 流程追踪：追踪用户输入到危险函数的调用链
4. 审计报告：生成结构化审计报告

核心依赖: 无（纯 Python 标准库）

使用方式:
  # 扫描单个文件
  python web_php_audit.py -f source.php

  # 扫描目录
  python web_php_audit.py -d /path/to/php/project/

  # 生成详细报告
  python web_php_audit.py -d /path/to/project/ --report

比赛时将源码包解压后直接扫描即可。
"""

import argparse
import os
import re
import sys
from collections import defaultdict

# ============================================================
# 危险函数分类定义
# ============================================================

DANGEROUS_FUNCTIONS = {
    '命令执行': [
        'system', 'exec', 'passthru', 'shell_exec',
        'popen', 'proc_open', 'pcntl_exec',
        # 反引号执行: `$cmd`
    ],
    '代码执行': [
        'eval', 'assert', 'preg_replace',  # /e 修饰符
        'create_function', 'call_user_func',
        'call_user_func_array', 'array_map',
        'usort', 'uasort', 'uksort',
        'array_filter', 'array_walk',
    ],
    '文件操作': [
        'file_get_contents', 'file_put_contents',
        'fopen', 'fread', 'fwrite',
        'readfile', 'include', 'require',
        'include_once', 'require_once',
        'unlink', 'copy', 'rename',
        'move_uploaded_file',
    ],
    '数据库操作': [
        'mysql_query', 'mysqli_query',
        'PDO::query', 'PDO::exec',
    ],
    '反序列化': [
        'unserialize', 'maybe_unserialize',
    ],
    '信息泄露': [
        'phpinfo', 'debug_zval_dump',
        'debug_print_backtrace',
        'var_dump', 'print_r', 'var_export',
    ],
    '网络请求': [
        'file_get_contents',  # 可触发 SSRF
        'curl_exec', 'fsockopen',
        'SoapClient',
    ],
}

# ============================================================
# 常见过滤函数及其绕过方法
# ============================================================

FILTER_FUNCTIONS = {
    'str_replace': {
        'desc': '字符串替换过滤',
        'bypass': [
            '双写绕过: 过滤"select"时, "selselectect" → "select"',
            '大小写绕过: 过滤区分大小写时, "SELECT" 不会被过滤',
        ],
    },
    'preg_replace': {
        'desc': '正则替换过滤',
        'bypass': [
            '检查是否带 i 修饰符(不区分大小写)',
            '检查是否多行模式 m, 单行模式 s',
            '/e 修饰符可导致代码执行 (PHP < 7.0)',
        ],
    },
    'stripslashes': {
        'desc': '去除反斜杠',
        'bypass': [
            '使用编码绕过: 0x, \\x',
            '多重编码: \\\\\\\\x → \\x',
        ],
    },
    'htmlspecialchars': {
        'desc': 'HTML 实体编码',
        'bypass': [
            'JavaScript 上下文中不需要 < >',
            '使用 JavaScript 事件: onerror=',
            '宽字节绕过 (多字节编码时)',
        ],
    },
    'trim': {
        'desc': '去除首尾空白',
        'bypass': [],
    },
    'strip_tags': {
        'desc': '去除 HTML 标签',
        'bypass': [
            '利用 <?php ?> 标签绕过',
            '使用 <script> 标签',
            '双写标签: <<script>script>',
        ],
    },
    'addslashes': {
        'desc': '添加反斜杠',
        'bypass': [
            '宽字节注入 (GBK 编码): %bf%27 → 運\'',
            '数字型注入不需要引号',
            '二次注入: 数据入库时转义, 出库时不转义',
        ],
    },
    'mysql_real_escape_string': {
        'desc': 'MySQL 转义',
        'bypass': [
            '宽字节注入 (GBK)',
            '数字型注入',
            '二次注入',
        ],
    },
    'intval': {
        'desc': '转整数',
        'bypass': [
            '无法绕过, 但检查是否对所有参数都做了转换',
        ],
    },
}

# ============================================================
# 审计器
# ============================================================

class PHPAuditor:
    """PHP 源码审计器"""

    def __init__(self):
        self.results = []
        self.filter_chains = []
        self.files_scanned = 0
        self.lines_scanned = 0

    def scan_file(self, filepath):
        """扫描单个 PHP 文件"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"[!] 读取文件失败: {filepath}: {e}")
            return

        self.files_scanned += 1
        self.lines_scanned += len(lines)

        file_results = []

        # 扫描危险函数
        for category, functions in DANGEROUS_FUNCTIONS.items():
            for func in functions:
                # 构造正则: 函数名后跟 ( 或空格
                pattern = rf'\b{re.escape(func)}\s*(?:\(|\s|$)'
                for i, line in enumerate(lines, 1):
                    matches = list(re.finditer(pattern, line, re.IGNORECASE))
                    if matches:
                        # 过滤注释行
                        stripped = line.strip()
                        if stripped.startswith('//') or stripped.startswith('#'):
                            continue
                        if stripped.startswith('*') or stripped.startswith('/*'):
                            continue

                        for match in matches:
                            result = {
                                'file': filepath,
                                'line': i,
                                'category': category,
                                'function': func,
                                'code': line.strip(),
                                'context': self._get_context(lines, i),
                            }
                            file_results.append(result)
                            self.results.append(result)

        # 扫描反引号执行
        for i, line in enumerate(lines, 1):
            if '`' in line and not line.strip().startswith('//'):
                # 检查是否是反引号执行（排除注释和字符串中的反引号）
                backtick_count = line.count('`')
                if backtick_count >= 2 and backtick_count % 2 == 0:
                    result = {
                        'file': filepath,
                        'line': i,
                        'category': '命令执行',
                        'function': 'backtick `cmd`',
                        'code': line.strip(),
                        'context': self._get_context(lines, i),
                    }
                    file_results.append(result)
                    self.results.append(result)

        # 扫描过滤函数
        for func_name, info in FILTER_FUNCTIONS.items():
            pattern = rf'\b{re.escape(func_name)}\s*\('
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    self.filter_chains.append({
                        'file': filepath,
                        'line': i,
                        'function': func_name,
                        'desc': info['desc'],
                        'bypass': info.get('bypass', []),
                        'code': line.strip(),
                    })

        # 扫描动态调用
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # $func() 可变函数调用
            if re.search(r'\$\w+\s*\(', stripped) and not stripped.startswith('//'):
                # 排除数组访问
                if not re.search(r'\$\w+\[', stripped):
                    result = {
                        'file': filepath,
                        'line': i,
                        'category': '代码执行',
                        'function': '可变函数 $var()',
                        'code': stripped,
                        'context': self._get_context(lines, i),
                    }
                    file_results.append(result)
                    self.results.append(result)

        # 输出单文件结果
        if file_results:
            print(f"\n[+] {filepath} — 发现 {len(file_results)} 个风险点:")
            for r in file_results:
                print(f"    [{r['category']}] 第 {r['line']} 行: {r['function']}()")
                print(f"      代码: {r['code'][:80]}")

    def scan_directory(self, dirpath, exclude=None):
        """扫描目录下所有 PHP 文件"""
        if exclude is None:
            exclude = ['vendor', 'node_modules', '.git', 'tests', 'test']

        print(f"[*] 扫描目录: {dirpath}")
        php_files = []

        for root, dirs, files in os.walk(dirpath):
            # 排除目录
            dirs[:] = [d for d in dirs if d not in exclude and not d.startswith('.')]

            for f in files:
                if f.endswith('.php') or f.endswith('.php5') or f.endswith('.php7') or f.endswith('.phtml'):
                    php_files.append(os.path.join(root, f))

        print(f"[*] 发现 {len(php_files)} 个 PHP 文件")

        for filepath in php_files:
            self.scan_file(filepath)

        print(f"\n[*] 扫描完成: {self.files_scanned} 个文件, {self.lines_scanned} 行代码")

    def _get_context(self, lines, line_num, context_size=2):
        """获取上下文"""
        start = max(0, line_num - 1 - context_size)
        end = min(len(lines), line_num + context_size)
        context_lines = []
        for i in range(start, end):
            marker = '>>>' if i == line_num - 1 else '   '
            context_lines.append(f"{marker} {i+1}: {lines[i]}")
        return '\n'.join(context_lines)

    # ============================================================
    # 输入流追踪
    # ============================================================

    def trace_input(self, filepath):
        """
        追踪用户输入到危险函数的调用链。
        识别 $_GET, $_POST, $_REQUEST, $_COOKIE 等超全局变量的使用。
        """
        print(f"\n[*] 输入流追踪: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            return

        input_sources = [
            r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE',
            r'\$_SERVER', r'\$_FILES', r'php://input',
        ]

        # 找到所有输入点
        input_points = []
        for i, line in enumerate(lines, 1):
            for src in input_sources:
                if re.search(src, line):
                    input_points.append({
                        'line': i,
                        'source': src.replace('\\', ''),
                        'code': line.strip(),
                    })

        if input_points:
            print(f"  [+] 发现 {len(input_points)} 个输入点:")
            for p in input_points:
                print(f"    第 {p['line']} 行 [{p['source']}]: {p['code'][:80]}")

            # 检查输入是否直接进入危险函数
            print(f"\n  [*] 检查输入到危险函数的调用链:")
            for point in input_points:
                # 检查同一行是否有危险函数
                line = point['code']
                for category, functions in DANGEROUS_FUNCTIONS.items():
                    for func in functions:
                        if re.search(rf'\b{re.escape(func)}\s*\(', line):
                            print(f"    [!] 第 {point['line']} 行: 输入直接进入 {func}() — {category}")
                            print(f"        代码: {line[:80]}")

            # 检查变量赋值后的传播
            self._trace_variable_propagation(lines, input_points)
        else:
            print("  [-] 未发现用户输入点")

    def _trace_variable_propagation(self, lines, input_points):
        """追踪变量赋值传播"""
        # 提取输入点涉及的变量名
        input_vars = set()
        for point in input_points:
            # 查找 $var = $_GET[...] 模式
            matches = re.findall(r'(\$\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)', point['code'])
            input_vars.update(matches)

        if not input_vars:
            return

        print(f"\n  [*] 追踪输入变量: {input_vars}")

        # 追踪每个变量在后续代码中的使用
        for var in input_vars:
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if var in stripped and not stripped.startswith('//'):
                    # 检查是否进入危险函数
                    for category, functions in DANGEROUS_FUNCTIONS.items():
                        for func in functions:
                            if re.search(rf'\b{re.escape(func)}\s*\(', stripped) and var in stripped:
                                print(f"    [!] 第 {i} 行: {var} 进入 {func}() — {category}")
                                print(f"        代码: {stripped[:80]}")
                                break

    # ============================================================
    # 生成报告
    # ============================================================

    def generate_report(self):
        """生成审计报告"""
        print(f"\n{'='*60}")
        print("CTF PHP 代码审计报告")
        print(f"{'='*60}")

        print(f"\n[扫描统计]")
        print(f"  文件数: {self.files_scanned}")
        print(f"  代码行: {self.lines_scanned}")
        print(f"  风险点: {len(self.results)}")
        print(f"  过滤点: {len(self.filter_chains)}")

        # 按分类统计
        categories = defaultdict(list)
        for r in self.results:
            categories[r['category']].append(r)

        print(f"\n[风险分布]")
        for cat, items in sorted(categories.items(), key=lambda x: -len(x[1])):
            print(f"  {cat}: {len(items)} 个")

        # 详细风险列表
        print(f"\n[风险详情]")
        for r in self.results:
            print(f"  [{r['category']}] {r['file']}:{r['line']}")
            print(f"    函数: {r['function']}")
            print(f"    代码: {r['code'][:80]}")

        # 过滤分析
        if self.filter_chains:
            print(f"\n[过滤分析]")
            for fc in self.filter_chains:
                print(f"  {fc['function']} — {fc['desc']}")
                print(f"    位置: {fc['file']}:{fc['line']}")
                print(f"    代码: {fc['code'][:80]}")
                if fc['bypass']:
                    print(f"    绕过方法:")
                    for b in fc['bypass']:
                        print(f"      - {b}")

        # 建议
        print(f"\n[审计建议]")
        suggestions = set()
        for r in self.results:
            if r['category'] == '命令执行':
                suggestions.add("检查命令执行函数的参数是否可控，是否有 escapeshellarg 过滤")
            elif r['category'] == '代码执行':
                suggestions.add("检查 eval/assert 的参数是否可控，是否有过滤")
            elif r['category'] == '文件操作':
                suggestions.add("检查文件路径是否可控，是否允许路径穿越")
            elif r['category'] == '反序列化':
                suggestions.add("检查 unserialize 的输入是否可控，是否有反序列化链")
            elif r['category'] == '数据库操作':
                suggestions.add("检查 SQL 查询是否使用参数化查询，是否有注入点")

        for s in suggestions:
            print(f"  - {s}")

        print(f"\n{'='*60}")


# ============================================================
# PHP 代码审计速查表
# ============================================================

PHP_AUDIT_CHEATSHEET = """
============================================================
CTF PHP 代码审计速查表
============================================================

【1. 危险函数优先级】
  ★★★ 命令执行: system, exec, passthru, shell_exec, `cmd`
  ★★★ 代码执行: eval, assert, preg_replace(/e), create_function
  ★★★ 反序列化: unserialize
  ★★☆ 文件包含: include, require（路径可控时）
  ★★☆ 文件操作: file_put_contents, move_uploaded_file
  ★☆☆ 信息泄露: phpinfo, var_dump

【2. 常见过滤绕过】
  str_replace → 双写: selselectect → select
  preg_replace → 检查修饰符: i(大小写) s(单行) e(执行)
  addslashes → 宽字节: %bf%27 (GBK编码)
  htmlspecialchars → JS上下文不需要 <>

【3. 输入源追踪】
  $_GET, $_POST, $_REQUEST, $_COOKIE
  $_SERVER['HTTP_*'] (HTTP 头)
  $_FILES (文件上传)
  php://input (请求体)
  file_get_contents("php://input")

【4. 常见 CTF 考点】
  - 弱类型比较: == vs ===, 0 == "admin", "0e123" == "0e456"
  - 伪协议: php://filter, php://input, data://
  - 反序列化链: __wakeup, __destruct, __toString, __call
  - 变量覆盖: extract(), parse_str(), $$var
  - 二次注入: 入库时转义, 出库使用时不转义
  - 宽字节注入: addslashes + GBK → %bf%27
  - preg_replace /e: preg_replace('/test/e', $code, $input)
  - intval 截断: intval("1e10") = 1

【5. 审计流程】
  1. 全局扫描危险函数
  2. 追踪用户输入到危险函数的路径
  3. 分析路径上的过滤函数
  4. 尝试绕过过滤
  5. 构造利用链

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='CTF 竞赛 PHP 代码审计辅助工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描单个文件
  python web_php_audit.py -f source.php

  # 扫描目录
  python web_php_audit.py -d /path/to/project/

  # 生成详细报告
  python web_php_audit.py -d /path/to/project/ --report

  # 输入流追踪
  python web_php_audit.py -f source.php --trace

  # 速查表
  python web_php_audit.py cheatsheet
        """
    )

    parser.add_argument('-f', '--file', help='扫描单个 PHP 文件')
    parser.add_argument('-d', '--dir', help='扫描 PHP 项目目录')
    parser.add_argument('--report', action='store_true', help='生成详细审计报告')
    parser.add_argument('--trace', action='store_true', help='追踪输入流到危险函数的路径')

    args = parser.parse_args()

    if 'cheatsheet' in sys.argv:
        print(PHP_AUDIT_CHEATSHEET)
        return

    if not args.file and not args.dir:
        parser.print_help()
        return

    auditor = PHPAuditor()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] 文件不存在: {args.file}")
            return
        auditor.scan_file(args.file)
        if args.trace:
            auditor.trace_input(args.file)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"[!] 目录不存在: {args.dir}")
            return
        auditor.scan_directory(args.dir)
        if args.trace:
            for r in auditor.results:
                auditor.trace_input(r['file'])

    if args.report or args.dir:
        auditor.generate_report()


if __name__ == '__main__':
    main()
