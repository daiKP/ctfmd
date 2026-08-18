# CTF 知识库 — Misc/IR方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## Misc 杂项 - 图片隐写

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D缺口

### 常见图片隐写类型

| 类型 | 常见载体 | 检测方式 |
|------|---------|---------|
| LSB 隐写 | PNG/BMP | StegSolve / zsteg / Python 脚本 |
| 文件附加数据 | 任何格式 | binwalk / foremost |
| 文件头修复 | PNG/JPG/GIF | WinHex / 010 Editor |
| EXIF 信息 | JPG/TIFF | exiftool |
| 盲水印 | PNG | blindwatermark 库 |
| 频域隐写 | PNG/BMP | StegSolve 频域分析 |
| GIF 帧隐写 | GIF | 逐帧提取 / convert |

### 工具速查

**StegSolve（Java GUI）**：
- 用于查看图片各颜色通道、LSB 位平面、异或叠加
- 按钮：Analyse → Data Extract → 勾选 R/G/B 的 0/1 位 → Preview
- 常见发现：LSB 最低位提取出 flag 文本

**zsteg（PNG/BMP LSB 检测）**：

```bash
# 自动检测所有通道的 LSB 隐写
zsteg image.png

# 指定通道
zsteg -a image.png  # 全部检测
zsteg -e b1,rgb,lsb,xy image.png  # 提取特定通道
```

**binwalk（文件附加数据检测）**：

```bash
# 检测嵌入文件
binwalk image.png

# 自动提取
binwalk -e image.png

# 未识别时用 foremost
foremost image.png -o output/
```

**exiftool（EXIF 信息提取）**：

```bash
exiftool image.jpg
# 关注: Comment, Artist, Copyright, UserComment 字段
```

### 文件头修复

常见文件头 signatures：

| 格式 | 文件头 (hex) | 文件尾 |
|------|-------------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `AE 42 60 82` |
| JPG | `FF D8 FF` | `FF D9` |
| GIF | `47 49 46 38 39 61` (GIF89a) | `00 3B` |
| BMP | `42 4D` | — |
| ZIP | `50 4B 03 04` | `50 4B 05 06` |

**PNG 文件头修复示例**：

```python
import struct

# 读取损坏的 PNG
with open('broken.png', 'rb') as f:
    data = bytearray(f.read())

# 修复 PNG 文件头
data[0:8] = b'\x89PNG\r\n\x1a\n'

# 修复 IHDR CRC
import zlib
ihdr_data = data[12:29]  # IHDR chunk data (13 bytes after length+type)
crc = zlib.crc32(ihdr_data) & 0xFFFFFFFF
struct.pack_into('>I', data, 29, crc)

with open('fixed.png', 'wb') as f:
    f.write(data)
```

### LSB 隐写原理与提取

**原理**：修改像素颜色值的最低位（Least Significant Bit），人类视觉无法察觉变化，但可携带隐藏信息。

```python
from PIL import Image

img = Image.open('stego.png')
pixels = list(img.convert('RGB').getdata())

# 提取 R 通道最低位
bits = ''
for r, g, b in pixels:
    bits += str(r & 1)

# 每 8 位转字符
text = ''
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        char = chr(int(byte, 2))
        text += char
        if text.endswith('}'):
            break

print(text)
```

### GIF 帧分离

```bash
# 分离所有帧
convert animation.gif frame_%03d.png

# 查看每帧差异
# 或用 identify 查看帧信息
identify animation.gif
```

### 盲水印

```bash
# 提取盲水印
python -m blindwatermark -- blinds --image original.png --watermark flag --output wm.png

# blindwatermark 库
from blindwatermark import blind_extract
bwm = blind_watermark()
bwm.extract('image.png', 'wm.png', wm_shape=(64, 64))
```

### 隐写检测流程

```
1. file / exiftool → 查看文件类型和元数据
2. binwalk → 检测附加数据
3. StegSolve / zsteg → 检测 LSB 隐写
4. 010 Editor → 检查文件头是否完整
5. 如果需要密码 → 尝试图片中的隐藏信息作为密码
```

> AI生成

---

---

## Misc 杂项 - 压缩包技巧

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D缺口

### 伪加密

**原理**：ZIP 文件中每个文件条目的通用位置标记（General Purpose Bit Flag）第 0 位控制   加密标志。仅修改该标志位即可让解压软件认为文件已加密，但数据本身并未加密。

**ZIP 文件结构**：

```
Local File Header:    50 4B 03 04 [version] [flag] [compression] ...
                      ↑                    ↑
                      固定头               加密标志位 (bit 0)
                      如果 flag 的 bit0=1 → 软件认为加密
```

**修复方法**：将加密标志位从 `09 00`（加密）改回 `00 00`（未加密）

```python
import struct

with open('fake.zip', 'rb') as f:
    data = bytearray(f.read())

# 遍历所有 Local File Header (PK\x03\x04)
offset = 0
while True:
    idx = data.find(b'PK\x03\x04', offset)
    if idx == -1:
        break
    # flag 在偏移 +6 处，2 字节
    flag_offset = idx + 6
    flag = struct.unpack_from('<H', data, flag_offset)[0]
    if flag & 1:  # bit 0 = 加密
        # 清除加密位
        struct.pack_into('<H', data, flag_offset, flag & ~1)
        print(f"修复加密标志: offset {flag_offset}, {flag:#06x} -> {flag & ~1:#06x}")
    offset = idx + 4

with open('fixed.zip', 'wb') as f:
    f.write(data)
```

### 暴力破解

```bash
# fcrackzip - 字典/暴力破解
fcrackzip -u -D -p rockyou.txt archive.zip   # 字典
fcrackzip -u -l 1-6 -c aA1 archive.zip        # 暴力

# ARCHPR (Windows) - 高级 ZIP/RAR 恢复

# John the Ripper
zip2john archive.zip > hash.txt
john --wordlist=rockyou.txt hash.txt

# hashcat
zip2john archive.zip | grep -oP '\$pkzip2.*' > hash.txt
hashcat -m 17200 hash.txt rockyou.txt
```

### ZIP 明文攻击

**原理**：已知加密 ZIP 中某个文件的明文内容（至少 12 字节），可以通过明文-密文对推导出加密密钥，解密同 ZIP 中的其他文件。

**前提条件**：
- ZIP 使用传统加密（ZipCrypto/Traditional PKZIP encryption）
- 已知 ZIP 中至少一个文件的完整明文（通常 >= 12 字节）
- 该文件未压缩或压缩方式已知

**利用工具**：bkcrack

```bash
# 1. 确认加密方式为 ZipCrypto（而非 AES）
zipinfo archive.zip
# 查看是否有 "compressed size" 和 "uncompressed size" 接近的文件

# 2. 准备已知明文文件（如 logo.png, readme.txt 等）
# 常见已知文件：框架自带的文件（如 WordPress 的 license.txt）

# 3. 获取明文的压缩数据（如果文件在 ZIP 中是无压缩存储的）
# 或使用已知明文文件

# 4. 使用 bkcrack 攻击
./bkcrack -C encrypted.zip -c known_file.txt -p plaintext.txt
# -C: 加密 ZIP, -c: ZIP 中的已知文件名, -p: 明文文件

# 5. 用恢复的密钥解密其他文件
./bkcrack -C encrypted.zip -c known_file.txt -p plaintext.txt -k key1 key2 key3 -d decrypted.zip
# -k: 上一步得到的三个密钥, -d: 输出解密后的 ZIP
```

### RAR 伪加密与修复

RAR 文件头标志位同样存在类似的伪加密机制：

```
RAR 4.x: 文件头 flags 字段的 bit 0 表示加密
RAR 5.x: 文件头中的加密标志位
```

### 嵌套压缩

CTF 中常见的多层嵌套压缩包套路：

```
archive.zip → 解压 → archive.rar → 解压 → archive.7z → ...
```

**自动化递归解压脚本**：

```python
import subprocess
import os
import glob

def recursive_extract(path, depth=0):
    """递归解压压缩包"""
    if depth > 50:  # 防止无限循环
        return
    
    archives = []
    for ext in ['*.zip', '*.rar', '*.7z', '*.gz', '*.tar', '*.bz2']:
        archives.extend(glob.glob(os.path.join(path, '**', ext), recursive=True))
    
    for archive in archives:
        extract_dir = archive + '_extracted'
        os.makedirs(extract_dir, exist_ok=True)
        
        if archive.endswith('.zip'):
            subprocess.run(['unzip', '-o', '-d', extract_dir, archive], capture_output=True)
        elif archive.endswith('.rar'):
            subprocess.run(['unrar', 'x', '-o+', archive, extract_dir], capture_output=True)
        elif archive.endswith('.7z'):
            subprocess.run(['7z', 'x', '-y', f'-o{extract_dir}', archive], capture_output=True)
        elif archive.endswith('.gz'):
            subprocess.run(['tar', 'xzf', archive, '-C', extract_dir], capture_output=True)
        
        print(f"  解压: {archive} -> {extract_dir}")
        recursive_extract(extract_dir, depth + 1)

# 使用
recursive_extract('./start/')
```

### 压缩包密码隐藏技巧

CTF 题目中密码可能隐藏在：
- 文件名中（如 `password_is_xxx.zip`）
- 文件注释中（`zipinfo` 查看）
- 文件属性中
- 前一层压缩包的文件名拼接
- 图片隐写内容中
- 通过伪加密修复后可见的文本文件中

### 常见套路速查

| 现象 | 可能的考点 |
|------|----------|
| 压缩包打不开 | 文件头损坏/被修改 |
| 提示需要密码但看不到加密数据 | 伪加密 |
| ZIP 中有已知的公开文件 | 明文攻击（bkcrack）|
| 压缩包注释中有信息 | `zipinfo` / `unzip -l` 查看注释 |
| 多层嵌套 | 递归解压脚本 |
| 压缩包大小异常 | 伪压缩率 / 隐藏文件 |
| CRC 无碰撞 | CRC 碰撞 / CRC32 暴力（仅限文本极短时）|

### CRC32 暴力破解（短文本）

当 ZIP 中有加密文件，但内容很短（4-6 字节）且是可见字符时，可直接暴力 CRC32：

```python
import zipfile
import string
import itertools

def crc32_bruteforce(zip_path, filename, max_len=6):
    """通过 CRC32 暴力破解短文本内容"""
    zf = zipfile.ZipFile(zip_path)
    target_crc = zf.getinfo(filename).CRC
    print(f"目标 CRC32: {target_crc:#010x}")
    
    chars = string.printable
    for length in range(1, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            text = ''.join(combo).encode()
            if zlib.crc32(text) & 0xFFFFFFFF == target_crc:
                return text
    return None
```

> AI生成

---

---

## 内存取证

> 补充日期：2026-08-04 | 优先级：中 | 对应附录D缺口

### 基本概念

内存取证（Memory Forensics）是指通过分析系统内存镜像（dump 文件），提取运行进程、网络连接、注册表、密码凭证等数字证据。CTF 中常见于 IR 应急响应和 Misc 杂项方向。

**核心工具**：Volatility

### Volatility 基础用法

**第 1 步：识别镜像类型**

```bash
# Volatility 2
python vol.py -f memory.dump imageinfo

# Volatility 3（推荐，无需指定 profile）
python3 vol.py -f memory.dump windows.info
```

**第 2 步：常用插件速查（Volatility 3）**

| 分析目标 | 命令 |
|---------|------|
| 系统信息 | `windows.info` |
| 进程列表 | `windows.pslist` / `windows.pstree` |
| 进程扫描（含隐藏进程） | `windows.psscan` |
| 网络连接 | `windows.netstat` / `windows.netscan` |
| 命令行历史 | `windows.cmdline` |
| 控制台历史 | `windows.consoles` |
| 注册表 | `windows.registry.hivelist` |
| 注册表值 | `windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"` |
| 文件列表 | `windows.filescan` |
| 文件提取 | `windows.dumpfiles --virtaddr <地址>` 或 `--pid <PID>` |
| 进程内存提取 | `windows.memmap --pid <PID> --dump` |
| Hash 提取 | `windows.hashdump` |
| LSA 密码 | `windows.lsadump` |
| 计划任务 | `windows.svcscan` |
| IE/Edge 历史 | `windows.iehistory` |
| 环境变量 | `windows.envars` |
| 进程依赖 | `windows.dlllist --pid <PID>` |
| 恶意代码 | `windows.malfind` |

### 常见解题流程

**场景 1：找出恶意进程**

```bash
# 1. 查看进程树，寻找异常进程
python3 vol.py -f mem.dump windows.pstree

# 2. 查找隐藏进程（psscan vs pslist 差异）
python3 vol.py -f mem.dump windows.psscan

# 3. 查看可疑进程的命令行
python3 vol.py -f mem.dump windows.cmdline --pid <PID>

# 4. 提取进程内存，搜索 flag
python3 vol.py -f mem.dump windows.memmap --pid <PID> --dump
strings process.dmp | grep -i flag
```

**场景 2：网络连接分析**

```bash
# 查看所有网络连接
python3 vol.py -f mem.dump windows.netscan

# 关注异常外连 IP、非常规端口
# 结合进程 PID 定位恶意程序
```

**场景 3：注册表取证**

```bash
# 列出注册表 hive
python3 vol.py -f mem.dump windows.registry.hivelist

# 查看启动项（持久化）
python3 vol.py -f mem.dump windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# 提取 SAM Hash
python3 vol.py -f mem.dump windows.hashdump
```

**场景 4：文件提取**

```flag
# 搜索 flag 文件
python3 vol.py -f mem.dump windows.filescan | grep -i flag

# 提取文件
python3 vol.py -f mem.dump windows.dumpfiles --virtaddr <虚拟地址>

# 提取后查看内容
cat flag.txt
```

**场景 5：命令历史**

```bash
# 查看命令行记录
python3 vol.py -f mem.dump windows.cmdscan

# 查看控制台输出
python3 vol.py -f mem.dump windows.consoles
```

### Linux 内存取证

```bash
# Volatility 3 Linux 插件
python3 vol.py -f mem.dump linux.pslist
python3 vol.py -f mem.dump linux.bash          # bash 历史
python3 vol.py -f mem.dump linux.check_syscall  # 系统调用表完整性
python3 vol.py -f mem.dump linux.proc.maps      # 进程内存映射
python3 vol.py -f mem.dump linux.tty_check      # TTY 输入
```

### 镜像获取方式

| 方法 | 工具 | 说明 |
|------|------|------|
| Windows 内存转储 | WinPMEM / DumpIt / FTK Imager | 获取 .raw / .dmp |
| Linux 内存转储 | LiME (Linux Memory Extractor) | 内核模块方式获取 |
| 虚拟机内存 | 直接复制 .vmem 文件 | VMware 暂停后获取 |
| 云服务器内存 | 配合云平台快照功能 | 创建快照后下载 |

### 快速排查 checklist

```
□ imageinfo / info → 确定系统版本
□ pslist / pstree → 排查异常进程
□ psscan → 查找隐藏/DKOM 进程
□ netscan / netstat → 排查异常网络连接
□ cmdline → 查看进程启动参数
□ hashdump → 提取密码哈希
□ registry Run 键 → 检查持久化
□ malfind → 检测注入/恶意代码
□ filescan → 搜索 flag/可疑文件
□ dumpfiles → 提取关键文件
□ consoles / cmdscan → 查看命令历史
```

> AI生成

---

---

## 网络流量分析方法论（CTF 竞赛 Misc / IR 方向）

> 难度定位：初中级。流量分析是 CTF 高频考点，现有第 17 题和第 18 题涉及但缺少系统性方法论。IR 方向已有 pcap_arcanum 通用工具，本专题补充方法论和手动分析技巧。

### 1. 流量分析标准流程

```
拿到 pcap/pcapng 文件
  │
  ├─ Step 1: 协议统计 → 统计各协议包数量
  │   Wireshark: Statistics → Protocol Hierarchy
  │   tshark: tshark -r file.pcap -q -z io,phs
  │
  ├─ Step 2: 会话分析 → 查看主要通信双方
  │   Wireshark: Statistics → Conversations
  │   tshark: tshark -r file.pcap -q -z conv,tcp
  │
  ├─ Step 3: HTTP 流量 → 导出 HTTP 对象
  │   Wireshark: File → Export Objects → HTTP
  │   tshark: tshark -r file.pcap --export-objects http,./output/
  │
  ├─ Step 4: 文件提取 → 搜索文件传输
  │   FTP-DATA / SMB / DICOM 等协议中的文件
  │
  ├─ Step 5: 凭据搜索 → 搜索明文密码
  │   ftp / telnet / http POST / pop3 / smtp
  │
  ├─ Step 6: 数据流追踪 → TCP Stream 追踪
  │   Wireshark: 右键 → Follow → TCP Stream
  │
  ├─ Step 7: 特殊流量分析
  │   DNS 隧道 / ICMP 隧道 / USB 流量 / 蓝牙流量
  │
  └─ Step 8: 导出文件 → 恢复传输的文件
      foremost / binwalk / 手动提取
```

### 2. Wireshark 过滤语法速查

**基础过滤**：

| 过滤器 | 说明 |
|--------|------|
| `http` | 所有 HTTP 流量 |
| `http.request.method == "POST"` | HTTP POST 请求 |
| `http.response.code == 200` | 200 响应 |
| `http contains "flag"` | HTTP 内容含 flag |
| `http.request.uri contains "upload"` | URL 含 upload |
| `tcp.port == 80` | TCP 80 端口 |
| `tcp.port == 443` | HTTPS 流量 |
| `ip.addr == 192.168.1.1` | 指定 IP |
| `ip.src == 192.168.1.1 && ip.dst == 10.0.0.1` | 指定源和目的 |
| `dns` | DNS 查询 |
| `dns.qry.name contains "flag"` | DNS 查询含 flag |
| `ftp` | FTP 流量 |
| `ftp.request.command == "PASS"` | FTP 密码 |
| `tcp contains "password"` | TCP 数据含 password |
| `frame contains "flag{"` | 任意层含 flag{ |

**高级过滤**：

```
# HTTP POST 表单数据
http.request.method == "POST" and http.file_data

# 查找 base64 编码内容
http contains "base64"

# DNS 异常长查询（可能 DNS 隧道）
dns.qry.name.len > 30

# ICMP 大数据包（可能 ICMP 隧道）
icmp and data.len > 64

# TLS 握手中的 SNI
tls.handshake.extensions_server_name contains "target.com"

# 查找特定文件头
frame[0:4] == ff:d8:ff:e0    # JPEG
frame[0:4] == 89:50:4e:47    # PNG
frame[0:4] == 50:4b:03:04    # ZIP
```

### 3. 常见流量分析场景

**场景 1：HTTP 凭据提取**

```
# 提取所有 HTTP POST 请求中的表单数据
tshark -r file.pcap -Y 'http.request.method == "POST"' -T fields \
    -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value

# 提取 Basic 认证
tshark -r file.pcap -Y 'http.authorization' -T fields \
    -e http.authorization -e http.host
```

**场景 2：文件还原**

```bash
# 方法1: Wireshark 导出 HTTP 对象
File → Export Objects → HTTP → Save All

# 方法2: tshark 导出
tshark -r file.pcap --export-objects http,./output/

# 方法3: foremost 恢复文件
foremost -i file.pcap -o output/

# 方法4: 手动提取 TCP 流
# Follow TCP Stream → Show data as Raw → Save as file
```

**场景 3：DNS 隧道检测**

```
# 特征: 大量长域名查询，子域名是 base64 编码数据
# 过滤: dns.qry.name.len > 30
# 提取域名部分解码:
tshark -r file.pcap -Y 'dns.qry.type == 1' -T fields \
    -e dns.qry.name | sort -u

# 提取后的域名前缀拼接 base64 解码
```

**场景 4：USB 流量分析**

```
# USB 键盘流量
tshark -r file.pcap -Y 'usb.transfer_type == 0x01' -T fields \
    -e usbhid.data

# USB 键盘数据格式: 6字节，第3字节是键码
# 键码对照表: 0x04=a, 0x05=b, ... 0x1e=1, 0x1f=2, ...
# 大写: 第1字节含 Shift 标志 (0x02)

# USB 鼠标流量
# 数据格式: 4字节，button(1) + x位移(1) + y位移(1) + 滚轮(1)
```

**场景 5：TLS/SSL 解密**

如果提供了密钥日志文件（key.log）：
```
# Wireshark: Edit → Preferences → Protocols → TLS
# (Pre)-Master-Secret log filename: 选择 key.log
# 之后 TLS 流量自动解密
```

### 4. 流量分析自动化脚本

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — 网络流量快速分析脚本
用途: 对 pcap 文件进行快速初步分析
场景: 竞赛流量分析题目第一步快速定位
依赖: tshark (Wireshark 命令行版)
"""
import subprocess
import sys
import os
import re
from collections import Counter

def run_tshark(pcap_file, filter_expr='', fields=None):
    """执行 tshark 命令"""
    cmd = ['tshark', '-r', pcap_file]
    if filter_expr:
        cmd.extend(['-Y', filter_expr])
    if fields:
        for f in fields:
            cmd.extend(['-e', f])
        cmd.extend(['-T', 'fields'])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        print("[!] 未找到 tshark，请安装 Wireshark 命令行工具")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return ""

def analyze_pcap(pcap_file):
    """主分析流程"""
    print("=" * 60)
    print("CTF 流量快速分析工具")
    print("=" * 60)

    if not os.path.isfile(pcap_file):
        print(f"[!] 文件不存在: {pcap_file}")
        return

    # 1. 协议统计
    print("\n[1] 协议统计:")
    output = run_tshark(pcap_file, '-q -z io,phs')
    for line in output.strip().split('\n')[:20]:
        print(f"    {line}")

    # 2. 会话统计
    print("\n[2] TCP 会话 Top 10:")
    output = run_tshark(pcap_file, '-q -z conv,tcp')
    lines = output.strip().split('\n')
    for line in lines[1:11]:
        print(f"    {line}")

    # 3. HTTP 请求分析
    print("\n[3] HTTP 请求:")
    output = run_tshark(pcap_file, 'http.request', ['http.request.method', 'http.host', 'http.request.uri'])
    for line in output.strip().split('\n')[:30]:
        if line.strip():
            print(f"    {line.strip()}")

    # 4. 搜索敏感关键词
    print("\n[4] 敏感关键词搜索:")
    for keyword in ['flag', 'password', 'passwd', 'secret', 'admin', 'token', 'key']:
        cmd = f'tshark -r "{pcap_file}" -Y \'frame contains "{keyword}"\' -T fields -e frame.number -e frame.len 2>/dev/null'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.stdout.strip():
            count = len(result.stdout.strip().split('\n'))
            print(f"    [{keyword}] 命中 {count} 个包")
            # 显示前 3 个
            for line in result.stdout.strip().split('\n')[:3]:
                print(f"        包 {line.strip()}")

    # 5. FTP 凭据提取
    print("\n[5] FTP 凭据:")
    output = run_tshark(pcap_file, 'ftp.request.command == "USER" or ftp.request.command == "PASS"', 
                        ['ftp.request.command', 'ftp.request.arg'])
    for line in output.strip().split('\n'):
        if line.strip():
            print(f"    {line.strip()}")

    # 6. DNS 查询分析
    print("\n[6] DNS 查询 Top 20:")
    output = run_tshark(pcap_file, 'dns.qry.type == 1', ['dns.qry.name'])
    queries = [q.strip() for q in output.strip().split('\n') if q.strip()]
    for q, count in Counter(queries).most_common(20):
        print(f"    [{count:3d}] {q}")

    # 7. DNS 隧道检测
    long_queries = [q for q in queries if len(q.split('.')[0]) > 20]
    if long_queries:
        print(f"\n[7] DNS 隧道嫌疑 ({len(long_queries)} 个长查询):")
        for q in long_queries[:10]:
            print(f"    {q}")

    # 8. 文件提取提示
    print("\n[8] 文件类型检测:")
    cmd = f'tshark -r "{pcap_file}" -Y "http" -T fields -e http.content_type 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    types = [t.strip() for t in result.stdout.strip().split('\n') if t.strip()]
    for t, count in Counter(types).most_common(10):
        print(f"    [{count:3d}] {t}")

    print(f"\n{'='*60}")
    print("[*] 快速分析完成")
    print("[*] 建议:")
    print("    - HTTP 对象: tshark -r file.pcap --export-objects http,./output/")
    print("    - TCP 流追踪: Wireshark → Follow → TCP Stream")
    print("    - 文件恢复: foremost -i file.pcap -o output/")
    print(f"{'='*60}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <pcap文件路径>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
```

### 5. 蓝牙流量分析

蓝牙流量在 CTF 中较少见但偶尔出现：

```
# 过滤蓝牙协议
bluetooth 或 btatt（蓝牙属性协议）

# 蓝牙键盘流量
btatt.opcode == 0x0b（写请求）
# 数据格式类似 USB 键盘：第2字节是键码

# 蓝牙文件传输 (OBEX)
obex
# Follow OBEX Stream 提取文件
```

### 6. 流量分析考点速查

| 特征 | 可能的考点 | 方法 |
|------|-----------|------|
| 大量 HTTP POST | 数据外传 / Web 交互 | 导出 HTTP 对象 |
| FTP 流量 | 文件传输 | 追踪 FTP-DATA Stream |
| 长 DNS 查询 | DNS 隧道 | 提取域名解码 |
| ICMP 大包 | ICMP 隧道 | 提取 data 字段 |
| USB 流量 | 键盘/鼠标输入 | 键码转字符 |
| TLS + key.log | 加密通信 | 加载密钥解密 |
| 蓝牙流量 | 键盘/文件传输 | btatt 分析 |
| 异常端口 | 自定义协议 | TCP Stream 分析 |
| 多个 pcap | 流量关联 | 时间戳+IP 对齐 |

---

---

