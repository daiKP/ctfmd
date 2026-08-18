# CTF 知识库 — IoT方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## IoT 固件分析入门（CTF 竞赛物联网方向）

> 难度定位：初中级。2026 年 CTF 赛事趋势明确提到"嵌入式安全成热门考点"，强网杯新增车联网专项赛道。初中级 IoT 题目大部分不需要嵌入式开发基础，解题流程接近 Misc 杂项题。

### 1. 固件分析工具链

| 工具 | 用途 | 安装命令 |
|------|------|---------|
| binwalk | 固件识别与提取（识别文件签名、提取嵌入式文件系统） | `pip install binwalk` 或 `apt install binwalk` |
| unsquashfs | 解压 SquashFS 文件系统（路由器固件最常见格式） | `apt install squashfs-tools` |
| firmwalker | 扫描固件中的敏感文件和目录 | `git clone https://github.com/craigz28/firmwalker.sh` |
| strings | 提取可打印字符串 | 系统自带 |
| file | 识别文件类型 | 系统自带 |
| Ghidra | 反编译 MIPS/ARM 二进制（NSA 开源工具） | 官网下载 |
| QEMU | 模拟运行 MIPS/ARM 架构二进制 | `apt install qemu-user qemu-system` |

### 2. 固件分析标准流程

```
固件文件 (.bin/.img/.tgz)
  │
  ├─ Step 1: file firmware.bin              → 识别文件类型
  ├─ Step 2: binwalk firmware.bin           → 识别内嵌文件系统
  ├─ Step 3: binwalk -e firmware.bin        → 提取文件系统
  ├─ Step 4: cd _firmware.bin.extracted/    → 进入提取目录
  ├─ Step 5: grep -ri "flag" .              → 搜索 flag
  ├─ Step 6: grep -ri "password\|passwd\|admin\|secret\|key" .
  │                                         → 搜索硬编码凭据
  ├─ Step 7: cat etc/shadow etc/passwd      → 查看用户配置
  ├─ Step 8: find . -name "*.conf" -o -name "*.cfg" -o -name "*.xml"
  │                                         → 查找配置文件
  ├─ Step 9: find . -name "*.pth" -o -name "*.py" → 查找模型/脚本文件
  └─ Step 10: strings squashfs-root/bin/... → 分析二进制中的字符串
```

### 3. 常见固件文件系统类型

| 魔数 | 类型 | 说明 | 提取命令 |
|------|------|------|---------|
| `hsqs` | SquashFS | 路由器最常见，只读压缩文件系统 | `unsquashfs xxx.squashfs` |
| `1f 8b` | gzip | 压缩固件 | `gunzip firmware.gz` |
| `42 5a 68` | bzip2 | 压缩固件 | `bunzip2 firmware.bz2` |
| `75 6c 74 72 61` | CPIO | 嵌入式 Linux 常见 | `cpio -idmv < file.cpio` |
| `5d 00 00` | LZMA | 高压缩比，U-Boot 常用 | `lzma -d file.lzma` |
| `UBI#` | UBI/UBIFS | NAND Flash 常见 | `ubireader_extract_images file.ubi` |

### 4. 敏感文件快速定位

CTF 固件题中最可能藏 flag 的位置：

```
# 用户凭据
etc/shadow              → 加密密码哈希
etc/passwd              → 用户列表
etc/config/             → OpenWrt 配置（含无线密码等）

# Web 管理界面
www/                    → Web 根目录
www/cgi-bin/            → CGI 脚本
usr/share/web/          → Web 资源
htdocs/                 → 部分固件 Web 根目录

# 配置文件
etc/*.conf              → 各种服务配置
var/etc/*.conf          → 运行时配置
mnt/settings/           → 用户设置

# 启动脚本
etc/init.d/             → 启动脚本（可能含硬编码密码）
etc/rc.d/               → 运行级别脚本

# 二进制文件
bin/                    → 系统命令
sbin/                   -> 管理命令
usr/bin/                → 用户命令
```

### 5. 常见 IoT 设备默认凭据速查

| 设备品牌 | 默认用户名 | 默认密码 | 说明 |
|---------|-----------|---------|------|
| TP-Link | admin | admin | 管理后台 |
| Tenda | admin | admin | 管理后台 |
| Netgear | admin | password | 管理后台 |
| D-Link | admin | (空) | 管理后台 |
| Huawei | root | admin | 部分型号 |
| 小米路由 | root | (无) | SSH 默认 |
| Various | root | 123456 | 摄像头常见 |
| Various | admin | 12345 | 摄像头常见 |
| Raspberry Pi | pi | raspberry | 默认系统 |

### 6. MIPS/ARM 架构速查

CTF IoT 题最常见的两种架构：

**MIPS 指令集要点**：
- 寄存器：`$a0-$a3` 参数传递，`$t0-$t9` 临时寄存器，`$s0-$s7` 保存寄存器，`$ra` 返回地址，`$sp` 栈指针
- 函数调用：`jal` 跳转链接（调用），`jr $ra` 返回
- 延迟槽：`jal` 和 `j` 后的指令会无条件执行（MIPS 特性）
- 大端序（MIPS-big）vs 小端序（MIPS-el）：CTF 中大端序更常见
- 栈溢出时返回地址在 `$ra`，偏移量计算方式与 x86 类似

**ARM 指令集要点**：
- 寄存器：`R0-R3` 参数传递，`R4-R11` 保存寄存器，`R13(SP)` 栈指针，`R14(LR)` 返回地址，`R15(PC)` 程序计数器
- 函数调用：`BL` 跳转链接，`BX LR` 返回
- ARM 模式（4字节对齐）vs Thumb 模式（2字节对齐）
- 函数指针在 `LR`，溢出覆盖 `LR` 即可控制执行流

**Ghidra 分析步骤**：
1. `File → Import` 选择二进制文件
2. 选择正确架构：MIPS:BE:32:default 或 ARM:LE:32:v7
3. 自动分析完成后查看 `Decompiler` 窗口
4. 搜索字符串：`Search → For Strings`
5. 查找 `main` 函数：`Symbol Tree → Functions → main`
6. 交叉引用：右键变量/函数 → `References`

### 7. 固件分析自动化脚本

以下脚本封装了固件分析的标准流程，竞赛时直接运行即可：

```python
#!/usr/bin/env python3
"""
CTF 解题工具 — IoT 固件分析自动化脚本
用途: 面向 CTF 竞赛的固件快速分析
场景: 竞赛平台物联网题目 / 固件分析练习
"""
import subprocess
import os
import re
import sys
from pathlib import Path

# 敏感关键词列表
SENSITIVE_KEYWORDS = [
    'flag', 'FLAG', 'flag{', 'Flag{',
    'password', 'passwd', 'Password',
    'admin', 'root', 'secret',
    'token', 'key', 'credential',
    'ssh', 'telnet', 'ftp',
    'mysql', 'redis', 'mongodb',
]

# 敏感文件路径
SENSITIVE_PATHS = [
    'etc/shadow', 'etc/passwd', 'etc/config',
    'etc/init.d', 'etc/rc.d',
    'www', 'htdocs', 'web',
    'var/etc', 'mnt/settings',
]

# 敏感文件扩展名
SENSITIVE_EXTS = ['.conf', '.cfg', '.xml', '.json', '.ini', '.sh', '.py', '.php']

def run_cmd(cmd, cwd=None):
    """执行终端命令并返回输出"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=cwd, timeout=60
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] 命令超时"
    except Exception as e:
        return f"[!] 执行失败: {e}"

def identify_firmware(filepath):
    """Step 1: 识别固件类型"""
    print(f"\n[1] 识别固件类型: {filepath}")
    output = run_cmd(f"file {filepath}")
    print(f"    {output.strip()}")

    output = run_cmd(f"binwalk {filepath}")
    print(f"\n    binwalk 识别结果:")
    for line in output.strip().split('\n'):
        print(f"    {line}")

    return output

def extract_firmware(filepath):
    """Step 2: 提取固件文件系统"""
    print(f"\n[2] 提取固件文件系统")
    run_cmd(f"binwalk -e {filepath}")

    extract_dir = f"_{Path(filepath).name}.extracted"
    if not os.path.isdir(extract_dir):
        for d in os.listdir('.'):
            if d.startswith('_') and d.endswith('.extracted'):
                extract_dir = d
                break

    if os.path.isdir(extract_dir):
        print(f"    [+] 提取成功: {extract_dir}/")

        for root, dirs, files in os.walk(extract_dir):
            for d in dirs:
                if 'squashfs' in d.lower() or 'root' in d.lower():
                    full = os.path.join(root, d)
                    print(f"    [+] 文件系统根: {full}")
                    return full
            if 'etc' in dirs or 'bin' in dirs or 'usr' in dirs:
                print(f"    [+] 文件系统根: {root}")
                return root

        return extract_dir

    print(f"    [-] 提取失败，尝试手动 unsquashfs")
    return None

def search_keywords(root_dir):
    """Step 3: 搜索敏感关键词"""
    print(f"\n[3] 搜索敏感关键词")
    root = Path(root_dir)
    results = []

    for keyword in SENSITIVE_KEYWORDS:
        output = run_cmd(f'grep -ri "{keyword}" "{root}" --include="*" -l 2>/dev/null')
        if output.strip():
            for f in output.strip().split('\n'):
                if f:
                    line_output = run_cmd(f'grep -n "{keyword}" "{f}" 2>/dev/null')
                    for line in line_output.strip().split('\n')[:5]:
                        results.append((f, line))
                        print(f"    [+] {f}: {line[:100]}")

    if not results:
        print("    [-] 未找到敏感关键词")

    return results

def scan_sensitive_files(root_dir):
    """Step 4: 扫描敏感文件"""
    print(f"\n[4] 扫描敏感文件")
    root = Path(root_dir)
    found = []

    for spath in SENSITIVE_PATHS:
        full = root / spath
        if full.exists():
            if full.is_file():
                found.append(str(full))
                print(f"    [+] {spath}")
                try:
                    with open(full, 'r', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if i >= 20:
                                break
                            print(f"        {line.rstrip()}")
                except:
                    pass
            elif full.is_dir():
                found.append(str(full))
                files = list(full.iterdir())[:10]
                print(f"    [+] {spath}/ ({len(list(full.iterdir()))} 个文件)")
                for f in files:
                    print(f"        {f.name}")

    return found

def scan_config_files(root_dir):
    """Step 5: 扫描配置文件"""
    print(f"\n[5] 扫描配置文件")
    root = Path(root_dir)
    found = []

    for ext in SENSITIVE_EXTS:
        output = run_cmd(f'find "{root}" -name "*{ext}" 2>/dev/null')
        if output.strip():
            for f in output.strip().split('\n')[:20]:
                if f:
                    found.append(f)
                    print(f"    [+] {f}")

    return found

def extract_strings(binary_path, min_len=6):
    """提取二进制中的字符串"""
    print(f"\n[6] 提取二进制字符串: {binary_path}")
    output = run_cmd(f"strings -n {min_len} {binary_path}")

    interesting = []
    for line in output.split('\n'):
        line = line.strip()
        if not line or len(line) < min_len:
            continue
        if any(kw in line.lower() for kw in ['flag', 'pass', 'admin', 'secret', 'key', 'token', '/', 'config']):
            interesting.append(line)
            if len(interesting) <= 50:
                print(f"    [+] {line[:120]}")

    return interesting

def analyze_firmware(filepath):
    """固件分析主流程"""
    print("=" * 60)
    print("CTF IoT 固件分析工具")
    print("=" * 60)

    if not os.path.isfile(filepath):
        print(f"[!] 文件不存在: {filepath}")
        return

    identify_firmware(filepath)

    root_dir = extract_firmware(filepath)
    if not root_dir:
        print("[!] 无法提取文件系统")
        return

    search_keywords(root_dir)
    scan_sensitive_files(root_dir)
    scan_config_files(root_dir)

    for binary in ['bin/busybox', 'usr/bin/httpd', 'sbin/init']:
        full = os.path.join(root_dir, binary)
        if os.path.isfile(full):
            extract_strings(full)

    print(f"\n{'='*60}")
    print("[*] 固件分析完成")
    print(f"    提取目录: {root_dir}")
    print(f"    建议手动检查: etc/, www/, config/ 目录")
    print(f"{'='*60}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <固件文件路径>")
        sys.exit(1)
    analyze_firmware(sys.argv[1])
```

---

---

## 车联网安全入门（CAN 总线 / UDS 诊断）

### 1. CAN 总线基础

CAN（Controller Area Network）是车载ECU间通信的总线协议。CTF车联网题通常给出一个 `.pcap` 或 `.log` 文件，要求分析CAN帧内容、提取异常数据或逆向报文含义。

#### 1.1 CAN 帧结构

```
┌──────────┬──────────┬────────────────────┬──────────────┐
│ CAN ID   │ DLC      │ Data (0-8 bytes)   │ CRC          │
│ 11/29bit │ 4 bit    │ 0-8 bytes          │ 15 bit       │
└──────────┴──────────┴────────────────────┴──────────────┘

标准帧: CAN ID = 11 bit (0x000-0x7FF)
扩展帧: CAN ID = 29 bit (0x00000000-0x1FFFFFFF)
DLC: 数据长度码 (Data Length Code)，0-8
```

#### 1.2 CTF 常见 CAN 题型

| 题型 | 特征 | 解题思路 |
|-----|------|---------|
| ID 识别 | 给 CAN ID 列表 | 对照标准 ID 表判断 ECU 类型 |
| 数据提取 | flag 隐藏在数据域 | 按字节拼接/解码 |
| 异常检测 | 大量帧中找异常 | 统计 ID 频率，找异常 ID/数据 |
| DoS 检测 | 高优先级帧洪泛 | 检查 0x000 高优先级帧频率 |
| 重放检测 | 重复帧序列 | 对比正常/异常时间段帧 |
| 逆向控制 | 控制特定功能 | 找到对应 ID + 数据字节映射 |

#### 1.3 常见 CAN ID 速查

| CAN ID (Hex) | 含义 | 说明 |
|-------------|------|------|
| 0x000 | 最高优先级 | 通常不会用，DoS 攻击常用 |
| 0x001-0x0FF | 动力总成 | 发动机、变速箱 |
| 0x100-0x1FF | 车身控制 | 车窗、门锁、灯光 |
| 0x200-0x2FF | 底盘 | 刹车、转向、悬挂 |
| 0x300-0x3FF | 诊断 | OBD-II 标准 ID |
| 0x400-0x4FF | 多媒体/仪表 | 信息娱乐、仪表盘 |
| 0x7DF | OBD-II 广播 | 请求所有 ECU 响应 |
| 0x7E0-0x7E7 | OBD-II 请求 | 逐个 ECU 诊断请求 |
| 0x7E8-0x7EF | OBD-II 响应 | 对应 ECU 诊断响应 |

### 2. CAN 流量分析

#### 2.1 Python CAN 报文分析脚本

```python
#!/usr/bin/env python3
"""
CAN 流量分析工具 - 支持 .pcap (SocketCAN) 和 .log 格式
功能: 统计 ID 频率、检测异常帧、提取数据
依赖: pip install python-can scapy
"""
import sys
from collections import defaultdict, Counter

try:
    import can
except ImportError:
    print('pip install python-can')
    sys.exit(1)

def analyze_pcap(pcap_file):
    """分析 SocketCAN pcap 文件"""
    try:
        from scapy.all import rdpcap, Raw
        packets = rdpcap(pcap_file)
    except ImportError:
        print('pip install scapy')
        return

    id_counter = Counter()
    id_data_map = defaultdict(list)
    id_set = set()

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        raw = bytes(pkt[Raw].load)
        # SocketCAN 帧格式: 4字节 ID + 1字节 DLC + 数据
        if len(raw) < 5:
            continue
        can_id = int.from_bytes(raw[0:4], 'little') & 0x1FFFFFFF  # 扩展帧掩码
        dlc = raw[4]
        data = raw[5:5+dlc] if dlc <= 8 else raw[5:13]

        id_counter[can_id] += 1
        id_data_map[can_id].append(data)
        id_set.add(can_id)

    print(f'=== CAN 流量统计 ===')
    print(f'总帧数: {sum(id_counter.values())}')
    print(f'不同 ID 数: {len(id_set)}')
    print(f'\n=== ID 频率 (Top 20) ===')
    for can_id, count in id_counter.most_common(20):
        is_obd = can_id in range(0x7E0, 0x7F0)
        is_diag = 0x7DF == can_id
        tag = ' [诊断]' if (is_obd or is_diag) else ''
        print(f'  0x{can_id:03X}: {count} 帧{tag}')

    print(f'\n=== 各 ID 数据样本 (前3条) ===')
    for can_id in sorted(id_set):
        samples = id_data_map[can_id][:3]
        hex_samples = [d.hex() for d in samples]
        print(f'  0x{can_id:03X}: {hex_samples}')

    # 异常检测: 频率异常高
    print(f'\n=== 异常检测 ===')
    avg_count = sum(id_counter.values()) / len(id_set) if id_set else 0
    for can_id, count in id_counter.most_common(10):
        if count > avg_count * 5:
            print(f'  [!] 0x{can_id:03X} 频率异常: {count} 帧 (平均 {avg_count:.0f})')
            print(f'      可能是 DoS 或重放攻击')

    # 数据变化检测: 某个 ID 数据持续变化
    for can_id, data_list in id_data_map.items():
        unique_data = set(d.hex() for d in data_list)
        if len(unique_data) == 1 and len(data_list) > 10:
            print(f'  [*] 0x{can_id:03X} 数据恒定: {data_list[0].hex()} ({len(data_list)} 帧)')
        elif len(unique_data) > len(data_list) * 0.8:
            print(f'  [*] 0x{can_id:03X} 数据频繁变化 ({len(unique_data)} 种)')

def extract_ascii(data_list):
    """从 CAN 数据域中尝试提取 ASCII 文本"""
    result = b''
    for d in data_list:
        for byte in d:
            if 0x20 <= byte < 0x7F:
                result += bytes([byte])
    return result.decode('ascii', errors='ignore')

def analyze_log(log_file):
    """分析 .log 格式 CAN 日志 (cantools 格式)"""
    id_counter = Counter()
    id_data_map = defaultdict(list)

    with open(log_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 格式: (timestamp) interface can_id#data
            # 或: timestamp interface can_id data
            parts = line.replace('(', '').replace(')', '').split()
            for part in parts:
                if '#' in part:
                    can_id_str, data_str = part.split('#')
                    can_id = int(can_id_str, 16)
                    data = bytes.fromhex(data_str) if data_str else b''
                    id_counter[can_id] += 1
                    id_data_map[can_id].append(data)
                    break

    print(f'=== CAN 日志分析 ===')
    print(f'总帧数: {sum(id_counter.values())}')
    print(f'不同 ID 数: {len(id_counter)}')

    print(f'\n=== ID 频率 ===')
    for can_id, count in id_counter.most_common(20):
        print(f'  0x{can_id:03X}: {count} 帧')

    print(f'\n=== ASCII 提取 ===')
    for can_id in sorted(id_data_map.keys()):
        text = extract_ascii(id_data_map[can_id])
        if len(text) > 3:
            print(f'  0x{can_id:03X}: {text}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('用法: python3 can_analyzer.py <pcap或log文件>')
        sys.exit(1)

    fname = sys.argv[1]
    if fname.endswith('.pcap') or fname.endswith('.pcapng'):
        analyze_pcap(fname)
    else:
        analyze_log(fname)
```

### 3. UDS 诊断协议

UDS（Unified Diagnostic Services，ISO 14229）是车辆诊断通信标准，建立在 CAN 之上（ISO 15765）。CTF 诊断题通常要求构造 UDS 请求或分析诊断响应。

#### 3.1 常见 UDS 服务

| Service ID (Hex) | 服务名 | 说明 |
|-----------------|-------|------|
| 0x10 | DiagnosticSessionControl | 切换诊断会话 |
| 0x11 | ECUReset | 重置 ECU |
| 0x14 | ClearDTC | 清除故障码 |
| 0x19 | ReadDTC | 读取故障码 |
| 0x22 | ReadDataByIdentifier | 按 ID 读数据 |
| 0x27 | SecurityAccess | 安全访问（解锁） |
| 0x2E | WriteDataByIdentifier | 按 ID 写数据 |
| 0x31 | RoutineControl | 例程控制 |
| 0x34 | RequestDownload | 请求下载（刷写） |
| 0x36 | TransferData | 数据传输 |
| 0x37 | RequestTransferExit | 退出传输 |
| 0x3E | TesterPresent | 在线诊断（防超时） |

#### 3.2 UDS 请求/响应格式

```
# 请求 (Tester → ECU): CAN ID 0x7E0
SID(1) + SubFunction/Data(0-6)

# 正响应 (ECU → Tester): CAN ID 0x7E8
SID|0x40 + SubFunction/Data (即 SID+0x40)

# 负响应: 0x7F + SID + NRC
```

#### 3.3 常用 UDS 交互

```python
# === DiagnosticSessionControl: 进入扩展会话 ===
# 请求: 10 03 (Extended Session)
# 响应: 50 03 (成功)

# === SecurityAccess: 种子-密钥 ===
# 步骤1: 请求种子
# 请求: 27 01
# 响应: 67 01 [seed]  ← ECU 返回随机种子
#
# 步骤2: 发送密钥
# 请求: 27 02 [key]   ← 根据 seed 计算密钥
# 响应: 67 02         ← 成功解锁

# CTF 常见: 逆向 ECU 固件找出种子→密钥的算法

# === ReadDataByIdentifier: 读 VIN ===
# 请求: 22 F1 90 (DID=0xF190 是 VIN)
# 响应: 62 F1 90 [17字节VIN]

# === ECUReset ===
# 请求: 11 01 (Hard Reset)
# 响应: 51 01 (成功)
```

#### 3.4 UDS 安全分析脚本

```python
#!/usr/bin/env python3
"""
UDS 诊断报文分析工具
解析 pcap 中的 UDS 交互，提取会话/安全访问/读数据等操作
"""
from scapy.all import rdpcap, Raw
from collections import defaultdict

UDS_SERVICES = {
    0x10: 'DiagnosticSessionControl',
    0x11: 'ECUReset',
    0x14: 'ClearDiagnosticInformation',
    0x19: 'ReadDTCInformation',
    0x22: 'ReadDataByIdentifier',
    0x27: 'SecurityAccess',
    0x2E: 'WriteDataByIdentifier',
    0x31: 'RoutineControl',
    0x34: 'RequestDownload',
    0x36: 'TransferData',
    0x37: 'RequestTransferExit',
    0x3E: 'TesterPresent',
}

NRC_CODES = {
    0x10: 'GeneralReject',
    0x11: 'ServiceNotSupported',
    0x12: 'SubFunctionNotSupported',
    0x13: 'IncorrectMessageLength',
    0x22: 'ConditionsNotCorrect',
    0x24: 'RequestSequenceError',
    0x31: 'RequestOutOfRange',
    0x33: 'SecurityAccessDenied',
    0x35: 'InvalidKey',
    0x36: 'ExceededNumberOfAttempts',
    0x37: 'RequiredTimeDelayNotExpired',
    0x78: 'ResponsePending',
    0x7E: 'SubFunctionNotSupportedInActiveSession',
    0x7F: 'ServiceNotSupportedInActiveSession',
}

def parse_uds(data):
    """解析 UDS 数据域"""
    if len(data) < 1:
        return None

    sid = data[0]
    # 正响应: SID + 0x40
    if 0x40 <= sid <= 0x7E and (sid & 0x40):
        orig_sid = sid & 0xBF  # 去掉 0x40
        service = UDS_SERVICES.get(orig_sid, f'Unknown(0x{orig_sid:02X})')
        sub = data[1] if len(data) > 1 else None
        payload = data[2:] if len(data) > 2 else b''
        return {'type': 'positive', 'sid': orig_sid, 'service': service,
                'sub': sub, 'payload': payload}

    # 负响应: 0x7F
    elif sid == 0x7F:
        orig_sid = data[1] if len(data) > 1 else 0
        nrc = data[2] if len(data) > 2 else 0
        service = UDS_SERVICES.get(orig_sid, f'Unknown(0x{orig_sid:02X})')
        nrc_desc = NRC_CODES.get(nrc, f'Unknown(0x{nrc:02X})')
        return {'type': 'negative', 'sid': orig_sid, 'service': service,
                'nrc': nrc, 'nrc_desc': nrc_desc}

    # 请求
    else:
        service = UDS_SERVICES.get(sid, f'Unknown(0x{sid:02X})')
        sub = data[1] if len(data) > 1 else None
        payload = data[2:] if len(data) > 2 else b''
        return {'type': 'request', 'sid': sid, 'service': service,
                'sub': sub, 'payload': payload}

def analyze_uds_pcap(pcap_file):
    """分析 UDS 交互"""
    packets = rdpcap(pcap_file)

    request_ids = set(range(0x7E0, 0x7E8))
    response_ids = set(range(0x7E8, 0x7F0))

    interactions = []

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        raw = bytes(pkt[Raw].load)
        if len(raw) < 5:
            continue
        can_id = int.from_bytes(raw[0:4], 'little') & 0x1FFFFFFF
        dlc = raw[4]
        data = raw[5:5+dlc] if dlc <= 8 else raw[5:13]

        uds = parse_uds(data)
        if uds is None:
            continue

        direction = 'req' if can_id in request_ids else 'resp'
        uds['can_id'] = can_id
        uds['direction'] = direction
        interactions.append(uds)

    print(f'=== UDS 交互分析 ({len(interactions)} 条) ===\n')

    for i, uds in enumerate(interactions):
        d = '>>>' if uds['direction'] == 'req' else '<<<'
        if uds['type'] == 'negative':
            print(f'{i:3d} {d} NEG  {uds["service"]} NRC={uds["nrc_desc"]}')
        elif uds['type'] == 'positive':
            payload_hex = uds.get('payload', b'').hex()
            print(f'{i:3d} {d} POS  {uds["service"]} sub={uds.get("sub")} '
                  f'data={payload_hex}')
        else:
            payload_hex = uds.get('payload', b'').hex()
            sub_hex = f'0x{uds["sub"]:02X}' if uds.get('sub') is not None else 'None'
            print(f'{i:3d} {d} REQ  {uds["service"]} sub={sub_hex} '
                  f'data={payload_hex}')

    # 提取安全访问种子
    print(f'\n=== SecurityAccess 分析 ===')
    for uds in interactions:
        if uds.get('sid') == 0x27 and (uds.get('sub') or 0) % 2 == 1:
            seed = uds.get('payload', b'').hex()
            print(f'  种子: {seed} (sub=0x{uds["sub"]:02X})')
        elif uds.get('sid') == 0x27 and (uds.get('sub') or 0) % 2 == 0:
            key = uds.get('payload', b'').hex()
            print(f'  密钥: {key} (sub=0x{uds["sub"]:02X})')

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('用法: python3 uds_analyzer.py <pcap文件>')
        sys.exit(1)
    analyze_uds_pcap(sys.argv[1])
```

### 4. 车联网安全速查

| 场景 | 工具/方法 | 关键操作 |
|-----|----------|---------|
| 分析 CAN pcap | Wireshark + SocketCAN | 过滤 `can.id == 0x7E0` |
| 提取 flag | 按ID分组+ASCII拼接 | `sort` + `xxd` |
| 逆向 ECU 固件 | Ghidra/IDA + ARM | 找种子密钥算法 |
| 模拟 CAN 发送 | can-utils / python-can | `cansend can0 7E0#1003` |
| 批量分析 | 本工具脚本 | 统计频率+异常检测 |
| 车载 Android | ADB + Frida | 逆向 APK + 抓 HTTPS |

---

---

## QEMU 固件模拟运行

### 1. 为什么需要 QEMU 模拟

CTF IoT 方向常给一个路由器/摄像头固件，题目要求找到 flag 但固件无法直接启动。需要用 QEMU 模拟运行固件中的 web 服务或二进制程序，然后进行动态分析或漏洞利用。

#### 1.1 QEMU 两种运行模式

| 模式 | 用途 | 命令示例 |
|-----|------|---------|
| 用户态模拟 | 运行单个 MIPS/ARM 二进制 | `qemu-mipsel ./binary` |
| 全系统模拟 | 模拟整个设备（内核+文件系统） | `qemu-system-mipsel -M ...` |

CTF 中 **用户态模拟最常用**，因为大部分 IoT 题只需要运行一个 CGI 程序或 web 后端。

### 2. 用户态模拟

#### 2.1 基本用法

```bash
# 安装 QEMU 用户态
apt install qemu-user qemu-user-static

# 查看二进制架构
file ./cgi-bin/admin
# ./cgi-bin/admin: ELF 32-bit LSB executable, MIPS, MIPS32, ...

# 运行 MIPS 小端
qemu-mipsel ./cgi-bin/admin

# 运行 ARM
qemu-arm ./binary

# 运行 MIPS 大端
qemu-mips ./binary

# 带 -L 指定库路径 (使用固件自带的库)
qemu-mipsel -L ./squashfs-root ./cgi-bin/admin

# 带 strace 调试
qemu-mipsel -strace -L ./squashfs-root ./cgi-bin/admin

# 带 gdb 调试 (等待 gdb 连接)
qemu-mipsel -g 1234 -L ./squashfs-root ./cgi-bin/admin
# 然后在另一个终端:
# gdb-multiarch ./cgi-bin/admin
# (gdb) target remote :1234
```

#### 2.2 用 chroot 模拟整棵文件系统

```bash
# 拷贝 qemu 静态版本到固件根目录
cp $(which qemu-mipsel-static) ./squashfs-root/usr/bin/

# chroot 运行
sudo chroot ./squashfs-root /usr/bin/qemu-mipsel-static /usr/sbin/httpd

# 如果需要网络
sudo chroot ./squashfs-root /usr/bin/qemu-mipsel-static /bin/sh -c "/usr/sbin/httpd &"
```

#### 2.3 模拟 CGI 程序 (GET 请求)

```bash
# CGI 程序通过环境变量获取请求参数
# 直接用环境变量传入
export REQUEST_METHOD="GET"
export QUERY_STRING="action=login&user=admin"
export REMOTE_ADDR="127.0.0.1"
export HTTP_COOKIE="session=abc123"

qemu-mipsel -L ./squashfs-root ./cgi-bin/admin.cgi
# CGI 程序会在 stdout 输出 HTTP 响应
```

#### 2.4 Python CGI 模拟测试脚本

```python
#!/usr/bin/env python3
"""
QEMU CGI 模拟测试工具
自动构造 CGI 环境变量并运行目标二进制
适用于: 路由器管理面板 CGI、命令注入测试
"""
import subprocess
import sys
import json

def run_cgi(qemu_cmd, cgi_path, lib_path,
            method='GET', query_string='', cookie='',
            post_data='', extra_env=None):
    """
    运行 CGI 程序
    qemu_cmd:  QEMU 二进制路径 (如 qemu-mipsel)
    cgi_path:  CGI 程序在固件中的路径
    lib_path:  固件文件系统根目录 (作为 -L 参数)
    method:    GET/POST
    query_string: URL 查询参数 (k=v&k2=v2)
    cookie:    HTTP Cookie 值
    post_data: POST 请求体
    extra_env: 额外环境变量字典
    """
    env = {
        'REQUEST_METHOD': method,
        'QUERY_STRING': query_string,
        'REMOTE_ADDR': '127.0.0.1',
        'HTTP_COOKIE': cookie,
        'CONTENT_LENGTH': str(len(post_data)) if post_data else '0',
        'CONTENT_TYPE': 'application/x-www-form-urlencoded' if post_data else '',
        'PATH_INFO': '/',
        'SCRIPT_NAME': cgi_path,
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'GATEWAY_INTERFACE': 'CGI/1.1',
    }
    if extra_env:
        env.update(extra_env)

    import os
    env = {**os.environ, **env}

    cmd = [qemu_cmd, '-L', lib_path, cgi_path]

    result = subprocess.run(
        cmd,
        input=post_data.encode() if post_data else None,
        capture_output=True,
        timeout=10,
        env=env
    )

    return {
        'stdout': result.stdout.decode('utf-8', errors='replace'),
        'stderr': result.stderr.decode('utf-8', errors='replace'),
        'returncode': result.returncode,
    }

def fuzz_cgi(qemu_cmd, cgi_path, lib_path, param_name,
             payloads, method='GET', base_query=''):
    """
    自动用 payload 列表 fuzz CGI 参数
    """
    print(f'=== CGI Fuzz: {param_name} ===')
    for payload in payloads:
        if method == 'GET':
            query = f'{param_name}={payload}'
            if base_query:
                query = f'{base_query}&{query}'
        else:
            query = base_query

        result = run_cgi(qemu_cmd, cgi_path, lib_path,
                        method=method, query_string=query,
                        post_data=f'{param_name}={payload}' if method == 'POST' else '')

        status = 'CRASH' if result['returncode'] != 0 else 'OK'
        output_preview = result['stdout'][:100].replace('\n', '\\n')
        print(f'  [{status}] payload={payload}')
        print(f'         output={output_preview}')

if __name__ == '__main__':
    # 示例: 模拟运行路由器 CGI
    qemu = 'qemu-mipsel'
    cgi = './squashfs-root/usr/lib/cgi-bin/admin.cgi'
    lib = './squashfs-root'

    # 单次测试
    result = run_cgi(qemu, cgi, lib,
                    method='GET',
                    query_string='action=login&user=admin&pass=admin')
    print('=== Response ===')
    print(result['stdout'])

    # Fuzz 测试 (命令注入)
    payloads = ['admin', 'admin;id', 'admin|id', 'admin`id`',
                'admin$(id)', 'admin\nid', 'admin&id']
    fuzz_cgi(qemu, cgi, lib, 'user', payloads,
             method='GET', base_query='action=login&pass=admin')
```

### 3. 全系统模拟

#### 3.1 适用场景

当用户态模拟不满足时（需要内核驱动、固件需要完整启动流程），使用全系统模拟。

#### 3.2 ARM 路由器模拟示例

```bash
# 提取内核和文件系统
binwalk -e firmware.bin
# 通常得到: kernel (zImage) + rootfs (squashfs/cramfs)

# 方法1: 使用 firmadyne (自动化工具)
# git clone https://github.com/firmadyne/firmadyne
# 按 README 配置依赖后:
./scripts/extract.sh firmware.bin
./scripts/tar2db.py
./scripts/makeNetwork.py
./run.sh

# 方法2: 手动 QEMU 全系统
# ARM 示例
qemu-system-arm \
    -M vexpress-a9 \
    -m 256M \
    -kernel ./zImage \
    -dtb ./vexpress-v2p-ca9.dtb \
    -append "root=/dev/mmcblk0 console=ttyAMA0" \
    -sd ./rootfs.ext2 \
    -net nic -net tap,ifname=tap0 \
    -nographic

# MIPS 示例
qemu-system-mipsel \
    -M malta \
    -m 256M \
    -kernel ./vmlinux \
    -append "root=/dev/sda console=ttyS0" \
    -hda ./rootfs.ext2 \
    -net nic -net tap,ifname=tap0 \
    -nographic
```

#### 3.3 搭建网络桥接

```bash
# 创建 tap 设备让 QEMU 虚拟机能和主机通信
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.100.1 up

# QEMU 启动后，虚拟机通常在 192.168.100.x 网段
# 从主机访问虚拟机:
curl http://192.168.100.2/

# 如果虚拟机需要联网:
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tap0 -j ACCEPT
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### 4. 常见问题与解决

| 问题 | 原因 | 解决 |
|-----|------|------|
| `libxxx.so: cannot open` | 库依赖缺失 | `-L ./squashfs-root` 指定库路径 |
| 程序立即退出 | 缺少 NVRAM 初始化 | 环境变量模拟 NVRAM 或 patch 二进制 |
| 程序卡住无输出 | 等待网络/NVRAM 初始化 | hook 超时相关函数或 patch |
| segmentation fault | 架构不匹配 | 确认 `file` 输出选对 QEMU |
| 无法绑定端口 | 端口被占或权限不足 | 用 `setcap` 或改端口 |
| HTTP 服务不响应 | 需要配置 hosts/网络 | 配置 `/etc/hosts` 和路由表 |

### 5. NVRAM 模拟

很多路由器固件依赖 NVRAM 读取配置（如 `nvram_get("lan_ipaddr")`），QEMU 环境中没有真实 NVRAM，需要 hook。

```python
#!/usr/bin/env python3
"""
生成 NVRAM 模拟库 (libnvram.so)
用途: 拦截固件中的 nvram_get/nvram_set 调用
      返回预设的配置值，让固件以为在真实设备上运行
编译: 用目标架构的交叉编译器编译 (如 mipsel-linux-gcc)
"""
import sys

LIBNVRAM_C = r'''
/* libnvram.c - NVRAM 模拟库
 * 编译: mipsel-linux-gcc -shared -fPIC -o libnvram.so libnvram.c -ldl
 * 使用: LD_PRELOAD=./libnvram.so qemu-mipsel -L ./root ./httpd
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 预设 NVRAM 键值对 */
static const char *nvram_pairs[][2] = {
    {"lan_ipaddr",   "192.168.1.1"},
    {"lan_netmask",  "255.255.255.0"},
    {"lan_proto",    "static"},
    {"wan_ipaddr",   "0.0.0.0"},
    {"wifi_ssid",    "TestWiFi"},
    {"wifi_pass",    "12345678"},
    {"admin_pass",   "admin"},
    {"http_enable",  "1"},
    {"http_lanport", "80"},
    {"remote_mgmt",  "1"},
    {"upnp_enable",  "1"},
    {"time_zone",    "GMT+8"},
    {NULL, NULL}
};

char *nvram_get(const char *name) {
    for (int i = 0; nvram_pairs[i][0] != NULL; i++) {
        if (strcmp(nvram_pairs[i][0], name) == 0) {
            return (char *)nvram_pairs[i][1];
        }
    }
    return "";
}

int nvram_set(const char *name, const char *value) {
    /* 模拟设置成功 */
    return 0;
}

int nvram_commit(void) {
    return 0;
}

int nvram_init(void *unused) {
    return 0;
}
'''

SETENV_SCRIPT = r'''#!/usr/bin/env python3
"""用 LD_PRELOAD 加载 NVRAM 库运行固件"""
import os, sys, subprocess

os.environ['LD_PRELOAD'] = os.path.abspath('libnvram.so')
qemu = sys.argv[1]   # e.g. qemu-mipsel
target = sys.argv[2]  # e.g. ./squashfs-root/usr/sbin/httpd
libpath = sys.argv[3] if len(sys.argv) > 3 else './squashfs-root'

cmd = [qemu, '-L', libpath, '-E', 'LD_PRELOAD=./libnvram.so', target]
subprocess.run(cmd)
'''

if __name__ == '__main__':
    print('生成 libnvram.c ...')
    with open('libnvram.c', 'w') as f:
        f.write(LIBNVRAM_C)
    print('生成 run_with_nvram.py ...')
    with open('run_with_nvram.py', 'w') as f:
        f.write(SETENV_SCRIPT)
    print('\n使用步骤:')
    print('1. mipsel-linux-gcc -shared -fPIC -o libnvram.so libnvram.c')
    print('2. cp libnvram.so ./squashfs-root/')
    print('3. LD_PRELOAD=./libnvram.so qemu-mipsel -L ./squashfs-root ./usr/sbin/httpd')
    print('   或直接用 LD_PRELOAD 环境变量')
    print('\n提示: 根据逆向分析结果修改 nvram_pairs 中的键值对')
```

### 6. QEMU 模拟速查

| 步骤 | 操作 | 命令/工具 |
|-----|------|----------|
| 确认架构 | `file` 命令 | `file ./binary` |
| 提取文件系统 | binwalk | `binwalk -e firmware.bin` |
| 用户态运行单文件 | qemu-user | `qemu-mipsel -L ./root ./binary` |
| 模拟 CGI | 环境变量 + qemu | 见上方 Python 脚本 |
| 模拟 NVRAM | LD_PRELOAD hook | 编译 libnvram.so |
| 全系统模拟 | qemu-system | 配合 firmadyne |
| 搭建网络桥接 | tunctl + iptables | tap0 网段访问 |
| 安装交叉编译 | apt install gcc-mipsel-linux-gnu | 编译 hook 库 |
| 调试 | qemu -g + gdb-multiarch | `target remote :1234` |

> AI生成

| 命令执行被禁 | disable_functions | file_put_contents 写文件 |

> AI生成
---

