#!/usr/bin/env python3
"""
CTF 解题工具 — 控制软件配置提取器 v2
用途: 面向 CTF 竞赛的自动化配置提取辅助
场景: 竞赛平台题目 / 授权测试靶场

v2 改进:
  1. 智能密钥定位引擎: capstone 反汇编 → RC4 KSA 识别 → lea 引用追踪 → 精确提取密钥
  2. 密钥派生检测: 识别 RC4(zero_buffer, key) → derived_key 模式
  3. 二进制整数端口提取: IP 附近按 uint16_be/le 读取端口号
  4. beacon| 格式化字符串模板识别
  5. 主引擎重构: 智能密钥优先，暴力穷举降级为备选

用法:
  python3 config_extractor.py <二进制文件路径>
  python3 config_extractor.py <二进制文件路径> --verbose
  python3 config_extractor.py <二进制文件路径> --rc4-key <key_hex>
  python3 config_extractor.py <二进制文件路径> --smart-only   # 仅智能模式
"""

import sys
import re
import struct
import hashlib
import argparse
from pathlib import Path
from collections import OrderedDict

# ============================================================
# 第一部分：加密/解密原语
# ============================================================

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 流密码加密/解密（同一函数）"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rc4_derive_key(key: bytes, derived_len: int = 64) -> bytes:
    """RC4 密钥派生: 对 derived_len 字节全零缓冲区做 RC4，得到派生密钥

    这是控制软件样本中常见的密钥派生模式:
      derived_key = RC4(zero_buffer[len=key_len], parent_key)
    """
    zero_buf = b'\x00' * derived_len
    return rc4_crypt(zero_buf, key)


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """单字节/多字节 XOR 解密"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def try_aes_ecb(data: bytes, key: bytes) -> bytes:
    """AES-ECB 解密（需要 pycryptodome）"""
    try:
        from Crypto.Cipher import AES
        if len(key) not in (16, 24, 32):
            key = hashlib.md5(key).digest()
        if len(data) % 16 != 0:
            data = data[:len(data) - (len(data) % 16)]
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)
    except ImportError:
        return b""


def try_aes_cbc(data: bytes, key: bytes, iv: bytes = b'\x00' * 16) -> bytes:
    """AES-CBC 解密"""
    try:
        from Crypto.Cipher import AES
        if len(key) not in (16, 24, 32):
            key = hashlib.md5(key).digest()
        if len(data) % 16 != 0:
            data = data[:len(data) - (len(data) % 16)]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(data)
    except ImportError:
        return b""


# ============================================================
# 第二部分：信息模式匹配器（含二进制端口 + beacon| 模板）
# ============================================================

# IP 地址模式（IPv4）
IP_PATTERN = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# 端口号模式（ASCII）
PORT_PATTERN = re.compile(rb'[:\s](\d{2,5})\b')

# TASK 标识模式
TASK_PATTERN = re.compile(rb'(TASK[-_]?\d{4,8}[-_]?\d{0,6}[-_]?[A-Za-z0-9]*)', re.IGNORECASE)

# 通用任务/标识名模式
ID_PATTERN = re.compile(rb'([A-Z]{2,}[-_]\d{4,}[-_][A-Za-z0-9]+)')

# URL / 域名模式
URL_PATTERN = re.compile(rb'(https?://[^\x00-\x1f\x7f-\xff\s]+)', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(rb'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)')

# 通信协议标识模式
PROTO_PATTERN = re.compile(rb'(tcp|udp|http|https|dns|icmp|smb)[:/]', re.IGNORECASE)

# beacon| 格式化字符串模板（控制软件常见格式）
BEACON_TEMPLATE_PATTERN = re.compile(
    rb'beacon\|([^\x00|]+)\|([^\x00|]+)\|([^\x00|]+)', re.IGNORECASE
)

# 常见配置字段名
CONFIG_KEYWORDS = [
    b'Server', b'server', b'Host', b'host', b'Port', b'port',
    b'Beacon', b'beacon', b'TASK', b'task', b'Listener',
    b'C2', b'c2', b'callback', b'Callback',
    b'pipe', b'Pipe', b'scheme', b'Scheme',
    b'uri', b'URI', b'path', b'Path',
    b'key', b'Key', b'password', b'Password',
    b'user', b'User', b'agent', b'Agent',
    b'proxy', b'Proxy', b'jitter', b'Jitter',
]


def extract_binary_ports(data: bytes, ip_offset: int, ip_match_end: int) -> list:
    """在 IP 地址之后紧邻位置提取二进制整数端口号

    策略（按可信度从高到低）:
    1. IP 字符串结束后的下一个字节位置，读 uint16_be 和 uint16_le
    2. IP 结束后跳过 1 字节（可能有分隔符），再读 uint16
    3. IP 结束后跳过 2 字节对齐，再读 uint16

    不再在 IP 附近所有偏移上逐字节扫描（那会产生大量误报）。
    """
    ports = []

    # 常见端口号范围（用于评分）—— 面向 CTF 控制软件场景
    COMMON_PORT_RANGES = [
        (4444, 4450),   # 常见控制软件端口
        (8443, 9500),   # HTTPS 替代端口
        (50000, 65535), # 动态端口
    ]

    def score_port(p):
        """给端口号打分，常见 C2 端口范围得分高"""
        for lo, hi in COMMON_PORT_RANGES:
            if lo <= p <= hi:
                return 2
        if 1024 <= p <= 49151:
            return 1
        return 0

    # 在 IP 结束后 0-4 字节偏移处尝试读取
    for gap in (0, 1, 2, 4):
        off = ip_match_end + gap
        if off + 2 > len(data):
            continue
        port_be = struct.unpack_from('>H', data, off)[0]
        port_le = struct.unpack_from('<H', data, off)[0]

        for port_val in (port_be, port_le):
            if 1 <= port_val <= 65535 and port_val not in (0, 80, 443):
                score = score_port(port_val)
                ports.append((port_val, score))

    # 按 score 降序排序，保留高分端口
    if ports:
        ports.sort(key=lambda x: x[1], reverse=True)
        # 取得分 >= 1 的端口，如果全为 0 分则取前 3 个
        high_score = [p for p, s in ports if s >= 1]
        if high_score:
            return list(dict.fromkeys(high_score))[:5]  # 去重，最多 5 个
        else:
            return list(dict.fromkeys([p for p, s in ports[:3]]))

    return []


def extract_info(data: bytes, verbose: bool = False) -> dict:
    """从数据中提取所有匹配的信息模式（含二进制端口 + beacon| 模板）"""
    results = {
        'ip_addresses': [],
        'ports': [],
        'task_ids': [],
        'urls': [],
        'domains': [],
        'protocols': [],
        'config_keywords': [],
        'raw_ascii': [],
        'beacon_templates': [],
    }

    # IP 地址
    for m in IP_PATTERN.finditer(data):
        ip = m.group(1).decode('ascii', errors='ignore')
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            results['ip_addresses'].append(ip)
            # 二进制端口提取
            bin_ports = extract_binary_ports(data, m.start(), m.end())
            results['ports'].extend(bin_ports)

    # ASCII 端口号（在 IP 附近 ± 32 字节范围内找端口）
    # 记录所有 IP 匹配的绝对偏移范围，避免将 IP 子串误识别为端口
    ip_match_ranges = [(m.start(), m.end()) for m in IP_PATTERN.finditer(data)]
    for m in IP_PATTERN.finditer(data):
        start = max(0, m.start() - 32)
        end = min(len(data), m.end() + 64)
        nearby = data[start:end]
        for pm in re.finditer(rb'(\d{2,5})', nearby):
            # 计算绝对偏移
            abs_start = start + pm.start()
            abs_end = start + pm.end()
            # 跳过与 IP 匹配重叠的数字
            overlaps_ip = any(
                abs_start < ip_end and abs_end > ip_start
                for ip_start, ip_end in ip_match_ranges
            )
            if overlaps_ip:
                continue
            port = int(pm.group(1))
            if 1 <= port <= 65535 and port not in (0, 80, 443):
                results['ports'].append(port)

    # TASK 标识
    for m in TASK_PATTERN.finditer(data):
        results['task_ids'].append(m.group(1).decode('ascii', errors='ignore'))
    for m in ID_PATTERN.finditer(data):
        val = m.group(1).decode('ascii', errors='ignore')
        # 严格过滤碎片化误报：
        # 1. 必须包含 4+ 位连续数字
        # 2. 总长 >= 10
        # 3. 前缀至少 3 个连续大写字母
        # 4. 不含连续 5 个以上大写字母（排除 XOR 破坏后的碎片）
        if (val not in results['task_ids']
                and re.search(r'\d{4,}', val)
                and len(val) >= 10
                and re.match(r'^[A-Z]{3,}', val)
                and not re.search(r'[A-Z]{5,}', val)):
            results['task_ids'].append(val)

    # beacon| 格式化字符串模板
    # 只保留参数干净（全可打印ASCII、不含乱码）的模板
    for m in BEACON_TEMPLATE_PATTERN.finditer(data):
        groups = [g.decode('ascii', errors='ignore') for g in m.groups()]
        # 质量过滤：每个参数必须至少 2 字符，且能正常打印
        if all(len(g) >= 1 and all(0x20 <= ord(c) <= 0x7e for c in g) for g in groups):
            results['beacon_templates'].append(groups)
            # 从模板参数中提取 IP/端口/标识
            for g in groups:
                if IP_PATTERN.match(g.encode()):
                    ip = g.strip()
                    if ip not in results['ip_addresses']:
                        results['ip_addresses'].append(ip)
                try:
                    p = int(g.strip())
                    if 1 <= p <= 65535 and p not in results['ports']:
                        results['ports'].append(p)
                except ValueError:
                    pass

    # URL
    for m in URL_PATTERN.finditer(data):
        results['urls'].append(m.group(1).decode('ascii', errors='ignore'))

    # 域名
    for m in DOMAIN_PATTERN.finditer(data):
        domain = m.group(1).decode('ascii', errors='ignore')
        if not any(domain.endswith(ext) for ext in ['.exe', '.dll', '.so', '.txt', '.log']):
            results['domains'].append(domain)

    # 协议标识
    for m in PROTO_PATTERN.finditer(data):
        results['protocols'].append(m.group(1).decode('ascii', errors='ignore'))

    # 配置关键字
    for kw in CONFIG_KEYWORDS:
        idx = 0
        while True:
            idx = data.find(kw, idx)
            if idx == -1:
                break
            ctx_end = min(len(data), idx + len(kw) + 64)
            after_kw = data[idx + len(kw):ctx_end]
            val_match = re.match(rb'[\x00-\x20]*([^\x00-\x1f\x7f-\xff]+)', after_kw)
            if val_match:
                val = val_match.group(1).decode('ascii', errors='ignore').strip()
                if len(val) >= 2:
                    results['config_keywords'].append({
                        'keyword': kw.decode('ascii'),
                        'offset': idx,
                        'value': val[:128],
                    })
            idx += len(kw)

    # 提取连续 ASCII 字符串（长度 >= 6）
    for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
        s = m.group(0).decode('ascii')
        if not re.match(r'^[A-Za-z]+$', s) or len(s) >= 10:
            results['raw_ascii'].append({
                'offset': m.start(),
                'text': s[:256],
            })

    # 去重
    for key in ['ip_addresses', 'ports', 'task_ids', 'urls', 'domains', 'protocols']:
        seen = set()
        deduped = []
        for item in results[key]:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        results[key] = deduped

    if verbose:
        print(f"  [模式匹配] 完成，原始ASCII数量: {len(results['raw_ascii'])}")

    return results


def has_interesting_info(info: dict) -> bool:
    """判断提取结果是否包含有价值的通信配置信息"""
    return bool(info.get('ip_addresses') or info.get('task_ids') or
                info.get('beacon_templates') or info.get('urls'))
# ============================================================
# 第三部分：智能密钥定位引擎
# ============================================================
#
# 核心思路:
#   1. 用 capstone 反汇编 .text 段
#   2. 识别 RC4 KSA（Key Scheduling Algorithm）特征
#   3. 在 KSA 函数前后追踪 lea 指令，提取密钥引用地址
#   4. 计算密钥虚拟地址 → 转文件偏移 → 读取密钥字节
#   5. 检测密钥派生模式: RC4(zero_buffer, key) → derived_key
#

def _try_capstone():
    """尝试导入 capstone 库"""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_ARCH_ARM64, CS_MODE_ARM
        return True
    except ImportError:
        return False


def detect_arch(data: bytes) -> dict:
    """检测 ELF/PE 文件的架构信息"""
    arch_info = {'arch': 'unknown', 'bits': 64, 'endian': 'little'}

    if len(data) < 4:
        return arch_info

    # ELF
    if data[:4] == b'\x7fELF':
        arch_info['bits'] = 64 if data[4] == 2 else 32
        arch_info['endian'] = 'little' if data[5] == 1 else 'big'
        ei_machine = struct.unpack_from('<H' if arch_info['endian'] == 'little' else '>H', data, 0x12)[0]
        if ei_machine == 0x3E:  # EM_X86_64
            arch_info['arch'] = 'x86_64'
        elif ei_machine == 0x03:  # EM_386
            arch_info['arch'] = 'x86'
            arch_info['bits'] = 32
        elif ei_machine == 0xB7:  # EM_AARCH64
            arch_info['arch'] = 'arm64'
        elif ei_machine == 0x28:  # EM_ARM
            arch_info['arch'] = 'arm'
            arch_info['bits'] = 32
        return arch_info

    # PE
    if data[:2] == b'MZ':
        try:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    arch_info['arch'] = 'x86_64'
                elif machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
                    arch_info['arch'] = 'x86'
                    arch_info['bits'] = 32
                elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                    arch_info['arch'] = 'arm64'
                return arch_info
        except Exception:
            pass

    return arch_info


def find_rc4_ksa_patterns_x86(code: bytes, base_addr: int, arch_bits: int = 64) -> list:
    """在 x86/x64 机器码中识别 RC4 KSA 特征模式

    RC4 KSA 的典型特征（编译器可能用不同方式实现 swap）:
      - mov reg, 0x100 (循环 256 次，KSA 初始化)
      - swap 操作: xchg 或 mov 三步交换
      - 回跳循环（jnz / jne / loop 到循环头）

    检测策略（宽松模式）:
      - 严格模式: xchg + mov 0x100 + 回跳 → 高置信度
      - 宽松模式: mov 0x100 + 回跳 → 中等置信度（覆盖编译器优化后的 KSA）

    返回: KSA 函数候选位置列表 [{addr, ksa_start, lea_candidates, confidence}]
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    except ImportError:
        return []

    mode = CS_MODE_64 if arch_bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)

    md.detail = False

    instructions = list(md.disasm(code, base_addr))

    # 第一步: 找到所有 mov reg, 0x100 指令
    mov_0x100_positions = []
    for i, insn in enumerate(instructions):
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        if mnemonic == 'mov' and ('0x100' in op_str or '256' in op_str):
            for reg in ('ecx', 'edi', 'rcx', 'rdi', 'esi', 'rsi', 'edx', 'rdx'):
                if op_str.startswith(reg + ','):
                    mov_0x100_positions.append(i)
                    break

    # 第二步: 在 mov 0x100 附近搜索交换和回跳特征
    ksa_candidates = []
    for idx in mov_0x100_positions:
        window_start = max(0, idx - 30)
        window_end = min(len(instructions), idx + 30)

        has_xchg = False
        has_loop = False
        has_mov_swap = False  # mov 三步交换模式

        for j in range(window_start, window_end):
            mn = instructions[j].mnemonic
            if mn == 'xchg':
                has_xchg = True
            if mn in ('jnz', 'jne', 'loop', 'jb', 'jl', 'jna', 'jbe'):
                has_loop = True
            # 检测 mov 三步交换: 连续的 mov reg, [mem + off] 模式
            # 编译器优化的 swap 通常是: mov tmp, [a]; mov [a], [b]; mov [b], tmp
            if mn == 'mov' and j + 2 < window_end:
                next_mn = instructions[j + 1].mnemonic if j + 1 < window_end else ''
                next2_mn = instructions[j + 2].mnemonic if j + 2 < window_end else ''
                if mn == 'mov' and next_mn == 'mov' and next2_mn == 'mov':
                    has_mov_swap = True

        # 严格模式: xchg + loop → 高置信度
        if has_xchg and has_loop:
            ksa_candidates.append({
                'addr': instructions[idx].address,
                'ksa_start': instructions[max(0, idx - 15)].address,
                'ksa_end': instructions[min(len(instructions) - 1, idx + 30)].address,
                'confidence': 'high',
            })
        # 宽松模式: 仅 loop + (xchg 或 mov swap) → 中等置信度
        elif has_loop and (has_xchg or has_mov_swap):
            ksa_candidates.append({
                'addr': instructions[idx].address,
                'ksa_start': instructions[max(0, idx - 15)].address,
                'ksa_end': instructions[min(len(instructions) - 1, idx + 30)].address,
                'confidence': 'medium',
            })
        # 最宽松: 仅 mov 0x100 + loop → 低置信度（可能误报，但覆盖面广）
        elif has_loop:
            ksa_candidates.append({
                'addr': instructions[idx].address,
                'ksa_start': instructions[max(0, idx - 20)].address,
                'ksa_end': instructions[min(len(instructions) - 1, idx + 40)].address,
                'confidence': 'low',
            })

    # 第三步: 在每个 KSA 候选范围内搜索 lea 指令（密钥加载）
    for ksa in ksa_candidates:
        lea_candidates = []
        for i, insn in enumerate(instructions):
            if insn.address < ksa['ksa_start'] - 512:
                continue
            if insn.address > ksa['ksa_end'] + 128:
                break
            if insn.mnemonic == 'lea' and ('rip' in insn.op_str or 'eip' in insn.op_str):
                rip_relative = _parse_lea_rip_relative(insn, arch_bits)
                if rip_relative is not None:
                    lea_candidates.append({
                        'addr': insn.address,
                        'key_va': rip_relative,
                        'insn_str': f'{insn.mnemonic} {insn.op_str}',
                    })
        ksa['lea_candidates'] = lea_candidates

    return ksa_candidates


def _parse_lea_rip_relative(insn, arch_bits: int = 64) -> int:
    """从 lea 指令中解析 RIP 相对地址，返回密钥的虚拟地址

    capstone 的 op_str 格式示例: "rsi, [rip + 0x2004]"
    我们需要计算: rip + offset (rip = 当前指令地址 + 指令长度)
    """
    try:
        op_str = insn.op_str
        # 格式: reg, [rip + offset] 或 reg, [rip - offset]
        import re
        m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', op_str)
        if not m:
            return None

        sign = m.group(1)
        offset_val = int(m.group(2), 16) if m.group(2).startswith('0x') else int(m.group(2))

        # RIP = 当前指令地址 + 指令长度
        rip = insn.address + insn.size
        if sign == '+':
            return rip + offset_val
        else:
            return rip - offset_val
    except Exception:
        return None


def va_to_file_offset(va: int, sections: dict, verbose: bool = False) -> int:
    """将虚拟地址转换为文件偏移

    遍历所有段，找到 VA 落在 [vaddr, vaddr + size) 范围内的段，
    计算 file_offset = va - vaddr + file_offset_of_section
    """
    for name, sec in sections.items():
        if name.startswith('_'):
            continue
        sec_vaddr = sec.get('vaddr', sec.get('offset', 0))
        sec_size = sec.get('size', 0)
        if sec_vaddr <= va < sec_vaddr + sec_size:
            offset_in_sec = va - sec_vaddr
            return sec['offset'] + offset_in_sec
    return -1


def read_bytes_at_va(data: bytes, va: int, length: int, sections: dict) -> bytes:
    """从虚拟地址读取指定长度的字节"""
    file_off = va_to_file_offset(va, sections)
    if file_off < 0 or file_off + length > len(data):
        return b""
    return data[file_off:file_off + length]


def read_string_at_va(data: bytes, va: int, sections: dict, max_len: int = 256) -> bytes:
    """从虚拟地址读取以 null 结尾的字符串"""
    file_off = va_to_file_offset(va, sections)
    if file_off < 0:
        return b""
    end = data.find(b'\x00', file_off, file_off + max_len)
    if end < 0:
        end = min(file_off + max_len, len(data))
    result = data[file_off:end]
    # 过滤可打印字符
    if all(0x20 <= b <= 0x7e for b in result):
        return result
    return result  # 也返回非可打印，可能是二进制密钥


def smart_key_extraction(data: bytes, sections: dict, arch_info: dict, verbose: bool = False) -> list:
    """智能密钥定位引擎: 反汇编 → KSA 识别 → lea 追踪 → 密钥提取

    两种策略并行:
    1. KSA 引导: 识别 RC4 KSA → 追踪附近 lea → 提取密钥
    2. 独立 lea 扫描: 扫描所有 lea rip 指令，目标字符串如果像密钥则直接提取

    返回: 智能提取到的密钥列表 [{key, source, decoded, method}]
    """
    if not _try_capstone():
        if verbose:
            print("  [智能引擎] capstone 未安装，跳过智能密钥定位")
        return []

    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

    # 获取 .text 段
    text_section = sections.get('.text')
    if not text_section:
        if verbose:
            print("  [智能引擎] 未找到 .text 段，跳过")
        return []

    code = text_section['data']
    base_addr = text_section.get('vaddr', text_section['offset'])

    if verbose:
        print(f"  [智能引擎] .text 段: {len(code)} 字节, 基址: 0x{base_addr:x}")

    arch = arch_info.get('arch', 'unknown')
    if arch not in ('x86_64', 'x86'):
        if verbose:
            print(f"  [智能引擎] 不支持的架构: {arch}")
        return []

    bits = arch_info.get('bits', 64)
    mode = CS_MODE_64 if bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    instructions = list(md.disasm(code, base_addr))

    keys = []
    seen_key_vas = set()  # 避免重复提取同一个地址

    # ===== 策略1: KSA 引导 =====
    ksa_candidates = find_rc4_ksa_patterns_x86(code, base_addr, bits)

    if verbose:
        print(f"  [智能引擎] 识别到 {len(ksa_candidates)} 个 KSA 候选")

    for i, ksa in enumerate(ksa_candidates):
        if verbose:
            conf = ksa.get('confidence', '?')
            print(f"  [智能引擎] KSA #{i+1} @ 0x{ksa['addr']:x}, "
                  f"置信度={conf}, lea 候选: {len(ksa.get('lea_candidates', []))} 个")

        for lea in ksa.get('lea_candidates', []):
            key_va = lea['key_va']
            if key_va in seen_key_vas:
                continue
            key_bytes = read_string_at_va(data, key_va, sections, max_len=64)
            if len(key_bytes) >= 4:
                decoded = key_bytes.decode('ascii', errors='replace')
                seen_key_vas.add(key_va)
                keys.append({
                    'key': key_bytes,
                    'source': f'smart_lea@0x{lea["addr"]:x}',
                    'decoded': decoded,
                    'method': 'smart',
                    'ksa_addr': ksa['addr'],
                    'key_va': key_va,
                    'confidence': ksa.get('confidence', 'medium'),
                })
                if verbose:
                    print(f"    -> [KSA] 密钥 VA=0x{key_va:x}, 长度={len(key_bytes)}, "
                          f"内容={decoded[:32]}...")

    # ===== 策略2: 独立 lea 密钥扫描 =====
    # 即使 KSA 没检测到，也扫描所有 lea rip 指令
    # 将目标地址的可读字符串作为候选密钥
    lea_keys = []
    for insn in instructions:
        if insn.mnemonic != 'lea' or 'rip' not in insn.op_str:
            continue

        key_va = _parse_lea_rip_relative(insn, bits)
        if key_va is None or key_va in seen_key_vas:
            continue

        # 读取目标地址的字符串
        key_bytes = read_string_at_va(data, key_va, sections, max_len=64)
        if len(key_bytes) < 5:
            continue

        # 判断是否像密钥（不是普通路径或格式化字符串）
        decoded = key_bytes.decode('ascii', errors='replace')
        if _looks_like_key(key_bytes):
            seen_key_vas.add(key_va)
            lea_keys.append({
                'key': key_bytes,
                'source': f'smart_lea_scan@0x{insn.address:x}',
                'decoded': decoded,
                'method': 'smart_scan',
                'key_va': key_va,
                'confidence': 'scan',
            })
            if verbose:
                print(f"    -> [扫描] lea @ 0x{insn.address:x} → VA=0x{key_va:x}, "
                      f"长度={len(key_bytes)}, 内容={decoded[:32]}...")

    keys.extend(lea_keys)
    return keys


def _looks_like_key(s: bytes) -> bool:
    """判断一个字符串是否像密钥而非普通文本

    密钥特征:
    - 长度 5-64 字节
    - 含大小写字母+数字+下划线（如 SYSTEM_UPDATE_AGENT_2026）
    - 或纯字母数字混合（如 MyS3cr3tK3y）
    - 不是路径（不以 / 开头）
    - 不是格式化字符串（不含 %s 等）
    - 不是普通英文句子（不含空格分隔的多个单词）
    """
    if len(s) < 5 or len(s) > 64:
        return False

    # 过滤路径
    if s.startswith(b'/') or s.startswith(b'\\'):
        return False

    # 过滤格式化字符串
    if b'%s' in s or b'%d' in s or b'%f' in s:
        return False

    # 过滤含多个空格的句子（普通英文描述）
    space_count = s.count(b' ')
    if space_count > 2:
        return False

    # 检查是否含字母和数字的混合（密钥常见特征）
    has_alpha = any(0x41 <= b <= 0x5a or 0x61 <= b <= 0x7a for b in s)
    has_digit = any(0x30 <= b <= 0x39 for b in s)
    has_underscore = b'_' in s

    # 至少含字母
    if not has_alpha:
        return False

    # 含数字或下划线的更像密钥
    # 或者全大写+下划线模式（如 SYSTEM_UPDATE_AGENT_2026）
    is_upper_underscore = all(
        (0x41 <= b <= 0x5a) or b == 0x5f or (0x30 <= b <= 0x39) for b in s
    )
    if is_upper_underscore and len(s) >= 5:
        return True

    # 字母+数字混合
    if has_alpha and has_digit:
        return True

    # 含下划线的标识符
    if has_underscore and has_alpha:
        return True

    return False


# ============================================================
# 第四部分：密钥派生检测
# ============================================================

def detect_key_derivation(data: bytes, keys: list, sections: dict, verbose: bool = False) -> list:
    """检测 RC4 密钥派生模式

    常见模式: RC4(zero_buffer, parent_key) → derived_key
    典型特征:
      - 代码中对全零缓冲区调用 RC4 加密
      - 派生长度通常为 16/32/64 字节

    本函数对每个已知密钥尝试派生，并返回派生后的密钥。
    """
    derived_keys = []
    derive_lengths = [16, 32, 64, 48, 128]

    for key_info in keys:
        key = key_info['key']
        if len(key) < 4:
            continue

        for dlen in derive_lengths:
            derived = rc4_derive_key(key, dlen)

            # 验证派生密钥: 用它尝试解密候选区域中的数据
            # 如果解密结果包含配置信息，则记录
            candidate_regions = _get_encrypted_data_regions(data, sections, verbose=False)

            for region in candidate_regions[:5]:  # 限制验证区域数量
                rdata = region['data']
                # 尝试不同的偏移起点（加密数据可能不在段开头）
                # 例如 .data 段前 0x20 字节可能是指针，加密数据从 0x20 开始
                for skip in (0, 0x10, 0x20, 0x40, 0x80):
                    if skip >= len(rdata):
                        break
                    chunk = rdata[skip:skip + dlen * 4]
                    if len(chunk) < dlen:
                        continue
                    decrypted = rc4_crypt(chunk, derived)
                    # 快速检查: 解密结果是否包含常见配置模式
                    if _quick_check_decrypted(decrypted):
                        decoded_hex = derived.hex()
                        derived_keys.append({
                            'key': derived,
                            'source': f'derived_from({key_info["source"]},len={dlen})',
                            'decoded': decoded_hex[:64],
                            'method': 'derived',
                            'parent_key_source': key_info['source'],
                            'derive_len': dlen,
                        })
                        if verbose:
                            print(f"  [密钥派生] 父密钥={key_info['decoded'][:24]}..., "
                                  f"派生长度={dlen}, 派生密钥={decoded_hex[:32]}..., "
                                  f"skip=0x{skip:x}")
                        break  # 找到有效偏移就够了
                else:
                    continue
                break  # 对这个父密钥，找到一种派生长度就够了

    return derived_keys


def _get_encrypted_data_regions(data: bytes, sections: dict, verbose: bool = False) -> list:
    """获取可能包含加密配置数据的区域（用于密钥派生验证）"""
    regions = []

    # 优先检查 .data 段
    for name in ['.data', '.rdata', '.rodata']:
        if name in sections:
            sec = sections[name]
            if sec['size'] >= 64:  # 至少 64 字节才有意义
                regions.append({
                    'name': f'section:{name}',
                    'offset': sec['offset'],
                    'size': sec['size'],
                    'data': sec['data'],
                })

    # 全文件扫描: 高熵区域
    block_size = 256
    for i in range(0, len(data) - block_size, block_size):
        block = data[i:i + block_size]
        unique_bytes = len(set(block))
        if unique_bytes > 200:
            regions.append({
                'name': f'high_entropy@{i:#x}',
                'offset': i,
                'size': block_size,
                'data': block,
            })

    return regions


def _quick_check_decrypted(data: bytes) -> bool:
    """快速检查解密数据是否可能包含配置信息"""
    # 检查 IP 地址模式
    if IP_PATTERN.search(data):
        return True
    # 检查 TASK 标识
    if TASK_PATTERN.search(data):
        return True
    # 检查 beacon| 模板
    if b'beacon' in data.lower():
        return True
    # 检查高比例可打印字符（可能是配置文本）
    if len(data) > 0:
        printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
        if printable / len(data) > 0.6:
            return True
    return False
# ============================================================
# 第五部分：二进制数据段提取（增强版，含 vaddr 解析）
# ============================================================

def parse_elf_sections(data: bytes) -> dict:
    """解析 ELF 文件，提取各段信息（含虚拟地址 vaddr）"""
    sections = {}
    if len(data) < 4 or data[:4] != b'\x7fELF':
        return sections

    try:
        is_64bit = data[4] == 2
        is_le = data[5] == 1
        fmt = '<' if is_le else '>'

        if is_64bit:
            # ELF64 Header
            e_phoff = struct.unpack_from(fmt + 'Q', data, 0x20)[0]
            e_shoff = struct.unpack_from(fmt + 'Q', data, 0x28)[0]
            e_phentsize = struct.unpack_from(fmt + 'H', data, 0x36)[0]
            e_phnum = struct.unpack_from(fmt + 'H', data, 0x38)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 0x3A)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 0x3E)[0]
            e_entry = struct.unpack_from(fmt + 'Q', data, 0x18)[0]
        else:
            # ELF32 Header
            e_phoff = struct.unpack_from(fmt + 'I', data, 0x1C)[0]
            e_shoff = struct.unpack_from(fmt + 'I', data, 0x20)[0]
            e_phentsize = struct.unpack_from(fmt + 'H', data, 0x2A)[0]
            e_phnum = struct.unpack_from(fmt + 'H', data, 0x2C)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 0x2E)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 0x30)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 0x32)[0]
            e_entry = struct.unpack_from(fmt + 'I', data, 0x18)[0]

        if e_shoff == 0 or e_shnum == 0:
            return sections

        # 获取段名表
        shstr_offset = e_shoff + e_shstrndx * e_shentsize
        if is_64bit:
            shstr_sh_offset = struct.unpack_from(fmt + 'Q', data, shstr_offset + 0x18)[0]
            shstr_sh_size = struct.unpack_from(fmt + 'Q', data, shstr_offset + 0x20)[0]
        else:
            shstr_sh_offset = struct.unpack_from(fmt + 'I', data, shstr_offset + 0x10)[0]
            shstr_sh_size = struct.unpack_from(fmt + 'I', data, shstr_offset + 0x14)[0]

        strtab = data[shstr_sh_offset:shstr_sh_offset + shstr_sh_size]

        # 解析所有段
        for i in range(e_shnum):
            offset = e_shoff + i * e_shentsize
            if offset + e_shentsize > len(data):
                break
            sh_name = struct.unpack_from(fmt + 'I', data, offset)[0]

            if is_64bit:
                sh_type = struct.unpack_from(fmt + 'I', data, offset + 4)[0]
                sh_flags = struct.unpack_from(fmt + 'Q', data, offset + 8)[0]
                sh_addr = struct.unpack_from(fmt + 'Q', data, offset + 0x10)[0]
                sh_offset = struct.unpack_from(fmt + 'Q', data, offset + 0x18)[0]
                sh_size = struct.unpack_from(fmt + 'Q', data, offset + 0x20)[0]
            else:
                sh_type = struct.unpack_from(fmt + 'I', data, offset + 4)[0]
                sh_flags = struct.unpack_from(fmt + 'I', data, offset + 8)[0]
                sh_addr = struct.unpack_from(fmt + 'I', data, offset + 0x0C)[0]
                sh_offset = struct.unpack_from(fmt + 'I', data, offset + 0x10)[0]
                sh_size = struct.unpack_from(fmt + 'I', data, offset + 0x14)[0]

            name_end = strtab.find(b'\x00', sh_name)
            name = strtab[sh_name:name_end].decode('ascii', errors='ignore') if name_end > sh_name else ''

            if sh_offset + sh_size <= len(data) and sh_size > 0:
                sections[name] = {
                    'offset': sh_offset,
                    'size': sh_size,
                    'type': sh_type,
                    'vaddr': sh_addr,
                    'flags': sh_flags,
                    'data': data[sh_offset:sh_offset + sh_size],
                }

        # 也解析 program headers，用于 VA 到文件偏移的通用转换
        phdr_mappings = []
        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + e_phentsize > len(data):
                break
            if is_64bit:
                p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
                p_offset = struct.unpack_from(fmt + 'Q', data, ph_off + 8)[0]
                p_vaddr = struct.unpack_from(fmt + 'Q', data, ph_off + 0x10)[0]
                p_filesz = struct.unpack_from(fmt + 'Q', data, ph_off + 0x20)[0]
            else:
                p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
                p_offset = struct.unpack_from(fmt + 'I', data, ph_off + 4)[0]
                p_vaddr = struct.unpack_from(fmt + 'I', data, ph_off + 8)[0]
                p_filesz = struct.unpack_from(fmt + 'I', data, ph_off + 0x10)[0]

            if p_type == 1:  # PT_LOAD
                phdr_mappings.append({
                    'vaddr': p_vaddr,
                    'offset': p_offset,
                    'filesz': p_filesz,
                })

        sections['_phdr_mappings'] = phdr_mappings

    except Exception:
        pass

    return sections


def parse_pe_sections(data: bytes) -> dict:
    """解析 PE 文件，提取各段信息（含虚拟地址）"""
    sections = {}
    if len(data) < 2 or data[:2] != b'MZ':
        return sections

    try:
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return sections

        # COFF Header
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]

        # Image Base
        opt_offset = pe_offset + 24
        magic = struct.unpack_from('<H', data, opt_offset)[0]
        is_pe64 = (magic == 0x20B)
        if is_pe64:
            image_base = struct.unpack_from('<Q', data, opt_offset + 24)[0]
        else:
            image_base = struct.unpack_from('<I', data, opt_offset + 28)[0]

        # Section Table
        sec_table_offset = pe_offset + 24 + opt_header_size

        for i in range(num_sections):
            offset = sec_table_offset + i * 40
            if offset + 40 > len(data):
                break
            name = data[offset:offset + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
            vsize = struct.unpack_from('<I', data, offset + 8)[0]
            rva = struct.unpack_from('<I', data, offset + 12)[0]
            raw_size = struct.unpack_from('<I', data, offset + 16)[0]
            raw_offset = struct.unpack_from('<I', data, offset + 20)[0]

            if raw_offset + raw_size <= len(data) and raw_size > 0:
                sections[name] = {
                    'offset': raw_offset,
                    'size': raw_size,
                    'vaddr': image_base + rva,
                    'data': data[raw_offset:raw_offset + raw_size],
                }

    except Exception:
        pass

    return sections


def get_data_sections(data: bytes) -> dict:
    """获取二进制文件中可能包含配置数据的段"""
    sections = {}

    elf_sections = parse_elf_sections(data)
    if elf_sections:
        sections = elf_sections
        sections['_format'] = 'ELF'
    else:
        pe_sections = parse_pe_sections(data)
        if pe_sections:
            sections = pe_sections
            sections['_format'] = 'PE'
        else:
            sections['_format'] = 'raw'

    return sections


def va_to_file_offset_generic(va: int, sections: dict) -> int:
    """通用的 VA → 文件偏移转换，优先使用段表，回退到 program header 映射"""
    # 优先: 通过段表转换
    for name, sec in sections.items():
        if name.startswith('_'):
            continue
        sec_vaddr = sec.get('vaddr', 0)
        sec_size = sec.get('size', 0)
        if sec_vaddr <= va < sec_vaddr + sec_size:
            offset_in_sec = va - sec_vaddr
            file_off = sec['offset'] + offset_in_sec
            return file_off

    # 回退: 通过 program header / section header 映射
    phdr_mappings = sections.get('_phdr_mappings', [])
    for mapping in phdr_mappings:
        vaddr_start = mapping['vaddr']
        vaddr_end = vaddr_start + mapping['filesz']
        if vaddr_start <= va < vaddr_end:
            return mapping['offset'] + (va - vaddr_start)

    return -1


# 覆盖之前的简单版 va_to_file_offset
def va_to_file_offset(va: int, sections: dict, verbose: bool = False) -> int:
    return va_to_file_offset_generic(va, sections)


def get_candidate_regions(data: bytes, sections: dict, verbose: bool = False) -> list:
    """获取可能包含配置数据的候选区域"""
    regions = []

    # 优先检查 .data / .rodata / .rdata 段
    priority_names = ['.data', '.rodata', '.rdata', '.bss', '.data1', '.rodata1']
    for name in priority_names:
        if name in sections:
            sec = sections[name]
            regions.append({
                'name': f'section:{name}',
                'offset': sec['offset'],
                'size': sec['size'],
                'data': sec['data'],
            })
            if verbose:
                print(f"  [候选区域] section:{name} offset=0x{sec['offset']:x} size={sec['size']}")

    # 检查 .text 段中的内联数据
    if '.text' in sections:
        text_data = sections['.text']['data']
        for m in re.finditer(rb'[\x20-\x7e]{16,}', text_data):
            regions.append({
                'name': f'.text_inline@{sections[".text"]["offset"] + m.start():#x}',
                'offset': sections['.text']['offset'] + m.start(),
                'size': len(m.group(0)),
                'data': m.group(0),
            })

    # 全文件扫描: 高熵区域
    block_size = 256
    for i in range(0, len(data) - block_size, block_size):
        block = data[i:i + block_size]
        unique_bytes = len(set(block))
        if unique_bytes > 200:
            regions.append({
                'name': f'high_entropy@{i:#x}',
                'offset': i,
                'size': block_size,
                'data': block,
            })

    # 全文件也加入
    regions.append({
        'name': 'full_file',
        'offset': 0,
        'size': len(data),
        'data': data,
    })

    return regions
# ============================================================
# 第六部分：密钥搜索（暴力穷举备选）
# ============================================================

def search_rc4_keys(data: bytes, verbose: bool = False) -> list:
    """在二进制中搜索可能的 RC4 密钥（暴力字符串搜索，作为备选方案）

    策略:
    1. 搜索可打印字符串 5-64 字节（常见密钥长度）
    2. 搜索 .rodata 段中的字符串
    3. 搜索 hex 编码的密钥
    4. 常见硬编码密钥
    """
    keys = []

    # 策略1: 可打印字符串 5-64 字节
    for m in re.finditer(rb'[\x20-\x7e]{5,64}', data):
        key_str = m.group(0)
        decoded = key_str.decode('ascii', errors='ignore')
        if len(decoded) < 5:
            continue
        if decoded.isdigit():
            continue
        keys.append({
            'key': key_str,
            'source': f'string@{m.start():#x}',
            'decoded': decoded,
            'method': 'bruteforce',
        })

    # 策略2: hex 编码的 16/32 字节密钥
    for m in re.finditer(rb'[0-9a-fA-F]{16,64}', data):
        hex_str = m.group(0).decode('ascii')
        try:
            key_bytes = bytes.fromhex(hex_str)
            if len(key_bytes) in (16, 24, 32):
                keys.append({
                    'key': key_bytes,
                    'source': f'hex@{m.start():#x}',
                    'decoded': hex_str,
                    'method': 'bruteforce',
                })
        except ValueError:
            pass

    # 策略3: 常见硬编码密钥（CTF 高频）
    common_keys = [
        b'reverseme', b'password', b'secret', b'123456', b'admin',
        b'ctfkey', b'flagkey', b'testkey', b'hello',
        b'\x00' * 16, b'\x01' * 16, b'\xff' * 16,
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        b'0123456789',
    ]
    for ck in common_keys:
        keys.append({
            'key': ck,
            'source': 'common_key',
            'decoded': ck.decode('ascii', errors='ignore'),
            'method': 'bruteforce',
        })

    if verbose:
        print(f"  [暴力搜索] 找到 {len(keys)} 个候选密钥")

    return keys


# ============================================================
# 第六点五部分：Cobalt Strike Beacon 专用解析模块
# ============================================================
#
# CTF 竞赛语境：本模块用于 CTF 应急响应方向竞赛中快速提取 CS Beacon 配置
# 参考：SentinelOne/CobaltStrikeParser 项目结构
# 支持：标准版(3.x/4.x) + 魔改版(XOR密钥爆破 + pos/datatype偏移适配)

# CS Beacon 配置块固定大小
CS_CONFIG_BLOCK_SIZE = 4096

# 标准 XOR 密钥
CS_XOR_KEYS_STANDARD = [0x2e, 0x69]

# 标准配置块特征头（解密后前6字节）
CS_CONFIG_SIGNATURE = b'\x00\x01\x00\x01\x00\x02'

# 标准字段映射（pos → 字段名）
CS_FIELD_MAP = {
    0x0001: 'BeaconType',
    0x0002: 'Port',
    0x0003: 'SleepTime',
    0x0004: 'MaxGetSize',
    0x0005: 'Jitter',
    0x0006: 'MaxDNS',
    0x0007: 'PublicKey',
    0x0008: 'C2Server',
    0x0009: 'UserAgent',
    0x000a: 'PostURI',
    0x000b: 'Unknown_0x0a',
    0x000c: 'UserAgent2',
    0x000d: 'Unknown_0x0d',
    0x000e: 'Unknown_0x0e',
    0x000f: 'Unknown_0x0f',
    0x0010: 'Unknown_0x10',
    0x0011: 'Unknown_0x11',
    0x0012: 'Unknown_0x12',
    0x0013: 'Unknown_0x13',
    0x0014: 'Unknown_0x14',
    0x0015: 'Unknown_0x15',
    0x0016: 'Unknown_0x16',
    0x0017: 'Unknown_0x17',
    0x0018: 'Unknown_0x18',
    0x0019: 'Unknown_0x19',
    0x001a: 'Unknown_0x1a',
    0x001b: 'Unknown_0x1b',
    0x001c: 'Stage',
    0x001d: 'Unknown_0x1d',
    0x001e: 'Unknown_0x1e',
    0x001f: 'Unknown_0x1f',
    0x0020: 'Unknown_0x20',
    0x0021: 'Unknown_0x21',
    0x0022: 'Unknown_0x22',
    0x0023: 'Unknown_0x23',
    0x0024: 'Unknown_0x24',
    0x0025: 'Unknown_0x25',
    0x0026: 'Unknown_0x26',
    0x0027: 'Unknown_0x27',
    0x0028: 'Unknown_0x28',
    0x0029: 'Unknown_0x29',
    0x002a: 'Unknown_0x2a',
    0x002b: 'Unknown_0x2b',
    0x002c: 'Unknown_0x2c',
    0x002d: 'Unknown_0x2d',
    0x002e: 'Unknown_0x2e',
    0x002f: 'Unknown_0x2f',
    0x0030: 'Unknown_0x30',
    0x0031: 'Unknown_0x31',
    0x0032: 'Unknown_0x32',
    0x0033: 'Unknown_0x33',
    0x0034: 'Unknown_0x34',
    0x0035: 'Unknown_0x35',
    0x0036: 'Unknown_0x36',
    0x0037: 'Unknown_0x37',
    0x0038: 'Unknown_0x38',
    0x0039: 'Unknown_0x39',
    0x003a: 'Unknown_0x3a',
    0x003b: 'Unknown_0x3b',
    0x003c: 'Unknown_0x3c',
    0x003d: 'Unknown_0x3d',
    0x003e: 'Unknown_0x3e',
    0x003f: 'Unknown_0x3f',
    0x0040: 'Unknown_0x40',
}

# BeaconType 值映射
CS_BEACON_TYPE_MAP = {
    0: 'HTTP',
    1: 'DNS',
    2: 'SMB',
    3: 'TCP',
    4: 'HTTPS',
    8: 'Bind_TCP',
    16: 'HTTP-Proxy',
    32: 'HTTPS-Proxy',
}

# DataType 值映射
CS_DATATYPE_MAP = {
    0: 'NONE',
    1: 'SHORT',
    2: 'INT',
    3: 'STR',
}


def detect_cs_beacon(data: bytes, sections: dict, verbose: bool = False) -> dict:
    """检测是否为 Cobalt Strike Beacon 并提取配置

    检测策略:
    1. 在各数据段中搜索 4096 字节配置块
    2. 用标准 XOR 密钥(0x2e, 0x69)尝试解密
    3. 检查解密后是否出现标准特征头 00 01 00 01 00 02
    4. 如果标准密钥失败，暴力扫描全部 256 个单字节密钥
    5. 对魔改版：检测 pos/datatype 偏移

    返回: dict（含配置信息）或空 dict
    """
    # 收集可能包含配置块的数据段
    search_regions = []
    for name in ['.data', '.rdata', '.rodata', '.text']:
        if name in sections:
            sec = sections[name]
            sec_data = sec['data']
            if len(sec_data) < 64:
                continue
            search_regions.append({
                'name': name,
                'offset': sec['offset'],
                'data': sec_data,
            })

    # 也检查全文件
    if len(data) >= CS_CONFIG_BLOCK_SIZE:
        search_regions.append({
            'name': 'full_file',
            'offset': 0,
            'data': data,
        })

    # 尝试每个搜索区域
    for region in search_regions:
        rdata = region['data']
        roffset = region['offset']

        # 在数据块中按 0x100 粒度滑动搜索配置块
        for scan_off in range(0, len(rdata) - 64, 0x100):
            block = rdata[scan_off: scan_off + min(CS_CONFIG_BLOCK_SIZE, len(rdata) - scan_off)]
            if len(block) < 64:
                break

            # 先尝试标准密钥
            for key in CS_XOR_KEYS_STANDARD:
                decrypted = bytes(b ^ key for b in block)
                if _check_cs_signature(decrypted):
                    if verbose:
                        print(f"  [CS] 标准密钥 0x{key:02x} 命中，"
                              f"区域={region['name']}, 偏移=0x{roffset + scan_off:x}")
                    config = _parse_cs_config(decrypted, key, roffset + scan_off,
                                              pos_offset=0, verbose=verbose)
                    if config:
                        return config

            # 标准密钥失败 → 暴力扫描
            for key in range(256):
                if key in CS_XOR_KEYS_STANDARD:
                    continue
                decrypted = bytes(b ^ key for b in block)
                if _check_cs_signature(decrypted):
                    if verbose:
                        print(f"  [CS] 非标准密钥 0x{key:02x} 命中（魔改），"
                              f"区域={region['name']}, 偏移=0x{roffset + scan_off:x}")
                    config = _parse_cs_config(decrypted, key, roffset + scan_off,
                                              pos_offset=0, verbose=verbose)
                    if config:
                        return config

            # 标准特征头未命中 → 尝试魔改检测
            # 魔改特征：解密后可能出现 00 65 00 07（pos+0x64, datatype+0x6）
            for key in range(256):
                decrypted = bytes(b ^ key for b in block)
                pos_off = _detect_modified_pos_offset(decrypted)
                if pos_off is not None:
                    if verbose:
                        print(f"  [CS] 检测到魔改偏移 pos+0x{pos_off:x}, "
                              f"XOR密钥=0x{key:02x}")
                    config = _parse_cs_config(decrypted, key, roffset + scan_off,
                                              pos_offset=pos_off, verbose=verbose)
                    if config:
                        return config

    return {}


def _check_cs_signature(decrypted: bytes) -> bool:
    """检查解密后的数据是否包含标准 CS Beacon 配置特征头"""
    # 特征头1：00 01 00 01 00 02（标准版）
    if decrypted[:6] == CS_CONFIG_SIGNATURE:
        return True
    # 特征头2：00 01 00 02 00 02（某些变体）
    if decrypted[:4] == b'\x00\x01\x00\x02':
        return True
    return False


def _detect_modified_pos_offset(decrypted: bytes):
    """检测魔改版 CS Beacon 的 pos/datatype 偏移

    魔改版特征：pos 值统一偏移 N，datatype 值统一偏移 M
    常见组合：pos += 0x64, datatype += 0x06

    检测方法：检查前 8 字节是否符合魔改模式
    正常: pos=0x0001, datatype=0x0001/0x0002, len=0x0002
    魔改: pos=0x00XX, datatype=0x00YY, len=0x0002
    其中 XX > 1 且 YY > 3 且 len 字段仍为 0x0002

    返回: pos 偏移量 或 None
    """
    if len(decrypted) < 8:
        return None

    pos1 = struct.unpack_from('>H', decrypted, 0)[0]
    dtype1 = struct.unpack_from('>H', decrypted, 2)[0]
    len1 = struct.unpack_from('>H', decrypted, 4)[0]

    # 标准 len 应该是 2（SHORT 类型），且 pos > 0
    if len1 != 2:
        return None
    if pos1 <= 1:
        return None  # 标准版，不是魔改

    # 计算偏移
    pos_offset = pos1 - 1  # 标准第一个字段 pos=1

    # 验证：偏移后 pos 应为 1（BeaconType）
    if pos_offset < 1 or pos_offset > 0x200:
        return None

    # 检查 datatype 偏移：标准应该是 1(SHORT) 或 2(INT)
    # 魔改后如果 datatype = 0x07，偏移 0x06
    dtype_offset = dtype1 - 1  # 标准第一个字段 datatype=1(SHORT)
    if dtype_offset < 0 or dtype_offset > 0x20:
        return None

    # 验证第二组数据（pos=0x02 对应 Port）
    if len(decrypted) >= 16:
        pos2 = struct.unpack_from('>H', decrypted, 8)[0]
        len2 = struct.unpack_from('>H', decrypted, 12)[0]
        expected_pos2 = 2 + pos_offset
        if pos2 == expected_pos2 and len2 == 2:
            return pos_offset

    return None


def _parse_cs_config(data: bytes, xor_key: int, block_offset: int,
                     pos_offset: int = 0, verbose: bool = False) -> dict:
    """解析 CS Beacon 配置块（TLV 格式）

    结构: pos(2B) | datatype(2B) | len(2B) | data(len B)
    魔改版: pos 值需要减去 pos_offset 还原
    """
    config = {}
    entries = []
    pos = 0
    valid_entries = 0

    while pos + 6 <= len(data):
        raw_pos = struct.unpack_from('>H', data, pos)[0]
        raw_dtype = struct.unpack_from('>H', data, pos + 2)[0]
        length = struct.unpack_from('>H', data, pos + 4)[0]

        # 长度校验
        if length > 2048 or pos + 6 + length > len(data):
            break

        # 还原魔改偏移
        field_pos = raw_pos - pos_offset
        # datatype 偏移检测（如果有）
        if pos_offset > 0:
            # 标准datatype: 0-3，魔改后可能偏移
            dtype = raw_dtype
            if raw_dtype > 3 and (raw_dtype - 6) in (0, 1, 2, 3):
                dtype = raw_dtype - 6
            elif raw_dtype > 3 and (raw_dtype - pos_offset) in (0, 1, 2, 3):
                dtype = raw_dtype - pos_offset
            else:
                dtype = raw_dtype
        else:
            dtype = raw_dtype

        value_bytes = data[pos + 6: pos + 6 + length]
        field_name = CS_FIELD_MAP.get(field_pos, f'Unknown_0x{field_pos:04x}')
        value = _decode_cs_value(dtype, value_bytes)

        if field_name in ('BeaconType', 'Port', 'C2Server', 'UserAgent',
                          'UserAgent2', 'PostURI', 'SleepTime', 'Jitter',
                          'Stage', 'PublicKey'):
            entries.append((field_name, value, dtype))
            config[field_name] = value
            valid_entries += 1

        pos += 6 + length

    if verbose and entries:
        print(f"  [CS] 解析到 {valid_entries} 个有效字段:")
        for fname, fval, fdtype in entries:
            dt_name = CS_DATATYPE_MAP.get(fdtype, f'?{fdtype}')
            print(f"    {fname:<16} ({dt_name}) = {fval}")

    # 至少需要 3 个有效字段才算成功
    if valid_entries < 3:
        if verbose:
            print(f"  [CS] 有效字段不足({valid_entries})，判定失败")
        return {}

    # 构造与通用提取器兼容的结果格式
    info = _cs_config_to_info(config, xor_key, block_offset, pos_offset)
    return info


def _decode_cs_value(dtype: int, value_bytes: bytes):
    """根据 CS 的 datatype 解码值"""
    if dtype == 1:  # SHORT
        if len(value_bytes) == 2:
            return struct.unpack('>H', value_bytes)[0]
        elif len(value_bytes) == 4:
            return struct.unpack('>I', value_bytes)[0]
        return int.from_bytes(value_bytes, 'big')
    elif dtype == 2:  # INT
        if len(value_bytes) == 4:
            return struct.unpack('>I', value_bytes)[0]
        return int.from_bytes(value_bytes, 'big')
    elif dtype == 3:  # STR
        return value_bytes.decode('ascii', errors='ignore').rstrip('\x00')
    else:
        return value_bytes.hex()


def _cs_config_to_info(config: dict, xor_key: int, block_offset: int,
                       pos_offset: int) -> dict:
    """将 CS 配置转换为通用提取器的 info 格式"""
    info = {
        'ip_addresses': [],
        'ports': [],
        'task_ids': [],
        'urls': [],
        'domains': [],
        'protocols': [],
        'config_keywords': [],
        'raw_ascii': [],
        'beacon_templates': [],
        '_xor_key': xor_key,
        '_block_offset': block_offset,
        '_pos_offset': pos_offset,
    }

    # 端口
    if 'Port' in config:
        port = config['Port']
        if isinstance(port, int) and 1 <= port <= 65535:
            info['ports'].append(port)

    # C2Server: 格式通常为 "IP,URI" 或 "DOMAIN,URI"
    if 'C2Server' in config:
        c2 = str(config['C2Server'])
        # 提取 IP
        for m in IP_PATTERN.finditer(c2.encode()):
            ip = m.group(1).decode()
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                info['ip_addresses'].append(ip)
        # 提取域名（非 IP 的主机名部分）
        if ',' in c2:
            host = c2.split(',')[0].strip()
            if host and not re.match(r'\d+\.\d+\.\d+\.\d+', host):
                info['domains'].append(host)
        # 如果包含完整 URL
        if 'http' in c2.lower():
            url_match = re.search(r'(https?://[^\s,]+)', c2)
            if url_match:
                info['urls'].append(url_match.group(1))

    # BeaconType → 协议
    if 'BeaconType' in config:
        btype = config['BeaconType']
        if isinstance(btype, int):
            proto = CS_BEACON_TYPE_MAP.get(btype, f'Unknown({btype})')
            info['protocols'].append(proto)

    # UserAgent
    ua = ''
    if 'UserAgent' in config and isinstance(config['UserAgent'], str):
        ua = config['UserAgent']
    elif 'UserAgent2' in config and isinstance(config['UserAgent2'], str):
        ua = config['UserAgent2']

    # 配置关键字
    for fname in ('BeaconType', 'Port', 'SleepTime', 'Jitter',
                  'C2Server', 'UserAgent', 'Stage', 'PublicKey'):
        if fname in config:
            info['config_keywords'].append({
                'keyword': fname,
                'offset': 0,
                'value': str(config[fname])[:128],
            })

    return info


# ============================================================
# 第七部分：自动解密引擎（重构版，智能优先）
# ============================================================

def try_decrypt_with_keys(region_data: bytes, keys: list, verbose: bool = False) -> list:
    """对一段数据使用指定密钥列表尝试解密

    尝试顺序:
    1. 单密钥 RC4
    2. 单密钥 RC4 + 密钥派生模式（RC4(zero_buf, key) → derived_key，再用 derived_key 解密）
    3. XOR（单字节 + 多字节）
    4. AES-ECB / AES-CBC

    注意: 双层 RC4 暴力组合已移除（O(n^2) 问题），改由密钥派生检测替代
    """
    results = []
    # 加密数据可能不在段开头（如 .data 段前 0x20 字节可能是指针）
    SKIP_OFFSETS = (0, 0x10, 0x20, 0x40, 0x80)

    for key_info in keys:
        key = key_info['key']
        source = key_info.get('source', '?')
        decoded = key_info.get('decoded', '?')

        # 1. 单密钥 RC4（含偏移扫描）
        for skip in SKIP_OFFSETS:
            if skip >= len(region_data):
                break
            chunk = region_data[skip:]
            if len(chunk) < 16:
                break
            decrypted = rc4_crypt(chunk, key)
            info = extract_info(decrypted, verbose=False)
            if has_interesting_info(info):
                results.append({
                    'method': f'rc4({decoded[:16]}...@{source},skip=0x{skip:x})',
                    'decrypted': decrypted,
                    'info': info,
                })

        # 2. 密钥派生模式: RC4(zero_buf, key) → derived_key → RC4(data, derived_key)
        #    含偏移扫描（真实样本中 .data 前 0x20 字节是非加密指针数据）
        for dlen in [16, 32, 64]:
            derived_key = rc4_derive_key(key, dlen)
            for skip in SKIP_OFFSETS:
                if skip >= len(region_data):
                    break
                chunk = region_data[skip:]
                if len(chunk) < 16:
                    break
                decrypted2 = rc4_crypt(chunk, derived_key)
                info2 = extract_info(decrypted2, verbose=False)
                if has_interesting_info(info2):
                    results.append({
                        'method': f'rc4_derived(parent={decoded[:12]}...,len={dlen},skip=0x{skip:x})',
                        'decrypted': decrypted2,
                        'info': info2,
                    })

        # 3. XOR（含偏移扫描）
        for skip in SKIP_OFFSETS:
            if skip >= len(region_data):
                break
            chunk = region_data[skip:]
            if len(chunk) < 16:
                break
            decrypted = xor_crypt(chunk, key)
            info = extract_info(decrypted, verbose=False)
            if has_interesting_info(info):
                results.append({
                    'method': f'xor({decoded[:16]}...@{source},skip=0x{skip:x})',
                    'decrypted': decrypted,
                    'info': info,
                })

        # 4. AES（密钥长度合适时，不偏移扫描，AES 通常对齐）
        if len(key) >= 5:
            decrypted = try_aes_ecb(region_data, key)
            if decrypted:
                info = extract_info(decrypted, verbose=False)
                if has_interesting_info(info):
                    results.append({
                        'method': f'aes_ecb({decoded[:16]}...)',
                        'decrypted': decrypted,
                        'info': info,
                    })

            decrypted = try_aes_cbc(region_data, key)
            if decrypted:
                info = extract_info(decrypted, verbose=False)
                if has_interesting_info(info):
                    results.append({
                        'method': f'aes_cbc({decoded[:16]}...)',
                        'decrypted': decrypted,
                        'info': info,
                    })

    return results


def try_single_byte_xor(region_data: bytes) -> list:
    """单字节 XOR 暴力（0x00-0xFF）"""
    results = []
    for xor_key in range(256):
        decrypted = xor_crypt(region_data, bytes([xor_key]))
        info = extract_info(decrypted, verbose=False)
        if has_interesting_info(info):
            results.append({
                'method': f'xor_single_byte(0x{xor_key:02x})',
                'decrypted': decrypted,
                'info': info,
            })
    return results


def merge_results(results_list: list) -> dict:
    """合并多个解密结果中的信息，去重，端口按频率排序"""
    merged = {
        'ip_addresses': [],
        'ports': [],
        'task_ids': [],
        'urls': [],
        'domains': [],
        'protocols': [],
        'config_keywords': [],
        'beacon_templates': [],
        'methods': [],
    }

    # 端口频率统计 + 方法质量加权
    port_counter = {}

    # 方法质量权重（高质量解密方法产生的端口优先）
    METHOD_WEIGHT = {
        'cs_beacon': 25,   # CS Beacon 专用解析（最高可信度）
        'rc4_derived': 20,  # 派生密钥解密（最可靠）
        'rc4': 15,          # 单密钥 RC4
        'aes_ecb': 12, 'aes_cbc': 12,
        'plaintext': 2,     # 明文中的端口（多为段名等噪声）
        'plain': 2,
        'xor': 3,           # XOR 暴力穷举（误报多）
        'xor_single_byte': 1,  # 单字节 XOR（误报最多）
    }

    def _method_weight(method_str: str) -> int:
        for prefix, weight in METHOD_WEIGHT.items():
            if method_str.startswith(prefix):
                return weight
        return 2

    for r in results_list:
        merged['methods'].append(r['method'])
        info = r['info']
        w = _method_weight(r['method'])
        for key in ['ip_addresses', 'task_ids', 'urls', 'domains',
                    'protocols', 'config_keywords', 'beacon_templates']:
            for item in info.get(key, []):
                if item not in merged[key]:
                    merged[key].append(item)
        # 端口按频率 + 方法质量加权统计
        for item in info.get('ports', []):
            # 过滤明显误报：端口号 1-9 几乎不可能是真实端口
            if 1 <= item <= 9:
                continue
            port_counter[item] = port_counter.get(item, 0) + w

    # 端口按加权分降序排序
    # CTF 控制软件常见端口范围加分
    PRIORITY_PORT_RANGES = [(4444, 4450), (8443, 9500), (50000, 65535)]
    def _port_priority(port):
        for lo, hi in PRIORITY_PORT_RANGES:
            if lo <= port <= hi:
                return port_counter.get(port, 0) + 15
        # 非知名高端口也适当加分
        if 1024 <= port <= 65535:
            return port_counter.get(port, 0) + 5
        # 端口 10-1023 不加分（极小的端口号几乎不可能是 C2 端口）
        return port_counter.get(port, 0)

    sorted_ports = sorted(port_counter.keys(), key=lambda p: _port_priority(p), reverse=True)
    # 只保留加权分 >= 3 的端口，如果全部低于 3 则保留前 5 个
    high_quality = [p for p in sorted_ports if port_counter[p] >= 3]
    if high_quality:
        merged['ports'] = high_quality[:10]
    else:
        merged['ports'] = sorted_ports[:5]

    return merged


# ============================================================
# 第八部分：主引擎（重构版，智能优先 + 暴力降级）
# ============================================================

def analyze_binary(filepath: str, verbose: bool = False, rc4_key_hex: str = None,
                   smart_only: bool = False) -> dict:
    """主分析函数: 智能密钥优先 → 暴力穷举降级

    分析流程:
    Phase 1: 明文扫描
    Phase 1.5: Cobalt Strike Beacon 专用检测（XOR 爆破 + TLV 解析）
    Phase 2: 智能密钥定位（capstone 反汇编 → KSA 识别 → lea 追踪）
    Phase 3: 密钥派生检测（RC4(zero_buf, key) → derived_key）
    Phase 4: 用智能密钥尝试解密
    Phase 5: 暴力穷举降级（仅在 smart_only=False 时）
    """
    filepath = Path(filepath)
    if not filepath.exists():
        print(f"[-] 文件不存在: {filepath}")
        return {}

    data = filepath.read_bytes()
    print(f"[*] 文件: {filepath.name} ({len(data)} bytes)")

    # ---- Phase 0: 文件格式识别与段解析 ----
    sections = get_data_sections(data)
    file_format = sections.get('_format', 'raw')
    del sections['_format']
    print(f"[*] 文件格式: {file_format}")
    if sections:
        sec_names = [n for n in sections.keys() if not n.startswith('_')]
        print(f"[*] 段信息: {', '.join(sec_names)}")

    arch_info = detect_arch(data)
    print(f"[*] 架构: {arch_info['arch']} ({arch_info['bits']}bit, {arch_info['endian']})")

    all_results = []

    # ---- Phase 1: 明文扫描 ----
    print(f"\n[Phase 1] 明文扫描...")
    plain_info = extract_info(data, verbose=verbose)
    if has_interesting_info(plain_info):
        print(f"  [+] 明文中发现信息!")
        _print_info(plain_info, indent='  ')
        all_results.append({'method': 'plaintext', 'info': plain_info, 'decrypted': data})

    # ---- Phase 1.5: Cobalt Strike Beacon 专用检测 ----
    print(f"\n[Phase 1.5] Cobalt Strike Beacon 检测...")
    cs_config = detect_cs_beacon(data, sections, verbose=verbose)
    if cs_config:
        print(f"  [+] 检测到 CS Beacon 配置!")
        _print_info(cs_config, indent='  ')
        all_results.append({
            'method': f'cs_beacon(xor_key=0x{cs_config.get("_xor_key", 0):02x})',
            'info': cs_config,
            'decrypted': b'',
        })
    else:
        print(f"  [-] 未检测到 CS Beacon 特征")

    # ---- Phase 2: 智能密钥定位 ----
    print(f"\n[Phase 2] 智能密钥定位引擎...")
    smart_keys = smart_key_extraction(data, sections, arch_info, verbose=verbose)
    print(f"  智能提取到 {len(smart_keys)} 把密钥")

    # ---- Phase 3: 密钥派生检测 ----
    print(f"\n[Phase 3] 密钥派生检测...")
    # 对智能提取的密钥做派生检测
    derived_keys = detect_key_derivation(data, smart_keys, sections, verbose=verbose)
    if not derived_keys:
        # 也对常见字符串做派生检测（有限范围）
        quick_keys = search_rc4_keys(data, verbose=False)
        # 去重并限制数量
        seen = set()
        unique_quick = []
        for k in quick_keys:
            if k['key'] not in seen:
                seen.add(k['key'])
                unique_quick.append(k)
        # 只取前 50 个做派生检测（避免太慢）
        derived_keys = detect_key_derivation(data, unique_quick[:50], sections, verbose=verbose)
    print(f"  检测到 {len(derived_keys)} 个派生密钥")

    # ---- Phase 4: 用智能密钥 + 派生密钥尝试解密 ----
    print(f"\n[Phase 4] 智能密钥解密尝试...")
    all_smart_keys = smart_keys + derived_keys

    if all_smart_keys:
        regions = get_candidate_regions(data, sections, verbose=verbose)
        # 限制区域数量
        if len(regions) > 50:
            regions = regions[:50]

        for region in regions:
            if verbose:
                print(f"  扫描区域 {region['name']} ({region['size']} bytes)")
            decrypt_results = try_decrypt_with_keys(region['data'], all_smart_keys, verbose=verbose)
            for r in decrypt_results:
                r['region'] = region['name']
                all_results.append(r)

    # 如果智能模式已经找到结果，可以提前报告
    smart_found = any(r['method'] not in ('plaintext', 'bruteforce') for r in all_results)
    if smart_found:
        print(f"  [+] 智能模式已发现有效解密结果!")

    # ---- Phase 5: 暴力穷举降级 ----
    if not smart_only:
        print(f"\n[Phase 5] 暴力穷举降级...")

        # 收集所有密钥
        print(f"  密钥搜索...")
        if rc4_key_hex:
            try:
                manual_key = bytes.fromhex(rc4_key_hex)
                brute_keys = [{'key': manual_key, 'source': 'manual', 'decoded': rc4_key_hex, 'method': 'manual'}]
                print(f"  使用手动指定密钥: {rc4_key_hex}")
            except ValueError:
                print(f"  [-] 无效的 hex 密钥: {rc4_key_hex}")
                brute_keys = search_rc4_keys(data, verbose=verbose)
        else:
            brute_keys = search_rc4_keys(data, verbose=verbose)

        # 去重
        seen_keys = set()
        unique_keys = []
        for k in brute_keys:
            if k['key'] not in seen_keys:
                seen_keys.add(k['key'])
                unique_keys.append(k)
        brute_keys = unique_keys
        if len(brute_keys) > 200:
            print(f"  (密钥过多，取前 200 个)")
            brute_keys = brute_keys[:200]

        print(f"  找到 {len(brute_keys)} 个暴力候选密钥")

        regions = get_candidate_regions(data, sections, verbose=verbose)
        if len(regions) > 50:
            regions = regions[:50]

        # 单字节 XOR（快速，对所有区域执行）
        print(f"  单字节 XOR 扫描...")
        for region in regions[:10]:  # 只对前 10 个区域做
            xor_results = try_single_byte_xor(region['data'][:1024])  # 限制数据量
            for r in xor_results:
                r['region'] = region['name']
                all_results.append(r)

        # 用候选密钥解密
        print(f"  候选密钥解密扫描...")
        for i, region in enumerate(regions):
            if verbose:
                print(f"  扫描区域 [{i+1}/{len(regions)}] {region['name']} ({region['size']} bytes)")
            decrypt_results = try_decrypt_with_keys(region['data'], brute_keys, verbose=verbose)
            for r in decrypt_results:
                r['region'] = region['name']
                all_results.append(r)
    else:
        print(f"\n[Phase 5] 跳过暴力穷举（--smart-only 模式）")

    # ---- 汇总结果 ----
    print(f"\n[汇总] 结果合并...")
    if all_results:
        merged = merge_results(all_results)
        merged['all_results'] = all_results
    else:
        merged = {
            'ip_addresses': [], 'ports': [], 'task_ids': [],
            'urls': [], 'domains': [], 'protocols': [],
            'config_keywords': [], 'beacon_templates': [], 'methods': [],
        }

    # 合并明文结果
    if plain_info and has_interesting_info(plain_info):
        if 'plain' not in merged['methods']:
            merged['methods'].append('plain')
        for key in ['ip_addresses', 'ports', 'task_ids', 'urls', 'domains', 'protocols']:
            for item in plain_info.get(key, []):
                if item not in merged[key]:
                    merged[key].append(item)

    return merged


# ============================================================
# 第九部分：报告输出
# ============================================================

def _print_info(info: dict, indent: str = ''):
    """打印提取到的信息"""
    if info.get('ip_addresses'):
        print(f"{indent}[IP 地址]")
        for ip in info['ip_addresses']:
            print(f"{indent}  - {ip}")

    if info.get('ports'):
        print(f"{indent}[端口]")
        for port in info['ports']:
            print(f"{indent}  - {port}")

    if info.get('task_ids'):
        print(f"{indent}[任务标识]")
        for tid in info['task_ids']:
            print(f"{indent}  - {tid}")

    if info.get('beacon_templates'):
        print(f"{indent}[模板]")
        for tmpl in info['beacon_templates']:
            print(f"{indent}  - beacon|{'|'.join(tmpl)}")

    if info.get('urls'):
        print(f"{indent}[URL]")
        for url in info['urls']:
            print(f"{indent}  - {url}")

    if info.get('domains'):
        print(f"{indent}[域名]")
        for domain in info['domains']:
            print(f"{indent}  - {domain}")

    if info.get('protocols'):
        print(f"{indent}[协议]")
        for proto in info['protocols']:
            print(f"{indent}  - {proto}")

    if info.get('config_keywords'):
        print(f"{indent}[配置关键字]")
        for kw in info['config_keywords'][:20]:
            print(f"{indent}  - {kw['keyword']:<16} = {kw['value']}")


def print_report(merged: dict):
    """打印最终分析报告"""
    print(f"\n{'='*60}")
    print(f"  CTF 控制软件配置提取报告 v2")
    print(f"{'='*60}")

    if not any([merged.get('ip_addresses'), merged.get('ports'),
                merged.get('task_ids'), merged.get('urls'),
                merged.get('beacon_templates')]):
        print("\n  [-] 未找到通信配置信息")
        print(f"\n  尝试的解密方法:")
        for m in merged.get('methods', []):
            print(f"    - {m}")
        print(f"\n  建议:")
        print(f"    1. 使用 --verbose 查看详细扫描过程")
        print(f"    2. 使用 --rc4-key <hex> 手动指定密钥")
        print(f"    3. 安装 capstone: pip install capstone")
        print(f"    4. 可能是自定义加密，需要手工逆向分析")
        print(f"    5. 参考 Reverse/knowledge/ 下的分析文档")
        print(f"\n{'='*60}")
        return

    # 核心信息
    print(f"\n  [核心发现]")
    if merged.get('ip_addresses'):
        print(f"  通信IP:")
        for ip in merged['ip_addresses']:
            print(f"    -> {ip}")
    if merged.get('ports'):
        print(f"  端口:")
        for port in merged['ports']:
            print(f"    -> {port}")
    if merged.get('task_ids'):
        print(f"  任务标识:")
        for tid in merged['task_ids']:
            print(f"    -> {tid}")
    if merged.get('beacon_templates'):
        # 只显示前 5 个模板，过滤含乱码的
        clean_templates = []
        for tmpl in merged['beacon_templates']:
            tmpl_str = '|'.join(str(t) for t in tmpl)
            # 过滤乱码模板：参数中不含连续3个以上不可读字符
            if all(all(0x20 <= ord(c) <= 0x7e for c in str(t)) for t in tmpl):
                clean_templates.append(tmpl_str)
                if len(clean_templates) >= 5:
                    break
        if clean_templates:
            print(f"  模板:")
            for ts in clean_templates:
                print(f"    -> beacon|{ts}")
        else:
            print(f"  模板: (含格式化字符串模板 beacon|%s|%s|%s)")

    # 次要信息
    if merged.get('urls'):
        print(f"\n  [URL]")
        for url in merged['urls']:
            print(f"    -> {url}")
    # 域名（过滤明显的乱码，只显示前 10 个）
    if merged.get('domains'):
        clean_domains = [d for d in merged['domains']
                         if all(0x20 <= ord(c) <= 0x7e for c in d) and len(d) >= 3]
        if clean_domains:
            print(f"\n  [域名]")
            for domain in clean_domains[:10]:
                print(f"    -> {domain}")
    if merged.get('protocols'):
        print(f"\n  [协议]")
        for proto in merged['protocols']:
            print(f"    -> {proto}")

    # 配置关键字（只显示前 15 个，过滤乱码值）
    if merged.get('config_keywords'):
        clean_kws = [kw for kw in merged['config_keywords']
                     if all(0x20 <= ord(c) <= 0x7e for c in kw['value'])]
        if clean_kws:
            print(f"\n  [配置关键字]")
            for kw in clean_kws[:15]:
                print(f"    {kw['keyword']:<16} = {kw['value']}")

    # 解密方法（只显示前 20 个，去重）
    print(f"\n  [有效解密方法]")
    seen_methods = set()
    shown = 0
    for m in merged.get('methods', []):
        if m not in seen_methods:
            seen_methods.add(m)
            print(f"    - {m}")
            shown += 1
            if shown >= 20:
                print(f"    ... (共 {len(merged.get('methods', []))} 个)")
                break

    # 详细结果（只显示前 5 个高质量结果）
    all_results = merged.get('all_results', [])
    # 优先显示含 IP 和 TASK 的结果
    priority_results = [r for r in all_results
                        if r['info'].get('ip_addresses') or r['info'].get('task_ids')]
    other_results = [r for r in all_results
                     if r not in priority_results]
    show_results = (priority_results + other_results)[:5]
    if show_results:
        print(f"\n  [详细结果] (前 {len(show_results)} 个)")
        for r in show_results:
            print(f"    Region: {r.get('region', '?')}")
            print(f"    Method: {r['method']}")
            if r['info'].get('ip_addresses'):
                print(f"    IPs: {r['info']['ip_addresses']}")
            if r['info'].get('ports'):
                print(f"    Ports: {r['info']['ports']}")
            if r['info'].get('task_ids'):
                print(f"    Tasks: {r['info']['task_ids']}")

    print(f"\n{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF 控制软件配置提取器 v2 — 智能密钥定位 + 暴力降级',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s sample.elf                    # 自动分析（智能 + 暴力）
  %(prog)s sample.elf --verbose          # 详细输出
  %(prog)s sample.elf --smart-only       # 仅智能模式（快速）
  %(prog)s sample.elf --rc4-key 6b6579   # 指定RC4密钥
  %(prog)s sample.exe --verbose          # PE文件分析
""")
    parser.add_argument('file', help='二进制样本文件路径')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出模式')
    parser.add_argument('--rc4-key', help='手动指定 RC4 密钥 (hex 格式)')
    parser.add_argument('--smart-only', action='store_true',
                        help='仅使用智能密钥定位，跳过暴力穷举')

    args = parser.parse_args()

    merged = analyze_binary(args.file, verbose=args.verbose,
                           rc4_key_hex=args.rc4_key,
                           smart_only=args.smart_only)
    print_report(merged)


if __name__ == '__main__':
    main()
