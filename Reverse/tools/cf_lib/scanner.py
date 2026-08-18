#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — 常量扫描引擎
==============================

在二进制文件中搜索密码算法的常量签名。
支持对齐约束过滤、多偏移报告、算法聚合。

作者：CTF 解题笔记本项目
版本：1.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .signatures import CryptoSignature, SIGNATURES, ALGORITHM_INDEX
from .binary_parser import BinaryInfo, SectionInfo


@dataclass
class ScanHit:
    """单次签名命中"""
    signature: CryptoSignature
    file_offset: int           # 文件偏移
    virtual_address: int       # 虚拟地址（0 如果无法映射）
    section_name: str          # 所在段名
    section_type: str          # 段类型
    alignment_ok: bool         # 是否满足对齐约束


@dataclass
class AlgorithmResult:
    """一个算法的聚合检测结果"""
    algo: str
    hits: list[ScanHit] = field(default_factory=list)
    components_found: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        """根据命中数量和置信度计算总体置信度"""
        if not self.hits:
            return 'none'
        high_count = sum(1 for h in self.hits if h.signature.confidence == 'high')
        if high_count >= 2:
            return 'very-high'
        if high_count == 1:
            return 'high'
        if any(h.signature.confidence == 'medium' for h in self.hits):
            return 'medium'
        return 'low'

    @property
    def first_offset(self) -> int:
        return min(h.file_offset for h in self.hits) if self.hits else 0


def _check_alignment(offset: int, alignment: int) -> bool:
    """检查偏移是否满足对齐要求"""
    if alignment <= 1:
        return True
    return offset % alignment == 0


def _scan_for_pattern(data: bytes, pattern: bytes, alignment: int = 1) -> list[int]:
    """在数据中搜索 pattern 的所有出现位置

    Args:
        data: 被搜索的字节流
        pattern: 要搜索的模式
        alignment: 对齐约束（1=任意偏移，2/4/8=对齐到 2/4/8 字节）

    Returns:
        所有命中偏移的列表
    """
    if not pattern or len(pattern) < 4:
        return []

    hits = []
    start = 0

    if alignment <= 1:
        # 无对齐约束，直接搜索所有位置
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            hits.append(pos)
            start = pos + 1
    else:
        # 有对齐约束，只在对齐位置搜索
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            if pos % alignment == 0:
                hits.append(pos)
            start = pos + 1

    return hits


def scan_binary(binary_info: BinaryInfo) -> list[ScanHit]:
    """扫描整个二进制文件，返回所有签名命中

    Args:
        binary_info: 已解析的二进制信息

    Returns:
        所有命中结果的列表，按文件偏移排序
    """
    all_hits: list[ScanHit] = []
    raw = binary_info.raw_data

    for sig in SIGNATURES:
        if len(sig.pattern) < 4:
            continue

        offsets = _scan_for_pattern(raw, sig.pattern, sig.alignment)

        for off in offsets:
            # 映射到虚拟地址
            va = binary_info.offset_to_va(off) or 0

            # 获取段信息
            section = binary_info.get_section_at_offset(off)
            section_name = section.name if section else 'unknown'
            section_type = section.type if section else 'unknown'

            # 检查对齐
            align_ok = _check_alignment(off, sig.alignment)

            all_hits.append(ScanHit(
                signature=sig,
                file_offset=off,
                virtual_address=va,
                section_name=section_name,
                section_type=section_type,
                alignment_ok=align_ok,
            ))

    # 按文件偏移排序
    all_hits.sort(key=lambda h: h.file_offset)
    return all_hits


def aggregate_by_algorithm(hits: list[ScanHit]) -> list[AlgorithmResult]:
    """将命中结果按算法聚合

    Args:
        hits: 所有扫描命中

    Returns:
        按置信度降序排列的算法结果列表
    """
    algo_map: dict[str, AlgorithmResult] = {}

    for hit in hits:
        algo = hit.signature.algo
        if algo not in algo_map:
            algo_map[algo] = AlgorithmResult(algo=algo)
        algo_map[algo].hits.append(hit)
        if hit.signature.component not in algo_map[algo].components_found:
            algo_map[algo].components_found.append(hit.signature.component)

    results = list(algo_map.values())

    # 排序：先按置信度，再按首次偏移
    confidence_order = {'very-high': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}
    results.sort(key=lambda r: (confidence_order.get(r.confidence, 5), r.first_offset))

    return results


def scan_section(binary_info: BinaryInfo, section: SectionInfo) -> list[ScanHit]:
    """扫描指定段，返回该段内的签名命中

    用于需要分段扫描的场景（如只扫描 .rodata）
    """
    raw = binary_info.raw_data
    section_data = raw[section.offset:section.offset + section.size]

    all_hits: list[ScanHit] = []

    for sig in SIGNATURES:
        if len(sig.pattern) < 4:
            continue

        offsets = _scan_for_pattern(section_data, sig.pattern, sig.alignment)

        for rel_off in offsets:
            abs_off = section.offset + rel_off
            va = section.virtual_address + rel_off
            align_ok = _check_alignment(abs_off, sig.alignment)

            all_hits.append(ScanHit(
                signature=sig,
                file_offset=abs_off,
                virtual_address=va,
                section_name=section.name,
                section_type=section.type,
                alignment_ok=align_ok,
            ))

    all_hits.sort(key=lambda h: h.file_offset)
    return all_hits


def scan_for_rc4_ksa(binary_info: BinaryInfo) -> list[dict]:
    """检测 RC4 KSA 初始化模式

    RC4 没有固定常量，但有特征性的 KSA 初始化：
    - 一个 256 字节的 identity 数组 (0,1,2,...,255) 出现在 .data/.bss
    - 但这可能是其他用途，仅作为弱信号

    更可靠的方法是通过反汇编检测循环模式（见 disasm.py）

    Returns:
        命中信息列表
    """
    from .signatures import RC4_IDENTITY_SBOX

    hits = []
    raw = binary_info.raw_data
    offsets = _scan_for_pattern(raw, RC4_IDENTITY_SBOX, alignment=1)

    for off in offsets:
        va = binary_info.offset_to_va(off) or 0
        section = binary_info.get_section_at_offset(off)
        hits.append({
            'type': 'rc4_ksa_identity',
            'file_offset': off,
            'virtual_address': va,
            'section': section.name if section else 'unknown',
            'note': '256 字节 identity 数组 (0,1,...,255)，可能是 RC4 KSA 初始化表',
            'confidence': 'low',  # 需要反汇编确认
        })

    return hits


def scan_for_xor_key_candidates(binary_info: BinaryInfo) -> list[dict]:
    """启发式检测可能的异或密钥

    策略：在 .rodata / .data 段中寻找小块连续字节（4-64 字节），
    周围有非零数据但本身看起来像密钥（高熵、不在 ASCII 范围内）

    这只是一个粗筛，需要结合反汇编确认

    Returns:
        候选密钥信息列表
    """
    candidates = []
    raw = binary_info.raw_data

    for section in binary_info.sections:
        if section.type not in ('rodata', 'data'):
            continue
        if section.size < 16:
            continue

        section_data = raw[section.offset:section.offset + section.size]

        # 寻找非 ASCII 高熵数据块（8-64 字节）
        i = 0
        while i < len(section_data) - 8:
            # 检查是否为非 ASCII 数据块
            byte_block = section_data[i:i+16]
            non_ascii = sum(1 for b in byte_block if b < 0x20 or b > 0x7e)
            non_zero = sum(1 for b in byte_block if b != 0)

            # 至少 10/16 是非 ASCII 且非零，可能是密钥
            if non_ascii >= 10 and non_zero >= 12:
                # 扩展到完整块
                block_start = i
                block_end = i + 16
                while block_end < len(section_data) and block_end - block_start < 64:
                    next_byte = section_data[block_end]
                    if next_byte == 0:
                        break
                    block_end += 1

                block = section_data[block_start:block_end]
                if len(block) >= 8:
                    abs_off = section.offset + block_start
                    va = section.virtual_address + block_start
                    candidates.append({
                        'type': 'xor_key_candidate',
                        'file_offset': abs_off,
                        'virtual_address': va,
                        'section': section.name,
                        'size': len(block),
                        'hex': block.hex(),
                        'confidence': 'low',
                        'note': f'高熵数据块 ({len(block)} 字节)，可能是异或密钥或加密数据',
                    })

                i = block_end + 1
            else:
                i += 1

    return candidates


# ============================================================
# 自定义编码表检测
# ============================================================

# 标准编码表（用于差异比较）
STD_BASE64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
STD_BASE64_URLSAFE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


def _is_printable_ascii(b: bytes) -> bool:
    """检查是否全部为可打印 ASCII (0x20-0x7E)"""
    return all(0x20 <= c <= 0x7E for c in b)


def _char_set_analysis(table: bytes) -> dict:
    """分析字符表的字符集构成，返回统计信息"""
    has_upper = any(0x41 <= c <= 0x5A for c in table)
    has_lower = any(0x61 <= c <= 0x7A for c in table)
    has_digit = any(0x30 <= c <= 0x39 for c in table)
    has_plus_slash = b'+' in table and b'/' in table
    has_dash_underscore = b'-' in table and b'_' in table
    unique_count = len(set(table))
    return {
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_plus_slash': has_plus_slash,
        'has_dash_underscore': has_dash_underscore,
        'unique_count': unique_count,
    }


def _compare_tables(table: bytes, std_table: bytes) -> int:
    """计算两个表之间的差异字符数"""
    diff = sum(1 for a, b in zip(table, std_table) if a != b)
    return diff


def scan_for_custom_base64_table(binary_info: BinaryInfo) -> list[dict]:
    """检测自定义 Base64/Base32/Base58 编码表

    策略：在 .rodata / .data 段中搜索连续 64 字节可打印 ASCII 序列，
    判断是否为 Base64 编码表（标准或魔改）。

    CTF 逆向题中常见魔改方式：
    - 大写字母倒序 (ZYX...VW)
    - 小写字母倒序 (zyx...vw)
    - 数字部分移位
    - 替换 +/ 为 -_ 或其他符号
    - 完全自定义排列

    Returns:
        检测结果列表，包含表内容、偏移、与标准表的差异
    """
    results = []
    raw = binary_info.raw_data
    visited_offsets = set()  # 避免重复报告

    for section in binary_info.sections:
        if section.type not in ('rodata', 'data', 'unknown'):
            continue
        if section.size < 64:
            continue

        section_data = raw[section.offset:section.offset + section.size]

        i = 0
        while i < len(section_data) - 64:
            if (section.offset + i) in visited_offsets:
                i += 1
                continue

            # 取 64 字节窗口
            window = section_data[i:i + 64]

            # 条件 1: 全部可打印 ASCII
            if not _is_printable_ascii(window):
                i += 1
                continue

            # 条件 2: 64 个字符全部唯一（编码表的必要条件）
            if len(set(window)) != 64:
                i += 1
                continue

            # 条件 3: 字符集分析——必须是字母+数字+符号的组合
            stats = _char_set_analysis(window)
            if not (stats['has_upper'] and stats['has_lower'] and stats['has_digit']):
                i += 1
                continue

            # 到这里，这 64 个唯一可打印字符很可能是编码表
            abs_off = section.offset + i
            va = section.virtual_address + i
            visited_offsets.add(abs_off)

            # 与标准 Base64 表比较
            diff_std = _compare_tables(window, STD_BASE64)
            diff_urlsafe = _compare_tables(window, STD_BASE64_URLSAFE)

            # 判断编码表类型和置信度
            if diff_std == 0:
                table_type = 'base64_standard'
                confidence = 'high'
                note = '标准 Base64 编码表'
                is_custom = False
            elif diff_urlsafe == 0:
                table_type = 'base64_urlsafe'
                confidence = 'high'
                note = 'URL-safe Base64 编码表 (+/ 替换为 -_)'
                is_custom = False
            elif diff_std <= 16:
                table_type = 'base64_custom'
                confidence = 'high'
                note = f'自定义 Base64 表（与标准表差异 {diff_std} 个字符）'
                is_custom = True
            elif diff_std <= 32:
                table_type = 'base64_custom'
                confidence = 'medium'
                note = f'自定义 Base64 表（与标准表差异 {diff_std} 个字符）'
                is_custom = True
            else:
                # 差异很大，可能是其他编码或恰好 64 个唯一可打印字符
                table_type = 'base64_suspected'
                confidence = 'low'
                note = f'疑似编码表（64 个唯一可打印字符，与标准 Base64 差异 {diff_std} 个字符）'
                is_custom = True

            result = {
                'type': 'base64_table',
                'table_type': table_type,
                'is_custom': is_custom,
                'file_offset': abs_off,
                'virtual_address': va,
                'section': section.name,
                'size': 64,
                'table_str': window.decode('ascii'),
                'table_hex': window.hex(),
                'diff_from_std64': diff_std,
                'confidence': confidence,
                'note': note,
            }
            results.append(result)

            # 跳过这个表，继续搜索
            i += 64

    return results
