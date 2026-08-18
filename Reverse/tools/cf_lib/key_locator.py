#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — 密钥位置启发式定位
====================================

基于常量命中位置和反汇编交叉引用，启发式定位可能的密钥位置。

策略层次：
1. 常量邻近区域：密钥通常与算法常量放在同一 .rodata/.data 段
2. 交叉引用邻近：引用算法常量的函数中，其他引用的数据可能是密钥
3. 结构推断：AES S-box 后面常跟 Rcon→Key，TEA delta 前常放 16 字节 key
4. 熵分析：高熵数据块（非 ASCII、非零）可能是密钥

作者：CTF 解题笔记本项目
版本：1.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import struct

from .binary_parser import BinaryInfo, SectionInfo
from .scanner import ScanHit, AlgorithmResult
from .disasm import XrefResult, FunctionInfo


@dataclass
class KeyCandidate:
    """密钥候选"""
    file_offset: int
    virtual_address: int
    section_name: str
    size: int                # 密钥长度
    data_hex: str            # 密钥数据 hex
    data_ascii: str          # 密钥数据 ASCII 可读部分
    confidence: str          # 'high' / 'medium' / 'low'
    source: str              # 推断来源描述
    algorithm: str           # 可能使用的算法
    referenced_by: list[str] = field(default_factory=list)  # 引用此地址的指令描述


# 算法 → 标准密钥长度（字节）
ALGO_KEY_SIZES = {
    'AES': [16, 24, 32],        # AES-128/192/256
    'DES': [8],                  # DES 56-bit + 8 parity
    '3DES': [24],                # 3DES 3×8
    'Blowfish': [16, 20, 24, 32, 48, 56],  # 4-56 bytes
    'TEA/XTEA/XXTEA': [16],     # 4×32-bit
    'RC5/RC6': [16, 24, 32],
    'CAST5/CAST-128': [16],
    'ChaCha20': [32],           # 256-bit key
    'Salsa20': [32],
    'SM4': [16],
    'Camellia': [16, 24, 32],
    'SEED': [16],
    'Twofish': [16, 24, 32],
    'RC4': [1, 5, 8, 16, 32, 48, 64, 128, 256],  # variable
    'CRC32': [4],                # poly as key
    'MD5': [],                   # hash, no key
    'SHA-1': [],
    'SHA-256': [],
    'SHA-512': [],
    'SHA-384': [],
    'SHA-224': [],
    'SM3': [],
    'RIPEMD-160': [],
    'Whirlpool': [],
    'HMAC': [16, 20, 32, 64],  # depends on inner hash
}


def _is_printable(data: bytes) -> bool:
    """判断数据是否为可打印 ASCII"""
    return all(0x20 <= b <= 0x7e for b in data)


def _hex_dump(data: bytes, max_len: int = 64) -> str:
    """生成 hex 字符串"""
    return data[:max_len].hex()


def _ascii_repr(data: bytes, max_len: int = 64) -> str:
    """生成 ASCII 可读表示"""
    return ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in data[:max_len])


def _check_key_sizes(algo: str, size: int) -> bool:
    """检查给定大小是否为算法的标准密钥长度"""
    sizes = ALGO_KEY_SIZES.get(algo, [])
    if not sizes:
        return False
    return size in sizes


def locate_keys_near_constants(binary_info: BinaryInfo,
                               algo_results: list[AlgorithmResult]) -> list[KeyCandidate]:
    """策略 1：在算法常量命中点附近搜索密钥

    编译器通常将密钥和算法常量放在同一数据段（.rodata 或 .data）。
    在常量命中位置的前后 N 字节范围内搜索看起来像密钥的数据。

    Args:
        binary_info: 二进制信息
        algo_results: 算法检测结果

    Returns:
        密钥候选列表
    """
    candidates: list[KeyCandidate] = []
    raw = binary_info.raw_data

    for result in algo_results:
        algo = result.algo
        key_sizes = ALGO_KEY_SIZES.get(algo, [])

        # 无密钥算法跳过
        if not key_sizes:
            continue

        for hit in result.hits:
            # 在常量位置前后 ±256 字节范围搜索
            search_start = max(0, hit.file_offset - 256)
            search_end = min(len(raw), hit.file_offset + hit.signature.length + 256)

            section = binary_info.get_section_at_offset(hit.file_offset)
            if not section:
                continue

            # 对每个标准密钥长度，检查常量前后是否有对应大小的数据块
            for ksize in key_sizes:
                # 检查常量前 ksize 字节
                if hit.file_offset - ksize >= section.offset:
                    key_off = hit.file_offset - ksize
                    key_data = raw[key_off:key_off + ksize]
                    if _is_likely_key(key_data, algo):
                        va = binary_info.offset_to_va(key_off) or 0
                        candidates.append(KeyCandidate(
                            file_offset=key_off,
                            virtual_address=va,
                            section_name=section.name,
                            size=ksize,
                            data_hex=_hex_dump(key_data, ksize),
                            data_ascii=_ascii_repr(key_data, ksize),
                            confidence='medium',
                            source=f'常量 {algo}/{hit.signature.component} 前 {ksize} 字节',
                            algorithm=algo,
                        ))

                # 检查常量后 ksize 字节
                after_off = hit.file_offset + hit.signature.length
                if after_off + ksize < section.offset + section.size:
                    key_data = raw[after_off:after_off + ksize]
                    if _is_likely_key(key_data, algo):
                        va = binary_info.offset_to_va(after_off) or 0
                        candidates.append(KeyCandidate(
                            file_offset=after_off,
                            virtual_address=va,
                            section_name=section.name,
                            size=ksize,
                            data_hex=_hex_dump(key_data, ksize),
                            data_ascii=_ascii_repr(key_data, ksize),
                            confidence='medium',
                            source=f'常量 {algo}/{hit.signature.component} 后 {ksize} 字节',
                            algorithm=algo,
                        ))

                # 检查常量紧接着的同段区域（常见模式：S-box | Inv S-box | Rcon | Key）
                # 对 AES 特别有效
                if algo == 'AES' and hit.signature.component == 'Inverse S-box':
                    after_inv = hit.file_offset + 256  # inv sbox is 256 bytes
                    if after_inv + ksize < section.offset + section.size:
                        key_data = raw[after_inv:after_inv + ksize]
                        if _is_likely_key(key_data, algo):
                            va = binary_info.offset_to_va(after_inv) or 0
                            candidates.append(KeyCandidate(
                                file_offset=after_inv,
                                virtual_address=va,
                                section_name=section.name,
                                size=ksize,
                                data_hex=_hex_dump(key_data, ksize),
                                data_ascii=_ascii_repr(key_data, ksize),
                                confidence='high',
                                source='AES Inv S-box 后（S-box|InvS-box|Rcon|Key 布局模式）',
                                algorithm='AES',
                            ))

    return candidates


def locate_keys_from_xrefs(binary_info: BinaryInfo,
                           xrefs: list[XrefResult],
                           algo_results: list[AlgorithmResult]) -> list[KeyCandidate]:
    """策略 2：通过交叉引用定位密钥

    如果一个函数同时引用了算法常量和另一个数据地址，
    那个数据地址很可能是密钥或明文/密文。

    Args:
        binary_info: 二进制信息
        xrefs: 交叉引用结果
        algo_results: 算法检测结果

    Returns:
        密钥候选列表
    """
    candidates: list[KeyCandidate] = []
    raw = binary_info.raw_data

    # 按函数地址分组交叉引用
    # 假设同一个函数内的 xref 在地址上相近
    crypto_xrefs = [x for x in xrefs if x.referenced_algo]

    if not crypto_xrefs:
        return []

    # 按代码地址排序
    crypto_xrefs.sort(key=lambda x: x.code_va)

    # 找到同函数内引用的其他数据地址
    # 简单方法：在同一函数范围内（±0x200 字节代码），搜索非密码常量的引用
    for i, xref in enumerate(crypto_xrefs):
        algo = xref.referenced_algo
        key_sizes = ALGO_KEY_SIZES.get(algo, [])
        if not key_sizes:
            continue

        # 寻找附近代码中的其他数据引用
        for j, other_xref in enumerate(crypto_xrefs):
            if i == j:
                continue
            # 同一函数范围内的其他 xref
            if abs(other_xref.code_va - xref.code_va) < 0x200:
                # 如果 other_xref 引用了一个不在密码常量列表中的地址
                other_va = other_xref.target_va
                other_off = binary_info.va_to_offset(other_va)
                if other_off is None:
                    continue

                # 检查是否在数据段
                section = binary_info.get_section_at_offset(other_off)
                if not section or section.is_executable:
                    continue

                # 对每个标准密钥长度，尝试读取
                for ksize in key_sizes:
                    if other_off + ksize > len(raw):
                        continue
                    key_data = raw[other_off:other_off + ksize]
                    if _is_likely_key(key_data, algo):
                        va = binary_info.offset_to_va(other_off) or other_va
                        candidates.append(KeyCandidate(
                            file_offset=other_off,
                            virtual_address=va,
                            section_name=section.name,
                            size=ksize,
                            data_hex=_hex_dump(key_data, ksize),
                            data_ascii=_ascii_repr(key_data, ksize),
                            confidence='high',
                            source=f'与 {algo} 常量同一函数中被引用的数据',
                            algorithm=algo,
                            referenced_by=[other_xref.instruction],
                        ))
                        break  # 每个地址只报告一个最可能的大小

    return candidates


def locate_keys_from_structure(binary_info: BinaryInfo,
                               algo_results: list[AlgorithmResult]) -> list[KeyCandidate]:
    """策略 3：基于算法数据结构推断密钥位置

    已知模式：
    - AES: S-box(256) → Inv S-box(256) → Rcon(10) → [可能密钥 16/24/32 字节]
    - TEA: Key(16) → Delta(4) 常出现在代码段
    - Blowfish: P-array(72) → S-box0(1024) → S-box1 → S-box2 → S-box3
    - SM4: S-box(256) → FK(16) → CK(128)
    """
    candidates: list[KeyCandidate] = []
    raw = binary_info.raw_data

    for result in algo_results:
        algo = result.algo
        hits = sorted(result.hits, key=lambda h: h.file_offset)

        # AES: S-box + Inv S-box 连续布局
        if algo == 'AES':
            sbox_hits = [h for h in hits if h.signature.component == 'S-box']
            inv_sbox_hits = [h for h in hits if h.signature.component == 'Inverse S-box']
            rcon_hits = [h for h in hits if h.signature.component == 'Rcon']

            for sbox in sbox_hits:
                # S-box(256) + Inv S-box(256) = 512
                expected_inv = sbox.file_offset + 256
                for inv in inv_sbox_hits:
                    if abs(inv.file_offset - expected_inv) <= 4:
                        # 找到 S-box + Inv S-box 连续布局
                        # Rcon 和 Key 可能在后面
                        after_inv = inv.file_offset + 256
                        rcon_found = False
                        for rcon in rcon_hits:
                            if abs(rcon.file_offset - after_inv) <= 16:
                                after_inv = rcon.file_offset + 16  # Rcon is ~10 bytes
                                rcon_found = True
                                break

                        # 在 after_inv 位置搜索密钥
                        section = binary_info.get_section_at_offset(after_inv)
                        if section and after_inv + 32 <= section.offset + section.size:
                            for ksize in [16, 24, 32]:
                                key_data = raw[after_inv:after_inv + ksize]
                                if _is_likely_key(key_data, 'AES'):
                                    va = binary_info.offset_to_va(after_inv) or 0
                                    candidates.append(KeyCandidate(
                                        file_offset=after_inv,
                                        virtual_address=va,
                                        section_name=section.name,
                                        size=ksize,
                                        data_hex=_hex_dump(key_data, ksize),
                                        data_ascii=_ascii_repr(key_data, ksize),
                                        confidence='high',
                                        source='AES 标准数据布局 (S-box→InvS-box→Rcon→Key)',
                                        algorithm='AES',
                                    ))
                                    break

        # Blowfish: P-array + S-box 连续布局
        if algo == 'Blowfish':
            p_hits = [h for h in hits if 'P-array' in h.signature.component]
            s_hits = [h for h in hits if 'S-box' in h.signature.component]

            for p in p_hits:
                # P-array: 18 × 4 = 72 bytes, S-box0: 256 × 4 = 1024 bytes
                expected_s0 = p.file_offset + 72
                for s in s_hits:
                    if abs(s.file_offset - expected_s0) <= 16:
                        # 密钥可能在 P-array 前
                        if p.file_offset - 56 >= 0:
                            for ksize in [16, 24, 32, 48, 56]:
                                key_off = p.file_offset - ksize
                                key_data = raw[key_off:key_off + ksize]
                                if _is_likely_key(key_data, 'Blowfish'):
                                    va = binary_info.offset_to_va(key_off) or 0
                                    section = binary_info.get_section_at_offset(key_off)
                                    if section:
                                        candidates.append(KeyCandidate(
                                            file_offset=key_off,
                                            virtual_address=va,
                                            section_name=section.name,
                                            size=ksize,
                                            data_hex=_hex_dump(key_data, ksize),
                                            data_ascii=_ascii_repr(key_data, ksize),
                                            confidence='medium',
                                            source='Blowfish 标准布局 (Key→P-array→S-boxes)',
                                            algorithm='Blowfish',
                                        ))
                                        break

    return candidates


def _is_likely_key(data: bytes, algo: str) -> bool:
    """判断数据块是否可能是密钥

    启发式规则：
    1. 不全为零
    2. 不全为同一个字节
    3. 如果是 ASCII 可读的，可能是一个字符串密钥
    4. 如果是高熵的，可能是随机密钥
    5. 全部字节中有足够多的非零字节
    """
    if not data:
        return False

    non_zero = sum(1 for b in data if b != 0)
    if non_zero < len(data) * 0.5:
        return False

    # 不全是同一种字节
    unique = len(set(data))
    if unique < 2:
        return False

    # 可打印 ASCII 字符串也是有效密钥
    if _is_printable(data):
        return True

    # 高熵（非 ASCII 但多变）
    if unique >= len(data) * 0.4:
        return True

    # 至少有 3 种不同字节
    if unique >= 3:
        return True

    return False


def deduplicate_candidates(candidates: list[KeyCandidate]) -> list[KeyCandidate]:
    """去重 + 合并密钥候选

    同一地址、同一大小的候选合并，保留置信度更高的
    """
    seen: dict[tuple[int, int], KeyCandidate] = {}

    for cand in candidates:
        key = (cand.file_offset, cand.size)
        if key in seen:
            existing = seen[key]
            # 保留高置信度的
            conf_order = {'high': 0, 'medium': 1, 'low': 2}
            if conf_order.get(cand.confidence, 3) < conf_order.get(existing.confidence, 3):
                seen[key] = cand
        else:
            seen[key] = cand

    return sorted(seen.values(), key=lambda c: c.file_offset)


def locate_all_keys(binary_info: BinaryInfo,
                    algo_results: list[AlgorithmResult],
                    xrefs: list[XrefResult]) -> list[KeyCandidate]:
    """执行所有密钥定位策略

    Args:
        binary_info: 二进制信息
        algo_results: 算法检测结果
        xrefs: 交叉引用结果

    Returns:
        去重后的密钥候选列表
    """
    all_candidates: list[KeyCandidate] = []

    # 策略 1：常量邻近区域
    all_candidates.extend(locate_keys_near_constants(binary_info, algo_results))

    # 策略 2：交叉引用关联
    all_candidates.extend(locate_keys_from_xrefs(binary_info, xrefs, algo_results))

    # 策略 3：结构推断
    all_candidates.extend(locate_keys_from_structure(binary_info, algo_results))

    return deduplicate_candidates(all_candidates)
