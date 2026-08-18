#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — Capstone 反汇编分析层
======================================

使用 Capstone 反汇编可执行段，实现以下功能：
1. 交叉引用分析：找到引用密码常量的代码位置
2. RC4 KSA 循环模式识别
3. 异或加密循环识别
4. 函数边界识别（便于定位密钥传参）

依赖：capstone

作者：CTF 解题笔记本项目
版本：1.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import struct

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_ARCH_ARM, CS_ARCH_MIPS, \
    CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN

from .binary_parser import BinaryInfo, SectionInfo
from .scanner import ScanHit


@dataclass
class XrefResult:
    """交叉引用结果"""
    code_offset: int          # 代码文件偏移
    code_va: int              # 代码虚拟地址
    target_offset: int        # 引用的数据偏移（常量位置）
    target_va: int            # 引用的数据虚拟地址
    instruction: str          # 反汇编文本
    mnemonic: str             # 助记符
    section_name: str         # 代码所在段名
    referenced_algo: str      # 被引用的算法名
    referenced_component: str # 被引用的组件名


@dataclass
class LoopPattern:
    """循环模式检测结果"""
    pattern_type: str         # 'rc4_ksa' / 'xor_loop' / 'shift_loop'
    code_offset: int          # 代码文件偏移
    code_va: int              # 代码虚拟地址
    section_name: str         # 代码所在段名
    description: str          # 描述
    confidence: str           # 'high' / 'medium' / 'low'
    loop_count: int = 0       # 循环次数（如 256）
    key_candidate: Optional[dict] = None  # 可能的密钥信息


@dataclass
class FunctionInfo:
    """函数信息"""
    start_offset: int
    start_va: int
    end_offset: int
    end_va: int
    name: str
    xrefs_to_data: list[XrefResult] = field(default_factory=list)


def _get_capstone_for_binary(binary_info: BinaryInfo) -> Optional[Cs]:
    """根据二进制信息创建对应的 Capstone 反汇编器"""
    arch = binary_info.arch
    endian = binary_info.endianness

    if arch == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'x64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 'arm':
        mode = CS_MODE_ARM
        if endian == 'big':
            mode |= CS_MODE_BIG_ENDIAN
        else:
            mode |= CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM, mode)
    elif arch == 'arm64':
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == 'mips':
        mode = CS_MODE_32
        if endian == 'big':
            mode |= CS_MODE_BIG_ENDIAN
        else:
            mode |= CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_MIPS, mode)
    else:
        return None

    md.detail = True
    return md


def _extract_memory_ref(insn) -> Optional[int]:
    """从 Capstone 指令中提取内存引用地址（用于 lea/mov 等指令）

    返回被引用的绝对地址（虚拟地址），如果没有内存引用则返回 None
    """
    try:
        for op in insn.operands:
            if op.type == capstone_op_mem:  # X86_OP_MEM
                # 直接内存引用 [disp]
                if op.mem.base == 0 and op.mem.index == 0:
                    return op.mem.disp
                # RIP-relative [rip + disp]
                if op.mem.base != 0:
                    # 检查是否为 RIP-relative (x86-64)
                    # base register is RIP (register id depends on capstone)
                    pass
    except Exception:
        pass

    # Fallback: parse op_str for hex addresses
    # This is less reliable but catches cases where detail mode doesn't expose it
    try:
        import re
        # Match patterns like 0x404030 or [0x404030]
        matches = re.findall(r'0x([0-9a-fA-F]+)', insn.op_str)
        if matches:
            val = int(matches[0], 16)
            # Filter to plausible VAs (not small immediates)
            if val > 0x1000:
                return val
    except Exception:
        pass

    return None


# Try to import capstone constants for operand type checking
try:
    from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
    _HAS_X86_CONSTS = True
except ImportError:
    _HAS_X86_CONSTS = False


def _extract_x86_refs(insn, md_mode_64: bool) -> list[int]:
    """从 x86/x64 指令中提取所有内存引用地址

    Returns:
        被引用的虚拟地址列表
    """
    refs = []

    if not _HAS_X86_CONSTS:
        # Fallback：正则解析
        import re
        for m in re.finditer(r'0x([0-9a-fA-F]+)', insn.op_str):
            val = int(m.group(1), 16)
            if val > 0x1000:
                refs.append(val)
        return refs

    try:
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                # Direct memory reference [disp]
                if op.mem.base == 0 and op.mem.index == 0:
                    refs.append(op.mem.disp)
                # RIP-relative: [rip + disp]
                elif md_mode_64 and op.mem.base == X86_REG_RIP:
                    rip_val = insn.address + insn.size
                    refs.append(rip_val + op.mem.disp)
                # Other base registers with displacement — could be table lookup
                elif op.mem.disp != 0 and op.mem.base != 0 and op.mem.index == 0:
                    # Can't resolve without register value, skip
                    pass
            elif op.type == X86_OP_IMM:
                # Immediate value that looks like an address
                if op.imm > 0x1000:
                    refs.append(op.imm)
    except Exception:
        pass

    return refs


def find_xrefs_to_hits(binary_info: BinaryInfo, hits: list[ScanHit],
                       scan_range: int = 0x100000) -> list[XrefResult]:
    """在可执行段中搜索引用了密码常量地址的指令

    Args:
        binary_info: 二进制信息
        hits: 常量扫描命中列表
        scan_range: 在每个段中扫描的最大字节数（防止超大段超时）

    Returns:
        交叉引用结果列表
    """
    md = _get_capstone_for_binary(binary_info)
    if md is None:
        return []

    is_x64 = binary_info.arch == 'x64'

    # 建立 VA → hit 的映射，便于快速查找
    hit_by_va: dict[int, ScanHit] = {}
    for hit in hits:
        if hit.virtual_address > 0:
            hit_by_va[hit.virtual_address] = hit
            # 也记录常量区域的范围内的地址（常量可能从中间引用）
            for delta in range(0, hit.signature.length, 4):
                hit_by_va[hit.virtual_address + delta] = hit

    xref_results: list[XrefResult] = []

    for section in binary_info.get_executable_sections():
        section_data = binary_info.raw_data[section.offset:section.offset + min(section.size, scan_range)]

        for insn in md.disasm(section_data, section.virtual_address):
            if is_x64:
                refs = _extract_x86_refs(insn, True)
            else:
                refs = _extract_x86_refs(insn, False)

            for ref_va in refs:
                if ref_va in hit_by_va:
                    hit = hit_by_va[ref_va]
                    xref_results.append(XrefResult(
                        code_offset=insn.address - section.virtual_address + section.offset,
                        code_va=insn.address,
                        target_offset=hit.file_offset,
                        target_va=hit.virtual_address,
                        instruction=f'{insn.mnemonic} {insn.op_str}',
                        mnemonic=insn.mnemonic,
                        section_name=section.name,
                        referenced_algo=hit.signature.algo,
                        referenced_component=hit.signature.component,
                    ))

    return xref_results


def detect_rc4_ksa_pattern(binary_info: BinaryInfo,
                           scan_range: int = 0x100000) -> list[LoopPattern]:
    """检测 RC4 KSA 初始化循环模式

    RC4 KSA 的汇编特征：
    - 初始化：把 0..255 写入 256 字节数组
      类似: mov dword [rax], 0x03020100 ; mov dword [rax+4], 0x07060504 ...
      或循环: mov byte [rcx+rax], al ; inc al ; cmp al, 0x100 ; jne

    - KSA 循环：
      movzx ecx, byte [rax+rdx]     ; S[i]
      add ecx, [rsp+key_idx]         ; + key[i % keylen]
      add ecx, edx                   ; + j
      and ecx, 0xff
      mov [rax+rdx], cl              ; (or via temp)
      inc rdx
      cmp rdx, 0x100
      jne loop
    """
    md = _get_capstone_for_binary(binary_info)
    if md is None:
        return []

    patterns: list[LoopPattern] = []

    for section in binary_info.get_executable_sections():
        section_data = binary_info.raw_data[section.offset:section.offset + min(section.size, scan_range)]

        # 策略 1: 搜索 "cmp ?, 0x100" 指令附近有 byte swap 的模式
        # Capstone 反汇编并寻找 0x100 比较指令
        instructions = list(md.disasm(section_data, section.virtual_address))

        for i, insn in enumerate(instructions):
            # 寻找 cmp 指令与 0x100 (256) 的比较
            if insn.mnemonic == 'cmp':
                # 检查操作数是否含 0x100
                if '0x100' in insn.op_str:
                    # 向前回溯 20 条指令，找 byte swap / xor / array access
                    start = max(0, i - 20)
                    window = instructions[start:i + 1]

                    has_xor = False
                    has_array_access = False
                    has_inc = False

                    for w in window:
                        if w.mnemonic == 'xor':
                            has_xor = True
                        if w.mnemonic in ('movzx', 'mov') and ('+' in w.op_str or '[' in w.op_str):
                            has_array_access = True
                        if w.mnemonic == 'inc':
                            has_inc = True

                    if has_array_access and has_inc:
                        confidence = 'medium'
                        if has_xor:
                            confidence = 'high'

                        patterns.append(LoopPattern(
                            pattern_type='rc4_ksa',
                            code_offset=insn.address - section.virtual_address + section.offset,
                            code_va=insn.address,
                            section_name=section.name,
                            description=f'RC4 KSA 循环模式 (cmp 0x100 + 数组访问 + inc + xor={has_xor})',
                            confidence=confidence,
                            loop_count=256,
                        ))

        # 策略 2: 搜索 "0xff" AND 操作（RC4 中常见 and ?, 0xff）
        for i, insn in enumerate(instructions):
            if insn.mnemonic == 'and' and '0xff' in insn.op_str:
                # 回溯检查附近是否有数组访问和 0x100 比较
                start = max(0, i - 15)
                end = min(len(instructions), i + 15)
                window = instructions[start:end]

                has_cmp_256 = any(w.mnemonic == 'cmp' and '0x100' in w.op_str for w in window)
                has_array = any('[' in w.op_str for w in window)

                if has_cmp_256 and has_array:
                    # 避免重复（如果已经检测到）
                    already = any(p.code_va == insn.address for p in patterns)
                    if not already:
                        patterns.append(LoopPattern(
                            pattern_type='rc4_ksa',
                            code_offset=insn.address - section.virtual_address + section.offset,
                            code_va=insn.address,
                            section_name=section.name,
                            description='RC4 KSA 模式 (and 0xff + cmp 0x100 + 数组访问)',
                            confidence='medium',
                            loop_count=256,
                        ))

    return patterns


def detect_xor_loop_pattern(binary_info: BinaryInfo,
                            scan_range: int = 0x100000) -> list[LoopPattern]:
    """检测异或解密/加密循环

    特征：
    - xor 指令在循环内
    - 有数组和索引访问
    - 循环回跳
    """
    md = _get_capstone_for_binary(binary_info)
    if md is None:
        return []

    patterns: list[LoopPattern] = []

    for section in binary_info.get_executable_sections():
        section_data = binary_info.raw_data[section.offset:section.offset + min(section.size, scan_range)]
        instructions = list(md.disasm(section_data, section.virtual_address))

        for i, insn in enumerate(instructions):
            if insn.mnemonic != 'xor':
                continue

            # 跳过 xor reg, reg（清零指令）
            operands = insn.op_str.replace(' ', '').split(',')
            if len(operands) == 2 and operands[0] == operands[1]:
                continue

            # 向前回溯和向后搜索循环结构
            start = max(0, i - 10)
            end = min(len(instructions), i + 10)
            window = instructions[start:end]

            has_loop = False
            has_array = False
            has_inc = False

            for w in window:
                if w.mnemonic in ('jne', 'jmp', 'jl', 'jg', 'jle', 'jge', 'jb', 'ja', 'jbe', 'jae', 'loop'):
                    # 检查是否回跳（循环）
                    try:
                        target = int(w.op_str, 16) if w.op_str.startswith('0x') else None
                        if target is not None and target <= w.address:
                            has_loop = True
                    except ValueError:
                        pass
                if '[' in w.op_str:
                    has_array = True
                if w.mnemonic == 'inc':
                    has_inc = True

            if has_loop and has_array:
                confidence = 'medium'
                if has_inc:
                    confidence = 'high'

                # 避免重复
                already = any(abs(p.code_va - insn.address) < 16 for p in patterns if p.pattern_type == 'xor_loop')
                if not already:
                    patterns.append(LoopPattern(
                        pattern_type='xor_loop',
                        code_offset=insn.address - section.virtual_address + section.offset,
                        code_va=insn.address,
                        section_name=section.name,
                        description=f'异或循环 (xor + 数组访问 + 回跳 + inc={has_inc})',
                        confidence=confidence,
                        loop_count=0,
                    ))

    return patterns


def detect_function_boundaries(binary_info: BinaryInfo,
                               scan_range: int = 0x200000) -> list[FunctionInfo]:
    """检测函数边界（简单启发式：ret 指令作为函数结束）

    注意：这是粗略估计，不如 IDA 的函数分析准确。
    主要用于在没有 IDA 时提供一个近似函数列表。
    """
    md = _get_capstone_for_binary(binary_info)
    if md is None:
        return []

    functions: list[FunctionInfo] = []

    for section in binary_info.get_executable_sections():
        section_data = binary_info.raw_data[section.offset:section.offset + min(section.size, scan_range)]
        instructions = list(md.disasm(section_data, section.virtual_address))

        func_start_idx = 0
        func_start_va = section.virtual_address

        for i, insn in enumerate(instructions):
            # 函数结束标志
            if insn.mnemonic in ('ret', 'retn', 'retf'):
                func_end_va = insn.address
                if func_end_va > func_start_va:
                    functions.append(FunctionInfo(
                        start_offset=func_start_va - section.virtual_address + section.offset,
                        start_va=func_start_va,
                        end_offset=func_end_va - section.virtual_address + section.offset,
                        end_va=func_end_va,
                        name=f'sub_{func_start_va:X}',
                    ))
                # 下一个函数从这里开始
                if i + 1 < len(instructions):
                    func_start_va = instructions[i + 1].address
                    func_start_idx = i + 1

    return functions


def find_xrefs_to_address(binary_info: BinaryInfo, target_va: int,
                           scan_range: int = 0x100000) -> list[XrefResult]:
    """查找引用指定虚拟地址的所有指令

    用于定位引用特定常量的代码
    """
    md = _get_capstone_for_binary(binary_info)
    if md is None:
        return []

    is_x64 = binary_info.arch == 'x64'
    results: list[XrefResult] = []

    for section in binary_info.get_executable_sections():
        section_data = binary_info.raw_data[section.offset:section.offset + min(section.size, scan_range)]

        for insn in md.disasm(section_data, section.virtual_address):
            refs = _extract_x86_refs(insn, is_x64)
            for ref_va in refs:
                if ref_va == target_va:
                    results.append(XrefResult(
                        code_offset=insn.address - section.virtual_address + section.offset,
                        code_va=insn.address,
                        target_offset=binary_info.va_to_offset(target_va) or 0,
                        target_va=target_va,
                        instruction=f'{insn.mnemonic} {insn.op_str}',
                        mnemonic=insn.mnemonic,
                        section_name=section.name,
                        referenced_algo='',
                        referenced_component='',
                    ))

    return results
