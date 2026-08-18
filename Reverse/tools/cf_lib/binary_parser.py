#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — 二进制文件解析器
==================================

支持 ELF / PE / Mach-O 三种格式，提取段信息并建立虚拟地址 ↔ 文件偏移映射。

依赖：lief（统一解析三种格式）

作者：CTF 解题笔记本项目
版本：1.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import lief


@dataclass
class SectionInfo:
    """一个段/节的信息"""
    name: str
    offset: int
    size: int
    virtual_address: int
    virtual_size: int
    permissions: str
    is_executable: bool
    is_writable: bool
    is_readable: bool
    type: str


@dataclass
class BinaryInfo:
    """二进制文件的完整信息"""
    file_path: str
    file_size: int
    format: str
    arch: str
    endianness: str
    entry_point: int
    base_address: int
    sections: list[SectionInfo] = field(default_factory=list)
    raw_data: bytes = b''

    def offset_to_va(self, offset: int) -> Optional[int]:
        for sec in self.sections:
            if sec.offset <= offset < sec.offset + sec.size:
                return sec.virtual_address + (offset - sec.offset)
        return None

    def va_to_offset(self, va: int) -> Optional[int]:
        for sec in self.sections:
            if sec.virtual_address <= va < sec.virtual_address + sec.virtual_size:
                return sec.offset + (va - sec.virtual_address)
        return None

    def get_section_at_offset(self, offset: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.offset <= offset < sec.offset + sec.size:
                return sec
        return None

    def get_section_at_va(self, va: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.virtual_address <= va < sec.virtual_address + sec.virtual_size:
                return sec
        return None

    def get_executable_sections(self) -> list[SectionInfo]:
        return [s for s in self.sections if s.is_executable]

    def get_data_sections(self) -> list[SectionInfo]:
        return [s for s in self.sections if not s.is_executable and s.type != 'bss']


def _detect_section_type(name: str) -> str:
    name_lower = name.lower()
    if '.text' in name_lower or name_lower == '__text':
        return 'code'
    if '.rodata' in name_lower or '.rdata' in name_lower or name_lower == '__const':
        return 'rodata'
    if '.data' in name_lower or name_lower == '__data':
        return 'data'
    if '.bss' in name_lower or name_lower == '__bss':
        return 'bss'
    return 'unknown'


def _arch_from_machine_type(mt_str: str) -> str:
    """从 machine_type / cpu_type 字符串推断架构（ELF / Mach-O 通用）"""
    mt = mt_str.upper()
    if 'I386' in mt:
        return 'x86'
    if 'X86_64' in mt or 'AMD64' in mt:
        return 'x64'
    if 'AARCH64' in mt or 'ARM64' in mt:
        return 'arm64'
    if 'ARM' in mt:
        return 'arm'
    if 'MIPS' in mt:
        return 'mips'
    if 'PPC' in mt:
        return 'ppc'
    if 'RISCV' in mt:
        return 'riscv'
    return 'unknown'


def _arch_from_pe_header(header) -> str:
    """从 PE header 的 machine 枚举推断架构

    lief 1.0+ 的 PE header 使用 machine 属性（MACHINE_TYPES 枚举），
    而非 ELF 的 machine_type 属性。
    """
    try:
        mt_str = str(header.machine)  # e.g. 'MACHINE_TYPES.AMD64'
        return _arch_from_machine_type(mt_str)
    except Exception:
        return 'unknown'


def parse_binary(file_path: str) -> BinaryInfo:
    """解析二进制文件，返回 BinaryInfo"""
    with open(file_path, 'rb') as f:
        raw_data = f.read()

    file_size = len(raw_data)

    # 尝试用 lief 解析
    try:
        binary = lief.parse(file_path)
    except Exception:
        binary = None

    if binary is None:
        # Raw binary
        return BinaryInfo(
            file_path=file_path,
            file_size=file_size,
            format='Raw',
            arch='unknown',
            endianness='little',
            entry_point=0,
            base_address=0,
            sections=[SectionInfo(
                name='raw', offset=0, size=file_size,
                virtual_address=0, virtual_size=file_size,
                permissions='rwx', is_executable=True,
                is_writable=True, is_readable=True, type='unknown',
            )],
            raw_data=raw_data,
        )

    # 确定格式
    fmt_str = str(binary.format)
    if 'ELF' in fmt_str:
        fmt = 'ELF'
    elif 'PE' in fmt_str:
        fmt = 'PE'
    elif 'MACHO' in fmt_str:
        fmt = 'Mach-O'
    else:
        fmt = 'Unknown'

    # 架构推断
    h = binary.header
    if hasattr(h, 'machine_type'):
        # ELF / Mach-O: machine_type 属性
        arch = _arch_from_machine_type(str(h.machine_type))
    elif hasattr(h, 'machine'):
        # PE (lief 1.0+): machine 属性（MACHINE_TYPES 枚举）
        arch = _arch_from_pe_header(h)
    elif hasattr(h, 'cpu_type'):
        arch = _arch_from_machine_type(str(h.cpu_type))
    else:
        arch = 'unknown'

    # 端序
    endianness = 'little'
    if hasattr(h, 'identity_data'):
        if 'MSB' in str(h.identity_data).upper():
            endianness = 'big'
    elif hasattr(h, 'is_64bit'):
        # Mach-O: no endianness field, default little for Apple Silicon
        pass

    entry_point = binary.entrypoint
    base_address = binary.imagebase if hasattr(binary, 'imagebase') else 0

    # 提取段信息
    sections = []
    for sec in binary.sections:
        name = sec.name if sec.name else f'sec_{sec.offset:#x}'
        offset = sec.offset
        size = sec.size
        va = sec.virtual_address
        # PE 段的 virtual_address 是 RVA，需要加上 imagebase 得到绝对 VA
        # ELF/Mach-O 的 virtual_address 已包含基址，无需调整
        if fmt == 'PE':
            va += base_address
        # PE 段的 virtual_size 与 raw size 不同，用于 VA 映射应使用 virtual_size
        if fmt == 'PE' and hasattr(sec, 'virtual_size'):
            vsize = sec.virtual_size
        else:
            vsize = size  # ELF/Mach-O: size 即为虚拟大小

        sec_type = _detect_section_type(name)

        # 权限判断
        perms = 'r'
        is_exec = False
        is_write = False

        if fmt == 'ELF':
            try:
                flags = sec.flags_list
                import lief._lief.ELF as ELFMod
                if ELFMod.Section.FLAGS.EXECINSTR in flags:
                    is_exec = True
                if ELFMod.Section.FLAGS.WRITE in flags:
                    is_write = True
            except Exception:
                pass
        elif fmt == 'PE':
            try:
                # lief 1.0+ PE Section 使用 characteristics_lists（枚举列表）
                char_list = sec.characteristics_lists if hasattr(sec, 'characteristics_lists') else []
                is_exec = any('MEM_EXECUTE' in str(c) for c in char_list)
                is_write = any('MEM_WRITE' in str(c) for c in char_list)
            except Exception:
                pass
        elif fmt == 'Mach-O':
            # Mach-O: infer from section name
            name_lower = name.lower()
            if name_lower == '__text' or name_lower.startswith('__text'):
                is_exec = True
            if name_lower == '__data' or name_lower.startswith('__data'):
                is_write = True
            # Mach-O sections have flags too, but name-based is sufficient for CTF

        # Fallback: name-based
        if not is_exec and not is_write:
            name_lower = name.lower()
            if '.text' in name_lower or name_lower == '__text':
                is_exec = True
            if '.data' in name_lower or name_lower == '__data':
                is_write = True

        perms = 'r'
        if is_write:
            perms += 'w'
        if is_exec:
            perms += 'x'

        # 跳过空段
        if size == 0 and offset == 0:
            continue

        sections.append(SectionInfo(
            name=name, offset=offset, size=size,
            virtual_address=va, virtual_size=vsize,
            permissions=perms,
            is_executable=is_exec,
            is_writable=is_write,
            is_readable=True,
            type=sec_type,
        ))

    return BinaryInfo(
        file_path=file_path,
        file_size=file_size,
        format=fmt,
        arch=arch,
        endianness=endianness,
        entry_point=entry_point,
        base_address=base_address,
        sections=sections,
        raw_data=raw_data,
    )
