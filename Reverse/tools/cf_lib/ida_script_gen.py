#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder — IDAPython 脚本生成器
=====================================

将检测结果生成为 IDAPython 脚本，用户可在 IDA 中直接运行，
自动标记算法常量、密钥候选位置，并添加注释。

生成的脚本兼容 IDA Pro 7.x / 9.0+。

作者：CTF 解题笔记本项目
版本：1.0
"""

from __future__ import annotations
from typing import Optional

from .binary_parser import BinaryInfo
from .scanner import ScanHit, AlgorithmResult
from .key_locator import KeyCandidate
from .disasm import XrefResult, LoopPattern


def generate_ida_script(binary_info: BinaryInfo,
                        algo_results: list[AlgorithmResult],
                        key_candidates: list[KeyCandidate],
                        loop_patterns: list[LoopPattern],
                        output_path: str) -> str:
    """生成 IDAPython 脚本

    Args:
        binary_info: 二进制信息
        algo_results: 算法检测结果
        key_candidates: 密钥候选
        loop_patterns: 循环模式
        output_path: 输出脚本路径

    Returns:
        生成的脚本文件路径
    """
    lines = []
    lines.append('# -*- coding: utf-8 -*-')
    lines.append('"""')
    lines.append('Crypto Finder — IDAPython 标注脚本')
    lines.append(f'源文件: {binary_info.file_path}')
    lines.append(f'格式: {binary_info.format} / 架构: {binary_info.arch}')
    lines.append(f'生成工具: crypto_finder.py v1.0')
    lines.append('')
    lines.append('在 IDA 中通过 File → Script file 运行此脚本。')
    lines.append('脚本将自动：')
    lines.append('  1. 在密码算法常量位置添加注释')
    lines.append('  2. 在密钥候选位置添加标注和命名')
    lines.append('  3. 在循环模式位置添加注释')
    lines.append('"""')
    lines.append('')
    lines.append('import idc')
    lines.append('import idaapi')
    lines.append('import idautils')
    lines.append('import ida_bytes')
    lines.append('import ida_name')
    lines.append('import ida_segment')
    lines.append('')
    lines.append(f'TARGET_FILE = r"{binary_info.file_path}"')
    lines.append('')
    lines.append('def set_comment(ea, comment):')
    lines.append('    """在指定地址添加注释（如果已有注释则追加）"""')
    lines.append('    existing = idc.get_cmt(ea, 0) or ""')
    lines.append('    if comment not in existing:')
    lines.append('        new_cmt = (existing + "\\n" + comment) if existing else comment')
    lines.append('        idc.set_cmt(ea, new_cmt, 0)')
    lines.append('')
    lines.append('def set_name(ea, name):')
    lines.append('    """在指定地址设置名称，自动处理重名"""')
    lines.append('    if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):')
    lines.append('        return True')
    lines.append('    # 尝试加后缀')
    lines.append('    for i in range(1, 100):')
    lines.append('        if ida_name.set_name(ea, f"{name}_{i}", ida_name.SN_NOWARN | ida_name.SN_NOCHECK):')
    lines.append('            return True')
    lines.append('    return False')
    lines.append('')
    lines.append('def color_address(ea, color):')
    lines.append('    """给地址上色（0xBBGGRR 格式）"""')
    lines.append('    idc.set_color(ea, idc.CIC_ITEM, color)')
    lines.append('')
    lines.append('# ============================================================')
    lines.append('# 颜色定义')
    lines.append('# ============================================================')
    lines.append('COLOR_ALGO = 0xCCCCFF    # 浅蓝：算法常量')
    lines.append('COLOR_KEY = 0xFFCCCC     # 浅红：密钥候选')
    lines.append('COLOR_LOOP = 0xCCFFCC    # 浅绿：循环模式')
    lines.append('')
    lines.append('print("=" * 60)')
    lines.append('print("Crypto Finder — 开始标注")')
    lines.append('print("=" * 60)')
    lines.append('')

    # === 1. 标注算法常量 ===
    lines.append('# ============================================================')
    lines.append('# 1. 标注密码算法常量')
    lines.append('# ============================================================')
    lines.append(f'algo_count = {len(algo_results)}')
    lines.append('print(f"检测到 {algo_count} 种算法")')
    lines.append('')

    for result in algo_results:
        lines.append(f'# --- {result.algo} (置信度: {result.confidence}) ---')
        for hit in result.hits:
            if hit.virtual_address == 0:
                continue
            va = hit.virtual_address
            comment = f'[CryptoFinder] {result.algo} {hit.signature.component}: {hit.signature.description}'
            safe_comment = comment.replace('"', '\\"')
            lines.append(f'set_comment(0x{va:X}, "{safe_comment}")')
            lines.append(f'set_name(0x{va:X}, "cf_{result.algo.replace("/", "_").replace(" ", "_")}_{hit.signature.component.replace(" ", "_").replace("-", "_")}")')
            lines.append(f'color_address(0x{va:X}, COLOR_ALGO)')
            lines.append(f'print("  {result.algo} / {hit.signature.component} @ 0x{va:X}")')
        lines.append('')

    # === 2. 标注密钥候选 ===
    lines.append('# ============================================================')
    lines.append('# 2. 标注密钥候选')
    lines.append('# ============================================================')
    lines.append(f'key_count = {len(key_candidates)}')
    lines.append('print(f"发现 {key_count} 个密钥候选")')
    lines.append('')

    for i, cand in enumerate(key_candidates):
        if cand.virtual_address == 0:
            continue
        va = cand.virtual_address
        conf_tag = {'high': '★★★', 'medium': '★★', 'low': '★'}.get(cand.confidence, '?')
        comment = f'[CryptoFinder] 密钥候选 {conf_tag} {cand.algorithm} ({cand.size}B): {cand.source} | hex={cand.data_hex[:32]}'
        safe_comment = comment.replace('"', '\\"')
        name = f'cf_key_{cand.algorithm.replace("/", "_").replace(" ", "_")}_{i}'
        lines.append(f'set_comment(0x{va:X}, "{safe_comment}")')
        lines.append(f'set_name(0x{va:X}, "{name}")')
        lines.append(f'color_address(0x{va:X}, COLOR_KEY)')
        lines.append(f'print("  密钥候选 [{cand.confidence}] {cand.algorithm} {cand.size}B @ 0x{va:X}: {cand.data_hex[:32]}...")')
    lines.append('')

    # === 3. 标注循环模式 ===
    if loop_patterns:
        lines.append('# ============================================================')
        lines.append('# 3. 标注加密循环模式')
        lines.append('# ============================================================')
        lines.append(f'loop_count = {len(loop_patterns)}')
        lines.append('print(f"检测到 {loop_count} 个加密循环模式")')
        lines.append('')

        for i, pat in enumerate(loop_patterns):
            if pat.code_va == 0:
                continue
            va = pat.code_va
            comment = f'[CryptoFinder] {pat.pattern_type}: {pat.description}'
            safe_comment = comment.replace('"', '\\"')
            lines.append(f'set_comment(0x{va:X}, "{safe_comment}")')
            lines.append(f'color_address(0x{va:X}, COLOR_LOOP)')
            lines.append(f'print("  {pat.pattern_type} @ 0x{va:X}: {pat.description}")')
        lines.append('')

    # === 4. 段信息输出 ===
    lines.append('# ============================================================')
    lines.append('# 4. 段信息摘要')
    lines.append('# ============================================================')
    lines.append('print("")')
    lines.append('print("段信息:")')
    for sec in binary_info.sections:
        lines.append(f'print("  {sec.name:16s} VA=0x{sec.virtual_address:08X} size=0x{sec.size:X} type={sec.type} perms={sec.permissions}")')
    lines.append('')

    lines.append('print("")')
    lines.append('print("=" * 60)')
    lines.append(f'print("Crypto Finder 标注完成: {len(algo_results)} 算法, {len(key_candidates)} 密钥候选, {len(loop_patterns)} 循环模式")')
    lines.append('print("颜色说明: 蓝=算法常量  红=密钥候选  绿=循环模式")')
    lines.append('print("=" * 60)')

    script_content = '\n'.join(lines)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(script_content)

    return output_path
