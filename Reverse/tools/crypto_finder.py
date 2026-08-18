#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder v1.1 — 二进制密码算法识别工具
=============================================

CTF 逆向辅助工具：快速识别二进制文件中使用的密码算法和密钥位置。

功能：
  1. 常量签名扫描 — 识别 23+ 种密码算法（AES/DES/MD5/SHA/RC4/TEA/SM3/SM4/...）
  2. Capstone 反汇编分析 — 交叉引用定位、循环模式识别（RC4 KSA / XOR 循环）
  3. 密钥位置启发式定位 — 常量邻域/交叉引用/结构推断三重策略
  4. IDAPython 脚本生成 — 自动在 IDA 中标注算法常量和密钥候选
  5. 自定义编码表检测 — 识别魔改 Base64 编码表（CTF 逆向高频考点）

支持格式：
  ELF (x86/x64/ARM/ARM64/MIPS)
  PE  (x86/x64)
  Mach-O (x86/x64/ARM64)
  Raw binary（仅常量扫描，无反汇编）

用法:
  python3 crypto_finder.py <二进制文件>
  python3 crypto_finder.py <二进制文件> --json
  python3 crypto_finder.py <二进制文件> --ida-script <输出路径>
  python3 crypto_finder.py <二进制文件> --verbose
  python3 crypto_finder.py <二进制文件> --no-disasm          # 跳过反汇编（快速模式）
  python3 crypto_finder.py <二进制文件> --scan-ascii           # 也搜索 ASCII 密钥字符串

作者：CTF 解题笔记本项目
版本：1.1
"""

import sys
import os
import json
import argparse
from pathlib import Path

# 确保 cf_lib 包可被导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cf_lib import (
    SIGNATURES, get_all_algorithms,
    parse_binary, scan_binary, aggregate_by_algorithm,
    scan_for_rc4_ksa, scan_for_xor_key_candidates, scan_for_custom_base64_table,
    find_xrefs_to_hits, detect_rc4_ksa_pattern, detect_xor_loop_pattern,
    locate_all_keys, generate_ida_script,
)


# ============================================================
# 输出格式化
# ============================================================

BANNER = r"""
  ____                      ___                       _ ___
 / ___|_ __ __ _ _____   _ / __| ___ _ __  _ __  ___| / __|
| |   | '__/ _` |_  / | | | |   / _ \ '_ \| '_ \/ __| \__ \
| |___| | | (_| |/ /| |_| | |__|  __/ |_) | |_) \__ \_|  _/
 \____|_|  \__,_/___|\__, |\____\___| .__/| .__/|___(_)_|
                     |___/           |_|   |_|
                                             v1.1
"""

CONFIDENCE_SYMBOLS = {
    'very-high': '[!!!]',
    'high':      '[!!]',
    'medium':    '[!]',
    'low':       '[?]',
    'none':      '[ ]',
}

CONFIDENCE_COLOR = {
    'very-high': '\033[91m',  # bright red
    'high':      '\033[31m',  # red
    'medium':    '\033[33m',  # yellow
    'low':       '\033[37m',  # white/grey
}

RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
CYAN = '\033[36m'
GREEN = '\033[32m'


def _color(text: str, color_code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f'{color_code}{text}{RESET}'


def _hex_dump_short(data: bytes, max_bytes: int = 32) -> str:
    """简短 hex dump"""
    if len(data) <= max_bytes:
        return data.hex()
    return data[:max_bytes].hex() + '...'


def _ascii_repr(data: bytes, max_bytes: int = 32) -> str:
    """ASCII 可读表示"""
    return ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in data[:max_bytes])


def print_binary_info(bin_info):
    """打印二进制文件基本信息"""
    print(_color(f'  文件: {bin_info.file_path}', DIM))
    print(f'  格式: {bin_info.format}   架构: {bin_info.arch}   端序: {bin_info.endianness}')
    print(f'  大小: {bin_info.file_size:,} 字节   入口: 0x{bin_info.entry_point:X}')
    print()

    # 段信息
    print(_color('  段 (Sections):', BOLD))
    for sec in bin_info.sections:
        perms = sec.permissions.ljust(3)
        print(f'    {sec.name:20s}  {perms}  VA=0x{sec.virtual_address:08X}  '
              f'size=0x{sec.size:X}  type={sec.type}')
    print()


def print_algorithm_results(algo_results):
    """打印算法检测结果"""
    if not algo_results:
        print(_color('  未检测到任何密码算法常量', DIM))
        print()
        return

    total_algos = len(algo_results)
    total_hits = sum(len(r.hits) for r in algo_results)
    print(_color(f'  检测到 {total_algos} 种算法 ({total_hits} 处常量命中):', BOLD))
    print()

    for result in algo_results:
        conf_sym = CONFIDENCE_SYMBOLS.get(result.confidence, '[?]')
        conf_color = CONFIDENCE_COLOR.get(result.confidence, '')

        algo_line = f'  {conf_sym} {_color(result.algo, conf_color + BOLD)}'
        if result.confidence == 'very-high':
            algo_line = f'  {conf_sym} {_color(result.algo, BOLD + "\033[91m")}'
        elif result.confidence == 'high':
            algo_line = f'  {conf_sym} {_color(result.algo, BOLD)}'
        else:
            algo_line = f'  {conf_sym} {result.algo}'

        components = ', '.join(result.components_found)
        print(f'{algo_line}  ({components})')

        for hit in result.hits:
            va_str = f'0x{hit.virtual_address:08X}' if hit.virtual_address else f'off=0x{hit.file_offset:X}'
            sec_str = hit.section_name if hit.section_name != 'unknown' else '?'
            align_str = '' if hit.alignment_ok else ' [未对齐]'
            desc = hit.signature.description or hit.signature.component
            print(f'      {_color(va_str, CYAN)}  [{sec_str:12s}]  {hit.signature.component:20s} {align_str}')
    print()


def print_xref_results(xrefs):
    """打印交叉引用结果"""
    if not xrefs:
        print(_color('  未找到对密码常量的代码引用', DIM))
        print()
        return

    print(_color(f'  交叉引用 ({len(xrefs)} 处):', BOLD))
    for xref in xrefs:
        print(f'    0x{xref.code_va:08X}  {xref.instruction:40s}  '
              f'→ {xref.referenced_algo}/{xref.referenced_component} (0x{xref.target_va:08X})')
    print()


def print_key_candidates(key_candidates):
    """打印密钥候选"""
    if not key_candidates:
        print(_color('  未发现密钥候选', DIM))
        print()
        return

    print(_color(f'  密钥候选 ({len(key_candidates)} 个):', BOLD))
    print()

    for i, cand in enumerate(key_candidates):
        conf_sym = CONFIDENCE_SYMBOLS.get(cand.confidence, '[?]')
        conf_color = CONFIDENCE_COLOR.get(cand.confidence, '')
        va_str = f'0x{cand.virtual_address:08X}' if cand.virtual_address else f'off=0x{cand.file_offset:X}'

        print(f'  {conf_sym} {_color(f'#{i+1}  {cand.algorithm} {cand.size}B @ {va_str}', conf_color + BOLD)}')
        print(f'      hex:   {cand.data_hex}')
        print(f'      ascii: {_ascii_repr(bytes.fromhex(cand.data_hex))}')
        print(f'      section: {cand.section_name}   source: {cand.source}')
        if cand.referenced_by:
            print(f'      ref:   {cand.referenced_by[0]}')
        print()


def print_loop_patterns(loop_patterns):
    """打印循环模式检测结果"""
    if not loop_patterns:
        return

    print(_color(f'  循环模式 ({len(loop_patterns)} 处):', BOLD))
    for pat in loop_patterns:
        conf_sym = CONFIDENCE_SYMBOLS.get(pat.confidence, '[?]')
        va_str = f'0x{pat.code_va:08X}' if pat.code_va else f'off=0x{pat.code_offset:X}'
        print(f'    {conf_sym} {pat.pattern_type:12s} @ {va_str}  {pat.description}')
    print()


def print_summary(algo_results, key_candidates, loop_patterns, xrefs, base64_tables=None):
    """打印摘要"""
    print(_color('  ────────────────────────────────────────────', DIM))

    # 算法摘要
    if algo_results:
        high_conf = [r for r in algo_results if r.confidence in ('high', 'very-high')]
        if high_conf:
            algo_names = ', '.join(r.algo for r in high_conf)
            print(f'  {_color("高置信度算法:", BOLD + GREEN)} {algo_names}')
        med_conf = [r for r in algo_results if r.confidence == 'medium']
        if med_conf:
            algo_names = ', '.join(r.algo for r in med_conf)
            print(f'  {_color("中等置信度:", BOLD)} {algo_names}')

    # 自定义编码表摘要
    if base64_tables:
        custom_tables = [t for t in base64_tables if t['is_custom']]
        if custom_tables:
            print(f'  {_color("自定义编码表:", BOLD + GREEN)} {len(custom_tables)} 个')
            for t in custom_tables[:3]:
                va = f'0x{t["virtual_address"]:08X}' if t['virtual_address'] else f'off=0x{t["file_offset"]:X}'
                print(f'    → {t["table_type"]} @ {va}: {t["table_str"][:32]}...')
        elif base64_tables:
            std_tables = [t for t in base64_tables if not t['is_custom']]
            if std_tables:
                types = ', '.join(set(t['table_type'] for t in std_tables))
                print(f'  {_color("标准编码表:", BOLD)} {types}')

    # 密钥摘要
    if key_candidates:
        high_keys = [k for k in key_candidates if k.confidence == 'high']
        if high_keys:
            print(f'  {_color("高置信度密钥:", BOLD + GREEN)} {len(high_keys)} 个')
            for k in high_keys[:3]:
                va = f'0x{k.virtual_address:08X}' if k.virtual_address else f'off=0x{k.file_offset:X}'
                print(f'    → {k.algorithm} {k.size}B @ {va}: {k.data_hex[:32]}...')

    # 循环摘要
    if loop_patterns:
        high_loops = [p for p in loop_patterns if p.confidence == 'high']
        if high_loops:
            types = ', '.join(set(p.pattern_type for p in high_loops))
            print(f'  {_color("高置信度循环:", BOLD + GREEN)} {types}')

    print()


# ============================================================
# JSON 输出
# ============================================================

def build_json_output(bin_info, algo_results, hits, xrefs, key_candidates, loop_patterns, rc4_hits, base64_tables=None):
    """构建 JSON 输出"""
    return {
        'tool': 'crypto_finder',
        'version': '1.1',
        'file': {
            'path': bin_info.file_path,
            'format': bin_info.format,
            'arch': bin_info.arch,
            'endianness': bin_info.endianness,
            'size': bin_info.file_size,
            'entry_point': bin_info.entry_point,
        },
        'sections': [
            {
                'name': s.name,
                'virtual_address': s.virtual_address,
                'size': s.size,
                'permissions': s.permissions,
                'type': s.type,
            }
            for s in bin_info.sections
        ],
        'algorithms': [
            {
                'name': r.algo,
                'confidence': r.confidence,
                'components': r.components_found,
                'hits': [
                    {
                        'component': h.signature.component,
                        'file_offset': h.file_offset,
                        'virtual_address': h.virtual_address,
                        'section': h.section_name,
                        'description': h.signature.description,
                    }
                    for h in r.hits
                ],
            }
            for r in algo_results
        ],
        'xrefs': [
            {
                'code_va': x.code_va,
                'target_va': x.target_va,
                'instruction': x.instruction,
                'algo': x.referenced_algo,
                'component': x.referenced_component,
            }
            for x in xrefs
        ],
        'key_candidates': [
            {
                'file_offset': k.file_offset,
                'virtual_address': k.virtual_address,
                'section': k.section_name,
                'size': k.size,
                'hex': k.data_hex,
                'confidence': k.confidence,
                'source': k.source,
                'algorithm': k.algorithm,
            }
            for k in key_candidates
        ],
        'loop_patterns': [
            {
                'type': p.pattern_type,
                'code_va': p.code_va,
                'section': p.section_name,
                'confidence': p.confidence,
                'description': p.description,
                'loop_count': p.loop_count,
            }
            for p in loop_patterns
        ],
        'rc4_candidates': rc4_hits if rc4_hits else [],
        'base64_tables': base64_tables if base64_tables else [],
    }


# ============================================================
# ASCII 密钥字符串扫描
# ============================================================

def scan_ascii_key_strings(bin_info, min_len=8, max_len=64):
    """在数据段中搜索可能的 ASCII 密钥字符串

    特征：长度 8-64 的非空可打印 ASCII 字符串，前面或后面有非 ASCII 上下文
    """
    candidates = []
    raw = bin_info.raw_data

    for section in bin_info.sections:
        if section.type not in ('rodata', 'data'):
            continue

        section_data = raw[section.offset:section.offset + section.size]
        i = 0

        while i < len(section_data):
            # 查找可打印字符串的起始
            if 0x20 <= section_data[i] <= 0x7e:
                j = i
                while j < len(section_data) and 0x20 <= section_data[j] <= 0x7e:
                    j += 1

                string_len = j - i
                if min_len <= string_len <= max_len:
                    string_data = section_data[i:j]
                    string_text = string_data.decode('ascii', errors='replace')

                    # 过滤掉明显不是密钥的（如段名、格式字符串）
                    skip = False
                    for pattern in [b'%s', b'%d', b'%x', b'.rodata', b'.text', b'.data',
                                   b'GLIBC', b'libc', b'lib/', b'/usr/', b'Error', b'error']:
                        if pattern in string_data:
                            skip = True
                            break

                    if not skip:
                        # 检查是否在密码常量附近
                        abs_off = section.offset + i
                        near_crypto = False
                        nearest_algo = ''

                        for hit in _global_hits:
                            if abs(hit.file_offset - abs_off) < 256 and hit.virtual_address > 0:
                                near_crypto = True
                                nearest_algo = hit.signature.algo
                                break

                        if near_crypto:
                            va = bin_info.offset_to_va(abs_off) or 0
                            candidates.append({
                                'type': 'ascii_key_string',
                                'file_offset': abs_off,
                                'virtual_address': va,
                                'section': section.name,
                                'size': string_len,
                                'text': string_text,
                                'hex': string_data.hex(),
                                'confidence': 'medium' if near_crypto else 'low',
                                'near_algorithm': nearest_algo,
                                'note': f'ASCII 字符串 "{string_text[:32]}..." 靠近 {nearest_algo} 常量',
                            })

                i = j + 1
            else:
                i += 1

    return candidates


# 全局变量：存储当前扫描的 hits，供 scan_ascii_key_strings 使用
_global_hits = []


# ============================================================
# 主函数
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Crypto Finder — 二进制密码算法识别工具 (CTF 逆向辅助)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s ./challenge.bin
  %(prog)s ./challenge.bin --json -o result.json
  %(prog)s ./challenge.bin --ida-script cf_annotate.py
  %(prog)s ./challenge.bin --no-disasm          # 快速模式：仅常量扫描
  %(prog)s ./challenge.bin --scan-ascii          # 也搜索 ASCII 密钥
  %(prog)s ./challenge.bin --verbose             # 详细输出
        ''',
    )
    parser.add_argument('binary', nargs='?', help='目标二进制文件路径')
    parser.add_argument('--json', action='store_true', help='以 JSON 格式输出结果')
    parser.add_argument('-o', '--output', help='输出文件路径（JSON 或文本）')
    parser.add_argument('--ida-script', metavar='PATH', help='生成 IDAPython 标注脚本到指定路径')
    parser.add_argument('--no-disasm', action='store_true', help='跳过反汇编分析（快速模式）')
    parser.add_argument('--scan-ascii', action='store_true', help='搜索 ASCII 密钥字符串')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出（含交叉引用和数据 dump）')
    parser.add_argument('--list-algos', action='store_true', help='列出所有支持的算法签名')

    args = parser.parse_args()

    # --list-algos 模式
    if args.list_algos:
        print(BANNER)
        print(_color('支持的密码算法签名:', BOLD))
        print(f'  共 {len(SIGNATURES)} 个签名，覆盖 {len(get_all_algorithms())} 种算法:\n')
        for algo in sorted(get_all_algorithms()):
            sigs = [s for s in SIGNATURES if s.algo == algo]
            components = ', '.join(s.component for s in sigs)
            print(f'  {algo:20s}  [{components}]')
        return 0

    # 检查文件
    if not os.path.isfile(args.binary):
        print(f'错误: 文件不存在: {args.binary}', file=sys.stderr)
        return 1

    # ⚠ AIGC 水印：本文件由 AI 生成

    if not args.json:
        print(BANNER)

    # === 1. 解析二进制 ===
    if not args.json:
        print(_color('[1/4] 解析二进制文件...', BOLD))
    bin_info = parse_binary(args.binary)

    if not args.json:
        print_binary_info(bin_info)

    # === 2. 常量扫描 ===
    if not args.json:
        print(_color('[2/4] 扫描密码算法常量...', BOLD))
    hits = scan_binary(bin_info)
    global _global_hits
    _global_hits = hits

    algo_results = aggregate_by_algorithm(hits)

    # RC4 特殊检测（identity 数组）
    rc4_hits = scan_for_rc4_ksa(bin_info)

    # 异或密钥候选
    xor_candidates = scan_for_xor_key_candidates(bin_info)

    # 自定义编码表检测（Base64 等）
    base64_tables = scan_for_custom_base64_table(bin_info)

    if not args.json:
        print_algorithm_results(algo_results)

        if rc4_hits:
            print(_color(f'  RC4 KSA 候选 ({len(rc4_hits)} 处):', BOLD))
            for rc4 in rc4_hits:
                va = f'0x{rc4["virtual_address"]:08X}' if rc4['virtual_address'] else f'off=0x{rc4["file_offset"]:X}'
                print(f'    [?] rc4_ksa  @ {va}  {rc4["note"]}')
            print()

        if xor_candidates:
            print(_color(f'  异或密钥候选 ({len(xor_candidates)} 处):', BOLD))
            for xc in xor_candidates:
                va = f'0x{xc["virtual_address"]:08X}' if xc['virtual_address'] else f'off=0x{xc["file_offset"]:X}'
                print(f'    [?] xor_key  @ {va}  {xc["size"]}B  hex={xc["hex"][:32]}...')
            print()

        if base64_tables:
            print(_color(f'  自定义编码表 ({len(base64_tables)} 处):', BOLD))
            for bt in base64_tables:
                va = f'0x{bt["virtual_address"]:08X}' if bt['virtual_address'] else f'off=0x{bt["file_offset"]:X}'
                conf_mark = '!!!' if bt['confidence'] == 'high' else ('!!' if bt['confidence'] == 'medium' else '?')
                custom_tag = ' [自定义]' if bt['is_custom'] else ''
                print(f'    [{conf_mark}] {bt["table_type"]:20s} @ {va}{custom_tag}')
                print(f'         表: {bt["table_str"]}')
                print(f'         {bt["note"]}')
            print()

    # === 3. 反汇编分析 ===
    xrefs = []
    loop_patterns = []
    key_candidates = []

    if not args.no_disasm and bin_info.format != 'Raw' and bin_info.arch in ('x86', 'x64', 'arm', 'arm64', 'mips'):
        if not args.json:
            print(_color('[3/4] Capstone 反汇编分析...', BOLD))

        # 交叉引用
        xrefs = find_xrefs_to_hits(bin_info, hits)

        # 循环模式检测
        rc4_loops = detect_rc4_ksa_pattern(bin_info)
        xor_loops = detect_xor_loop_pattern(bin_info)
        loop_patterns = rc4_loops + xor_loops

        if not args.json:
            if args.verbose:
                print_xref_results(xrefs)
            else:
                if xrefs:
                    print(f'  交叉引用: {len(xrefs)} 处（使用 --verbose 查看）')

            print_loop_patterns(loop_patterns)

        # === 4. 密钥定位 ===
        if not args.json:
            print(_color('[4/4] 密钥位置定位...', BOLD))

        key_candidates = locate_all_keys(bin_info, algo_results, xrefs)

        if not args.json:
            print_key_candidates(key_candidates)

    else:
        if not args.json:
            if args.no_disasm:
                print(_color('[3/4] 跳过反汇编分析 (--no-disasm)', DIM))
                print(_color('[4/4] 跳过密钥定位（需要反汇编数据）', DIM))
            else:
                if bin_info.format == 'Raw':
                    print(_color('[3/4] 跳过反汇编分析 (Raw 格式)', DIM))
                else:
                    print(_color(f'[3/4] 跳过反汇编分析 (不支持架构: {bin_info.arch})', DIM))
                print(_color('[4/4] 跳过密钥定位', DIM))
            print()

    # ASCII 密钥扫描
    ascii_keys = []
    if args.scan_ascii:
        if not args.json:
            print(_color('[+] 扫描 ASCII 密钥字符串...', BOLD))
        ascii_keys = scan_ascii_key_strings(bin_info)
        if not args.json:
            if ascii_keys:
                print(f'  发现 {len(ascii_keys)} 个 ASCII 密钥候选:')
                for ak in ascii_keys:
                    va = f'0x{ak["virtual_address"]:08X}' if ak['virtual_address'] else f'off=0x{ak["file_offset"]:X}'
                    print(f'    [{ak["confidence"]}] "{ak["text"][:32]}..." @ {va} (靠近 {ak["near_algorithm"]})')
            else:
                print('  未发现 ASCII 密钥候选')
            print()

    # 摘要
    if not args.json:
        print_summary(algo_results, key_candidates, loop_patterns, xrefs, base64_tables)

    # IDA 脚本生成
    if args.ida_script:
        if not args.json:
            print(_color(f'[+] 生成 IDAPython 脚本: {args.ida_script}', BOLD))
        generate_ida_script(bin_info, algo_results, key_candidates, loop_patterns, args.ida_script)
        if not args.json:
            print(f'    在 IDA 中通过 File → Script file 运行: {args.ida_script}')
            print()

    # JSON 输出
    if args.json:
        result = build_json_output(bin_info, algo_results, hits, xrefs, key_candidates, loop_patterns, rc4_hits, base64_tables)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f'JSON 结果已写入: {args.output}', file=sys.stderr)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.output:
        # 文本输出到文件
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        # 重新输出（已经被打印过了，这里只做文件写入）
        # 实际上文本已经打印过了，这里只是简单的重定向提示
        sys.stdout = old_stdout
        # 简化：直接输出到文件
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(f'Crypto Finder 结果 — {bin_info.file_path}\n')
            f.write(f'格式: {bin_info.format} / 架构: {bin_info.arch}\n')
            f.write(f'大小: {bin_info.file_size:,} 字节\n\n')
            f.write(f'检测到 {len(algo_results)} 种算法:\n')
            for r in algo_results:
                f.write(f'  [{r.confidence}] {r.algo}: {", ".join(r.components_found)}\n')
                for h in r.hits:
                    va = f'0x{h.virtual_address:08X}' if h.virtual_address else f'off=0x{h.file_offset:X}'
                    f.write(f'      {h.signature.component} @ {va} [{h.section_name}]\n')
            if key_candidates:
                f.write(f'\n密钥候选 ({len(key_candidates)} 个):\n')
                for k in key_candidates:
                    va = f'0x{k.virtual_address:08X}' if k.virtual_address else f'off=0x{k.file_offset:X}'
                    f.write(f'  [{k.confidence}] {k.algorithm} {k.size}B @ {va}: {k.data_hex}\n')
                    f.write(f'      source: {k.source}\n')
        print(f'结果已写入: {args.output}', file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
