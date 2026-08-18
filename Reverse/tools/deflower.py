#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeFlower v2 — 花指令自动清除脚本 (IDA Python)
=============================================

用途：CTF 逆向题中自动检测并清除花指令（Junk Code / Flower Instruction），
     恢复 IDA Pro 的正确反汇编结果。

适用环境：
  - IDA Pro 7.x / 9.0+ (x86/x64)
  - 在 IDA 中通过 File → Script file 运行

支持 11 条检测规则，覆盖 CTF 真实题目中的主流花指令：
  1. 垃圾跳转 (junk_jmp)
  2. 相反条件跳转对 (opp_jcc_pair)
  3. 交替条件跳转 (alt_jcc)
  4. push+pop 同寄存器 (push_pop_same)
  5. 数学恒等变换 (math_identity)
  6. call+pop 获取 EIP (call_pop_eip)
  7. 不透明谓词 (opaque_predicate)
  8. 偏移跳转+垃圾字节 (jcc_offset)  ← CTF 最高频
  9. jmp 跳过垃圾字节 (jmp_over_junk)
  10. 标志位操控 (stc_clc_jcc)
  11. call+add esp 平衡栈 (call_add_esp)

迭代扫描机制：多轮扫描逐层清除嵌套花指令，每轮前强制重新分析。
清除方式：将花指令字节替换为 0x90 (NOP)。

⚠ 注意：
  - 所有修改仅在 IDA 内存中生效，不修改磁盘文件
  - 建议运行前备份 .i64/.idb 文件
  - 仅支持 x86/x64 架构

作者：CTF 解题笔记本项目
版本：2.0
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_ua
import ida_funcs
import ida_segment

# ═══════════════════════════════════════════════════
#  配置
# ═══════════════════════════════════════════════════

RULES_ENABLED = {
    "junk_jmp":        True,
    "opp_jcc_pair":    True,
    "alt_jcc":         True,
    "push_pop_same":   True,
    "math_identity":   True,
    "call_pop_eip":    True,
    "opaque_predicate":True,
    "jcc_offset":      True,
    "jmp_over_junk":   True,
    "stc_clc_jcc":     True,
    "call_add_esp":    True,
}

DEFAULT_ITERATIONS = 5
NOP = 0x90

# ═══════════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════════

def get_insn_at(ea):
    """获取 ea 处的指令对象，失败返回 None"""
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)
    if length > 0:
        return insn
    return None

def get_insn_size(ea):
    """获取 ea 处指令长度"""
    insn = get_insn_at(ea)
    if insn:
        return insn.size
    return 0

def get_mnemonic(ea):
    """获取 ea 处的助记符字符串"""
    return idc.print_insn_mnem(ea)

def get_byte(ea):
    """读取 ea 处一个字节"""
    return ida_bytes.get_byte(ea)

def nop_range(start, end):
    """将 [start, end) 范围内的字节全部 NOP"""
    for ea in range(start, end):
        ida_bytes.patch_byte(ea, NOP)
    return end - start

def is_code_ea(ea):
    """判断 ea 是否在代码段内"""
    seg = ida_segment.getseg(ea)
    if seg and seg.type == ida_segment.SEG_CODE:
        return True
    return False

def get_jump_target(ea):
    """获取条件/无条件跳转目标地址，非跳转返回 None"""
    insn = get_insn_at(ea)
    if not insn:
        return None
    if insn.itype in (idaapi.NN_jmp, idaapi.NN_jmpshort, idaapi.NN_jmpnear,
                       idaapi.NN_ja, idaapi.NN_jb, idaapi.NN_jc,
                       idaapi.NN_jz, idaapi.NN_jg, idaapi.NN_jl,
                       idaapi.NN_jna, idaapi.NN_jnb, idaapi.NN_jnc,
                       idaapi.NN_jnz, idaapi.NN_jnge, idaapi.NN_jnl,
                       idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns,
                       idaapi.NN_jo, idaapi.NN_jp, idaapi.NN_js,
                       # x64 variants
                       idaapi.NN_ja_short, idaapi.NN_jb_short,
                       idaapi.NN_jc_short, idaapi.NN_jz_short,
                       idaapi.NN_jg_short, idaapi.NN_jl_short,
                       idaapi.NN_jna_short, idaapi.NN_jnb_short,
                       idaapi.NN_jnc_short, idaapi.NN_jnz_short,
                       idaapi.NN_jnge_short, idaapi.NN_jnl_short,
                       idaapi.NN_jno_short, idaapi.NN_jnp_short,
                       idaapi.NN_jns_short, idaapi.NN_jo_short,
                       idaapi.NN_jp_short, idaapi.NN_js_short):
        for op in insn.ops:
            if op.type == ida_ua.o_near:
                return op.value
    return None

def is_jcc(insn_type):
    """判断是否为条件跳转"""
    return insn_type in (
        idaapi.NN_ja, idaapi.NN_jb, idaapi.NN_jc,
        idaapi.NN_jz, idaapi.NN_jg, idaapi.NN_jl,
        idaapi.NN_jna, idaapi.NN_jnb, idaapi.NN_jnc,
        idaapi.NN_jnz, idaapi.NN_jnge, idaapi.NN_jnl,
        idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns,
        idaapi.NN_jo, idaapi.NN_jp, idaapi.NN_js,
        idaapi.NN_ja_short, idaapi.NN_jb_short,
        idaapi.NN_jc_short, idaapi.NN_jz_short,
        idaapi.NN_jg_short, idaapi.NN_jl_short,
        idaapi.NN_jna_short, idaapi.NN_jnb_short,
        idaapi.NN_jnc_short, idaapi.NN_jnz_short,
        idaapi.NN_jnge_short, idaapi.NN_jnl_short,
        idaapi.NN_jno_short, idaapi.NN_jnp_short,
        idaapi.NN_jns_short, idaapi.NN_jo_short,
        idaapi.NN_jp_short, idaapi.NN_js_short,
    )

def is_unconditional_jmp(insn_type):
    """判断是否为无条件跳转"""
    return insn_type in (idaapi.NN_jmp, idaapi.NN_jmpshort, idaapi.NN_jmpnear)

def opposite_jcc(t):
    """返回条件相反的跳转类型，无对应返回 None"""
    mapping = {
        idaapi.NN_jz: idaapi.NN_jnz,  idaapi.NN_jnz: idaapi.NN_jz,
        idaapi.NN_ja: idaapi.NN_jna,   idaapi.NN_jna: idaapi.NN_ja,
        idaapi.NN_jb: idaapi.NN_jnb,   idaapi.NN_jnb: idaapi.NN_jb,
        idaapi.NN_jc: idaapi.NN_jnc,   idaapi.NN_jnc: idaapi.NN_jc,
        idaapi.NN_jg: idaapi.NN_jnge,  idaapi.NN_jnge: idaapi.NN_jg,
        idaapi.NN_jl: idaapi.NN_jnl,   idaapi.NN_jnl: idaapi.NN_jl,
        idaapi.NN_jo: idaapi.NN_jno,   idaapi.NN_jno: idaapi.NN_jo,
        idaapi.NN_jp: idaapi.NN_jnp,   idaapi.NN_jnp: idaapi.NN_jp,
        idaapi.NN_js: idaapi.NN_jns,   idaapi.NN_jns: idaapi.NN_js,
        # short variants
        idaapi.NN_jz_short: idaapi.NN_jnz_short,
        idaapi.NN_jnz_short: idaapi.NN_jz_short,
        idaapi.NN_ja_short: idaapi.NN_jna_short,
        idaapi.NN_jna_short: idaapi.NN_ja_short,
        idaapi.NN_jb_short: idaapi.NN_jnb_short,
        idaapi.NN_jnb_short: idaapi.NN_jb_short,
        idaapi.NN_jc_short: idaapi.NN_jnc_short,
        idaapi.NN_jnc_short: idaapi.NN_jc_short,
        idaapi.NN_jg_short: idaapi.NN_jnge_short,
        idaapi.NN_jnge_short: idaapi.NN_jg_short,
        idaapi.NN_jl_short: idaapi.NN_jnl_short,
        idaapi.NN_jnl_short: idaapi.NN_jl_short,
        idaapi.NN_jo_short: idaapi.NN_jno_short,
        idaapi.NN_jno_short: idaapi.NN_jo_short,
        idaapi.NN_jp_short: idaapi.NN_jnp_short,
        idaapi.NN_jnp_short: idaapi.NN_jp_short,
        idaapi.NN_js_short: idaapi.NN_jns_short,
        idaapi.NN_jns_short: idaapi.NN_js_short,
    }
    return mapping.get(t)

# ═══════════════════════════════════════════════════
#  检测规则
# ═══════════════════════════════════════════════════

def rule_junk_jmp(ea):
    """
    规则1: 垃圾跳转 — jmp $+2 (跳到下一条指令)
    典型: EB 00, EB 01 (short jmp 跳过0/1字节)
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    if is_unconditional_jmp(insn.itype):
        target = get_jump_target(ea)
        if target is not None and target == ea + insn.size:
            return insn.size
    return 0

def rule_opp_jcc_pair(ea):
    """
    规则2: 相反条件跳转对 — jz A; jnz A (永真跳转)
    两条条件跳转条件相反但目标相同，等价于无条件跳转
    """
    insn = get_insn_at(ea)
    if not insn or not is_jcc(insn.itype):
        return 0
    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    if is_jcc(insn2.itype) and opposite_jcc(insn.itype) == insn2.itype:
        t1 = get_jump_target(ea)
        t2 = get_jump_target(next_ea)
        if t1 is not None and t1 == t2:
            return insn.size + insn2.size
    return 0

def rule_alt_jcc(ea):
    """
    规则3: 交替条件跳转 — jcc A; jmp B; A: <垃圾块>
    条件跳转到一个短距离标签，中间跳过一些垃圾指令
    """
    insn = get_insn_at(ea)
    if not insn or not is_jcc(insn.itype):
        return 0
    target = get_jump_target(ea)
    if target is None:
        return 0
    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    if is_unconditional_jmp(insn2.itype):
        jmp2_target = get_jump_target(next_ea)
        # 条件跳转目标应该在跳转对之后不远
        if target is not None and target > next_ea and target < next_ea + 64:
            return target - ea  # NOP 到条件跳转目标
    return 0

def rule_push_pop_same(ea):
    """
    规则4: push+pop 同寄存器 — push rax; pop rax (无副作用)
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)
    if mnem != "push":
        return 0
    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    mnem2 = get_mnemonic(next_ea)
    if mnem2 != "pop":
        return 0
    # 检查操作数是否相同寄存器
    if insn.ops[0].type == ida_ua.o_reg and insn2.ops[0].type == ida_ua.o_reg:
        if insn.ops[0].reg == insn2.ops[0].reg:
            return insn.size + insn2.size
    return 0

def rule_math_identity(ea):
    """
    规则5: 数学恒等变换 — sub rax,5; add rax,5 或 xor eax,val; xor eax,val
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)

    pairs = [("sub", "add"), ("add", "sub"), ("xor", "xor")]
    matched_pair = None
    for a, b in pairs:
        if mnem == a:
            matched_pair = (a, b)
            break
    if not matched_pair:
        return 0

    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    mnem2 = get_mnemonic(next_ea)
    if mnem2 != matched_pair[1]:
        return 0

    # 检查操作数完全相同 (reg, imm) 或 (reg, reg)
    if (insn.ops[0].type == insn2.ops[0].type and
        insn.ops[1].type == insn2.ops[1].type):
        if (insn.ops[0].type == ida_ua.o_reg and
            insn.ops[0].reg == insn2.ops[0].reg):
            if insn.ops[1].type == ida_ua.o_imm:
                if insn.ops[1].value == insn2.ops[1].value:
                    return insn.size + insn2.size
            elif insn.ops[1].type == ida_ua.o_reg:
                if insn.ops[1].reg == insn2.ops[1].reg:
                    return insn.size + insn2.size
    return 0

def rule_call_pop_eip(ea):
    """
    规则6: call+pop 获取 EIP — call $+5; pop reg
    call 指令将下一条指令地址压栈，pop 取出，用于获取当前 EIP/RIP
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)
    if mnem != "call":
        return 0
    # call 目标应该是下一条指令 (call $+5)
    target = get_jump_target(ea)
    next_ea = ea + insn.size
    if target != next_ea:
        return 0
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    mnem2 = get_mnemonic(next_ea)
    if mnem2 == "pop":
        return insn.size + insn2.size
    return 0

def rule_opaque_predicate(ea):
    """
    规则7: 不透明谓词 — xor eax,eax; test eax,eax; jz label
    或 cmp reg,reg; jz label — 结果可预知的条件判断
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)
    if mnem != "xor":
        return 0
    # xor reg, reg (自身异或 = 清零)
    if insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_reg:
        if insn.ops[0].reg != insn.ops[1].reg:
            return 0
    else:
        return 0

    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    mnem2 = get_mnemonic(next_ea)
    if mnem2 not in ("test", "cmp"):
        return 0

    next_ea2 = next_ea + insn2.size
    insn3 = get_insn_at(next_ea2)
    if not insn3:
        return 0
    if is_jcc(insn3.itype):
        # 三条一起 NOP
        return insn.size + insn2.size + insn3.size
    return 0

def rule_jcc_offset(ea):
    """
    规则8: 偏移跳转+垃圾字节 — jz label+1; jnz label+1; db 0xE8
    CTF 最经典花指令，两条条件相反跳转跳到目标偏移处，中间插入垃圾字节
    """
    insn = get_insn_at(ea)
    if not insn or not is_jcc(insn.itype):
        return 0
    target = get_jump_target(ea)
    if target is None:
        return 0

    next_ea = ea + insn.size
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    if not is_jcc(insn2.itype):
        return 0
    target2 = get_jump_target(next_ea)
    if target2 is None:
        return 0

    # 条件相反且目标相同
    if opposite_jcc(insn.itype) != insn2.itype:
        return 0
    if target != target2:
        return 0

    # 目标应该跳过一些垃圾字节（跳转对结尾后1~8字节）
    jcc_end = next_ea + insn2.size
    if target > jcc_end and target <= jcc_end + 8:
        # NOP 到跳转目标
        return target - ea
    return 0

def rule_jmp_over_junk(ea):
    """
    规则9: jmp 跳过垃圾字节 — jmp skip; db 0xE8,0xED...
    jmp 直接跳过中间插入的垃圾数据
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    if not is_unconditional_jmp(insn.itype):
        return 0
    target = get_jump_target(ea)
    if target is None:
        return 0
    next_ea = ea + insn.size
    # 跳转目标在 jmp 之后 1~20 字节
    if target > next_ea and target <= next_ea + 20:
        # 检查中间是否有可疑字节 (0xE8=call, 0xE9=jmp, 0xED=LOCK前缀等)
        has_junk = False
        for addr in range(next_ea, target):
            b = get_byte(addr)
            if b in (0xE8, 0xE9, 0xED, 0xEB, 0x90):
                has_junk = True
                break
        # 即使没有明显垃圾字节，短距离 jmp 也可能是花指令
        if target - next_ea <= 8:
            has_junk = True
        if has_junk:
            return target - ea
    return 0

def rule_stc_clc_jcc(ea):
    """
    规则10: 标志位操控 — stc; jnb target 或 clc; jb target
    stc 设置 CF=1 → jnb(CF=0跳) 永假
    clc 清除 CF=0 → jb(CF=1跳) 永假
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)

    if mnem == "stc":
        next_ea = ea + insn.size
        insn2 = get_insn_at(next_ea)
        if insn2 and is_jcc(insn2.itype):
            # stc (CF=1) 后跟 jnb/jae/jnc (CF=0跳) = 永假
            if insn2.itype in (idaapi.NN_jnb, idaapi.NN_jnb_short,
                               idaapi.NN_jna, idaapi.NN_jna_short):
                return insn.size + insn2.size
    elif mnem == "clc":
        next_ea = ea + insn.size
        insn2 = get_insn_at(next_ea)
        if insn2 and is_jcc(insn2.itype):
            # clc (CF=0) 后跟 jb/jc/jnae (CF=1跳) = 永假
            if insn2.itype in (idaapi.NN_jb, idaapi.NN_jb_short,
                               idaapi.NN_jc, idaapi.NN_jc_short,
                               idaapi.NN_jnae, idaapi.NN_jnae_short):
                return insn.size + insn2.size
    return 0

def rule_call_add_esp(ea):
    """
    规则11: call+add esp 平衡栈 — call label; label: add esp,4
    call 将下一条指令压栈，add esp,4 平衡栈，等效于 jmp label
    """
    insn = get_insn_at(ea)
    if not insn:
        return 0
    mnem = get_mnemonic(ea)
    if mnem != "call":
        return 0
    target = get_jump_target(ea)
    next_ea = ea + insn.size
    if target != next_ea:
        return 0
    insn2 = get_insn_at(next_ea)
    if not insn2:
        return 0
    mnem2 = get_mnemonic(next_ea)
    if mnem2 == "add":
        # add esp, 4 或 add rsp, 8
        if (insn2.ops[0].type == ida_ua.o_reg and
            insn2.ops[1].type == ida_ua.o_imm):
            reg = insn2.ops[0].reg
            val = insn2.ops[1].value
            if (reg == idautils.proccmd() and
                val in (4, 8)):
                return insn.size + insn2.size
    return 0

# ═══════════════════════════════════════════════════
#  扫描引擎
# ═══════════════════════════════════════════════════

ALL_RULES = [
    ("junk_jmp",        rule_junk_jmp),
    ("opp_jcc_pair",    rule_opp_jcc_pair),
    ("alt_jcc",         rule_alt_jcc),
    ("push_pop_same",   rule_push_pop_same),
    ("math_identity",   rule_math_identity),
    ("call_pop_eip",    rule_call_pop_eip),
    ("opaque_predicate",rule_opaque_predicate),
    ("jcc_offset",      rule_jcc_offset),
    ("jmp_over_junk",   rule_jmp_over_junk),
    ("stc_clc_jcc",     rule_stc_clc_jcc),
    ("call_add_esp",    rule_call_add_esp),
]

def scan_range(start_ea, end_ea, rules, stats):
    """扫描 [start_ea, end_ea) 范围，应用所有启用的规则"""
    total_nop = 0
    ea = start_ea
    while ea < end_ea:
        for rule_name, rule_func in rules:
            if not RULES_ENABLED.get(rule_name, True):
                continue
            consumed = rule_func(ea)
            if consumed > 0:
                nop_range(ea, ea + consumed)
                stats[rule_name] = stats.get(rule_name, 0) + 1
                total_nop += consumed
                ea += consumed
                break  # 匹配到规则后跳过已 NOP 的区域
        else:
            size = get_insn_size(ea)
            if size > 0:
                ea += size
            else:
                ea += 1  # 无法解码时前进1字节
    return total_nop

def force_reanalyze(start_ea, end_ea):
    """强制重新分析指定范围：取消定义后重新解码"""
    ea = start_ea
    while ea < end_ea:
        idc.del_items(ea, idc.DELIT_SIMPLE, 1)
        ea += 1
    ea = start_ea
    while ea < end_ea:
        ida_ua.create_insn(ea)
        size = get_insn_size(ea)
        if size > 0:
            ea += size
        else:
            ea += 1

def get_scan_range():
    """获取扫描范围（由用户选择）"""
    # 检测是否有选中区域
    sel_start = idc.read_selection_start()
    sel_end = idc.read_selection_end()
    if sel_start != idc.BADADDR and sel_end != idc.BADADDR:
        return sel_start, sel_end, "选中区域"

    # 检测当前函数
    func = ida_funcs.get_func(idc.get_screen_ea())
    if func:
        return func.start_ea, func.end_ea, "当前函数"

    # 回退到第一个代码段
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg and seg.type == ida_segment.SEG_CODE:
            return seg.start_ea, seg.end_ea, "代码段"
    return idc.BADADDR, idc.BADADDR, "无"

# ═══════════════════════════════════════════════════
#  主入口
# ═══════════════════════════════════════════════════

def main():
    start_ea, end_ea, range_desc = get_scan_range()
    if start_ea == idc.BADADDR:
        print("[DeFlower] 无法确定扫描范围")
        return

    print("[DeFlower v2] 花指令自动清除")
    print(f"  扫描范围: {range_desc} (0x{start_ea:X} - 0x{end_ea:X})")
    print(f"  迭代次数: {DEFAULT_ITERATIONS}")

    # 启用的规则列表
    active_rules = [(name, func) for name, func in ALL_RULES
                    if RULES_ENABLED.get(name, True)]
    print(f"  启用规则: {len(active_rules)}/{len(ALL_RULES)}")

    stats = {}
    for iteration in range(DEFAULT_ITERATIONS):
        # 每轮迭代前强制重新分析
        force_reanalyze(start_ea, end_ea)

        # 扫描
        total_nop = scan_range(start_ea, end_ea, active_rules, stats)

        # 统计本轮
        round_matches = sum(1 for name, func in active_rules
                           if stats.get(name, 0) > 0)
        print(f"  [Round {iteration}] NOP {total_nop} bytes, "
              f"matched {len([k for k,v in stats.items() if v > 0])} rule types")

        if total_nop == 0:
            print(f"  [Round {iteration}] No new findings, stopping")
            break

    # 输出结果
    print("\n========== RESULTS ==========")
    total_matches = 0
    for rule_name, _ in ALL_RULES:
        count = stats.get(rule_name, 0)
        print(f"  {rule_name}: {count}")
        total_matches += count
    total_nop_bytes = sum(stats.values())  # 近似
    print(f"  total_matches: {total_matches}")

    print(f"\n[DeFlower] 完成！清除后请在函数入口按 P 重建，按 F5 重新生成伪代码。")

if __name__ == "__main__":
    main()
