"""
CTF 解题工具 — angr 符号执行自动化求解
用途: 面向 CTF 竞赛的 angr 符号执行解题
场景: angr_ctf 题目集 — 三道渐进式 angr 解题实战
题目来源: https://github.com/jakespringer/angr_ctf

三道题循序渐进地覆盖 angr 核心技术:
  题目一 (00_angr_find):          入门 — find/avoid 目标地址搜索
  题目二 (08_angr_constraints):   中级 — blank_state + 手动约束添加
  题目三 (09_angr_hooks):         中级 — SimProcedure 函数 Hook
"""

import angr
import claripy
import sys


# ============================================================
# 题目一: 00_angr_find
# ============================================================
def solve_00_angr_find(binary_path):
    """
    【题目分析】
    程序读取 8 字符密码，逐字符经 complex_function 变换后与硬编码字符串比较。
    正确输出 "Good Job."，错误输出 "Try again."
    
    【angr 策略: find + avoid】
    1. entry_state 从入口开始符号执行
    2. explore(find=Good_Job地址, avoid=Try_again地址) 自动搜索
    3. 找到后从 stdin dump 出 angr 为满足路径约束而构造的输入
    
    【核心知识点】
    - entry_state(): 创建从程序入口点开始的初始执行状态
    - explore(find=, avoid=): 引导符号执行器搜索/避开特定地址
    - posix.dumps(fd): 获取状态在指定文件描述符上的数据
    """
    print("=" * 60)
    print("题目一: 00_angr_find — find/avoid 目标地址搜索")
    print("=" * 60)
    
    project = angr.Project(binary_path)
    
    # 创建初始状态，添加符号填充选项避免未初始化内存问题
    initial_state = project.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    simulation = project.factory.simgr(initial_state)
    
    # 目标地址: push "Good Job." 参数后 call puts 的地址 (0x804867d)
    # 避免地址: push "Try again." 参数后 call puts 的地址 (0x8048672)
    simulation.explore(find=0x804867d, avoid=0x8048672)
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
        print(f"[+] 密码: {solution}")
        return solution
    else:
        raise Exception('未找到解')


# ============================================================
# 题目二: 08_angr_constraints
# ============================================================
def solve_08_angr_constraints(binary_path):
    """
    【题目分析】
    程序读取 16 字符密码，经 complex_function 变换后，
    由 check_equals_AUPDNNPROEZRJWKB 函数逐字符比较。
    
    【难点: 路径爆炸】
    check_equals_ 内部循环逐字符 if 判断，产生 2^16 = 65536 条分支，
    符号执行器会因搜索空间爆炸而无法在合理时间内完成。
    
    【angr 策略: SimProcedure Hook】
    用 angr 的 SimProcedure 机制 Hook 整个 check_equals_ 函数，
    替换为一条等价的符号表达式，避免逐字符分支:
    - 原函数: 循环 16 次 if (buf[i] == password[i]) num_correct++
    - Hook:  直接返回 claripy.If(buf == target, 1, 0)
    
    Z3 约束求解器可以在不展开循环的情况下直接求解这个等式。
    
    【核心知识点】
    - SimProcedure: angr 的函数级 Hook 机制
    - claripy.If(cond, true_val, false_val): 符号条件表达式
    - 路径爆炸的根本原因: 循环内的条件分支导致状态指数级增长
    """
    print("\n" + "=" * 60)
    print("题目二: 08_angr_constraints — Hook 规避路径爆炸")
    print("=" * 60)
    
    project = angr.Project(binary_path)
    
    # 定义 SimProcedure 替换 check_equals_AUPDNNPROEZRJWKB
    class CheckEqualsReplacement(angr.SimProcedure):
        def run(self, to_check, length):
            # 从内存加载 16 字节 buffer
            buffer_content = self.state.memory.load(to_check, 16)
            # 目标字符串（从函数名获取）
            target = 'AUPDNNPROEZRJWKB'
            # 返回符号比较结果，避免逐字符分支
            return claripy.If(
                buffer_content == target.encode(),
                claripy.BVV(1, 32),
                claripy.BVV(0, 32)
            )
    
    # Hook check_equals_ 函数（地址 0x8048565）
    project.hook(0x8048565, CheckEqualsReplacement())
    
    initial_state = project.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    simulation = project.factory.simgr(initial_state)
    
    def is_successful(state):
        return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())
    
    def should_abort(state):
        return b'Try again.' in state.posix.dumps(sys.stdout.fileno())
    
    simulation.explore(find=is_successful, avoid=should_abort)
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
        print(f"[+] 密码: {solution}")
        return solution
    else:
        raise Exception('未找到解')


# ============================================================
# 题目三: 09_angr_hooks
# ============================================================
def solve_09_angr_hooks(binary_path):
    """
    【题目分析】
    程序执行两轮输入验证:
    1. 读取 16 字符 -> complex_function 变换 -> check_equals_ 比较 -> 保存结果
    2. 读取另外 16 字符 -> complex_function 变换 -> strncmp 比较
    两轮都通过才输出 "Good Job."
    
    【难点】
    check_equals_ 同样会导致路径爆炸。
    但这次有两轮 scanf 输入，不能用 blank_state 跳过，
    必须让 angr 处理完整的输入流程。
    
    【angr 策略: SimProcedure Hook + 条件搜索】
    1. 从 entry_state 开始，angr 自动处理 scanf 的符号输入
    2. SimProcedure Hook check_equals_ 函数，避免路径爆炸
    3. 用 stdout 内容判断成功/失败路径
    
    【核心知识点】
    - SimProcedure 在 entry_state 模式下的工作方式
    - 多轮输入的符号执行处理
    - is_successful/should_abort 回调函数的灵活使用
    """
    print("\n" + "=" * 60)
    print("题目三: 09_angr_hooks — 多轮输入 + SimProcedure")
    print("=" * 60)
    
    project = angr.Project(binary_path)
    
    # 定义 SimProcedure 替换 check_equals_XYMKBKUHNIQYNQXE
    class CheckEqualsReplacement(angr.SimProcedure):
        def run(self, to_check, length):
            buffer_content = self.state.memory.load(to_check, 16)
            target = 'XYMKBKUHNIQYNQXE'
            return claripy.If(
                buffer_content == target.encode(),
                claripy.BVV(1, 32),
                claripy.BVV(0, 32)
            )
    
    # Hook check_equals_ 函数（地址 0x80485a5）
    project.hook(0x80485a5, CheckEqualsReplacement())
    
    initial_state = project.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    simulation = project.factory.simgr(initial_state)
    
    def is_successful(state):
        return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())
    
    def should_abort(state):
        return b'Try again.' in state.posix.dumps(sys.stdout.fileno())
    
    print("[*] 开始符号执行（两轮输入，需要较长时间）...")
    simulation.explore(find=is_successful, avoid=should_abort)
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
        print(f"[+] 输入（两行密码）:")
        for i, line in enumerate(solution.split('\n')):
            if line.strip():
                print(f"    第{i+1}轮: {line.strip()}")
        return solution
    else:
        raise Exception('未找到解')


# ============================================================
# 主程序
# ============================================================
if __name__ == '__main__':
    import os
    
    base_dir = '/Users/kingpong/.local/share/TeleAgent/TeleAgent的工作空间/.temp/angr_ctf/dist'
    
    results = {}
    
    # 题目一
    results['00'] = solve_00_angr_find(os.path.join(base_dir, '00_angr_find'))
    
    # 题目二
    results['08'] = solve_08_angr_constraints(os.path.join(base_dir, '08_angr_constraints'))
    
    # 题目三
    results['09'] = solve_09_angr_hooks(os.path.join(base_dir, '09_angr_hooks'))
    
    # 汇总
    print("\n" + "=" * 60)
    print("解题结果汇总")
    print("=" * 60)
    print(f"  00_angr_find:        {results['00'].strip()}")
    print(f"  08_angr_constraints: {results['08'].strip()}")
    print(f"  09_angr_hooks:       {results['09'].strip()}")
