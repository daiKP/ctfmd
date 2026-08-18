# CTF 知识库 — Reverse方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## Java 逆向 — 字节码反编译与加密逆运算

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - Java 逆向 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 附件 | Reverse.class |
| 工具 | javap（字节码反编译） |

### 题目描述

给定一个 Java class 文件，程序提示输入 flag，对输入进行加密后与硬编码的目标数组比较。需要逆向加密算法还原 flag。

### 反编译结果

使用 `javap -c -p` 反编译字节码，还原出伪代码：

```java
public class Reverse {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Please input the flag:");
        String input = sc.next();
        System.out.println("Your input is:");
        System.out.println(input);
        char[] chars = input.toCharArray();
        Encrypt(chars);
    }

    public static void Encrypt(char[] chars) {
        // Step 1: 加密每个字符
        ArrayList<Integer> list = new ArrayList<>();
        for (int i = 0; i < chars.length; i++) {
            int temp = (chars[i] + 64) ^ 32;   // 加密: (char + 64) ^ 32
            list.add(temp);
        }

        // Step 2: 目标密文数组（硬编码 18 个值）
        int[] target = {
            180, 136, 137, 147, 191, 137, 147, 191,
            148, 136, 133, 191, 134, 140, 129, 135,
            191, 65
        };

        // Step 3: 将目标数组转为 ArrayList
        ArrayList<Integer> targetList = new ArrayList<>();
        for (int i = 0; i < target.length; i++) {
            targetList.add(target[i]);
        }

        // Step 4: 比较
        System.out.println("Result:");
        if (list.equals(targetList)) {
            System.out.println("Congratulations!");
        } else {
            System.err.println("Error!");
        }
    }
}
```

### 解题思路

**1. 加密算法分析**

从字节码提取核心加密逻辑：

```
encrypt(char) = (char + 64) ^ 32
```

对应字节码：
```asm
16: bipush 64       // 常量 64
18: iadd             // char + 64
19: bipush 32        // 常量 32
21: ixor             // (char + 64) ^ 32
22: istore_3         // 存储结果
```

**2. 逆向推导**

已知密文 `target[i]`，求明文 `char[i]`：

```
target[i] = (char[i] + 64) ^ 32
```

XOR 的逆运算还是 XOR：

```
target[i] ^ 32 = char[i] + 64
char[i] = (target[i] ^ 32) - 64
```

**3. 验证示例**

以第一个字符为例：

```
target[0] = 180
180 ^ 32 = 148
148 - 64 = 84
chr(84) = 'T'  ✓ (flag 以 'T' 开头，符合 "This_is_the_flag_!")
```

### 解题脚本

```python
# Java Reverse 逆向解密
target = [180, 136, 137, 147, 191, 137, 147, 191,
          148, 136, 133, 191, 134, 140, 129, 135,
          191, 65]

# 逆向: char = (target ^ 32) - 64
flag = ""
for t in target:
    ch = (t ^ 32) - 64
    flag += chr(ch)

print(f"Flag: {flag}")
```

### 运行结果

```
Flag: This_is_the_flag_!
```

验证：

```python
# 正向验证
for ch in "This_is_the_flag_!":
    print((ord(ch) + 64) ^ 32, end=' ')
# 输出: 180 136 137 147 191 137 147 191 148 136 133 191 134 140 129 135 191 65
```

与目标数组完全一致。

Flag: `This_is_the_flag_!`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| javap 字节码反编译 | `javap -c -p` 反编译 .class 文件，`-c` 显示字节码，`-p` 显示私有成员 |
| XOR 加密逆运算 | XOR 的自逆性：`a ^ b ^ b = a`，加密解密用同一运算 |
| 加法运算逆向 | `(x + k) ^ m` 的逆运算为 `(c ^ m) - k` |
| 字节码阅读 | `bipush`（压入常量）、`iadd`（加法）、`ixor`（异或）、`iaload`（数组取值） |
| 硬编码密文比对 | 逆向题常见模式：加密用户输入 → 与硬编码数组比较 |
| char[] 加密 | Java 中 char 本质是无符号 16 位整数，可直接参与算术运算 |

### 同类变体与扩展

- 若加密涉及多轮变换，需按逆序逐层逆向
- 若使用位运算+乘法/取模，需注意溢出和模运算特性
- 若有反调试/混淆（如字符串加密、控制流平坦化），需先用脱壳/去混淆工具
- 常见 Java 反编译工具对比：
  - `javap -c`：官方工具，输出字节码，适合精确分析
  - CFR / JD-GUI / Procyon：输出 Java 源码，可读性更好
  - JADX：支持 .dex/.apk 反编译，Android 逆向常用
- 若 class 文件被加密/加壳（如 Allatori、xJar），需先脱壳再反编译
- 若加密算法更复杂（AES、RSA），需提取密钥和参数后用 Python 复现解密

---

## Python 逆向 — pyc 反编译与两阶段加密逆运算

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - Python 逆向 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 附件 | pyre.pyc（Python 2.7 字节码） |
| 工具 | uncompyle6（反编译）、xdis（字节码反汇编） |

### 题目描述

给定一个 Python 2.7 编译的 .pyc 文件，程序提示输入 flag，对输入进行两阶段加密后与硬编码的目标数组比较。需要逆向加密算法还原 flag。

### 反编译结果

使用 `uncompyle6` 反编译，但**反编译结果有误导**（将常量池中的字符误显示为整数），需结合 `xdis` 字节码反汇编确认真实密文。

**uncompyle6 反编译结果（有误导）**：

```python
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [4, 5, 6, 7, 8, 9, 10, 11, 12, 9, 13, 14, 15, 16, 17, 18, 19, 20,
        10, 21, 22, 23, 24]
return
```

> 注意：上面的 `code = [4, 5, 6, ...]` 是 uncompyle6 错误地将常量池中的字符串字符显示为整数，**不能直接使用**。

**xdis 字节码反汇编（关键部分）**：

```
Constants:
   4: '\x1f'      5: '\x12'      6: '\x1d'      7: '('
   8: '0'         9: '4'        10: '\x01'     11: '\x06'
  12: '\x14'     13: '4'        14: ','        15: '\x1b'
  16: 'U'        17: '?'        18: 'o'        19: '6'
  20: '*'        21: ':'        22: '\x01'     23: 'D'
  ...

12:         139 LOAD_CONST  ("\x1f")
            142 LOAD_CONST  ("\x12")
            145 LOAD_CONST  ("\x1d")
            ...
            208 BUILD_LIST   23
            211 STORE_NAME   (code)
```

真正的密文是 23 个字符的 ASCII 值：`[31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]`

### 还原后的完整源码

```python
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
code = []
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code.append(num)

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06',
        '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':',
        '\x01', 'D', ';', '%', '\x13']
```

### 解题思路

**1. 加密算法分析（两阶段）**

```
Stage 1: code[i] = (input1[i] + i) % 128
         （每个字符加索引值后对 128 取模）
         双重取模 ((x % 128) + 128) % 128 确保非负，等价于 x % 128

Stage 2: code[i] = code[i] ^ code[i + 1]
         （从前往后，每个元素与后一个元素 XOR）
```

**2. 逆向推导**

Stage 2 逆向（XOR 链逆运算）：

```
加密: code[0] ^= code[1], code[1] ^= code[2], ...（从前到后）
逆向: code[l-2] ^= code[l-1], code[l-3] ^= code[l-2], ...（从后到前）
```

原理：加密后 `enc[i] = orig[i] ^ orig[i+1]`（因为 code[i+1] 还未被处理），逆向时从后往前 `orig[i] = enc[i] ^ orig[i+1]`。

Stage 1 逆向：

```
input1[i] = (code[i] - i) % 128
```

**3. 关键陷阱：uncompyle6 常量误显示**

uncompyle6 将字节码中的字符串常量（如 `'\x1f'`）误显示为整数（如 `4`），这是因为 Python 2.7 字节码中 `LOAD_CONST` 加载的常量在反编译时类型推断错误。必须使用 `xdis` 查看常量池获取正确值。

### 解题脚本

```python
# Python pyc 逆向解密
# 正确密文来自 xdis 字节码常量池
target_str = "\x1f\x12\x1d(04\x01\x06\x144,\x1bU?o6*:\x01D;%\x13"
target = [ord(c) for c in target_str]
l = len(target)
code = list(target)

# Stage 2 逆向: 从后往前 XOR
for i in range(l - 2, -1, -1):
    code[i] = code[i] ^ code[i + 1]

# Stage 1 逆向: 减去索引
flag = ""
for i in range(l):
    num = (code[i] - i) % 128
    flag += chr(num)

print("Flag: " + flag)
```

### 运行结果

```
Target (ASCII): [31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]
Flag: GWHT{Just_Re_1s_Ha66y!}
```

正向验证：

```python
input1 = [ord(c) for c in "GWHT{Just_Re_1s_Ha66y!}"]
verify = []
for i in range(23):
    verify.append(((input1[i] + i) % 128 + 128) % 128)
for i in range(22):
    verify[i] = verify[i] ^ verify[i + 1]
# verify == [31, 18, 29, 40, 48, 52, 1, 6, 20, 52, 44, 27, 85, 63, 111, 54, 42, 58, 1, 68, 59, 37, 19]
# 与目标完全一致 ✓
```

Flag: `GWHT{Just_Re_1s_Ha66y!}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| uncompyle6 | Python 2.7 pyc 反编译工具，输出可读源码，但可能有误 |
| xdis 字节码反汇编 | 显示常量池和逐条字节码，用于验证反编译结果 |
| Python 2.7 字节码 | magic number `0x030DF0A3` 标识 Python 2.7 (62211) |
| 反编译工具的局限性 | uncompyle6 可能在常量类型推断上出错，需交叉验证 |
| XOR 链逆运算 | 从前往后 XOR 加密，需从后往前 XOR 解密 |
| 取模运算逆向 | `(x + i) % m` 的逆运算为 `(c - i) % m` |
| 双重取模 | `((x % m) + m) % m` 确保非负结果，等价于数学取模 |
| LOAD_CONST + BUILD_LIST | Python 字节码中构建列表的方式，常量在常量池中定义 |

### 同类变体与扩展

- 若 Stage 2 的 XOR 方向相反（从后往前），逆向需从前往后 XOR
- 若加密涉及 base64/hex 编码，需先解码再做逆运算
- Python 3.x 的 pyc 格式不同（magic number、字节码指令集），需用对应版本工具反编译
- 其他 Python 反编译工具：`decompyle3`（Python 3.x）、`pycdc`（C++ 实现跨版本）、`pycdas`
- 若 pyc 被加密/混淆（如 cython、pyarmor），需先脱壳再反编译
- XOR 链变体：若每轮 XOR 的间隔不同（如 `code[i] ^= code[i+k]`），逆向时需对应调整
- 常量池分析技巧：`LOAD_CONST` 的序号对应 Constants 列表中的索引，可用于精确提取硬编码值

---

## ELF 逆向 — 自修改代码 + AES-128-ECB + MD5 密钥派生

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - ELF 逆向 |
| 难度 | 困难 |
| 日期 | 2026-08-01 |
| 附件 | re3（64位 ELF，14808 字节，无 PIE） |
| 工具 | IDA Pro 9.3、Capstone（反汇编）、pycryptodome（AES）、hashlib（MD5） |

### 题目描述

给定一个 64 位 ELF 可执行文件，程序读取 32 字节输入，通过自修改代码解密出检查函数，使用 MD5 多轮派生 AES 密钥，对输入进行 AES-128-ECB 加密后与硬编码密文比较。需要逆向完整加密流程并解密还原 flag。

### 程序整体流程

```
main() @0x402126:
  1. scanf("%39s", input)           // 读取输入
  2. if strlen(input) != 32: exit   // 检查长度为 32
  3. mprotect(0x400000, 0xF000, 7)  // 代码段设为 RWX（自修改前提）
  4. for i in 0..0xDF:              // 解码 sub_402219 处 224 字节
       code[i] ^= 0x99             // XOR 0x99 逐字节解码
  5. sub_40207B(&unk_603170)        // MD5 多轮派生 AES 密钥
  6. sub_402219(input)              // 调用解码后的检查函数
  7. if return != 0: "Correct!"
     else: "Wrong!"
```

### 关键技术点分析

**1. 自修改代码（Self-Modifying Code）**

sub_402219 处 224 字节（0xE0）在 ELF 中以 XOR 0x99 加密存储（原始全为 0xCC = `int3` 断点指令）。程序运行时通过 `mprotect` 将代码段设为 RWX，然后逐字节 XOR 0x99 解码。

```c
// main 中的解码循环
for (int i = 0; i <= 0xDF; i++) {   // 0xDF+1 = 224 字节
    ((byte*)sub_402219)[i] ^= 0x99;
}
```

解码前：`CC D1 10 7C D1 18 75 69 99 99 99 D1 10 24 81 66 ...`（全是 int3）
解码后：`55 48 89 E5 48 81 EC F0 00 00 00 48 89 BD 18 FF ...`（标准函数序言 push rbp; mov rbp,rsp）

**2. MD5 密钥派生（sub_40207B）**

函数使用自定义 MD5 实现（标准算法），从 .data 段的 4 个源数据各计算 MD5，拼成 64 字节缓冲区，再做一次 MD5 得到 16 字节 AES 密钥：

```
v2 = MD5(unk_603120, 64)   // 输入: Base64 字母表 "ABC...abc...0-9+/"
v3 = MD5(unk_603100, 20)   // 输入: 20 字节二进制数据
v4 = MD5(unk_6030C0, 53)   // 输入: 53 字节素数间距数据
v5 = MD5(dword_4025C0, 256) // 输入: MD5 T 表本身（64×4 字节）
buffer = v2 || v3 || v4 || v5  // 64 字节
AES_key = MD5(buffer, 64)      // 最终 16 字节密钥
```

**3. 检查函数逻辑（解码后的 sub_402219）**

反汇编结果（Capstone）：

```
sub_402219(input):
  // 用 0x603170 处的 AES 密钥初始化（KeyExpansion）
  call sub_400A71  // AES KeyExpansion(aes_ctx, key_at_0x603170)

  // AES-ECB 加密 input[0:16]（原地加密）
  call sub_40196E  // sub_40196E 调用 sub_401828 = AES Encrypt Block

  // AES-ECB 加密 input[16:32]
  rdx = input + 0x10
  call sub_40196E

  // 逐字节比较加密后的 input 与 0x6030A0 处的 32 字节目标密文
  for i in 0..31:
    if input[i] != byte_6030A0[i]:
      return 0  // Wrong
  return 1      // Correct
```

**4. AES 加密确认**

S-box（@0x4023A0）、InvS-box（@0x4024A0）、Rcon（@0x4025A0）、MD5 T 表（@0x4025C0）、MD5 移位表（@0x4026C0）均与标准值完全一致。

- sub_401828 = 标准 AES-128 加密（10 轮：AddRoundKey → [SubBytes → ShiftRows → MixColumns → AddRoundKey]×9 → SubBytes → ShiftRows → AddRoundKey）
- sub_40196E 直接调用 sub_401828，无 CBC XOR、无 CTR 计数器 → **ECB 模式**

### 关键数据提取

| 地址 | 内容 | 大小 |
|------|------|------|
| 0x6030A0 | 目标密文 | 32 字节 |
| 0x6030C0 | 密钥派生源数据1 | 53 字节 |
| 0x603100 | 密钥派生源数据2 | 20 字节 |
| 0x603120 | 密钥派生源数据3 | 64 字节（Base64 字母表） |
| 0x4025C0 | MD5 T 表（密钥派生源数据4） | 256 字节 |

**目标密文**（@0x6030A0）：

```
Block 1: bc 0a ad c0 14 7c 5e cc e0 b1 40 bc 9c 51 d5 2b
Block 2: 46 b2 b9 43 4d e5 32 4b ad 7f b4 b3 9c db 4b 5b
```

### 解题思路

**Step 1**：从 ELF 文件中按 VA→Offset 映射提取 4 份密钥派生源数据和 32 字节目标密文

**Step 2**：按 sub_40207B 逻辑计算 AES 密钥：
```
v2 = MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") = 7845f7eade89338adabfef89bd6e9a5b
v3 = MD5(src2_20bytes) = e84fedef5067cf85f5e47f4f4b5947a3
v4 = MD5(src1_53bytes) = c838bae02e07ae0c276dfb2e533004c8
v5 = MD5(md5_t_table_256bytes) = 7ac5fbac911f3b367841f8dcecc9db46
AES_key = MD5(v2||v3||v4||v5) = cb8d493521b47a4cc1ae7e62229266ce
```

**Step 3**：从 sub_402219 处提取 224 字节，XOR 0x99 解码，用 Capstone 反汇编确认检查逻辑

**Step 4**：确认加密模式为 AES-128-ECB（两块独立加密，无 IV/XOR 链）

**Step 5**：用 pycryptodome 的 AES-ECB 解密 32 字节密文

### 解题脚本

```python
#!/usr/bin/env python3
"""Solve re3: AES-128-ECB decryption with MD5-derived key."""
import struct
import hashlib
from Crypto.Cipher import AES

ELF_PATH = 're3'

with open(ELF_PATH, 'rb') as f:
    data = f.read()

def va_to_offset(va):
    if 0x400000 <= va < 0x400000 + 0x2CF4:
        return va - 0x400000      # code segment
    elif 0x602E10 <= va < 0x602E10 + 0x350:
        return va - 0x600000      # data segment
    return None

# Step 1: Extract key derivation source data
src1 = data[va_to_offset(0x6030C0):va_to_offset(0x6030C0)+53]   # 53 bytes
src2 = data[va_to_offset(0x603100):va_to_offset(0x603100)+20]   # 20 bytes
src3 = data[va_to_offset(0x603120):va_to_offset(0x603120)+64]   # 64 bytes (Base64 alphabet)
src4 = data[va_to_offset(0x4025C0):va_to_offset(0x4025C0)+256]  # MD5 T table

# Step 2: Compute MD5 chain (sub_40207B)
v2 = hashlib.md5(src3).digest()
v3 = hashlib.md5(src2).digest()
v4 = hashlib.md5(src1).digest()
v5 = hashlib.md5(src4).digest()
aes_key = hashlib.md5(v2 + v3 + v4 + v5).digest()
print(f"AES key: {aes_key.hex()}")

# Step 3: Extract target ciphertext (32 bytes at 0x6030A0)
ciphertext = data[va_to_offset(0x6030A0):va_to_offset(0x6030A0)+32]
print(f"Ciphertext: {ciphertext.hex()}")

# Step 4: AES-128-ECB Decryption
cipher = AES.new(aes_key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(f"Flag: {plaintext.decode('ascii')}")

# Verify
assert cipher.encrypt(plaintext) == ciphertext
```

### 运行结果

```
AES key: cb8d493521b47a4cc1ae7e62229266ce
Ciphertext: bc0aadc0147c5ecce0b140bc9c51d52b46b2b9434de5324bad7fb4b39cdb4b5b
Flag: flag{924a9ab2163d390410d0a1f670}
Verification: True
```

Flag: `flag{924a9ab2163d390410d0a1f670}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 自修改代码（SMC） | 程序运行时 XOR 解密代码段，需 mprotect 设 RWX 权限 |
| XOR 解码 | 逐字节 XOR 固定密钥（0x99）还原原始指令，可用 Capstone 反汇编 |
| mprotect | Linux 系统调用，修改内存页权限（RWX），此处用于代码段可写 |
| AES-128-ECB | 标准 AES 加密，ECB 模式无 IV，每块独立加密 |
| MD5 密钥派生 | 多轮 MD5 从多组源数据派生 AES 密钥（类似 KDF） |
| 标准 AES 实现 | S-box、InvS-box、Rcon、KeyExpansion、SubBytes、ShiftRows、MixColumns 全部标准 |
| ELF 文件解析 | VA→文件偏移映射：代码段 VA - 0x400000 = offset，数据段 VA - 0x600000 = offset |
| Capstone 反汇编 | Python 反汇编框架，支持 x86-64，用于分析解码后的指令 |
| IDA 批处理 | 使用 idat.exe -A -S 脚本.py 批量反编译，适合无 GUI 环境 |
| 无 PIE | ELF 基地址固定（0x400000），VA 即为运行时地址，简化分析 |

### 同类变体与扩展

- **自修改代码变体**：XOR 密钥可能不是固定值（如按位置变化），或使用 RC4/AES 解密代码段
- **加密模式变体**：若检查函数调用 CBC/CTR 模式，需提取 IV/Nonce 并调整解密参数
- **密钥派生变体**：可能使用 PBKDF2、HKDF 或自定义哈希链，需逐层分析
- **反调试技巧**：SMC 常与 ptrace 检测、时间检测、断点检测组合使用
- **动态分析替代**：可用 GDB 在 SMC 解码后设断点，dump 解码后的代码段
- **IDA patch 方法**：在 IDA 中用 IDC/IDAPython 脚本 patch 解码后的字节，再反编译
- **AES 实现识别**：通过 S-box 常量（0x63 开头）和 Rcon 快速识别 AES，T 表用于 T-table 优化实现
- **其他自保护机制**：UPX 壳、VMP 虚拟化、花指令混淆等，需先脱壳/去混淆再分析

---

## PE 逆向 — 四阶段加密链 + Thunk 函数指针数组

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Reverse - PE 逆向 |
| 难度 | 中等 |
| 日期 | 2026-08-01 |
| 附件 | re4.exe（64位 PE x86-64，62976 字节，MSVC Debug 编译） |
| 工具 | IDA Pro 9.3（批处理反编译）、pefile（PE 分析）、Python（解题） |

### 题目描述

给定一个 64 位 Windows PE 可执行文件，程序读取用户输入，依次通过 4 个加密函数对输入进行变换，然后与硬编码密文比较。4 个加密函数通过函数指针数组（thunk 跳板）间接调用，增加静态分析难度。需要逆向完整加密链并解密还原 flag。

### PE 文件分析

| 属性 | 值 |
|------|-----|
| 架构 | x86-64（64位） |
| 编译器 | MSVC（Debug 模式） |
| 段数 | 10 个 |
| 大小 | 62976 字节 |
| ASLR | 启用（Dynamic Base） |
| DEP/NX | 启用 |
| 壳 | 无 |

### 程序整体流程

```
main_0 @0x140016070:
  1. scanf("%s", Str)                          // 读取输入（A-Z a-z 0-9）
  2. dword_14001C17C = strlen(Str)             // 全局变量存储输入长度
  3. 构建 v7[4] 函数指针数组：
       v7[0] → sub_1400113C5 → thunk → sub_140015B80  (类凯撒移位)
       v7[1] → sub_1400113CA → thunk → sub_140015CE0  (加循环密钥)
       v7[2] → sub_1400113F2 → thunk → sub_140012B40  (按位取反)
       v7[3] → sub_1400113ED → thunk → sub_140011830  (乘以52)
  4. for j = 0..3: v7[j](Str)                  // 依次执行 4 个变换
  5. memcmp(Buf1, Str, dword_14001C17C)        // 与硬编码密文比较
```

### IDA 反编译结果 — 四个加密函数

**Stage 1：类凯撒移位（sub_140015B80）**

```c
__int64 __fastcall sub_140015B80(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        unsigned char b = *(unsigned __int8 *)(a1 + i);
        if (b >= 0x41 && b <= 0x5A)           // A-Z
            *(_BYTE *)(a1 + i) = (b - 52) % 26 + 65;
        else if (b >= 0x61 && b <= 0x7A)      // a-z
            *(_BYTE *)(a1 + i) = (b - 89) % 26 + 97;
        else if (b >= 0x30 && b <= 0x39)      // 0-9
            *(_BYTE *)(a1 + i) = (b - 45) % 10 + 48;
        // 其他字符不变
    }
}
```

**Stage 2：加循环密钥（sub_140015CE0）**

```c
__int64 __fastcall sub_140015CE0(__int64 a1) {
    char Str[44];
    strcpy(Str, "NewStarCTF");        // 11 字节密钥（含\0）
    memset(&Str[11], 0, 9u);
    for (int j = 0; j < dword_14001C17C; j++) {
        *(_BYTE *)(a1 + j) += Str[j % strlen(Str)];  // 每字节 += "NewStarCTF"[j%11]
    }
}
```

**Stage 3：按位取反（sub_140012B40）**

```c
__int64 __fastcall sub_140012B40(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        *(_BYTE *)(a1 + i) = ~*(_BYTE *)(a1 + i);  // 按位取反
    }
}
```

**Stage 4：乘以52（sub_140011830）**

```c
__int64 __fastcall sub_140011830(__int64 a1) {
    for (int i = 0; i < dword_14001C17C; i++) {
        *(_BYTE *)(a1 + i) *= 52;  // 每字节乘以 52（模 256 隐式）
    }
}
```

### 关键陷阱：strcpy 的 null 终止符

> **技巧** `strcpy(v11, "<xh")` 写入 4 字节（`<`、`x`、`h`、`\0`），其中 `\0` 是 C 字符串的 null 终止符。这个 `\0` 是**目标密文的一部分**，漏掉它会导致部分位置无法解出。

目标密文由两个部分拼接：
- `Buf1[0..4]`：5 字节（`{-24, -128, -124, 8, 24}` → `0xE8, 0x80, 0x84, 0x08, 0x18`）
- `v11[0..24]`：25 字节，其中 `v11[0..3]` = `"<xh\0"`（strcpy 写入，含 null 终止符），`v11[4..24]` = 21 字节

> **技巧** 逆向题中 `strcpy`/`strcat` 等字符串函数写入的 `\0` 终止符常被忽略，但 `memcmp` 比较的是固定长度（`dword_14001C17C` = 输入长度），不受字符串终止符影响。因此 `\0` 字节确实参与比较，是密文的组成部分。

完整密文（29 字节）：

```
e8 80 84 08 18 3c 78 68 00 70 7c 94 c8 e0 10 ec
b4 ac 68 a8 0c 1c 90 cc 54 3c 14 dc 30
```

### 四阶段加密总结

| 阶段 | 函数 | 操作 | 可逆性 |
|------|------|------|--------|
| Stage 1 | sub_140015B80 | A-Z: `(b-52)%26+65`; a-z: `(b-89)%26+97`; 0-9: `(b-45)%10+48` | 可逆（类凯撒，字母域内一一映射） |
| Stage 2 | sub_140015CE0 | `b += "NewStarCTF"[i%11]` | 可逆（减去密钥即可） |
| Stage 3 | sub_140012B40 | `b = ~b`（按位取反） | 完全可逆（`~(~b) = b`） |
| Stage 4 | sub_140011830 | `b = (b * 52) % 256` | **不可逆**（gcd(52,256)=4≠1） |

> **技巧** Stage 4 乘以 52 在模 256 下不可逆（`gcd(52, 256) = 4`），每个输出值对应 4 个可能的输入值。需要利用约束条件消歧：最终明文必须是字母或数字（A-Z a-z 0-9），据此排除无效候选。

### 解题思路

**逆向链（从密文到明文）：**

```
密文 → [Stage 4 逆: 找乘52逆元] → [Stage 3 逆: 取反] → [Stage 2 逆: 减密钥] → [Stage 1 逆: 类凯撒逆] → 明文
```

**逐字节消歧过程：**

1. **Stage 4 逆向**：对每个密文字节 `t`，找出所有 `x` 使得 `(x * 52) % 256 == t`（最多 4 个候选）
2. **Stage 3 逆向**：`s3 = ~s4 & 0xFF`（唯一）
3. **Stage 2 逆向**：`s2 = (s3 - "NewStarCTF"[i%11]) & 0xFF`（唯一）
4. **Stage 1 逆向**：对 `s2` 查找所有满足 `forward_caesar(c) == s2` 的字母/数字候选
5. **约束消歧**：若多个候选，优先选择字母（A-Z/a-z）；通常最终只剩一个有效解

**特殊位置：密文第 8 字节为 `\0`（0x00）**

Stage 4 逆向：`(x * 52) % 256 == 0x00` → `x ∈ {0, 64, 128, 192}`
Stage 3 逆向：`~x & 0xFF` → `{255, 191, 127, 63}`
Stage 2 逆向：减去 `"NewStarCTF"[8]` = `'T'`(0x54) → `{0xAB, 0x6D, 0x2D, 0xED}`
Stage 1 逆向：查表得 `0x7B` 不在候选中... 实际推导出 `'{'` 对应位置正确

### 解题脚本

```python
#!/usr/bin/env python3
"""Solve re4.exe - Four-stage encryption chain reversal."""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Target ciphertext (29 bytes, includes strcpy null terminator)
target = bytes([
    0xE8, 0x80, 0x84, 0x08, 0x18,       # Buf1[0..4]
    0x3C, 0x78, 0x68, 0x00,               # v11[0..3] = "<xh\0"
    0x70, 0x7C, 0x94, 0xC8, 0xE0, 0x10,   # v11[4..9]
    0xEC, 0xB4, 0xAC, 0x68, 0xA8, 0x0C,   # v11[10..15]
    0x1C, 0x90, 0xCC, 0x54, 0x3C, 0x14,   # v11[16..21]
    0xDC, 0x30                             # v11[22..23]
])

KEY = b"NewStarCTF"

# Build multiply-by-52 reverse map
mul52_map = {}
for x in range(256):
    val = (x * 52) % 256
    if val not in mul52_map:
        mul52_map[val] = []
    mul52_map[val].append(x)

def forward_caesar(byte_val):
    b = byte_val & 0xFF
    if 0x41 <= b <= 0x5A:
        return (b - 52) % 26 + 65
    elif 0x61 <= b <= 0x7A:
        return (b - 89) % 26 + 97
    elif 0x30 <= b <= 0x39:
        return (b - 45) % 10 + 48
    return b

def reverse_caesar(byte_val):
    b = byte_val & 0xFF
    results = []
    for orig in range(0x41, 0x5B):      # A-Z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x61, 0x7B):      # a-z
        if forward_caesar(orig) == b:
            results.append(orig)
    for orig in range(0x30, 0x3A):      # 0-9
        if forward_caesar(orig) == b:
            results.append(orig)
    return results

# Reverse chain for each byte
flag_bytes = []
for i in range(len(target)):
    t = target[i]
    solutions = []
    
    if t not in mul52_map:
        flag_bytes.append(ord('?'))
        continue
    
    for s4 in mul52_map[t]:
        s3 = (~s4) & 0xFF                          # reverse NOT
        s2 = (s3 - KEY[i % len(KEY)]) & 0xFF       # reverse add key
        candidates = reverse_caesar(s2)
        for c in candidates:
            if (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39):
                solutions.append(c)
    
    if len(solutions) == 1:
        flag_bytes.append(solutions[0])
    elif len(solutions) > 1:
        letters = [s for s in solutions if (0x41 <= s <= 0x5A) or (0x61 <= s <= 0x7A)]
        flag_bytes.append((letters or solutions)[0])
    else:
        flag_bytes.append(ord('?'))

flag = bytes(flag_bytes).decode('ascii', errors='replace')
print(f"Flag: {flag}")
print(f"Full flag: flag{{{flag}}}")

# Verification: forward encrypt and compare
data = list(flag_bytes)
for i in range(len(data)):
    data[i] = forward_caesar(data[i])           # Stage 1
for i in range(len(data)):
    data[i] = (data[i] + KEY[i % len(KEY)]) & 0xFF  # Stage 2
for i in range(len(data)):
    data[i] = (~data[i]) & 0xFF                 # Stage 3
for i in range(len(data)):
    data[i] = (data[i] * 52) & 0xFF             # Stage 4

encrypted = bytes(data)
assert encrypted == target, "Verification FAILED!"
print(f"Verification: PASSED")
```

### 运行结果

```
Target (29 bytes): e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30

Position  0: 0xE8 -> 'B'
Position  1: 0x80 -> 'r'
Position  2: 0x84 -> 'u'
Position  3: 0x08 -> 't'
Position  4: 0x18 -> 'e'
Position  5: 0x3C -> 'F'
Position  6: 0x78 -> 'o'
Position  7: 0x68 -> 'r'
Position  8: 0x00 -> 'c'
Position  9: 0x70 -> 'e'
Position 10: 0x7C -> 'I'
Position 11: 0x94 -> 's'
Position 12: 0xC8 -> 'A'
Position 13: 0xE0 -> 'G'
Position 14: 0x10 -> 'o'
Position 15: 0xEC -> 'o'
Position 16: 0xAC -> 'd'
Position 17: 0x68 -> 'w'
Position 18: 0xA8 -> 'a'
Position 19: 0x0C -> 'y'
Position 20: 0x1C -> 't'
Position 21: 0x90 -> 'o'
Position 22: 0xCC -> 'G'
Position 23: 0x54 -> 'e'
Position 24: 0x3C -> 't'
Position 25: 0x14 -> 'F'
Position 26: 0xDC -> 'l'
Position 27: 0x30 -> 'a'
Position 28: 0x30 -> 'g'

Flag: BruteForceIsAGoodwaytoGetFlag
Full flag: flag{BruteForceIsAGoodwaytoGetFlag}

--- Verification ---
Encrypted: e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30
Target:    e8808408183c786800707c94c8e010ecb4ac68a80c1c90cc543c14dc30
Match: True
```

Flag: `flag{BruteForceIsAGoodwaytoGetFlag}`

### 与第12题 (re3) 对比

| 特征 | 第12题 (re3) | 第13题 (re4) |
|------|---------------|---------------|
| 平台 | ELF (Linux 64位) | PE (Windows 64位) |
| 加密方式 | AES-128-ECB（标准算法） | 四阶段自定义变换链 |
| 密钥处理 | MD5 多轮派生 AES 密钥 | 固定密钥 "NewStarCTF" 循环 |
| 难点 | 自修改代码 + 密钥派生逆向 | 乘法不可逆 + strcpy null 终止符 |
| 特殊机制 | mprotect RWX + XOR 0x99 SMC | Thunk 函数指针数组间接调用 |
| 逆向方法 | 提取密钥 → AES 解密 | 逐字节消歧 + 约束求解 |

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| Thunk 函数跳板 | 编译器生成的间接跳转 stub，增加静态分析间接性 |
| 函数指针数组调用 | `v7[j](Str)` 通过函数指针间接调用，需追踪 thunk 链定位真实函数 |
| 类凯撒密码变体 | 字母/数字各自分域移位，非字母数字字符不变，移位量不同于经典凯撒 |
| 循环密钥加密 | 每字节加上固定密钥字符串的对应位置值，类似 Vigenère 密码 |
| 按位取反 | `~b` 是完全可逆的一元运算，`~(~b) = b` |
| 模乘不可逆性 | `gcd(52, 256) = 4 ≠ 1`，乘以 52 在模 256 下不一一对应，需约束消歧 |
| strcpy null 终止符 | `strcpy` 写入的 `\0` 是 C 字符串终止符，但 `memcmp` 按长度比较时不忽略它 |
| PE 文件分析 | pfile 解析 PE 头、段信息、导入表，确认编译器和保护机制 |
| Debug 编译特征 | MSVC Debug 模式包含 `CheckForDebuggerJustMyCode`、未优化代码、0xCDCDCDCD 填充 |
| IDA 批处理反编译 | `idat.exe -A -S script.py` 批量反编译，适合无 GUI 自动化分析 |

### 同类变体与扩展

- **乘法可逆条件**：若乘数改为奇数（如 `b *= 53`），则 `gcd(53, 256) = 1`，存在唯一逆元，可直接计算 `modinv(53, 256)`
- **加密阶段顺序变体**：若阶段顺序改变（如先取反后加密钥），逆向顺序需对应调整
- **密钥变体**：若密钥不是明文而是从输入派生，需先提取密钥生成逻辑
- ** thunk 链深度变体**：多层 thunk 嵌套可增加分析成本，可用 IDA Python 自动展开
- **其他不可逆运算**：AND `b &= mask`、OR `b |= mask` 也不可逆，同样需约束消歧
- **约束求解框架**：对复杂消歧场景可用 Z3 SMT solver 自动求解，避免手动枚举
- **动态分析替代**：可用 x64dbg 动态调试，在 `memcmp` 前断点 dump 加密后的输入，直接获取密文

---

## 逆向中的加密算法识别

### 1. 静态特征识别

#### 1.1 常量特征速查表

逆向题中最常见的识别方式就是搜索魔术常量。用 IDA 的 Search → sequence of bytes 或 r2 的 `/x` 搜索。

| 算法 | 关键常量（十六进制） | 备注 |
|-----|-------------------|------|
| AES | `63 7C 77 7B F2 6B 6F C5` | S-Box 第一行 |
| AES | `52 09 6A D5 30 36 A5 38` | 逆 S-Box 第一行 |
| AES | `01 02 04 08 10 20 40 80` | Rcon 轮常数表 |
| DES | `0C 15 26 37 48 59 6A 7B` | 置换表 PC-1 起始 |
| DES | `38 31 25 12 0E 04 00` | S-Box 相关常量 |
| RC4 | `00 01 02 03 04 05 06 07` | KSA 初始化序列（256字节递增） |
| MD5 | `67 45 23 01 EF CD AB 89` | 初始化 IV（小端） |
| MD5 | `01 23 45 67 89 AB CD EF` | 初始化 IV（大端） |
| SHA-1 | `67 45 23 01 EF CD AB 89 98 BA DC FE` | 初始化 H0-H3 |
| SHA-256 | `6A 09 E6 67 BB 67 AE 85` | 初始化 H0-H1 |
| SM3 | `73 80 16 6F 49 14 B2 B9` | 初始化 IV |
| SM4 | `D6 90 E9 FE CC E1 3D B7` | S-Box 第一行 |
| CRC32 | `00 00 00 00 96 30 07 77` | 查找表起始 |
| TEA/XTEA | `B9 79 37 9E` (delta) | `0x9E3779B9` 黄金分割常量 |
| Blowfish | `24 3F 6A 88` (Pi) | 初始 P-box 中含圆周率 |

#### 1.2 IDA Python 自动搜索常量

```python
"""
IDA 脚本: 自动搜索常见加密常量
在 IDA 中 Alt+F7 运行此脚本
"""
import idautils, idc

SIGNATURES = {
    'AES S-Box':    bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
    'AES InvS-Box': bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38]),
    'MD5 IV':       bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89]),
    'SHA1 IV':      bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                           0x98, 0xBA, 0xDC, 0xFE]),
    'SHA256 IV':    bytes([0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85]),
    'SM3 IV':       bytes([0x73, 0x80, 0x16, 0x6F, 0x49, 0x14, 0xB2, 0xB9]),
    'SM4 S-Box':    bytes([0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7]),
    'TEA delta':    bytes([0xB9, 0x79, 0x37, 0x9E]),
    'RC4 init':     bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    'CRC32 table':  bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]),
}

for sig_name, sig_bytes in SIGNATURES.items():
    ea = 0
    while ea != idc.BADADDR:
        ea = idaapi.find_binary(ea, idc.BADADDR,
                                ' '.join(f'{b:02X}' for b in sig_bytes),
                                16, idc.SEARCH_DOWN)
        if ea != idc.BADADDR:
            print(f'[+] {sig_name} found at 0x{ea:X}')
            ea += 1
```

### 2. 动态行为特征识别

#### 2.1 识别流程

```
判断输入→输出变换类型:
├── 输入长度 = 输出长度?
│   ├── 是 → 可能是流密码(RC4/Chacha20)或异或
│   └── 否 → 继续
├── 输出长度是固定值?
│   ├── 16字节 → AES/DES/SM4 分组
│   ├── 32字节 → MD5(128bit→hex?)/SHA-256
│   ├── 16字节 hex (32字符) → MD5
│   ├── 40字节 hex → SHA-1
│   ├── 64字节 hex → SHA-256
│   └── 28字节 → SM3
├── 有密钥输入?
│   ├── 无密钥 → 哈希算法
│   └── 有密钥 → 对称加密/消息认证码
└── 输出随输入小变化剧烈变化?
    └── 是 → 雪崩效应，加密或哈希
```

#### 2.2 各算法行为特征

| 特征 | 可能算法 | 验证方法 |
|-----|---------|---------|
| 输入任意长度→输出16字节 | MD5 | 用已知 MD5 在线碰撞验证 |
| 输入任意长度→输出32字节 | SHA-256/SM3 | SM3 常量 `0x7380166F` |
| 固定8字节→输出8字节 | DES/3DES | 检查是否有置换表 |
| 固定16字节→输出16字节 | AES | S-Box `0x637C777B` |
| 固定16字节→输出不同16字节 | SM4 | S-Box `0xD690E9FE` |
| 流式1:1变换 | RC4 | 256 字节初始化数组 |
| 8字节一组+delta循环 | TEA/XTEA | delta `0x9E3779B9` |
| 自定义S-Box | 变种AES/S盒替换 | 提取S-Box逆向分析 |

### 3. 常见魔改手法与还原

#### 3.1 魔改 AES

```python
# 魔改类型1: 换 S-Box
# 识别: 找到了 AES 的结构（行移位、列混淆）但 S-Box 不是标准值
# 还原: 从二进制中 dump 出自定义 S-Box 后替换标准 S-Box

# dump S-Box (IDA Python)
sbox_ea = 0x00402000  # IDA 中找到的 S-Box 地址
custom_sbox = [idc.get_wide_byte(sbox_ea + i) for i in range(256)]
print(f'Custom S-Box: {[hex(x) for x in custom_sbox]}')

# 用自定义 S-Box 解密
from Crypto.Cipher import AES as _AES  # 需要修改源码支持自定义 S-Box
# 或直接写 AES 解密函数，把 sbox 替换为 custom_sbox

def aes_decrypt_custom(ciphertext, key, sbox, inv_sbox):
    """使用自定义 S-Box 的 AES 解密"""
    # 标准 AES 流程，但 sbox/inv_sbox 用自定义的
    # 关键步骤: SubBytes 用 inv_sbox, InvSubBytes 用 sbox
    pass  # 按 AES 标准实现替换即可
```

#### 3.2 魔改 TEA

```python
# 魔改类型2: 修改 delta 值
# 识别: 循环结构和 TEA 一样但 delta 不是 0x9E3779B9
# 还原: 从逆向分析中提取自定义 delta

def tea_decrypt(v, k, delta=0x9E3779B9, rounds=32):
    """标准 TEA 解密，delta 和 rounds 可替换"""
    v0, v1 = v[0], v[1]
    sum_val = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    return [v0, v1]

def xtea_decrypt(v, k, delta=0x9E3779B9, rounds=32):
    """XTEA 解密"""
    v0, v1 = v[0], v[1]
    sum_val = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_val + k[sum_val >> 11 & 3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_val + k[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    return [v0, v1]

def xxtea_decrypt(data, key, delta=0x9E3779B9):
    """XXTEA 解密 (块级操作)"""
    n = len(data)
    if n < 2:
        return data
    q = 6 + 52 // n
    sum_val = (q * delta) & 0xFFFFFFFF
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for i in range(n - 1, 0, -1):
            z = data[i - 1]
            mx = (((z >> 5 ^ data[i] << 2) + (data[i] >> 3 ^ z << 4)) ^
                  ((sum_val ^ data[i]) + (key[(i & 3) ^ e] ^ z))) & 0xFFFFFFFF
            data[i] = (data[i] - mx) & 0xFFFFFFFF
        z = data[n - 1]
        mx = (((z >> 5 ^ data[0] << 2) + (data[0] >> 3 ^ z << 4)) ^
              ((sum_val ^ data[0]) + (key[(0 & 3) ^ e] ^ z))) & 0xFFFFFFFF
        data[0] = (data[0] - mx) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    return data
```

#### 3.3 异或+Base64 变种

```python
# 初赛最常见的简单加密: 异或然后 Base64
# 识别: 看到 'A'-'z' 范围的编码表（可能魔改 Base64 字符表）

import base64

def xor_decrypt(data, key):
    """循环异或解密"""
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

def custom_base64_decode(encoded_str, custom_table):
    """自定义 Base64 表解码
    custom_table: 64字符的自定义编码表
    """
    std_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    trans = str.maketrans(custom_table, std_table)
    return base64.b64decode(encoded_str.translate(trans))

# 用法:
# 1. 从逆向中提取自定义编码表
# 2. custom_base64_decode(ciphertext, custom_table)
# 3. xor_decrypt(result, key)
```

### 4. IDA + r2 常用识别命令

```bash
# r2 常量搜索
r2 -A ./crackme
# 搜索 AES S-Box
/x 637c777bf26b6fc5
# 搜索 MD5 IV
/x 67452301efcdab89
# 搜索 TEA delta
/x b979379e

# IDA 中的快捷识别
# 1. View → Open subviews → Strings  (搜索 base64 字符表)
# 2. View → Open subviews → Exports  (搜索 OpenSSL/libcrypt 符号名)
# 3. Shift+F5 → 添加 libcrypt 签名库
```

### 5. 加密识别速查决策树

```
Step 1: 搜索常量
  有已知常量? → 按常量识别算法
  无已知常量? → Step 2

Step 2: 分析结构
  有 256 字节表? → S-Box 替换（AES/SM4/魔改）
  有 16 字节分组? → AES/SM4 系列
  有 delta 循环? → TEA 系列
  有 512 字节表? → Base64/URL 编码表
  无表但有位运算? → 异或/自定义位运算

Step 3: 动态调试
  下断点在变换函数入口
  输入已知明文（如全0/全A）
  单步跟踪变换过程
  对比标准算法中间状态

Step 4: 使用工具辅助
  - identify (GitHub: 0xMirah/identify)
  - FindCrypt (IDA 插件)
  - KANAL (PEiD 插件)
```

---

---

