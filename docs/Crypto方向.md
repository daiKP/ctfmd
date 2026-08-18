# CTF 知识库 — Crypto方向

> 本文件由 CTF解题笔记本.md 自动拆分生成，如需查看完整原始笔记请参阅原文件。

---

## RSA 基础解密

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - RSA |
| 难度 | 入门 |
| 日期 | 2026-07-31 |
| 工具 | gmpy2（大数加速）、pycryptodome（编码转换） |

### 题目描述

"Math is cool! Use the RSA algorithm to decode the secret message, c, p, q, and e are parameters for the RSA algorithm."

直接给出 RSA 的全部参数：p、q、e、c，要求解密还原明文。

### 题目参数

```
p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e = 65537
c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034
```

### 解题思路

**1. RSA 算法回顾**

RSA 加解密流程：
- 公钥：`(n, e)`，其中 `n = p × q`
- 加密：`c = m^e mod n`
- 私钥：`d = e⁻¹ mod φ(n)`，其中 `φ(n) = (p-1)(q-1)`
- 解密：`m = c^d mod n`

**2. 本题特点**

题目直接给出了 p 和 q（无需因式分解 n），因此可以直接计算 φ(n)，再求私钥 d，最后解密。

**3. 库选择与性能对比**

本题使用三个核心库替代纯 Python 内置函数：

| 库 | 用途 | 对比 Python 内置 |
|----|------|-----------------|
| `gmpy2` | 模逆元 `invert()`、模幂 `powmod()`、开方 `iroot()`、素性检测 | 快 **6.2x**（500次RSA运算: 0.35s vs 2.18s） |
| `pycryptodome` | `long_to_bytes()` / `bytes_to_long()` 编码转换 | 比手写 `int.to_bytes()` 更方便，自动处理长度 |
| `sympy` | `factorint()` 因式分解（Pollard rho + ECM） | 离线可用，适合中小规模 n |

gmpy2 底层是 GMP (GNU Multiple Precision) C 库，大数运算远快于 Python 的纯整数实现。

**4. 解题步骤**

```
Step 1: n = p × q
Step 2: φ(n) = (p-1) × (q-1)
Step 3: d = e⁻¹ mod φ(n)        ← gmpy2.invert(e, phi)
Step 4: m = c^d mod n            ← gmpy2.powmod(c, d, n)
Step 5: 验证 m^e mod n == c      ← 确认解密正确
```

### 解题脚本

> 完整脚本保存为 `rsa_toolkit.py`，封装了 RSA 解密 + 常见攻击模块，可复用。

```python
#!/usr/bin/env python3
"""
CTF RSA 解题通用脚本库 (rsa_toolkit.py)
封装 RSA 常用操作，优先使用 gmpy2 加速大数运算，
无 gmpy2 时自动回退到 Python 内置函数。

核心依赖: gmpy2, pycryptodome
可选依赖: sympy (因式分解)
安装: pip install gmpy2 pycryptodome sympy
"""

# ---- 依赖加载（优先 gmpy2，回退内置）----
try:
    import gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

from Crypto.Util.number import long_to_bytes, bytes_to_long

# ---- 基础运算 ----

def modinv(a, m):
    """模逆元 a^{-1} mod m"""
    if _HAS_GMPY2:
        return int(gmpy2.invert(a, m))
    return pow(a, -1, m)

def powmod(base, exp, mod):
    """模幂 base^exp mod mod"""
    if _HAS_GMPY2:
        return int(gmpy2.powmod(base, exp, mod))
    return pow(base, exp, mod)

def iroot(n, k):
    """整数 k 次方根，返回 (root, is_exact)"""
    if _HAS_GMPY2:
        r, exact = gmpy2.iroot(n, k)
        return int(r), bool(exact)
    # 回退：二分搜索
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo, (lo ** k == n)

# ---- RSA 核心 ----

def rsa_compute_d(p, q, e):
    """已知 p, q, e 计算私钥 d"""
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)

def rsa_decrypt(c, d, n):
    """RSA 解密: m = c^d mod n"""
    return powmod(c, d, n)

# ---- 第6题: RSA 基础解密 ----

if __name__ == '__main__':
    p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
    q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
    e = 65537
    c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034

    print(f"gmpy2 加速: {'已启用' if _HAS_GMPY2 else '未安装(回退内置)'}")

    n = p * q
    d = rsa_compute_d(p, q, e)
    m = rsa_decrypt(c, d, n)

    # 验证
    assert powmod(m, e, n) == c, "验证失败!"

    print(f"n   = {n}")
    print(f"d   = {d}")
    print(f"m   = {m}")
    print(f"hex = {hex(m)}")
    print(f"bytes = {long_to_bytes(m)}")
    print(f"验证: m^e mod n == c  ✓")
    print(f"\nSecret message: {m}")
```

> 此外 `rsa_toolkit.py` 还封装了以下攻击模块，供后续 RSA 变体题复用：
> - `factorize_n(n)` — 因式分解（sympy 本地 + factordb 在线）
> - `attack_small_e(c, e, n)` — 小加密指数攻击（直接开方）
> - `attack_common_modulus(n, e1, c1, e2, c2)` — 共模攻击
> - `attack_wiener(e, n)` — Wiener 攻击（连分数展开恢复 d）

### 运行结果

```
gmpy2 加速: 已启用
n   = 114573516752272714750064227635008832737477859608443481000717283425702025029279291376859256856603741797722497252841363753834114679306784379319341824813349417007577541466886971550474580368413974382926969910999462429631003527365143148445405716553105750338796691010126879918594076915709977585368841428779903869581
d   = 56632047571190660567520341028861194862411428416862507034762587229995138605649836960220619903456392752115943299335385163216233744624623848874235303309636393446736347238627793022725260986466957974753004129210680401432377444984195145009801967391196615524488853620232925992387563270746297909112117451398527453977
m   = 5577446633554466577768879988
hex = 0x12058e43d9e0c22559c19774
bytes = b'\x12\x05\x8eC\xd9\xe0\xc2%Y\xc1\x97t'
验证: m^e mod n == c  ✓

Secret message: 5577446633554466577768879988
```

明文转为 bytes 后不构成可读 ASCII 文本，说明本题的 secret message 就是这个整数本身。

Flag: `5577446633554466577768879988`

### 环境依赖

```
# requirements.txt
gmpy2>=2.1            # GMP 大数运算加速，比Python内置快6x+
pycryptodome>=3.20    # long_to_bytes/bytes_to_long, RSA/AES等
sympy>=1.12           # factorint() 因式分解, isprime() 素性检测
pwntools>=4.12        # PWN题远程连接
```

安装方式：
```bash
# 在线安装
pip install -r requirements.txt

# 离线迁移（比赛断网环境）
# 1. 有网环境下载
pip download -r requirements.txt -d ./packages
# 2. 拷贝 packages 目录到离线环境
pip install --no-index --find-links=./packages -r requirements.txt
```

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| RSA 加解密原理 | 公钥加密 `c=m^e mod n`，私钥解密 `m=c^d mod n` |
| 欧拉函数 φ(n) | `φ(n) = (p-1)(q-1)`，用于计算私钥 |
| 模逆元 | `d = e⁻¹ mod φ(n)`，gmpy2 用 `gmpy2.invert(e, phi)` |
| 模幂运算 | gmpy2.powmod 比内置 pow 快 6x+ |
| gmpy2 vs 内置 | gmpy2 底层 GMP C 库，大数运算远快于 Python 纯整数实现 |
| long_to_bytes | pycryptodome 提供，比手写 `int.to_bytes()` 更方便 |
| 明文编码 | RSA 明文可为整数，不一定能转为可读 bytes |
| e=65537 | RSA 最常用的公钥指数，费马数 F4 |

### 同类变体与扩展

- 若只给 n 和 e（不给 p、q），需先因式分解 n：小 n 用 sympy `factorint()` 或 `factordb.com`，大 n 用 yafu/msieve/GNFS
- 若 e=1，则 c=m，直接提交 c 即可
- 若 e 极小（如 e=3）且 m^3 < n，可直接对 c 开三次方：`gmpy2.iroot(c, 3)`
- 若多组相同 n 不同 e（共模攻击），用扩展欧几里得算法求 `s1*e1 + s2*e2 = 1`，再 `m = c1^s1 * c2^s2 mod n`
- Wiener 攻击：当 d 很小时（d < n^0.25），可用连分数展开 e/n 恢复 d
- 低加密指数广播攻击：同一明文用多个不同 n 加密且 e 相同，用中国剩余定理（CRT）合并后开 e 次方
- 离线迁移：`pip download -r requirements.txt -d ./packages` 提前下载，断网环境用 `--find-links` 安装

---

## [BJDCTF 2nd] 燕言燕语 — Hex 解码 + 维吉尼亚密码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 编码转换 + 维吉尼亚密码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 来源 | BJDCTF 2nd |
| 脚本 | [solve.py](Crypto/14-bjdctf-yanzi/solve.py) |

### 题目描述

> 小燕子，穿花衣，年年春天来这里，我问燕子你为啥来，燕子说: 79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20

题目给出一段十六进制字符串，结合"燕子"主题，需要逐步解码。

### 解题思路

**1. Hex 解码**

题目字符串为纯十六进制（0-9, A-F），直接转换为 ASCII：

```
79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20
→ yanzi ZJQ{xilzv_iqssuhoc_suzjg}
```

解码后分为两部分：
- `yanzi`（燕子拼音）— 密钥提示
- `ZJQ{xilzv_iqssuhoc_suzjg}` — 密文

**2. 密码类型识别**

> **技巧** 看到密文格式 `ZJQ{...}` 而比赛是 BJDCTF，猜测明文应为 `BJD{...}`。对比各字母偏移量：Z→B(24), J→J(0), Q→D(15) — 偏移量不一致，排除凯撒密码。偏移量随位置变化，指向**维吉尼亚密码**。

分析 `Z→B` 的偏移：`(25 - 24) % 26 = 1`，而密钥第一个字母 `y` 的值也是 24（`ord('y')-ord('a')=24`），符合维吉尼亚加密公式 `cipher = (plain + key) % 26`。

**3. 维吉尼亚解密**

```
解密公式：plain[i] = (cipher[i] - key[i]) % 26
```

密钥 `yanzi` 循环使用，跳过非字母字符（`{`、`_`、`}`），仅对字母位置推进密钥索引。

```
密文: Z  J  Q  {  x  i  l  z  v  _  i  q  s  s  u  h  o  c  _  s  u  z  j  g  }
密钥: y  a  n  z  i  y  a  n  z  i  y  a  n  z  i  y  a  n  z  i  y  a  n
明文: b  j  d  {  y  a  n  z  i  _  j  i  u  s  h  i  g  e  _  s  h  a  b  i  }
```

### 解题脚本

```python
hex_str = '79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20'

# Step 1: Hex 解码
decoded = bytes.fromhex(hex_str).decode('ascii')
# => 'yanzi ZJQ{xilzv_iqssuhoc_suzjg}'

key = 'yanzi'
cipher = decoded.strip().split(' ', 1)[1]  # 取空格后的密文部分

# Step 2: 维吉尼亚解密
def vigenere_decrypt(ciphertext, key):
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch.lower()) - ord('a')
            k = ord(key[ki % len(key)].lower()) - ord('a')
            p = (c - k) % 26
            result.append(chr(p + ord('a')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

plaintext = vigenere_decrypt(cipher, key)
print(f'Flag: {plaintext}')
```

### 运行结果

```
[1] Hex 解码: 'yanzi ZJQ{xilzv_iqssuhoc_suzjg} '
    密钥: yanzi
    密文: ZJQ{xilzv_iqssuhoc_suzjg}
[2] 维吉尼亚解密: bjd{yanzi_jiushige_shabi}
[3] 验证加密: zjq{xilzv_iqssuhoc_suzjg}
    匹配: True

Flag: bjd{yanzi_jiushige_shabi}
```

Flag: `bjd{yanzi_jiushige_shabi}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| Hex 编码 | 每个字符用两位十六进制表示，`bytes.fromhex()` 一键解码 |
| 维吉尼亚密码 | 多表替换密码，密钥循环使用，`cipher = (plain + key) % 26` |
| 凯撒 vs 维吉尼亚 | 凯撒是固定偏移（单表），维吉尼亚是随位置变化的偏移（多表） |
| 密钥提示识别 | 题目文本中的关键词（如"yanzi"）可能就是密钥 |
| flag 格式识别 | `ZJQ{...}` → `BJD{...}` 的偏移差异用于判断密码类型 |
| 非字母跳过 | 维吉尼亚解密时 `{`、`_`、`}` 等非字母字符不消耗密钥索引 |

### 同类变体与扩展

- 若密钥未直接给出，可用[维吉尼亚破解工具](https://www.guballa.de/vigenere-solver)或 Kasiski 测试法 + 字频分析自动破解
- 偏移量不固定也可能是指定位置的凯撒变体，需注意区分
- Hex 可能替换为 Base32/Base64/URL 编码，解题第一步总是识别编码方式
- 若解出后明文不可读，检查是否有第二层加密（如先 Hex 再 Base64 再维吉尼亚的链式编码）
- 常见 CTF 编码识别：纯 0-9A-F → Hex；末尾 `=` → Base64；纯 A-Z2-7 → Base32；`%` 开头 → URL 编码

---

---

## 老文盲了 — 生僻字拼音密码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 编码/文字密码 |
| 来源 | BJDCTF 2nd |
| 难度 | 入门 |
| 日期 | 2026-08-01 |

### 题目内容

```
罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝
```

提示：读了这句话感觉自己就是一个文盲。在小时候遇到不会的字我们都是怎么做的呢？没错——注拼音。

### 解题思路

**1. 识别编码类型**

密文由 20 个生僻汉字组成，不是常见的 ASCII 编码、Hex、Base64 等格式。题目名称"老文盲了"和提示"注拼音"直接暗示解题方向。

> **⚠️ 关键线索**：题目名称"文盲"+ 提示"注拼音" = 每个字的拼音是答案

**2. 查询每个字的拼音**

使用在线汉字拼音转换工具，获取每个字的读音：

| 索引 | 字 | 拼音 | 首字母 |
|------|----|------|--------|
| 0 | 罼 | bi | b |
| 1 | 雧 | ji | j |
| 2 | 締 | di | d |
| 3 | 眔 | da | d |
| 4 | 擴 | kuo | k |
| 5 | 灝 | hao | h |
| 6 | 淛 | zhe | z |
| 7 | 匶 | jiu | j |
| 8 | 襫 | shi | s |
| 9 | 黼 | fu | f |
| 10 | 瀬 | lai | l |
| 11 | 鎶 | ge | g |
| 12 | 軄 | zhi | z |
| 13 | 鶛 | jie | j |
| 14 | 驕 | jiao | j |
| 15 | 鳓 | le | l |
| 16 | 哵 | ba | b |
| 17 | 眔 | da | d |
| 18 | 鞹 | kuo | k |
| 19 | 鰝 | hao | h |

**3. 分组解读**

将 20 个字按语义分组：

```
索引  0-2:  罼雧締           → bi-ji-di → BJD (flag格式前缀)
索引  3-5:  眔擴灝           → da-kuo-hao → 大括号 {
索引  6-16: 淛匶襫黼瀬鎶軄鶛驕鳓哵 → zhe-jiu-shi-fu-lai-ge-zhi-jie-jiao-le-ba
索引 17-19: 眔鞹鰝           → da-kuo-hao → 大括号 }
```

中文含义：这就是flag直接交了吧

**4. 构造 Flag**

flag 内容为大括号之间的生僻字原文：

```
BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}
```

### 解题脚本

```python
# 手动建立生僻字→拼音映射（只有20个字，无需第三方库）
HANZI_PINYIN = {
    '罼': 'bi', '雧': 'ji', '締': 'di', '眔': 'da', '擴': 'kuo',
    '灝': 'hao', '淛': 'zhe', '匶': 'jiu', '襫': 'shi', '黼': 'fu',
    '瀬': 'lai', '鎶': 'ge', '軄': 'zhi', '鶛': 'jie', '驕': 'jiao',
    '鳓': 'le', '哵': 'ba', '鞹': 'kuo', '鰝': 'hao',
}

CIPHERTEXT = '罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝'

def get_full_pinyin(text):
    return [HANZI_PINYIN.get(ch, '?') for ch in text]

def solve():
    pinyins = get_full_pinyin(CIPHERTEXT)
    initials = ''.join(p[0] for p in pinyins)

    # 分组：BJD(0-2) {(3-5) 内容(6-16) }(17-19)
    flag_content = CIPHERTEXT[6:17]
    flag = f'BJD{{{flag_content}}}'

    print(f'拼音首字母序列: {initials}')
    print(f'分组: BJD {{ {flag_content} }}')
    print(f'中文含义: 这就是flag直接交了吧')
    print(f'Flag: {flag}')

solve()
```

### 运行结果

```
拼音首字母序列: bjddkhzjsflgzjjlbdkh
分组: BJD { 淛匶襫黼瀬鎶軄鶛驕鳓哵 }
中文含义: 这就是flag直接交了吧
Flag: BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}
```

Flag: `BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 生僻字密码 | 用不常见汉字的拼音首字母隐藏信息，常见于中文 CTF |
| 拼音首字母法 | 每个字取拼音首字母拼接，类似藏头诗的变体 |
| "大括号"文字编码 | `眔擴灝` → da-kuo-hao → 大括号，用文字描述特殊符号 |
| 汉字拼音查询 | 在线工具如 [汉字拼音转换器](https://www.aies.cn/pinyin.htm) 可批量查拼音 |
| 题目名称暗示 | "老文盲了" → 看不懂字 → 查拼音，题目名本身就是解题提示 |

> **技巧**：遇到全是生僻字的密文，第一反应应该是查每个字的拼音，取首字母拼接。常见于 BJDCTF 等国内比赛的 Crypto/Misc 分类。

### 同类变体与扩展

- 变体1：取拼音的**完整拼写**而非首字母（如 `zhejiushiflag`）
- 变体2：结合**部首拆解**（如"武"→止+戈）或**笔画数**编码
- 变体3：利用**汉字 Unicode 码点**的某种运算进行编码（需排除此方向后才转拼音）
- 工具推荐：`pypinyin` Python 库可程序化批量获取拼音，但生僻字覆盖可能不全
- 相关中文密码类型：与佛论禅、百家姓密码、仓颉码、四角号码等

---

---

## 仿射密码 — 小学生密码学

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 经典密码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 关联课程 | 信息安全数学基础（数论） |

### 题目内容

加密函数：`e(x) = 11x + 6 (mod 26)`

密文：`welcylk`

（flag 为 base64 形式）

### 解题思路

**1. 识别密码类型**

`e(x) = ax + b (mod m)` 是标准的**仿射密码（Affine Cipher）**公式，其中：
- `a = 11`（乘法密钥）
- `b = 6`（加法密钥/位移）
- `m = 26`（字母表长度）

仿射密码 = 凯撒密码（加法）+ 乘法密码的复合，是信息安全数学基础课的经典内容。

> **⚠️ 你说的"阿基米德算法"其实是"扩展欧几里得算法"（Extended Euclidean Algorithm）**，正是这题的核心——用来求模逆元进行解密。

**2. 数学原理：仿射密码的加解密**

```
加密: E(x) = (a * x + b) mod m
解密: D(y) = a_inv * (y - b) mod m
```

其中 `a_inv` 是 `a` 模 `m` 的**乘法逆元**，满足 `a * a_inv ≡ 1 (mod m)`。

关键前提：`gcd(a, m) = 1`（a 和 m 必须互素），否则模逆元不存在，密码不可逆。

```
gcd(11, 26) = 1 → 可解 ✓
```

**3. 扩展欧几里得算法求模逆元**

扩展欧几里得算法在求 `gcd(a, m)` 的同时，找到整数 `x, y` 满足：

```
a * x + m * y = gcd(a, m)
```

当 `gcd = 1` 时，`x` 就是 `a` 的模逆元（取正模后）。

```
gcd(11, 26):
  26 = 2 * 11 + 4    →  gcd(11, 4)
  11 = 2 * 4 + 3     →  gcd(4, 3)
  4  = 1 * 3 + 1     →  gcd(3, 1)
  3  = 3 * 1 + 0     →  gcd = 1

回代求 Bezout 系数:
  1 = 4 - 1*3
    = 4 - 1*(11 - 2*4) = 3*4 - 11
    = 3*(26 - 2*11) - 11 = 3*26 - 7*11

所以: -7*11 ≡ 1 (mod 26)
      11 * (-7) ≡ 1 (mod 26)
      a_inv = -7 mod 26 = 19

验证: 11 * 19 = 209 = 8*26 + 1 ≡ 1 (mod 26) ✓
```

> **技巧**：手算模逆元时，也可以暴力枚举——从 1 到 25 逐个试 `(11 * i) % 26 == 1`，很快就能找到 19。但理解扩展欧几里得算法的原理更重要，因为大数场景（如 RSA）暴力不可行。

**4. 逐字符解密**

```
解密公式: D(y) = 19 * (y - 6) mod 26

w: y=22, D = 19*(22-6) mod 26 = 19*16 mod 26 = 304 mod 26 = 18 → s
e: y=4,  D = 19*(4-6)  mod 26 = 19*(-2) mod 26 = -38 mod 26 = 14 → o
l: y=11, D = 19*(11-6) mod 26 = 19*5  mod 26 = 95  mod 26 = 17 → r
c: y=2,  D = 19*(2-6)  mod 26 = 19*(-4) mod 26 = -76 mod 26 = 2  → c
y: y=24, D = 19*(24-6) mod 26 = 19*18 mod 26 = 342 mod 26 = 4  → e
l: y=11, D = 19*(11-6) mod 26 = 19*5  mod 26 = 95  mod 26 = 17 → r
k: y=10, D = 19*(10-6) mod 26 = 19*4  mod 26 = 76  mod 26 = 24 → y

明文: sorcery (巫术/魔法)
```

**5. Base64 编码**

```
sorcery → base64 → c29yY2VyeQ==
```

Flag: `flag{c29yY2VyeQ==}`

### 解题脚本

```python
import base64

a, b, m = 11, 6, 26
CIPHERTEXT = 'welcylk'

def extended_gcd(a, m):
    """扩展欧几里得算法，返回 (gcd, x, y) 使 a*x + m*y = gcd"""
    if a == 0:
        return m, 0, 1
    g, x1, y1 = extended_gcd(m % a, a)
    return g, y1 - (m // a) * x1, x1

def mod_inverse(a, m):
    """求 a 模 m 的乘法逆元"""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f'{a} 和 {m} 不互素，无模逆元')
    return x % m

# 求模逆元
a_inv = mod_inverse(a, m)
print(f'a_inv = {a_inv}')  # 19

# 解密: D(y) = a_inv * (y - b) mod m
plaintext = ''.join(
    chr((a_inv * (ord(ch) - ord('a') - b)) % m + ord('a'))
    for ch in CIPHERTEXT
)
print(f'明文: {plaintext}')  # sorcery

# Base64 编码
flag = base64.b64encode(plaintext.encode()).decode()
print(f'Flag: flag{{{flag}}}')
```

### 运行结果

```
仿射密码: E(x) = 11x + 6 (mod 26)
密文: welcylk

[1] 扩展欧几里得算法:
    gcd(11, 26) = 1 (必须为1，否则不可解)
    11 的模逆元 a_inv = 19
    验证: 11 * 19 mod 26 = 1
    解密公式: D(y) = 19 * (y - 6) mod 26

[2] 解密:
    密文: welcylk
    明文: sorcery

[3] 加密验证:
    明文: sorcery
    加密: welcylk
    匹配: True

[4] Base64 编码:
    明文: sorcery
    Base64: c29yY2VyeQ==

Flag: flag{c29yY2VyeQ==}
```

Flag: `flag{c29yY2VyeQ==}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| 仿射密码 | `E(x) = ax + b (mod m)`，凯撒密码的推广，结合乘法密码与加法密码 |
| 模逆元 | `a * a_inv ≡ 1 (mod m)`，解密的关键，需 `gcd(a, m) = 1` |
| 扩展欧几里得算法 | 求 gcd 同时求 Bezout 系数，用于计算模逆元 |
| gcd 互素条件 | `gcd(a, m) = 1` 是仿射密码可逆的充要条件 |
| Base64 编码 | 将字节序列编码为 ASCII 字符，CTF 常见的 flag 包装格式 |
| 模运算 | 负数取模需注意：`-38 mod 26 = 14`（不是 -12），Python 的 `%` 自动处理 |

> **技巧**：识别仿射密码——看到 `e(x) = ax + b (mod m)` 形式就是仿射密码。解题三步走：①验证 `gcd(a,m)=1` → ②扩展欧几里得求 `a_inv` → ③代入 `D(y) = a_inv * (y-b) mod m` 逐字符解密。

> **技巧**：Python 的 `%` 运算符对负数也返回非负结果（如 `-38 % 26 = 14`），所以解密公式可以直接写 `(a_inv * (y - b)) % m`，无需手动处理负数。C/C++/Java 则需加 `m` 再取模。

### 同类变体与扩展

- **已知 a, b 直接解**：本题形式，最简单
- **已知 a, b 未知（已知明文攻击）**：通过一对明文-密文列出方程组求解
- **唯密文攻击**：利用字母频率分析 + 暴力枚举 `a`（12 个候选值）和 `b`（26 个候选值），共 312 种可能
- **a 的有效值**：模 26 下与 26 互素的 a 有 φ(26) = 12 个（1,3,5,7,9,11,15,17,19,21,23,25），密钥空间 12×26 = 312
- **与 RSA 的联系**：RSA 解密也需要模逆元求 `d = e_inv mod φ(n)`，但模数极大，暴力不可行，必须用扩展欧几里得
- **Hill 密码**：仿射密码的矩阵推广版，`E(x) = Kx + b (mod m)`，K 为矩阵，逆元变为逆矩阵

---

---

## easyencode — 五层嵌套编码

### 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | Crypto - 多层编码 |
| 难度 | 入门 |
| 日期 | 2026-08-01 |
| 题目文件 | `easyencode.zip`（345字节，ZipCrypto加密） |

### 编码链路总览

```
easyencode.zip (ZIP密码: 100861)
  └─ encode.txt (3124字节摩斯电码)
       └─ [Layer 1] 摩斯电码解码 → 528字符hex字符串
            └─ [Layer 2] Hex解码 → 264字符 \uXXXX Unicode转义序列
                 └─ [Layer 3] Unicode转义解码 → 44字符 Base64+URL编码
                      └─ [Layer 4] URL解码 (%3D→=) → 标准Base64
                           └─ [Layer 5] Base64解码 → flag
```

### 解题过程

**1. ZIP暴力破解**

ZIP 文件使用 ZipCrypto 传统加密（非 AES）。文件仅 345 字节，含一个 `encode.txt`（原始大小 3124 字节）。

排除伪加密后，对 6 位纯数字密码进行暴力枚举：

```python
import zipfile, itertools

with zipfile.ZipFile('easyencode.zip', 'r') as z:
    for combo in itertools.product('0123456789', repeat=6):
        pwd = ''.join(combo).encode()
        try:
            z.setpassword(pwd)
            z.read('encode.txt')
            print(f"Password: {pwd.decode()}")
            break
        except:
            continue
# 密码: 100861
```

> **技巧**：CTF 中 ZIP 密码常见为纯数字（手机号、短数字）。6 位数字仅 100 万种组合，Python `itertools.product` 几秒内可枚举完毕。

**2. 第一层：摩斯电码解码**

解压后的 `encode.txt` 内容全部是摩斯电码（`.` 和 `-`，空格分隔）：

```
..... -.-. --... ..... ...-- ----- ...-- ----- ...-- ..... ...-- ..--- .....
```

摩斯解码使用标准码表。注意本题摩斯码只使用了数字 `0-9` 和字母 `C`（`-.-.`）：

```python
MORSE_CODE = {
    '.....': '5', '-.-.': 'C', '--...': '7', '...--': '3',
    '-----': '0', '....-': '4', '..---': '2', '-....': '6',
    # ... 完整码表
}
decoded = ''.join(MORSE_CODE[m] for m in morse_text.split(' '))
# 结果: 5C75303035325C75303034375C75303035365C75303037615C...
# 长度: 528 字符，全部为 hex 字符 (0-9, A-F 中的 C)
```

> **技巧**：摩斯电码中只出现数字和少数字母时，解码结果很可能是 hex 编码。`5C` = `\`、`75` = `u` 是 Unicode 转义 `\u` 的典型开头，是识别下一层编码的关键线索。

**3. 第二层：Hex 解码**

528 字符 hex 字符串每 2 位一组，解码为 264 字节 ASCII 文本：

```python
hex_bytes = bytes.fromhex(decoded_morse)
unicode_escaped = hex_bytes.decode('ascii')
# 结果: \u0052\u0047\u0056\u007a\u0064\u0044\u0042\u006e\u004d\u0033\u0074\u0045...
```

Hex 解码后得到的是 `\uXXXX` 格式的 Unicode 转义序列，每 6 个字符（`\u` + 4位hex）表示一个字符。

**4. 第三层：Unicode 转义解码**

将 `\uXXXX` 转义序列逐个转换为实际字符：

```python
import re
result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), unicode_escaped)
# 结果: RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D
```

解码后得到 44 字符的字符串，看起来像 Base64 但末尾是 `%3D%3D` 而非 `==`。

> **技巧**：`\uXXXX` 是 JavaScript/Python/Java 中常见的 Unicode 转义格式。正则 `\\u([0-9a-fA-F]{4})` 可批量匹配并转换。注意 Python 字符串中 `\u` 本身是转义前缀，处理时需用原始字符串 `r'\u'` 或双反斜杠 `\\u`。

**5. 第四层：URL 解码**

`%3D` 是 `=` 的 URL 百分号编码。Base64 的填充字符 `=` 被 URL 编码了：

```python
import urllib.parse
b64_str = urllib.parse.unquote('RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D')
# 结果: RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==
```

> **技巧**：URL 百分号编码常用于隐藏 Base64 的 `=` 填充符。`%3D` = `=`、`%2B` = `+`、`%2F` = `/` 是 Base64 字符集中常被 URL 编码的三个字符。看到以 `%3D%3D` 结尾的字符串应立即联想到 URL 编码的 Base64。

**6. 第五层：Base64 解码**

标准 Base64 解码得到最终 flag：

```python
import base64
flag = base64.b64decode('RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==').decode('utf-8')
# 结果: Dest0g3{Deoding_1s_e4sy_4_U}
```

### 验证

```
Layer 1 (Morse):    5C75303035325C7530303437...  (528 chars)
Layer 2 (Hex):      \u0052\u0047\u0056\u007a...  (264 chars)
Layer 3 (Unicode):  RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ%3D%3D  (44 chars)
Layer 4 (URL):      RGVzdDBnM3tEZW9kaW5nXzFzX2U0c3lfNF9VfQ==  (44 chars)
Layer 5 (Base64):   Dest0g3{Deoding_1s_e4sy_4_U}  ✓
```

Flag: `Dest0g3{Deoding_1s_e4sy_4_U}`

### 涉及知识点

| 知识点 | 说明 |
|--------|------|
| ZIP 暴力破解 | ZipCrypto 传统加密，6 位纯数字密码可通过 `itertools.product` 快速枚举 |
| 摩斯电码 (Morse Code) | 点划编码，数字 0-9 和字母 A-Z 各有唯一编码；本题仅用数字+字母C |
| Hex 编码 | 每 2 个 hex 字符表示 1 字节，`5C`=`\`、`75`=`u` 是识别 Unicode 转义的关键 |
| Unicode 转义 `\uXXXX` | 4 位 hex 表示 Unicode 码点，常见于 JS/Python/Java 字符串 |
| URL 百分号编码 | `%XX` 格式，`%3D`=`=`、`%2B`=`+`、`%2F`=`/`，常隐藏 Base64 特殊字符 |
| Base64 编码 | 3 字节→4 字符，`=` 为末尾填充，`+` 和 `/` 为扩展字符 |

> **技巧**：多层编码题的通用解题策略——**从外到内逐层剥离**。每层解码后先观察结果特征（字符集、长度、结构），再判断下一层编码类型。关键识别特征：① 全 hex 字符→Hex解码；② `\uXXXX` 模式→Unicode转义；③ `%XX` 模式→URL解码；④ `[A-Za-z0-9+/=]` 字符集→Base64解码。

> **技巧**：题名是最好的提示。`easyencode` 强调"编码"而非"加密"，意味着无需密钥的编码链，关键是识别每层编码类型。类似题名还有 `encode`、`encoding`、`base` 等。

### 同类变体与扩展

- **编码层数变化**：常见 2-5 层嵌套，可能加入 Base32、Base58、ROT13、AAencode（JS颜文字编码）、Brainfuck 等冷门编码
- **UUencode/XXencode**：较老的二进制转文本编码，字符集不同于 Base64
- **摩斯电码变体**：分隔符可能用 `/` 或换行而非空格；可能包含标点符号摩斯码
- **Hex 变体**：可能用 `0x` 前缀、`\x` 前缀、或空格分隔的 hex
- **防御/检测**：多层编码是恶意软件混淆 payload 的常见手段，YARA 规则可检测 base64/hex 链式编码特征

### 解题脚本

完整脚本：[Crypto/19-easyencode/solve.py](Crypto/19-easyencode/solve.py)

```python
# 核心解码链（5层）
import zipfile, re, base64, urllib.parse

# Layer 0: ZIP解压 (密码: 100861)
with zipfile.ZipFile('easyencode.zip', 'r') as z:
    z.setpassword(b'100861')
    morse_text = z.read('encode.txt').decode('utf-8')

# Layer 1: 摩斯电码 → hex字符串
MORSE = {'.....': '5', '-.-.': 'C', '--...': '7', '...--': '3', '-----': '0', ...}
hex_str = ''.join(MORSE[m] for m in morse_text.split(' '))

# Layer 2: Hex解码 → \uXXXX Unicode转义
unicode_escaped = bytes.fromhex(hex_str).decode('ascii')

# Layer 3: Unicode转义解码 → Base64+URL编码
b64_url = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), unicode_escaped)

# Layer 4: URL解码 → 标准Base64
b64_str = urllib.parse.unquote(b64_url)

# Layer 5: Base64解码 → flag
flag = base64.b64decode(b64_str).decode('utf-8')
print(flag)  # Dest0g3{Deoding_1s_e4sy_4_U}
```

---

---

## Crypto - AES 分组密码与 Padding Oracle

> 补充日期：2026-08-04 | 优先级：高 | 对应附录D.3 Crypto未覆盖考点

### AES 基础

高级加密标准（Advanced Encryption Standard, AES）是分组密码，分组长度 128 位（16 字节），密钥长度 128/192/256 位。

**加密模式**：

| 模式 | 全称 | 特点 | CTF 关注点 |
|------|------|------|-----------|
| ECB | Electronic Codebook | 每块独立加密，相同明文→相同密文 | 模式最弱，可重排/替换块 |
| CBC | Cipher Block Chaining | 前一块密文 XOR 后一块明文 | IV 可控时攻击 |
| CTR | Counter | 计数器模式，流式加密 | Nonce 重用导致明文泄露 |
| CFB | Cipher Feedback | 密文反馈 | IV 相关攻击 |
| OFB | Output Feedback | 输出反馈 | — |
| GCM | Galois/Counter | 带认证的加密 | 认证标签绕过 |

### AES-ECB 特点与攻击

**特点**：每 16 字节独立加密，无链式依赖。

**攻击1：ECB 重排攻击**

```
# 相同明文块产生相同密文块
# 攻击者可以：
# 1. 截获密文，重排块顺序
# 2. 删除某些块
# 3. 替换块（如用之前捕获的密文块替换）

# 示例：将 "admin=false" 改为 "admin=true\x0e\x0e..."
# 通过重排16字节块实现
```

**攻击2：ECB 字节逐字节恢复（选择明文攻击）**

```python
from Crypto.Cipher import AES
import os

KEY = os.urandom(16)

def oracle(plaintext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# 逐字节恢复未知密文
unknown = b'The flag is: flag{aes_ecb_attack}'

for i in range(len(unknown)):
    # 构造 15 字节填充 + 已知前缀 + 1 字节待猜
    padding = b'A' * (15 - (i % 16))
    # ... 逐字节对比密文块
```

### AES-CBC 与 Padding Oracle 攻击

**CBC 加密过程**：

```
C0 = IV
Ci = AES_Encrypt(Pi XOR C(i-1))
Pi = AES_Decrypt(Ci) XOR C(i-1)
```

**PKCS#7 填充**：

```
# 最后一字节填充 1-16，表示填充字节数
# 缺 1 字节: ... 0x01
# 缺 2 字节: ... 0x02 0x02
# 缺 16 字节(整块): 0x10 0x10 ... 0x10 (16个)

# 验证规则:
# 1. 最后一字节的值 n 必须在 1-16 之间
# 2. 最后 n 个字节必须都等于 n
# 不满足 → 返回填充错误
```

**Padding Oracle 原理**：

当服务端对解密结果做 PKCS#7 填充校验，且能区分"填充错误"和"解密成功但业务错误"时（通过错误消息、响应码、响应时间等），攻击者可以逐字节恢复明文。

**攻击过程**：

```
目标: 恢复密文块 Ci 的明文 Pi

1. 设前一密文块为 Ci-1，构造伪造的 Ci-1' = [随机字节]
2. 发送 (Ci-1' || Ci) 给服务端
3. 服务端解密: Pi' = AES_Decrypt(Ci) XOR Ci-1'
4. 校验 Pi' 的 PKCS#7 填充:
   - 填充合法 → 服务端返回业务错误（非填充错误）
   - 填充非法 → 服务端返回填充错误
5. 逐字节爆破 Ci-1' 的最后一个字节:
   - 当填充合法时，Pi' 最后一个字节 = 0x01
   - 即 AES_Decrypt(Ci)[15] XOR Ci-1'[15] = 0x01
   - 即 Pi[15] = Ci-1[15] XOR AES_Decrypt(Ci)[15] = Ci-1[15] XOR Ci-1'[15] XOR 0x01
6. 逐字节向前推进，恢复完整块
```

**Python 实现**：

```python
import requests

def padding_oracle(ciphertext_block, prev_block, oracle_url):
    """恢复单个密文块的明文"""
    intermediate = bytearray(16)  # 中间值: AES_Decrypt(Ci)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        padding_val = 16 - byte_pos  # 期望的填充值

        # 构造伪造的前一块
        fake_prev = bytearray(16)
        # 已知中间值的字节设为正确值
        for j in range(byte_pos + 1, 16):
            fake_prev[j] = intermediate[j] ^ padding_val

        # 爆破当前字节
        for guess in range(256):
            fake_prev[byte_pos] = guess

            # 发送给 oracle
            payload = bytes(fake_prev) + ciphertext_block
            resp = requests.get(oracle_url, params={'data': payload.hex()})

            if 'padding error' not in resp.text:
                # 填充合法，中间值 = guess ^ padding_val
                intermediate[byte_pos] = guess ^ padding_val
                plaintext[byte_pos] = prev_block[byte_pos] ^ intermediate[byte_pos]
                break

    return bytes(plaintext)

# 恢复所有块
full_plaintext = b''
for i in range(1, len(ciphertext_blocks)):
    pt = padding_oracle(ciphertext_blocks[i], ciphertext_blocks[i-1], url)
    full_plaintext += pt
```

### CBC-IV 可控攻击

**Bit Flipping Attack（位翻转攻击）**：

当 IV 或前一密文块可控时，可以修改明文。

```python
# 假设明文第一个块是: "amount=1000\x05\x05\x05\x05\x05"
# 攻击者想改为: "amount=9000\x05\x05\x05\x05\x05"
# 只需修改 IV 的对应字节

original_plaintext = b'amount=1000\x05\x05\x05\x05\x05'
target_plaintext   = b'amount=9000\x05\x05\x05\x05\x05'

# P = D(C) XOR IV
# P' = D(C) XOR IV'
# IV' = IV XOR P XOR P'
iv_modified = bytearray(iv)
for i in range(len(original_plaintext)):
    iv_modified[i] = iv[i] ^ original_plaintext[i] ^ target_plaintext[i]

# 使用 iv_modified 后解密出 target_plaintext
```

### CTR 模式 Nonce 重用

```
# CTR 模式: Ci = Pi XOR AES(Key, Nonce || Counter)
# 如果两个消息使用相同 Nonce:
# C1 = P1 XOR Stream
# C2 = P2 XOR Stream
# C1 XOR C2 = P1 XOR P2
# 已知 P1 可推导 P2，反之亦然
```

### 常见 CTF 套路

| 套路 | 识别特征 | 解法 |
|------|---------|------|
| ECB 模式 | 密文长度 16 倍数，相同块出现 | 重排/字节恢复 |
| Padding Oracle | 有解密接口，报错区分填充/业务 | 逐字节爆破 |
| CBC Bit Flipping | IV 可控或注释中有可控字段 | 修改 IV/前块 |
| CTR Nonce 重用 | 两条密文用相同 key+nonce | XOR 恢复 |
| 弱密钥 | 密钥可猜测/已知 | 直接解密 |
| AES-ECB 图片 | 给出 BMP/PNG 用 ECB 加密 | 块模式可见图案 |

> AI生成

---

---

## Crypto - RSA 全面题型手册

> 补充日期：2026-08-04 | 优先级：高 | 14种攻击类型，每种配完整可复用Python脚本

### RSA 数学基础

```
密钥生成:
  1. 选两个大素数 p, q
  2. n = p * q
  3. φ(n) = (p-1) * (q-1)      # 欧拉函数
  4. 选 e, 满足 1 < e < φ(n) 且 gcd(e, φ(n)) = 1  (常用 e=65537)
  5. d = e^(-1) mod φ(n)        # 模逆元

加密: c = m^e mod n
解密: m = c^d mod n

关键关系:
  d = e^(-1) mod φ(n)
  φ(n) = (p-1)(q-1) = n - p - q + 1
  p + q = n - φ(n) + 1
  p - q ≈ sqrt(n) 当 p,q 接近时
```

### 通用工具库（开头导入，后续脚本复用）

```python
# rsa_common.py — RSA CTF 通用工具库
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, GCD
from sympy import factorint, prevprime, nextprime
import gmpy2
import subprocess

def egcd(a, b):
    """扩展欧几里得算法，返回 (g, x, y) 使得 a*x + b*y = g = gcd(a,b)"""
    if a == 0:
        return (b, 0, 1)
    g, x, y = egcd(b % a, a)
    return (g, y - (b // a) * x, x)

def modinv(a, m):
    """求 a 模 m 的逆元"""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise Exception('模逆元不存在')
    return x % m

def decrypt(c, d, n):
    """RSA 解密"""
    m = pow(c, d, n)
    return long_to_bytes(m)

def encrypt(m, e, n):
    """RSA 加密"""
    return pow(bytes_to_long(m), e, n)
```

### 题型1：直接分解 n（n 较小）

**特征**：n < 2^256（通常 256 位以下），可直接用工具分解。

```python
from Crypto.Util.number import long_to_bytes
from sympy import factorint

n = 0x00b7bee8b1...  # 替换为题目给的 n（十六进制或十进制）
e = 65537
c = 0x4e8f72c3...     # 替换为题目给的密文

# 方法1: sympy 分解（适用于较小 n）
factors = factorint(n)
p, q = list(factors.keys())
print(f"p = {p}")
print(f"q = {q}")

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)  # Python 3.8+
m = pow(c, d, n)
print(long_to_bytes(m))

# 方法2: factordb 在线查询（见题型2）
# 方法3: yafu 分解（大数）
# 命令行: yafu "factor(0x...)" -silent
```

### 题型2：在线查询 factordb

**特征**：n 可能较大但已被人提交过，factordb 已有记录。

```python
import requests
from Crypto.Util.number import long_to_bytes

def factor_from_factordb(n):
    """通过 factordb.com 在线分解 n"""
    url = f'http://factordb.com/api?query={n}'
    resp = requests.get(url, timeout=10)
    data = resp.json()
    # data: {"status": "FF", "factors": [["p", 1], ["q", 1]]}
    if data['status'] in ('FF', 'CF'):
        factors = [int(f[0]) for f in data['factors']]
        return factors
    else:
        print(f"factordb 未收录，status={data['status']}")
        return None

n = 0x00b7bee8b1...  # 替换
e = 65537
c = 0x4e8f72c3...

factors = factor_from_factordb(n)
if len(factors) == 2:
    p, q = factors
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

### 题型3：p 和 q 接近（Fermat 分解）

**特征**：|p - q| < n^(1/4)，即两个素数非常接近。

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

n = 0x00a8c...  # 替换
e = 65537
c = 0x6f2c...

def fermat_factor(n, max_iter=1000000):
    """Fermat 分解法，适用于 p, q 接近的情况"""
    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n
    for i in range(max_iter):
        if gmpy2.is_square(b2):
            b = gmpy2.isqrt(b2)
            p = int(a + b)
            q = int(a - b)
            assert p * q == n
            return p, q
        a += 1
        b2 = a * a - n
    return None

result = fermat_factor(n)
if result:
    p, q = result
    print(f"p = {p}\nq = {q}")
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

### 题型4：共模攻击

**特征**：同一明文 m 用相同 n、不同 e1/e2 加密，得到 c1/c2。gcd(e1, e2) = 1。

```python
from Crypto.Util.number import long_to_bytes

n  = 0x00a1b2c3...  # 相同的 n
e1 = 0x10001        # 第一个公钥
e2 = 0x10003        # 第二个公钥
c1 = 0x789abc...    # 第一个密文
c2 = 0xdef012...    # 第二个密文

def common_modulus_attack(n, e1, e2, c1, c2):
    """RSA 共模攻击"""
    # 求 s1*e1 + s2*e2 = gcd(e1, e2) = 1
    from Crypto.Util.number import GCD
    g, s1, s2 = egcd(e1, e2)  # 使用上面通用库的 egcd
    assert g == 1

    # m = c1^s1 * c2^s2 mod n
    # 处理负指数：先求逆元
    if s1 < 0:
        c1 = pow(c1, -1, n)  # c1 的逆元
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

# 需要从通用库导入 egcd
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x, y = egcd(b % a, a)
    return (g, y - (b // a) * x, x)

m = common_modulus_attack(n, e1, e2, c1, c2)
print(m)
```

### 题型5：小公钥指数 e=3（低加密指数）

**特征**：e=3 且明文 m 很小，m^3 < n，此时 c = m^3（未取模），直接开立方根。

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

c = 0x10652cdf...  # 密文
e = 3
n = 0x00b8e7...   # 可能不需要，如果 m^3 < n

# 情况1: m^3 < n，直接开根
m = gmpy2.iroot(c, e)[0]
print(long_to_bytes(int(m)))

# 情况2: m^3 略大于 n，尝试 m^3 = c + k*n
for k in range(10000):
    m, exact = gmpy2.iroot(c + k * n, e)
    if exact:
        print(f"k = {k}")
        print(long_to_bytes(int(m)))
        break

# 情况3: 多组密文，使用 Hastad 广播攻击（见题型6）
```

### 题型6：Hastad 广播攻击

**特征**：e=3（或更小），同一明文用 不同 n 加密 3 次，得到 3 组 (n_i, c_i)。用中国剩余定理恢复 m^e。

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

# 假设 e=3，有 3 组数据
e  = 3
n1, c1 = 0x00a1..., 0x12f3...
n2, c2 = 0x00b2..., 0x23e4...
n3, c3 = 0x00c3..., 0x34f5...

def crt(residues, moduli):
    """中国剩余定理：求解 x ≡ r_i (mod m_i)"""
    from functools import reduce
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        yi = pow(Mi, -1, m)
        x += r * Mi * yi
    return x % M

def hastad_broadcast(e, pairs):
    """Hastad 广播攻击
    pairs: [(n1, c1), (n2, c2), ...]
    """
    ns = [p[0] for p in pairs]
    cs = [p[1] for p in pairs]
    M = crt(cs, ns)  # m^e mod (n1*n2*...*ne)
    m, exact = gmpy2.iroot(M, e)
    if exact:
        return long_to_bytes(int(m))
    return None

m = hastad_broadcast(e, [(n1,c1), (n2,c2), (n3,c3)])
print(m)
```

### 题型7：低解密指数攻击（Wiener 攻击）

**特征**：d < n^0.25（私钥很小），通常 e 很大。

```python
from Crypto.Util.number import long_to_bytes

n = 0x00d3ad9...  # 替换
e = 0x2f3d4e5...  # e 很大（d 很小）
c = 0x88aef2...

def wiener_attack(e, n):
    """Wiener 攻击：利用连分数逼近恢复 d"""
    # 计算 e/n 的连分数
    def continued_fraction(a, b):
        cf = []
        while b:
            q = a // b
            cf.append(q)
            a, b = b, a - q * b
        return cf

    # 从连分数得到渐进分数
    def convergents(cf):
        convs = []
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for q in cf:
            h_prev, h_curr = h_curr, q * h_curr + h_prev
            k_prev, k_curr = k_curr, q * k_curr + k_prev
            convs.append((h_curr, k_curr))
        return convs

    cf = continued_fraction(e, n)
    for k, d_candidate in convergents(cf):
        if k == 0:
            continue
        # 检查 (e*d - 1) / k 是否为整数
        if (e * d_candidate - 1) % k != 0:
            continue
        phi = (e * d_candidate - 1) // k
        # 由 phi = n - p - q + 1，解二次方程
        # p + q = n - phi + 1, p*q = n
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        import gmpy2
        sqrt_disc = gmpy2.isqrt(discriminant)
        if sqrt_disc * sqrt_disc == discriminant:
            p = (s + int(sqrt_disc)) // 2
            q = (s - int(sqrt_disc)) // 2
            if p * q == n:
                return d_candidate
    return None

d = wiener_attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
else:
    print("Wiener 攻击失败")
```

### 题型8：已知 p（或 q）

**特征**：题目直接给出 p 或 q（或可以从其他信息推出）。

```python
from Crypto.Util.number import long_to_bytes

p = 0x00f1a2b3...  # 已知 p
n = 0x00c4d5e6...  # n
e = 65537
c = 0x88aef2...

q = n // p
assert p * q == n

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### 题型9：素数生成缺陷（共享素数 / GCD）

**特征**：多个 n 共享某个素数因子。

```python
from Crypto.Util.number import long_to_bytes, GCD

e = 65537

# 多组公钥和密文
n1, c1 = 0x00a1..., 0x1234...
n2, c2 = 0x00b2..., 0x5678...
n3, c3 = 0x00c3..., 0x9abc...

def gcd_attack(ns, cs, e, target_idx=0):
    """检查多个 n 之间是否存在共享素数"""
    n_target = ns[target_idx]
    c_target = cs[target_idx]
    for i, n_other in enumerate(ns):
        if i == target_idx:
            continue
        g = GCD(n_target, n_other)
        if g > 1 and g < n_target:
            # 找到共享素数
            p = g
            q = n_target // p
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c_target, d, n_target)
            return long_to_bytes(m)
    return None

ns = [n1, n2, n3]
cs = [c1, c2, c3]
m = gcd_attack(ns, cs, e, target_idx=0)  # 对第0个密文解密
if m:
    print(m)
# 如果要解每个密文，遍历 target_idx
```

### 题型10：phi 已知

**特征**：题目直接给出 φ(n) 或可以推出。

```python
from Crypto.Util.number import long_to_bytes

n = 0x00d3a...
e = 65537
c = 0x88ae...
phi = 0x00c4b...  # 直接给出 φ(n)

d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))

# 如果给出的是 d，直接用
# m = pow(c, d, n)
```

### 题型11：dp / dq 泄露

**特征**：题目给出 dp = d mod (p-1) 或 dq = d mod (q-1)。

```python
from Crypto.Util.number import long_to_bytes, GCD

def decrypt_with_dp(n, e, c, dp):
    """已知 dp = d mod (p-1) 恢复明文"""
    # 遍历可能的 k: dp = d mod (p-1)
    # => e*dp ≡ 1 (mod (p-1))
    # => e*dp - 1 = k*(p-1)
    for k in range(1, e):
        if (e * dp - 1) % k == 0:
            p_candidate = (e * dp - 1) // k + 1
            if n % p_candidate == 0:
                p = p_candidate
                q = n // p
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                return long_to_bytes(m)
    return None

n  = 0x00d3a...
e  = 65537
c  = 0x88ae...
dp = 0x6f2b...

m = decrypt_with_dp(n, e, c, dp)
if m:
    print(m)
```

### 题型12：Rabin 密码体制（e=2）

**特征**：加密指数 e=2，即 c ≡ m^2 (mod n)。解密等同于求模 n 的平方根。

```python
from Crypto.Util.number import long_to_bytes

p = 0x00f1...  # 已知 p, q（均 ≡ 3 mod 4 最简单）
q = 0x00f2...
n = p * q
c = 0x88ae...  # c = m^2 mod n

def rabin_decrypt(c, p, q):
    """Rabin 密码体制解密：求解 m^2 ≡ c (mod n)"""
    n = p * q

    # p, q ≡ 3 mod 4 时，简单公式
    assert p % 4 == 3 and q % 4 == 3

    # 计算 mod p 和 mod q 下的平方根
    r = pow(c, (p + 1) // 4, p)
    s = pow(c, (q + 1) // 4, q)

    # CRT 组合 4 个解
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, yp, yq = extended_gcd(p, q)

    x1 = ( yp * p * s + yq * q * r) % n
    x2 = ( yp * p * s - yq * q * r) % n
    x3 = (-yp * p * s + yq * q * r) % n
    x4 = (-yp * p * s - yq * q * r) % n

    return [x1, n - x1, x2, n - x2]  # 4 个候选明文

candidates = rabin_decrypt(c, p, q)
for m in candidates:
    plaintext = long_to_bytes(m)
    # 4 个候选中只有一个是正确的明文
    if b'flag' in plaintext or b'ctf' in plaintext:
        print(plaintext)
        break
    else:
        print(f"候选: {plaintext}")
```

### 题型13：选择密文攻击（CCA）

**特征**：有解密 Oracle（可以向服务器提交密文获取解密结果），但不能直接提交目标密文 c。

```python
"""
利用 RSA 的同态特性:
  如果 c = m^e mod n，那么 (c * r^e) mod n = (m * r)^e mod n
  解密后得到 m*r mod n，再除以 r 就得到 m

适用场景: 有解密接口但禁止直接解密 c
"""
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random

n = 0x00d3a...
e = 65537
c = 0x88ae...  # 目标密文

# 选择随机 r
r = random.randint(2, n - 1)
# 构造新密文: c' = c * r^e mod n
c_prime = (c * pow(r, e, n)) % n

# 将 c' 提交给解密 Oracle（这里用模拟）
# 假设 oracle(c_prime) 返回 m' = m * r mod n
# m' = oracle(c_prime)  ← 向服务器提交

# 模拟演示 (已知私钥时)
d = ...  # 实际场景中没有 d，通过 Oracle 获取
m_prime = pow(c_prime, d, n)  # ← 实际场景用 Oracle 替代

# 恢复 m = m' * r^(-1) mod n
r_inv = pow(r, -1, n)
m = (m_prime * r_inv) % n
print(long_to_bytes(m))
```

### 题型14：n 因素分解（p-1 光滑 / Williams）

**特征**：p-1 全部由小素因子组成（B-smooth），可用 Pollard's p-1 算法分解。

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

n = 0x00d3a...
e = 65537
c = 0x88ae...

def pollard_p_minus_1(n, B=2**20):
    """Pollard's p-1 算法
    当 p-1 是 B-smooth（所有素因子 <= B）时可以分解 n
    """
    a = 2
    # 累乘 a^(k!) mod n，k 从 2 到 B
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 1000 == 0:
            d = gmpy2.gcd(a - 1, n)
            if 1 < d < n:
                return int(d)
    d = gmpy2.gcd(a - 1, n)
    if 1 < d < n:
        return int(d)
    return None

p = pollard_p_minus_1(n, B=2**20)  # B 可调大
if p:
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
else:
    print("Pollard p-1 失败，尝试增大 B 或换方法")
```

### RSA 题型快速识别表

| 题目特征 | 攻击方法 | 对应题型 |
|---------|---------|---------|
| n < 2^256 | 直接分解 / factordb | 1, 2 |
| p ≈ q | Fermat 分解 | 3 |
| 相同 n 不同 e | 共模攻击 | 4 |
| e=3, m^3<n | 开立方根 | 5 |
| e=3, 多组 n | Hastad 广播 | 6 |
| d 很小(e 很大) | Wiener 攻击 | 7 |
| 已知 p 或 q | 直接计算 | 8 |
| 多组 n 有公因数 | GCD 检查 | 9 |
| 已知 phi 或 d | 直接解密 | 10 |
| 已知 dp/dq | dp 泄露攻击 | 11 |
| e=2 | Rabin 解密 | 12 |
| 有解密接口 | 选择密文攻击 | 13 |
| p-1 光滑 | Pollard p-1 | 14 |

> AI生成

---

---

## Crypto - 古典密码全面速查

> 补充日期：2026-08-04 | 优先级：高 | 9种古典密码，每种配解密脚本

### 1. 凯撒密码（Caesar）

**原理**：字母表固定位移。位移量 k = 0~25。

```python
def caesar_decrypt_all(ciphertext):
    """枚举所有 25 种位移"""
    results = []
    for k in range(26):
        plain = ''
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                plain += chr((ord(ch) - base - k) % 26 + base)
            else:
                plain += ch
        results.append((k, plain))
    return results

cipher = "Khoor Zruog"  # 替换为密文
for k, plain in caesar_decrypt_all(cipher):
    print(f"k={k:2d}: {plain}")
# k=3 时输出 "Hello World"
```

### 2. 维吉尼亚密码（Vigenère）

> 笔记本题14已有实战记录，此处补充通用自动化解密脚本

```python
def vigenere_decrypt(ciphertext, key):
    """已知密钥时解密"""
    plain = ''
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)].upper()) - ord('A')
            plain += chr((ord(ch) - base - k) % 26 + base)
            key_idx += 1
        else:
            plain += ch
    return plain

# 未知密钥时，用 Kasiski 测试 + 重合指数法确定密钥长度和内容
# 推荐工具: pip install py-vigenere
# 或在线工具: https://www.guballa.de/vigenere-solver

cipher = "Lxfopv ef rnhr..."  # 替换为密文
key = "KEY"                    # 替换为已知密钥
print(vigenere_decrypt(cipher, key))
```

**Kasiski 测试（确定密钥长度）**：

```python
from collections import Counter
import re

def kasiski_test(ciphertext, min_repeat=3):
    """Kasiski 测试：通过重复子串间距推测密钥长度"""
    ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
    distances = []
    for length in range(min_repeat, len(ciphertext) // 2):
        for i in range(len(ciphertext) - length):
            pattern = ciphertext[i:i+length]
            # 查找重复出现
            next_pos = ciphertext.find(pattern, i + 1)
            if next_pos != -1:
                distances.append(next_pos - i)

    # 间距的 GCD 最可能就是密钥长度
    from math import gcd
    from functools import reduce
    if distances:
        common_gcd = reduce(gcd, distances)
        factor_counts = Counter()
        for d in distances:
            for f in range(2, 20):
                if d % f == 0:
                    factor_counts[f] += 1
        print("密钥长度候选（按频率排序）:")
        for length, count in factor_counts.most_common(5):
            print(f"  长度 {length}: 出现 {count} 次")
```

### 3. 栅栏密码（Rail Fence）

**原理**：将明文按行写入栅栏，逐行读出密文。

```python
def rail_fence_decrypt(cipher, rails):
    """栅栏密码解密"""
    # 计算每行字符数
    n = len(cipher)
    cycle = 2 * (rails - 1)

    # 标记每个字符所属的行
    marks = []
    for i in range(n):
        pos = i % cycle
        row = pos if pos < rails else cycle - pos
        marks.append(row)

    # 分配字符到各行
    rows = [[] for _ in range(rails)]
    idx = 0
    for r in range(rails):
        for i in range(n):
            if marks[i] == r:
                rows[r].append(cipher[idx])
                idx += 1

    # 按 marks 顺序读出
    row_ptrs = [0] * rails
    plain = ''
    for i in range(n):
        r = marks[i]
        plain += rows[r][row_ptrs[r]]
        row_ptrs[r] += 1
    return plain

cipher = "hloel ol!"  # 替换为密文
rails = 2              # 栅栏层数
print(rail_fence_decrypt(cipher, rails))

# 未知 rails 时，枚举 2~n/2
for r in range(2, len(cipher) // 2 + 1):
    result = rail_fence_decrypt(cipher, r)
    print(f"rails={r}: {result}")
```

### 4. 培根密码（Bacon）

**原理**：每个字母用 5 位二进制编码，A=00000, B=10001, ... 用 a/b、A/B 或 0/1 表示。

```python
def bacon_decrypt(ciphertext):
    """培根密码解密"""
    # 培根密码表 (标准 26 字母变体)
    bacon_table = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
        'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
        'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
        'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P',
        'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
        'BBAAA': 'Y', 'BBAAB': 'Z'
    }

    # 转换为 A/B 表示
    binary = ''
    for ch in ciphertext:
        if ch in 'Aa':
            binary += 'A'
        elif ch in 'Bb':
            binary += 'B'

    # 每5位一组解码
    plain = ''
    for i in range(0, len(binary) - 4, 5):
        group = binary[i:i+5]
        if group in bacon_table:
            plain += bacon_table[group]

    return plain

cipher = "AABAAABBAABAAAAABABAAAAB"  # 替换
print(bacon_decrypt(cipher))
```

### 5. 仿射密码（Affine）

> 笔记本题16已有实战记录，此处补充通用脚本

```python
def affine_decrypt(cipher, a, b):
    """仿射密码解密: E(x) = (a*x + b) mod 26, D(y) = a_inv*(y - b) mod 26"""
    # 求 a 的模逆
    a_inv = pow(a, -1, 26)
    plain = ''
    for ch in cipher:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            x = (a_inv * (y - b)) % 26
            plain += chr(x + base)
        else:
            plain += ch
    return plain

# 未知 a, b 时暴力枚举
from math import gcd
cipher = "KQQMQ..."  # 替换为密文

for a in range(1, 26):
    if gcd(a, 26) != 1:
        continue
    for b in range(26):
        result = affine_decrypt(cipher, a, b)
        if 'flag' in result.lower() or 'the' in result.lower():
            print(f"a={a}, b={b}: {result}")
```

### 6. ROT13

**原理**：凯撒密码的特例，固定 k=13（字母表的一半）。

```python
import codecs

cipher = "Synt{ubbx}"  # 替换
plain = codecs.decode(cipher, 'rot_13')
print(plain)  # Flag{hook}
```

### 7. 埃特巴什码（Atbash）

**原理**：字母表反转 A↔Z, B↔Y, ..., M↔N。

```python
def atbash(text):
    result = ''
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr(ord('Z') - (ord(ch) - base) + (0 if ch.isupper() else 32))
        else:
            result += ch
    return result

cipher = "Uizs"  # 替换
print(atbash(cipher))  # Frah
```

### 8. 摩尔斯电码（Morse）

```python
MORSE_TABLE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'",
    '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')',
    '.-...': '&', '---...': ':', '-.-.-.': ';', '-...-': '=',
    '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"',
    '...-..-': '$', '.--.-.': '@'
}

def morse_decode(morse_str):
    """摩尔斯电码解码，/ 或空格分隔单词"""
    words = morse_str.replace('/', ' ').split('  ')  # 双空格或/分单词
    result = []
    for word in words:
        chars = word.strip().split()
        decoded_word = ''.join(MORSE_TABLE.get(c, '?') for c in chars)
        result.append(decoded_word)
    return ' '.join(result)

cipher = ".... . .-.. .-.. ---"  # 替换为摩尔斯电码
print(morse_decode(cipher))  # HELLO
```

### 9. Playfair 密码

**原理**：5x5 字母矩阵，双字母一起加密。

```python
import string

def playfair_decrypt(ciphertext, key):
    """Playfair 密码解密"""
    # 构建 5x5 矩阵
    key = key.upper().replace('J', 'I')
    seen = set()
    matrix = []
    for ch in key + string.ascii_uppercase.replace('J', ''):
        if ch not in seen:
            seen.add(ch)
            matrix.append(ch)

    # 找字符在矩阵中的行列
    def find_pos(ch):
        idx = matrix.index(ch)
        return idx // 5, idx % 5

    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i].upper().replace('J','I'), ciphertext[i+1].upper().replace('J','I')
        r1, c1 = find_pos(a)
        r2, c2 = find_pos(b)

        if r1 == r2:  # 同行
            plaintext += matrix[r1*5 + (c1-1)%5]
            plaintext += matrix[r2*5 + (c2-1)%5]
        elif c1 == c2:  # 同列
            plaintext += matrix[(r1-1)%5*5 + c1]
            plaintext += matrix[(r2-1)%5*5 + c2]
        else:  # 矩形
            plaintext += matrix[r1*5 + c2]
            plaintext += matrix[r2*5 + c1]

    # 去除插入的 X
    plaintext = plaintext.replace('X', '')
    return plaintext

cipher = "BMODZBXNAB"  # 替换为密文
key = "PLAYFAIR"        # 替换为密钥
print(playfair_decrypt(cipher, key))
```

### 古典密码识别速查

| 密文特征 | 可能的密码 | 尝试方法 |
|---------|-----------|---------|
| 全字母，无明显规律 | 凯撒 | 枚举 25 位移 |
| 全字母，有周期性 | 维吉尼亚 | Kasiski 测试 |
| 全 A/B 或 a/b | 培根 | 5位一组 |
| 密文有数学系数关系 | 仿射 | 暴力 a,b |
| 点线和短横线 | 摩尔斯 | 查表 |
| 双字母分组 | Playfair | 需要密钥 |
| 字母频率接近自然语言 | 栅栏 | 枚举栏数 |
| 字母反转(A=Z) | Atbash | 反转 |

> AI生成

---

---

## Crypto - 散列攻击

> 补充日期：2026-08-04 | 优先级：高

### 1. MD5 碰撞

**原理**：找到两个不同输入产生相同 MD5 值。已有成熟方法可快速生成碰撞。

```python
"""
MD5 碰撞生成工具:
- HashClash (Marc Stevens)
- fastcoll (可快速生成前缀相同的碰撞)

CTF 常见套路:
1. 给出两个不同文件 md5 相同，要求构造
2. 给定前缀，构造两个 md5 相同的不同文件
3. 数组绕过: 利用 md5 碰撞使两个不同字符串的 md5 相等
   if(md5(a) == md5(b) && a != b) → 传入特定碰撞值
"""

# 场景1: PHP 弱类型绕过 (== 比较 md5 全为科学计数法)
# 当 md5 以 0e 开头且后续全为数字，== 比较时视为科学计数法 0
# 寻找 md5 值为 0eXXXXXXXX 的字符串
QNRMD5 = [
    "240610708",  # md5 = 0e462097431906509019562988736854
    "QNKCDZO",    # md5 = 0e830400451993494058024219903391
    "aabg7XSs",   # PHP 5.x
    "aabC9RqS",
]

# 验证
import hashlib
for s in QNRMD5:
    md5 = hashlib.md5(s.encode()).hexdigest()
    print(f"{s}: {md5}")

# PHP 中: md5("240610708") == md5("QNKCDZO") 为 True
# 因为 "0e..." == "0e..." 在 == 下被视为 0 == 0

# 场景2: 严格比较 (!=) 用数组绕过
# PHP: $_GET['a'] != $_GET['b'] 但 md5($_GET['a']) === md5($_GET['b'])
# 传入 a[]=1&b[]=2 → md5(Array) === md5(Array) → NULL === NULL → True
```

### 2. 长度扩展攻击（Length Extension Attack）

**原理**：已知 `Hash(secret || message)` 和 `len(secret)`，可以在不知道 secret 的情况下计算 `Hash(secret || message || padding || extension)`。适用于 MD5、SHA-1、SHA-256 等 Merkle-Damgård 结构散列。

**适用场景**：服务端用 `hash(secret + data)` 做认证，攻击者可以伪造追加数据后的合法 hash。

```python
# 工具: hashpumpy (pip install hashpumpy)
# 或 Python 原生实现

import struct
import hashlib

def md5_length_extension(original_hash, original_data, append_data, key_length):
    """MD5 长度扩展攻击
    original_hash: 已知的 hash(secret || original_data)
    original_data: 原始消息（不含 secret）
    append_data:   要追加的数据
    key_length:    secret 的长度
    """
    # 1. 从已知 hash 恢复 MD5 内部状态
    digest = bytes.fromhex(original_hash)
    # MD5 状态: 4 个 32 位字 (小端序)
    a = struct.unpack('<I', digest[0:4])[0]
    b = struct.unpack('<I', digest[4:8])[0]
    c = struct.unpack('<I', digest[8:12])[0]
    d = struct.unpack('<I', digest[12:16])[0]

    # 2. 计算 padding
    # total = key_length + len(original_data)
    # padding = 0x80 + \x00 * ... + length_bits (64-bit LE)
    total_len = key_length + len(original_data)
    padding = b'\x80'
    padding += b'\x00' * ((56 - (total_len + 1) % 64) % 64)
    padding += struct.pack('<Q', total_len * 8)

    # 3. 构造新消息（攻击者发送的内容）
    new_message = original_data + padding + append_data

    # 4. 计算 append_data 在新长度下的 hash
    new_total = key_length + len(new_message)
    # 用恢复的内部状态作为初始值，处理 append_data
    # 需要调用底层 _hashpump 或 hashpumpy 库

    # 推荐: 用 hashpumpy 库
    import hashpumpy
    new_hash, new_data = hashpumpy.hashpump(
        original_hash,
        original_data,
        append_data,
        key_length
    )
    return new_hash, new_data

# 使用示例
original_hash = '5e5e3a3de9e0c5f8c2f8e5f4...'  # 已知 hash
original_data = b'user=guest'                    # 已知消息
append_data   = b'&user=admin'                   # 追加内容
key_length    = 16                               # secret 长度

try:
    import hashpumpy
    new_hash, new_data = hashpumpy.hashpump(
        original_hash, original_data, append_data, key_length
    )
    print(f"新 Hash: {new_hash}")
    print(f"新 Data: {new_data}")  # 提交这个 data 和 hash
except ImportError:
    print("请安装: pip install hashpumpy")
    print("或使用: hash_extender (C 语言工具)")
    # hash_extender -f md5 -l 16 -d 'user=guest' -a '&user=admin' -s <原hash>
```

### 3. 哈希爆破

```python
import hashlib

# 字典爆破
def hash_bruteforce(target_hash, wordlist_path, algo='md5'):
    """用字典爆破哈希"""
    with open(wordlist_path, 'r', errors='ignore') as f:
        for line in f:
            word = line.strip()
            h = hashlib.new(algo, word.encode()).hexdigest()
            if h == target_hash:
                return word
    return None

# 常见在线爆破:
# https://cmd5.com (国内，支持中文)
# https://crackstation.net (国外，大字典)

# hashcat 离线爆破（推荐，GPU 加速）
# hashcat -m 0 hash.txt rockyou.txt        # MD5
# hashcat -m 100 hash.txt rockyou.txt       # SHA-1
# hashcat -m 1400 hash.txt rockyou.txt      # SHA-256
# hashcat -m 0 hash.txt -a 3 '?l?l?l?l?d'  # 模式爆破
```

> AI生成

---

---

## Crypto - Diffie-Hellman 与离散对数攻击

> 补充日期：2026-08-04 | 优先级：中

### Diffie-Hellman 密钥交换

```
公共参数: 大素数 p, 生成元 g
Alice: 选 a, 发送 A = g^a mod p
Bob:   选 b, 发送 B = g^b mod p
共享密钥: s = B^a mod p = A^b mod p = g^(ab) mod p

攻击前提: 能截获 A, B, 推出 a 或 b (离散对数问题)
```

### 1. 小步大步算法（Baby-Step Giant-Step）

**原理**：时间-空间折中算法，将离散对数问题复杂度从 O(p) 降到 O(√p)。

```python
def bsgs(g, h, p):
    """小步大步算法: 求 x 使得 g^x ≡ h (mod p)
    适用于 p 不太大（√p 在内存可接受范围内）
    """
    import math
    m = int(math.isqrt(p)) + 1

    # Baby step: g^j mod p → j
    table = {}
    power = 1
    for j in range(m):
        table[power] = j
        power = (power * g) % p

    # Giant step: h * (g^(-m))^i
    factor = pow(g, -m, p)  # g^(-m) mod p
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * factor) % p

    return None  # 无解

# 示例: 求 g^x ≡ c (mod p)
p = 17627874957797958951  # 替换
g = 98487224729781204589  # 替换
h = 12642893257552813465  # 替换 (h = g^x mod p)

x = bsgs(g, h, p)
if x is not None:
    print(f"x = {x}")
    assert pow(g, x, p) == h
```

### 2. Pohlig-Hellman 攻击

**原理**：当 p-1 分解为小素因子时，将离散对数问题分解到各小素因子上求解，再 CRT 合并。

```python
def pohlig_hellman(g, h, p):
    """Pohlig-Hellman 算法: 当 p-1 有小素因子时高效求解 DLP"""
    from sympy import factorint
    import math

    order = p - 1  # 群的阶
    factors = factorint(order)

    remainders = []
    moduli = []

    for q, e in factors.items():
        # 对每个素因子 q^e 求 x mod q^e
        gi = pow(g, order // (q**e), p)
        hi = pow(h, order // (q**e), p)
        # 用 BSGS 求 gi^xi ≡ hi (mod p)
        xi = bsgs(gi, hi, p)
        if xi is None:
            continue
        xi = xi % (q**e)
        remainders.append(xi)
        moduli.append(q**e)

    # CRT 合并
    return crt(remainders, moduli)

def crt(residues, moduli):
    """中国剩余定理"""
    from functools import reduce
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        yi = pow(Mi, -1, m)
        x += r * Mi * yi
    return x % M

# 当 p-1 是光滑数时非常有效
p = 0x00...  # 替换
g = 0x00...
h = 0x00...
x = pohlig_hellman(g, h, p)
if x:
    print(f"离散对数 x = {x}")
```

### 3. 中间人攻击（MITM）

```python
"""
DH 密钥交换中没有认证，攻击者可以中间人:
1. 截获 Alice 的 A，发送自己的 A' 给 Bob
2. 截获 Bob 的 B，发送自己的 B' 给 Alice
3. 与 Alice 共享 g^(a') mod p，与 Bob 共享 g^(b') mod p

CTF 中: 如果能插入通信，替换双方的公钥即可
防御: 引入数字签名认证 (如 STS 协议)
"""
```

> AI生成

---

---

## Crypto - 椭圆曲线密码 ECC 攻击

> 补充日期：2026-08-04 | 优先级：中

### ECC 基础

```
椭圆曲线: y² = x³ + ax + b (mod p)
基点 G，阶 n
私钥 d, 公钥 Q = dG
加密: 选随机 k, C1 = kG, C2 = M + kQ
解密: M = C2 - d*C1

关键问题: 已知 G, Q=dG，求 d (椭圆曲线离散对数 ECDLP)
```

### 1. Smart 攻击（异常曲线）

**特征**：曲线阶等于 p（#E(Fp) = p），此时曲线同构于有理数加法群，可直接求解。

```python
def smart_attack(P, Q, p):
    """Smart 攻击: 适用于 #E(Fp) = p 的异常曲线
    P: 基点 (x, y)
    Q: 公钥 (x, y) = d*P
    返回 d
    """
    # 椭圆曲线提升到 Qp (p-adic 数)
    E = EllipticCurve(GF(p), [a, b])  # 需要用 SageMath

    # 以下为 SageMath 代码
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0,p)*p for t in E.a_invariants()])
    P_Qp = Eqp.lift_x(ZZ(P.xy()[0]), all=True)[0]
    Q_Qp = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)[0]

    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    return int(GF(p)((x_Q/y_Q) / (x_P/y_P)))

# 注意: Smart 攻击需要在 SageMath 中运行
# SageMath 代码示例:
"""
p = 0x...
a = 0x...
b = 0x...
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
assert E.order() == p  # 确认是异常曲线
d = smart_attack(G, Q, p)
print(d)
"""
```

### 2. Pohlig-Hellman（ECC 版）

**原理**：当曲线阶 n 有小素因子时，将 ECDLP 分解。

```python
# SageMath 代码
"""
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
n = E.order()
# 如果 n 有小因子，直接用 discrete_log
d = discrete_log(Q, G, n, operation='+')
print(d)
"""
```

### 3. 无效曲线攻击

**原理**：如果服务端不验证输入点是否在曲线上，攻击者使用不同曲线上的点，每次泄露一部分私钥。

```python
# SageMath 代码
"""
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
n = E.order()

# 构造不同 b 值的曲线（但用相同的 a）
# 对每个 b', 找到阶有小因子的曲线
for b_test in range(p):
    try:
        E_test = EllipticCurve(GF(p), [a, b_test])
        order = E_test.order()
        # 检查 order 是否有小因子
        from sympy import factorint
        factors = factorint(order)
        small_factors = {f: e for f, e in factors.items() if f < 2**20}
        if small_factors:
            print(f"b'={b_test}, order={order}, small factors={small_factors}")
            # 在此曲线上选点，发给服务端，收集结果
    except:
        continue
"""
```

### ECC 攻击识别表

| 特征 | 攻击方法 | 工具 |
|------|---------|------|
| #E = p (异常曲线) | Smart 攻击 | SageMath |
| 阶有小因子 | Pohlig-Hellman | SageMath |
| 不验证点合法性 | 无效曲线攻击 | SageMath |
| p 小 | BSGS / 暴力 | Python |
| 曲线参数非标准 | 检查是否弱曲线 | SageMath |

> AI生成

---

---

## Crypto - 伪随机数攻击

> 补充日期：2026-08-04 | 优先级：中

### 1. 线性同余生成器（LCG）攻击

**原理**：LCG 公式 `s_{n+1} = (a * s_n + b) mod m`，已知连续输出即可恢复参数。

```python
from Crypto.Util.number import long_to_bytes

def crack_lcg(outputs, m=None):
    """从 LCG 连续输出恢复参数 a, b, m
    outputs: 连续输出列表 [s0, s1, s2, ...]
    m: 模数（如果已知）
    """
    s = outputs

    if m is None:
        # 未知 m: 用差分序列的 GCD 推断
        # t_i = s_{i+1} - s_i
        t = [s[i+1] - s[i] for i in range(len(s)-1)]
        # u_i = t_{i+1} * t_{i-1} - t_i^2
        u = [t[i+1] * t[i-1] - t[i]**2 for i in range(1, len(t)-1)]
        m = abs(u[0])
        for val in u[1:]:
            m = math.gcd(m, abs(val))
        print(f"恢复模数 m = {m}")

    # 已知 m 后求 a 和 b
    # s1 = a*s0 + b (mod m), s2 = a*s1 + b (mod m)
    # s2 - s1 = a*(s1 - s0) (mod m)
    a = ((s[2] - s[1]) * pow(s[1] - s[0], -1, m)) % m
    b = (s[1] - a * s[0]) % m
    print(f"a = {a}, b = {b}")

    # 预测下一个
    next_val = (a * s[-1] + b) % m
    print(f"下一个输出: {next_val}")
    return a, b, m, next_val

import math
# 示例
outputs = [12345, 67890, 11111, 22222]  # 替换为题目输出
a, b, m, nxt = crack_lcg(outputs)
```

### 2. 梅森旋转算法（MT19937）攻击

**原理**：Python 的 `random` 模块和许多语言默认 PRNG 使用 MT19937。已知连续 624 个 32 位输出可以恢复内部状态，预测未来输出。

```python
def untemper(y):
    """MT19937 逆变换：从输出恢复内部状态"""
    # 反转右移异或
    def undo_right(y, shift, mask=0xFFFFFFFF):
        result = y
        for i in range(32 // shift + 1):
            result = y ^ (result >> shift)
        return result & mask

    # 反转左移异或
    def undo_left(y, shift, mask=0xFFFFFFFF):
        result = y
        for i in range(32 // shift + 1):
            result = y ^ ((result << shift) & mask)
        return result & mask

    # MT19937 tempering 参数
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xEFC60000)
    y = undo_left(y, 7, 0x9D2C5680)
    y = undo_right(y, 11)
    return y

def recover_mt19937(outputs):
    """从 624 个连续 32 位输出恢复 MT19937 状态"""
    assert len(outputs) >= 624
    state = [untemper(x) for x in outputs[:624]]
    # 重新初始化 random 的状态
    import random
    mt = random.Random()
    mt.setstate((3, tuple(state + [624]), None))
    return mt

# 使用
outputs = [...]  # 替换为 624 个连续输出（0xFFFFFFFF 范围内）
if len(outputs) >= 624:
    rng = recover_mt19937(outputs)
    # 现在 rng 可以预测未来输出
    next_val = rng.getrandbits(32)
    print(f"预测下一个值: {next_val}")

# 如果输出是 getrandbits(64)，每两个 32 位组合一个 64 位
# 需要 1248 个连续输出
```

### 3. LFSR（线性反馈移位寄存器）攻击

**原理**：已知 LFSR 输出序列可建线性方程组恢复初始状态/反馈多项式。

```python
def crack_lfsr(output_bits, n):
    """已知 LFSR 输出和级数 n，恢复初始状态
    output_bits: 输出比特序列 [0, 1, 1, 0, ...]
    n: LFSR 级数
    """
    # 构建矩阵方程: A * state = output
    # 利用 Berlekamp-Massey 算法求最小多项式
    from sympy import Matrix, GF

    # 构建方程组
    # s_{i+n} = c_{n-1}*s_{i+n-1} + ... + c_0*s_i (mod 2)
    # 用前 2n 个输出恢复 n 个系数
    if len(output_bits) < 2 * n:
        return None

    # 构建矩阵
    A = []
    b = []
    for i in range(n):
        row = output_bits[i:i+n]
        A.append([int(x) for x in row])
        b.append(int(output_bits[i+n]))

    # 在 GF(2) 上求解
    from sympy import Matrix
    M = Matrix(A)
    try:
        # 增广矩阵求解
        aug = M.row_join(Matrix(b))
        rref, pivots = aug.rref()
        # 提取解
        coeffs = [int(aug[i, n] % 2) for i in range(n)]
        return coeffs
    except:
        return None

# 示例
bits = [0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1]  # 替换
n = 4  # LFSR 级数
coeffs = crack_lfsr(bits, n)
```

### 4. LCG 种子爆破

```python
"""
场景: Python random.seed(int) 中 seed 较小（如时间戳）
"""
import random
import time

# 如果 seed 是当前时间戳
target_output = 0x12345678  # 替换为已知输出

# 暴力枚举时间戳（假设在某个范围内）
for timestamp in range(1700000000, 1700001000):  # 替换范围
    random.seed(timestamp)
    if random.getrandbits(32) == target_output:
        print(f"找到 seed: {timestamp}")
        print(f"对应时间: {time.ctime(timestamp)}")
        # 恢复后可预测所有后续随机数
        break
```

> AI生成

---

---

## Crypto - 格密码基础

> 补充日期：2026-08-04 | 优先级：中 | CTF 进阶考点

### 基础概念

格（Lattice）是 n 维空间中离散点的集合。格密码的安全性基于格上的困难问题（SVP/CVP）。在 CTF 中，格归约算法（LLL）常用于解决看似不相关的问题。

### 1. LLL 算法解决隐藏数问题（HNP）

**场景**：已知多组 `(t_i, a_i)`，其中 `a_i ≈ k_i * secret + t_i (mod n)` 且泄露了高位，求 secret。

```python
# SageMath 代码
"""
from sage.all import *

# 场景: 已知 secret * t_i mod n 的高位 a_i
# 构造格:
# | n  0  0 ... 0 |
# | 0  n  0 ... 0 |
# | t1 t2 t3... 0 |
# | a1 a2 a3... B |
# LLL 归约后，短向量中包含 (k1, k2, ..., secret)

p = 0x...  # 模数
t = [t1, t2, t3, ...]  # 已知的 t_i
a = [a1, a2, a3, ...]  # 泄露的高位
n_bits = 256  # p 的位数
leaked_bits = 200  # 泄露的位数

m = len(t)
B = 2 ** (n_bits - leaked_bits)

# 构造格矩阵
M = matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M[i, i] = p
M[m, :m] = vector(t)
for i in range(m):
    M[m+1, i] = a[i]
M[m+1, m] = B
M[m+1, m+1] = 1

# LLL 归约
L = M.LLL()
# 短向量中提取 secret
for row in L:
    if abs(row[-1]) == 1:
        secret = row[-2] // B * (-1)
        if 0 < secret < p:
            print(f"secret = {secret}")
            break
"""
```

### 2. 背包密码系统（Knapsack）

**原理**：子集和问题。给定公钥和目标和，找到子集使其和等于目标。

```python
# SageMath 代码
"""
# 超增序列（私钥）→ 公钥变形
# 用 LLL 归约攻击

# 低密度子集和问题
# density = n / log2(max(a_i))
# density < 0.9408 时可以用 CJLOSS 算法

from sage.all import *

a = [int(x) for x in '公钥序列'.split()]  # 替换
s = 目标和  # 替换
n = len(a)

# 构造格
M = matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 1
    M[i, n] = a[i]
M[n, n] = -s

L = M.LLL()
# 找全 0 或 1 的行
for row in L:
    if all(x in (0, 1) for x in row[:n]):
        if sum(a[i] for i in range(n) if row[i] == 1) == s:
            print(f"解: {row[:n]}")
            break
"""
```

### 3. Coppersmith 方法

**原理**：已知模数 n 和多项式 f(x)，当 x 足够小时可以找到小根。用于 RSA 场景中部分明文已知的情况。

```python
# SageMath 代码
"""
from sage.all import *

# 场景1: 已知明文高位，求低位
# m = m_high + x，其中 x < n^(1/e)
n = 0x...
e = 3
c = 0x...
m_high = 0x...  # 已知的高位部分

P.<x> = PolynomialRing(Zmod(n))
f = (m_high + x)^e - c
roots = f.small_roots(X=2**64, beta=1, epsilon=0.05)
# X 是 x 的上界

# 场景2: 已知 p 的高位（Coppersmith partial p）
n = 0x...
p_high = 0x...  # 已知 p 的高位
known_bits = 比特数
unknown_bits = n.bit_length() // 2 - known_bits

P.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.small_roots(X=2**unknown_bits, beta=0.5)
if roots:
    p = p_high + int(roots[0])
    print(f"p = {p}")
"""
```

### 格密码识别速查

| 题目特征 | 可能的方法 |
|---------|-----------|
| 多组高位泄露 | LLL + HNP |
| 子集和问题 | LLL 背包攻击 |
| RSA 部分明文已知 | Coppersmith (small_roots) |
| RSA 部分 p 已知 | Coppersmith partial p |
| 线性方程组求小解 | LLL 归约 |
| NTRU 类问题 | LLL |

---

---

