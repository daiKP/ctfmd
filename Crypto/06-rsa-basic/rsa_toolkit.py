#!/usr/bin/env python3
"""
CTF RSA 解题通用脚本库 (rsa_toolkit.py)
=========================================
封装 RSA 常用操作，优先使用 gmpy2 加速大数运算，
无 gmpy2 时自动回退到 Python 内置函数。

核心依赖: gmpy2, pycryptodome
可选依赖: sympy (因式分解), factordb (在线查表)

安装: pip install gmpy2 pycryptodome sympy
"""

# ============================================================
# 依赖加载（优先 gmpy2，回退内置）
# ============================================================
try:
    import gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False

from Crypto.Util.number import long_to_bytes, bytes_to_long

# ============================================================
# 基础运算
# ============================================================

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

def isqrt(n):
    """整数平方根"""
    if _HAS_GMPY2:
        return int(gmpy2.isqrt(n))
    import math
    return math.isqrt(n)

def iroot(n, k):
    """整数 k 次方根，返回 (root, is_exact)"""
    if _HAS_GMPY2:
        r, exact = gmpy2.iroot(n, k)
        return int(r), bool(exact)
    # 回退：二分搜索
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0, True
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo, (lo ** k == n)

def gcd(a, b):
    """最大公约数"""
    if _HAS_GMPY2:
        return int(gmpy2.gcd(a, b))
    import math
    return math.gcd(a, b)

def is_prime(n):
    """素性检测"""
    if _HAS_GMPY2:
        return gmpy2.is_prime(n)
    import sympy
    return sympy.isprime(n)

# ============================================================
# RSA 核心
# ============================================================

def rsa_decrypt(c, d, n):
    """RSA 解密: m = c^d mod n"""
    return powmod(c, d, n)

def rsa_encrypt(m, e, n):
    """RSA 加密: c = m^e mod n"""
    return powmod(m, e, n)

def rsa_compute_d(p, q, e):
    """已知 p, q, e 计算私钥 d"""
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)

def rsa_solve_with_pq(p, q, e, c):
    """已知 p, q, e, c 直接解密"""
    n = p * q
    d = rsa_compute_d(p, q, e)
    m = rsa_decrypt(c, d, n)
    return m, d, n

def long_to_text(m):
    """将明文整数转为可读文本，输出多种尝试"""
    results = []
    # bytes 转换
    b = long_to_bytes(m)
    results.append(('bytes', b))
    # 尝试 ASCII/UTF-8
    try:
        results.append(('utf-8', b.decode('utf-8')))
    except:
        pass
    try:
        results.append(('ascii', b.decode('ascii')))
    except:
        pass
    # 十进制字符串本身
    results.append(('decimal', str(m)))
    # hex
    results.append(('hex', hex(m)))
    return results

# ============================================================
# 因式分解（当 n 已知但 p/q 未知时）
# ============================================================

def factorize_n(n):
    """
    尝试因式分解 n。
    策略: sympy (本地, 适合中小数) -> factordb (在线, 适合大数)
    返回字典 {p: k, ...}
    """
    # 方法1: sympy (离线, Pollard rho + ECM)
    try:
        from sympy.ntheory import factorint
        factors = factorint(n)
        if factors:
            print(f"[*] sympy 分解成功: {factors}")
            return factors
    except Exception as e:
        print(f"[!] sympy 分解失败: {e}")

    # 方法2: factordb (在线查表)
    try:
        import factordb
        f = factordb.Factordb(n)
        f.connect()
        factors = f.get_factor_list()
        if factors:
            from collections import Counter
            factors_dict = dict(Counter(factors))
            print(f"[*] factordb 分解成功: {factors_dict}")
            return factors_dict
    except ImportError:
        print("[!] factordb 库未安装，跳过在线查表")
    except Exception as e:
        print(f"[!] factordb 查询失败: {e}")

    print("[!] 无法分解 n，可能需要 yafu/msieve 等外部工具")
    return None


# ============================================================
# 常见 RSA 攻击
# ============================================================

def attack_small_e(c, e, n=None):
    """
    小加密指数攻击: 当 m^e < n 时，直接开 e 次方
    也适用于多组同 n 不同 e 的广播攻击 (CRT 后开方)
    """
    m, exact = iroot(c, e)
    if exact:
        print(f"[+] 小指数攻击成功: e={e}, 开方精确")
        return m
    else:
        print(f"[-] 开方不精确，m^e >= n，小指数攻击失败")
        return None

def attack_common_modulus(n, e1, c1, e2, c2):
    """
    共模攻击: 同 n 不同 e (gcd(e1,e2)=1)
    m = c1^s1 * c2^s2 mod n, 其中 s1*e1 + s2*e2 = 1
    """
    from math import gcd as _gcd
    if _gcd(e1, e2) != 1:
        print("[-] gcd(e1,e2) != 1, 共模攻击不适用")
        return None
    # 扩展欧几里得
    def ext_gcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = ext_gcd(b, a % b)
        return g, y, x - (a // b) * y
    _, s1, s2 = ext_gcd(e1, e2)
    if s1 < 0:
        c1 = modinv(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        s2 = -s2
    m = (powmod(c1, s1, n) * powmod(c2, s2, n)) % n
    print(f"[+] 共模攻击成功")
    return m

def attack_wiener(e, n):
    """
    Wiener 攻击: 当 d < n^0.25 时，用连分数展开 e/n 恢复 d
    需要 gmpy2
    """
    if not _HAS_GMPY2:
        print("[-] Wiener 攻击需要 gmpy2")
        return None
    # 连分数逼近 e/n
    convergents = []
    num, den = e, n
    while den:
        q_val = num // den
        convergents.append(q_val)
        num, den = den, num - q_val * den
    # 逐个检查收敛子
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in convergents:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        # k_curr 是候选 d
        if k_curr == 0:
            continue
        phi_candidate = (e * k_curr - 1) // h_curr
        # 检查 phi 是否合理: n - phi + 1 = p + q, (p+q)^2 - 4n = (p-q)^2
        s = n - phi_candidate + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r, exact = gmpy2.iroot(disc, 2)
        if exact:
            p = (s + int(r)) // 2
            q = (s - int(r)) // 2
            if p * q == n:
                print(f"[+] Wiener 攻击成功: d={k_curr}")
                return int(k_curr)
    print("[-] Wiener 攻击失败")
    return None


# ============================================================
# 主函数: 第6题 RSA 基础解密
# ============================================================

if __name__ == '__main__':
    print("=" * 60)
    print("CTF 第6题: RSA 基础解密")
    print("=" * 60)

    # RSA 参数
    p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
    q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
    e = 65537
    c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034

    print(f"\n[*] gmpy2 加速: {'已启用' if _HAS_GMPY2 else '未安装(回退内置)'}")

    # Step 1: 计算 n, phi, d
    n = p * q
    phi = (p - 1) * (q - 1)
    d = rsa_compute_d(p, q, e)
    print(f"[*] n   = {n}")
    print(f"[*] phi = {phi}")
    print(f"[*] d   = {d}")

    # Step 2: 解密
    m = rsa_decrypt(c, d, n)

    # Step 3: 验证
    assert rsa_encrypt(m, e, n) == c, "验证失败!"
    print(f"[*] 验证: m^e mod n == c  ✓")

    # Step 4: 输出结果
    print(f"\n[*] m   = {m}")
    print(f"[*] hex = {hex(m)}")

    print(f"\n[*] 明文多种表示:")
    for label, val in long_to_text(m):
        print(f"    {label:8s}: {val}")

    print(f"\n[+] Secret message: {m}")
