---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'd8ba3ee8-6d7e-4559-a44f-ae22085bffb5'
  PropagateID: 'd8ba3ee8-6d7e-4559-a44f-ae22085bffb5'
  ReservedCode1: '82a3a977-03d5-4a3a-af82-b99b830ae9ff'
  ReservedCode2: '82a3a977-03d5-4a3a-af82-b99b830ae9ff'
---

# DASCTF Rabbit — CryptoJS RabbitLegacy 空密码解密

## 题目信息

- **平台**: DASCTF
- **类型**: Crypto
- **Flag**: `Cute_Rabbit`

## 密文分析

```
U2FsdGVkX1/+ydnDPowGbjjJXhZxm2MP2AgI
```

### 特征识别

1. **`U2FsdGVkX1`** = Base64 解码后为 **`Salted__`** — 这是 OpenSSL/CryptoJS 加密输出的标准前缀
2. 格式：`Salted__` + 8字节 salt + 密文
3. 题目名 **"rabbit"** 指向 **Rabbit 流密码算法**

### 二进制结构

```
53616c7465645f5f  fec9d9c33e8c066e  38c95e16719b630fd80808
  "Salted__"        8字节 salt         11字节密文
```

## 解题过程

### 尝试过程

| 尝试 | 结果 |
|------|------|
| `CryptoJS.Rabbit.decrypt(ct, 'rabbit')` | 解密成功但非有效 UTF-8 |
| `CryptoJS.Rabbit.decrypt(ct, '')` | 解密成功但非有效 UTF-8 |
| `openssl enc -rabbit -d` | LibreSSL 不支持 Rabbit |
| Python Rabbit 库 | 无可用库 |

### 关键突破：RabbitLegacy

CryptoJS 提供了两个 Rabbit 实现：

| 算法 | 说明 |
|------|------|
| `CryptoJS.Rabbit` | 修订版 Rabbit（与 OpenSSL 的 key 派生方式可能不同） |
| **`CryptoJS.RabbitLegacy`** | 旧版 Rabbit（与原始 OpenSSL 兼容） |

使用 **RabbitLegacy + 空密码** 解密成功：

```javascript
const CryptoJS = require('crypto-js');
const ct = 'U2FsdGVkX1/+ydnDPowGbjjJXhZxm2MP2AgI';
const bytes = CryptoJS.RabbitLegacy.decrypt(ct, '');
const plaintext = bytes.toString(CryptoJS.enc.Utf8);
// => "Cute_Rabbit"
```

## 知识点总结

### 1. OpenSSL Salted 格式

```
Base64(Salted__ + 8_bytes_salt + ciphertext)
```

- 前 8 字节固定为 `Salted__`（0x53616c7465645f5f）
- 接下来 8 字节是随机 salt
- 剩余是加密后的密文

### 2. CryptoJS Rabbit vs RabbitLegacy

| 特性 | Rabbit | RabbitLegacy |
|------|--------|-------------|
| IV 处理 | 修订后的 IV 设置 | 原始 IV 设置 |
| OpenSSL 兼容 | 可能不兼容 | **兼容** |
| CTF 出现频率 | 较少 | **更常见** |

在 CTF 中遇到 OpenSSL Salted 格式 + Rabbit 题目时，**优先尝试 `RabbitLegacy`**。

### 3. CryptoJS 密码模式

CryptoJS 的 `encrypt(text, password)` 使用内置 KDF（基于 MD5 的 EVP_BytesToKey）从密码派生密钥：
- 空密码 `''` 也是合法输入
- KDF: `MD5(password + salt)` → 16 字节密钥

### 4. CTF 密码学常见套路

| 套路 | 说明 |
|------|------|
| 题目名即算法 | 题名 "rabbit" → Rabbit 算法 |
| 弱密码/空密码 | 很多 CTF 题目使用空密码或简单密码 |
| CryptoJS 兼容性 | RabbitLegacy vs Rabbit 的区别 |
| Salted__ 格式 | 识别 OpenSSL/CryptoJS 加密格式 |

> AI生成