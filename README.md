---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '2e430b98-d346-4671-bfa2-bf852300be14'
  PropagateID: '2e430b98-d346-4671-bfa2-bf852300be14'
  ReservedCode1: '1d2a5568-5755-4836-beb8-c3fa212b81dc'
  ReservedCode2: '1d2a5568-5755-4836-beb8-c3fa212b81dc'
---

# CTF 解题笔记本

> 比赛解题笔记 + 可复用脚本库，离线可用，断网可迁移。

## 目录结构

```
CTF解题笔记本/
├── CTF解题笔记本.md          # 主笔记本（27题完整记录 + 赛事情报 + 备考指南）
├── README.md                # 本文件
├── requirements.txt         # Python 依赖清单
├── Web/                     # Web 安全
│   ├── 01-php-eval/         #   #1 可变变量 + eval
│   ├── 02-php-sha1/         #   #2 sha1 数组绕过
│   ├── 03-flask-blind-sqli/ #   #3 Flask 布尔盲注
│   ├── 07-php-regex-base64/ #   #7 正则混淆 + Base64
│   ├── 08-sqli-union/       #   #8 UNION 回显注入
│   ├── 09-php-cookie/       #   #9 逻辑绕过 + Cookie
│   └── 17-traffic-analysis/  #17 流量分析 SQL盲注还原
│       └── solve.py
│   └── 20-file-upload-llf/   #20 文件上传 任意文件读取
│       └── solve.py
├── PWN/                     # 二进制利用
│   ├── 04-ret2text/         #   #4 栈溢出 + 后门
│   │   ├── exploit.py
│   │   └── decompiled.txt   #     IDA 反编译存档
│   └── 05-float-bypass/     #   #5 栈溢出 + 浮点绕过
│       ├── exploit.py
│       └── decompiled.txt
│   └── 06-bypwn/             #   #21 栈溢出+Ret2Shellcode
│   │   ├── exploit.py
│   │   └── decompiled.txt
│   └── 07-easyheap/           #   #22 堆溢出+Fastbin Attack
│       ├── exploit.py
│       └── decompiled.txt
│   └── pwn-arcanum/             # 通用 自动化PWN分析解题工具 (4种策略,一键出flag)
│       └── pwn_arcanum.py       #     ret2text/ret2shellcode/ret2syscall/ret2libc, 跨平台
├── Crypto/                  # 密码学
│   ├── 06-rsa-basic/        #   #6 RSA 基础解密
│   │   ├── rsa_decrypt.py
│   │   └── rsa_toolkit.py   #     可复用 RSA 工具库
│   ├── 14-bjdctf-yanzi/     #   #14 燕言燕语 Hex+维吉尼亚
│   │   └── solve.py
│   ├── 15-bjdctf-laowenmang/  #15 老文盲了 生僻字拼音
│   │   └── solve.py
│   └── 16-affine-cipher/     #   #16 仿射密码+模逆元
│       └── solve.py
│   └── 19-easyencode/        #   #19 五层嵌套编码
│       └── solve.py
├── Reverse/                 # 逆向工程
│   ├── 10-java-bytecode/    #   #10 Java 字节码逆向
│   ├── 11-python-pyc/       #   #11 Python pyc 逆向
│   ├── 12-elf-aes-md5/      #   #12 ELF 自修改+AES+MD5
│   │   ├── solve.py
│   │   ├── extract_data.py
│   │   ├── disasm.py
│   │   └── ida_analysis/    #     IDA 反编译存档
│   └── 13-pe-encryption-chain/  #13 PE 四阶段加密链
│       ├── solve.py
│       ├── analyze_pe.py
│       └── ida_analysis/    #     IDA 反编译存档
├── IR/                      # 应急响应 (Incident Response)
│   ├── 18-simpleflow-antsword/  #18 蚁剑Webshell流量分析
│   │   └── solve.py
│   └── 19-pcap-arcanum/           #23 PCAP Arcanum 流量取证工具 (13检测模块,一键出flag)
│       ├── pcap_arcanum.py      #     自动化流量分析工具
│       ├── log_arcanum.py       #     自动化日志分析工具 (7检测模块,一键出flag)
│       └── test_output/         #     测试输出 (报告+JSON+提取文件)
│   └── 20-redis-incident/        #24 Redis未授权访问应急响应
│       └── ir_scan.py            #     靶机SSH排查脚本
│   └── 21-win-web-ir/            #25 Windows Web应急响应
│       ├── win_web_ir.py         #     靶机排查脚本
│       └── kuang_analyze.py      #     挖矿程序逆向分析
│   └── 22-linux-web-ir2/         #26 Linux Web应急响应 (PHPEMS)
│       └── linux_web_ir2.py      #     靶机SSH排查脚本
│   └── auto-ir-scanner/          #通用 自动化IR扫描器 (18模块+智能分析+Flag汇总)
│       ├── ir_scanner.py         #     Linux版 v1.3 (1636行, SUID提权检测, JSON/HTML报告, Flag汇总)
│       └── ir_scanner_win.py     #     Windows版 v1.2 (~1980行, WinRM/pypsrp, 隐藏账户/Defender/驱动Rootkit检测, Flag汇总, JSON/HTML报告)
└── screenshots/             # 关键截图
```

## 题目概览

| #  | 类型     | 题目                  | Flag                            |
|----|----------|----------------------|---------------------------------|
| 1  | Web      | 可变变量 + eval       | flag{03bf915408d2349051395522ea5f4cf3} |
| 2  | Web      | sha1 数组绕过         | flag{f2bbcca065a83153280a94f74bb0ae81} |
| 3  | Web      | Flask 布尔盲注        | flag{4e8a47682414b4fba441d2a4108ba632} |
| 4  | PWN      | 栈溢出 + 后门         | CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88} |
| 5  | PWN      | 栈溢出 + 浮点绕过     | CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab} |
| 6  | Crypto   | RSA 基础             | 5577446633554466577768879988    |
| 7  | Web      | 正则混淆 + Base64    | (payload 验证通过)              |
| 8  | Web      | UNION 回显注入       | CTF2{4272c390-2265-40a3-b578-1661895a2d96} |
| 9  | Web      | 逻辑绕过 + Cookie    | CTF2{bb4ae566-9ae0-4e0a-b9d6-9d3bd18b1b2f} |
| 10 | Reverse  | Java 字节码逆向      | This_is_the_flag_!              |
| 11 | Reverse  | Python pyc 逆向      | GWHT{Just_Re_1s_Ha66y!}        |
| 12 | Reverse  | ELF 自修改+AES+MD5  | flag{924a9ab2163d390410d0a1f670} |
| 13 | Reverse  | PE 四阶段加密链      | flag{BruteForceIsAGoodwaytoGetFlag} |
| 14 | Crypto   | 燕言燕语 Hex+维吉尼亚 | bjd{yanzi_jiushige_shabi}             |
| 15 | Crypto   | 老文盲了 生僻字拼音   | BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}             |
| 16 | Crypto   | 仿射密码+模逆元      | flag{c29yY2VyeQ==}                     |
| 17 | Web      | 流量分析 SQL盲注还原  | flag{c84bb04a-8663-4ee2-9449-349f1ee83e11} |
| 18 | IR       | 蚁剑Webshell流量分析  | DASCTF{f3f32f434eddbc6e6b5043373af95ae8}   |
| 19 | Crypto   | easyencode 多层编码    | Dest0g3{Deoding_1s_e4sy_4_U}              |
| 20 | Web      | 文件上传 任意文件读取  | CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5} |
| 21 | PWN      | bypwn 栈溢出+shellcode | CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0} |
| 22 | PWN      | easyheap 堆溢出+Fastbin | CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c} |
| 23 | IR       | PCAP Arcanum 流量取证工具 | DASCTF{f3f3...} |
| 24 | IR       | Redis未授权访问应急响应 | flag{thisismybaby} flag{kfcvme50} flag{P@ssW0rd_redis} |
| 25 | IR       | Windows Web应急响应 | IP:192.168.126.1 账户:hack168$ 密码:rebeyond 矿池:wakuang.zhigongshanfang.top |
| 26 | IR       | Linux Web应急响应 (PHPEMS) | IP:192.168.20.131 密码:Network@2020 flag1-3 |
| 27 | IR       | Windows挖矿应急响应 (c3pool) | IP:192.168.115.131 端口:3389 矿池:auto.c3pool.org 钱包:4APXVhuk... |

```bash
pip install -r requirements.txt
```

核心库：gmpy2, pycryptodome, pwntools, capstone, pefile, sympy, scapy, paramiko, pypsrp

> **自动化IR扫描器（Linux版）**（`IR/auto-ir-scanner/ir_scanner.py`）：v1.3, 18模块全量排查, SUID提权检测(GTFOBins风格35+种二进制), 智能异常分析(基线对比+攻击链推断), **Flag汇总引擎(从全部模块结果中提取flag模式并标注来源)**, JSON/HTML报告, 自动Web根目录探测
>
> **自动化IR扫描器（Windows版）**（`IR/auto-ir-scanner/ir_scanner_win.py`）：v1.2, WinRM/pypsrp远程连接(默认端口5985), 18模块全量排查, 隐藏账户($结尾)检测, Windows Defender隔离区恢复, 未签名驱动检测, IFEO Debugger劫持, 智能异常分析(Windows基线+攻击链推断), **Flag汇总引擎(从全部模块结果中提取flag模式并标注来源)**, JSON/HTML报告, 实测248秒/17个发现/风险100
>
> **PWN Arcanum 工具**（`PWN/pwn-arcanum/pwn_arcanum.py`）：v1.2, 4种自动利用策略 — ret2text(调后门函数) / ret2shellcode(跳转shellcode) / ret2syscall(ROP链execve) / ret2libc(leak+system两阶段)，自动静态分析(保护检查/危险函数/后门检测/gadget搜索)，自动策略推荐，硬编码多架构shellcode(不依赖asm)，纯pwntools远程利用(跨平台Windows/macOS/Linux)
> - v1.2 修复：remote 模式全面重写 — 接收banner → sendline发payload(gets需\n) → cat-flag类型自动提取flag → shell类型先验证存活再交互 → Mac上interactive立即退出问题修复
> - v1.1 新增：cat-flag gadget 字节扫描 + gets缓冲区偏移自动检测
> - v1.0 基础：4种策略 + 自动分析 + 跨平台
>
> **PCAP Arcanum 工具**（`IR/19-pcap-arcanum/pcap_arcanum.py`）：13检测模块一键出flag — 蚁剑/冰蝎/哥斯拉/菜刀/CS + SQL注入还原 + 凭证提取 + DNS/ICMP隐写 + 反向Shell + Shiro反序列化 + 文件传输 + 协议统计/全局搜索
>
> **Log Arcanum 工具**（`IR/19-pcap-arcanum/log_arcanum.py`）：7检测模块一键出flag — SQL盲注还原(布尔/联合/报错/时间盲注) + Webshell检测(蚁剑/冰蝎/哥斯拉/菜刀) + 暴力破解(登录失败/成功统计) + 扫描探测(敏感路径/404/Log4Shell/XSS) + 文件传输(后门上传/数据下载/URL flag) + 凭证提取(URL参数/Base64/Cookie) + 统计分析+全局Flag搜索
>
> **自动化IR扫描器** 额外依赖：paramiko（Linux SSH远程连接）、pypsrp（Windows WinRM远程连接）
>
> **PyInstaller 逆向**额外依赖：uncompyle6（Python 3.8 .pyc 反编译）

### 离线迁移（比赛断网环境）

```bash
# 有网环境下载
pip download -r requirements.txt -d ./packages

# 拷贝 packages 到离线环境后安装
pip install --no-index --find-links=./packages -r requirements.txt
```

## 工具版本

| 工具 | 版本 | 用途 |
|------|------|------|
| IDA Pro | 9.3 | PWN/Reverse 反编译（路径 Z:\IDA\ida.exe） |
| Python | 3.12 | 脚本运行环境 |
| JDK | 1.8.0_271 | Java 逆向（javap） |
| uncompyle6 | 3.9 | Python 2.7/3.8 pyc 反编译 |
| xdis | latest | pyc 字节码反汇编（交叉验证） |
| pyinstxtractor | latest | PyInstaller 打包的 exe 解包 |

## 使用方式

1. 查阅 `CTF解题笔记本.md` 学习每道题的完整解题思路
2. 进入对应题型目录（如 `PWN/04-ret2text/`）运行脚本复现
3. PWN 和 Reverse 题目录下的 `ida_analysis/` 子目录存有 IDA 反编译原始输出
4. `requirements.txt` 一键安装所有依赖，支持离线迁移

## 分类统计

| 类型 | 题数 | 题号 |
|------|------|------|
| Web | 8 | #1, #2, #3, #7, #8, #9, #17, #20 |
| PWN | 4 | #4, #5, #21, #22 |
| Crypto | 5 | #6, #14, #15, #16, #19 |
| Reverse | 4 | #10, #11, #12, #13 |
| IR | 6 | #18, #23, #24, #25, #26, #27 |

**总计：27 题**

> AI生成
## Git 同步（Windows ↔ Mac）

仓库地址：https://github.com/daiKP/ctfmd

### 首次克隆（Mac 端）

```bash
git clone https://github.com/daiKP/ctfmd.git
cd ctfmd
pip3 install -r requirements.txt
```

### 日常同步

```bash
# Windows 端推送更新（解题后）
cd "C:\Users\j520x\.local\share\TeleAgent\TeleAgent的工作空间\test_output\CTF解题笔记本"
git add .
git commit -m "新增第XX题解题记录"
git push

# Mac 端拉取更新
cd ctfmd
git pull
```

### 跨平台注意事项

| 项目 | Windows | Mac | 说明 |
|------|---------|-----|------|
| IDA Pro | `Z:\IDA\ida.exe` | `/Applications/IDA Pro 9.3/ida` | 路径不同，按实际安装位置调整 |
| Python | `py -3` / `python` | `python3` | Mac 默认 python3 |
| pwntools | 原生支持 | `pip3 install pwntools` | Mac 需先装 brew + libmpc |
| gmpy2 | 预编译 wheel | `brew install gmp mpfr libmpc` 后 `pip3 install gmpy2` | Mac 需手动装依赖库 |
| paramiko | 原生支持 | `pip3 install paramiko` | Mac 原生支持 |
| pypsrp | 原生支持 | `pip3 install pypsrp` | Mac 原生支持 |

### Mac 端依赖安装

```bash
# Homebrew 基础库（gmpy2 依赖）
brew install gmp mpfr libmpc

# Python 依赖
pip3 install -r requirements.txt

# 验证关键库
python3 -c "import gmpy2; print('gmpy2 OK')"
python3 -c "import Crypto; print('pycryptodome OK')"
python3 -c "from pwn import *; print('pwntools OK')"
```

### 离线迁移（比赛断网环境）

在有网的 Mac 上打包依赖，拷贝到比赛机离线安装：

```bash
pip3 download -r requirements.txt -d ./packages
# 拷贝 packages/ 到比赛机后
pip3 install --no-index --find-links=./packages -r requirements.txt
```

> AI生成