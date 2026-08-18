---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '23ac2c64-ff86-4c1e-9cf6-e34fa0e75b78'
  PropagateID: '23ac2c64-ff86-4c1e-9cf6-e34fa0e75b78'
  ReservedCode1: '06bc64ac-b1aa-4f88-b91f-8dc86d2f02ad'
  ReservedCode2: '06bc64ac-b1aa-4f88-b91f-8dc86d2f02ad'
---

# CTF 解题笔记本

> 比赛解题笔记 + 可复用脚本库，离线可用，断网可迁移。

## 项目结构

```
ctfmd/
├── README.md                     # 本文件（主索引）
├── CTF解题笔记本.md              # 完整原始笔记本（11800+行，归档保留）
├── ctf_knowledge.db              # SQLite 知识库数据库
├── app.py                        # Web 查询系统入口
├── requirements.txt              # Python 依赖清单
│
├── docs/                         # 按方向拆分的知识文档
│   ├── Web方向.md                #   Web 安全（2400+行）
│   ├── PWN方向.md                #   二进制利用（1300+行）
│   ├── Crypto方向.md            #   密码学（2700+行）
│   ├── Reverse方向.md           #   逆向工程（1100+行）
│   ├── IR方向.md                 #   应急响应（1800+行）
│   ├── Misc方向.md              #   杂项/取证（800+行）
│   ├── IoT方向.md                #   物联网/车联网（1100+行）
│   ├── 综合方向.md               #   法律法规等（100+行）
│   └── 附录.md                   #   自动化工具/赛事情报
│
├── Web/                          # Web 解题脚本
│   ├── knowledge/                #   Web 知识点补充
│   │   ├── 文件解析配置利用-htaccess-userini.md  # .user.ini/.htaccess 文件解析控制
│   │   └── PHP伪协议详解-php-wrappers.md          # PHP 伪协议完整指南
│   ├── 03-flask-blind-sqli/     #   #3 Flask 布尔盲注
│   ├── 08-sqli-union/           #   #8 UNION 回显注入
│   ├── 17-traffic-analysis/     #   #17 流量分析 SQL盲注还原
│   ├── 20-file-upload-llf/      #   #20 文件上传 任意文件读取
│   └── tools/                    #   7个通用工具
│       ├── web_sqli_toolkit.py
│       ├── web_ssti_toolkit.py
│       ├── web_ssrf_toolkit.py
│       ├── web_lfi_toolkit.py
│       ├── web_rce_bypass.py
│       ├── web_php_audit.py
│       └── web_dir_scanner.py
│
├── PWN/                          # PWN 解题脚本
│   ├── 04-ret2text/             #   #4 栈溢出 + 后门
│   ├── 05-float-bypass/         #   #5 栈溢出 + 浮点绕过
│   ├── 06-bypwn/                #   #21 栈溢出 + Ret2Shellcode
│   ├── 07-easyheap/             #   #22 堆溢出 + Fastbin Attack
│   └── pwn-arcanum/             #   通用自动化PWN工具
│
├── Crypto/                       # 密码学解题脚本
│   ├── 06-rsa-basic/            #   #6 RSA 基础解密
│   ├── 14-bjdctf-yanzi/         #   #14 Hex+维吉利亚
│   ├── 15-bjdctf-laowenmang/   #   #15 生僻字拼音
│   ├── 16-affine-cipher/        #   #16 仿射密码
│   └── 19-easyencode/           #   #19 五层嵌套编码
│
├── Reverse/                      # 逆向工程解题脚本
│   ├── knowledge/               #   逆向知识点
│   │   └── 控制软件配置逆向分析.md  # C2配置提取方法论+双层RC4实战案例
│   ├── tools/                   #   逆向工具
│   │   ├── config_extractor.py  #   控制软件配置提取器(自动解密+信息提取)
│   │   └── deflower.py          #   花指令自动清除脚本(IDA Python, 11规则)
│   ├── 12-elf-aes-md5/          #   #12 ELF 自修改+AES+MD5
│   └── 13-pe-encryption-chain/  #   #13 PE 四阶段加密链
│
├── IR/                           # 应急响应解题脚本
│   ├── 18-simpleflow-antsword/  #   #18 蚁剑Webshell流量分析
│   ├── 19-pcap-arcanum/         #   #23 流量+日志自动化分析工具
│   ├── 20-redis-incident/       #   #24 Redis未授权访问
│   ├── 21-win-web-ir/           #   #25 Windows Web应急
│   ├── 22-linux-web-ir2/        #   #26 Linux Web应急
│   └── auto-ir-scanner/         #   通用IR扫描器(Linux+Windows)
│
└── screenshots/                  # 关键截图
```

## 知识体系总览

### 题目（28题）

| #  | 方向     | 题目                  | Flag |
|----|----------|----------------------|------|
| 1  | Web      | 可变变量 + eval       | flag{03bf915408d2349051395522ea5f4cf3} |
| 2  | Web      | sha1 数组绕过         | flag{f2bbcca065a83153280a94f74bb0ae81} |
| 3  | Web      | Flask 布尔盲注        | flag{4e8a47682414b4fba441d2a4108ba632} |
| 4  | PWN      | 栈溢出 + 后门         | CTF2{fd5d48ff-5eb9-4ed2-b9d6-3aca695e0a88} |
| 5  | PWN      | 栈溢出 + 浮点绕过     | CTF2{619d0c3f-3afe-4e01-8217-81ccc77243ab} |
| 6  | Crypto   | RSA 基础             | 5577446633554466577768879988 |
| 7  | Web      | 正则混淆 + Base64    | (payload 验证通过) |
| 8  | Web      | UNION 回显注入       | CTF2{4272c390-2265-40a3-b578-1661895a2d96} |
| 9  | Web      | 逻辑绕过 + Cookie    | CTF2{bb4ae566-9ae0-4e0a-b9d6-9d3bd18b1b2f} |
| 10 | Reverse  | Java 字节码逆向      | This_is_the_flag_! |
| 11 | Reverse  | Python pyc 逆向      | GWHT{Just_Re_1s_Ha66y!} |
| 12 | Reverse  | ELF 自修改+AES+MD5  | flag{924a9ab2163d390410d0a1f670} |
| 13 | Reverse  | PE 四阶段加密链      | flag{BruteForceIsAGoodwaytoGetFlag} |
| 14 | Crypto   | 燕言燕语 Hex+维吉尼亚 | bjd{yanzi_jiushige_shabi} |
| 15 | Crypto   | 老文盲了 生僻字拼音   | BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵} |
| 16 | Crypto   | 仿射密码+模逆元      | flag{c29yY2VyeQ==} |
| 17 | Web      | 流量分析 SQL盲注还原  | flag{c84bb04a-8663-4ee2-9449-349f1ee83e11} |
| 18 | IR       | 蚁剑Webshell流量分析  | DASCTF{f3f32f434eddbc6e6b5043373af95ae8} |
| 19 | Crypto   | easyencode 多层编码   | Dest0g3{Deoding_1s_e4sy_4_U} |
| 20 | Web      | 文件上传 任意文件读取 | CTF2{1cd01c68-f86c-49aa-b4e0-7ffb38d98ae5} |
| 21 | PWN      | bypwn 栈溢出+shellcode | CTF2{82c990a5-988f-4ba8-8458-f031e3df66c0} |
| 22 | PWN      | easyheap 堆溢出+Fastbin | CTF2{eeeec215-f3d6-41e3-961f-9544f77ed57c} |
| 23 | IR       | PCAP Arcanum 流量取证 | DASCTF{f3f3...} |
| 24 | IR       | Redis未授权访问应急响应 | flag{thisismybaby} 等3个 |
| 25 | IR       | Windows Web应急响应  | 账户:hack168$ 密码:rebeyond |
| 26 | IR       | Linux Web应急响应    | flag1-3 |
| 27 | IR       | Windows挖矿应急响应  | 矿池:auto.c3pool.org |
| 28 | PWN      | testpwn (Warm Up)    | SSL+ret2text自动化 |

### 知识点专题（27个）

#### Web 方向（9个专题 + 7个工具）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| SSTI 模板注入 | [Web方向.md](docs/Web方向.md) | Jinja2/Twig/Freemarker 检测+利用+绕过 |
| 反序列化漏洞 | [Web方向.md](docs/Web方向.md) | PHP POP链/Java/Object的 |
| SSRF 服务端请求伪造 | [Web方向.md](docs/Web方向.md) | 内网探测/协议构造/云元数据 |
| XSS 跨站脚本攻击 | [Web方向.md](docs/Web方向.md) | 反射/存储/DOM+绕过速查 |
| 文件包含漏洞 | [Web方向.md](docs/Web方向.md) | LFI/PHP伪协议/日志投毒 |
| 命令执行与代码执行 | [Web方向.md](docs/Web方向.md) | RCE绕过/无字母数字Webshell |
| 文件上传漏洞系统专题 | [Web方向.md](docs/Web方向.md) | 后缀绕过/.htaccess/图片马/竞争上传 |
| PHP 反序列化进阶 | [Web方向.md](docs/Web方向.md) | phar/session/__wakeup绕过 |
| Web 方向通用工具集 | [Web方向.md](docs/Web方向.md) | SQLi/SSTI/LFI/RCE/SSRF/审计/扫描 |

#### PWN 方向（4个专题）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| Ret2Libc 技术 | [PWN方向.md](docs/PWN方向.md) | 泄露libc/ROP链/one_gadget |
| 格式化字符串漏洞 | [PWN方向.md](docs/PWN方向.md) | 泄露/任意写/%n |
| 堆利用基础 | [PWN方向.md](docs/PWN方向.md) | fastbin/tcache/UAF/safe-linking |
| testpwn 自动化 | [PWN方向.md](docs/PWN方向.md) | SSL+ret2text自动利用 |

#### Crypto 方向（8个专题）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| RSA 全面题型手册 | [Crypto方向.md](docs/Crypto方向.md) | 14种RSA题型+脚本 |
| 古典密码全面速查 | [Crypto方向.md](docs/Crypto方向.md) | 凯撒/维吉尼亚/仿射等9种 |
| AES 分组密码与 Padding Oracle | [Crypto方向.md](docs/Crypto方向.md) | ECB/CBC/Padding Oracle |
| 散列攻击 | [Crypto方向.md](docs/Crypto方向.md) | MD5碰撞/长度扩展 |
| Diffie-Hellman 与离散对数 | [Crypto方向.md](docs/Crypto方向.md) | Pohlig-Hellman/BSGS |
| 椭圆曲线密码 ECC 攻击 | [Crypto方向.md](docs/Crypto方向.md) | Pohlig-Hellman/Smart |
| 伪随机数攻击 | [Crypto方向.md](docs/Crypto方向.md) | LCG/MT19937预测 |
| 格密码基础 | [Crypto方向.md](docs/Crypto方向.md) | LLL/CVP/隐藏数问题 |

#### Reverse 方向（2个专题 + 1个工具）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| 加密算法识别 | [Reverse方向.md](docs/Reverse方向.md) | 常量速查/IDA搜索/魔改AES+TEA还原 |
| 控制软件配置逆向分析 | [控制软件配置逆向分析.md](Reverse/knowledge/控制软件配置逆向分析.md) | C2配置提取/双层RC4/自动解密引擎 |

#### IR/Misc 方向（4个专题）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| 图片隐写 | [Misc方向.md](docs/Misc方向.md) | LSB/EXIF/文件头/宽高修改 |
| 压缩包技巧 | [Misc方向.md](docs/Misc方向.md) | 伪加密/爆破/ ZIP结构 |
| 内存取证 | [Misc方向.md](docs/Misc方向.md) | Volatility/进程提取 |
| 网络流量分析方法论 | [IR方向.md](docs/IR方向.md) | Wireshark过滤/DNS隧道/USB流量 |

#### IoT 方向（3个专题）
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| IoT 固件分析入门 | [IoT方向.md](docs/IoT方向.md) | binwalk/文件系统/MIPS+ARM |
| 车联网安全入门 | [IoT方向.md](docs/IoT方向.md) | CAN总线/UDS诊断/流量分析脚本 |
| QEMU 固件模拟运行 | [IoT方向.md](docs/IoT方向.md) | 用户态模拟/CGI测试/NVRAM |

#### 综合
| 专题 | 文档 | 关键内容 |
|------|------|---------|
| 网络安全法律法规高频考点 | [综合方向.md](docs/综合方向.md) | 网安法/数据安全法等 |

### 通用工具

| 工具 | 方向 | 路径 | 功能 |
|------|------|------|------|
| PWN Arcanum | PWN | [PWN/pwn-arcanum/](PWN/pwn-arcanum/pwn_arcanum.py) | 自动化利用框架v1.10(4625行) |
| PCAP Arcanum | IR | [IR/19-pcap-arcanum/](IR/19-pcap-arcanum/pcap_arcanum.py) | 13模块流量分析(2383行) |
| Log Arcanum | IR | [IR/19-pcap-arcanum/](IR/19-pcap-arcanum/log_arcanum.py) | 7模块日志分析(865行) |
| IR Scanner (Linux) | IR | [IR/auto-ir-scanner/](IR/auto-ir-scanner/ir_scanner.py) | 18模块Linux应急(1745行) |
| IR Scanner (Windows) | IR | [IR/auto-ir-scanner/](IR/auto-ir-scanner/ir_scanner_win.py) | 18模块Windows应急(1988行) |
| RSA Toolkit | Crypto | [Crypto/06-rsa-basic/](Crypto/06-rsa-basic/rsa_toolkit.py) | RSA多种题型(290行) |
| SQLi Toolkit | Web | [Web/tools/](Web/tools/web_sqli_toolkit.py) | 盲注/UNION/时间盲注(844行) |
| SSTI Toolkit | Web | [Web/tools/](Web/tools/web_ssti_toolkit.py) | 6引擎检测+利用(645行) |
| SSRF Toolkit | Web | [Web/tools/](Web/tools/web_ssrf_toolkit.py) | 检测/内网/云元数据(627行) |
| LFI Toolkit | Web | [Web/tools/](Web/tools/web_lfi_toolkit.py) | 多绕过/伪协议(622行) |
| RCE Bypass | Web | [Web/tools/](Web/tools/web_rce_bypass.py) | 绕过生成器(584行) |
| PHP Audit | Web | [Web/tools/](Web/tools/web_php_audit.py) | 代码审计(557行) |
| Dir Scanner | Web | [Web/tools/](Web/tools/web_dir_scanner.py) | 多线程目录扫描(329行) |
| DeFlower | Reverse | [Reverse/tools/](Reverse/tools/deflower.py) | 11规则花指令清除(IDA Python, 624行) |
| Config Extractor | Reverse | [Reverse/tools/](Reverse/tools/config_extractor.py) | C2配置自动提取+解密(846行) |

## Web 查询系统

启动本地 Web 界面，按方向浏览或关键字搜索全部知识点：

```bash
python3 app.py
# 浏览器打开 http://localhost:5000
```

功能：
- 按方向（Web/PWN/Crypto/Reverse/IR/IoT）分类浏览题目和专题
- 全文关键字搜索（FTS5），支持标题、内容、标签联合检索
- 题目/专题详情查看，含完整 Markdown 内容
- 工具脚本一览

## 分类统计

| 方向 | 题目 | 专题 | 工具 |
|------|------|------|------|
| Web | 10 | 9 | 7 |
| PWN | 5 | 4 | 1 |
| Crypto | 5 | 8 | 1 |
| Reverse | 4 | 2 | 2 |
| IR | 5 | 1 | 3 |
| IoT | 0 | 3 | 0 |
| 综合 | 0 | 1 | 0 |
| **合计** | **28** | **27** | **13** |

## 环境配置

```bash
pip install -r requirements.txt
```

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