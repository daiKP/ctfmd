#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Arcanum - 自动化流量取证分析工具
=====================================

自动识别 pcap/pcapng 中的 Webshell 管理工具和 C2 框架流量，
解码加密载荷，提取 flag 和攻击者操作时间线。

支持检测:
  1. 蚁剑 (AntSword)      - URL编码 + Base64 + 特征PHP函数
  2. 冰蝎 (Behinder)       - AES加密通信 (v3/v4)
  3. 哥斯拉 (Godzilla)      - AES/加密通信 (PHP/JSP)
  4. 中国菜刀 (Chopper)     - URL编码 + Base64 + eval/assert
  5. Cobalt Strike (CS)    - checksum8 URI + 心跳包 + Beacon特征
  6. 明文HTTP命令执行       - 通用Shell命令检测

输出:
  - 攻击工具识别结果
  - 解码后的命令和参数
  - 攻击时间线 (命令 → 响应)
  - 自动提取 flag
  - 文件下载/上传检测
  - 加密压缩包密码提取

用法:
  python pcap_arcanum.py <pcap文件路径> [--verbose] [--export-dir <dir>]
  python pcap_arcanum.py SimpleFlow.pcapng

依赖: pip install scapy pycryptodome
"""

import sys
import os
import re
import io
import json
import base64
import struct
import hashlib
import zipfile
import argparse
from collections import defaultdict, OrderedDict
from urllib.parse import unquote, parse_qs

try:
    from scapy.all import rdpcap, TCP, Raw, IP
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)

# AES解密支持 (冰蝎/哥斯拉)
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ============================================================
# TCP 流重组引擎
# ============================================================

class TCPStreamReassembler:
    """将散落的 TCP 包重组为完整的 HTTP 请求/响应对"""

    def __init__(self, packets):
        self.packets = packets
        self.streams = {}  # {stream_key: {'req': [data], 'resp': [data]}}
        self.http_pairs = []  # [(request_dict, response_bytes)]

    def reassemble(self):
        """重组所有TCP流并提取HTTP请求/响应对"""
        # 收集每个方向的TCP数据
        for pkt in self.packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp[Raw].load)

            # 确定流方向（4元组）
            fwd_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            rev_key = (ip.dst, tcp.dport, ip.src, tcp.sport)

            # 使用有序标识（小IP+小端口在前）
            if fwd_key <= rev_key:
                stream_key = fwd_key
                direction = 'req'
            else:
                stream_key = rev_key
                direction = 'resp'

            if stream_key not in self.streams:
                self.streams[stream_key] = {'req': [], 'resp': []}

            self.streams[stream_key][direction].append({
                'seq': tcp.seq,
                'data': payload,
                'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0
            })

        # 对每个流按seq排序并拼接
        for stream_key, dirs in self.streams.items():
            for direction in ['req', 'resp']:
                dirs[direction].sort(key=lambda x: x['seq'])
                dirs[direction] = b''.join([x['data'] for x in dirs[direction]])

        # 提取HTTP请求/响应对
        self._extract_http_pairs()
        return self.http_pairs

    def _extract_http_pairs(self):
        """从重组的流中提取 HTTP 请求/响应对"""
        for stream_key, dirs in self.streams.items():
            req_data = dirs['req']
            resp_data = dirs['resp']

            if not req_data:
                continue

            # 解析HTTP请求
            req = self._parse_http_request(req_data)
            if req is None:
                continue

            # 解析HTTP响应
            resp = self._parse_http_response(resp_data) if resp_data else None

            req['stream_key'] = stream_key
            req['response'] = resp
            self.http_pairs.append(req)

    def _parse_http_request(self, data):
        """解析 HTTP 请求数据"""
        if isinstance(data, bytes):
            try:
                text = data.decode('utf-8', errors='replace')
            except:
                text = data.decode('latin-1', errors='replace')
        else:
            text = data

        # 找到 HTTP 头部
        header_end = text.find('\r\n\r\n')
        if header_end < 0:
            return None

        headers = text[:header_end]
        body = text[header_end + 4:]

        lines = headers.split('\r\n')
        if not lines:
            return None

        # 解析请求行
        parts = lines[0].split(' ', 2)
        if len(parts) < 3:
            return None

        method, path, version = parts

        # 解析头部字段
        header_dict = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                header_dict[k.strip().lower()] = v.strip()

        return {
            'method': method,
            'path': path,
            'headers': header_dict,
            'body': body if isinstance(body, str) else body.encode('latin-1'),
            'raw': data if isinstance(data, bytes) else data.encode('latin-1'),
            'raw_headers': headers,
        }

    def _parse_http_response(self, data):
        """解析 HTTP 响应数据"""
        if isinstance(data, bytes):
            try:
                text = data.decode('utf-8', errors='replace')
            except:
                text = data.decode('latin-1', errors='replace')
        else:
            text = data

        header_end = text.find('\r\n\r\n')
        if header_end < 0:
            return {'raw': data, 'body': data, 'headers': {}}

        headers = text[:header_end]
        body_raw = data[header_end + 4:] if isinstance(data, bytes) else text[header_end + 4:].encode('latin-1')

        lines = headers.split('\r\n')
        status_line = lines[0] if lines else ''

        header_dict = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                header_dict[k.strip().lower()] = v.strip()

        # 处理 Transfer-Encoding: chunked
        body = body_raw
        if header_dict.get('transfer-encoding', '').lower() == 'chunked':
            body = self._dechunk(body_raw)

        # 处理 Content-Encoding: gzip
        if header_dict.get('content-encoding', '').lower() == 'gzip':
            try:
                import gzip
                body = gzip.decompress(body)
            except:
                pass

        return {
            'status': status_line,
            'headers': header_dict,
            'body': body,
            'raw': data,
        }

    def _dechunk(self, data):
        """解码 HTTP chunked 编码"""
        result = b''
        pos = 0
        if isinstance(data, str):
            data = data.encode('latin-1')
        while pos < len(data):
            # 找到 chunk size 行
            crlf = data.find(b'\r\n', pos)
            if crlf < 0:
                break
            try:
                size_str = data[pos:crlf].split(b';')[0].strip()
                chunk_size = int(size_str, 16)
            except:
                break
            if chunk_size == 0:
                break
            result += data[crlf + 2: crlf + 2 + chunk_size]
            pos = crlf + 2 + chunk_size + 2  # skip data + CRLF
        return result


# ============================================================
# 检测器基类
# ============================================================

class DetectorResult:
    """单个检测器的检测结果"""
    def __init__(self, tool_name, confidence, events=None, metadata=None):
        self.tool_name = tool_name
        self.confidence = confidence  # 0.0 - 1.0
        self.events = events or []
        self.metadata = metadata or {}

    def __repr__(self):
        return f"[{self.tool_name}] confidence={self.confidence:.0%}, events={len(self.events)}"


class AbstractDetector:
    """检测器基类"""
    name = "Abstract"

    def detect(self, http_pairs):
        """检测并返回 DetectorResult"""
        raise NotImplementedError

    def _extract_flag(self, text):
        """从文本中提取 flag"""
        if not text:
            return None
        if isinstance(text, bytes):
            text = text.decode('utf-8', errors='replace')

        # 匹配各种 flag 格式
        patterns = [
            r'DASCTF\{[^\}]+\}',
            r'Dest0g3\{[^\}]+\}',
            r'CTF2\{[^\}]+\}',
            r'CTF\{[^\}]+\}',
            r'flag\{[^\}]+\}',
            r'FLAG\{[^\}]+\}',
            r'GWHT\{[^\}]+\}',
            r'BJD\{[^\}]+\}',
            r'bjd\{[^\}]+\}',
            r'key\{[^\}]+\}',
            r'KEY\{[^\}]+\}',
            r'\bflag\s*[:=]\s*([^\s,;\}\]]+)',
        ]
        flags = []
        for pat in patterns:
            matches = re.findall(pat, text, re.IGNORECASE)
            if matches:
                if '[:=]' in pat:
                    flags.extend(matches)
                else:
                    flags.extend(matches)
        return flags[0] if flags else None


# ============================================================
# 蚁剑 (AntSword) 检测器
# ============================================================

class AntSwordDetector(AbstractDetector):
    """检测蚁剑(AntSword) Webshell 流量"""

    name = "蚁剑 (AntSword)"

    # 蚁剑特征
    SIGNATURES = [
        '@ini_set("display_errors", "0")',
        "ini_set(\"display_errors\"",
        '@eval(@base64_decode($_POST',
        '@eval(@base64_decode($_REQUEST',
        'antSword',
        'antsword',
        'ant.php',
    ]

    # 蚁剑默认 User-Agent
    UA_PATTERNS = [
        r'antSword',
        r'AntSword',
        r'antsword/v',
    ]

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            body = pair.get('body', '')
            if isinstance(body, bytes):
                body_str = body.decode('utf-8', errors='replace')
            else:
                body_str = body

            ua = pair.get('headers', {}).get('user-agent', '')

            # 检查特征
            is_antsword = False
            for sig in self.SIGNATURES:
                if sig in body_str:
                    is_antsword = True
                    matches += 1
                    break

            # 检查 UA 特征
            if not is_antsword:
                for pat in self.UA_PATTERNS:
                    if re.search(pat, ua, re.IGNORECASE):
                        is_antsword = True
                        matches += 1
                        break

            # 检查蚁剑常见POST参数模式 (参数名=base64编码内容)
            if not is_antsword:
                if self._check_antsword_param_pattern(body_str):
                    is_antsword = True
                    matches += 1

            if is_antsword:
                event = self._decode_antsword_request(pair)
                if event:
                    events.append(event)

        confidence = min(matches / 2.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)

    def _check_antsword_param_pattern(self, body):
        """检查是否符合蚁剑的POST参数模式"""
        # 蚁剑通常有 @eval(base64_decode($_POST['xxx'])) 结构
        if 'eval' in body and 'base64' in body and '_POST' in body:
            return True
        # 多个参数名是随机hex，值是base64编码
        params = {}
        for pair_str in body.split('&'):
            if '=' in pair_str:
                k, v = pair_str.split('=', 1)
                params[k] = unquote(v)
        if len(params) >= 2:
            # 检查是否有 base64 编码的值 且 参数名是随机 hex
            b64_values = 0
            hex_keys = 0
            for k, v in params.items():
                if re.match(r'^[a-f0-9]{8,}$', k):
                    hex_keys += 1
                if len(v) > 20 and re.match(r'^[A-Za-z0-9+/=]{20,}$', v[2:] if v[:2] in ('1f', '2d', 'cd') else v):
                    b64_values += 1
            if hex_keys >= 2 and b64_values >= 1:
                return True
        return False

    def _decode_antsword_request(self, http_pair):
        """解码单个蚁剑请求"""
        body = http_pair.get('body', '')
        if isinstance(body, bytes):
            body_str = body.decode('utf-8', errors='replace')
        else:
            body_str = body

        # 解析 POST 参数
        params = {}
        for pair_str in body_str.split('&'):
            if '=' in pair_str:
                k, v = pair_str.split('=', 1)
                params[k] = unquote(v)

        # 提取执行的命令
        commands = []
        for k, v in params.items():
            # 蚁剑参数通常前2个字符是编码标记(如 "cd"),后面是base64
            # 实际命令参数: 参数值去掉前2字符后base64解码
            decoded_cmd = None

            # 尝试方式1: 直接 base64 解码
            try:
                if len(v) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', v):
                    decoded = base64.b64decode(v).decode('utf-8', errors='replace')
                    if self._is_shell_command(decoded):
                        decoded_cmd = decoded
            except:
                pass

            # 尝试方式2: 去掉前2字符后 base64 解码
            if not decoded_cmd and len(v) > 12:
                try:
                    candidate = v[2:]
                    if re.match(r'^[A-Za-z0-9+/=]+$', candidate):
                        decoded = base64.b64decode(candidate).decode('utf-8', errors='replace')
                        if self._is_shell_command(decoded):
                            decoded_cmd = decoded
                except:
                    pass

            # 尝试方式3: URL解码后检查
            if not decoded_cmd:
                url_decoded = unquote(v)
                if self._is_shell_command(url_decoded):
                    decoded_cmd = url_decoded

            if decoded_cmd:
                commands.append(decoded_cmd)

        # 提取响应内容
        resp = http_pair.get('response', None)
        resp_content = ''
        zip_data = None
        if resp:
            resp_body = resp.get('body', b'')
            if isinstance(resp_body, bytes):
                # 检查是否是文件下载 (ZIP)
                if b'PK\x03\x04' in resp_body:
                    pk_start = resp_body.find(b'PK\x03\x04')
                    eocd = resp_body.find(b'PK\x05\x06')
                    if eocd >= 0:
                        zip_data = resp_body[pk_start:eocd + 22]
                    resp_content = '[ZIP文件下载]'

                # 蚁剑响应格式: 前12位hex + 内容 + 后12位hex
                elif len(resp_body) > 24:
                    resp_str = resp_body.decode('utf-8', errors='replace')
                    # 去掉蚁剑标记
                    if len(resp_str) > 24 and re.match(r'^[0-9a-f]{6,}', resp_str):
                        resp_content = resp_str[12:-12] if len(resp_str) > 24 else resp_str
                    else:
                        resp_content = resp_str[:500]
                else:
                    resp_content = resp_body.decode('utf-8', errors='replace')[:500]

        # 提取关键信息
        all_text = ' '.join(commands) + ' ' + resp_content
        flag = self._extract_flag(all_text)

        # 提取ZIP密码
        zip_password = None
        for cmd in commands:
            m = re.search(r'zip\s+-P\s+(\S+)', cmd)
            if m:
                zip_password = m.group(1)
                break

        # 构建命令描述
        cmd_summary = '; '.join(commands) if commands else '(无显式命令 - 可能是文件管理或数据库操作)'

        return {
            'timestamp': http_pair.get('stream_key', ('?',))[0],
            'method': http_pair.get('method', 'POST'),
            'path': http_pair.get('path', '/'),
            'commands': commands,
            'cmd_summary': cmd_summary[:200],
            'response': resp_content[:300] if resp_content else '(空)',
            'flag': flag,
            'zip_data': zip_data,
            'zip_password': zip_password,
            'raw_params': params,
        }


    def _is_shell_command(self, text):
        """判断是否是shell命令"""
        shell_keywords = [
            'cd ', 'ls ', 'cat ', 'head ', 'tail ', 'pwd', 'whoami', 'id',
            'uname', 'ifconfig', 'netstat', 'ps ', 'kill ', 'wget ', 'curl ',
            'find ', 'grep ', 'sed ', 'awk ', 'tar ', 'zip ', 'unzip ',
            'cp ', 'mv ', 'rm ', 'mkdir', 'chmod', 'chown', 'echo ',
            'base64 ', 'openssl ', 'python', 'perl', 'ruby', 'php ',
            'nc ', 'bash ', 'sh ', '/bin/', '/tmp/', 'flag', 'passwd',
            'shadow', 'sudo', 'su ', 'export', 'env', 'history',
            'mysql', 'sqlmap', 'nmap', 'masscan', 'hydra',
            'powershell', 'cmd ', 'certutil', 'bitsadmin',
        ]
        return any(kw in text.lower() for kw in shell_keywords)


# ============================================================
# 冰蝎 (Behinder) 检测器
# ============================================================

class BehinderDetector(AbstractDetector):
    """检测冰蝎(Behinder) Webshell 流量"""

    name = "冰蝎 (Behinder)"

    # 冰蝎特征
    # v2: 明文密钥交换 (第一次请求返回16字节key)
    # v3: 固定密钥 "e45e329feb5d925b" (AES key, MD5("rebeyond")前16位)
    # v4: 动态密钥协商

    BEHINDER_KEY_V3 = b'e45e329feb5d925b'  # 默认AES密钥

    # 冰蝎常见 Content-Type
    CONTENT_TYPES = [
        'application/octet-stream',
    ]

    # 冰蝎请求特征: 密钥协商阶段会请求shell脚本文件
    SHELL_PATTERN = re.compile(r'\.(php|jsp|asp|aspx)(\?|$)', re.IGNORECASE)

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            ct = pair.get('headers', {}).get('content-type', '')
            body = pair.get('body', b'')
            if isinstance(body, str):
                body = body.encode('latin-1')

            ua = pair.get('headers', {}).get('user-agent', '')

            # 冰蝎 v3 特征1: Content-Type: application/octet-stream 且 body 是 AES 加密数据
            is_behinder = False
            key_to_try = None

            # 特征: body 大小是 16 的倍数 (AES块对齐)
            if ct and 'octet-stream' in ct and len(body) > 0 and len(body) % 16 == 0:
                is_behinder = True
                key_to_try = self.BEHINDER_KEY_V3
                matches += 1

            # 特征: 请求的路径像 webshell (如 shell.php)
            if not is_behinder:
                path = pair.get('path', '')
                if self.SHELL_PATTERN.search(path):
                    # 检查 body 是否疑似加密数据 (高熵)
                    if len(body) > 16 and self._is_likely_encrypted(body):
                        is_behinder = True
                        key_to_try = self.BEHINDER_KEY_V3
                        matches += 1

            # 特征: 响应体也是加密的 (16字节对齐)
            resp = pair.get('response', None)
            if resp:
                resp_body = resp.get('body', b'')
                if isinstance(resp_body, str):
                    resp_body = resp_body.encode('latin-1')
                if is_behinder and len(resp_body) > 0 and len(resp_body) % 16 == 0:
                    if key_to_try:
                        pass  # 确认是冰蝎

            if is_behinder:
                event = self._decode_behinder_request(pair, key_to_try)
                events.append(event)

        confidence = min(matches / 2.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)

    def _is_likely_encrypted(self, data):
        """判断数据是否疑似加密 (高熵)"""
        if len(data) < 16:
            return False
        # 统计字节分布
        unique_bytes = len(set(data[:256]))
        return unique_bytes > 80  # 加密数据通常有较高的字节多样性

    def _decode_behinder_request(self, http_pair, key=None):
        """解密冰蝎请求"""
        body = http_pair.get('body', b'')
        if isinstance(body, str):
            body = body.encode('latin-1')

        decrypted = None
        if key and HAS_CRYPTO and len(body) % 16 == 0 and len(body) > 0:
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(body), AES.block_size).decode('utf-8', errors='replace')
            except:
                decrypted = '(AES解密失败 - 可能是自定义密钥)'

        if decrypted is None:
            decrypted = '(需AES-ECB解密, 默认key=e45e329feb5d925b, 可能被修改)'

        # 解密响应
        resp = http_pair.get('response', None)
        resp_decrypted = ''
        if resp:
            resp_body = resp.get('body', b'')
            if isinstance(resp_body, str):
                resp_body = resp_body.encode('latin-1')
            if key and HAS_CRYPTO and len(resp_body) % 16 == 0 and len(resp_body) > 0:
                try:
                    cipher = AES.new(key, AES.MODE_ECB)
                    resp_decrypted = unpad(cipher.decrypt(resp_body), AES.block_size).decode('utf-8', errors='replace')
                except:
                    resp_decrypted = '(响应AES解密失败)'
            else:
                resp_decrypted = '(响应体非16字节对齐或无法解密)'

        flag = self._extract_flag(decrypted + ' ' + resp_decrypted)

        return {
            'timestamp': http_pair.get('stream_key', ('?',))[0],
            'method': http_pair.get('method', 'POST'),
            'path': http_pair.get('path', '/'),
            'decrypted': decrypted[:500],
            'response_decrypted': resp_decrypted[:500],
            ' commands': self._extract_commands(decrypted),
            'cmd_summary': decrypted[:200] if decrypted else '(无法解密)',
            'flag': flag,
            'encryption': 'AES-ECB (key=e45e329feb5d925b)',
        }

    def _extract_commands(self, text):
        """从解密文本中提取shell命令"""
        if not text:
            return []
        commands = []
        # 冰蝎 payload 格式:通常是类JSON结构
        # {"status":"ok","msg":"cmd output"} 或 PHP代码
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, str) and len(v) > 2:
                        commands.append(v)
        except:
            # 非JSON, 按原始文本处理
            commands.append(text[:200])
        return commands


# ============================================================
# 哥斯拉 (Godzilla) 检测器
# ============================================================

class GodzillaDetector(AbstractDetector):
    """检测哥斯拉(Godzilla) Webshell 流量"""

    name = "哥斯拉 (Godzilla)"

    # 哥斯拉特征
    # PHP payload: @eval(@base64_decode($_POST['pass']))  类似蚁剑但有区别
    # 哥斯拉的请求体格式: pass=base64编码的payload
    # 哥斯拉 v4.0.1 默认密码: pass, 默认密钥: key (MD5后取前16位作为AES key)
    # 哥斯拉默认 key = "key" → MD5 = "3c6e0b8a9c15224a8228b9a98ca1531d" → 前16位 "3c6e0b8a9c15224a"

    GODZILLA_DEFAULT_KEY = b'3c6e0b8a9c15224a'

    # 哥斯拉常见 payload 结构特征
    SIGNATURES = [
        'eval(base64_decode',  # 与蚁剑共有
        'pass=',                # 哥斯拉默认密码参数
        'payload',
    ]

    # 哥斯拉响应特征: 前缀+加密结果+后缀
    # 前缀和后缀是固定字符串,用于标记

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            body = pair.get('body', b'')            # fix: was http_pair
            if isinstance(body, bytes):
                body_str = body.decode('utf-8', errors='replace')
            else:
                body_str = body

            ua = pair.get('headers', {}).get('user-agent', '')
            is_godzilla = False

            # 特征1: Java UA (哥斯拉是基于Java的)
            if 'Java/' in ua or 'java' in ua.lower():
                if 'pass=' in body_str or 'payload' in body_str:
                    is_godzilla = True
                    matches += 1

            # 特征2: 请求体中有 "pass=" 参数且内容是 base64
            if not is_godzilla and 'pass=' in body_str:
                params = parse_qs(body_str)
                if 'pass' in params:
                    val = params['pass'][0]
                    if len(val) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', val):
                        is_godzilla = True
                        matches += 1

            # 特征3: 哥斯拉独有的响应格式 (前17位 + 内容 + 后16位)
            resp = pair.get('response', None)
            if resp:
                resp_body = resp.get('body', b'')
                if isinstance(resp_body, bytes):
                    resp_str = resp_body.decode('utf-8', errors='replace')
                else:
                    resp_str = resp_body
                # 哥斯拉响应前缀: 通常是一些固定的标记字符
                if len(resp_str) > 33:
                    # 检查哥斯拉响应结构
                    if self._check_godzilla_response(resp_str):
                        is_godzilla = True
                        matches += 1

            if is_godzilla:
                event = self._decode_godzilla_request(pair)
                events.append(event)

        confidence = min(matches / 2.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)

    def _check_godzilla_response(self, text):
        """检查是否符合哥斯拉响应格式"""
        # 哥斯拉响应格式: 随机前缀(16) + base64加密数据 + 随机后缀(16)
        # 或者: 固定格式
        # 实际上哥斯拉响应体前几位和后几位是标记
        if len(text) < 33:
            return False
        # 检查中间部分是否是 base64 编码
        middle = text[16:-16]
        if len(middle) > 0 and re.match(r'^[A-Za-z0-9+/=]+$', middle):
            return True
        return False

    def _decode_godzilla_request(self, http_pair):
        """解码哥斯拉请求"""
        body = http_pair.get('body', b'')
        if isinstance(body, bytes):
            body_str = body.decode('utf-8', errors='replace')
        else:
            body_str = body

        # 解析参数
        params = {}
        for pair_str in body_str.split('&'):
            if '=' in pair_str:
                k, v = pair_str.split('=', 1)
                params[k] = unquote(v)

        # 哥斯拉请求结构:
        # pass=<base64编码的payload>
        # payload 解码后: <?php ... eval(base64_decode(<实际PHP代码>)) ...
        # 或者是 AES 加密的数据

        decoded_payload = None
        for k, v in params.items():
            # 尝试 base64 解码
            try:
                if len(v) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', v):
                    stage1 = base64.b64decode(v).decode('utf-8', errors='replace')
                    # 进一步解码内层
                    # 哥斯拉 PHP payload 通常有 eval(base64_decode('...'))
                    inner_match = re.search(r"base64_decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)", stage1)
                    if inner_match:
                        stage2 = base64.b64decode(inner_match.group(1)).decode('utf-8', errors='replace')
                        decoded_payload = stage2
                    else:
                        decoded_payload = stage1
            except:
                pass

        # 尝试 AES 解密
        aes_decrypted = None
        if HAS_CRYPTO and len(body) > 0:
            try:
                cipher = AES.new(self.GODZILLA_DEFAULT_KEY, AES.MODE_ECB)
                # 尝试解密
                body_bytes = body if isinstance(body, bytes) else body.encode('latin-1')
                if len(body_bytes) % 16 == 0:
                    aes_decrypted = unpad(cipher.decrypt(body_bytes), AES.block_size).decode('utf-8', errors='replace')
            except:
                pass

        # 解密响应
        resp = http_pair.get('response', None)
        resp_decrypted = ''
        if resp:
            resp_body = resp.get('body', b'')
            if isinstance(resp_body, str):
                resp_body = resp_body.encode('latin-1')
            # 哥斯拉响应: 去掉前16和后16字节,然后 base64 解码, 然后可能需要 AES 解密
            if len(resp_body) > 32:
                stripped = resp_body[16:-16]
                try:
                    decoded_resp = base64.b64decode(stripped)
                    if HAS_CRYPTO:
                        try:
                            cipher = AES.new(self.GODZILLA_DEFAULT_KEY, AES.MODE_ECB)
                            if len(decoded_resp) % 16 == 0:
                                resp_decrypted = unpad(cipher.decrypt(decoded_resp), AES.block_size).decode('utf-8', errors='replace')
                            else:
                                resp_decrypted = decoded_resp.decode('utf-8', errors='replace')
                        except:
                            resp_decrypted = decoded_resp.decode('utf-8', errors='replace')
                    else:
                        resp_decrypted = decoded_resp.decode('utf-8', errors='replace')
                except:
                    resp_decrypted = '(base64解码失败)'
            else:
                resp_decrypted = '(响应体过短)'

        all_decoded = (decoded_payload or '') + ' ' + resp_decrypted
        flag = self._extract_flag(all_decoded)

        return {
            'timestamp': http_pair.get('stream_key', ('?',))[0],
            'method': http_pair.get('method', 'POST'),
            'path': http_pair.get('path', '/'),
            'decoded_payload': decoded_payload[:500] if decoded_payload else '(无法解码)',
            'response_decrypted': resp_decrypted[:500],
            'aes_decrypted': aes_decrypted[:500] if aes_decrypted else None,
            'cmd_summary': decoded_payload[:200] if decoded_payload else '(无法解码)',
            'flag': flag,
            'encryption': 'AES-ECB (key=3c6e0b8a9c15224a)',
        }


# ============================================================
# 中国菜刀 (Chopper) 检测器
# ============================================================

class ChopperDetector(AbstractDetector):
    """检测中国菜刀(Chopper) Webshell 流量"""

    name = "中国菜刀 (Chopper)"

    SIGNATURES = [
        'eval(base64_decode($_POST',
        'assert($_POST',
        'eval($_POST',
        'eval(gzinflate(base64_decode',
        'Chopper',
    ]

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            body = pair.get('body', '')
            if isinstance(body, bytes):
                body_str = body.decode('utf-8', errors='replace')
            else:
                body_str = body

            is_chopper = False
            for sig in self.SIGNATURES:
                if sig in body_str:
                    is_chopper = True
                    matches += 1
                    break

            if is_chopper:
                event = self._decode_chopper_request(pair)
                events.append(event)

        confidence = min(matches / 1.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)

    def _decode_chopper_request(self, http_pair):
        """解码菜刀请求"""
        body = http_pair.get('body', '')
        if isinstance(body, bytes):
            body_str = body.decode('utf-8', errors='replace')
        else:
            body_str = body

        # 菜刀的POST体通常是: 参数=URL编码(base64_decode(eval payload))
        # 菜刀格式: zz1=base64("cd "/tmp";命令 2>&1"); zz2=base64("/bin/sh")
        params = {}
        for pair_str in body_str.split('&'):
            if '=' in pair_str:
                k, v = pair_str.split('=', 1)
                params[k] = unquote(v)

        commands = []
        for k, v in params.items():
            try:
                decoded = base64.b64decode(v).decode('utf-8', errors='replace')
                if any(kw in decoded.lower() for kw in ['cd ', 'ls', 'cat', 'pwd', 'whoami', 'id', 'find', 'zip', 'tar']):
                    commands.append(decoded)
            except:
                pass

        resp = http_pair.get('response', None)
        resp_content = ''
        if resp:
            resp_body = resp.get('body', b'')
            if isinstance(resp_body, bytes):
                resp_content = resp_body.decode('utf-8', errors='replace')[:500]
            else:
                resp_content = resp_body[:500]

        flag = self._extract_flag(' '.join(commands) + ' ' + resp_content)

        return {
            'timestamp': http_pair.get('stream_key', ('?',))[0],
            'method': http_pair.get('method', 'POST'),
            'path': http_pair.get('path', '/'),
            'commands': commands,
            'cmd_summary': '; '.join(commands)[:200] if commands else '(无法解码命令)',
            'response': resp_content[:300],
            'flag': flag,
        }


# ============================================================
# Cobalt Strike C2 检测器
# ============================================================

class CobaltStrikeDetector(AbstractDetector):
    """检测 Cobalt Strike Beacon C2 流量"""

    name = "Cobalt Strike"

    def __init__(self):
        # 预计算所有 checksum8 = 92 的4字母URI (32位stager)
        # 和 checksum8 = 93 的URI (64位stager)
        self.stager_uris_92 = self._generate_checksum8_uris(target_sum=92)
        self.stager_uris_93 = self._generate_checksum8_uris(target_sum=93)

    @staticmethod
    def _checksum8(text):
        """CS checksum8 算法: 所有ASCII字符的和 mod 256"""
        if not text:
            return 0
        return sum(ord(c) for c in text) % 256

    def _generate_checksum8_uris(self, target_sum=92, length=4):
        """预计算符合 checksum8 = target_sum 的 URI (仅4字符)"""
        # 对于4字符URI,计算量太大,改为运行时动态检查
        # 这里返回空集合,运行时检查
        return set()

    def detect(self, http_pairs):
        events = []
        matches = 0
        beacon_ips = set()

        # 统计每个客户端的请求频率 (心跳检测)
        client_requests = defaultdict(list)

        for pair in http_pairs:
            path = pair.get('path', '/')
            method = pair.get('method', '')
            headers = pair.get('headers', {})
            ua = headers.get('user-agent', '')
            stream_key = pair.get('stream_key', ('?',))
            client_ip = stream_key[0]

            # 提取URI路径 (去掉query string)
            uri_path = path.split('?')[0]
            # 去掉开头的 /
            uri_name = uri_path.lstrip('/')

            is_cs = False
            cs_type = []

            # 特征1: checksum8 stager URI (32位: sum=92, 64位: sum=93)
            if uri_name and len(uri_name) >= 2:
                csum = self._checksum8(uri_name)
                if csum == 92:
                    is_cs = True
                    cs_type.append('Stager URI (32-bit, checksum8=92)')
                    matches += 2
                elif csum == 93:
                    is_cs = True
                    cs_type.append('Stager URI (64-bit, checksum8=93)')
                    matches += 2

            # 特征2: CS默认UA (老版本)
            cs_uas = [
                'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
                'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)',
            ]
            if ua in cs_uas:
                is_cs = True
                cs_type.append(f'Default CS UA')
                matches += 1

            # 特征3: 周期性心跳请求 (CS Beacon 间隔通常为 30s/60s/120s)
            # 统计同一客户端的请求
            client_requests[client_ip].append(pair)

            # 特征4: 响应体特征 - CS stager 返回的PE文件 (MZ头)
            resp = pair.get('response', None)
            if resp:
                resp_body = resp.get('body', b'')
                if isinstance(resp_body, str):
                    resp_body = resp_body.encode('latin-1')
                if resp_body[:2] == b'MZ':
                    is_cs = True
                    cs_type.append('PE文件响应 (stager下载)')
                    matches += 2

                # 特征5: 响应头特征
                resp_headers = resp.get('headers', {})
                # CS 常用响应头特征
                ct = resp_headers.get('content-type', '')
                if ct and 'text/html' in ct and len(resp_body) > 0:
                    # 检查响应体是否是加密数据 (CS回传数据可能加密)
                    if self._is_likely_cs_payload(resp_body):
                        is_cs = True
                        cs_type.append('疑似CS加密响应')
                        matches += 1

            # 特征6: Cookie 特征 - CS有时在Cookie中编码元数据
            cookie = headers.get('cookie', '')
            if cookie and self._check_cs_cookie(cookie):
                is_cs = True
                cs_type.append('CS Cookie特征')
                matches += 1

            if is_cs:
                event = self._analyze_cs_event(pair, cs_type)
                events.append(event)
                beacon_ips.add(client_ip)

        # 心跳分析: 检查是否存在固定间隔的周期请求
        for client_ip, pairs_list in client_requests.items():
            if len(pairs_list) >= 3:
                intervals = []
                for i in range(1, len(pairs_list)):
                    t1 = pairs_list[i-1].get('_timestamp', 0)
                    t2 = pairs_list[i].get('_timestamp', 0)
                    if t1 and t2:
                        intervals.append(t2 - t1)
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    # CS 心跳间隔通常在 10s - 900s 之间
                    if 10 < avg_interval < 900:
                        # 检查间隔是否相对固定 (CS特征)
                        if len(intervals) >= 2:
                            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                            std_dev = variance ** 0.5
                            if std_dev < avg_interval * 0.3:  # 标准差小于均值的30%
                                events.append({
                                    'timestamp': client_ip,
                                    'type': 'CS心跳检测',
                                    'interval': f'{avg_interval:.1f}s',
                                    'request_count': len(pairs_list),
                                    'details': f'客户端 {client_ip} 存在周期性心跳 (间隔~{avg_interval:.0f}s), 符合CS Beacon特征',
                                })
                                matches += 2

        confidence = min(matches / 4.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)

    def _is_likely_cs_payload(self, data):
        """检查数据是否疑似CS payload (加密/编码)"""
        if len(data) < 16:
            return False
        unique = len(set(data[:128]))
        return unique > 60

    def _check_cs_cookie(self, cookie):
        """检查Cookie是否符合CS特征"""
        # CS有时会在Cookie中放置元数据
        # 格式: __cfduid=xxx 或自定义Cookie
        if len(cookie) > 100:
            return True
        return False

    def _analyze_cs_event(self, http_pair, cs_types):
        """分析单个CS事件"""
        resp = http_pair.get('response', None)
        resp_info = ''
        if resp:
            resp_body = resp.get('body', b'')
            if isinstance(resp_body, bytes) and resp_body[:2] == b'MZ':
                resp_info = f'[PE文件] {len(resp_body)} bytes (Beacon/Stage下载)'
            elif isinstance(resp_body, bytes):
                resp_info = f'[数据] {len(resp_body)} bytes (疑似加密数据)'
            else:
                resp_info = str(resp_body)[:100]

        return {
            'timestamp': http_pair.get('stream_key', ('?',))[0],
            'method': http_pair.get('method', ''),
            'path': http_pair.get('path', '/'),
            'cs_type': ', '.join(cs_types),
            'ua': http_pair.get('headers', {}).get('user-agent', '')[:100],
            'response_info': resp_info,
            'flag': self._extract_flag(resp_info),
        }


# ============================================================
# 通用 Shell 命令检测器 (检测明文命令执行)
# ============================================================

class GenericShellDetector(AbstractDetector):
    """检测明文HTTP命令执行流量"""

    name = "通用Shell命令"

    SHELL_INDICATORS = [
        r'whoami', r'uname\s+-[a-z]', r'ifconfig', r'ip\s+addr',
        r'cat\s+/etc/', r'cat\s+/proc/', r'ls\s+-[a-z]*la',
        r'id;', r'pwd;', r'wget\s+', r'curl\s+',
        r'python\s+-c', r'perl\s+-e', r'ruby\s+-e',
        r'nc\s+-[a-z]', r'bash\s+-i', r'/bin/sh',
        r'flag\{', r'CTF\{', r'DASCTF\{',
        r'sudo\s+', r'chmod\s+', r'chown\s+',
        r'mysql\s+-u', r'sqlmap', r'nmap\s+',
        r'powershell\s+', r'certutil\s+',
        r'base64\s+-d', r'openssl\s+enc',
    ]

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            body = pair.get('body', '')
            if isinstance(body, bytes):
                body_str = body.decode('utf-8', errors='replace')
            else:
                body_str = body

            resp = pair.get('response', None)
            resp_content = ''
            if resp:
                resp_body = resp.get('body', b'')
                if isinstance(resp_body, bytes):
                    resp_content = resp_body.decode('utf-8', errors='replace')
                else:
                    resp_content = resp_body

            all_text = body_str + ' ' + resp_content

            detected_indicators = []
            for pattern in self.SHELL_INDICATORS:
                if re.search(pattern, all_text, re.IGNORECASE):
                    detected_indicators.append(pattern.replace('\\s', ' ').replace('\\', ''))
                    matches += 1

            if detected_indicators:
                flag = self._extract_flag(all_text)
                events.append({
                    'timestamp': http_pair.get('stream_key', ('?',))[0],
                    'method': pair.get('method', ''),
                    'path': pair.get('path', '/'),
                    'indicators': detected_indicators,
                    'body': body_str[:200],
                    'response': resp_content[:200],
                    'flag': flag,
                })

        confidence = min(matches / 3.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)


# ============================================================
# 文件传输检测器
# ============================================================

class FileTransferDetector(AbstractDetector):
    """检测文件上传/下载 (ZIP, 图片, 二进制等)"""

    name = "文件传输"

    FILE_SIGNATURES = {
        b'PK\x03\x04': 'ZIP压缩包',
        b'\x89PNG': 'PNG图片',
        b'\xff\xd8\xff': 'JPEG图片',
        b'GIF8': 'GIF图片',
        b'\x7fELF': 'ELF可执行文件',
        b'MZ': 'PE可执行文件 (Windows)',
        b'\x1f\x8b': 'GZIP压缩包',
        b'BZ': 'BZIP2压缩包',
        b'Rar!': 'RAR压缩包',
        b'\x25\x50\x44\x46': 'PDF文档',
    }

    def detect(self, http_pairs):
        events = []
        matches = 0

        for pair in http_pairs:
            # 检查请求体 (上传)
            body = pair.get('body', b'')
            if isinstance(body, str):
                body = body.encode('latin-1')

            for sig, ftype in self.FILE_SIGNATURES.items():
                if sig in body:
                    events.append({
                        'timestamp': pair.get('stream_key', ('?',))[0],
                        'direction': '上传',
                        'file_type': ftype,
                        'method': pair.get('method', ''),
                        'path': pair.get('path', '/'),
                        'size': len(body),
                    })
                    matches += 1
                    break

            # 检查响应体 (下载)
            resp = pair.get('response', None)
            if resp:
                resp_body = resp.get('body', b'')
                if isinstance(resp_body, str):
                    resp_body = resp_body.encode('latin-1')

                for sig, ftype in self.FILE_SIGNATURES.items():
                    if sig in resp_body:
                        # 提取ZIP数据
                        zip_data = None
                        if sig == b'PK\x03\x04':
                            pk_start = resp_body.find(sig)
                            eocd = resp_body.find(b'PK\x05\x06')
                            if eocd >= 0:
                                zip_data = resp_body[pk_start:eocd + 22]

                        events.append({
                            'timestamp': pair.get('stream_key', ('?',))[0],
                            'direction': '下载',
                            'file_type': ftype,
                            'method': pair.get('method', ''),
                            'path': pair.get('path', '/'),
                            'size': len(resp_body),
                            'zip_data': zip_data,
                        })
                        matches += 1
                        break

        confidence = min(matches / 2.0, 1.0) if matches > 0 else 0.0
        return DetectorResult(self.name, confidence, events)


# ============================================================
# 主分析引擎
# ============================================================

class PCAPArcanum:
    """主分析引擎"""

    def __init__(self, pcap_path, verbose=False, export_dir=None):
        self.pcap_path = pcap_path
        self.verbose = verbose
        self.export_dir = export_dir
        self.results = OrderedDict()
        self.all_events = []
        self.all_flags = []

        # 初始化检测器 - 按优先级排序
        self.detectors = [
            AntSwordDetector(),      # 蚁剑 (最常见)
            GodzillaDetector(),      # 哥斯拉
            BehinderDetector(),      # 冰蝎
            ChopperDetector(),       # 菜刀
            CobaltStrikeDetector(),  # Cobalt Strike
            FileTransferDetector(),  # 文件传输
            GenericShellDetector(),  # 通用Shell命令 (最低优先级)
        ]

    def analyze(self):
        """执行完整分析"""
        print(f"[*] 加载 PCAP 文件: {self.pcap_path}")
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"[!] 无法读取PCAP文件: {e}")
            return None

        print(f"[*] 共 {len(packets)} 个数据包")

        # 为每个HTTP pair添加时间戳
        for pkt in packets:
            if hasattr(pkt, 'time'):
                setattr(pkt, '_timestamp', float(pkt.time))

        self.packets = packets
        self.http_pairs = []

        # TCP流重组
        print(f"[*] 重组 TCP 流...")
        reassembler = TCPStreamReassembler(packets)
        self.http_pairs = reassembler.reassemble()
        print(f"[*] 提取到 {len(self.http_pairs)} 个 HTTP 请求/响应对")

        if self.verbose:
            for i, pair in enumerate(self.http_pairs):
                print(f"  [{i}] {pair.get('method', '?')} {pair.get('path', '?')}"
                      f"  UA={pair.get('headers', {}).get('user-agent', '?')[:50]}")

        # 运行所有检测器
        print(f"\n[*] 开始流量特征检测...\n")
        for detector in self.detectors:
            result = detector.detect(self.http_pairs)
            self.results[detector.name] = result

            status = "✓ 检测到" if result.confidence > 0.3 else "✗ 未检测到"
            print(f"  {detector.name:20s}  {status}  置信度: {result.confidence:.0%}  事件数: {len(result.events)}")

            if result.events:
                for event in result.events:
                    if 'flag' in event and event['flag']:
                        self.all_flags.append({
                            'flag': event['flag'],
                            'source': detector.name,
                            'path': event.get('path', ''),
                        })
                    self.all_events.append({
                        'tool': detector.name,
                        **event,
                    })

        return self._generate_report()

    def _generate_report(self):
        """生成分析报告"""
        report = []
        report.append("=" * 70)
        report.append("  PCAP Arcanum - 流量取证分析报告")
        report.append("=" * 70)
        report.append(f"\n文件: {self.pcap_path}")
        report.append(f"时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # 工具检测结果
        report.append("-" * 70)
        report.append("  一、攻击工具识别")
        report.append("-" * 70)

        detected_tools = []
        for name, result in self.results.items():
            if result.confidence > 0.3:
                detected_tools.append((name, result))
                status = "✓ 确认" if result.confidence > 0.7 else "? 疑似"
                report.append(f"\n  [{status}] {name}  (置信度: {result.confidence:.0%})")

                if result.events:
                    report.append(f"  检测到 {len(result.events)} 个相关事件")

        if not detected_tools:
            report.append("\n  (未检测到已知攻击工具流量)")

        # 攻击时间线
        report.append("\n")
        report.append("-" * 70)
        report.append("  二、攻击时间线")
        report.append("-" * 70)

        # 按工具分组展示
        for name, result in self.results.items():
            if result.confidence > 0.3 and result.events:
                report.append(f"\n  ▸ {name}:")
                for i, event in enumerate(result.events):
                    # 过滤掉心跳事件(除非verbose)
                    if event.get('type') == 'CS心跳检测' and not self.verbose:
                        continue

                    report.append(f"\n  [{i+1}] 时间标识: {event.get('timestamp', '?')}")
                    if 'method' in event:
                        report.append(f"      请求: {event.get('method', '')} {event.get('path', '')}")

                    if 'cmd_summary' in event:
                        report.append(f"      命令: {event.get('cmd_summary', '')[:150]}")
                    if 'commands' in event and event['commands']:
                        for cmd in event['commands']:
                            report.append(f"      └─ {cmd[:150]}")

                    if 'decrypted' in event:
                        report.append(f"      解密: {event.get('decrypted', '')[:150]}")
                    if 'decoded_payload' in event and event['decoded_payload'] != '(无法解码)':
                        report.append(f"      解码: {event.get('decoded_payload', '')[:150]}")
                    if 'response' in event:
                        report.append(f"      响应: {event.get('response', '')[:150]}")
                    if 'response_decrypted' in event and event['response_decrypted']:
                        report.append(f"      响应解密: {event.get('response_decrypted', '')[:150]}")
                    if 'response_info' in event:
                        report.append(f"      响应: {event.get('response_info', '')[:150]}")
                    if 'cs_type' in event:
                        report.append(f"      类型: {event.get('cs_type', '')}")
                    if 'file_type' in event:
                        report.append(f"      文件: {event.get('direction', '')} {event.get('file_type', '')} ({event.get('size', 0)} bytes)")
                    if 'indicators' in event:
                        report.append(f"      指标: {', '.join(event.get('indicators', []))}")
                    if 'encryption' in event:
                        report.append(f"      加密: {event.get('encryption', '')}")
                    if 'interval' in event:
                        report.append(f"      心跳间隔: {event.get('interval', '')}")

        # ZIP 文件处理 (在 Flag 提取之前,以便从ZIP中发现flag)
        report.append("\n")
        report.append("-" * 70)
        report.append("  三、文件传输分析")
        report.append("-" * 70)

        zip_files = []
        seen_zip_hashes = set()  # 去重
        # 从所有检测器事件中收集ZIP数据
        for event in self.all_events:
            if 'zip_data' in event and event['zip_data']:
                zip_hash = hashlib.md5(event['zip_data']).hexdigest()
                if zip_hash not in seen_zip_hashes:
                    seen_zip_hashes.add(zip_hash)
                    zip_files.append(event)
            if 'zip_password' in event and event['zip_password']:
                report.append(f"\n  密码提取: {event['zip_password']}")
                report.append(f"    来源: {event.get('tool', '')} - 命令中包含 zip -P 参数")

        for i, event in enumerate(zip_files):
            report.append(f"\n  [{i+1}] ZIP压缩包 ({len(event['zip_data'])} bytes)")
            report.append(f"      传输方向: {event.get('direction', '?')}")
            report.append(f"      请求路径: {event.get('path', '?')}")

            # 尝试解压
            try:
                zf = zipfile.ZipFile(io.BytesIO(event['zip_data']))
                report.append(f"      文件列表: {zf.namelist()}")
                for name in zf.namelist():
                    # 检查是否需要密码
                    if zf.infolist()[0].flag_bits & 0x1:
                        # 需要密码,尝试已知密码
                        passwords = [event.get('zip_password', b''), b'PaSsZiPWorD', b'password', b'flag', b'123456']
                        extracted = False
                        for pwd in passwords:
                            if pwd:
                                try:
                                    content = zf.read(name, pwd=pwd.encode() if isinstance(pwd, str) else pwd)
                                    report.append(f"      [{name}] (密码: {pwd})")
                                    report.append(f"        内容: {content.decode('utf-8', errors='replace')[:200]}")
                                    flag = self._extract_flag_global(content.decode('utf-8', errors='replace'))
                                    if flag:
                                        report.append(f"        ✓ FLAG: {flag}")
                                        self.all_flags.append({'flag': flag, 'source': f'ZIP解压({name})', 'path': event.get('path', '')})
                                    extracted = True
                                    break
                                except:
                                    continue
                        if not extracted:
                            report.append(f"      [{name}] (加密,密码未知)")
                    else:
                        content = zf.read(name)
                        report.append(f"      [{name}]")
                        report.append(f"        内容: {content.decode('utf-8', errors='replace')[:200]}")
                        flag = self._extract_flag_global(content.decode('utf-8', errors='replace'))
                        if flag:
                            report.append(f"        ✓ FLAG: {flag}")
                            self.all_flags.append({'flag': flag, 'source': f'ZIP解压({name})', 'path': event.get('path', '')})
            except Exception as e:
                report.append(f"      (ZIP解析失败: {e})")

        # Flag 提取
        report.append("\n")
        report.append("-" * 70)
        report.append("  四、Flag 提取")
        report.append("-" * 70)

        # 全局搜索补充flag
        if not self.all_flags:
            for event in self.all_events:
                for key in ['response', 'response_decrypted', 'decrypted', 'decoded_payload',
                           'body', 'cmd_summary', 'response_info']:
                    val = event.get(key, '')
                    if isinstance(val, list):
                        val = ' '.join(str(v) for v in val)
                    if val and isinstance(val, str):
                        flag = self._extract_flag_global(val)
                        if flag:
                            self.all_flags.append({'flag': flag, 'source': '全局文本搜索', 'path': event.get('path', '')})

        if self.all_flags:
            seen_flags = set()
            for flag_info in self.all_flags:
                if flag_info['flag'] not in seen_flags:
                    seen_flags.add(flag_info['flag'])
                    report.append(f"\n  ✓ {flag_info['flag']}")
                    report.append(f"    来源: {flag_info['source']}  路径: {flag_info['path']}")
        else:
            report.append("\n  (未自动检测到 flag, 建议人工检查响应内容)")

        # 建议
        report.append("\n")
        report.append("-" * 70)
        report.append("  五、分析建议")
        report.append("-" * 70)

        suggestions = []
        for name, result in self.results.items():
            if result.confidence > 0.7:
                if '蚁剑' in name:
                    suggestions.append("• 蚁剑流量已确认, 建议检查所有 POST 参数中的 Base64 编码命令")
                    suggestions.append("• 关注 zip -P 参数获取压缩包密码, 以及 readfile/download 等文件下载操作")
                elif '冰蝎' in name:
                    suggestions.append("• 冰蝎流量已确认, 通信使用 AES-ECB 加密, 默认密钥 e45e329feb5d925b")
                    suggestions.append("• 如果默认密钥解密失败, 可能使用了自定义密钥, 需要找密钥协商阶段的握手包")
                elif '哥斯拉' in name:
                    suggestions.append("• 哥斯拉流量已确认, 默认 AES 密钥 3c6e0b8a9c15224a (MD5('key')前16位)")
                    suggestions.append("• 哥斯拉响应格式: 前16字节标记 + Base64(AES加密数据) + 后16字节标记")
                elif '菜刀' in name:
                    suggestions.append("• 中国菜刀流量已确认, 参数值通常为 Base64编码, 解码后包含 shell 命令")
                elif 'Cobalt Strike' in name:
                    suggestions.append("• Cobalt Strike C2 流量已确认, 检查 checksum8 URI 和心跳包间隔")
                    suggestions.append("• CS Stage 下载返回 PE 文件, 可提取 Beacon 样本进行逆向分析")
                    suggestions.append("• 关注 C2 服务器 IP, 可结合 Threat Intelligence 进行归属分析")

        if not suggestions:
            suggestions.append("• 未检测到明确的攻击工具流量, 建议人工检查 HTTP 请求路径和参数")
            suggestions.append("• 可尝试使用 Wireshark 的 'Follow TCP Stream' 功能人工分析流量")

        for s in suggestions:
            report.append(f"\n  {s}")

        # 元信息
        report.append("\n")
        report.append("-" * 70)
        report.append("  六、元信息")
        report.append("-" * 70)
        report.append(f"\n  数据包总数: {len(self.packets) if hasattr(self, 'packets') else '?'}")
        report.append(f"  HTTP请求对数: {len(self.http_pairs) if hasattr(self, 'http_pairs') else '?'}")
        report.append(f"  检测器数量: {len(self.detectors)}")
        report.append(f"  事件总数: {len(self.all_events)}")
        report.append(f"  Flag数量: {len(self.all_flags)}")

        if not HAS_CRYPTO:
            report.append("\n  ⚠ 未安装 pycryptodome, 冰蝎/哥斯拉的 AES 解密功能不可用")
            report.append("    安装: pip install pycryptodome")

        report_text = '\n'.join(report)

        # 导出
        if self.export_dir:
            os.makedirs(self.export_dir, exist_ok=True)
            report_path = os.path.join(self.export_dir, 'analysis_report.txt')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n[*] 报告已保存到: {report_path}")

            # 导出JSON格式
            json_path = os.path.join(self.export_dir, 'analysis_data.json')
            export_data = {
                'tools': {name: {
                    'confidence': r.confidence,
                    'event_count': len(r.events),
                    'events': r.events,
                } for name, r in self.results.items() if r.confidence > 0.3},
                'flags': self.all_flags,
                'all_events': self.all_events,
            }
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)
            print(f"[*] JSON数据已保存到: {json_path}")

            # 导出提取的ZIP文件
            for i, event in enumerate(zip_files):
                if event.get('zip_data'):
                    zip_path = os.path.join(self.export_dir, f'extracted_{i+1}.zip')
                    with open(zip_path, 'wb') as f:
                        f.write(event['zip_data'])
                    print(f"[*] ZIP文件已保存到: {zip_path}")

        return report_text

    def _extract_flag_global(self, text):
        """全局flag提取"""
        if not text:
            return None
        if isinstance(text, bytes):
            text = text.decode('utf-8', errors='replace')

        patterns = [
            r'DASCTF\{[^\}]+\}',
            r'Dest0g3\{[^\}]+\}',
            r'CTF2\{[^\}]+\}',
            r'CTF\{[^\}]+\}',
            r'flag\{[^\}]+\}',
            r'FLAG\{[^\}]+\}',
            r'GWHT\{[^\}]+\}',
            r'BJD\{[^\}]+\}',
            r'bjd\{[^\}]+\}',
            r'key\{[^\}]+\}',
            r'KEY\{[^\}]+\}',
            r'\bflag\s*[:=]\s*([^\s,;\}\]]+)',
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(0)
        return None


# ============================================================
# 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='PCAP Arcanum - 自动化流量取证分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python pcap_arcanum.py SimpleFlow.pcapng
  python pcap_arcanum.py traffic.pap --verbose
  python pcap_arcanum.py capture.pcapng --export-dir ./output

支持检测:
  - 蚁剑 (AntSword)     URL编码+Base64, @ini_set("display_errors","0")
  - 冰蝎 (Behinder)     AES-ECB加密, 默认key=e45e329feb5d925b
  - 哥斯拉 (Godzilla)    AES加密, 默认key=3c6e0b8a9c15224a, Java UA
  - 中国菜刀 (Chopper)  eval/assert+Base64, URL编码
  - Cobalt Strike       checksum8 URI, 心跳包, PE stager
  - 通用Shell命令        whoami/id/cat/ls 等明文命令
  - 文件传输             ZIP/PNG/JPEG/ELF/PE 等文件签名检测
        """)
    parser.add_argument('pcap', help='PCAP/PCAPNG 文件路径')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出模式')
    parser.add_argument('--export-dir', '-o', help='导出目录 (报告+提取文件)')

    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[!] 文件不存在: {args.pcap}")
        sys.exit(1)

    tool = PCAPArcanum(args.pcap, verbose=args.verbose, export_dir=args.export_dir)
    report = tool.analyze()

    if report:
        print(f"\n\n{report}")


if __name__ == '__main__':
    main()
