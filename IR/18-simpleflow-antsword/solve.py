#!/usr/bin/env python3
"""
SimpleFlow - 蚁剑(AntSword) Webshell 流量分析
题目: SimpleFlow.pcapng
攻击场景: 攻击者通过蚁剑连接webshell，执行命令查看flag.txt，打包为加密zip下载

流量特征:
  - HTTP POST 到 192.168.0.104:8888
  - 蚁剑payload: @eval(@base64_decode($_POST['xxx'])) + URL编码
  - 响应带蚁剑标记: 前6位hex标识 + 内容 + 后6位hex标识

攻击时间线:
  1. 获取服务器信息 (uname, pwd, whoami)
  2. 列目录 (ls /Users/chang/Sites/test)
  3. cat ../flag.txt (head命令读取flag内容)
  4. zip -P PaSsZiPWorD flag.zip ../flag.txt (打包加密zip)
  5. 下载 flag.zip (readfile读取二进制)

关键发现: ZIP密码在压缩命令中明文传输: PaSsZiPWorD

依赖: pip install scapy
"""

from scapy.all import rdpcap
from urllib.parse import unquote
import base64
import re
import io
import zipfile


def analyze_antsword_traffic(pcap_path):
    pkts = rdpcap(pcap_path)

    # 按TCP流重组（源端口配对请求和响应）
    streams = {}
    for p in pkts:
        if p.haslayer('TCP') and p.haslayer('Raw'):
            tcp = p['TCP']
            if tcp.dport == 8888:
                key = tcp.sport
                streams.setdefault(key, {})['req'] = tcp['Raw'].load.decode('utf-8', errors='replace')
            elif tcp.sport == 8888:
                key = tcp.dport
                streams.setdefault(key, {}).setdefault('resp', b'')
                streams[key]['resp'] += tcp['Raw'].load

    # 解码每个蚁剑请求的PHP代码和参数
    attack_timeline = []
    zip_data = None
    zip_password = None

    for port in sorted(streams.keys()):
        data = streams[port]
        req = data.get('req', '')
        if 'POST' not in req:
            continue

        body_start = req.find('\r\n\r\n')
        if body_start < 0:
            continue
        body = req[body_start + 4:].strip()

        # 解析POST参数
        params = {}
        for pair in body.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = unquote(v)

        # 蚁剑命令执行模式: 找shell参数和命令参数
        # 参数 o1faebd4ec3d97 = /bin/sh (shell路径)
        # 参数 g479cf6f058cf8 = 实际命令
        cmd = None
        for k, v in params.items():
            if v.startswith('/') and v.endswith('sh'):
                continue  # shell路径
            # base64解码 (去掉前2字符)
            if len(v) > 10 and re.match(r'^[A-Za-z0-9+/=]{10,}$', v[2:]):
                try:
                    decoded = base64.b64decode(v[2:]).decode('utf-8', errors='replace')
                    if 'cd ' in decoded or 'cat ' in decoded or 'head ' in decoded or 'zip ' in decoded or 'ls' in decoded:
                        cmd = decoded
                        # 提取zip密码
                        if 'zip -P' in decoded:
                            m = re.search(r'zip -P (\S+)', decoded)
                            if m:
                                zip_password = m.group(1)
                except:
                    pass

        # 提取响应内容（去chunked编码 + 蚁剑标记）
        resp = data.get('resp', b'')
        resp_text = resp.decode('utf-8', errors='replace')
        header_end = resp_text.find('\r\n\r\n')
        resp_content = ''
        if header_end > 0:
            resp_body = resp_text[header_end + 4:]
            chunk_end = resp_body.find('\r\n')
            if chunk_end > 0:
                try:
                    chunk_size = int(resp_body[:chunk_end].strip(), 16)
                    chunk_content = resp_body[chunk_end + 2:chunk_end + 2 + chunk_size]
                    # 去掉蚁剑前后缀标记（各12位hex）
                    if len(chunk_content) > 24:
                        resp_content = chunk_content[12:-12]
                    else:
                        resp_content = chunk_content
                except:
                    pass

        # 检测是否是文件下载（zip二进制）
        if b'PK\x03\x04' in resp:
            pk_start = resp.find(b'PK\x03\x04')
            eocd = resp.find(b'PK\x05\x06')
            if eocd >= 0:
                zip_data = resp[pk_start:eocd + 22]

        if cmd or 'flag' in resp_content.lower():
            attack_timeline.append({
                'port': port,
                'command': cmd or '(PHP info / ls)',
                'response': resp_content[:200] if isinstance(resp_content, str) else str(resp_content)[:200]
            })

    return attack_timeline, zip_data, zip_password


def main():
    import sys
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else r'SimpleFlow.pcapng'

    print('=== SimpleFlow 蚁剑流量分析 ===\n')

    timeline, zip_data, zip_password = analyze_antsword_traffic(pcap_path)

    print('攻击时间线:')
    for i, step in enumerate(timeline):
        print(f'  [{i+1}] port={step["port"]}')
        print(f'      命令: {step["command"][:120]}')
        print(f'      响应: {step["response"][:120]}')
        print()

    if zip_password:
        print(f'ZIP密码: {zip_password}')

    if zip_data and zip_password:
        zf = zipfile.ZipFile(io.BytesIO(zip_data))
        for name in zf.namelist():
            content = zf.read(name, pwd=zip_password.encode())
            print(f'\n{name} 内容:')
            print(content.decode('utf-8', errors='replace'))


if __name__ == '__main__':
    main()
