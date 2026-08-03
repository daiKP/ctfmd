#!/usr/bin/env python3
"""
流量分析 - SQL盲注流量还原
题目: 流量分析.pcap
攻击者通过 HTTP SQL 盲注逐字符提取数据库内容
注入点: /comments.php?name=if((substr((select(text)from(wfy_comments)where(id=100)),POS,1)="CHAR"),100,0)
  - 条件为 true: 返回 100 条评论 (响应更大)
  - 条件为 false: 返回 0 条评论 (响应更小)
解法: 对每个位置取响应体最大的字符（即条件为 true 的字符），按位置拼接得到 flag

依赖: pip install scapy
"""

from scapy.all import rdpcap
import re
import gzip
from urllib.parse import unquote


PCAP_FILE = r'流量分析.pcap'  # 同目录下放置pcap文件


def extract_flag(pcap_path):
    pkts = rdpcap(pcap_path)

    # 按源端口配对请求和响应
    streams = {}
    for p in pkts:
        if p.haslayer('TCP') and p.haslayer('Raw'):
            tcp = p['TCP']
            if tcp.dport == 80:
                # HTTP 请求
                key = tcp.sport
                payload = tcp['Raw'].load.decode('utf-8', errors='replace')
                streams.setdefault(key, {})['req'] = payload
            elif tcp.sport == 80:
                # HTTP 响应
                key = tcp.dport
                raw = tcp['Raw'].load
                streams.setdefault(key, {})['resp_raw'] = raw

    # 解析每个请求的注入参数 + 解压响应获取真实内容长度
    results = {}  # (rid, pos) -> [(char, content_len)]
    for port, data in streams.items():
        req = data.get('req', '')
        # 提取注入参数: substr(..., id=X), POS, 1) = "CHAR"
        m = re.search(
            r'substr\(\(select\(text\)from\(wfy_comments\)where\(id=(\d+)\)\)'
            r',(\d+),1\)=%22(.+?)%22',
            req
        )
        if not m:
            continue

        rid = int(m.group(1))
        pos = int(m.group(2))
        char = unquote(m.group(3))

        # 解压 HTTP 响应获取真实内容长度
        resp = data.get('resp_raw', b'')
        content_len = 0
        header_end = resp.find(b'\r\n\r\n')
        if header_end > 0:
            body = resp[header_end + 4:]
            crlf = body.find(b'\r\n')
            if crlf > 0:
                try:
                    chunk_hex = body[:crlf].decode('ascii').strip()
                    chunk_size = int(chunk_hex, 16)
                    chunk_content = body[crlf + 2:crlf + 2 + chunk_size]
                    decompressed = gzip.decompress(chunk_content)
                    content_len = len(decompressed)
                except Exception:
                    pass

        results.setdefault((rid, pos), []).append((char, content_len))

    # 找到 id=100 的数据，按位置还原 flag
    # 分界线: content_len > 830 为 true（返回评论），830 为 false（无评论）
    flag_chars = {}
    for (rid, pos), chars in results.items():
        if rid != 100:
            continue
        # 取 content_len 最大的字符（true 条件的响应更大）
        true_chars = [(c, l) for c, l in chars if l > 830]
        if true_chars:
            true_chars.sort(key=lambda x: x[1], reverse=True)
            flag_chars[pos] = true_chars[0][0]

    # 拼接 flag
    if not flag_chars:
        return None

    min_pos = min(flag_chars.keys())
    max_pos = max(flag_chars.keys())
    flag_text = ''
    for p in range(min_pos, max_pos + 1):
        flag_text += flag_chars.get(p, '?')

    return flag_text


if __name__ == '__main__':
    import sys
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else PCAP_FILE
    flag = extract_flag(pcap_path)
    if flag:
        print(f'Flag: {flag}')
    else:
        print('未能提取 flag')
