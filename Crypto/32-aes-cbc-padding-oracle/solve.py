#!/usr/bin/env python3
"""
AES-CBC Padding Oracle Attack - 高速版
每请求用 recv_until 精确读取，不依赖超时
"""
import socket
import sys
import time

HOST = "218.94.126.123"
PORT = 35260
BLOCK = 16

class Conn:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect((HOST, PORT))
        self.buf = b""
    
    def recv_until(self, marker, timeout=5):
        self.sock.settimeout(timeout)
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("断开")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result
    
    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)
    
    def close(self):
        self.sock.close()

def setup():
    conn = Conn()
    conn.recv_until(b"job name:\n", 5)
    conn.send(b"a" * 15 + b"\n")
    conn.recv_until(b"choice:", 2)
    
    conn.send(b"1\n")
    while True:
        line = conn.recv_until(b"\n", 3).strip()
        if line and len(line) >= 32 and all(c in b'0123456789abcdef' for c in line.lower()):
            break
    # 读取 "** Give your choice: " 行尾
    conn.recv_until(b"choice: ", 2)
    ct = bytes.fromhex(line.decode())
    return conn, ct

def oracle(conn, ct_bytes):
    """精确读取响应，不用超时等待"""
    conn.send(b"3\n")
    conn.recv_until(b"(hex):\n", 3)
    conn.send(ct_bytes.hex().encode() + b"\n")
    # 读取响应直到 "** Give your choice: "
    resp = conn.recv_until(b"choice: ", 3)
    return b"verification failed" not in resp

def decode_byte(b):
    return chr(b) if 32 <= b < 127 else f'\\x{b:02x}'

def main():
    open("progress.txt", "w").close()
    
    def log(msg):
        with open("progress.txt", "a", encoding="utf-8") as f:
            f.write(msg + "\n")
        print(msg, flush=True)
    
    log(f"[*] 连接 {HOST}:{PORT}")
    conn, ct = setup()
    
    blocks = [ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK)]
    num = len(blocks)
    log(f"[*] 密文 {len(ct)}字节 / {num}块")
    for i, b in enumerate(blocks):
        log(f"  C{i}: {b.hex()}")
    
    # 先测速度
    t0 = time.time()
    forged = [0]*16
    forged[15] = 0
    oracle(conn, bytes(forged) + blocks[1])
    t1 = time.time()
    log(f"[*] 单次请求耗时: {(t1-t0)*1000:.0f}ms")
    log(f"[*] 预计每字节最多256次, 每块16字节, 共{num-1}块")
    log(f"[*] 预计总时间: 最坏{256*16*(num-1)*(t1-t0)/60:.1f}分钟")
    
    full_plain = b""
    
    for blk in range(1, num):
        log(f"\n[=== 解密块 {blk}/{num-1} ===]")
        target = blocks[blk]
        prev = blocks[blk-1]
        inter = [0]*BLOCK
        plain = [0]*BLOCK
        
        for pos in range(BLOCK-1, -1, -1):
            pad = BLOCK - pos
            forged = [0]*BLOCK
            for j in range(pos+1, BLOCK):
                forged[j] = inter[j] ^ pad
            
            hit = -1
            for g in range(256):
                forged[pos] = g
                test = bytes(forged) + target
                if oracle(conn, test):
                    if pad == 1 and pos > 0:
                        f2 = forged[:]
                        f2[pos-1] ^= 1
                        if not oracle(conn, bytes(f2) + target):
                            continue
                    hit = g
                    break
            
            if hit == -1:
                log(f"  [!] 块{blk} pos={pos} 失败!")
                conn.close()
                return
            
            inter[pos] = hit ^ pad
            plain[pos] = inter[pos] ^ prev[pos]
            log(f"  块{blk} pos {pos:2d}: '{decode_byte(plain[pos])}' (0x{plain[pos]:02x})")
        
        bp = bytes(plain)
        full_plain += bp
        log(f"  块{blk}明文: {bp}")
        log(f"  [累积]: {full_plain.decode('utf-8', errors='replace')}")
    
    if full_plain and 1 <= full_plain[-1] <= 16:
        pl = full_plain[-1]
        if full_plain[-pl:] == bytes([pl])*pl:
            full_plain = full_plain[:-pl]
    
    result = full_plain.decode('utf-8', errors='replace')
    log(f"\n{'='*60}")
    log(f"[+] FLAG: {result}")
    log(f"{'='*60}")
    
    with open("result.txt", "w", encoding="utf-8") as f:
        f.write(result + "\n")
    
    conn.send(b"4\n")
    conn.close()

if __name__ == '__main__':
    main()
