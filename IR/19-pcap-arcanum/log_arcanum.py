#!/usr/bin/env python3
"""LogArcanum v1.0 - CTF Log Analysis Engine
Seven analysis modules for extracting flags and attack evidence from web server logs.

Modules:
  1. SQLBlindInjectionAnalyzer - Blind/Union/Error/Time-based SQLi extraction
  2. WebshellAnalyzer - AntSword/Behinder/Godzilla/Chopper URL detection
  3. BruteForceAnalyzer - Login failure/success stats + credential extraction
  4. ScanDetector - Sensitive paths, 404s, Log4Shell, XSS, SQLi patterns
  5. FileTransferAnalyzer - Backdoor upload, data download, flag in URL
  6. LogCredentialAnalyzer - URL params, Base64 decode, Cookie credentials
  7. StatsProfiler - IP/UA/Status stats + global flag search

Usage:
  python log_arcanum.py <log_file> [--output report.txt] [--verbose]
"""

import re
import sys
import os
import base64
import urllib.parse
import json
import argparse
import hashlib
from collections import defaultdict, Counter
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI Colors
# ---------------------------------------------------------------------------
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    BG_RED = "\033[41m"
    BG_GRN = "\033[42m"
    BG_YEL = "\033[43m"

    @staticmethod
    def hdr(text): return f"{C.CYN}{C.BLD}{'='*20} {text} {'='*20}{C.RST}"
    @staticmethod
    def sub(text): return f"{C.BLU}{C.BLD}--- {text} ---{C.RST}"
    @staticmethod
    def flag(text): return f"{C.BG_RED}{C.WHT}{C.BLD}[FLAG] {text}{C.RST}"
    @staticmethod
    def hit(text): return f"{C.GRN}[+] {text}{C.RST}"
    @staticmethod
    def warn(text): return f"{C.YEL}[!] {text}{C.RST}"
    @staticmethod
    def info(text): return f"{C.CYN}[*] {text}{C.RST}"
    @staticmethod
    def err(text):  return f"{C.RED}[-] {text}{C.RST}"

# ---------------------------------------------------------------------------
# Log Entry
# ---------------------------------------------------------------------------
class LogEntry:
    __slots__ = ('ip','ident','user','time_str','method','path','proto',
                 'status','size','referer','ua','raw')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k, ''))

    @property
    def path_lower(self):
        return self.path.lower()

    @property
    def size_int(self):
        try: return int(self.size)
        except: return 0

# Common log formats
_FMT_COMBINED = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s*(\S*)"\s+(\d+)\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?')
_FMT_SIMPLE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s*(\S*)"\s+(\d+)\s+(\S+)')

def parse_log_file(filepath):
    """Parse Apache/Nginx combined or common log format."""
    entries = []
    errors = 0
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip('\n\r')
            if not line.strip():
                continue
            m = _FMT_COMBINED.match(line) or _FMT_SIMPLE.match(line)
            if m:
                g = m.groups()
                e = LogEntry(
                    ip=g[0], ident=g[1], user=g[2], time_str=g[3],
                    method=g[4], path=g[5], proto=g[6],
                    status=g[7], size=g[8],
                    referer=g[9] if len(g) > 9 else '',
                    ua=g[10] if len(g) > 10 else '',
                    raw=line
                )
                entries.append(e)
            else:
                errors += 1
    return entries, errors

# ---------------------------------------------------------------------------
# Flag Extraction
# ---------------------------------------------------------------------------
_FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.I),
    re.compile(r'ctf\{[^}]+\}', re.I),
    re.compile(r'key\{[^}]+\}', re.I),
    re.compile(r'secret\{[^}]+\}', re.I),
    re.compile(r'flag\[[^\]]+\]', re.I),
    re.compile(r'[a-f0-9]{32}'),   # MD5
    re.compile(r'[a-f0-9]{40}'),   # SHA1
    re.compile(r'[a-f0-9]{64}'),   # SHA256
]

def extract_flag(text):
    """Extract potential flags from text."""
    found = []
    for p in _FLAG_PATTERNS:
        found.extend(p.findall(text))
    return list(dict.fromkeys(found))  # dedupe preserving order

def safe_b64_decode(s):
    """Try base64 decode, return decoded string or empty."""
    try:
        # handle URL-safe base64
        s = s.replace('-', '+').replace('_', '/')
        pad = 4 - len(s) % 4
        if pad != 4:
            s += '=' * pad
        decoded = base64.b64decode(s).decode('utf-8', errors='replace')
        # only return if it looks like printable text
        if sum(1 for c in decoded if c.isprintable() or c in '\r\n\t') > len(decoded) * 0.8:
            return decoded
    except Exception:
        pass
    return ''

def url_decode(s):
    """URL decode, trying multiple layers."""
    try:
        d = urllib.parse.unquote(s)
        if d != s:
            d2 = urllib.parse.unquote(d)
            return d2 if d2 != d else d
        return s
    except:
        return s

# ===================================================================
# Analyzer 1: SQL Blind Injection
# ===================================================================
class SQLBlindInjectionAnalyzer:
    NAME = "SQL Injection Extraction"

    # Boolean blind: response size differs between true/false conditions
    # Union: SELECT ... UNION SELECT ...
    # Error-based: extractvalue / updatexml / exp
    # Time-based: SLEEP / BENCHMARK

    SQLI_PATTERNS = [
        (re.compile(r'union\s+(all\s+)?select', re.I), 'UNION SELECT'),
        (re.compile(r'(?:extractvalue|updatexml)\s*\(', re.I), 'Error-based (XML)'),
        (re.compile(r'(?:sleep|benchmark)\s*\(', re.I), 'Time-based'),
        (re.compile(r'(?:ord|ascii|substr|mid|char|conv)\s*\(', re.I), 'Blind (char)'),
        (re.compile(r'(?:if|case)\s*\(.*?then', re.I), 'Conditional'),
        (re.compile(r'information_schema', re.I), 'Info schema'),
        (re.compile(r'(?:load_file|into\s+outfile|into\s+dumpfile)', re.I), 'File op'),
        (re.compile(r'(?:group_concat|concat_ws?)\s*\(', re.I), 'Concat extraction'),
    ]

    def __init__(self):
        self.sqli_entries = []
        self.blind_sequences = defaultdict(list)  # ip -> entries
        self.extracted_data = {}

    def analyze(self, entries):
        for e in entries:
            decoded_path = url_decode(e.path)
            for pat, label in self.SQLI_PATTERNS:
                if pat.search(decoded_path):
                    self.sqli_entries.append((e, label))
                    if 'ascii' in label.lower() or 'blind' in label.lower() or 'ord' in label.lower():
                        self.blind_sequences[e.ip].append(e)
                    break

        # Try to reconstruct blind injection extracted values
        self._reconstruct_blind()

    def _reconstruct_blind(self):
        for ip, seq in self.blind_sequences.items():
            # Group by timestamp proximity (same extraction session)
            # Look for patterns like: ascii(substr((select...),N,1))>X
            char_map = {}
            for e in seq:
                m = re.search(r'substr\([^,]+,\s*(\d+)', e.path, re.I)
                if m:
                    pos = int(m.group(1))
                    # Try to find the character value from comparison
                    cm = re.search(r'[><=!]+\s*(\d+)', e.path)
                    if cm:
                        val = int(cm.group(1))
                        if 32 <= val <= 126:
                            char_map[pos] = chr(val)

            if char_map:
                max_pos = max(char_map.keys())
                result = ''.join(char_map.get(i, '?') for i in range(1, max_pos + 1))
                if len(result) > 2:
                    self.extracted_data[ip] = result

    def report(self):
        lines = []
        if not self.sqli_entries:
            return lines
        lines.append(C.hdr("SQL INJECTION ANALYSIS"))
        lines.append(f"  Total SQLi requests: {C.GRN}{len(self.sqli_entries)}{C.RST}")

        # Group by type
        type_count = Counter(label for _, label in self.sqli_entries)
        for t, c in type_count.most_common():
            lines.append(f"    {t}: {c}")

        # Union SELECT - extract inline data
        union_data = []
        for e, label in self.sqli_entries:
            if 'UNION' in label:
                flags = extract_flag(url_decode(e.path))
                union_data.extend(flags)
                # Also try to extract data from response size patterns
                if e.size_int > 0:
                    lines.append(f"    Union query size={e.size_int}: {e.path[:120]}")

        if union_data:
            lines.append(C.flag(f"Union extracted flags: {', '.join(set(union_data))}"))

        # Blind reconstruction
        for ip, data in self.extracted_data.items():
            lines.append(C.flag(f"Blind SQLi from {ip}: {data}"))
            flags = extract_flag(data)
            for f in flags:
                lines.append(C.flag(f"  FLAG: {f}"))

        # Show top attackers
        ip_count = Counter(e.ip for e, _ in self.sqli_entries)
        lines.append(C.sub("Top SQLi attackers"))
        for ip, c in ip_count.most_common(10):
            lines.append(f"    {ip}: {c} requests")

        return lines


# ===================================================================
# Analyzer 2: Webshell Detection
# ===================================================================
class WebshellAnalyzer:
    NAME = "Webshell Detection"

    SHELL_SIGS = [
        (re.compile(r'(?:asenc|assert|eval|base64_decode)\s*\(', re.I),
         'AntSword', 'antsword'),
        (re.compile(r'rebeyond|behinder|pass=|btshell', re.I),
         'Behinder', 'behinder'),
        (re.compile(r'(?:godzilla| Godzilla|eval\(base64)', re.I),
         'Godzilla', 'godzilla'),
        (re.compile(r'Z0=(?:&|$)|base64_decode\s*\(\s*\$_POST', re.I),
         'Chopper/Knife', 'chopper'),
        (re.compile(r'(?:cmd=|exec=|command=|shell=|cmdshell)', re.I),
         'Generic Webshell', 'generic'),
        (re.compile(r'(?:upload|uploaded|file_content|savefile|writefile)', re.I),
         'Upload Activity', 'upload'),
        (re.compile(r'(?:phpinfo|phpinfo\(\))', re.I),
         'PHPInfo', 'phpinfo'),
    ]

    def __init__(self):
        self.detections = []

    def analyze(self, entries):
        for e in entries:
            decoded = url_decode(e.path)
            full = decoded + ' ' + (e.ua or '') + ' ' + (e.referer or '')
            for pat, label, tag in self.SHELL_SIGS:
                if pat.search(full):
                    self.detections.append((e, label, tag))
                    break

    def report(self):
        lines = []
        if not self.detections:
            return lines
        lines.append(C.hdr("WEBSHELL DETECTION"))
        lines.append(f"  Total webshell hits: {C.GRN}{len(self.detections)}{C.RST}")

        by_type = defaultdict(list)
        for e, label, tag in self.detections:
            by_type[label].append(e)

        for label, evts in sorted(by_type.items()):
            lines.append(C.sub(f"{label} ({len(evts)} hits)"))
            # Show sample
            for e in evts[:5]:
                lines.append(f"    [{e.ip}] {e.method} {e.path[:100]}")
                flags = extract_flag(url_decode(e.path))
                for f in flags:
                    lines.append(C.flag(f"  FLAG in webshell URL: {f}"))
            if len(evts) > 5:
                lines.append(f"    ... and {len(evts)-5} more")

        return lines

# ===================================================================
# Analyzer 3: Brute Force Detection
# ===================================================================
class BruteForceAnalyzer:
    NAME = "Brute Force Detection"

    LOGIN_PATTERNS = [
        re.compile(r'(?:login|signin|auth|session|authenticate)', re.I),
        re.compile(r'(?:admin|manager|dashboard)\s*$', re.I),
        re.compile(r'(?:wp-login|wp-admin|administrator)', re.I),
    ]

    def __init__(self):
        self.brute_ips = {}
        self.success_logins = []
        self.failed_logins = []

    def analyze(self, entries):
        login_entries = defaultdict(lambda: {'fail': [], 'success': []})

        for e in entries:
            is_login = any(p.search(e.path_lower) for p in self.LOGIN_PATTERNS)
            if not is_login:
                # Also check POST to root or common endpoints
                if e.method == 'POST' and e.status in ('200', '301', '302', '401', '403'):
                    is_login = True

            if is_login:
                if e.status in ('401', '403'):
                    login_entries[e.ip]['fail'].append(e)
                    self.failed_logins.append(e)
                elif e.status in ('200', '301', '302') and e.method == 'POST':
                    login_entries[e.ip]['success'].append(e)
                    self.success_logins.append(e)

        # Identify brute force: IPs with many failures followed by success
        for ip, data in login_entries.items():
            fails = len(data['fail'])
            succs = len(data['success'])
            if fails >= 3:  # threshold
                self.brute_ips[ip] = {'fail': fails, 'success': succs, 'entries': data}

    def report(self):
        lines = []
        if not self.brute_ips:
            return lines
        lines.append(C.hdr("BRUTE FORCE DETECTION"))
        lines.append(f"  IPs with brute force behavior: {C.GRN}{len(self.brute_ips)}{C.RST}")

        for ip, data in sorted(self.brute_ips.items(),
                               key=lambda x: x[1]['fail'], reverse=True)[:15]:
            lines.append(f"    {ip}: {C.RED}{data['fail']} fails{C.RST} / "
                        f"{C.GRN}{data['success']} success{C.RST}")
            if data['success'] > 0:
                lines.append(C.warn(f"  !! Brute force SUCCESS from {ip}"))

                # Extract possible credentials from successful login paths
                for e in data['entries']['success'][:3]:
                    decoded = url_decode(e.path)
                    flags = extract_flag(decoded)
                    for f in flags:
                        lines.append(C.flag(f"  FLAG from brute force: {f}"))

        return lines


# ===================================================================
# Analyzer 4: Scan Detection
# ===================================================================
class ScanDetector:
    NAME = "Scan Detection"

    SENSITIVE_PATHS = [
        re.compile(r'(?:\.git|\.svn|\.env|\.htaccess|\.DS_Store)', re.I),
        re.compile(r'(?:wp-config|web\.config|database\.yml|settings\.py)', re.I),
        re.compile(r'(?:/etc/passwd|/etc/shadow|/proc/self)', re.I),
        re.compile(r'(?:phpMyAdmin|adminer|pma|mysql)', re.I),
        re.compile(r'(?:/api/(?:v1|v2|v3)/?(?:keys?|tokens?|users?|admin))', re.I),
        re.compile(r'(?:\.bak|\.old|\.orig|\.swp|\.save)$', re.I),
        re.compile(r'(?:/actuator|/swagger|/api-docs|/debug|/trace)', re.I),
    ]

    LOG4SHELL = re.compile(r'\$\{jndi:(?:ldap|rmi|dns|nis|iiop|nds|corba):', re.I)

    XSS_PATTERNS = [
        re.compile(r'<script', re.I),
        re.compile(r'(?:alert|confirm|prompt)\s*\(', re.I),
        re.compile(r'(?:onerror|onload|onmouseover)\s*=', re.I),
        re.compile(r'javascript:', re.I),
    ]

    def __init__(self):
        self.scan_ips = defaultdict(lambda: {'paths': [], '404s': 0, 'hits': 0})
        self.log4shell = []
        self.xss = []

    def analyze(self, entries):
        for e in entries:
            decoded = url_decode(e.path)
            full = decoded + ' ' + (e.ua or '')

            # Sensitive path scanning
            for pat in self.SENSITIVE_PATHS:
                if pat.search(decoded):
                    self.scan_ips[e.ip]['paths'].append(e)
                    self.scan_ips[e.ip]['hits'] += 1
                    break

            # 404 scanning
            if e.status == '404':
                self.scan_ips[e.ip]['404s'] += 1

            # Log4Shell
            if self.LOG4SHELL.search(full):
                self.log4shell.append(e)

            # XSS
            for pat in self.XSS_PATTERNS:
                if pat.search(decoded):
                    self.xss.append(e)
                    break

    def report(self):
        lines = []
        has_content = bool(self.scan_ips) or self.log4shell or self.xss
        if not has_content:
            return lines
        lines.append(C.hdr("SCAN & ATTACK DETECTION"))

        # Scanner IPs (high 404 or sensitive path access)
        scanners = [(ip, d) for ip, d in self.scan_ips.items()
                    if d['404s'] > 10 or d['hits'] > 0]
        if scanners:
            lines.append(C.sub(f"Scanner IPs ({len(scanners)})"))
            for ip, d in sorted(scanners, key=lambda x: x[1]['404s'], reverse=True)[:10]:
                lines.append(f"    {ip}: 404s={d['404s']}, sensitive_hits={d['hits']}")

        if self.log4shell:
            lines.append(C.sub(f"Log4Shell attempts ({len(self.log4shell)})"))
            for e in self.log4shell[:5]:
                lines.append(f"    [{e.ip}] {e.path[:120]}")
            lines.append(C.flag("Log4Shell attack detected!"))

        if self.xss:
            lines.append(C.sub(f"XSS attempts ({len(self.xss)})"))
            for e in self.xss[:5]:
                lines.append(f"    [{e.ip}] {e.path[:120]}")

        return lines

# ===================================================================
# Analyzer 5: File Transfer Detection
# ===================================================================
class FileTransferAnalyzer:
    NAME = "File Transfer Detection"

    # File signatures in URL parameters
    UPLOAD_SIGS = [
        re.compile(r'(?:upload|file_content|save_file|write_file|fputs|fwrite)', re.I),
        re.compile(r'\.(?:php|jsp|asp|aspx|exe|sh|bat|ps1|dll)\b', re.I),
    ]

    DOWNLOAD_SIGS = [
        re.compile(r'(?:download|export|backup|dump|backup)', re.I),
        re.compile(r'(?:\.(?:sql|zip|tar|gz|bak|conf|cfg|log|db)\b)', re.I),
    ]

    BACKDOOR_EXTENSIONS = ['.php', '.jsp', '.jspx', '.asp', '.aspx', '.exe', '.sh', '.bat', '.ps1']

    def __init__(self):
        self.uploads = []
        self.downloads = []
        self.url_flags = []

    def analyze(self, entries):
        for e in entries:
            decoded = url_decode(e.path)

            # Check for flag directly in URL
            flags = extract_flag(decoded)
            if flags:
                for f in flags:
                    self.url_flags.append((e, f))

            # Upload detection
            for pat in self.UPLOAD_SIGS:
                if pat.search(decoded):
                    self.uploads.append(e)
                    break

            # Download detection
            for pat in self.DOWNLOAD_SIGS:
                if pat.search(decoded):
                    self.downloads.append(e)
                    break

            # POST to create backdoor files
            if e.method == 'POST' and e.status in ('200', '301', '302'):
                for ext in self.BACKDOOR_EXTENSIONS:
                    if ext in decoded.lower():
                        self.uploads.append(e)
                        break

    def report(self):
        lines = []
        if not self.uploads and not self.downloads and not self.url_flags:
            return lines
        lines.append(C.hdr("FILE TRANSFER & URL FLAGS"))

        if self.url_flags:
            lines.append(C.sub(f"Flags found in URLs ({len(self.url_flags)})"))
            seen = set()
            for e, f in self.url_flags:
                if f not in seen:
                    seen.add(f)
                    lines.append(C.flag(f"  {f}"))
                    lines.append(f"    from [{e.ip}] {e.path[:100]}")

        if self.uploads:
            lines.append(C.sub(f"Potential backdoor uploads ({len(self.uploads)})"))
            for e in self.uploads[:10]:
                lines.append(f"    [{e.ip}] {e.method} {e.path[:100]}")
                flags = extract_flag(url_decode(e.path))
                for f in flags:
                    lines.append(C.flag(f"  FLAG: {f}"))

        if self.downloads:
            lines.append(C.sub(f"Potential data downloads ({len(self.downloads)})"))
            for e in self.downloads[:10]:
                lines.append(f"    [{e.ip}] {e.method} {e.path[:100]}")

        return lines


# ===================================================================
# Analyzer 6: Credential Extraction from Logs
# ===================================================================
class LogCredentialAnalyzer:
    NAME = "Credential Extraction"

    CRED_PATTERNS = [
        (re.compile(r'(?:password|passwd|pwd|pass)\s*[=:]\s*(\S+)', re.I), 'password'),
        (re.compile(r'(?:username|user|login|account)\s*[=:]\s*(\S+)', re.I), 'username'),
        (re.compile(r'(?:token|apikey|api_key|access_token|secret)\s*[=:]\s*(\S+)', re.I), 'token'),
        (re.compile(r'(?:cookie|session)\s*[=:]\s*(\S+)', re.I), 'cookie'),
    ]

    def __init__(self):
        self.credentials = defaultdict(list)
        self.b64_decoded = []

    def analyze(self, entries):
        for e in entries:
            decoded = url_decode(e.path)

            # Direct credential patterns in URL params
            for pat, cred_type in self.CRED_PATTERNS:
                m = pat.search(decoded)
                if m:
                    self.credentials[cred_type].append({
                        'ip': e.ip,
                        'value': m.group(1)[:100],  # truncate
                        'path': e.path[:120]
                    })

            # Base64 encoded data in URL
            # Look for base64-like strings (long, ends with = or alnum)
            b64_matches = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', decoded)
            for b64 in b64_matches:
                decoded_b64 = safe_b64_decode(b64)
                if decoded_b64:
                    flags = extract_flag(decoded_b64)
                    if flags:
                        for f in flags:
                            self.b64_decoded.append({
                                'ip': e.ip,
                                'raw': b64[:60],
                                'decoded': decoded_b64[:200],
                                'flag': f
                            })

            # Cookie-based credentials
            if e.ua:
                cookie_match = re.search(r'(?:cookie|Cookie):\s*(\S+)', e.ua)
                if cookie_match:
                    cookie_val = cookie_match.group(1)
                    flags = extract_flag(cookie_val)
                    for f in flags:
                        self.credentials['cookie_flag'].append({
                            'ip': e.ip, 'value': f, 'path': e.path[:80]
                        })

    def report(self):
        lines = []
        has_content = bool(self.credentials) or self.b64_decoded
        if not has_content:
            return lines
        lines.append(C.hdr("CREDENTIAL EXTRACTION"))

        for cred_type, items in self.credentials.items():
            if items:
                lines.append(C.sub(f"{cred_type} ({len(items)} found)"))
                for item in items[:10]:
                    lines.append(f"    [{item['ip']}] {cred_type}={item['value']}")
                    flags = extract_flag(item['value'])
                    for f in flags:
                        lines.append(C.flag(f"  FLAG: {f}"))

        if self.b64_decoded:
            lines.append(C.sub(f"Base64 decoded flags ({len(self.b64_decoded)})"))
            for item in self.b64_decoded[:10]:
                lines.append(f"    [{item['ip']}] decoded: {item['decoded'][:100]}")
                lines.append(C.flag(f"  FLAG: {item['flag']}"))

        return lines


# ===================================================================
# Analyzer 7: Stats Profiler + Global Flag Search
# ===================================================================
class StatsProfiler:
    NAME = "Statistics & Global Flag Search"

    def __init__(self):
        self.ip_count = Counter()
        self.ua_count = Counter()
        self.status_count = Counter()
        self.method_count = Counter()
        self.global_flags = []
        self.total = 0

    def analyze(self, entries):
        self.total = len(entries)
        for e in entries:
            self.ip_count[e.ip] += 1
            if e.ua:
                self.ua_count[e.ua] += 1
            self.status_count[e.status] += 1
            self.method_count[e.method] += 1

            # Global flag search on every entry
            decoded = url_decode(e.path)
            flags = extract_flag(decoded)
            # Also search UA and referer
            flags += extract_flag(e.ua or '')
            flags += extract_flag(e.referer or '')
            # Try base64 decode of path components
            for part in decoded.split('/'):
                for seg in part.split('&'):
                    for kv in seg.split('='):
                        if len(kv) > 10:
                            b64_decoded = safe_b64_decode(kv)
                            if b64_decoded:
                                flags += extract_flag(b64_decoded)

            for f in flags:
                self.global_flags.append((e, f))

    def report(self):
        lines = []
        lines.append(C.hdr("STATISTICS & GLOBAL FLAG SEARCH"))
        lines.append(f"  Total entries: {self.total}")

        # Top IPs
        lines.append(C.sub("Top 15 IPs"))
        for ip, c in self.ip_count.most_common(15):
            lines.append(f"    {ip}: {c} requests")

        # Status code distribution
        lines.append(C.sub("Status codes"))
        for s, c in self.status_count.most_common():
            lines.append(f"    {s}: {c}")

        # Methods
        lines.append(C.sub("HTTP methods"))
        for m, c in self.method_count.most_common():
            lines.append(f"    {m}: {c}")

        # Global flags
        if self.global_flags:
            seen = set()
            lines.append(C.sub(f"Global flag search ({len(self.global_flags)} hits)"))
            for e, f in self.global_flags:
                if f not in seen:
                    seen.add(f)
                    lines.append(C.flag(f"  {f}"))
                    lines.append(f"    from [{e.ip}] {e.path[:100]}")

        return lines

# ===================================================================
# Main Engine
# ===================================================================
class LogArcanum:
    """Main log analysis engine."""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.analyzers = [
            SQLBlindInjectionAnalyzer(),
            WebshellAnalyzer(),
            BruteForceAnalyzer(),
            ScanDetector(),
            FileTransferAnalyzer(),
            LogCredentialAnalyzer(),
            StatsProfiler(),
        ]
        self.entries = []
        self.parse_errors = 0

    def load(self, filepath):
        """Load and parse log file."""
        print(C.info(f"Loading {filepath} ..."))
        self.entries, self.parse_errors = parse_log_file(filepath)
        print(C.hit(f"Parsed {len(self.entries)} entries "
                    f"({self.parse_errors} unparseable lines)"))

    def run(self):
        """Run all analyzers."""
        if not self.entries:
            print(C.err("No entries loaded. Use load() first."))
            return

        print(C.info("Running analysis modules ..."))
        for analyzer in self.analyzers:
            name = analyzer.NAME
            print(C.info(f"  Running: {name}"))
            analyzer.analyze(self.entries)

    def report(self, output_file=None):
        """Generate and optionally save report."""
        all_lines = []
        all_lines.append("")
        all_lines.append(C.hdr("LOG ARCANUM v1.0 - ANALYSIS REPORT"))
        all_lines.append(f"  Entries analyzed: {len(self.entries)}")
        all_lines.append(f"  Parse errors: {self.parse_errors}")
        all_lines.append("")

        # Collect all flags
        all_flags = []

        for analyzer in self.analyzers:
            lines = analyzer.report()
            if lines:
                all_lines.extend(lines)
                all_lines.append("")

        # Flag summary
        all_lines.append(C.hdr("FLAG SUMMARY"))

        # Re-scan all reports for FLAG lines
        flag_collected = []
        for analyzer in self.analyzers:
            report_lines = analyzer.report()
            for line in report_lines:
                if '[FLAG]' in line:
                    # Extract the flag value
                    m = re.search(r'(flag\{[^}]+\}|ctf\{[^}]+\}|key\{[^}]+\}|secret\{[^}]+\}|[a-f0-9]{32,})', line, re.I)
                    if m:
                        flag_collected.append(m.group(0))

        if flag_collected:
            seen = set()
            for f in flag_collected:
                if f not in seen:
                    seen.add(f)
                    all_lines.append(C.flag(f))
        else:
            all_lines.append(C.info("No flags automatically extracted. "
                                    "Review detailed analysis above."))

        all_lines.append("")
        all_lines.append(C.hdr("END OF REPORT"))

        report_text = '\n'.join(all_lines)

        # Print to console
        print(report_text)

        # Save to file if requested
        if output_file:
            # Strip ANSI codes for file output
            clean = re.sub(r'\033\[[0-9;]*m', '', report_text)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(clean)
            print(C.hit(f"Report saved to {output_file}"))

        return report_text


# ===================================================================
# CLI Entry Point
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description='LogArcanum v1.0 - CTF Log Analysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_arcanum.py access.log
  python log_arcanum.py access.log --output report.txt
  python log_arcanum.py *.log --verbose
  python log_arcanum.py /path/to/nginx.log -o results.txt
""")
    parser.add_argument('logfile', nargs='+',
                        help='Log file(s) to analyze (Apache/Nginx combined format)')
    parser.add_argument('-o', '--output', default=None,
                        help='Save report to file (plain text, no ANSI)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    engine = LogArcanum(verbose=args.verbose)

    # Load all log files
    all_entries = []
    total_errors = 0
    for lf in args.logfile:
        if not os.path.isfile(lf):
            print(C.err(f"File not found: {lf}"))
            continue
        entries, errors = parse_log_file(lf)
        all_entries.extend(entries)
        total_errors += errors
        print(C.hit(f"Loaded {lf}: {len(entries)} entries, {errors} errors"))

    if not all_entries:
        print(C.err("No log entries loaded. Exiting."))
        sys.exit(1)

    # Manually set entries
    engine.entries = all_entries
    engine.parse_errors = total_errors

    # Run analysis
    engine.run()
    engine.report(args.output)


if __name__ == '__main__':
    main()