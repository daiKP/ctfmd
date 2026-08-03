#!/usr/bin/env python3
"""Analyze re4.exe PE structure."""
import struct
import sys
import pefile

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PE_PATH = r'C:\Users\j520x\.local\share\TeleAgent\TeleAgent的工作空间\.temp\re4.exe'

pe = pefile.PE(PE_PATH)

print("=" * 60)
print("PE BASIC INFO")
print("=" * 60)
print(f"Machine: 0x{pe.FILE_HEADER.Machine:04X}", end="")
if pe.FILE_HEADER.Machine == 0x14c: print(" (x86 32-bit)")
elif pe.FILE_HEADER.Machine == 0x8664: print(" (x86-64)")
print(f"Number of sections: {pe.FILE_HEADER.NumberOfSections}")
print(f"TimeDateStamp: 0x{pe.FILE_HEADER.TimeDateStamp:08X}")
print(f"Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
print(f"Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
print(f"Section alignment: 0x{pe.OPTIONAL_HEADER.SectionAlignment:X}")
print(f"File alignment: 0x{pe.OPTIONAL_HEADER.FileAlignment:X}")
print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
print(f"DLL characteristics: 0x{pe.OPTIONAL_HEADER.DllCharacteristics:04X}")

# Check for ASLR, DEP, etc.
flags = []
if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040: flags.append("DYNAMIC_BASE (ASLR)")
if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100: flags.append("NX_COMPAT (DEP)")
if pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000: flags.append("GUARD_CF")
print(f"Security features: {flags if flags else 'None'}")

print(f"\n{'='*60}")
print("SECTIONS")
print(f"{'='*60}")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  {name:10s} VA=0x{s.VirtualAddress:08X} VSize=0x{s.Misc_VirtualSize:08X} "
          f"RawOff=0x{s.PointerToRawData:08X} RawSize=0x{s.SizeOfRawData:08X} "
          f"Flags=0x{s.Characteristics:08X}")
    # Interpret flags
    perms = []
    if s.Characteristics & 0x20000000: perms.append("X")
    if s.Characteristics & 0x40000000: perms.append("R")
    if s.Characteristics & 0x80000000: perms.append("W")
    print(f"             Perms: {''.join(perms)}")

print(f"\n{'='*60}")
print("IMPORTS")
print(f"{'='*60}")
try:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('ascii')
        funcs = [imp.name.decode('ascii') if imp.name else f"ord_{imp.ordinal}" for imp in entry.imports]
        print(f"  {dll}:")
        for f in funcs:
            print(f"    - {f}")
except AttributeError:
    print("  No imports found (might be packed)")

print(f"\n{'='*60}")
print("STRINGS (interesting)")
print(f"{'='*60}")
with open(PE_PATH, 'rb') as f:
    data = f.read()

# Find ASCII strings of length >= 4
import re
ascii_strings = re.findall(b'[\x20-\x7e]{4,}', data)
interesting = []
for s in ascii_strings:
    s_dec = s.decode('ascii')
    lower = s_dec.lower()
    if any(kw in lower for kw in ['flag', 'correct', 'wrong', 'right', 'input', 'enter',
                                   'key', 'encrypt', 'decrypt', 'success', 'fail', 'congrat',
                                   'password', 'crack', 'check', 'hash', 'aes', 'des', 'rsa',
                                   'verify', 'try', 'please', 'welcome', 'serial', 'license',
                                   '.dll', '.lib', 'msvc', 'kernel', 'user32', 'crypto']):
        interesting.append(s_dec)

# Remove duplicates and sort
interesting = sorted(set(interesting))
for s in interesting[:80]:
    print(f"  {s}")

# Also show all strings near "flag" or "correct"
print(f"\n--- All strings containing 'flag'/'correct'/'wrong'/'input' ---")
for s in ascii_strings:
    s_dec = s.decode('ascii')
    lower = s_dec.lower()
    if any(kw in lower for kw in ['flag', 'correct', 'wrong', 'input', 'enter', 'right', 'success']):
        print(f"  [{s_dec}]")

# Check for TLS callbacks
print(f"\n{'='*60}")
print("TLS CALLBACKS")
print(f"{'='*60}")
if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print(f"  TLS directory found!")
    print(f"  AddressOfCallBacks: 0x{tls.AddressOfCallBacks:08X}")
    # Read the callback addresses
    rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
    offset = pe.get_offset_from_rva(rva)
    i = 0
    while True:
        cb = struct.unpack_from('<I', data, offset + i * 4)[0]
        if cb == 0:
            break
        print(f"  Callback {i}: 0x{cb:08X}")
        i += 1
else:
    print("  No TLS directory")

# Check for resource section
print(f"\n{'='*60}")
print("RESOURCES")
print(f"{'='*60}")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = pefile.RESOURCE_TYPE.get(res_type.struct.Id, str(res_type.struct.Id))
        if hasattr(res_type, 'directory'):
            for res_id in res_type.directory.entries:
                if hasattr(res_id, 'directory'):
                    for res_lang in res_id.directory.entries:
                        offset = res_lang.data.struct.OffsetToData
                        size = res_lang.data.struct.Size
                        print(f"  Type={type_name} ID={res_id.struct.Id} Offset=0x{offset:X} Size={size}")
else:
    print("  No resources")
