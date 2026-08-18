#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Finder 密码算法识别工具包
"""

from .signatures import SIGNATURES, ALGORITHM_INDEX, get_all_algorithms
from .binary_parser import parse_binary, BinaryInfo
from .scanner import scan_binary, aggregate_by_algorithm, scan_for_rc4_ksa, scan_for_xor_key_candidates, scan_for_custom_base64_table
from .disasm import find_xrefs_to_hits, detect_rc4_ksa_pattern, detect_xor_loop_pattern
from .key_locator import locate_all_keys
from .ida_script_gen import generate_ida_script

__version__ = '1.1'
