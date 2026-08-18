"""
CTF 解题工具 — SSTI 引擎模块共享工具函数
用途: 面向 CTF 竞赛的 SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场
"""

import re

# ============================================================
# 响应清洗
# ============================================================

def clean_response(text, original_payload=None):
    """清洗 HTTP 响应: HTML 实体解码、去除 HTML 标签、去除模板渲染痕迹"""
    if not text:
        return ''
    text = text.replace('&#39;', "'").replace('&amp;', '&')
    text = text.replace('&lt;', '<').replace('&gt;', '>')
    text = text.replace('&quot;', '"').replace('&nbsp;', ' ')
    text = re.sub(r'<(?![a-z]+ [\'\"])[a-z\/][a-z0-9]*[^>]*>', '', text)
    text = re.sub(r'\{\{.*?\}\}', '', text)
    text = re.sub(r'\{%.*?%\}', '', text)
    return text.strip()


# ============================================================
# WAF 拦截判断
# ============================================================

WAF_BLOCK_SIGNATURES = [
    'waf:', 'waf检测', 'waf:', 'blocked', 'forbidden', '请求被拦截',
    '危险关键词', '检测到危险', 'illegal', 'rejected', 'malicious',
    '请求已被', '访问被拒', 'intercepted',
    'get out', 'hacker',
]

WAF_BLOCK_PATTERNS_EXACT = [
    r'in blacklist',
]


def is_waf_blocked(text):
    """判断响应是否被 WAF 拦截"""
    if not text:
        return False
    lower = text.lower()
    for sig in WAF_BLOCK_SIGNATURES:
        if sig.lower() in lower:
            return True
    for pattern in WAF_BLOCK_PATTERNS_EXACT:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
