"""
CTF 解题工具 — SSTI 多引擎模块包
用途: 面向 CTF 竞赛的多模板引擎 SSTI 自动化解题辅助
场景: 竞赛平台题目 / 授权测试靶场

支持的引擎:
  - Jinja2 (Python/Flask)    — 完整 WAF 探测 + 14 种绕过策略
  - Twig (PHP/Symfony)        — map/filter/sort/reduce 回调绕过
  - Smarty (PHP)              — {if} 标签多函数变体绕过
  - FreeMarker (Java/Spring)  — ?new/?api + ObjectConstructor 绕过
  - Velocity (Java/Apache)    — 反射链 + #set 变量拼接绕过
  - Thymeleaf (Java/Spring)   — SpEL 注入 + 空格绕过
  - Mako (Python)             — 原生代码块（无沙箱）
  - Tornado (Python)          — handler.settings 泄露 + __import__ 链
"""

from .base import BaseEngine
from .jinja2_engine import Jinja2Engine
from .twig_engine import TwigEngine
from .smarty_engine import SmartyEngine
from .freemarker_engine import FreeMarkerEngine
from .velocity_engine import VelocityEngine
from .thymeleaf_engine import ThymeleafEngine
from .mako_engine import MakoEngine
from .tornado_engine import TornadoEngine

# ============================================================
# 引擎注册表
# ============================================================

ENGINE_REGISTRY = {
    'jinja2':     Jinja2Engine,
    'twig':       TwigEngine,
    'smarty':     SmartyEngine,
    'freemarker': FreeMarkerEngine,
    'velocity':   VelocityEngine,
    'thymeleaf':  ThymeleafEngine,
    'mako':       MakoEngine,
    'tornado':    TornadoEngine,
}


def get_engine(name):
    """工厂函数: 根据引擎名获取引擎实例"""
    cls = ENGINE_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"不支持的引擎: {name} (支持: {list(ENGINE_REGISTRY.keys())})")
    return cls()


# ============================================================
# 统一检测 Payload（汇总各引擎的 detect_payloads）
# ============================================================

DETECT_PAYLOADS = []
_seen_payloads = set()
for _eng_cls in ENGINE_REGISTRY.values():
    for _item in _eng_cls.detect_payloads:
        _key = (_item['payload'], _item['expected'])
        if _key not in _seen_payloads:
            DETECT_PAYLOADS.append(_item)
            _seen_payloads.add(_key)


# ============================================================
# 统一引擎指纹（汇总各引擎的 fingerprints）
# ============================================================

ENGINE_FINGERPRINTS = {}
for _eng_name, _eng_cls in ENGINE_REGISTRY.items():
    ENGINE_FINGERPRINTS[_eng_name] = _eng_cls.fingerprints


# ============================================================
# 支持的引擎名列表（供 CLI choices 使用）
# ============================================================

SUPPORTED_ENGINES = list(ENGINE_REGISTRY.keys())
