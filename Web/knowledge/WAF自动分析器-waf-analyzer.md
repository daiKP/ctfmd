---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '0e80e7e5-e2b2-47b9-9ce8-c63862f66dc3'
  PropagateID: '0e80e7e5-e2b2-47b9-9ce8-c63862f66dc3'
  ReservedCode1: '0caf6556-cb93-4f1f-b210-ba2d4e99001b'
  ReservedCode2: '0caf6556-cb93-4f1f-b210-ba2d4e99001b'
---

## WAF 自动分析器：探测、绕过与 Exploit 自动生成

### 工具概述

| 项目 | 内容 |
|------|------|
| 工具名称 | WAF 自动分析器 (waf_analyzer.py) |
| 分类 | Web - SQL 注入 / WAF 绕过 |
| 脚本路径 | `Web/tools/waf_analyzer.py` |
| 代码行数 | ~2750 行 |
| 依赖 | Python 3, requests |
| 开发日期 | 2026-08-10 (v4 多数据库: 2026-08-11) |

### 设计理念

在 CTF SQL 注入竞赛中，WAF 绕过是解题的核心瓶颈。传统方式是手工逐个测试关键词过滤，耗时且容易遗漏。本工具实现 **自动化分层方案**：

```
WAF 探测引擎 → 复杂度判定 → 分流生成
  ├── 简单/中等 WAF → sqlmap tamper 脚本
  └── 复杂 WAF → 自定义 exploit 脚本
```

**关键设计决策**：tamper 只能做字符级替换（如 `and`→`aandnd`），无法处理语义重构（如 `=`→`locate()`、`limit`→`group_concat`）。当 WAF 过滤了核心运算符和函数时，必须生成自定义 exploit。

### 核心功能

#### 1. WAF 探测引擎 (WAFProbe)

自动向目标发送探测 payload，逐一测试以下分类：

| 探测分类 | 测试项数 | 示例 |
|---------|---------|------|
| SQL 关键词 | 58 个 | `select`, `union`, `insert`, `having`, `by`, `handler` |
| 运算符 | 30 个 | `=`, `>`, `<`, `and`, `or`, `&&`, `\|\|`, `+`, `*`, `mod` |
| 函数 | 74 个 | `substr`, `ascii`, `if`, `case`, `sleep`, `updatexml` |
| 注释符 | 6 种 | `#`, `-- `, `/**/`, `--+`, `;%00`, `-- -` |
| 空白替代符 | 7 种 | LF(%0a), CR(%0d), TAB(%09), VT(%0b), FF(%0c), NBSP(%a0), 括号`(` |

**探测模式识别**：自动区分以下 WAF 检测模式：
- `keyword_alone`：关键词单独出现即拦截
- `keyword_plus_space`：关键词+空白字符组合才拦截，关键词单独不拦截
- `keyword_case_insensitive`：大小写不敏感拦截
- `keyword_regex`：正则模式拦截
- `length_based`：基于长度拦截

**关键发现机制**：
- `select(` / `from(` / `where(` → 括号无空格绕过验证
- `limit(` → MySQL 语法不合法，探测会给出假阳性
- 注释符需 URL 编码（`#`→`%23`），否则被当作 URL fragment

#### 2. WAF 分析引擎 (WAFAnalysis)

基于探测结果进行智能分析：

- **模式识别**：`keyword_alone` vs `keyword_plus_space`
- **复杂度判定**：
  - `simple`：仅过滤少量关键词，有可用的空白替代符
  - `medium`：过滤了部分运算符/函数，但有替代方案
  - `complex`：核心运算符(`=,>,<,and,or`)和核心函数(`substr,ascii,if,case,sleep`)全过滤
- **可用工具箱构建**：自动筛选未被过滤的函数和运算符，生成绕过方案

#### 3. Tamper 生成器 (TamperGenerator)

为简单/中等 WAF 生成 sqlmap tamper 脚本：

- 关键词替换（如 `and`→`aandnd`）
- 空格替换（如 `%0a`, `%09`）
- 大小写混淆（如 `SeLeCt`）
- 关键词等价替换（如 `and`→`&&`）

```bash
sqlmap -u "http://target/page?id=1" --tamper=waf_bypass_tamper.py --batch
```

#### 4. Exploit 生成器 (ExploitGenerator)

为复杂 WAF 生成自定义 exploit 脚本，支持：

- **多数据库支持**：自动检测 MySQL/MariaDB、PostgreSQL、MSSQL、Oracle、SQLite，根据数据库类型适配报错函数和元数据查询
- **注入类型自动判定**：报错注入(updatexml/extractvalue/floor) vs 布尔盲注(XOR+二分查找) vs 时间盲注(sleep) vs UNION 注入
- **绕过语法自动选择**：根据可用函数构建 `select(`, `from(`, `where(` 语法
- **报错函数动态选择**：updatexml → extractvalue → floor(rand()) 优先级自动切换（MySQL）；cast(as int) (PostgreSQL)；convert(int,...) (MSSQL)；utl_inaddr.get_host_name (Oracle)
- **布尔盲注二分查找**：替代线性遍历32-127，大幅减少请求数
- **时间盲注分支**：完整的 `if(expr,sleep(N),0)` 逐字符提取流程
- **UNION 注入分支**：列数探测 + 回显位确认 + 自动回退
- **数据策略**：优先使用 `group_concat`/`string_agg`/`STRING_AGG`/`listagg`（按数据库类型）
- **报错截断恢复**：updatexml/extractvalue 报错注入有 32 字符截断限制，自动用 `reverse(right(str,N))` 获取后半段拼接
- **HTTP 支持**：requests 替代 curl，支持 GET/POST/form+json/Cookie/Header/Proxy
- **注入位置**：支持 param (URL参数/表单字段)、cookie (Cookie字段)、header (HTTP头) 三种注入位置
- **hex 编码修复**：表名 hex 编码不再截断至20字符，使用完整 hex

生成的 exploit 脚本自动完成完整利用链：

```
Step 0: 连通性验证 (报错/布尔/时间盲注/UNION 四种模式自动适配)
Step 0.5: 数据库类型检测 (version() 或错误信息特征)
Step 1: 数据库名 (报错→直接回显, 盲注→二分查找)
Step 2: 表名 (information_schema.tables / user_tables / sqlite_master 等按数据库类型)
Step 3: 列名 (information_schema.columns / user_tab_columns / pragma_table_info 等按数据库类型)
Step 4: 数据获取 (含 32 字符截断恢复)
```

### 使用方法

```bash
# 完整分析 + 自动生成
python waf_analyzer.py -u "http://target/page?id=1" --param id

# 指定引号和注释符
python waf_analyzer.py -u "http://target/check.php?username=1&password=1" \
    --param username --quote "'" --comment "#"

# 仅分析不生成脚本
python waf_analyzer.py -u "http://target/page?id=1" --param id --analyze-only

# 手动指定 WAF 标记
python waf_analyzer.py -u "http://target/page?id=1" --param id \
    --waf-mark "逮住" --success-mark "Login Success"

# 从已有结果加载并生成 (跳过探测)
python waf_analyzer.py --load-result waf_result.json --gen-only

# 保存分析结果
python waf_analyzer.py -u "http://target/page?id=1" --param id \
    --save-result waf_result.json
```

### 关键技术点

| 技术点 | 说明 |
|--------|------|
| URL 编码陷阱 | `requests.get(params=...)` 和 `urllib.parse.quote()` 会对 `%` 二次编码，必须手动拼接 URL（仅替换 `'`→`%27`、`#`→`%23`、空格→`%0a`） |
| 注释符探测 | payload 必须是 `1'#xxxx`（引号在数字后面闭合），不能是 `'1#xxxx`（会导致 `''1` 语法错误） |
| XOR 盲注 payload 顺序 | 必须是 `zzzz'^expr#`（前缀+引号+异或），不能是 `'zzzz^expr#`（引号在前会导致语法错误） |
| `limit(` 假阳性 | WAF 不拦截 `limit(`，但 MySQL 不接受括号语法，探测会给出假阳性 |
| `limit` 策略回退 | 当 `limit` 仅有括号绕过时，自动回退到 `group_concat` 策略 |
| 报错截断恢复 | `reverse(right(str,N))` 反转尾部再反转回来，去掉与前段重叠部分后拼接 |
| 连接信息持久化 | 分析结果 JSON 中保存 URL/param/quote/comment 等连接信息，`--load-result` 可恢复 |

### 实战验证

在 DASCTF 靶机上验证通过 (v2 重构后):

```
靶机: http://2e8ec8b2694f487ebf4f6287.http-ctf2.dasctf.com:80/check.php
WAF 模式: keyword_plus_space
注入类型: error_updatexml (XOR 盲注 + updatexml 报错)

绕过方案:
  select → select(    from → from(    where → where(
  =  → locate()       and/or → ^      substr/ascii → ord(left/right())
  limit → group_concat (limit+空白被拦截, limit(不合法)

自动生成 exploit 执行结果:
  database() → ~geek
  表名 → H4rDsq1
  列名 → id, username, password
  password (完整) → CTF2{d490e291-594a-473c-ad50-468b58ca93a6}


靶机 (v1 已下线): http://340ce9395f31faae07b31da9.http-ctf2.dasctf.com/check.php
  password (完整) → CTF2{7b1a0efb-46b2-462f-95c1-685580b91d78}
```

### 开发中修复的关键 Bug

1. **limit 数据策略**：`DATA_STRATEGY = "limit"` 但 `limit(` 语法不合法 → 有 `group_concat` 时优先使用
2. **括号漏闭**：`error_inject(f"({table_expr}")` 缺少右括号 → 改为 `error_inject(f"({table_expr})")`
3. **JSON 连接信息缺失**：`--load-result` 时 URL/param 为 None → `to_dict` 中保存 `connection` 字段
4. **Step 4 空实现**：数据获取步骤为 `pass` → 补全含截断恢复的完整逻辑
5. **`bypasses` 未定义**：`_render_exploit` 中引用 `bypasses` 变量 → 改为 `av["bypasses"]`

### v2 重构改进 (2026-08-11)

1. **requests 替代 curl**：生成的 exploit 改用 `requests` 库，支持 GET/POST/form+json/Cookie/Header/Proxy
2. **报错函数动态选择**：updatexml → extractvalue → floor(rand()) 三级优先级自动切换
3. **布尔盲注二分查找**：替代线性遍历32-127，请求数从 ~95/字符降至 ~7/字符
4. **时间盲注分支**：完整的 `if(expr,sleep(N),0)` 逐字符提取，含长度检测和二分查找
5. **括号闭合逻辑统一**：新增 `build_select_expr()` 运行时函数，统一 `SEL/FRM/WHR` 的括号闭合
6. **hex 截断修复**：表名 hex 编码从 `[:20]` 改为完整 hex，避免长表名数据丢失
7. **三元表达式优先级修复**：`sel + content + (")" if sel_is_paren else "")` → 统一用 `build_select()`
8. **UNION 注入类型修复**：`keyword_plus_space` 模式下 UNION 判断需检查空白替代符可用性
9. **`content_type` 参数传递**：ExploitGenerator 构造函数增加 `content_type` 参数
10. **classify 增强**：支持 Duplicate entry 报错回显、通用 WAF 模式匹配、超时检测

### v3 增强改进 (2026-08-11 下午)

1. **UNION 注入模板**：完整的列数探测（ORDER BY + UNION SELECT 回退）+ 回显位确认 + 自动回退到报错注入
2. **复杂度判定修复**：核心运算符全过滤时，大小写混淆不再降低复杂度（因为运算符不受大小写影响），DASCTF 靶机正确判为 complex
3. **Tamper operator_func 修复**：不再忽略 `operator_func` 类型规则，改为保守策略（跳过需要语义重构的 `=` 替换）
4. **Tamper keyword_equiv 增强**：新增 `and→&&`、`or→||`、`ascii→ord` 等价替换
5. **Tamper 组合策略**：多条规则依次应用（space_replace → case_mix → comment_replace → paren_bypass → keyword_equiv → operator_func）
6. **UNION 列数探测回退**：UNION 列数探测失败时自动回退到报错/盲注，确保全场景覆盖

### v4 多数据库支持 (2026-08-11 晚)

1. **数据库类型自动检测**：
   - 分析阶段：`_build_toolbox()` 通过 WAF 探测响应中的版本标识识别 MySQL/MariaDB/PostgreSQL/MSSQL/Oracle/SQLite
   - 运行时：`detect_db_type()` 通过 `version()` 报错回显或特定函数探测确认数据库类型
2. **多数据库报错注入**：`error_inject()` 根据 `DB_TYPE` 自动选择报错函数：
   - MySQL: `updatexml()` → `extractvalue()` → `floor(rand())` (原有)
   - PostgreSQL: `cast(chr(58)||expr as int)` 类型转换报错
   - MSSQL: `convert(int, expr)` 类型转换报错
   - Oracle: `utl_inaddr.get_host_name(expr)` 报错
   - SQLite/未知: `cast(expr as int)` 通用报错
3. **多数据库响应识别**：`classify()` 新增报错回显模式：
   - PostgreSQL: `invalid input syntax for integer` / `cannot cast type`
   - MSSQL: `Conversion failed when converting the varchar value`
   - Oracle: `ORA-\d+:` 错误码模式
   - SQLite: `near "...": syntax error` (仅类型识别，无数据回显)
4. **元数据查询适配**：`get_schema_queries()` 按 DB 类型返回不同的元数据表和函数：
   - MySQL: `information_schema.tables/columns`, `database()`, `group_concat()`
   - PostgreSQL: `information_schema.tables/columns`, `current_database()`, `string_agg()`
   - MSSQL: `information_schema.tables/columns`, `db_name()`, `STRING_AGG()`
   - Oracle: `user_tables/user_tab_columns`, `sys_context('userenv','current_schema')`, `listagg()`
   - SQLite: `sqlite_master/pragma_table_info`, `'main'`, `group_concat()`
5. **注入位置支持**：`send()` 函数支持三种注入位置：
   - `param`：URL 参数 / POST 表单字段 (默认)
   - `cookie`：Cookie 字段注入
   - `header`：HTTP 头部注入
6. **工具箱输出增强**：`_build_toolbox()` 新增数据库类型显示
7. **DASCTF 靶机验证**：v4 全部功能在 MySQL 靶机上验证通过（GET/POST/param 三种模式均正常）

> AI生成