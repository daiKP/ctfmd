---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'b7721100-4121-4f97-b528-597bc22843cc'
  PropagateID: 'b7721100-4121-4f97-b528-597bc22843cc'
  ReservedCode1: 'fe8d7556-459b-47f2-b827-28c168284e25'
  ReservedCode2: 'fe8d7556-459b-47f2-b827-28c168284e25'
---

# Web 信息泄露 — CTF/渗透全路径速查手册

## 题目信息

- **平台**: DASCTF
- **类型**: Web / 信息泄露
- **Flag**: `flag{r0bots_1s_s0_us3ful_4nd_www.zip_1s_s0_d4ng3rous}`

## 本题解法

| 泄露点 | 内容 |
|--------|------|
| `/robots.txt` | `PART ONE: flag{r0bots_1s_s0_us3ful` |
| `/www.zip` | index.php 源码含 `PART_TWO = "_4nd_www.zip_1s_s0_d4ng3rous}"` |

---

## 信息泄露路径完整分类

### 一、版本控制系统泄露

| 路径 | 泄露内容 | 危害 | dirsearch 覆盖 |
|------|----------|------|----------------|
| `.git/HEAD` | Git 仓库头文件 | 可重建完整源码 | 部分 |
| `.git/config` | Git 配置（远程 URL 等） | 泄露仓库地址 | 部分 |
| `.git/index` | Git 索引文件 | 可提取文件列表 | 部分 |
| `.git/objects/` | Git 对象存储 | 可逐步提取所有文件 | 部分 |
| `.git/packed-refs` | Git 引用打包 | 泄露分支/标签 | 无 |
| `.git/refs/heads/` | 分支引用 | 泄露分支名 | 无 |
| `.git/refs/stash` | stash 内容 | 可能含敏感信息 | 无 |
| `.git/logs/HEAD` | Git 操作日志 | 泄露提交者信息 | 无 |
| `.svn/entries` | SVN 条目 | 可重建源码 | 部分 |
| `.svn/wc.db` | SVN 工作副本数据库 | 可提取文件 | 部分 |
| `.hg/store/` | Mercurial 存储 | 可重建源码 | 无 |
| `.hg/00manifest.i` | Mercurial 清单 | 文件列表 | 无 |
| `.hg/hgrc` | Mercurial 配置 | 远程仓库 URL | 无 |
| `.bzr/checkout/` | Bazaar 检出信息 | 可重建源码 | 无 |
| `.bzr/repository/` | Bazaar 仓库 | 文件内容 | 无 |

**利用工具**：
- Git: `git-dumper`, `dvcs-ripper`, `GitHack`
- SVN: `svn-extractor`, `dvcs-ripper`
- HG/BZR: `dvcs-ripper`

### 二、源码/备份文件泄露

| 路径 | 泄露内容 | dirsearch 覆盖 |
|------|----------|----------------|
| `www.zip` / `www.tar.gz` / `www.rar` / `www.7z` | 整站源码备份 | **不覆盖（关键遗漏）** |
| `web.zip` / `web.tar.gz` | 整站源码备份 | **不覆盖** |
| `backup.zip` / `backup.tar.gz` | 备份文件 | 部分 |
| `site.zip` / `site.tar.gz` | 站点备份 | **不覆盖** |
| `1.zip` / `2.zip` / `test.zip` | 临时备份 | **不覆盖** |
| `wwwroot.zip` / `wwwroot.tar.gz` | Web 根目录备份 | **不覆盖** |
| `html.zip` / `html.tar.gz` | HTML 目录备份 | **不覆盖** |
| `dist.zip` / `build.zip` | 构建产物 | **不覆盖** |
| `deploy.zip` / `release.zip` | 部署包 | **不覆盖** |
| `code.zip` / `source.zip` | 源码包 | **不覆盖** |
| `data.zip` / `db.zip` | 数据备份 | **不覆盖** |
| `archive.zip` / `bak.zip` | 归档/备份 | **不覆盖** |

> **dirsearch 盲区**：dirsearch 主要按扩展名（-e）+ 目录名扫描，**不会主动测试 `www.zip`、`site.zip` 这类备份压缩包路径**。这是 CTF 信息泄露题中最常见的遗漏。

### 三、编辑器临时文件泄露

| 路径 | 编辑器 | 泄露内容 | dirsearch 覆盖 |
|------|--------|----------|----------------|
| `.index.php.swp` | Vim (swap) | 文件内容 | 部分 |
| `index.php~` | Vim/Nano (备份) | 文件内容 | 部分 |
| `.index.php.un~` | Nano (undo) | 文件内容 | 无 |
| `index.php.bak` | 通用备份 | 文件内容 | 部分 |
| `index.php.old` | 旧版本 | 文件内容 | 部分 |
| `index.php.orig` | 原始版本 | 文件内容 | 无 |
| `index.php.save` | 编辑器保存 | 文件内容 | 无 |
| `index.php.tmp` | 临时文件 | 文件内容 | 无 |
| `index.php.copy` | 复制备份 | 文件内容 | 无 |
| `index.php.txt` | 文本副本 | 文件内容 | 部分 |
| `%23index.php%23` | Emacs (auto-save) | 文件内容 | 无 |
| `.index.html.swp` | Vim swap | 文件内容 | 部分 |
| `index.html.bak` | 备份 | 文件内容 | 部分 |

### 四、环境/配置文件泄露

| 路径 | 泄露内容 | dirsearch 覆盖 |
|------|----------|----------------|
| `.env` | 数据库密码、API密钥等 | **不覆盖（关键遗漏）** |
| `.env.bak` / `.env.local` / `.env.production` / `.env.staging` | 环境变量备份 | **不覆盖** |
| `.env.save` / `.env.old` / `.env~` | 环境变量备份 | **不覆盖** |
| `config.php` / `config.inc.php` | 数据库配置 | 部分 |
| `config.yaml` / `config.json` / `config.ini` | 应用配置 | 部分 |
| `configuration.php` | CMS 配置 | 部分 |
| `app.config` / `web.config` | .NET 配置 | 部分 |
| `database.yml` | Rails 数据库配置 | 无 |
| `db.php` / `db.inc.php` | 数据库连接文件 | 部分 |
| `settings.py` / `settings.pyc` | Django 配置 | 部分 |
| `wp-config.php` | WordPress 配置 | 部分 |
| `composer.json` / `composer.lock` | PHP 依赖 | 部分 |
| `package.json` / `yarn.lock` | JS 依赖 | 部分 |
| `Gemfile` / `Gemfile.lock` | Ruby 依赖 | 无 |
| `Pipfile` / `Pipfile.lock` | Python 依赖 | 无 |
| `requirements.txt` | Python 依赖 | 部分 |
| `Dockerfile` / `docker-compose.yml` | Docker 配置 | 部分 |
| `.dockerenv` | Docker 环境标识 | 无 |
| `.gitignore` | Git 忽略规则（泄露项目结构） | 部分 |
| `.npmrc` | NPM 配置（可能含 token） | 无 |

> **dirsearch 盲区**：`.env` 及其变体（`.env.bak`、`.env.local` 等）是 CTF 和实战中极高价值的泄露点，但 dirsearch **默认不测试这些路径**。

### 五、目录/文件信息泄露

| 路径 | 泄露内容 | dirsearch 覆盖 |
|------|----------|----------------|
| `robots.txt` | 目录结构、敏感路径 | 部分 |
| `.DS_Store` | macOS 目录结构 | 部分 |
| `Thumbs.db` | Windows 缩略图缓存 | 无 |
| `.directory` | KDE 目录文件 | 无 |
| `desktop.ini` | Windows 目录配置 | 无 |
| `.htaccess` / `.htpasswd` | Apache 认证配置 | 部分 |
| `crossdomain.xml` | Flash 跨域策略 | 部分 |
| `sitemap.xml` | 站点地图 | 部分 |
| `.well-known/security.txt` | 安全联系方式 | 无 |
| `.well-known/assetlinks.json` | Android App Links | 无 |
| `favicon.ico` | 框架指纹 | 部分 |

### 六、日志/调试信息泄露

| 路径 | 泄露内容 | dirsearch 覆盖 |
|------|----------|----------------|
| `error.log` / `error_log` | 错误日志 | 部分 |
| `access.log` / `access_log` | 访问日志 | 部分 |
| `debug.log` / `debug.log.txt` | 调试日志 | 部分 |
| `log.txt` / `log/` | 日志目录 | 部分 |
| `phpinfo.php` / `info.php` / `test.php` | PHP 配置信息 | 部分 |
| `server-status` / `server-info` | Apache 状态 | 部分 |
| `phpmyadmin/` / `pma/` | 数据库管理 | 部分 |
| `console/` / `adminer.php` | 管理后台 | 部分 |

### 七、API/框架信息泄露

| 路径 | 框架/场景 | 泄露内容 | dirsearch 覆盖 |
|------|-----------|----------|----------------|
| `swagger-ui.html` / `swagger-ui/` | Swagger | API 文档 | 部分 |
| `api-docs` / `api/swagger` | Swagger | API 文档 | 部分 |
| `swagger.json` / `api.json` | Swagger/OpenAPI | API 定义 | 部分 |
| `actuator` / `actuator/env` | Spring Boot | 配置/环境变量 | **不覆盖（关键遗漏）** |
| `actuator/health` / `actuator/info` | Spring Boot | 服务信息 | **不覆盖** |
| `actuator/heapdump` | Spring Boot | **堆转储（可提取密码）** | **不覆盖** |
| `actuator/logfile` | Spring Boot | 运行日志 | **不覆盖** |
| `druid/` / `druid/index.html` | Druid | 数据库监控 | **不覆盖** |
| `graphql` / `graphiql` | GraphQL | API 调试界面 | 无 |
| `elmah.axd` / `elmah/` | .NET ELMAH | 错误日志 | 无 |
| `trace.axd` | .NET Trace | 请求追踪 | 无 |
| `WEB-INF/web.xml` | Java | 部署描述符 | 无 |
| `META-INF/` | Java | 元数据 | 无 |
| `_profiler/` | Symfony | 性能分析 | 无 |

> **dirsearch 盲区**：Spring Boot Actuator 系列路径（`/actuator/env`、`/actuator/heapdump` 等）是实战中极常见的泄露点，dirsearch 默认不覆盖。

### 八、JS/前端信息泄露

| 路径 | 泄露内容 | dirsearch 覆盖 |
|------|----------|----------------|
| `*.js.map` (source map) | 完整前端源码 | **不覆盖（关键遗漏）** |
| `static/js/*.js.map` | 前端源码映射 | **不覆盖** |
| `webpack.json` | Webpack 配置 | 无 |
| `.vue/` | Vue 项目文件 | 无 |

### 九、IDE/开发工具泄露

| 路径 | 工具 | 泄露内容 | dirsearch 覆盖 |
|------|------|----------|----------------|
| `.idea/workspace.xml` | IntelliJ IDEA | 项目路径、部署配置 | 无 |
| `.idea/misc.xml` | IntelliJ IDEA | 项目配置 | 无 |
| `.idea/modules.xml` | IntelliJ IDEA | 模块结构 | 无 |
| `.vscode/settings.json` | VS Code | 工作区配置 | 无 |
| `.vscode/launch.json` | VS Code | 调试配置 | 无 |
| `*.code-workspace` | VS Code | 工作区文件 | 无 |
| `.project` | Eclipse | 项目配置 | 无 |
| `.classpath` | Eclipse | 类路径 | 无 |
| `*.sln` / `*.csproj` | Visual Studio | 项目文件 | 无 |

---

## dirsearch 覆盖度分析

### dirsearch 擅长的

- 按扩展名扫描（`-e php,html,txt`）
- 目录名枚举
- 常见 CMS 路径
- 基于字典的暴力扫描

### dirsearch 的关键盲区（CTF 高频考点）

| 盲区 | 重要性 | 示例 |
|------|--------|------|
| **压缩包备份** | 极高 | `www.zip`, `site.zip`, `web.tar.gz`, `backup.zip` |
| **.env 系列** | 极高 | `.env`, `.env.bak`, `.env.local`, `.env.production` |
| **Spring Actuator** | 高 | `/actuator/env`, `/actuator/heapdump` |
| **Source Map** | 高 | `*.js.map`, `app.js.map` |
| **IDE 文件** | 中 | `.idea/workspace.xml`, `.vscode/settings.json` |
| **编辑器临时文件** | 中 | `.xxx.swp`, `xxx~`, `xxx.bak` |
| **Git 高级路径** | 中 | `.git/packed-refs`, `.git/logs/HEAD` |
| **Swagger/API 文档** | 中 | `swagger-ui.html`, `actuator` |

### 补充扫描脚本

建议在使用 dirsearch 之外，额外扫描以下路径（dirsearch 不覆盖的）：

```bash
# 信息泄露补充扫描列表
www.zip www.tar.gz www.rar www.7z
web.zip web.tar.gz
site.zip site.tar.gz site.rar
backup.zip backup.tar.gz
1.zip 2.zip test.zip bak.zip
dist.zip build.zip deploy.zip release.zip
code.zip source.zip archive.zip
data.zip db.zip wwwroot.zip html.zip

# .env 系列
.env .env.bak .env.local .env.production .env.staging
.env.save .env.old .env~ .env.swp

# Spring Boot
actuator actuator/env actuator/health actuator/info
actuator/heapdump actuator/logfile actuator/beans
actuator/mappings actuator/configprops

# Source Map
main.js.map app.js.map index.js.map
static/js/main.js.map static/js/app.js.map
chunk.js.map vendor.js.map

# IDE
.idea/workspace.xml .idea/modules.xml
.vscode/settings.json .vscode/launch.json

# Git 高级
.git/packed-refs .git/logs/HEAD .git/refs/stash
```

---

## CTF 信息泄露快速决策树

```
┌──────────────────────────────────────────────────────────┐
│              Web 信息泄露 — 快速决策树                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  首页/响应头有什么线索？                                   │
│    ├── 提示"粗心管理员"/"敏感信息"                        │
│    │     → robots.txt + www.zip（本题模式）               │
│    │                                                      │
│    ├── 响应头有 X-Powered-By / Server                     │
│    │     → 确定框架版本，搜 CVE                           │
│    │                                                      │
│    └── 页面有 JS 框架特征                                 │
│          → 检查 .js.map source map                       │
│                                                          │
│  逐步检查路径：                                           │
│    ├── 1. robots.txt → 目录/路径泄露                      │
│    ├── 2. .git/HEAD → Git 源码泄露                       │
│    ├── 3. www.zip / site.zip → 源码备份泄露               │
│    ├── 4. .env → 环境变量/密码泄露                        │
│    ├── 5. .DS_Store → 目录结构泄露                       │
│    ├── 6. *.swp / *~ / *.bak → 编辑器临时文件            │
│    ├── 7. phpinfo.php / info.php → PHP 配置泄露          │
│    ├── 8. actuator/env → Spring Boot 配置泄露            │
│    ├── 9. swagger-ui.html → API 文档泄露                 │
│    └── 10. .js.map → 前端源码泄露                        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

> AI生成