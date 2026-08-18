#!/usr/bin/env python3
"""
CTF 知识库 — Web 查询系统
Flask + SQLite，支持分类浏览和全文搜索
启动: python3 app.py → http://localhost:8888
"""
import os
import json
import sqlite3
import re
import html as html_module
import markdown as markdown_lib
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer, TextLexer
from pygments.formatters import HtmlFormatter
from flask import Flask, render_template_string, request, g, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ctf_knowledge.db')

app = Flask(__name__)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# ====== 页面模板 ======

INDEX_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTF 知识库</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; line-height: 1.6; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 0; position: sticky; top: 0; z-index: 100; }
.header-inner { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; align-items: center; justify-content: space-between; }
.logo { font-size: 20px; font-weight: 700; color: #f0f6fc; }
.search-box { flex: 1; max-width: 500px; margin: 0 20px; }
input[type="text"] { width: 100%; padding: 8px 16px; background: #0d1117; border: 1px solid #30363d;
                     border-radius: 6px; color: #c9d1d9; font-size: 14px; }
input[type="text"]:focus { outline: none; border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
.btn { padding: 8px 16px; background: #238636; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
.btn:hover { background: #2ea043; }
.nav-links { display: flex; gap: 16px; align-items: center; }
.nav-links a { font-size: 14px; }
.card { display: block; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.card:hover { border-color: #58a6ff; }
.card-title { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
.card-meta { font-size: 13px; color: #8b949e; display: flex; gap: 12px; flex-wrap: wrap; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
.badge-web { background: #1f6feb33; color: #58a6ff; }
.badge-pwn { background: #da363333; color: #f85149; }
.badge-crypto { background: #3fb95033; color: #3fb950; }
.badge-reverse { background: #d2992233; color: #d29922; }
.badge-ir { background: #a371f733; color: #a371f7; }
.badge-iot { background: #f778ba33; color: #f778ba; }
.badge-misc { background: #76839033; color: #768390; }
.badge-default { background: #30363d; color: #8b949e; }
.section { margin-bottom: 32px; }
.section-title { font-size: 18px; font-weight: 700; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 12px; }
.stats { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; text-align: center; }
.stat-num { font-size: 28px; font-weight: 700; }
.stat-label { font-size: 13px; color: #8b949e; margin-top: 4px; }
.content { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; }
.content pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; overflow-x: auto; margin: 12px 0; }
.content code { font-family: 'SF Mono', Consolas, monospace; font-size: 13px; }
.content table { width: 100%; border-collapse: collapse; margin: 12px 0; }
.content th, .content td { border: 1px solid #30363d; padding: 8px 12px; text-align: left; }
.content th { background: #21262d; }

/* Markdown 正文排版 */
.content h1 { font-size: 1.8em; margin: 24px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
.content h2 { font-size: 1.5em; margin: 20px 0 10px; }
.content h3 { font-size: 1.25em; margin: 16px 0 8px; }
.content h4 { font-size: 1.1em; margin: 14px 0 6px; }
.content h5, .content h6 { font-size: 1em; margin: 10px 0 4px; }
.content p { margin: 8px 0; line-height: 1.7; }
.content ul, .content ol { margin: 8px 0; padding-left: 28px; }
.content li { margin: 4px 0; line-height: 1.7; }
.content blockquote { border-left: 3px solid #58a6ff; padding: 4px 16px; margin: 12px 0; background: #161b22; color: #8b949e; }
.content hr { border: none; border-top: 1px solid #30363d; margin: 20px 0; }
.content strong { font-weight: 700; color: #f0f6fc; }
.content em { font-style: italic; }
.content del { text-decoration: line-through; color: #8b949e; }
.content a { color: #58a6ff; text-decoration: none; }

/* 行内代码 */
.content code { font-family: 'SF Mono', Consolas, monospace; font-size: 0.88em; background: #21262d; padding: 2px 6px; border-radius: 4px; }

/* 代码块（codehilite / fenced_code） */
.content pre { background: #0d1117 !important; border: 1px solid #30363d; border-radius: 6px; padding: 16px; overflow-x: auto; margin: 14px 0; font-size: 13px; line-height: 1.5; }
.content pre code { background: none; padding: 0; border-radius: 0; font-size: 13px; }
.content .codehilite { margin: 14px 0; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
.content .codehilite pre { margin: 0; border: none; border-radius: 0; }

/* 表格增强 */
.content table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 14px; }
.content th, .content td { border: 1px solid #30363d; padding: 8px 14px; text-align: left; }
.content th { background: #21262d; font-weight: 600; }
.content tr:nth-child(even) td { background: #161b22; }
.content td code { font-size: 0.85em; }

/* Pygments monokai 语法高亮（内联） */
""" + HtmlFormatter(style='monokai').get_style_defs('.codehilite') + """
</style>
</head>
<body>
<header>
<div class="header-inner">
  <div class="logo">CTF 知识库</div>
  <div class="search-box">
    <form action="/search" method="get">
      <input type="text" name="q" placeholder="搜索题目、知识点、工具..." value="{{ q or '' }}">
    </form>
  </div>
  <div class="nav-links">
    <a href="/">首页</a>
    <a href="/challenges">题目</a>
    <a href="/topics">专题</a>
    <a href="/tools">工具</a>
  </div>
</div>
</header>
<div class="container">
{% block content %}{% endblock %}
</div>
</body>
</html>
"""

def render_page(content_block, **kwargs):
    """渲染完整页面"""
    template = INDEX_HTML
    # 替换 content block
    full_template = template.replace(
        '{% block content %}{% endblock %}',
        content_block
    )
    return render_template_string(full_template, **kwargs)


# ====== 路由 ======

@app.route('/')
def index():
    db = get_db()
    stats = {
        'challenges': db.execute('SELECT COUNT(*) FROM challenges').fetchone()[0],
        'topics': db.execute('SELECT COUNT(*) FROM topics').fetchone()[0],
        'tools': db.execute('SELECT COUNT(*) FROM tools').fetchone()[0],
        'categories': db.execute('SELECT COUNT(DISTINCT category) FROM challenges').fetchone()[0],
    }

    # 各方向统计
    categories = {}
    for row in db.execute('SELECT category, COUNT(*) FROM challenges GROUP BY category').fetchall():
        cat = row[0] or '未分类'
        if cat not in categories:
            categories[cat] = {'challenges': 0, 'topics': 0, 'tools': 0}
        categories[cat]['challenges'] = row[1]
    for row in db.execute('SELECT category, COUNT(*) FROM topics GROUP BY category').fetchall():
        cat = row[0] or '未分类'
        if cat not in categories:
            categories[cat] = {'challenges': 0, 'topics': 0, 'tools': 0}
        categories[cat]['topics'] = row[1]
    for row in db.execute('SELECT category, COUNT(*) FROM tools GROUP BY category').fetchall():
        cat = row[0] or '未分类'
        if cat not in categories:
            categories[cat] = {'challenges': 0, 'topics': 0, 'tools': 0}
        categories[cat]['tools'] = row[1]

    recent_challenges = db.execute(
        'SELECT * FROM challenges ORDER BY challenge_no DESC LIMIT 8'
    ).fetchall()
    recent_topics = db.execute(
        'SELECT * FROM topics ORDER BY id DESC LIMIT 8'
    ).fetchall()

    content = """
<div class="stats">
  <div class="stat-card"><div class="stat-num">{{ stats.challenges }}</div><div class="stat-label">题目</div></div>
  <div class="stat-card"><div class="stat-num">{{ stats.topics }}</div><div class="stat-label">专题</div></div>
  <div class="stat-card"><div class="stat-num">{{ stats.tools }}</div><div class="stat-label">工具</div></div>
  <div class="stat-card"><div class="stat-num">{{ stats.categories }}</div><div class="stat-label">方向</div></div>
</div>
<div class="section">
  <div class="section-title">按方向浏览</div>
  <div class="grid">
    {% for cat, info in categories.items() %}
    <a href="/category/{{ cat }}" class="card">
      <div class="card-title">{{ cat }}</div>
      <div class="card-meta">
        <span>{{ info.challenges }} 题</span>
        <span>{{ info.topics }} 专题</span>
        <span>{{ info.tools }} 工具</span>
      </div>
    </a>
    {% endfor %}
  </div>
</div>
<div class="section">
  <div class="section-title">最近题目</div>
  {% for ch in recent_challenges %}
  <a href="/challenge/{{ ch.id }}" class="card">
    <div class="card-title">{{ ch.title }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (ch.category or 'default').lower().replace('/', '') }}">{{ ch.category or '未分类' }}</span>
      {% if ch.sub_category %}<span>{{ ch.sub_category }}</span>{% endif %}
      {% if ch.difficulty %}<span>{{ ch.difficulty }}</span>{% endif %}
      {% if ch.date %}<span>{{ ch.date }}</span>{% endif %}
    </div>
  </a>
  {% endfor %}
</div>
<div class="section">
  <div class="section-title">知识点专题</div>
  <div class="grid">
    {% for tp in recent_topics %}
    <a href="/topic/{{ tp.id }}" class="card">
      <div class="card-title">{{ tp.title }}</div>
      <div class="card-meta">
        <span class="badge badge-{{ (tp.category or 'default').lower().replace('/', '') }}">{{ tp.category or '未分类' }}</span>
        {% if tp.round %}<span>第{{ tp.round }}轮</span>{% endif %}
        <span>{{ tp.summary[:60] if tp.summary else '' }}</span>
      </div>
    </a>
    {% endfor %}
  </div>
</div>
"""
    return render_page(content, stats=stats, categories=categories,
                       recent_challenges=recent_challenges,
                       recent_topics=recent_topics, q='')


@app.route('/challenges')
def challenges():
    db = get_db()
    cat = request.args.get('category', '')
    if cat:
        rows = db.execute(
            'SELECT * FROM challenges WHERE category = ? ORDER BY challenge_no', (cat,)
        ).fetchall()
    else:
        rows = db.execute(
            'SELECT * FROM challenges ORDER BY challenge_no'
        ).fetchall()

    content = """
<div class="section">
  <div class="section-title">题目列表 ({{ rows|length }} 题)</div>
  {% for ch in rows %}
  <a href="/challenge/{{ ch.id }}" class="card">
    <div class="card-title">{{ ch.title }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (ch.category or 'default').lower().replace('/', '') }}">{{ ch.category or '未分类' }}</span>
      {% if ch.sub_category %}<span>{{ ch.sub_category }}</span>{% endif %}
      {% if ch.difficulty %}<span>{{ ch.difficulty }}</span>{% endif %}
      {% if ch.date %}<span>{{ ch.date }}</span>{% endif %}
      {% if ch.flag %}<span>Flag: {{ ch.flag[:30] }}...</span>{% endif %}
    </div>
  </a>
  {% endfor %}
</div>
"""
    return render_page(content, rows=rows, q='')


@app.route('/topics')
def topics():
    db = get_db()
    cat = request.args.get('category', '')
    if cat:
        rows = db.execute(
            'SELECT * FROM topics WHERE category = ? ORDER BY round, id', (cat,)
        ).fetchall()
    else:
        rows = db.execute(
            'SELECT * FROM topics ORDER BY round, id'
        ).fetchall()

    content = """
<div class="section">
  <div class="section-title">知识点专题 ({{ rows|length }} 个)</div>
  <div class="grid">
    {% for tp in rows %}
    <a href="/topic/{{ tp.id }}" class="card">
      <div class="card-title">{{ tp.title }}</div>
      <div class="card-meta">
        <span class="badge badge-{{ (tp.category or 'default').lower().replace('/', '') }}">{{ tp.category or '未分类' }}</span>
        {% if tp.round %}<span>第{{ tp.round }}轮</span>{% endif %}
        <span>{{ tp.summary[:80] if tp.summary else '' }}</span>
      </div>
    </a>
    {% endfor %}
  </div>
</div>
"""
    return render_page(content, rows=rows, q='')


@app.route('/tools')
def tools():
    db = get_db()
    rows = db.execute('SELECT * FROM tools ORDER BY category, name').fetchall()

    content = """
<div class="section">
  <div class="section-title">通用工具 ({{ rows|length }} 个)</div>
  {% for t in rows %}
  <div class="card">
    <div class="card-title">{{ t.name }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (t.category or 'default').lower().replace('/', '') }}">{{ t.category or '未分类' }}</span>
      <span>{{ t.description or '' }}</span>
      <span><a href="file://{{ project_root }}/{{ t.script_path }}">{{ t.script_path }}</a></span>
    </div>
  </div>
  {% endfor %}
</div>
"""
    return render_page(content, rows=rows, q='', project_root=BASE_DIR)


@app.route('/challenge/<int:cid>')
def challenge_detail(cid):
    db = get_db()
    ch = db.execute('SELECT * FROM challenges WHERE id = ?', (cid,)).fetchone()
    if not ch:
        abort(404)

    content = """
<div class="content">
  <h2>{{ ch.title }}</h2>
  <div class="card-meta" style="margin: 12px 0;">
    <span class="badge badge-{{ (ch.category or 'default').lower().replace('/', '') }}">{{ ch.category or '未分类' }}</span>
    {% if ch.sub_category %}<span>{{ ch.sub_category }}</span>{% endif %}
    {% if ch.difficulty %}<span>{{ ch.difficulty }}</span>{% endif %}
    {% if ch.date %}<span>{{ ch.date }}</span>{% endif %}
    <span>来源: {{ ch.source or '未知' }}</span>
    {% if ch.flag %}<span>Flag: <code>{{ ch.flag }}</code></span>{% endif %}
    {% if ch.script_path %}<span>脚本: <a href="file://{{ project_root }}/{{ ch.script_path }}">{{ ch.script_path }}</a></span>{% endif %}
  </div>
  <hr style="border-color: #30363d; margin: 16px 0;">
  <div>{{ content_html | safe }}</div>
</div>
"""
    # 简易 Markdown 渲染
    content_html = simple_markdown(ch['content'])
    return render_page(content, ch=ch, q='', project_root=BASE_DIR,
                       content_html=content_html)


@app.route('/topic/<int:tid>')
def topic_detail(tid):
    db = get_db()
    tp = db.execute('SELECT * FROM topics WHERE id = ?', (tid,)).fetchone()
    if not tp:
        abort(404)

    content = """
<div class="content">
  <h2>{{ tp.title }}</h2>
  <div class="card-meta" style="margin: 12px 0;">
    <span class="badge badge-{{ (tp.category or 'default').lower().replace('/', '') }}">{{ tp.category or '未分类' }}</span>
    {% if tp.round %}<span>第{{ tp.round }}轮补充</span>{% endif %}
    <span>{{ tp.summary or '' }}</span>
    {% if tp.tags %}<span>标签: {{ tp.tags }}</span>{% endif %}
  </div>
  <hr style="border-color: #30363d; margin: 16px 0;">
  <div>{{ content_html | safe }}</div>
</div>
"""
    content_html = simple_markdown(tp['content'])
    return render_page(content, tp=tp, q='', content_html=content_html)


@app.route('/category/<path:cat>')
def category_view(cat):
    db = get_db()
    challenges = db.execute(
        'SELECT * FROM challenges WHERE category = ? ORDER BY challenge_no', (cat,)
    ).fetchall()
    topics = db.execute(
        'SELECT * FROM topics WHERE category = ? ORDER BY round, id', (cat,)
    ).fetchall()
    tools = db.execute(
        'SELECT * FROM tools WHERE category = ? ORDER BY name', (cat,)
    ).fetchall()

    content = """
<div class="section">
  <div class="section-title">{{ cat }} 方向</div>
  {% if challenges %}
  <h3 style="margin: 16px 0 8px;">题目 ({{ challenges|length }} 题)</h3>
  {% for ch in challenges %}
  <a href="/challenge/{{ ch.id }}" class="card">
    <div class="card-title">{{ ch.title }}</div>
    <div class="card-meta">
      {% if ch.sub_category %}<span>{{ ch.sub_category }}</span>{% endif %}
      {% if ch.difficulty %}<span>{{ ch.difficulty }}</span>{% endif %}
    </div>
  </a>
  {% endfor %}
  {% endif %}
  {% if topics %}
  <h3 style="margin: 16px 0 8px;">专题 ({{ topics|length }} 个)</h3>
  <div class="grid">
    {% for tp in topics %}
    <a href="/topic/{{ tp.id }}" class="card">
      <div class="card-title">{{ tp.title }}</div>
      <div class="card-meta">
        {% if tp.round %}<span>第{{ tp.round }}轮</span>{% endif %}
        <span>{{ tp.summary[:60] if tp.summary else '' }}</span>
      </div>
    </a>
    {% endfor %}
  </div>
  {% endif %}
  {% if tools %}
  <h3 style="margin: 16px 0 8px;">工具 ({{ tools|length }} 个)</h3>
  {% for t in tools %}
  <div class="card">
    <div class="card-title">{{ t.name }}</div>
    <div class="card-meta">
      <span>{{ t.description or '' }}</span>
      <span><a href="file://{{ project_root }}/{{ t.script_path }}">{{ t.script_path }}</a></span>
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% if not challenges and not topics and not tools %}
  <p>该方向暂无内容</p>
  {% endif %}
</div>
"""
    return render_page(content, cat=cat, challenges=challenges,
                       topics=topics, tools=tools, q='', project_root=BASE_DIR)


@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return render_page('<div class="section"><div class="section-title">请输入搜索关键词</div></div>', q='')

    db = get_db()
    # 使用 FTS5 全文搜索
    results = db.execute("""
        SELECT si.ref_type, si.ref_id, si.title, si.category,
               snippet(search_index, 4, '<mark>', '</mark>', '...', 20) as excerpt
        FROM search_index si
        WHERE search_index MATCH ?
        ORDER BY rank
        LIMIT 50
    """, (q,)).fetchall()

    content = """
<div class="section">
  <div class="section-title">搜索 "{{ q }}" ({{ results|length }} 条结果)</div>
  {% for r in results %}
  {% if r.ref_type == 'challenge' %}
  <a href="/challenge/{{ r.ref_id }}" class="card">
    <div class="card-title">{{ r.title }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (r.category or 'default').lower().replace('/', '') }}">{{ r.category or '' }}</span>
      <span>题目</span>
    </div>
    <div style="margin-top: 8px; font-size: 13px; color: #8b949e;">{{ r.excerpt | safe }}</div>
  </a>
  {% elif r.ref_type == 'topic' %}
  <a href="/topic/{{ r.ref_id }}" class="card">
    <div class="card-title">{{ r.title }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (r.category or 'default').lower().replace('/', '') }}">{{ r.category or '' }}</span>
      <span>专题</span>
    </div>
    <div style="margin-top: 8px; font-size: 13px; color: #8b949e;">{{ r.excerpt | safe }}</div>
  </a>
  {% elif r.ref_type == 'tool' %}
  <div class="card">
    <div class="card-title">{{ r.title }}</div>
    <div class="card-meta">
      <span class="badge badge-{{ (r.category or 'default').lower().replace('/', '') }}">{{ r.category or '' }}</span>
      <span>工具</span>
    </div>
    <div style="margin-top: 8px; font-size: 13px; color: #8b949e;">{{ r.excerpt | safe }}</div>
  </div>
  {% endif %}
  {% endfor %}
  {% if not results %}
  <p>未找到匹配结果</p>
  {% endif %}
</div>
"""
    return render_page(content, results=results, q=q)


# ====== Markdown 渲染 ======

# Markdown 扩展配置
MD_EXTENSIONS = [
    'fenced_code',      # ``` 代码块
    'tables',           # GFM 表格
    'nl2br',            # 换行转 <br>
    'sane_lists',       # 更好的列表解析
    'codehilite',       # 代码语法高亮
    'toc',              # 自动生成目录（anchor 支持）
    'admonition',       # 提示框
]


def simple_markdown(md_text):
    """Markdown → HTML 转换（支持完整语法 + 语法高亮）"""
    if not md_text:
        return ''
    return markdown_lib.markdown(
        md_text,
        extensions=MD_EXTENSIONS,
        extension_configs={
            'codehilite': {
                'guess_lang': True,
                'noclasses': False,
                'pygments_style': 'monokai',
            }
        },
        output_format='html'
    )


if __name__ == '__main__':
    print(f"[+] CTF 知识库 Web 系统")
    print(f"[*] 数据库: {DB_PATH}")
    print(f"[*] 启动: http://localhost:8888")
    app.run(host='127.0.0.1', port=8888, debug=True)
