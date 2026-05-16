#!/usr/bin/env python3
"""
Web Dashboard for the network proxy SQLite database.

Usage:
  python dashboard.py                  # serves on http://127.0.0.1:5500
  python dashboard.py --port 8888
  python dashboard.py --db /path/to/proxy.db
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DATA_DIR = Path(__file__).parent / "proxy_data"
DB_PATH  = DATA_DIR / "proxy.db"

# ──────────────────────────────────────────────────────────
# DB
# ──────────────────────────────────────────────────────────

def get_db():
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def q(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]

def q1(conn, sql, args=()):
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None

# ──────────────────────────────────────────────────────────
# API handlers
# ──────────────────────────────────────────────────────────

def api_overview():
    conn = get_db()
    if not conn: return {"error": "DB not found"}
    domains = q(conn, """
        SELECT h.domain,
               COUNT(h.id) AS requests,
               SUM(h.size_bytes) AS total_bytes,
               MAX(h.timestamp) AS last_seen,
               COUNT(DISTINCT ck.name) AS cookies
        FROM history h
        LEFT JOIN cookies ck ON ck.domain = h.domain
        GROUP BY h.domain ORDER BY last_seen DESC
    """)
    stats = q1(conn, "SELECT COUNT(*) AS reqs, SUM(size_bytes) AS bytes FROM history")
    ck_count = q1(conn, "SELECT COUNT(*) AS n FROM cookies")
    methods  = q(conn, "SELECT method, COUNT(*) AS n FROM history GROUP BY method ORDER BY n DESC")
    statuses = q(conn, "SELECT status_code, COUNT(*) AS n FROM history GROUP BY status_code ORDER BY n DESC LIMIT 10")
    db_size  = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    return {
        "domains": domains,
        "stats":   stats,
        "cookies_total": ck_count["n"] if ck_count else 0,
        "methods":  methods,
        "statuses": statuses,
        "db_size":  db_size,
    }

def api_history(domain=None, since=None, until=None, search=None, limit=200, offset=0, status=None, method=None):
    conn = get_db()
    if not conn: return {"error": "DB not found"}
    clauses, args = [], []
    if domain:  clauses.append("domain=?");          args.append(domain)
    if since:   clauses.append("timestamp>=?");      args.append(since)
    if until:   clauses.append("timestamp<=?");      args.append(until + "T23:59:59")
    if status:  clauses.append("status_code=?");     args.append(int(status))
    if method:  clauses.append("method=?");          args.append(method.upper())
    if search:
        clauses.append("(url LIKE ? OR req_body LIKE ? OR res_body LIKE ?)")
        p = f"%{search}%"; args += [p, p, p]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = q1(conn, f"SELECT COUNT(*) AS n FROM history {where}", args)["n"]
    rows  = q(conn, f"""
        SELECT id, timestamp, domain, method, status_code, url,
               content_type, size_bytes, req_body_is_binary, res_body_is_binary
        FROM history {where}
        ORDER BY timestamp DESC LIMIT ? OFFSET ?
    """, args + [limit, offset])
    return {"rows": rows, "total": total}

def api_request(row_id):
    conn = get_db()
    if not conn: return {"error": "DB not found"}
    r = q1(conn, "SELECT * FROM history WHERE id=?", (row_id,))
    if not r: return {"error": "Not found"}
    for f in ("req_headers","req_cookies","res_headers","res_cookies"):
        try: r[f] = json.loads(r[f]) if r[f] else {}
        except: pass
    return r

def api_cookies(domain=None):
    conn = get_db()
    if not conn: return {"error": "DB not found"}
    where = "WHERE domain=?" if domain else ""
    args  = (domain,) if domain else ()
    rows  = q(conn, f"SELECT * FROM cookies {where} ORDER BY domain, name", args)
    return {"cookies": rows}

def api_domains():
    conn = get_db()
    if not conn: return []
    return [r["domain"] for r in q(conn, "SELECT DISTINCT domain FROM history ORDER BY domain")]

# ──────────────────────────────────────────────────────────
# HTML / JS  (single-page app, no dependencies)
# ──────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Proxy Dashboard</title>
<style>
  :root{
    --bg:#0f1117; --bg2:#181c27; --bg3:#1e2436; --bg4:#252d42;
    --border:#2e3a55; --accent:#4f8ef7; --accent2:#7b5ef7;
    --green:#3ecf8e; --red:#f75f5f; --yellow:#f7c45f; --dim:#5a6a8a;
    --text:#e0e6f0; --text2:#9aaabe;
    --font:'Segoe UI',system-ui,sans-serif; --mono:'Cascadia Code','Fira Code',monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;min-height:100vh;display:flex;flex-direction:column}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}

  /* ── layout ── */
  #shell{display:flex;flex:1;overflow:hidden;height:100vh}
  #sidebar{width:230px;min-width:230px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
  #main{flex:1;overflow-y:auto;padding:24px}

  /* ── sidebar ── */
  .logo{padding:18px 16px 12px;font-size:15px;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);letter-spacing:.03em}
  .logo span{color:var(--text2);font-weight:400;font-size:12px;display:block;margin-top:2px}
  nav a{display:flex;align-items:center;gap:9px;padding:10px 16px;color:var(--text2);border-left:3px solid transparent;transition:all .15s}
  nav a:hover{color:var(--text);background:var(--bg3);text-decoration:none}
  nav a.active{color:var(--accent);background:var(--bg3);border-left-color:var(--accent)}
  nav .icon{font-size:16px;width:20px;text-align:center}
  .sidebar-section{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);padding:14px 16px 4px;border-top:1px solid var(--border);margin-top:4px}
  #domain-list{overflow-y:auto;flex:1}
  #domain-list a{font-size:12px;padding:7px 16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}

  /* ── cards / grid ── */
  .stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:24px}
  .stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px}
  .stat-card .label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
  .stat-card .value{font-size:26px;font-weight:700;color:var(--accent)}
  .stat-card .sub{font-size:11px;color:var(--text2);margin-top:3px}

  /* ── panels ── */
  .panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
  .panel-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}
  .panel-head h2{font-size:13px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}
  .panel-body{padding:0}

  /* ── toolbar ── */
  .toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3)}
  input,select{background:var(--bg4);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 10px;font-size:13px;outline:none}
  input:focus,select:focus{border-color:var(--accent)}
  input[type=text]{min-width:200px}
  button{background:var(--accent);color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:13px;font-weight:600;transition:opacity .15s}
  button:hover{opacity:.85}
  button.secondary{background:var(--bg4);color:var(--text);border:1px solid var(--border)}
  button.secondary:hover{background:var(--bg3)}

  /* ── table ── */
  .tbl{width:100%;border-collapse:collapse}
  .tbl th{padding:9px 12px;text-align:left;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;border-bottom:1px solid var(--border);white-space:nowrap;background:var(--bg3)}
  .tbl td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;max-width:0}
  .tbl tr:last-child td{border-bottom:none}
  .tbl tr:hover td{background:var(--bg3);cursor:pointer}
  .tbl .url{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:400px;font-size:12px;font-family:var(--mono)}
  .tbl .domain{color:var(--accent);font-size:12px}
  .tbl .ts{color:var(--dim);font-size:11px;white-space:nowrap}
  .tbl .method{font-size:11px;font-weight:700;font-family:var(--mono)}
  .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono)}
  .ok {background:#1a3a2a;color:var(--green)}
  .err{background:#3a1a1a;color:var(--red)}
  .rdr{background:#3a301a;color:var(--yellow)}
  .bin{color:var(--dim);font-size:10px}
  .pager{display:flex;align-items:center;gap:10px;padding:10px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--text2)}

  /* ── detail drawer ── */
  #drawer{position:fixed;top:0;right:0;width:620px;height:100vh;background:var(--bg2);border-left:1px solid var(--border);transform:translateX(100%);transition:transform .2s;z-index:100;display:flex;flex-direction:column;overflow:hidden}
  #drawer.open{transform:translateX(0)}
  #drawer-head{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  #drawer-head h2{font-size:13px;font-weight:600;color:var(--text2)}
  #drawer-close{background:none;border:none;color:var(--dim);font-size:22px;cursor:pointer;padding:0 4px;line-height:1}
  #drawer-close:hover{color:var(--text)}
  #drawer-body{flex:1;overflow-y:auto;padding:16px}
  .kv-block{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:12px;font-size:12px;font-family:var(--mono);white-space:pre-wrap;word-break:break-all;max-height:250px;overflow-y:auto}
  .section-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin:14px 0 5px}
  .meta-row{display:flex;gap:8px;align-items:baseline;margin-bottom:5px;font-size:12px}
  .meta-row .k{color:var(--dim);min-width:90px}
  .meta-row .v{color:var(--text);font-family:var(--mono)}

  /* ── charts ── */
  .chart-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px}
  canvas{display:block;width:100%;max-height:180px}

  /* ── cookies table ── */
  .ck-domain{color:var(--accent);font-weight:600;padding:6px 12px;background:var(--bg3);border-bottom:1px solid var(--border);font-size:12px}

  /* ── empty ── */
  .empty{padding:40px;text-align:center;color:var(--dim);font-size:13px}

  /* ── scrollbar ── */
  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:var(--bg2)}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

  #page-overview, #page-history, #page-cookies{ display:none }
  #page-overview.active, #page-history.active, #page-cookies.active { display:block }
</style>
</head>
<body>
<div id="shell">

  <!-- sidebar -->
  <div id="sidebar">
    <div class="logo">🌐 Proxy Dashboard<span id="db-path">Loading…</span></div>
    <nav>
      <a href="#" class="active" onclick="showPage('overview',this)" id="nav-overview">
        <span class="icon">📊</span> Overview
      </a>
      <a href="#" onclick="showPage('history',this)" id="nav-history">
        <span class="icon">📜</span> History
      </a>
      <a href="#" onclick="showPage('cookies',this)" id="nav-cookies">
        <span class="icon">🍪</span> Cookies
      </a>
    </nav>
    <div class="sidebar-section">Domains</div>
    <div id="domain-list"><div class="empty" style="padding:12px 16px;font-size:12px">Loading…</div></div>
  </div>

  <!-- main -->
  <div id="main">

    <!-- OVERVIEW -->
    <div id="page-overview" class="active">
      <div class="stat-grid" id="stat-grid"></div>
      <div class="chart-row">
        <div class="panel">
          <div class="panel-head"><h2>Requests by Method</h2></div>
          <div class="panel-body" style="padding:16px"><canvas id="chart-methods"></canvas></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>Status Codes</h2></div>
          <div class="panel-body" style="padding:16px"><canvas id="chart-status"></canvas></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Top Domains</h2></div>
        <div class="panel-body"><table class="tbl" id="domains-table"></table></div>
      </div>
    </div>

    <!-- HISTORY -->
    <div id="page-history">
      <div class="panel">
        <div class="toolbar">
          <input type="text" id="h-search" placeholder="Search URL / body…" oninput="debounce(loadHistory,400)()">
          <select id="h-method" onchange="loadHistory()">
            <option value="">All methods</option>
            <option>GET</option><option>POST</option><option>PUT</option>
            <option>DELETE</option><option>OPTIONS</option><option>HEAD</option>
          </select>
          <select id="h-status" onchange="loadHistory()">
            <option value="">All statuses</option>
            <option>200</option><option>201</option><option>204</option>
            <option>301</option><option>302</option><option>304</option>
            <option>400</option><option>401</option><option>403</option>
            <option>404</option><option>500</option>
          </select>
          <input type="date" id="h-since" onchange="loadHistory()" title="Since">
          <input type="date" id="h-until" onchange="loadHistory()" title="Until">
          <button class="secondary" onclick="clearHistoryFilters()">Clear</button>
        </div>
        <table class="tbl">
          <thead>
            <tr>
              <th>ID</th><th>Time</th><th>Method</th><th>Status</th>
              <th>Domain</th><th>URL</th><th>Size</th>
            </tr>
          </thead>
          <tbody id="history-body"></tbody>
        </table>
        <div class="pager">
          <button class="secondary" id="btn-prev" onclick="histPage(-1)">← Prev</button>
          <span id="pager-info"></span>
          <button class="secondary" id="btn-next" onclick="histPage(1)">Next →</button>
        </div>
      </div>
    </div>

    <!-- COOKIES -->
    <div id="page-cookies">
      <div class="panel">
        <div class="toolbar">
          <input type="text" id="ck-search" placeholder="Filter by name or value…" oninput="filterCookies()">
          <span id="ck-count" style="color:var(--dim);font-size:12px"></span>
        </div>
        <div id="cookies-body"></div>
      </div>
    </div>

  </div><!-- /main -->
</div><!-- /shell -->

<!-- Detail Drawer -->
<div id="drawer">
  <div id="drawer-head">
    <h2 id="drawer-title">Request Detail</h2>
    <button id="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div id="drawer-body"></div>
</div>

<script>
// ── State ────────────────────────────────────────────────
let histOffset = 0;
const PAGE_SIZE = 50;
let histTotal   = 0;
let activeDomain = null;
let allCookies   = [];

// ── Utilities ────────────────────────────────────────────
const $ = id => document.getElementById(id);

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function statusBadge(s) {
  if (!s) return `<span class="badge err">???</span>`;
  const cls = s < 300 ? 'ok' : s < 400 ? 'rdr' : 'err';
  return `<span class="badge ${cls}">${s}</span>`;
}

function fmtSize(b) {
  if (!b) return '—';
  return b > 1048576 ? (b/1048576).toFixed(1)+' MB'
       : b > 1024    ? (b/1024).toFixed(1)+' KB'
       : b+' B';
}

function fmtTs(ts) {
  return ts ? ts.replace('T',' ').slice(0,19) : '—';
}

async function api(path) {
  const r = await fetch('/api' + path);
  return r.json();
}

// ── Pages ────────────────────────────────────────────────
function showPage(name, el) {
  document.querySelectorAll('#page-overview,#page-history,#page-cookies')
    .forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  $('page-' + name).classList.add('active');
  if (el) el.classList.add('active');
  if (name === 'history') { histOffset = 0; loadHistory(); }
  if (name === 'cookies') loadCookies();
}

// ── Overview ─────────────────────────────────────────────
async function loadOverview() {
  const d = await api('/overview');
  if (d.error) return;

  // stat cards
  const sg = $('stat-grid');
  const kb = v => v ? (v/1024).toFixed(1)+' KB' : '0 B';
  sg.innerHTML = `
    <div class="stat-card"><div class="label">Total Requests</div><div class="value">${(d.stats?.reqs||0).toLocaleString()}</div></div>
    <div class="stat-card"><div class="label">Traffic Captured</div><div class="value">${kb(d.stats?.bytes)}</div></div>
    <div class="stat-card"><div class="label">Domains</div><div class="value">${d.domains.length}</div></div>
    <div class="stat-card"><div class="label">Cookies</div><div class="value">${d.cookies_total}</div></div>
    <div class="stat-card"><div class="label">DB Size</div><div class="value">${kb(d.db_size)}</div></div>
  `;

  // domain list in sidebar
  const dl = $('domain-list');
  dl.innerHTML = d.domains.map(dom =>
    `<a href="#" onclick="filterByDomain('${dom}',this)">${dom.domain}</a>`
  ).join('');

  // top domains table
  $('domains-table').innerHTML = `
    <thead><tr><th>Domain</th><th>Requests</th><th>Traffic</th><th>Cookies</th><th>Last seen</th></tr></thead>
    <tbody>${d.domains.slice(0,20).map(dom => `
      <tr onclick="filterByDomain('${dom.domain}')">
        <td class="domain">${dom.domain}</td>
        <td>${(dom.requests||0).toLocaleString()}</td>
        <td>${fmtSize(dom.total_bytes)}</td>
        <td>${dom.cookies}</td>
        <td class="ts">${fmtTs(dom.last_seen)}</td>
      </tr>`).join('')}
    </tbody>`;

  drawBarChart('chart-methods', d.methods.map(m=>m.method), d.methods.map(m=>m.n),
    ['#4f8ef7','#7b5ef7','#3ecf8e','#f7c45f','#f75f5f','#5ff7d8']);
  drawBarChart('chart-status',  d.statuses.map(s=>String(s.status_code)), d.statuses.map(s=>s.n),
    d.statuses.map(s => s.status_code < 300 ? '#3ecf8e' : s.status_code < 400 ? '#f7c45f' : '#f75f5f'));
}

// ── Simple canvas bar chart (no dependency) ──────────────
function drawBarChart(canvasId, labels, values, colors) {
  const canvas = $(canvasId);
  if (!canvas || !values.length) return;
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth || 400, H = 160;
  canvas.width  = W * dpr; canvas.height = H * dpr;
  canvas.style.width  = W + 'px'; canvas.style.height = H + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const pad = {t:10,r:10,b:30,l:40};
  const max = Math.max(...values) || 1;
  const bw  = (W - pad.l - pad.r) / labels.length;
  const gap = bw * 0.15;

  ctx.clearRect(0,0,W,H);

  // grid lines
  ctx.strokeStyle = '#2e3a55'; ctx.lineWidth = 1;
  for (let i=0;i<=4;i++) {
    const y = pad.t + (H - pad.t - pad.b) * i / 4;
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(W-pad.r,y); ctx.stroke();
    ctx.fillStyle='#5a6a8a'; ctx.font='10px sans-serif'; ctx.textAlign='right';
    ctx.fillText(Math.round(max*(4-i)/4), pad.l-4, y+3);
  }

  values.forEach((v, i) => {
    const col  = Array.isArray(colors) ? (colors[i] || colors[0]) : colors;
    const barH = (v / max) * (H - pad.t - pad.b);
    const x    = pad.l + i * bw + gap;
    const y    = H - pad.b - barH;
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, bw-gap*2, barH, [3,3,0,0])
                  : ctx.rect(x, y, bw-gap*2, barH);
    ctx.fill();
    // label
    ctx.fillStyle = '#9aaabe'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
    ctx.fillText(labels[i], pad.l + i*bw + bw/2, H - pad.b + 12);
  });
}

// ── History ──────────────────────────────────────────────
async function loadHistory() {
  const search = $('h-search').value;
  const method = $('h-method').value;
  const status = $('h-status').value;
  const since  = $('h-since').value;
  const until  = $('h-until').value;

  let qs = `?limit=${PAGE_SIZE}&offset=${histOffset}`;
  if (activeDomain) qs += `&domain=${encodeURIComponent(activeDomain)}`;
  if (search) qs += `&search=${encodeURIComponent(search)}`;
  if (method) qs += `&method=${method}`;
  if (status) qs += `&status=${status}`;
  if (since)  qs += `&since=${since}`;
  if (until)  qs += `&until=${until}`;

  const d = await api('/history' + qs);
  histTotal = d.total || 0;

  const tbody = $('history-body');
  if (!d.rows || !d.rows.length) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty">No results.</div></td></tr>`;
  } else {
    tbody.innerHTML = d.rows.map(r => `
      <tr onclick="openRequest(${r.id})">
        <td style="color:var(--dim);font-size:11px">${r.id}</td>
        <td class="ts">${fmtTs(r.timestamp)}</td>
        <td><span class="method" style="color:${r.method==='GET'?'#4f8ef7':r.method==='POST'?'#3ecf8e':'#f7c45f'}">${r.method}</span></td>
        <td>${statusBadge(r.status_code)}</td>
        <td class="domain">${r.domain}</td>
        <td class="url" title="${r.url}">${r.url}</td>
        <td style="white-space:nowrap;font-size:11px">${fmtSize(r.size_bytes)}${r.res_body_is_binary?'<span class="bin"> bin</span>':''}</td>
      </tr>`).join('');
  }

  $('pager-info').textContent = `${histOffset+1}–${Math.min(histOffset+PAGE_SIZE, histTotal)} of ${histTotal.toLocaleString()}`;
  $('btn-prev').disabled = histOffset === 0;
  $('btn-next').disabled = histOffset + PAGE_SIZE >= histTotal;
}

function histPage(dir) {
  histOffset = Math.max(0, histOffset + dir * PAGE_SIZE);
  loadHistory();
}

function clearHistoryFilters() {
  ['h-search','h-since','h-until'].forEach(id => $(id).value = '');
  ['h-method','h-status'].forEach(id => $(id).selectedIndex = 0);
  activeDomain = null;
  histOffset = 0;
  loadHistory();
}

function filterByDomain(domain, el) {
  activeDomain = domain;
  histOffset   = 0;
  showPage('history', $('nav-history'));
}

// ── Request Detail ────────────────────────────────────────
async function openRequest(id) {
  const r = await api('/request/' + id);
  if (r.error) return;

  const fmt = o => JSON.stringify(o, null, 2);
  const stcCol = r.status_code < 300 ? 'var(--green)' : r.status_code < 400 ? 'var(--yellow)' : 'var(--red)';

  $('drawer-title').textContent = `#${r.id} — ${r.method} ${r.url.slice(0,60)}`;
  $('drawer-body').innerHTML = `
    <div class="meta-row"><span class="k">URL</span><span class="v" style="word-break:break-all">${r.url}</span></div>
    <div class="meta-row"><span class="k">Time</span><span class="v">${fmtTs(r.timestamp)}</span></div>
    <div class="meta-row"><span class="k">Domain</span><span class="v">${r.domain}</span></div>
    <div class="meta-row"><span class="k">Method</span><span class="v">${r.method}</span></div>
    <div class="meta-row"><span class="k">Status</span><span class="v" style="color:${stcCol}">${r.status_code}</span></div>
    <div class="meta-row"><span class="k">Content-Type</span><span class="v">${r.content_type||'—'}</span></div>
    <div class="meta-row"><span class="k">Size</span><span class="v">${fmtSize(r.size_bytes)}</span></div>

    <div class="section-label">Request Headers</div>
    <div class="kv-block">${fmt(r.req_headers)}</div>

    <div class="section-label">Cookies Sent</div>
    <div class="kv-block">${fmt(r.req_cookies)}</div>

    <div class="section-label">Request Body</div>
    <div class="kv-block">${r.req_body_is_binary ? '(binary)' : (r.req_body || '(empty)')}</div>

    <div class="section-label">Response Headers</div>
    <div class="kv-block">${fmt(r.res_headers)}</div>

    <div class="section-label">Cookies Set</div>
    <div class="kv-block">${fmt(r.res_cookies)}</div>

    <div class="section-label">Response Body</div>
    <div class="kv-block">${r.res_body_is_binary ? '(binary — not stored)' : (r.res_body ? r.res_body.slice(0,4000) + (r.res_body.length>4000?'\n…':'') : '(not saved)')}</div>
  `;
  $('drawer').classList.add('open');
}

function closeDrawer() { $('drawer').classList.remove('open'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

// ── Cookies ──────────────────────────────────────────────
async function loadCookies() {
  const d = await api('/cookies');
  allCookies = d.cookies || [];
  renderCookies(allCookies);
}

function renderCookies(cookies) {
  $('ck-count').textContent = `${cookies.length} cookies`;
  if (!cookies.length) {
    $('cookies-body').innerHTML = `<div class="empty">No cookies found.</div>`; return;
  }
  let html = '';
  let cur = null;
  for (const ck of cookies) {
    if (ck.domain !== cur) {
      cur = ck.domain;
      html += `<div class="ck-domain">${ck.domain}</div>`;
    }
    const flags = [];
    if (ck.secure)    flags.push('<span style="color:var(--green)">Secure</span>');
    if (ck.http_only) flags.push('<span style="color:var(--yellow)">HttpOnly</span>');
    const val = (ck.value||'').length > 80 ? ck.value.slice(0,80)+'…' : (ck.value||'');
    html += `<div class="tbl" style="display:table;width:100%">
      <div style="display:table-row;border-bottom:1px solid var(--border)">
        <div style="display:table-cell;padding:7px 12px;color:var(--text);font-size:12px;font-family:var(--mono);width:200px">${ck.name}</div>
        <div style="display:table-cell;padding:7px 4px;color:var(--text2);font-size:12px;font-family:var(--mono);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${val}</div>
        <div style="display:table-cell;padding:7px 12px;white-space:nowrap;font-size:11px">${flags.join(' ')}</div>
        <div style="display:table-cell;padding:7px 12px;color:var(--dim);font-size:11px;white-space:nowrap">${fmtTs(ck.updated_at)}</div>
      </div>
    </div>`;
  }
  $('cookies-body').innerHTML = html;
}

function filterCookies() {
  const term = $('ck-search').value.toLowerCase();
  if (!term) { renderCookies(allCookies); return; }
  renderCookies(allCookies.filter(c =>
    (c.name||'').toLowerCase().includes(term) ||
    (c.value||'').toLowerCase().includes(term) ||
    (c.domain||'').toLowerCase().includes(term)
  ));
}

// ── Domain list in sidebar ────────────────────────────────
async function loadSidebarDomains() {
  const domains = await api('/domains');
  const dl = $('domain-list');
  if (!domains.length) { dl.innerHTML = `<div class="empty" style="padding:12px 16px;font-size:12px">No data yet</div>`; return; }
  dl.innerHTML = domains.map(d =>
    `<a href="#" onclick="filterByDomain('${d}')">${d}</a>`
  ).join('');
}

// ── Boot ─────────────────────────────────────────────────
(async () => {
  await loadOverview();
  loadSidebarDomains();
})();
</script>
</body>
</html>"""

# ──────────────────────────────────────────────────────────
# HTTP handler
# ──────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        def p(key, default=None):
            v = qs.get(key, [default])
            return v[0] if v else default

        if path in ("", "/"):
            self.send_html(HTML)
            return

        if path == "/api/overview":
            self.send_json(api_overview())
        elif path == "/api/history":
            self.send_json(api_history(
                domain=p("domain"), since=p("since"), until=p("until"),
                search=p("search"), limit=int(p("limit",200)), offset=int(p("offset",0)),
                status=p("status"), method=p("method"),
            ))
        elif path.startswith("/api/request/"):
            row_id = int(path.split("/")[-1])
            self.send_json(api_request(row_id))
        elif path == "/api/cookies":
            self.send_json(api_cookies(domain=p("domain")))
        elif path == "/api/domains":
            self.send_json(api_domains())
        else:
            self.send_response(404)
            self.end_headers()


def main():
    global DB_PATH

    parser = argparse.ArgumentParser(description="Proxy Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5500)
    parser.add_argument("--db",   default=str(DB_PATH), help="Path to proxy.db")
    args = parser.parse_args()

    DB_PATH = Path(args.db)
    if not DB_PATH.exists():
        print(f"[ERROR] DB not found: {DB_PATH}")
        print("        Run the proxy first, then start the dashboard.")
        sys.exit(1)

    url = f"http://{args.host}:{args.port}"
    print(f"""
{'='*55}
  🌐  Proxy Dashboard
  Open  : {url}
  DB    : {DB_PATH.resolve()}
  Press Ctrl+C to stop.
{'='*55}
""")

    server = HTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")


if __name__ == "__main__":
    main()
