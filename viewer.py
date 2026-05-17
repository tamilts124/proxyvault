#!/usr/bin/env python3
"""
Proxy DB Viewer — query cookies and history from SQLite.

Commands:
  python viewer.py                              # list all domains + stats
  python viewer.py --domain google.com          # cookies + recent history
  python viewer.py --domain google.com --limit 200
  python viewer.py --cookies                    # all latest cookies
  python viewer.py --cookies --domain google.com
  python viewer.py --history [--domain X] [--limit N] [--since YYYY-MM-DD] [--until YYYY-MM-DD]
  python viewer.py --request <id>               # full request/response for a row
  python viewer.py --search <term>              # search URLs AND bodies (FTS5)
  python viewer.py --replay <id>                # re-send a saved request live
  python viewer.py --export report.json         # dump everything to JSON
  python viewer.py --export report.har          # export as HAR (Chrome DevTools / Burp)
  python viewer.py --export report.csv          # export history as CSV
  python viewer.py --export report.postman_collection.json  # Postman Collection v2.1 + environment file
  python viewer.py --stats                      # DB statistics
  python viewer.py --prune --older-than 7       # delete rows older than N days
  python viewer.py --prune --keep-last 5000     # keep only the N most recent rows
  python viewer.py --watch                      # live-tail new requests (Ctrl+C to stop)
"""

__version__ = "2.3.0"

import argparse
import csv
import json
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode

# Shared query layer (fix #5 — no more duplicated SQL)
from db_queries import (
    build_where,
    query_overview,
    query_history,
    query_request,
    query_cookies,
    exec_prune,
)

DATA_DIR = Path(__file__).parent / "proxy_data"
DB_PATH  = DATA_DIR / "proxy.db"

# ANSI colours
CY = "\033[96m"; GR = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; BD = "\033[1m";  DM = "\033[2m"; RS = "\033[0m"
def c(col, t): return f"{col}{t}{RS}"

# ──────────────────────────────────────────────────────────
# Tips
# ──────────────────────────────────────────────────────────

def tips(*lines):
    print(c(DM, "  ╭─ What next? " + "─"*44))
    for line in lines:
        print(c(DM, "  │ ") + line)
    print(c(DM, "  ╰" + "─"*57))
    print()

# ──────────────────────────────────────────────────────────
# DB helper
# ──────────────────────────────────────────────────────────

def db() -> sqlite3.Connection:
    if not DB_PATH.exists():
        print(c(RD, f"DB not found: {DB_PATH}\nRun the proxy first."))
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

# ──────────────────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────────────────

def cmd_list():
    conn = db()
    # Re-use query_overview for the domain list; pull domains out of it
    data = query_overview(conn, DB_PATH)
    rows = data["domains"]

    if not rows:
        print(c(YL, "\n  No data yet. Start the proxy and browse something.\n"))
        tips(
            f"Start proxy   : {c(CY,'python proxy.py')}",
            f"Then come back: {c(CY,'python viewer.py')}",
        )
        return

    print(c(BD, f"\n  {'Domain':<35} {'Reqs':>6} {'Size':>10} {'Cookies':>8}  Last seen"))
    print("  " + "─"*80)
    for r in rows:
        size = f"{r['total_bytes']/1024:.1f} KB" if r['total_bytes'] else "0 B"
        ts   = r['last_seen'][:19].replace("T", " ") if r['last_seen'] else "-"
        print(f"  {c(CY,r['domain']):<44} {r['requests']:>6} {size:>10} {r['cookies']:>8}  {ts}")
    print()

    example = rows[0]['domain']
    tips(
        f"Drill into a domain : {c(CY,f'python viewer.py --domain {example}')}",
        f"See all cookies     : {c(CY,'python viewer.py --cookies')}",
        f"Full history        : {c(CY,'python viewer.py --history')}",
        f"Search across all   : {c(CY,'python viewer.py --search <term>')}",
        f"DB stats            : {c(CY,'python viewer.py --stats')}",
        f"Web dashboard       : {c(CY,'python dashboard.py')}",
        f"Live tail           : {c(CY,'python viewer.py --watch')}",
    )


def cmd_domain(domain: str, limit: int = 50):
    conn = db()

    ck_result = query_cookies(conn, domain)
    cookies   = ck_result["cookies"]

    print(c(BD, f"\n{'─'*60}"))
    print(c(BD, f"  {domain}"))
    print(c(BD, f"{'─'*60}\n"))

    if cookies:
        print(c(GR, f"  🍪  Cookies ({len(cookies)})\n"))
        print(f"  {'Name':<30} {'Value':<35} Secure  HttpOnly  Updated")
        print("  " + "─"*95)
        for ck in cookies:
            val = (ck['value'] or '')[:33] + ('…' if len(ck['value'] or '') > 33 else '')
            sec = c(GR, "yes") if ck['secure']    else "no "
            hto = c(GR, "yes") if ck['http_only'] else "no "
            ts  = (ck['updated_at'] or '')[:19].replace("T", " ")
            print(f"  {ck['name']:<30} {val:<35} {sec}     {hto}       {ts}")
    else:
        print(c(YL, "  No cookies for this domain."))

    result = query_history(conn, domain=domain, limit=limit)
    rows   = result["rows"]

    print(c(GR, f"\n  📜  History (last {len(rows)} requests)\n"))
    print(f"  {'ID':>6}  {'Time':<20} {'St':>3}  {'Method':<7} {'Type':<10} {'URL'}")
    print("  " + "─"*110)
    for r in rows:
        ts    = r['timestamp'][:19].replace("T", " ")
        url   = r['url'][:55] + ('…' if len(r['url']) > 55 else '')
        stc   = GR if r['status_code'] and r['status_code'] < 400 else RD
        btype = (r['req_body_type'] or '')[:9]
        print(f"  {r['id']:>6}  {ts}  {c(stc,str(r['status_code'])):>3}  {r['method']:<7} {btype:<10} {url}")
    print()

    first_id = rows[0]['id'] if rows else '42'
    tips(
        f"Inspect a request   : {c(CY,f'python viewer.py --request {first_id}')}",
        f"Replay a request    : {c(CY,f'python viewer.py --replay {first_id}')}",
        f"Show more rows      : {c(CY,f'python viewer.py --domain {domain} --limit 200')}",
        f"Filter by date      : {c(CY,f'python viewer.py --domain {domain} --since 2025-05-01')}",
        f"Search this domain  : {c(CY,f'python viewer.py --search <term> --domain {domain}')}",
        f"Export domain HAR   : {c(CY,f'python viewer.py --export {domain}.har --domain {domain}')}",
        f"Export domain CSV   : {c(CY,f'python viewer.py --export {domain}.csv --domain {domain}')}",
    )


def cmd_cookies(domain_filter=None):
    conn   = db()
    result = query_cookies(conn, domain_filter)
    rows   = result["cookies"]

    print(c(BD, f"\n🍪  All Cookies ({len(rows)})\n"))
    cur_domain   = None
    domains_seen = []
    for r in rows:
        if r['domain'] != cur_domain:
            cur_domain = r['domain']
            domains_seen.append(cur_domain)
            print(c(CY, f"  {cur_domain}"))
        val   = (r['value'] or '')[:60] + ('…' if len(r['value'] or '') > 60 else '')
        flags = []
        if r['secure']:    flags.append("Secure")
        if r['http_only']: flags.append("HttpOnly")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"    {r['name']:<35} = {val}{tag}")
    print()

    example = domains_seen[0] if domains_seen else "example.com"
    if domain_filter:
        tips(
            f"See requests for this domain : {c(CY,f'python viewer.py --domain {domain_filter}')}",
            f"Search for a cookie value    : {c(CY,f'python viewer.py --search <value> --domain {domain_filter}')}",
            f"Export to JSON               : {c(CY,f'python viewer.py --export cookies.json --domain {domain_filter}')}",
        )
    else:
        tips(
            f"Filter to one domain  : {c(CY,f'python viewer.py --cookies --domain {example}')}",
            f"Drill into a domain   : {c(CY,f'python viewer.py --domain {example}')}",
            f"Search a cookie value : {c(CY,'python viewer.py --search <value>')}",
            f"Export everything     : {c(CY,'python viewer.py --export report.json')}",
        )


def cmd_history(domain_filter=None, limit=100, since=None, until=None):
    conn   = db()
    result = query_history(conn, domain=domain_filter, since=since, until=until, limit=limit)
    rows   = result["rows"]

    filters = []
    if domain_filter: filters.append(f"domain={domain_filter}")
    if since:         filters.append(f"since={since}")
    if until:         filters.append(f"until={until}")
    label = f"  [{', '.join(filters)}]" if filters else ""

    print(c(BD, f"\n📜  History ({len(rows)} rows){label}\n"))
    print(f"  {'ID':>6}  {'Time':<20} {'Domain':<28} {'St':>3}  {'Method':<7} {'URL'}")
    print("  " + "─"*110)
    for r in rows:
        ts       = r['timestamp'][:19].replace("T", " ")
        url      = r['url'][:50] + ('…' if len(r['url']) > 50 else '')
        dom      = r['domain'][:26]
        stc      = GR if r['status_code'] and r['status_code'] < 400 else RD
        bin_flag = c(DM, " [bin]") if r['res_body_is_binary'] else ""
        print(f"  {r['id']:>6}  {ts}  {c(CY,dom):<37} {c(stc,str(r['status_code'])):>3}  {r['method']:<7} {url}{bin_flag}")
    print()

    first_id  = rows[0]['id']     if rows else '42'
    first_dom = rows[0]['domain'] if rows else 'example.com'
    shown     = len(rows)

    tip_lines = [f"Inspect a request : {c(CY,f'python viewer.py --request {first_id}')}"]
    if not domain_filter:
        tip_lines.append(f"Filter by domain  : {c(CY,f'python viewer.py --history --domain {first_dom}')}")
    if not since:
        tip_lines.append(f"Filter by date    : {c(CY,f'python viewer.py --history --since 2025-05-01 --until 2025-05-15')}")
    if shown == limit:
        tip_lines.append(f"Load more rows    : {c(CY,f'python viewer.py --history --limit {limit*2}')}")
    tip_lines.append(f"Live tail         : {c(CY,'python viewer.py --watch')}")
    tip_lines.append(f"Search bodies     : {c(CY,'python viewer.py --search <term>')}")
    tip_lines.append(f"Export as HAR     : {c(CY,'python viewer.py --export report.har')}")
    tips(*tip_lines)


def cmd_request(row_id: int):
    conn = db()
    r    = query_request(conn, row_id)
    if not r:
        print(c(RD, f"\n  No history row with id={row_id}\n"))
        tips(
            f"List all domains : {c(CY,'python viewer.py')}",
            f"Browse history   : {c(CY,'python viewer.py --history')}",
        )
        return

    def pretty_json(v):
        if isinstance(v, dict):
            return json.dumps(v, indent=4)
        try:
            return json.dumps(json.loads(v), indent=4)
        except Exception:
            return v or "(none)"

    print(c(BD, f"\n{'═'*65}"))
    print(c(BD, f"  Request #{r['id']}  —  {r['timestamp'][:19].replace('T',' ')}"))
    print(c(BD, f"{'═'*65}\n"))

    print(c(GR, "  ── REQUEST ──────────────────────────────"))
    print(f"  {r['method']}  {r['url']}")
    body_type = r['req_body_type'] or 'text'
    print(c(DM, f"  Body type: {body_type}"))
    print(c(YL, "\n  Headers:"))
    print(pretty_json(r['req_headers']))
    print(c(YL, "\n  Cookies sent:"))
    print(pretty_json(r['req_cookies']))
    print(c(YL, "\n  Body:"))
    if r['req_body_is_binary']:
        print(c(RD, "  (binary — not stored)"))
    else:
        print(r['req_body'] or "(empty)")

    print(c(GR, "\n  ── RESPONSE ─────────────────────────────"))
    stc = GR if r['status_code'] and r['status_code'] < 400 else RD
    print(f"  Status : {c(stc, str(r['status_code']))}")
    print(f"  Type   : {r['content_type']}")
    print(f"  Size   : {r['size_bytes']:,} bytes")
    print(c(YL, "\n  Headers:"))
    print(pretty_json(r['res_headers']))
    print(c(YL, "\n  Cookies set:"))
    print(pretty_json(r['res_cookies']))
    print(c(YL, "\n  Body:"))
    if r['res_body_is_binary']:
        print(c(RD, "  (binary — not stored)"))
    elif r['res_body']:
        preview = r['res_body'][:2000]
        print(preview)
        if len(r['res_body']) > 2000:
            print(c(YL, f"\n  … ({len(r['res_body']):,} chars total, showing first 2000)"))
    else:
        print("  (not saved — run proxy with SAVE_PAGES=True)")
    print()

    domain = r['domain']
    tips(
        f"Replay this request          : {c(CY,f'python viewer.py --replay {row_id}')}",
        f"All requests for this domain : {c(CY,f'python viewer.py --domain {domain}')}",
        f"Search similar requests      : {c(CY,f'python viewer.py --search <term> --domain {domain}')}",
        f"Export this domain to HAR    : {c(CY,f'python viewer.py --export {domain}.har --domain {domain}')}",
        f"Back to history              : {c(CY,'python viewer.py --history')}",
    )


def cmd_replay(row_id: int):
    """Re-send a saved request and print the live response + diff vs stored."""
    conn = db()
    r    = query_request(conn, row_id)
    if not r:
        print(c(RD, f"\n  No history row with id={row_id}\n"))
        return

    url    = r['url']
    method = r['method']
    print(c(BD, f"\n🔁  Replaying #{row_id} — {method} {url}\n"))

    skip = {"host", "content-length", "transfer-encoding", "connection",
            "proxy-connection", "keep-alive", "upgrade", "te", "trailers"}
    saved_headers = r['req_headers'] or {}
    if isinstance(saved_headers, str):
        try:
            saved_headers = json.loads(saved_headers)
        except Exception:
            saved_headers = {}
    headers = {k: (v if isinstance(v, str) else v[0])
               for k, v in saved_headers.items() if k.lower() not in skip}

    body = None
    if r['req_body'] and not r['req_body_is_binary']:
        ct = saved_headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in ct:
            try:
                pairs = json.loads(r['req_body'])
                body  = urlencode(pairs).encode()
            except Exception:
                body = r['req_body'].encode()
        else:
            body = r['req_body'].encode()

    redirect_chain: list[str] = []

    class _LoggingRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirect_chain.append(f"  {code} → {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_LoggingRedirectHandler())

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with opener.open(req, timeout=15) as resp:
            live_status  = resp.status
            live_headers = dict(resp.headers)
            live_body    = resp.read(4096)
    except urllib.error.HTTPError as e:
        live_status  = e.code
        live_headers = {}
        live_body    = b""
        print(c(RD, f"  HTTP {e.code} — {e.reason}"))
    except Exception as e:
        print(c(RD, f"  Error: {e}"))
        print(c(YL, "  (Make sure no proxy is required for this URL, or run via the proxy)"))
        print()
        return

    stc = GR if live_status < 400 else RD

    if redirect_chain:
        print(c(YL, "  ↪ Redirect chain:"))
        for step in redirect_chain:
            print(c(YL, step))

    stored_status = r['status_code']
    stored_body   = (r.get('res_body') or '')[:1000]
    live_body_str = live_body.decode("utf-8", errors="replace")[:1000]

    print(f"  Status  : stored={c(GR if stored_status and stored_status<400 else RD, str(stored_status))}  "
          f"live={c(stc, str(live_status))}"
          + (c(RD, "  ← CHANGED") if stored_status != live_status else c(GR, "  ✓")))
    print(f"  Size    : stored={r['size_bytes']:,}B  live={len(live_body):,}B  "
          f"delta={len(live_body)-r['size_bytes']:+,}B")
    print(c(YL, "\n  Live Response Headers:"))
    print(json.dumps(live_headers, indent=4))
    print(c(YL, "\n  Live Body:"))
    print(live_body_str)

    if stored_body and live_body_str:
        import difflib
        a_words = stored_body.split()[:200]
        b_words = live_body_str.split()[:200]
        sm      = difflib.SequenceMatcher(None, a_words, b_words, autojunk=False)
        changes = [op for op in sm.get_opcodes() if op[0] != "equal"]
        if changes:
            print(c(YL, f"\n  Body diff ({len(changes)} changed span(s) in first 200 words):"))
            for tag, i1, i2, j1, j2 in changes[:10]:
                if tag in ("replace", "delete"):
                    print(c(RD, f"  - {' '.join(a_words[i1:i2])}"))
                if tag in ("replace", "insert"):
                    print(c(GR, f"  + {' '.join(b_words[j1:j2])}"))
        else:
            print(c(GR, "\n  Body diff: no textual changes detected in first 200 words."))
    print()


def cmd_search(term: str, domain_filter=None, since=None, until=None, limit=200):
    """
    Full-text search using FTS5 (fix #15 — replaces the old slow LIKE scan).
    Falls back to a LIKE scan if the FTS5 table isn't present (e.g. old DB).
    """
    conn = db()
    if len(term) > 200:
        print(c(YL, "  Search term truncated to 200 characters."))
        term = term[:200]

    # FTS5 path — delegates to the same query_history() used by dashboard.py
    try:
        result = query_history(
            conn,
            domain=domain_filter, since=since, until=until,
            search=term, limit=limit,
        )
        rows     = result["rows"]
        fts_used = True
    except Exception:
        # FTS5 table missing or malformed — fall back to LIKE full scan
        pat     = f"%{term}%"
        clauses = []
        args: list = []
        if domain_filter:
            clauses.append("domain = ?"); args.append(domain_filter)
        if since:
            clauses.append("timestamp >= ?"); args.append(since)
        if until:
            clauses.append("timestamp <= ?"); args.append(until + "T23:59:59")
        clauses.append("(url LIKE ? OR req_body LIKE ? OR res_body LIKE ?)")
        args += [pat, pat, pat]
        where = "WHERE " + " AND ".join(clauses)
        raw = conn.execute(f"""
            SELECT id, timestamp, domain, method, status_code, url,
                   req_body_type, req_body_is_binary, res_body_is_binary,
                   content_type, size_bytes
            FROM history {where}
            ORDER BY timestamp DESC LIMIT ?
        """, args + [limit]).fetchall()
        rows     = [dict(r) for r in raw]
        fts_used = False

    filters = []
    if domain_filter: filters.append(f"domain={domain_filter}")
    if since:         filters.append(f"since={since}")
    if until:         filters.append(f"until={until}")
    label    = f"  [{', '.join(filters)}]" if filters else ""
    fts_note = "" if fts_used else c(DM, "  (LIKE fallback — FTS5 unavailable)")

    print(c(BD, f"\n🔍  Search: '{term}'  ({len(rows)} results){label}{fts_note}\n"))

    if not rows:
        tips(
            f"Try a broader term   : {c(CY,f'python viewer.py --search <other-term>')}",
            f"Remove domain filter : {c(CY,f'python viewer.py --search {term}')}",
            f"Browse all history   : {c(CY,'python viewer.py --history')}",
        )
        return

    for r in rows:
        ts  = r['timestamp'][:19].replace("T", " ")
        stc = GR if r['status_code'] and r['status_code'] < 400 else RD
        url = r['url'][:75] + ('…' if len(r['url']) > 75 else '')
        print(f"  {r['id']:>6}  {ts}  {c(stc,str(r['status_code']))}  {r['method']:<7} {url}")
    print()

    first_id  = rows[0]['id']
    first_dom = rows[0]['domain']
    shown     = len(rows)

    tip_lines = [f"Inspect a result      : {c(CY,f'python viewer.py --request {first_id}')}"]
    if not domain_filter:
        tip_lines.append(f"Narrow to one domain  : {c(CY,f'python viewer.py --search {term} --domain {first_dom}')}")
    if not since:
        tip_lines.append(f"Narrow by date        : {c(CY,f'python viewer.py --search {term} --since 2025-05-01')}")
    if shown == limit:
        tip_lines.append(f"Raise result limit    : {c(CY,f'python viewer.py --search {term} --limit 500')}")
    tip_lines.append(f"Export matches to CSV : {c(CY,f'python viewer.py --export matches.csv --domain {first_dom}')}")
    tips(*tip_lines)


def cmd_stats():
    conn = db()
    data = query_overview(conn, DB_PATH)

    h        = data["stats"]
    db_size  = data["db_size"]
    domains  = data["domains"]
    methods  = data["methods"]
    statuses = data["statuses"]

    ck_n    = data["cookies_total"]
    d_n     = len(domains)
    bin_req = conn.execute("SELECT COUNT(*) as n FROM history WHERE req_body_is_binary=1").fetchone()['n']
    bin_res = conn.execute("SELECT COUNT(*) as n FROM history WHERE res_body_is_binary=1").fetchone()['n']
    btypes  = conn.execute(
        "SELECT req_body_type, COUNT(*) as n FROM history "
        "WHERE req_body_type IS NOT NULL GROUP BY req_body_type ORDER BY n DESC"
    ).fetchall()

    print(c(BD, "\n📊  Database Statistics\n"))
    print(f"  DB file        : {DB_PATH}")
    print(f"  DB size        : {db_size/1024:.1f} KB")
    print(f"  Domains        : {d_n}")
    print(f"  Total requests : {h['reqs'] if h else 0}")
    print(f"  Total traffic  : {(h['bytes'] or 0)/1024:.1f} KB" if h else "  Total traffic  : 0 KB")
    print(f"  Cookies stored : {ck_n}")
    print(f"  Binary req body: {bin_req}")
    print(f"  Binary res body: {bin_res}")

    if btypes:
        print(c(YL, "\n  Request body types:"))
        for bt in btypes:
            print(f"    {(bt['req_body_type'] or 'none'):<14} {bt['n']:>6}")

    print(c(YL, "\n  Methods:"))
    for m in methods:
        print(f"    {m['method']:<10} {m['n']:>6}")

    print(c(YL, "\n  Status codes:"))
    for s in statuses:
        col = GR if s['status_code'] and s['status_code'] < 400 else RD
        print(f"    {c(col,str(s['status_code'])):<20} {s['n']:>6}")

    print(c(YL, "\n  Top domains:"))
    top = domains[:5]
    for t in top:
        print(f"    {c(CY,t['domain']):<40} {t['requests']:>6} reqs")
    print()

    example = top[0]['domain'] if top else "example.com"
    tips(
        f"Drill into top domain : {c(CY,f'python viewer.py --domain {example}')}",
        f"Browse full history   : {c(CY,'python viewer.py --history')}",
        f"Search across all     : {c(CY,'python viewer.py --search <term>')}",
        f"Prune old data        : {c(CY,'python viewer.py --prune --older-than 30')}",
        f"Export everything     : {c(CY,'python viewer.py --export report.json')}",
        f"Open web dashboard    : {c(CY,'python dashboard.py')}",
    )


def cmd_prune(older_than: int | None = None, keep_last: int | None = None):
    """Delete old rows from history to keep DB size manageable."""
    conn   = db()
    result = exec_prune(conn, older_than=older_than, keep_last=keep_last)

    if older_than is not None:
        print(c(GR, f"\n✅  Deleted rows older than {older_than} days"))
    elif keep_last is not None:
        print(c(GR, f"\n✅  Kept the {keep_last} most recent rows"))

    print(f"  Removed  : {result['removed']} rows")
    print(f"  Remaining: {result['remaining']} rows")
    new_size = DB_PATH.stat().st_size / 1024
    print(f"  DB size  : {new_size:.1f} KB (after VACUUM)\n")


def cmd_watch(domain_filter=None):
    """Live-tail new requests as they arrive (polls DB every 2 seconds)."""
    watch_conn = db()
    watch_conn.execute("PRAGMA journal_mode=WAL")

    last_id_row = watch_conn.execute("SELECT MAX(id) as n FROM history").fetchone()
    last_id = last_id_row['n'] or 0

    print(c(BD, f"\n👁  Watching for new requests… (Ctrl+C to stop)\n"))
    print(f"  {'ID':>6}  {'Time':<20} {'Domain':<28} {'St':>3}  {'Method':<7} {'URL'}")
    print("  " + "─"*110)

    try:
        while True:
            time.sleep(2)
            watch_conn.execute("PRAGMA wal_checkpoint(PASSIVE)")

            where = "WHERE id > ?"
            args: list = [last_id]
            if domain_filter:
                where += " AND domain = ?"
                args.append(domain_filter)
            rows = watch_conn.execute(f"""
                SELECT id, timestamp, domain, method, status_code, url, res_body_is_binary
                FROM history {where}
                ORDER BY id ASC
            """, args).fetchall()

            for r in rows:
                ts       = r['timestamp'][:19].replace("T", " ")
                url      = r['url'][:50] + ('…' if len(r['url']) > 50 else '')
                dom      = r['domain'][:26]
                stc      = GR if r['status_code'] and r['status_code'] < 400 else RD
                bin_flag = c(DM, " [bin]") if r['res_body_is_binary'] else ""
                print(f"  {r['id']:>6}  {ts}  {c(CY,dom):<37} {c(stc,str(r['status_code'])):>3}  {r['method']:<7} {url}{bin_flag}")
                last_id = max(last_id, r['id'])
    except KeyboardInterrupt:
        watch_conn.close()
        print(c(YL, "\n\n  Watch stopped."))
        tips(
            f"Inspect last row  : {c(CY,f'python viewer.py --request {last_id}')}",
            f"Full history      : {c(CY,'python viewer.py --history')}",
        )

# ──────────────────────────────────────────────────────────
# Export: JSON
# ──────────────────────────────────────────────────────────

def cmd_export_json(path: str, domain_filter=None, since=None, until=None):
    conn   = db()
    report = {"exported_at": datetime.now().isoformat(), "cookies": [], "history": []}

    ck_where, ck_args = build_where(domain=domain_filter)
    for r in conn.execute(f"SELECT * FROM cookies {ck_where} ORDER BY domain, name", ck_args):
        report["cookies"].append(dict(r))

    h_where, h_args = build_where(domain=domain_filter, since=since, until=until)
    for r in conn.execute(f"SELECT * FROM history {h_where} ORDER BY timestamp", h_args):
        row = dict(r)
        for field in ("req_headers", "req_cookies", "res_headers", "res_cookies"):
            try:
                row[field] = json.loads(row[field]) if row[field] else {}
            except Exception:
                pass
        report["history"].append(row)

    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(c(GR, f"\n✅  JSON export: {len(report['history'])} rows + {len(report['cookies'])} cookies → {path}\n"))
    tips(
        f"Also export as HAR : {c(CY, path.replace('.json','.har') + ' (--export)')}",
        f"Also export as CSV : {c(CY, path.replace('.json','.csv') + ' (--export)')}",
        f"Open dashboard     : {c(CY,'python dashboard.py')}",
    )

# ──────────────────────────────────────────────────────────
# Export: CSV
# ──────────────────────────────────────────────────────────

def cmd_export_csv(path: str, domain_filter=None, since=None, until=None):
    conn        = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows        = conn.execute(
        f"SELECT * FROM history {where} ORDER BY timestamp", args
    ).fetchall()

    COLS = [
        "id", "timestamp", "domain", "url", "method", "status_code",
        "content_type", "size_bytes",
        "req_body_is_binary", "req_body_type", "res_body_is_binary",
        "req_body", "res_body",
    ]

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r[k] for k in COLS if k in r.keys()})

    Path(path).write_text(buf.getvalue(), encoding="utf-8-sig")
    print(c(GR, f"\n✅  CSV export: {len(rows)} rows → {path}\n"))
    tips(
        "Open in Excel / Google Sheets directly",
        f"Also export as HAR : {c(CY,'python viewer.py --export report.har')}",
        f"Also export as JSON: {c(CY,'python viewer.py --export report.json')}",
    )

# ──────────────────────────────────────────────────────────
# Export: HAR  (HTTP Archive 1.2)
# ──────────────────────────────────────────────────────────

def _iso_z(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return ts


def _har_headers(json_str) -> list:
    try:
        obj = json_str if isinstance(json_str, dict) else (json.loads(json_str) if json_str else {})
    except Exception:
        return []
    out = []
    for k, v in obj.items():
        if isinstance(v, list):
            for vi in v:
                out.append({"name": k, "value": str(vi)})
        else:
            out.append({"name": k, "value": str(v)})
    return out


def _har_cookies(json_str) -> list:
    try:
        obj = json_str if isinstance(json_str, dict) else (json.loads(json_str) if json_str else {})
    except Exception:
        return []
    return [{"name": k, "value": str(v)} for k, v in obj.items()]


def cmd_export_har(path: str, domain_filter=None, since=None, until=None):
    conn        = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows        = conn.execute(
        f"SELECT * FROM history {where} ORDER BY timestamp", args
    ).fetchall()

    entries = []
    for r in rows:
        parsed   = urlparse(r["url"])
        req_body = r["req_body"] or ""
        req_ct   = ""
        try:
            hdrs   = json.loads(r["req_headers"] or "{}")
            req_ct = hdrs.get("content-type", "")
        except Exception:
            pass

        post_data = None
        if req_body:
            post_data = {"mimeType": req_ct, "text": req_body, "params": []}

        res_body  = r["res_body"] or ""
        res_ct    = r["content_type"] or "application/octet-stream"
        raw_query = parsed.query or ""
        query_string = []
        if raw_query:
            for qp in raw_query.split("&"):
                if "=" in qp:
                    qk, _, qv = qp.partition("=")
                    query_string.append({"name": qk, "value": qv})
                else:
                    query_string.append({"name": qp, "value": ""})

        entry = {
            "startedDateTime": _iso_z(r["timestamp"]),
            "time": -1,
            "request": {
                "method":      r["method"],
                "url":         r["url"],
                "httpVersion": "HTTP/1.1",
                "headers":     _har_headers(r["req_headers"]),
                "cookies":     _har_cookies(r["req_cookies"]),
                "queryString": query_string,
                "postData":    post_data,
                "headersSize": -1,
                "bodySize":    len(req_body.encode()),
            },
            "response": {
                "status":      r["status_code"] or 0,
                "statusText":  "",
                "httpVersion": "HTTP/1.1",
                "headers":     _har_headers(r["res_headers"]),
                "cookies":     _har_cookies(r["res_cookies"]),
                "content": {
                    "size":     r["size_bytes"] or 0,
                    "mimeType": res_ct,
                    "text":     res_body if not r["res_body_is_binary"] else "",
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize":    r["size_bytes"] or -1,
            },
            "cache": {},
            "timings": {"send": -1, "wait": -1, "receive": -1},
        }
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "proxyvault", "version": __version__},
            "entries": entries,
        }
    }

    Path(path).write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
    print(c(GR, f"\n✅  HAR export: {len(entries)} entries → {path}\n"))
    tips(
        "Chrome DevTools : Network tab → ⬆ Import HAR",
        "Burp Suite      : Proxy → HTTP history → Import",
        f"Insomnia        : File → Import → {path}",
        f"Also as CSV     : {c(CY,'python viewer.py --export report.csv')}",
    )

# ──────────────────────────────────────────────────────────
# Export: Postman Collection v2.1
# ──────────────────────────────────────────────────────────

def _make_postman_env(env_name: str, domains: list[str], primary_domain: str) -> dict:
    import uuid

    def _slug(d: str) -> str:
        return d.replace(".", "_").replace("-", "_")

    conn2      = db()
    scheme_map: dict[str, str] = {}
    for dom in domains:
        row = conn2.execute("SELECT url FROM history WHERE domain=? LIMIT 1", (dom,)).fetchone()
        if row:
            scheme_map[dom] = urlparse(row["url"]).scheme or "https"
        else:
            scheme_map[dom] = "https"

    primary_scheme = scheme_map.get(primary_domain, "https")
    variables = [
        {
            "id":      str(uuid.uuid4()),
            "key":    "base_url",
            "value":  f"{primary_scheme}://{primary_domain}",
            "type":   "default",
            "enabled": True,
        }
    ]
    for dom in domains:
        if dom == primary_domain:
            continue
        variables.append({
            "id":      str(uuid.uuid4()),
            "key":    f"base_url_{_slug(dom)}",
            "value":  f"{scheme_map[dom]}://{dom}",
            "type":   "default",
            "enabled": True,
        })

    return {
        "id":   str(uuid.uuid4()),
        "name": env_name,
        "values": variables,
        "_postman_variable_scope": "environment",
        "_postman_exported_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "_postman_exported_using": f"proxyvault/{__version__}",
    }


def cmd_export_postman(path: str, domain_filter=None, since=None, until=None):
    conn        = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows        = conn.execute(
        f"SELECT * FROM history {where} ORDER BY domain, timestamp", args
    ).fetchall()

    folders: dict[str, list]       = {}
    domain_req_count: dict[str, int] = {}

    def _slug(d: str) -> str:
        return d.replace(".", "_").replace("-", "_")

    for r in rows:
        parsed   = urlparse(r["url"])
        domain   = r["domain"]
        method   = r["method"]
        url_path = parsed.path or "/"

        query = []
        if parsed.query:
            for qp in parsed.query.split("&"):
                if "=" in qp:
                    k, _, v = qp.partition("=")
                    query.append({"key": k, "value": v})
                else:
                    query.append({"key": qp, "value": ""})

        headers = []
        try:
            for k, v in (json.loads(r["req_headers"] or "{}")).items():
                val = v if isinstance(v, str) else v[0] if v else ""
                headers.append({"key": k, "value": val})
        except Exception:
            pass

        body      = None
        body_type = r["req_body_type"] or "text"
        req_body  = r["req_body"] or ""
        if req_body and not r["req_body_is_binary"]:
            if body_type == "form":
                try:
                    pairs = json.loads(req_body)
                    body  = {
                        "mode": "urlencoded",
                        "urlencoded": [
                            {"key": k, "value": str(v), "type": "text"}
                            for k, v in pairs.items()
                        ],
                    }
                except Exception:
                    body = {"mode": "raw", "raw": req_body,
                            "options": {"raw": {"language": "text"}}}
            elif body_type == "json":
                body = {"mode": "raw", "raw": req_body,
                        "options": {"raw": {"language": "json"}}}
            elif body_type == "multipart":
                body = {"mode": "formdata", "formdata": []}
            else:
                body = {"mode": "raw", "raw": req_body,
                        "options": {"raw": {"language": "text"}}}

        res_headers = []
        try:
            for k, v in (json.loads(r["res_headers"] or "{}")).items():
                val = v if isinstance(v, str) else v[0] if v else ""
                res_headers.append({"key": k, "value": val})
        except Exception:
            pass

        res_body_text = ""
        if not r["res_body_is_binary"] and r["res_body"]:
            res_body_text = r["res_body"][:8000]

        ct = r["content_type"] or ""
        preview_lang = ("json" if "json" in ct else "html" if "html" in ct else "text")

        domain_req_count[domain] = domain_req_count.get(domain, 0) + 1
        var_key      = f"__DOMAIN_VAR_{domain}__"
        raw_with_var = f"{var_key}{url_path}" + (f"?{parsed.query}" if parsed.query else "")

        url_obj = {
            "raw":   raw_with_var,
            "host":  [var_key],
            "path":  [p for p in url_path.split("/") if p],
            "query": query,
        }

        item = {
            "name": f"{method} {url_path}",
            "request": {
                "method": method,
                "header": headers,
                "url":    url_obj,
                **({"body": body} if body else {}),
            },
            "response": [{
                "name": "Captured response",
                "originalRequest": {"method": method, "url": url_obj},
                "status": str(r["status_code"] or ""),
                "code":   r["status_code"] or 0,
                "_postman_previewlanguage": preview_lang,
                "header": res_headers,
                "body":   res_body_text,
            }],
        }
        folders.setdefault(domain, []).append(item)

    if domain_req_count:
        primary_domain = max(domain_req_count, key=lambda d: domain_req_count[d])
    elif domain_filter:
        primary_domain = domain_filter
    else:
        primary_domain = "unknown"

    def _var_for(domain: str) -> str:
        if domain == primary_domain:
            return "{{base_url}}"
        return "{{" + f"base_url_{_slug(domain)}" + "}}"

    for domain, items in folders.items():
        var_ref     = _var_for(domain)
        placeholder = f"__DOMAIN_VAR_{domain}__"
        for item in items:
            for obj in (
                item["request"]["url"],
                item["response"][0]["originalRequest"]["url"],
            ):
                obj["raw"]  = obj["raw"].replace(placeholder, var_ref)
                obj["host"] = [var_ref]

    label = domain_filter or "All domains"

    # fix #16 — embed the actual primary-domain URL so the collection works
    # standalone without the environment file.  Postman showed an empty-variable
    # error when "value" was "".  The environment file still overrides this when
    # both files are imported together.
    _scheme_row = conn.execute(
        "SELECT url FROM history WHERE domain=? LIMIT 1", (primary_domain,)
    ).fetchone()
    _primary_scheme  = urlparse(_scheme_row["url"]).scheme if _scheme_row else "https"
    _base_url_value  = f"{_primary_scheme}://{primary_domain}"

    collection = {
        "info": {
            "name":   f"Proxy Capture — {label}",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [{"key": "base_url", "value": _base_url_value, "type": "string"}],
        "item": [{"name": domain, "item": items} for domain, items in folders.items()],
    }
    Path(path).write_text(json.dumps(collection, indent=2, ensure_ascii=False), encoding="utf-8")

    stem = Path(path).name
    for suffix in (".postman_collection.json", ".postman.json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    else:
        stem = Path(path).stem

    env_path = Path(path).parent / f"{stem}.postman_environment.json"
    env_obj  = _make_postman_env(
        env_name       = f"Proxy Capture — {label}",
        domains        = list(folders.keys()),
        primary_domain = primary_domain,
    )
    env_path.write_text(json.dumps(env_obj, indent=2, ensure_ascii=False), encoding="utf-8")

    total_reqs = sum(len(v) for v in folders.values())
    print(c(GR, f"\n✅  Postman export: {total_reqs} requests across {len(folders)} domains"))
    print(f"    Collection  → {path}")
    print(f"    Environment → {env_path}")
    print()
    tips(
        "Import both files : Postman → File → Import → select both .json files",
        f"Set active environment to {c(CY, f'Proxy Capture — {label}')} in the top-right dropdown",
        f"base_url is pre-set to {c(CY, _base_url_value)} — override per-env if needed",
        c(YL, "Note: redacted headers/tokens won't appear — run proxy with --no-redact to capture them."),
        f"Also export as HAR : {c(CY,'python viewer.py --export report.har')}",
    )

# ──────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────

def main():
    global DB_PATH
    parser = argparse.ArgumentParser(
        description="Proxy DB Viewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python viewer.py
  python viewer.py --domain google.com --limit 200
  python viewer.py --history --since 2025-05-01 --until 2025-05-15
  python viewer.py --search login --domain github.com
  python viewer.py --replay 42
  python viewer.py --export out.har
  python viewer.py --export out.csv --since 2025-05-10
  python viewer.py --export out.postman_collection.json
  python viewer.py --export out.postman_collection.json --domain github.com
  python viewer.py --prune --older-than 7
  python viewer.py --prune --keep-last 5000
  python viewer.py --watch
  python viewer.py --watch --domain api.example.com
""")

    parser.add_argument("--version",    "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db",               default=str(DB_PATH), help="Path to proxy.db")
    parser.add_argument("--domain",     "-d", help="Filter by domain")
    parser.add_argument("--cookies",    "-c", action="store_true", help="Dump all cookies")
    parser.add_argument("--history",          action="store_true", help="Show browsing history")
    parser.add_argument("--request",    "-r", type=int, metavar="ID",
                        help="Full request/response for a row")
    parser.add_argument("--replay",           type=int, metavar="ID",
                        help="Re-send a saved request live")
    parser.add_argument("--search",     "-s", metavar="TERM",
                        help="Search URLs + request/response bodies (FTS5)")
    parser.add_argument("--export",     "-e", metavar="FILE",
                        help="Export to .json / .har / .csv / .postman_collection.json")
    parser.add_argument("--stats",            action="store_true", help="Database statistics")
    parser.add_argument("--watch",      "-w", action="store_true",
                        help="Live-tail new requests (Ctrl+C stops)")
    parser.add_argument("--prune",            action="store_true",
                        help="Delete old rows (use with --older-than or --keep-last)")
    parser.add_argument("--older-than",       type=int, metavar="DAYS",
                        help="Delete rows older than N days")
    parser.add_argument("--keep-last",        type=int, metavar="N",
                        help="Keep only the N most recent rows")
    parser.add_argument("--limit",            type=int, default=100, help="Max rows (default 100)")
    parser.add_argument("--since",            metavar="YYYY-MM-DD", help="Filter from date (inclusive)")
    parser.add_argument("--until",            metavar="YYYY-MM-DD", help="Filter to date (inclusive)")
    args = parser.parse_args()

    DB_PATH = Path(args.db)

    if args.request:
        cmd_request(args.request)
    elif args.replay:
        cmd_replay(args.replay)
    elif args.prune:
        if args.older_than is None and args.keep_last is None:
            print(c(RD, "\n  --prune requires --older-than <days> or --keep-last <n>\n"))
            sys.exit(1)
        cmd_prune(older_than=args.older_than, keep_last=args.keep_last)
    elif args.watch:
        cmd_watch(domain_filter=args.domain)
    elif args.cookies:
        cmd_cookies(args.domain)
    elif args.history:
        cmd_history(args.domain, args.limit, args.since, args.until)
    elif args.search:
        cmd_search(args.search, args.domain, args.since, args.until, args.limit or 200)
    elif args.export:
        p = args.export.lower()
        if p.endswith(".har"):
            cmd_export_har(args.export, args.domain, args.since, args.until)
        elif p.endswith(".csv"):
            cmd_export_csv(args.export, args.domain, args.since, args.until)
        elif p.endswith(".postman_collection.json") or p.endswith(".postman.json"):
            cmd_export_postman(args.export, args.domain, args.since, args.until)
        else:
            cmd_export_json(args.export, args.domain, args.since, args.until)
    elif args.stats:
        cmd_stats()
    elif args.domain:
        cmd_domain(args.domain, args.limit)
    else:
        cmd_list()


if __name__ == "__main__":
    main()
