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
  python viewer.py --search <term>              # search URLs AND bodies
  python viewer.py --search <term> --body       # force body search (implied by default)
  python viewer.py --export report.json         # dump everything to JSON
  python viewer.py --export report.har          # export as HAR (importable into DevTools/Burp)
  python viewer.py --export report.csv          # export history as CSV
  python viewer.py --stats                      # DB statistics
"""

import argparse
import csv
import json
import sqlite3
import sys
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

DATA_DIR = Path(__file__).parent / "proxy_data"
DB_PATH  = DATA_DIR / "proxy.db"

# ANSI colours
CY = "\033[96m"; GR = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; BD = "\033[1m";  DM = "\033[2m"; RS = "\033[0m"
def c(col, t): return f"{col}{t}{RS}"

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
# Shared filter builder
# ──────────────────────────────────────────────────────────

def build_where(domain=None, since=None, until=None, extra_clauses=None):
    """Return (where_sql, args_list) for common filters."""
    clauses = list(extra_clauses or [])
    args    = []
    if domain:
        clauses.append("domain = ?"); args.append(domain)
    if since:
        clauses.append("timestamp >= ?"); args.append(since)
    if until:
        clauses.append("timestamp <= ?"); args.append(until + "T23:59:59")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, args

# ──────────────────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────────────────

def cmd_list():
    conn = db()
    rows = conn.execute("""
        SELECT
            h.domain,
            COUNT(h.id)                              AS requests,
            SUM(h.size_bytes)                        AS total_bytes,
            MAX(h.timestamp)                         AS last_seen,
            COUNT(DISTINCT c.name)                   AS cookies
        FROM history h
        LEFT JOIN cookies c ON c.domain = h.domain
        GROUP BY h.domain
        ORDER BY last_seen DESC
    """).fetchall()

    if not rows:
        print(c(YL, "No data yet. Run the proxy and browse something.")); return

    print(c(BD, f"\n  {'Domain':<35} {'Reqs':>6} {'Size':>10} {'Cookies':>8}  Last seen"))
    print("  " + "─"*80)
    for r in rows:
        size = f"{r['total_bytes']/1024:.1f} KB" if r['total_bytes'] else "0 B"
        ts   = r['last_seen'][:19].replace("T"," ") if r['last_seen'] else "-"
        print(f"  {c(CY,r['domain']):<44} {r['requests']:>6} {size:>10} {r['cookies']:>8}  {ts}")
    print()


def cmd_domain(domain: str, limit: int = 50):
    conn = db()

    cookies = conn.execute(
        "SELECT * FROM cookies WHERE domain=? ORDER BY name", (domain,)
    ).fetchall()

    print(c(BD, f"\n{'─'*60}"))
    print(c(BD, f"  {domain}"))
    print(c(BD, f"{'─'*60}\n"))

    if cookies:
        print(c(GR, f"  🍪  Cookies ({len(cookies)})\n"))
        print(f"  {'Name':<30} {'Value':<35} Secure  HttpOnly  Updated")
        print("  " + "─"*95)
        for ck in cookies:
            val = (ck['value'] or '')[:33] + ('…' if len(ck['value'] or '')>33 else '')
            sec = c(GR,"yes") if ck['secure'] else "no "
            hto = c(GR,"yes") if ck['http_only'] else "no "
            ts  = (ck['updated_at'] or '')[:19].replace("T"," ")
            print(f"  {ck['name']:<30} {val:<35} {sec}     {hto}       {ts}")
    else:
        print(c(YL, "  No cookies."))

    rows = conn.execute("""
        SELECT id, timestamp, method, status_code, url,
               content_type, size_bytes, req_body_is_binary, res_body_is_binary
        FROM history WHERE domain=?
        ORDER BY timestamp DESC LIMIT ?
    """, (domain, limit)).fetchall()

    print(c(GR, f"\n  📜  History (last {len(rows)} requests)\n"))
    print(f"  {'ID':>6}  {'Time':<20} {'St':>3}  {'Method':<7} {'URL'}")
    print("  " + "─"*100)
    for r in rows:
        ts  = r['timestamp'][:19].replace("T"," ")
        url = r['url'][:65] + ('…' if len(r['url'])>65 else '')
        stc = GR if r['status_code'] and r['status_code']<400 else RD
        print(f"  {r['id']:>6}  {ts}  {c(stc,str(r['status_code'])):>3}  {r['method']:<7} {url}")

    print(f"\n  Tip: python viewer.py --request <ID>  to see full request/response\n")


def cmd_cookies(domain_filter=None):
    conn = db()
    q    = "SELECT * FROM cookies"
    args = ()
    if domain_filter:
        q += " WHERE domain=?"; args = (domain_filter,)
    q += " ORDER BY domain, name"
    rows = conn.execute(q, args).fetchall()

    print(c(BD, f"\n🍪  All Cookies ({len(rows)})\n"))
    cur_domain = None
    for r in rows:
        if r['domain'] != cur_domain:
            cur_domain = r['domain']
            print(c(CY, f"  {cur_domain}"))
        val = (r['value'] or '')[:60] + ('…' if len(r['value'] or '')>60 else '')
        flags = []
        if r['secure']:    flags.append("Secure")
        if r['http_only']: flags.append("HttpOnly")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"    {r['name']:<35} = {val}{tag}")
    print()


def cmd_history(domain_filter=None, limit=100, since=None, until=None):
    conn   = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows   = conn.execute(f"""
        SELECT id, timestamp, domain, method, status_code, url,
               content_type, size_bytes, req_body_is_binary, res_body_is_binary
        FROM history {where}
        ORDER BY timestamp DESC LIMIT ?
    """, args + [limit]).fetchall()

    filters = []
    if domain_filter: filters.append(f"domain={domain_filter}")
    if since:         filters.append(f"since={since}")
    if until:         filters.append(f"until={until}")
    label = f"  [{', '.join(filters)}]" if filters else ""

    print(c(BD, f"\n📜  History ({len(rows)} rows){label}\n"))
    print(f"  {'ID':>6}  {'Time':<20} {'Domain':<28} {'St':>3}  {'Method':<7} {'URL'}")
    print("  " + "─"*110)
    for r in rows:
        ts  = r['timestamp'][:19].replace("T"," ")
        url = r['url'][:50] + ('…' if len(r['url'])>50 else '')
        dom = r['domain'][:26]
        stc = GR if r['status_code'] and r['status_code']<400 else RD
        bin_flag = c(DM," [bin]") if r['res_body_is_binary'] else ""
        print(f"  {r['id']:>6}  {ts}  {c(CY,dom):<37} {c(stc,str(r['status_code'])):>3}  {r['method']:<7} {url}{bin_flag}")
    print()


def cmd_request(row_id: int):
    conn = db()
    r = conn.execute("SELECT * FROM history WHERE id=?", (row_id,)).fetchone()
    if not r:
        print(c(RD, f"No history row with id={row_id}")); return

    def pretty_json(s):
        try: return json.dumps(json.loads(s), indent=4)
        except: return s or "(none)"

    print(c(BD, f"\n{'═'*65}"))
    print(c(BD, f"  Request #{r['id']}  —  {r['timestamp'][:19].replace('T',' ')}"))
    print(c(BD, f"{'═'*65}\n"))

    print(c(GR, "  ── REQUEST ──────────────────────────────"))
    print(f"  {r['method']}  {r['url']}")
    print(c(YL, "\n  Headers:"))
    print(pretty_json(r['req_headers']))
    print(c(YL, "\n  Cookies sent:"))
    print(pretty_json(r['req_cookies']))
    print(c(YL, "\n  Body:"))
    if r['req_body_is_binary']:
        print(c(RD,"  (binary — not stored)"))
    else:
        print(r['req_body'] or "(empty)")

    print(c(GR, "\n  ── RESPONSE ─────────────────────────────"))
    stc = GR if r['status_code'] and r['status_code']<400 else RD
    print(f"  Status : {c(stc, str(r['status_code']))}")
    print(f"  Type   : {r['content_type']}")
    print(f"  Size   : {r['size_bytes']:,} bytes")
    print(c(YL, "\n  Headers:"))
    print(pretty_json(r['res_headers']))
    print(c(YL, "\n  Cookies set:"))
    print(pretty_json(r['res_cookies']))
    print(c(YL, "\n  Body:"))
    if r['res_body_is_binary']:
        print(c(RD,"  (binary — not stored)"))
    elif r['res_body']:
        preview = r['res_body'][:2000]
        print(preview)
        if len(r['res_body']) > 2000:
            print(c(YL,f"\n  … ({len(r['res_body']):,} chars total, showing first 2000)"))
    else:
        print("  (not saved — enable --save-pages or check content type)")
    print()


def cmd_search(term: str, domain_filter=None, since=None, until=None, limit=200):
    """Search URLs and text bodies (req + res)."""
    conn = db()
    pat  = f"%{term}%"

    extra = ["(url LIKE ? OR req_body LIKE ? OR res_body LIKE ?)"]
    where, base_args = build_where(domain=domain_filter, since=since, until=until,
                                   extra_clauses=extra)
    # The LIKE pattern needs to appear 3× for the OR expression
    args = [pat, pat, pat] + base_args

    # SQLite evaluates WHERE left-to-right; rewrite so domain/time come first
    # Actually rebuild properly:
    clauses = []
    args    = []
    if domain_filter:
        clauses.append("domain = ?"); args.append(domain_filter)
    if since:
        clauses.append("timestamp >= ?"); args.append(since)
    if until:
        clauses.append("timestamp <= ?"); args.append(until + "T23:59:59")
    clauses.append("(url LIKE ? OR req_body LIKE ? OR res_body LIKE ?)")
    args += [pat, pat, pat]

    where = "WHERE " + " AND ".join(clauses)

    rows = conn.execute(f"""
        SELECT id, timestamp, domain, method, status_code, url,
               req_body, res_body
        FROM history {where}
        ORDER BY timestamp DESC LIMIT ?
    """, args + [limit]).fetchall()

    filters = []
    if domain_filter: filters.append(f"domain={domain_filter}")
    if since:         filters.append(f"since={since}")
    if until:         filters.append(f"until={until}")
    label = f"  [{', '.join(filters)}]" if filters else ""

    print(c(BD, f"\n🔍  Search: '{term}'  ({len(rows)} results){label}\n"))
    for r in rows:
        ts  = r['timestamp'][:19].replace("T"," ")
        stc = GR if r['status_code'] and r['status_code']<400 else RD
        url = r['url'][:75] + ('…' if len(r['url'])>75 else '')

        # Show which field matched
        tl = term.lower()
        matched = []
        if tl in (r['url'] or '').lower():                matched.append("url")
        if tl in (r['req_body'] or '').lower():           matched.append("req-body")
        if tl in (r['res_body'] or '').lower():           matched.append("res-body")
        match_tag = c(DM, f"  [{', '.join(matched)}]") if matched else ""

        print(f"  {r['id']:>6}  {ts}  {c(stc,str(r['status_code']))}  {r['method']:<7} {url}{match_tag}")
    print()


def cmd_stats():
    conn = db()
    h        = conn.execute("SELECT COUNT(*) as n, SUM(size_bytes) as sz FROM history").fetchone()
    ck       = conn.execute("SELECT COUNT(*) as n FROM cookies").fetchone()
    d        = conn.execute("SELECT COUNT(DISTINCT domain) as n FROM history").fetchone()
    bin_req  = conn.execute("SELECT COUNT(*) as n FROM history WHERE req_body_is_binary=1").fetchone()
    bin_res  = conn.execute("SELECT COUNT(*) as n FROM history WHERE res_body_is_binary=1").fetchone()
    methods  = conn.execute("SELECT method, COUNT(*) as n FROM history GROUP BY method ORDER BY n DESC").fetchall()
    statuses = conn.execute("SELECT status_code, COUNT(*) as n FROM history GROUP BY status_code ORDER BY n DESC LIMIT 10").fetchall()
    top_dom  = conn.execute("SELECT domain, COUNT(*) as n FROM history GROUP BY domain ORDER BY n DESC LIMIT 5").fetchall()
    db_size  = DB_PATH.stat().st_size if DB_PATH.exists() else 0

    print(c(BD, "\n📊  Database Statistics\n"))
    print(f"  DB file        : {DB_PATH}")
    print(f"  DB size        : {db_size/1024:.1f} KB")
    print(f"  Domains        : {d['n']}")
    print(f"  Total requests : {h['n']}")
    print(f"  Total traffic  : {(h['sz'] or 0)/1024:.1f} KB")
    print(f"  Cookies stored : {ck['n']}")
    print(f"  Binary req body: {bin_req['n']}")
    print(f"  Binary res body: {bin_res['n']}")

    print(c(YL, "\n  Methods:"))
    for m in methods:
        print(f"    {m['method']:<10} {m['n']:>6}")

    print(c(YL, "\n  Status codes:"))
    for s in statuses:
        col = GR if s['status_code'] and s['status_code']<400 else RD
        print(f"    {c(col,str(s['status_code'])):<20} {s['n']:>6}")

    print(c(YL, "\n  Top domains:"))
    for t in top_dom:
        print(f"    {c(CY,t['domain']):<40} {t['n']:>6} reqs")
    print()


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
        for field in ("req_headers","req_cookies","res_headers","res_cookies"):
            try: row[field] = json.loads(row[field]) if row[field] else {}
            except: pass
        report["history"].append(row)

    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(c(GR, f"\n✅  JSON export: {len(report['history'])} rows + {len(report['cookies'])} cookies → {path}\n"))


# ──────────────────────────────────────────────────────────
# Export: CSV
# ──────────────────────────────────────────────────────────

def cmd_export_csv(path: str, domain_filter=None, since=None, until=None):
    conn    = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows    = conn.execute(
        f"SELECT * FROM history {where} ORDER BY timestamp", args
    ).fetchall()

    COLS = [
        "id","timestamp","domain","url","method","status_code",
        "content_type","size_bytes",
        "req_body_is_binary","res_body_is_binary",
        "req_body","res_body",
    ]

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r[k] for k in COLS if k in r.keys()})

    Path(path).write_text(buf.getvalue(), encoding="utf-8-sig")   # utf-8-sig → Excel opens correctly
    print(c(GR, f"\n✅  CSV export: {len(rows)} rows → {path}\n"))


# ──────────────────────────────────────────────────────────
# Export: HAR  (HTTP Archive 1.2)
# ──────────────────────────────────────────────────────────

def _iso_z(ts: str) -> str:
    """Convert stored ISO timestamp to UTC Z-suffix format required by HAR."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return ts

def _har_headers(json_str: str) -> list:
    """Convert stored JSON headers object → HAR headers array."""
    try:
        obj = json.loads(json_str) if json_str else {}
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

def _har_cookies(json_str: str) -> list:
    """Convert stored JSON cookies object → HAR cookies array."""
    try:
        obj = json.loads(json_str) if json_str else {}
    except Exception:
        return []
    return [{"name": k, "value": str(v)} for k, v in obj.items()]

def cmd_export_har(path: str, domain_filter=None, since=None, until=None):
    conn    = db()
    where, args = build_where(domain=domain_filter, since=since, until=until)
    rows    = conn.execute(
        f"SELECT * FROM history {where} ORDER BY timestamp", args
    ).fetchall()

    entries = []
    for r in rows:
        parsed   = urlparse(r["url"])
        req_body = r["req_body"] or ""
        req_ct   = ""
        try:
            hdrs = json.loads(r["req_headers"] or "{}")
            req_ct = hdrs.get("content-type", "")
        except Exception:
            pass

        post_data = None
        if req_body:
            post_data = {
                "mimeType": req_ct,
                "text":     req_body,
                "params":   [],
            }

        res_body = r["res_body"] or ""
        res_ct   = r["content_type"] or "application/octet-stream"

        entry = {
            "startedDateTime": _iso_z(r["timestamp"]),
            "time":            -1,   # total ms; unknown
            "request": {
                "method":      r["method"],
                "url":         r["url"],
                "httpVersion": "HTTP/1.1",
                "headers":     _har_headers(r["req_headers"]),
                "cookies":     _har_cookies(r["req_cookies"]),
                "queryString": [{"name": k, "value": v}
                                for k, v in (q.split("=",1) if "=" in q else (q,"")
                                             for q in (parsed.query.split("&") if parsed.query else []))],
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
            "creator": {"name": "network-proxy", "version": "1.0"},
            "entries": entries,
        }
    }

    Path(path).write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
    print(c(GR, f"\n✅  HAR export: {len(entries)} entries → {path}"))
    print(c(DM,  "    Import in Chrome DevTools → Network → ⬆ Import HAR\n"))


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
  python viewer.py --export out.har
  python viewer.py --export out.csv --since 2025-05-10
""")

    parser.add_argument("--db",       default=str(DB_PATH), help="Path to proxy.db")
    parser.add_argument("--domain",   "-d", help="Filter by domain")
    parser.add_argument("--cookies",  "-c", action="store_true", help="Dump all cookies")
    parser.add_argument("--history",  action="store_true",        help="Show browsing history")
    parser.add_argument("--request",  "-r", type=int, metavar="ID", help="Full request/response for a row")
    parser.add_argument("--search",   "-s", metavar="TERM", help="Search URLs + request/response bodies")
    parser.add_argument("--export",   "-e", metavar="FILE",  help="Export to .json / .har / .csv")
    parser.add_argument("--stats",    action="store_true",   help="Database statistics")
    parser.add_argument("--limit",    type=int, default=100, help="Max rows for history/domain (default 100)")
    parser.add_argument("--since",    metavar="YYYY-MM-DD",  help="Filter: from date (inclusive)")
    parser.add_argument("--until",    metavar="YYYY-MM-DD",  help="Filter: to date (inclusive)")
    args = parser.parse_args()

    DB_PATH = Path(args.db)

    if args.request:
        cmd_request(args.request)
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
