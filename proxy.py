#!/usr/bin/env python3
"""
CLI Network Proxy - SQLite-backed storage for cookies, history, requests/responses.

Schema:
  cookies  — one row per cookie name per domain (upserted, always latest)
  history  — one row per HTTP request with full headers, body, response
"""

import asyncio
import argparse
import json
import re
import sys
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import http as mhttp
except ImportError:
    print("[ERROR] mitmproxy not found. Run: pip install mitmproxy")
    sys.exit(1)

# ──────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────
DATA_DIR   = Path(__file__).parent / "proxy_data"
SAVE_PAGES = True
DB_PATH    = DATA_DIR / "proxy.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

# ──────────────────────────────────────────────
# DB layer
# ──────────────────────────────────────────────

# One connection per thread (mitmproxy runs hooks on multiple threads)
_local = threading.local()

def get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")   # fastest safe mode
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA cache_size=-8000")   # 8 MB cache
    return _local.conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    conn.executescript("""
        -- ── cookies ──────────────────────────────────────────
        -- One row per (domain, name). Upserted on every Set-Cookie.
        CREATE TABLE IF NOT EXISTS cookies (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            domain       TEXT    NOT NULL,
            name         TEXT    NOT NULL,
            value        TEXT,
            path         TEXT,
            expires      TEXT,
            http_only    INTEGER DEFAULT 0,   -- 1/0
            secure       INTEGER DEFAULT 0,   -- 1/0
            same_site    TEXT,
            source       TEXT    DEFAULT 'server',  -- 'server' | 'browser'
            updated_at   TEXT    NOT NULL,
            UNIQUE(domain, name) ON CONFLICT REPLACE
        );
        CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies(domain);

        -- ── history ───────────────────────────────────────────
        -- One row per intercepted HTTP request/response pair.
        CREATE TABLE IF NOT EXISTS history (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp            TEXT    NOT NULL,
            domain               TEXT    NOT NULL,
            url                  TEXT    NOT NULL,
            method               TEXT    NOT NULL,

            -- request
            req_headers          TEXT,   -- JSON object
            req_cookies          TEXT,   -- JSON object  (cookies sent by browser)
            req_body             TEXT,   -- text body (NULL if binary)
            req_body_is_binary   INTEGER DEFAULT 0,  -- 1 if body was binary

            -- response
            status_code          INTEGER,
            res_headers          TEXT,   -- JSON object
            res_cookies          TEXT,   -- JSON object  (Set-Cookie values)
            res_body             TEXT,   -- text body (NULL if binary or non-HTML)
            res_body_is_binary   INTEGER DEFAULT 0,  -- 1 if body was binary
            content_type         TEXT,
            size_bytes           INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_history_domain    ON history(domain);
        CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_history_url       ON history(url);
    """)
    conn.commit()
    log.info(f"[DB] initialised → {DB_PATH}")

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def sanitize_domain(url: str) -> str:
    return urlparse(url).netloc or "unknown"

def now_iso() -> str:
    return datetime.now().isoformat(timespec="milliseconds")

def headers_to_dict(headers) -> dict:
    """Convert mitmproxy Headers to a plain dict (multi-value → list)."""
    result = {}
    for k, v in headers.items():
        k = k.lower()
        if k in result:
            if isinstance(result[k], list):
                result[k].append(v)
            else:
                result[k] = [result[k], v]
        else:
            result[k] = v
    return result

def parse_set_cookie(header_val: str) -> dict:
    """Parse a single Set-Cookie header into a structured dict."""
    parts   = [p.strip() for p in header_val.split(";")]
    cookie  = {"name": "", "value": "", "path": None, "expires": None,
               "http_only": 0, "secure": 0, "same_site": None}
    if parts and "=" in parts[0]:
        k, _, v      = parts[0].partition("=")
        cookie["name"]  = k.strip()
        cookie["value"] = v.strip()
    for attr in parts[1:]:
        al = attr.lower()
        if al == "httponly":
            cookie["http_only"] = 1
        elif al == "secure":
            cookie["secure"] = 1
        elif al.startswith("path="):
            cookie["path"] = attr[5:]
        elif al.startswith("expires="):
            cookie["expires"] = attr[8:]
        elif al.startswith("samesite="):
            cookie["same_site"] = attr[9:]
    return cookie

def is_binary(data: bytes) -> bool:
    """Heuristic: if >30% bytes are non-text, treat as binary."""
    if not data:
        return False
    sample = data[:2048]
    non_text = sum(1 for b in sample if b < 9 or (14 <= b < 32) or b > 126)
    return (non_text / len(sample)) > 0.30

def body_text(data: bytes, content_type: str) -> tuple[str | None, bool]:
    """Return (text_or_None, is_binary)."""
    if not data:
        return None, False
    if is_binary(data):
        return None, True
    try:
        encoding = "utf-8"
        if "charset=" in content_type:
            encoding = content_type.split("charset=")[-1].split(";")[0].strip()
        return data.decode(encoding, errors="replace"), False
    except Exception:
        return data.decode("utf-8", errors="replace"), False

# ──────────────────────────────────────────────
# DB write functions
# ──────────────────────────────────────────────

def upsert_cookie(domain: str, cookie: dict, source: str = "server"):
    if not cookie.get("name"):
        return
    conn = get_conn()
    conn.execute("""
        INSERT INTO cookies
            (domain, name, value, path, expires, http_only, secure, same_site, source, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(domain, name) DO UPDATE SET
            value      = excluded.value,
            path       = excluded.path,
            expires    = excluded.expires,
            http_only  = excluded.http_only,
            secure     = excluded.secure,
            same_site  = excluded.same_site,
            source     = excluded.source,
            updated_at = excluded.updated_at
    """, (
        domain,
        cookie["name"],
        cookie.get("value"),
        cookie.get("path"),
        cookie.get("expires"),
        cookie.get("http_only", 0),
        cookie.get("secure", 0),
        cookie.get("same_site"),
        source,
        now_iso(),
    ))
    conn.commit()


def insert_history(
    domain, url, method,
    req_headers, req_cookies, req_body, req_body_is_binary,
    status_code,
    res_headers, res_cookies, res_body, res_body_is_binary,
    content_type, size_bytes,
):
    conn = get_conn()
    conn.execute("""
        INSERT INTO history (
            timestamp, domain, url, method,
            req_headers, req_cookies, req_body, req_body_is_binary,
            status_code,
            res_headers, res_cookies, res_body, res_body_is_binary,
            content_type, size_bytes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        now_iso(), domain, url, method,
        json.dumps(req_headers, ensure_ascii=False),
        json.dumps(req_cookies, ensure_ascii=False),
        req_body, 1 if req_body_is_binary else 0,
        status_code,
        json.dumps(res_headers, ensure_ascii=False),
        json.dumps(res_cookies, ensure_ascii=False),
        res_body, 1 if res_body_is_binary else 0,
        content_type, size_bytes,
    ))
    conn.commit()
    log.info(f"[DB] {method} {status_code} {url[:80]}")

# ──────────────────────────────────────────────
# Addon
# ──────────────────────────────────────────────

class ProxyAddon:

    def request(self, flow: mhttp.HTTPFlow):
        """Save browser-sent cookies early (before response arrives)."""
        try:
            domain = sanitize_domain(flow.request.pretty_url)
            raw    = flow.request.headers.get("cookie", "")
            if raw:
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        upsert_cookie(domain, {"name": k.strip(), "value": v.strip()}, source="browser")
        except Exception as e:
            log.error(f"[request hook] {e}")

    def response(self, flow: mhttp.HTTPFlow):
        try:
            url    = flow.request.pretty_url
            domain = sanitize_domain(url)

            # ── request side ──────────────────────────
            req_headers = headers_to_dict(flow.request.headers)

            req_cookies: dict = {}
            raw = flow.request.headers.get("cookie", "")
            if raw:
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        req_cookies[k.strip()] = v.strip()

            req_body_bytes   = flow.request.content or b""
            req_ct           = flow.request.headers.get("content-type", "")
            req_body, req_bin = body_text(req_body_bytes, req_ct)

            # ── response side ─────────────────────────
            res_headers  = headers_to_dict(flow.response.headers)
            content_type = flow.response.headers.get("content-type", "")
            size_bytes   = len(flow.response.content) if flow.response.content else 0

            # Parse & upsert Set-Cookie headers
            res_cookies: dict = {}
            for hval in flow.response.headers.get_all("set-cookie"):
                c = parse_set_cookie(hval)
                if c["name"]:
                    res_cookies[c["name"]] = c["value"]
                    upsert_cookie(domain, c, source="server")

            # Save HTML page bodies; mark everything else binary if needed
            save_html = SAVE_PAGES and "text/html" in content_type
            res_body_bytes = flow.response.content or b""
            if save_html:
                res_body, res_bin = body_text(res_body_bytes, content_type)
            else:
                res_body, res_bin = None, is_binary(res_body_bytes)

            insert_history(
                domain=domain, url=url, method=flow.request.method,
                req_headers=req_headers, req_cookies=req_cookies,
                req_body=req_body, req_body_is_binary=req_bin,
                status_code=flow.response.status_code,
                res_headers=res_headers, res_cookies=res_cookies,
                res_body=res_body, res_body_is_binary=res_bin,
                content_type=content_type, size_bytes=size_bytes,
            )

        except Exception as e:
            log.error(f"[response hook] {e}", exc_info=True)

# ──────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────

async def run(host: str, port: int):
    opts = Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=True,
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(ProxyAddon())

    print(f"""
{'='*55}
  🌐  Network Proxy  (SQLite backend)
  Listen : {host}:{port}
  DB     : {DB_PATH.resolve()}
  Pages  : {'yes' if SAVE_PAGES else 'no'}
{'='*55}
  Set browser proxy → {host}:{port}
  Press Ctrl+C to stop.
""")

    try:
        await master.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping…")
        master.shutdown()


def main():
    global DATA_DIR, DB_PATH, SAVE_PAGES

    parser = argparse.ArgumentParser(description="CLI Network Proxy (SQLite)")
    parser.add_argument("--host",          default="127.0.0.1")
    parser.add_argument("--port",          type=int, default=8080)
    parser.add_argument("--no-save-pages", action="store_true")
    parser.add_argument("--data-dir",      default=str(DATA_DIR))
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    DATA_DIR   = Path(args.data_dir)
    DB_PATH    = DATA_DIR / "proxy.db"
    SAVE_PAGES = not args.no_save_pages
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    init_db()
    asyncio.run(run(args.host, args.port))


if __name__ == "__main__":
    main()
