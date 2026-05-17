#!/usr/bin/env python3
"""
Web Dashboard for the network proxy SQLite database.

Usage:
  python dashboard.py                          # serves on http://127.0.0.1:5500
  python dashboard.py --port 8888
  python dashboard.py --db /path/to/proxy.db
  python dashboard.py --password secret        # enable HTTP Basic Auth

WebSocket push:
  The dashboard broadcasts new history rows in real-time over a lightweight
  WebSocket server running on (HTTP port + 1).  No extra dependencies — uses
  only the Python standard library's socket + threading.
  Clients connect to  ws://<host>:<port+1>/ws  and receive JSON messages:
    { "type": "new_request", "row": { ...history columns... } }
"""

__version__ = "2.3.0"

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

import sqlite3

# Shared query layer (fix #5 — no more duplicated SQL)
from db_queries import (
    q, q1,
    query_overview,
    query_history,
    query_request,
    query_cookies,
    query_domains,
    query_history_since,
    query_ws_messages,
    query_ws_domains,
    exec_prune,
)

DATA_DIR  = Path(__file__).parent / "proxy_data"
DB_PATH   = DATA_DIR / "proxy.db"
HTML_FILE = Path(__file__).parent / "dashboard.html"

# #11 — stored as SHA-256 hex digest; compared at auth time with hash of supplied password
_DASHBOARD_PASSWORD_HASH: str | None = None

# ──────────────────────────────────────────────────────────
# DB  — persistent connection with auto-reconnect
# ──────────────────────────────────────────────────────────

_db_conn: sqlite3.Connection | None = None
_db_lock = threading.Lock()   # guards _db_conn across HTTP + WS threads


def get_db() -> sqlite3.Connection | None:
    """Return the shared connection, reconnecting automatically on error."""
    global _db_conn
    if not DB_PATH.exists():
        return None
    with _db_lock:
        # Lightweight probe; reconnect if the connection is stale/broken
        if _db_conn is not None:
            try:
                _db_conn.execute("SELECT 1")
            except Exception:
                try:
                    _db_conn.close()
                except Exception:
                    pass
                _db_conn = None
        if _db_conn is None:
            _db_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            _db_conn.row_factory = sqlite3.Row
            _db_conn.execute("PRAGMA journal_mode=WAL")
        # Passive checkpoint so WAL changes are visible without forcing a full flush
        _db_conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return _db_conn


# ──────────────────────────────────────────────────────────
# API handlers  (thin wrappers — real SQL lives in db_queries.py)
# ──────────────────────────────────────────────────────────

def api_overview():
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        return query_overview(conn, DB_PATH)


def api_history(domain=None, since=None, until=None, search=None,
                limit=200, offset=0, status=None, method=None, body_type=None):
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        return query_history(
            conn,
            domain=domain, since=since, until=until,
            search=search, limit=limit, offset=offset,
            status=status, method=method, body_type=body_type,
        )


def api_request(row_id: int):
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        r = query_request(conn, row_id)
    return r if r is not None else {"error": "Not found"}


def api_cookies(domain=None):
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        return query_cookies(conn, domain)


def api_domains():
    conn = get_db()
    if not conn:
        return []
    with _db_lock:
        return query_domains(conn)


def api_ws_messages(history_id=None, domain=None, since=None, until=None,
                    direction=None, opcode=None, limit=200, offset=0):
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        return query_ws_messages(
            conn,
            history_id=int(history_id) if history_id else None,
            domain=domain, since=since, until=until,
            direction=direction,
            opcode=int(opcode) if opcode else None,
            limit=limit, offset=offset,
        )


def api_ws_domains():
    conn = get_db()
    if not conn:
        return []
    with _db_lock:
        return query_ws_domains(conn)


def api_prune(older_than: int | None = None, keep_last: int | None = None) -> dict:
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        return exec_prune(conn, older_than=older_than, keep_last=keep_last)


# #4/#5 — Replay endpoint: re-issues the stored request and returns live response + diff
def api_replay(row_id: int) -> dict:
    conn = get_db()
    if not conn:
        return {"error": "DB not found"}
    with _db_lock:
        r = query_request(conn, row_id)
    if not r:
        return {"error": "Not found"}

    url    = r["url"]
    method = r["method"]

    # Reconstruct headers — skip hop-by-hop
    skip = {"host", "content-length", "transfer-encoding", "connection",
            "proxy-connection", "keep-alive", "upgrade", "te", "trailers"}
    saved_headers = r.get("req_headers") or {}
    if isinstance(saved_headers, str):
        try:
            saved_headers = json.loads(saved_headers)
        except Exception:
            saved_headers = {}
    headers = {k: (v if isinstance(v, str) else v[0])
               for k, v in saved_headers.items() if k.lower() not in skip}

    body = None
    if r.get("req_body") and not r.get("req_body_is_binary"):
        req_ct = saved_headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in req_ct:
            try:
                pairs = json.loads(r["req_body"])
                body  = urlencode(pairs).encode()
            except Exception:
                body = r["req_body"].encode()
        else:
            body = r["req_body"].encode()

    # #7 — Capture redirect chain
    redirect_chain: list[str] = []

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirect_chain.append(f"{code} → {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_NoRedirect())

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with opener.open(req, timeout=15) as resp:
            live_status     = resp.status
            live_headers    = dict(resp.headers)
            live_body_bytes = resp.read(65536)
    except urllib.error.HTTPError as e:
        live_status     = e.code
        live_headers    = dict(e.headers) if e.headers else {}
        live_body_bytes = b""
    except Exception as e:
        return {"error": str(e), "redirect_chain": redirect_chain}

    try:
        live_body = live_body_bytes.decode("utf-8", errors="replace")
    except Exception:
        live_body = "(binary)"

    stored_status = r["status_code"]
    stored_body   = r.get("res_body") or ""
    stored_size   = r.get("size_bytes") or 0
    live_size     = len(live_body_bytes)

    def _word_diff(a: str, b: str) -> list[dict]:
        import difflib
        a_words = a.split()[:500]
        b_words = b.split()[:500]
        sm      = difflib.SequenceMatcher(None, a_words, b_words, autojunk=False)
        result  = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                result.append({"type": "eq",  "text": " ".join(a_words[i1:i2])})
            elif tag in ("replace", "delete"):
                result.append({"type": "del", "text": " ".join(a_words[i1:i2])})
            if tag in ("replace", "insert"):
                result.append({"type": "ins", "text": " ".join(b_words[j1:j2])})
        return result

    diff = _word_diff(stored_body[:4000], live_body[:4000])

    return {
        "id":             row_id,
        "url":            url,
        "method":         method,
        "redirect_chain": redirect_chain,
        "stored": {
            "status":       stored_status,
            "size":         stored_size,
            "body_preview": stored_body[:500],
        },
        "live": {
            "status":       live_status,
            "headers":      live_headers,
            "size":         live_size,
            "body_preview": live_body[:500],
        },
        "diff": {
            "status_changed": stored_status != live_status,
            "size_delta":     live_size - stored_size,
            "body_diff":      diff,
        },
    }


# ──────────────────────────────────────────────────────────
# WebSocket push server  (stdlib only — no websockets package)
# ──────────────────────────────────────────────────────────

_ws_clients: list[socket.socket] = []
_ws_clients_lock = threading.Lock()
_ws_last_id: int = 0          # highest history id already broadcast


def _ws_handshake(conn: socket.socket) -> bool:
    """Perform the HTTP→WS upgrade handshake. Return True on success."""
    try:
        raw = b""
        conn.settimeout(5.0)
        while b"\r\n\r\n" not in raw:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            raw += chunk
        conn.settimeout(None)
        headers = {}
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key", "")
        if not key:
            return False
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        conn.sendall(
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode()
        )
        return True
    except Exception:
        return False


def _ws_send_text(conn: socket.socket, text: str) -> bool:
    """Send a single WebSocket text frame. Return False if the socket is dead."""
    try:
        payload = text.encode("utf-8")
        n = len(payload)
        if n <= 125:
            header = struct.pack("BB", 0x81, n)
        elif n <= 65535:
            header = struct.pack("!BBH", 0x81, 126, n)
        else:
            header = struct.pack("!BBQ", 0x81, 127, n)
        conn.sendall(header + payload)
        return True
    except Exception:
        return False


def _ws_broadcast(message: str):
    """Send a text message to every connected WS client; drop dead ones."""
    dead: list[socket.socket] = []
    with _ws_clients_lock:
        for client in list(_ws_clients):
            if not _ws_send_text(client, message):
                dead.append(client)
        for d in dead:
            _ws_clients.remove(d)
            try:
                d.close()
            except Exception:
                pass


def _ws_client_thread(conn: socket.socket):
    """Keep a single WS connection alive; remove it when the client closes."""
    with _ws_clients_lock:
        _ws_clients.append(conn)
    try:
        conn.settimeout(60.0)
        while True:
            try:
                hdr = conn.recv(2)
                if len(hdr) < 2:
                    break
                masked = bool(hdr[1] & 0x80)
                plen   = hdr[1] & 0x7F
                if plen == 126:
                    plen = struct.unpack("!H", conn.recv(2))[0]
                elif plen == 127:
                    plen = struct.unpack("!Q", conn.recv(8))[0]
                if masked:
                    conn.recv(4)   # masking key
                if plen:
                    conn.recv(plen)
                opcode = hdr[0] & 0x0F
                if opcode == 0x08:   # close frame
                    break
            except Exception:
                break
    finally:
        with _ws_clients_lock:
            if conn in _ws_clients:
                _ws_clients.remove(conn)
        try:
            conn.close()
        except Exception:
            pass


def _ws_poller_thread():
    """
    Background thread: polls DB every second for new rows, broadcasts to WS clients.

    Fix #7 — skips the DB query entirely when no clients are connected,
    avoiding a pointless lock acquisition + SQL round-trip every second.
    """
    global _ws_last_id
    while True:
        time.sleep(1)

        # Fix #7 — fast-path: no clients → nothing to broadcast
        with _ws_clients_lock:
            has_clients = bool(_ws_clients)
        if not has_clients:
            continue

        try:
            db_conn = get_db()
            if db_conn is None:
                continue
            with _db_lock:
                rows = query_history_since(db_conn, _ws_last_id, limit=50)
            if rows:
                _ws_last_id = rows[-1]["id"]
                for row in rows:
                    _ws_broadcast(json.dumps({"type": "new_request", "row": row}, default=str))
        except Exception:
            pass   # never let the poller crash


def _ws_accept_thread(server_sock: socket.socket):
    """Accept loop: spawn a thread per connected WS client."""
    while True:
        try:
            conn, _ = server_sock.accept()
            if not _ws_handshake(conn):
                conn.close()
                continue
            t = threading.Thread(target=_ws_client_thread, args=(conn,), daemon=True)
            t.start()
        except Exception:
            break


def start_ws_server(host: str, ws_port: int):
    """Bind the WS server socket and launch background threads."""
    global _ws_last_id
    try:
        conn = get_db()
        if conn:
            with _db_lock:
                row = conn.execute("SELECT MAX(id) AS n FROM history").fetchone()
            _ws_last_id = row["n"] or 0
    except Exception:
        _ws_last_id = 0

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, ws_port))
    srv.listen(32)

    threading.Thread(target=_ws_accept_thread, args=(srv,), daemon=True).start()
    threading.Thread(target=_ws_poller_thread, daemon=True).start()
    return ws_port


# ──────────────────────────────────────────────────────────
# Auth helper
# ──────────────────────────────────────────────────────────

def _check_auth(handler) -> bool:
    """Return True if auth passes (or auth is disabled).
    #11 — Compares SHA-256 hash of supplied password, not plaintext.
    """
    if not _DASHBOARD_PASSWORD_HASH:
        return True
    auth_header = handler.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8", errors="replace")
        _, _, pwd = decoded.partition(":")
        supplied_hash = hashlib.sha256(pwd.encode()).hexdigest()
        return supplied_hash == _DASHBOARD_PASSWORD_HASH
    except Exception:
        return False


# ──────────────────────────────────────────────────────────
# HTML loader
# ──────────────────────────────────────────────────────────

def _load_html() -> str:
    if HTML_FILE.exists():
        return HTML_FILE.read_text(encoding="utf-8")
    return (
        "<h1>dashboard.html not found — "
        "make sure it is in the same directory as dashboard.py</h1>"
    )


# ──────────────────────────────────────────────────────────
# HTTP handler
# ──────────────────────────────────────────────────────────

# #10 — CSRF token for destructive POST endpoints
_CSRF_HEADER = "X-Requested-With"
_CSRF_VALUE  = "XHR"

# Exposed via /api/ws_port; set in main()
_WS_PORT: int = 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def _require_auth(self) -> bool:
        if _check_auth(self):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Proxy Dashboard"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Unauthorized")
        return False

    def _require_csrf(self) -> bool:
        """#10 — Block cross-origin form submissions on state-mutating endpoints."""
        if self.headers.get(_CSRF_HEADER) == _CSRF_VALUE:
            return True
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Forbidden: missing X-Requested-With header")
        return False

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
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        def p(key, default=None):
            v = qs.get(key, [default])
            return v[0] if v else default

        if path in ("", "/"):
            self.send_html(_load_html())
            return

        if path == "/api/ws_port":
            self.send_json({"ws_port": _WS_PORT})
            return

        if path == "/api/ws_messages":
            self.send_json(api_ws_messages(
                history_id=p("history_id"),
                domain=p("domain"), since=p("since"), until=p("until"),
                direction=p("direction"), opcode=p("opcode"),
                limit=int(p("limit", 200)), offset=int(p("offset", 0)),
            ))
            return

        if path == "/api/ws_domains":
            self.send_json(api_ws_domains())
            return

        if path == "/api/overview":
            self.send_json(api_overview())
        elif path == "/api/history":
            self.send_json(api_history(
                domain=p("domain"), since=p("since"), until=p("until"),
                search=p("search"),
                limit=int(p("limit", 200)), offset=int(p("offset", 0)),
                status=p("status"), method=p("method"),
                body_type=p("body_type"),
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

    def do_POST(self):
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        def p(key, default=None):
            v = qs.get(key, [default])
            return v[0] if v else default

        if path == "/api/prune":
            if not self._require_csrf():
                return
            older_than = p("older_than")
            keep_last  = p("keep_last")
            self.send_json(api_prune(
                older_than=int(older_than) if older_than else None,
                keep_last=int(keep_last)   if keep_last  else None,
            ))
        elif path.startswith("/api/replay/"):
            if not self._require_csrf():
                return
            row_id = int(path.split("/")[-1])
            self.send_json(api_replay(row_id))
        else:
            self.send_response(404)
            self.end_headers()


# ──────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────

def main():
    global DB_PATH, _DASHBOARD_PASSWORD_HASH, _WS_PORT

    parser = argparse.ArgumentParser(description="Proxy Web Dashboard")
    parser.add_argument("--version",  "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=5500)
    parser.add_argument("--db",       default=str(DB_PATH), help="Path to proxy.db")
    parser.add_argument("--password", default=None, metavar="SECRET",
                        help="Enable HTTP Basic Auth (username can be anything)")
    parser.add_argument("--no-ws",    action="store_true",
                        help="Disable WebSocket push server")
    args = parser.parse_args()

    DB_PATH = Path(args.db)
    if not DB_PATH.exists():
        print(f"[ERROR] DB not found: {DB_PATH}")
        print("        Run the proxy first, then start the dashboard.")
        sys.exit(1)

    # #11 — Store SHA-256 hash of password, never compare plaintext
    if args.password:
        _DASHBOARD_PASSWORD_HASH = hashlib.sha256(args.password.encode()).hexdigest()

    ws_note = ""
    if not args.no_ws:
        ws_port  = args.port + 1
        _WS_PORT = start_ws_server(args.host, ws_port)
        ws_note  = f"  WS    : ws://{args.host}:{ws_port}  (live push)\n"

    url       = f"http://{args.host}:{args.port}"
    auth_note = ("  Auth  : enabled (HTTP Basic Auth, SHA-256 verified)\n"
                 if _DASHBOARD_PASSWORD_HASH else "")
    print(f"""
{'='*55}
  🌐  Proxy Dashboard  v{__version__}
  Open  : {url}
  DB    : {DB_PATH.resolve()}
{ws_note}{auth_note}  Press Ctrl+C to stop.
{'='*55}
""")

    server = HTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")


if __name__ == "__main__":
    main()
