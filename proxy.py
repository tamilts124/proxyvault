#!/usr/bin/env python3
"""
CLI Network Proxy - SQLite-backed storage for cookies, history, requests/responses.

Schema:
  cookies  — one row per cookie name per domain (upserted, always latest)
  history  — one row per HTTP request with full headers, body, response

Response mock rules (config.json → "mock_rules"):
  Drop fixture files in mock_responses/ and reference them from config.json.
  See mock_responses/README.md for the full field reference and examples.

  Quick example:
    "mock_rules": [
      {
        "match":  "/api/feature-flags",
        "file":   "mock_responses/feature_flags.json",
        "status": 200
      },
      {
        "match":   "regex:^https://api\\.example\\.com/v1/user",
        "file":    "mock_responses/user.json",
        "methods": ["GET"]
      }
    ]

  Rules are togglable at runtime via the web dashboard (Mocks panel) or the
  /api/mock_rules endpoints — no proxy restart required.
"""

__version__ = "2.4.0"

import asyncio
import argparse
import hashlib
import json
import re
import sys
import logging
import sqlite3
import queue
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs

try:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import http as mhttp
    from mitmproxy import websocket as mws
except ImportError:
    print("[ERROR] mitmproxy not found. Run: pip install mitmproxy")
    sys.exit(1)

import plugin_loader
from plugin_loader import PluginContext

# ──────────────────────────────────────────────
# Globals (overridable via CLI / config)
# ──────────────────────────────────────────────
DATA_DIR        = Path(__file__).parent / "proxy_data"
SAVE_PAGES      = True
DB_PATH         = DATA_DIR / "proxy.db"
INCLUDE_DOMAINS: list[str] = []
EXCLUDE_DOMAINS: list[str] = []
REDACT          = True

DEDUP_WINDOW: int = 0

REDACT_HEADERS   = {"authorization", "x-api-key", "x-auth-token", "x-secret"}
REDACT_BODY_KEYS = {"password", "passwd", "token", "secret", "api_key",
                    "apikey", "access_token", "refresh_token", "private_key"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

# ──────────────────────────────────────────────
# Mock / response-rule engine
# ──────────────────────────────────────────────

class _CompiledRule:
    """A single compiled mock rule ready for fast matching."""

    __slots__ = ("raw_match", "is_regex", "_pattern", "file_path",
                 "status", "headers", "methods", "body", "enabled")

    def __init__(self, rule: dict, base_dir: Path):
        raw = rule.get("match", "")
        if raw.startswith("regex:"):
            self.is_regex = True
            self._pattern = re.compile(raw[6:])
        else:
            self.is_regex = False
            self._pattern = raw          # plain substring
        self.raw_match = raw

        fp = base_dir / rule["file"]
        if not fp.exists():
            raise FileNotFoundError(
                f"Mock rule references missing file: {fp}  (rule match={raw!r})"
            )
        self.file_path = fp
        self.body      = fp.read_bytes()

        self.status  = int(rule.get("status", 200))
        self.headers = rule.get("headers", {})
        raw_methods  = rule.get("methods", [])
        self.methods = [m.upper() for m in raw_methods] if raw_methods else []
        # enabled=True by default; togglable at runtime via dashboard or API
        self.enabled = bool(rule.get("enabled", True))

    def matches(self, url: str, method: str) -> bool:
        if not self.enabled:
            return False
        if self.methods and method.upper() not in self.methods:
            return False
        if self.is_regex:
            return bool(self._pattern.search(url))
        return self._pattern in url      # type: ignore[operator]

    def as_dict(self, index: int) -> dict:
        """Serialisable summary for the dashboard API."""
        return {
            "index":    index,
            "match":    self.raw_match,
            "file":     self.file_path.name,
            "status":   self.status,
            "methods":  self.methods or ["*"],
            "enabled":  self.enabled,
        }

    def __repr__(self):
        kind    = "regex" if self.is_regex else "substr"
        state   = "" if self.enabled else " [disabled]"
        return f"<Rule {kind}={self.raw_match!r} → {self.file_path.name} {self.status}{state}>"


class MockRules:
    """
    Loads, applies, and runtime-toggles response-mock rules.

    Rules are loaded from ``config.json → mock_rules`` at startup.
    Individual rules can be enabled/disabled at runtime (thread-safe) through
    ``set_enabled(index, enabled)`` — no proxy restart required.

    See ``mock_responses/README.md`` for the full field reference.
    """

    def __init__(self, rules_cfg: list[dict], base_dir: Path):
        self._rules: list[_CompiledRule] = []
        self._lock  = threading.Lock()   # guards .enabled mutations
        errors: list[str] = []
        for i, r in enumerate(rules_cfg):
            try:
                self._rules.append(_CompiledRule(r, base_dir))
            except Exception as e:
                errors.append(f"  rule[{i}]: {e}")
        if errors:
            log.error("[MOCK] Failed to compile some rules:\n" + "\n".join(errors))
        log.info(f"[MOCK] {len(self._rules)} rule(s) loaded")
        for rule in self._rules:
            log.info(f"[MOCK]   {rule}")

    def __bool__(self):
        return bool(self._rules)

    def __len__(self):
        return len(self._rules)

    # ── matching ──────────────────────────────────────────────────────────

    def match(self, url: str, method: str) -> "_CompiledRule | None":
        """Return the first enabled rule that matches *url* + *method*, or None."""
        with self._lock:
            for rule in self._rules:
                if rule.matches(url, method):
                    return rule
        return None

    # ── runtime toggle (dashboard / API) ──────────────────────────────────

    def set_enabled(self, index: int, enabled: bool) -> dict | None:
        """
        Enable or disable rule at *index*.  Returns the updated rule summary
        dict, or None if *index* is out of range.
        """
        with self._lock:
            if index < 0 or index >= len(self._rules):
                return None
            self._rules[index].enabled = enabled
            log.info(f"[MOCK] rule[{index}] {'enabled' if enabled else 'disabled'}: "
                     f"{self._rules[index].raw_match!r}")
            return self._rules[index].as_dict(index)

    def toggle(self, index: int) -> dict | None:
        """Toggle the enabled state of rule at *index*."""
        with self._lock:
            if index < 0 or index >= len(self._rules):
                return None
            self._rules[index].enabled = not self._rules[index].enabled
            rule = self._rules[index]
            log.info(f"[MOCK] rule[{index}] toggled → "
                     f"{'enabled' if rule.enabled else 'disabled'}: {rule.raw_match!r}")
            return rule.as_dict(index)

    def list_rules(self) -> list[dict]:
        """Return all rules as serialisable dicts (safe to JSON-encode)."""
        with self._lock:
            return [r.as_dict(i) for i, r in enumerate(self._rules)]

    # ── response injection ────────────────────────────────────────────────

    @staticmethod
    def apply(flow: mhttp.HTTPFlow, rule: "_CompiledRule"):
        """Replace the live response on *flow* with the rule's mock body."""
        extra_headers = dict(rule.headers)
        if "content-type" not in {k.lower() for k in extra_headers}:
            ext = rule.file_path.suffix.lower()
            ct_map = {
                ".json": "application/json",
                ".html": "text/html",
                ".xml":  "application/xml",
                ".txt":  "text/plain",
                ".js":   "application/javascript",
                ".css":  "text/css",
            }
            extra_headers["content-type"] = ct_map.get(ext, "application/octet-stream")

        flow.response = mhttp.Response.make(
            status_code = rule.status,
            content     = rule.body,
            headers     = {"content-length": str(len(rule.body)), **extra_headers},
        )
        log.info(f"[MOCK] {flow.request.method} {flow.request.pretty_url[:80]}"
                 f" → {rule.file_path.name} ({rule.status})")


# Singleton — populated in main() after config is loaded
_mock_rules: MockRules | None = None


# ── public helpers used by dashboard.py ───────────────────────────────────────

def mock_list() -> list[dict]:
    """Return all mock rules as JSON-serialisable dicts. Empty list if none."""
    return _mock_rules.list_rules() if _mock_rules else []


def mock_toggle(index: int) -> dict | None:
    """Toggle rule at *index*. Returns updated rule dict or None if OOB."""
    return _mock_rules.toggle(index) if _mock_rules else None


def mock_set_enabled(index: int, enabled: bool) -> dict | None:
    """Explicitly enable/disable rule at *index*."""
    return _mock_rules.set_enabled(index, enabled) if _mock_rules else None


# ──────────────────────────────────────────────
# DB connection pool
# ──────────────────────────────────────────────
_pool: queue.Queue = queue.Queue()
_POOL_SIZE = 5


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")
    return conn


class _PooledConn:
    def __enter__(self) -> sqlite3.Connection:
        try:
            self._conn = _pool.get_nowait()
        except queue.Empty:
            self._conn = _make_conn()
        return self._conn

    def __exit__(self, *_):
        try:
            _pool.put_nowait(self._conn)
        except queue.Full:
            self._conn.close()


def get_conn() -> _PooledConn:
    return _PooledConn()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    if DB_PATH.exists():
        try:
            check_conn = sqlite3.connect(str(DB_PATH))
            result = check_conn.execute("PRAGMA integrity_check").fetchone()
            check_conn.close()
            if result and result[0] != "ok":
                log.error(
                    f"[DB] INTEGRITY CHECK FAILED: {result[0]}\n"
                    "     The database may be corrupted. Options:\n"
                    "       • Delete proxy.db to start fresh\n"
                    "       • Run: sqlite3 proxy.db '.recover' > recovered.sql"
                )
                sys.exit(1)
        except sqlite3.DatabaseError as e:
            log.error(f"[DB] Cannot open database: {e}\n"
                      "     The file may be corrupted. Delete proxy.db to start fresh.")
            sys.exit(1)

    for _ in range(_POOL_SIZE):
        _pool.put(_make_conn())

    # ── Schema migrations (safe to run on every startup) ──────────────────
    # Adds columns that were introduced after the initial schema.
    # ALTER TABLE ignores columns that already exist via the try/except.
    _MIGRATIONS = [
        ("req_body_type",      "ALTER TABLE history ADD COLUMN req_body_type TEXT"),
        ("req_body_is_binary", "ALTER TABLE history ADD COLUMN req_body_is_binary INTEGER DEFAULT 0"),
        ("res_body_is_binary", "ALTER TABLE history ADD COLUMN res_body_is_binary INTEGER DEFAULT 0"),
    ]
    with get_conn() as conn:
        existing_cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(history)").fetchall()
        }
        for col_name, sql in _MIGRATIONS:
            if col_name not in existing_cols:
                try:
                    conn.execute(sql)
                    conn.commit()
                    log.info(f"[DB] migration applied: added column '{col_name}' to history")
                except sqlite3.OperationalError as exc:
                    log.warning(f"[DB] migration skipped for '{col_name}': {exc}")

    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cookies (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT    NOT NULL,
                name         TEXT    NOT NULL,
                value        TEXT,
                path         TEXT,
                expires      TEXT,
                http_only    INTEGER DEFAULT 0,
                secure       INTEGER DEFAULT 0,
                same_site    TEXT,
                source       TEXT    DEFAULT 'server',
                updated_at   TEXT    NOT NULL,
                UNIQUE(domain, name) ON CONFLICT REPLACE
            );
            CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies(domain);

            CREATE TABLE IF NOT EXISTS history (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp            TEXT    NOT NULL,
                domain               TEXT    NOT NULL,
                url                  TEXT    NOT NULL,
                method               TEXT    NOT NULL,
                req_headers          TEXT,
                req_cookies          TEXT,
                req_body             TEXT,
                req_body_is_binary   INTEGER DEFAULT 0,
                req_body_type        TEXT,
                status_code          INTEGER,
                res_headers          TEXT,
                res_cookies          TEXT,
                res_body             TEXT,
                res_body_is_binary   INTEGER DEFAULT 0,
                content_type         TEXT,
                size_bytes           INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_history_domain    ON history(domain);
            CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_history_url       ON history(url);
            CREATE INDEX IF NOT EXISTS idx_history_method    ON history(method);
            CREATE INDEX IF NOT EXISTS idx_history_status    ON history(status_code);

            CREATE VIRTUAL TABLE IF NOT EXISTS history_fts
                USING fts5(url, req_body, res_body,
                           content='history', content_rowid='id');

            CREATE TRIGGER IF NOT EXISTS history_ai
                AFTER INSERT ON history BEGIN
                    INSERT INTO history_fts(rowid, url, req_body, res_body)
                    VALUES (new.id, new.url, new.req_body, new.res_body);
                END;
            CREATE TRIGGER IF NOT EXISTS history_ad
                AFTER DELETE ON history BEGIN
                    INSERT INTO history_fts(history_fts, rowid, url, req_body, res_body)
                    VALUES ('delete', old.id, old.url, old.req_body, old.res_body);
                END;
            CREATE TRIGGER IF NOT EXISTS history_au
                AFTER UPDATE ON history BEGIN
                    INSERT INTO history_fts(history_fts, rowid, url, req_body, res_body)
                    VALUES ('delete', old.id, old.url, old.req_body, old.res_body);
                    INSERT INTO history_fts(rowid, url, req_body, res_body)
                    VALUES (new.id, new.url, new.req_body, new.res_body);
                END;

            CREATE TABLE IF NOT EXISTS ws_messages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                history_id     INTEGER REFERENCES history(id) ON DELETE CASCADE,
                timestamp      TEXT    NOT NULL,
                domain         TEXT    NOT NULL,
                url            TEXT    NOT NULL,
                direction      TEXT    NOT NULL CHECK(direction IN ('client','server')),
                opcode         INTEGER NOT NULL,
                opcode_label   TEXT    NOT NULL,
                payload        TEXT,
                is_binary      INTEGER DEFAULT 0,
                size_bytes     INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ws_history_id ON ws_messages(history_id);
            CREATE INDEX IF NOT EXISTS idx_ws_domain     ON ws_messages(domain);
            CREATE INDEX IF NOT EXISTS idx_ws_timestamp  ON ws_messages(timestamp);

            CREATE TABLE IF NOT EXISTS errors (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                hook       TEXT,
                url        TEXT,
                error      TEXT
            );
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
    result = {}
    for k, v in headers.items():
        k = k.lower()
        if k in result:
            result[k] = [result[k], v] if not isinstance(result[k], list) else result[k] + [v]
        else:
            result[k] = v
    return result

def redact_headers(headers: dict) -> dict:
    if not REDACT:
        return headers
    return {k: ("***REDACTED***" if k.lower() in REDACT_HEADERS else v)
            for k, v in headers.items()}

def redact_body(body: str, content_type: str) -> str:
    if not REDACT or not body:
        return body
    ct = content_type.lower()
    if "application/json" in ct:
        try:
            return json.dumps(_redact_dict(json.loads(body)), ensure_ascii=False)
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in ct:
        parts = []
        for pair in body.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                parts.append(f"{k}=***REDACTED***" if k.lower() in REDACT_BODY_KEYS else pair)
            else:
                parts.append(pair)
        return "&".join(parts)
    return body

def _redact_dict(obj):
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if k.lower() in REDACT_BODY_KEYS else _redact_dict(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_dict(i) for i in obj]
    return obj

def parse_set_cookie(header_val: str) -> dict:
    parts  = [p.strip() for p in header_val.split(";")]
    cookie = {"name": "", "value": "", "path": None, "expires": None,
              "http_only": 0, "secure": 0, "same_site": None}
    if parts and "=" in parts[0]:
        k, _, v         = parts[0].partition("=")
        cookie["name"]  = k.strip()
        cookie["value"] = v.strip()
    for attr in parts[1:]:
        al = attr.lower()
        if al == "httponly":              cookie["http_only"] = 1
        elif al == "secure":              cookie["secure"]    = 1
        elif al.startswith("path="):      cookie["path"]      = attr[5:]
        elif al.startswith("expires="):   cookie["expires"]   = attr[8:]
        elif al.startswith("samesite="): cookie["same_site"] = attr[9:]
    return cookie

def is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample   = data[:2048]
    non_text = sum(1 for b in sample if b < 9 or (14 <= b < 32) or b > 126)
    return (non_text / len(sample)) > 0.30

def body_text(data: bytes, content_type: str) -> tuple[str | None, bool]:
    if not data:
        return None, False
    if is_binary(data):
        return None, True
    try:
        enc = "utf-8"
        if "charset=" in content_type:
            enc = content_type.split("charset=")[-1].split(";")[0].strip()
        return data.decode(enc, errors="replace"), False
    except Exception:
        return data.decode("utf-8", errors="replace"), False

def decode_request_body(data: bytes, content_type: str) -> tuple[str | None, bool, str]:
    if not data:
        return None, False, "text"
    if is_binary(data):
        return None, True, "binary"
    ct  = content_type.lower()
    raw, _ = body_text(data, content_type)
    if "application/json" in ct:
        try:
            return json.dumps(json.loads(raw), indent=2, ensure_ascii=False), False, "json"
        except Exception:
            return raw, False, "text"
    elif "application/x-www-form-urlencoded" in ct:
        try:
            pairs  = parse_qs(raw, keep_blank_values=True)
            pretty = json.dumps({k: v[0] if len(v) == 1 else v
                                 for k, v in pairs.items()}, indent=2, ensure_ascii=False)
            return pretty, False, "form"
        except Exception:
            return raw, False, "text"
    elif "multipart/form-data" in ct:
        return f"[multipart/form-data — {len(data)} bytes]", False, "multipart"
    return raw, False, "text"

def domain_allowed(domain: str) -> bool:
    if INCLUDE_DOMAINS and not any(domain.endswith(d) for d in INCLUDE_DOMAINS):
        return False
    if EXCLUDE_DOMAINS and any(domain.endswith(d) for d in EXCLUDE_DOMAINS):
        return False
    return True

# ──────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────
_dedup_cache: dict[str, str] = {}
_dedup_lock = threading.Lock()

def _is_duplicate(domain: str, url: str, method: str, status: int) -> bool:
    if DEDUP_WINDOW <= 0:
        return False
    key = f"{domain}|{url}|{method}|{status}"
    now = datetime.now()
    with _dedup_lock:
        last = _dedup_cache.get(key)
        if last:
            try:
                if (now - datetime.fromisoformat(last)).total_seconds() < DEDUP_WINDOW:
                    return True
            except Exception:
                pass
        _dedup_cache[key] = now.isoformat(timespec="milliseconds")
    return False

def _dedup_cleanup_thread():
    while True:
        interval = max(60, DEDUP_WINDOW * 2) if DEDUP_WINDOW > 0 else 60
        threading.Event().wait(interval)
        if DEDUP_WINDOW <= 0:
            continue
        cutoff = datetime.now()
        stale: list[str] = []
        with _dedup_lock:
            for key, ts in list(_dedup_cache.items()):
                try:
                    if (cutoff - datetime.fromisoformat(ts)).total_seconds() >= DEDUP_WINDOW:
                        stale.append(key)
                except Exception:
                    stale.append(key)
            for key in stale:
                del _dedup_cache[key]
        if stale:
            log.debug(f"[DEDUP] pruned {len(stale)} stale cache entries")

# ──────────────────────────────────────────────
# DB write functions
# ──────────────────────────────────────────────

def upsert_cookie(domain: str, cookie: dict, source: str = "server"):
    if not cookie.get("name"):
        return
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO cookies
                (domain, name, value, path, expires, http_only, secure, same_site, source, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(domain, name) DO UPDATE SET
                value=excluded.value, path=excluded.path, expires=excluded.expires,
                http_only=excluded.http_only, secure=excluded.secure,
                same_site=excluded.same_site, source=excluded.source,
                updated_at=excluded.updated_at
        """, (domain, cookie["name"], cookie.get("value"), cookie.get("path"),
              cookie.get("expires"), cookie.get("http_only", 0), cookie.get("secure", 0),
              cookie.get("same_site"), source, now_iso()))
        conn.commit()

def insert_history(
    domain, url, method,
    req_headers, req_cookies, req_body, req_body_is_binary, req_body_type,
    status_code,
    res_headers, res_cookies, res_body, res_body_is_binary,
    content_type, size_bytes,
):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO history (
                timestamp, domain, url, method,
                req_headers, req_cookies, req_body, req_body_is_binary, req_body_type,
                status_code, res_headers, res_cookies, res_body, res_body_is_binary,
                content_type, size_bytes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (now_iso(), domain, url, method,
              json.dumps(req_headers, ensure_ascii=False),
              json.dumps(req_cookies, ensure_ascii=False),
              req_body, 1 if req_body_is_binary else 0, req_body_type,
              status_code,
              json.dumps(res_headers, ensure_ascii=False),
              json.dumps(res_cookies, ensure_ascii=False),
              res_body, 1 if res_body_is_binary else 0,
              content_type, size_bytes))
        conn.commit()
    log.info(f"[DB] {method} {status_code} {url[:80]}")

def _log_error_to_db(hook: str, url: str, error: str):
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO errors (timestamp, hook, url, error) VALUES (?,?,?,?)",
                (now_iso(), hook, url, error))
            conn.commit()
    except Exception:
        pass


# Opcode int → human label (RFC 6455)
_WS_OPCODES: dict[int, str] = {
    0: "continuation", 1: "text", 2: "binary",
    8: "close", 9: "ping", 10: "pong",
}

# history_id cache: flow id (Python object id) → history row id
# populated by websocket_start so websocket_message can foreign-key into history
_ws_flow_to_history: dict[int, int | None] = {}
_ws_flow_lock = threading.Lock()


def _resolve_ws_opcode(msg) -> tuple[int, str]:
    """Return (int_opcode, label) from a mitmproxy WebSocketMessage."""
    raw = msg.type
    # mitmproxy >= 9 exposes an Opcode enum; older versions use a plain int
    opcode = int(raw) if not isinstance(raw, int) else raw
    label  = _WS_OPCODES.get(opcode, f"opcode-{opcode}")
    return opcode, label


def insert_ws_message(
    history_id: int | None,
    domain: str,
    url: str,
    direction: str,
    opcode: int,
    opcode_label: str,
    payload: str | None,
    is_binary: bool,
    size_bytes: int,
) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO ws_messages
                (history_id, timestamp, domain, url, direction,
                 opcode, opcode_label, payload, is_binary, size_bytes)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (history_id, now_iso(), domain, url, direction,
               opcode, opcode_label,
               payload, 1 if is_binary else 0, size_bytes))
        conn.commit()
    log.debug(f"[WS] {direction} opcode={opcode_label} {len(payload or '')}B  {url[:60]}")

# ──────────────────────────────────────────────
# Addon
# ──────────────────────────────────────────────

class ProxyAddon:

    def request(self, flow: mhttp.HTTPFlow):
        try:
            domain = sanitize_domain(flow.request.pretty_url)
            if not domain_allowed(domain):
                return
            raw = flow.request.headers.get("cookie", "")
            if raw:
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        upsert_cookie(domain, {"name": k.strip(), "value": v.strip()},
                                      source="browser")

            # ── Plugin on_request hooks ────────────────────────────────
            loader = plugin_loader.get()
            if loader:
                req_body_bytes = flow.request.content or b""
                req_ct         = flow.request.headers.get("content-type", "")
                req_body_text, _, _ = decode_request_body(req_body_bytes, req_ct)
                ctx = PluginContext(
                    url         = flow.request.pretty_url,
                    domain      = domain,
                    method      = flow.request.method,
                    req_headers = headers_to_dict(flow.request.headers),
                    req_body    = req_body_text,
                    flow        = flow,
                )
                if not loader.run_request_hooks(ctx):
                    # Plugin short-circuited — mark flow so response hook skips it
                    flow.metadata["plugin_skip"] = True

        except Exception as e:
            log.error(f"[request hook] {e}", exc_info=True)

    # ── WebSocket lifecycle ────────────────────────────────────────────────

    def websocket_start(self, flow: mhttp.HTTPFlow):
        """
        Called once when the HTTP Upgrade handshake completes.
        We record a stub history row for the upgrade request itself so that
        ws_messages can reference it via history_id.
        """
        try:
            url    = flow.request.pretty_url
            domain = sanitize_domain(url)
            if not domain_allowed(domain):
                with _ws_flow_lock:
                    _ws_flow_to_history[id(flow)] = None
                return

            req_headers = redact_headers(headers_to_dict(flow.request.headers))
            req_cookies: dict = {}
            raw = flow.request.headers.get("cookie", "")
            if raw:
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        req_cookies[k.strip()] = v.strip()

            # The upgrade response status (101) is on flow.response when available
            status = 101
            if flow.response:
                status = flow.response.status_code
                res_headers = redact_headers(headers_to_dict(flow.response.headers))
            else:
                res_headers = {}

            insert_history(
                domain=domain, url=url, method="WEBSOCKET",
                req_headers=req_headers, req_cookies=req_cookies,
                req_body=None, req_body_is_binary=False, req_body_type="websocket",
                status_code=status,
                res_headers=res_headers, res_cookies={},
                res_body=None, res_body_is_binary=False,
                content_type="application/websocket", size_bytes=0,
            )

            # Retrieve the id of the row we just inserted
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM history WHERE url=? AND method='WEBSOCKET' "
                    "ORDER BY id DESC LIMIT 1", (url,)
                ).fetchone()
            history_id = row["id"] if row else None

            with _ws_flow_lock:
                _ws_flow_to_history[id(flow)] = history_id

            log.info(f"[WS] connection opened  {url[:80]}  (history_id={history_id})")

        except Exception as e:
            log.error(f"[websocket_start hook] {e}", exc_info=True)
            with _ws_flow_lock:
                _ws_flow_to_history[id(flow)] = None

    def websocket_message(self, flow: mhttp.HTTPFlow):
        """
        Called for every frame.  flow.websocket.messages[-1] is the new frame.
        """
        try:
            url    = flow.request.pretty_url
            domain = sanitize_domain(url)
            if not domain_allowed(domain):
                return

            msg       = flow.websocket.messages[-1]
            opcode, label = _resolve_ws_opcode(msg)

            # Skip ping/pong control frames to avoid noise (configurable later)
            if opcode in (9, 10):
                return

            direction = "client" if msg.from_client else "server"
            content   = msg.content  # bytes
            size      = len(content)

            if opcode == 2 or is_binary(content):   # binary frame
                payload   = None
                binary    = True
            else:
                payload = content.decode("utf-8", errors="replace")
                binary  = False

            with _ws_flow_lock:
                history_id = _ws_flow_to_history.get(id(flow))

            insert_ws_message(
                history_id=history_id,
                domain=domain,
                url=url,
                direction=direction,
                opcode=opcode,
                opcode_label=label,
                payload=payload,
                is_binary=binary,
                size_bytes=size,
            )

        except Exception as e:
            log.error(f"[websocket_message hook] {e}", exc_info=True)

    def websocket_end(self, flow: mhttp.HTTPFlow):
        """Called when the WebSocket connection closes. Cleans up the flow cache."""
        try:
            url = flow.request.pretty_url
            log.info(f"[WS] connection closed  {url[:80]}")
        except Exception:
            pass
        finally:
            with _ws_flow_lock:
                _ws_flow_to_history.pop(id(flow), None)

    def response(self, flow: mhttp.HTTPFlow):
        try:
            url    = flow.request.pretty_url
            domain = sanitize_domain(url)
            method = flow.request.method

            if not domain_allowed(domain):
                return

            # ── Mock rules — mutate the flow before recording ──────────
            if _mock_rules:
                rule = _mock_rules.match(url, method)
                if rule:
                    MockRules.apply(flow, rule)
                    # fall through so the mocked response is still stored in DB

            # ── Request side ───────────────────────────────────────────
            req_headers    = redact_headers(headers_to_dict(flow.request.headers))
            req_cookies: dict = {}
            raw = flow.request.headers.get("cookie", "")
            if raw:
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        req_cookies[k.strip()] = v.strip()
            req_body_bytes = flow.request.content or b""
            req_ct         = flow.request.headers.get("content-type", "")
            req_body, req_bin, req_body_type = decode_request_body(req_body_bytes, req_ct)
            if req_body and not req_bin:
                req_body = redact_body(req_body, req_ct)

            # ── Response side ──────────────────────────────────────────
            res_headers  = redact_headers(headers_to_dict(flow.response.headers))
            content_type = flow.response.headers.get("content-type", "")
            size_bytes   = len(flow.response.content) if flow.response.content else 0
            status_code  = flow.response.status_code

            if _is_duplicate(domain, url, method, status_code):
                log.debug(f"[DEDUP] skipped {method} {status_code} {url[:80]}")
                return

            # ── Short-circuit if a request-side plugin set the skip flag ───────
            if flow.metadata.get("plugin_skip"):
                log.debug(f"[PLUGIN] response skipped (plugin_skip)  {url[:60]}")
                return

            res_cookies: dict = {}
            for hval in flow.response.headers.get_all("set-cookie"):
                c = parse_set_cookie(hval)
                if c["name"]:
                    res_cookies[c["name"]] = c["value"]
                    upsert_cookie(domain, c, source="server")

            res_body_bytes = flow.response.content or b""
            if SAVE_PAGES and "text/html" in content_type:
                res_body, res_bin = body_text(res_body_bytes, content_type)
            else:
                res_body, res_bin = None, is_binary(res_body_bytes)

            # ── Plugin on_response hooks ──────────────────────────────
            loader = plugin_loader.get()
            if loader:
                ctx = PluginContext(
                    url         = url,
                    domain      = domain,
                    method      = method,
                    req_headers = req_headers,
                    req_body    = req_body,
                    status_code = status_code,
                    res_headers = res_headers,
                    res_body    = res_body,
                    flow        = flow,
                )
                loader.run_response_hooks(ctx)

            insert_history(
                domain=domain, url=url, method=method,
                req_headers=req_headers, req_cookies=req_cookies,
                req_body=req_body, req_body_is_binary=req_bin, req_body_type=req_body_type,
                status_code=status_code,
                res_headers=res_headers, res_cookies=res_cookies,
                res_body=res_body, res_body_is_binary=res_bin,
                content_type=content_type, size_bytes=size_bytes,
            )

        except Exception as e:
            log.error(f"[response hook] {e}", exc_info=True)
            try:
                _log_error_to_db(
                    hook="response",
                    url=flow.request.pretty_url if flow and flow.request else "unknown",
                    error=str(e),
                )
            except Exception:
                pass

# ──────────────────────────────────────────────
# Config loader
# ──────────────────────────────────────────────

def load_config(config_path: str | None) -> dict:
    if config_path:
        p = Path(config_path)
    else:
        p = Path(__file__).parent / "config.json"
    if p.exists():
        try:
            cfg = json.loads(p.read_text(encoding="utf-8"))
            log.info(f"[CFG] loaded → {p}")
            return cfg
        except Exception as e:
            log.warning(f"[CFG] failed to load {p}: {e}")
    return {}

# ──────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────

async def run(host: str, port: int):
    opts   = Options(listen_host=host, listen_port=port, ssl_insecure=True)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(ProxyAddon())

    filter_info = ""
    if INCLUDE_DOMAINS: filter_info += f"\n  Include: {', '.join(INCLUDE_DOMAINS)}"
    if EXCLUDE_DOMAINS: filter_info += f"\n  Exclude: {', '.join(EXCLUDE_DOMAINS)}"
    dedup_info = f"\n  Dedup  : {DEDUP_WINDOW}s window" if DEDUP_WINDOW > 0 else ""
    mock_info  = f"\n  Mocks  : {len(_mock_rules)} rule(s) active" if _mock_rules else ""

    print(f"""
{'='*55}
  🌐  Network Proxy  v{__version__}  (SQLite backend)
  Listen : {host}:{port}
  DB     : {DB_PATH.resolve()}
  Pages  : {'yes' if SAVE_PAGES else 'no'}
  Redact : {'yes' if REDACT else 'no'}{filter_info}{dedup_info}{mock_info}
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
    global DATA_DIR, DB_PATH, SAVE_PAGES, INCLUDE_DOMAINS, EXCLUDE_DOMAINS
    global REDACT, DEDUP_WINDOW, _mock_rules

    parser = argparse.ArgumentParser(description="CLI Network Proxy (SQLite)")
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--host",             default=None)
    parser.add_argument("--port",             type=int, default=None)
    parser.add_argument("--no-save-pages",    action="store_true")
    parser.add_argument("--data-dir",         default=None)
    parser.add_argument("--config",           default=None, help="Path to config.json")
    parser.add_argument("--include-domains",  default=None)
    parser.add_argument("--exclude-domains",  default=None)
    parser.add_argument("--no-redact",        action="store_true")
    parser.add_argument("--dedup",            type=int, default=None, metavar="SECONDS")
    parser.add_argument("--hooks-dir",        default=None, metavar="DIR",
                        help="Directory of plugin *.py files (hot-reloaded)")
    parser.add_argument("--verbose", "-v",    action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)

    host       = args.host     or cfg.get("host",      "127.0.0.1")
    port       = args.port     or cfg.get("port",      8080)
    data_dir   = args.data_dir or cfg.get("data_dir",  str(DATA_DIR))
    save_pages = not args.no_save_pages and cfg.get("save_pages", True)
    redact     = not args.no_redact     and cfg.get("redact",     True)
    dedup      = args.dedup if args.dedup is not None else cfg.get("dedup_window", 0)

    inc = args.include_domains or cfg.get("include_domains", "")
    exc = args.exclude_domains or cfg.get("exclude_domains", "")
    include_domains = [d.strip() for d in inc.split(",") if d.strip()] if inc else []
    exclude_domains = [d.strip() for d in exc.split(",") if d.strip()] if exc else []

    DATA_DIR        = Path(data_dir)
    DB_PATH         = DATA_DIR / "proxy.db"
    SAVE_PAGES      = save_pages
    INCLUDE_DOMAINS = include_domains
    EXCLUDE_DOMAINS = exclude_domains
    REDACT          = redact
    DEDUP_WINDOW    = max(0, int(dedup))
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.verbose or cfg.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)

    rules_cfg = cfg.get("mock_rules", [])
    if rules_cfg:
        config_path = Path(args.config) if args.config else Path(__file__).parent / "config.json"
        base_dir    = config_path.parent if config_path.exists() else Path(__file__).parent
        _mock_rules = MockRules(rules_cfg, base_dir=base_dir)
    else:
        _mock_rules = None

    init_db()

    # ── Plugin system ───────────────────────────────────────────────────
    hooks_dir = args.hooks_dir or cfg.get("hooks_dir", str(Path(__file__).parent / "hooks"))
    plugin_loader.init(hooks_dir)

    t = threading.Thread(target=_dedup_cleanup_thread, daemon=True, name="dedup-cleanup")
    t.start()

    asyncio.run(run(host, port))


if __name__ == "__main__":
    main()
