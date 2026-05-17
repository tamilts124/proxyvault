#!/usr/bin/env python3
"""
db_queries.py — shared read/write query layer for dashboard.py and viewer.py.

Every function accepts an open sqlite3.Connection as its first argument and
never opens its own connection.  This keeps the module free of global state
and lets each caller manage its own connection strategy (pool, persistent
singleton, short-lived, etc.).

Write helpers (upsert / insert) are intentionally NOT here — those live in
proxy.py which owns the write path and its own connection pool.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

# ── tiny helpers ────────────────────────────────────────────────────────────

def q(conn, sql: str, args=()):
    """Execute *sql* and return all rows as plain dicts."""
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def q1(conn, sql: str, args=()):
    """Execute *sql* and return the first row as a dict, or None."""
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None


def build_where(
    domain: str | None = None,
    since:  str | None = None,
    until:  str | None = None,
    extra_clauses: list[str] | None = None,
    extra_args:    list       | None = None,
) -> tuple[str, list]:
    """
    Build a ``WHERE …`` fragment from common filter parameters.

    Returns (where_clause_string, args_list).  The caller appends its own
    positional args after the returned list.

    Parameters
    ----------
    domain          Filter to a single domain (``domain = ?``).
    since           ISO date string ``YYYY-MM-DD``; matches ``timestamp >= ?``.
    until           ISO date string ``YYYY-MM-DD``; matches ``timestamp <= ?T23:59:59``.
    extra_clauses   Additional SQL fragments (no leading AND).
    extra_args      Positional values that correspond to ``extra_clauses``.
    """
    clauses: list[str] = list(extra_clauses or [])
    args:    list      = list(extra_args    or [])

    if domain:
        clauses.append("domain = ?")
        args.append(domain)
    if since:
        clauses.append("timestamp >= ?")
        args.append(since)
    if until:
        clauses.append("timestamp <= ?")
        args.append(until + "T23:59:59")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, args


# ── read queries ─────────────────────────────────────────────────────────────

_SEARCH_MAX_LEN = 200   # guard against runaway search terms


def query_overview(conn, db_path: Path) -> dict:
    """
    Aggregate stats used by the dashboard Overview panel and ``viewer --stats``.

    Returns a dict with keys:
      domains, stats, cookies_total, methods, statuses, timeline, db_size
    """
    domains = q(conn, """
        SELECT h.domain,
               COUNT(h.id)          AS requests,
               SUM(h.size_bytes)    AS total_bytes,
               MAX(h.timestamp)     AS last_seen,
               COUNT(DISTINCT ck.name) AS cookies
        FROM history h
        LEFT JOIN cookies ck ON ck.domain = h.domain
        GROUP BY h.domain
        ORDER BY last_seen DESC
    """)
    stats    = q1(conn, "SELECT COUNT(*) AS reqs, SUM(size_bytes) AS bytes FROM history")
    ck_count = q1(conn, "SELECT COUNT(*) AS n FROM cookies")
    methods  = q(conn, "SELECT method, COUNT(*) AS n FROM history GROUP BY method ORDER BY n DESC")
    statuses = q(conn, """
        SELECT status_code, COUNT(*) AS n
        FROM history
        GROUP BY status_code
        ORDER BY n DESC
        LIMIT 10
    """)
    timeline = q(conn, """
        SELECT strftime('%Y-%m-%dT%H:%M', timestamp) AS bucket, COUNT(*) AS n
        FROM history
        WHERE timestamp >= datetime('now', '-2 hours')
        GROUP BY bucket
        ORDER BY bucket
    """)
    db_size = db_path.stat().st_size if db_path.exists() else 0

    return {
        "domains":       domains,
        "stats":         stats,
        "cookies_total": ck_count["n"] if ck_count else 0,
        "methods":       methods,
        "statuses":      statuses,
        "timeline":      timeline,
        "db_size":       db_size,
    }


def query_history(
    conn,
    *,
    domain: str | None = None,
    since:  str | None = None,
    until:  str | None = None,
    search: str | None = None,
    limit:  int        = 200,
    offset: int        = 0,
    status: int | str | None = None,
    method: str | None = None,
    body_type: str | None = None,
) -> dict:
    """
    Return a page of history rows plus a total count.

    When *search* is provided the FTS5 virtual table is used for fast
    full-text matching across ``url``, ``req_body``, and ``res_body``.
    All other parameters are applied as additional filters.

    Returns ``{"rows": [...], "total": int}``.
    """
    # Clamp search term length
    if search and len(search) > _SEARCH_MAX_LEN:
        search = search[:_SEARCH_MAX_LEN]

    # Columns returned for list views (no body content — keeps payloads small)
    LIST_COLS = """
        id, timestamp, domain, method, status_code, url,
        content_type, size_bytes, req_body_is_binary, res_body_is_binary,
        req_body_type
    """
    # Fully-qualified version used in FTS JOIN to avoid ambiguous column errors
    # (history_fts also exposes url/req_body/res_body columns)
    FTS_COLS = """
        h.id, h.timestamp, h.domain, h.method, h.status_code, h.url,
        h.content_type, h.size_bytes, h.req_body_is_binary, h.res_body_is_binary,
        h.req_body_type
    """

    if search:
        # ── FTS5 path ────────────────────────────────────────────────────
        safe_term  = search.replace('"', '""')
        fts_clause = f"""history_fts MATCH '"{safe_term}"'"""

        extra: list[str] = []
        args:  list      = []
        if domain:    extra.append("h.domain=?");        args.append(domain)
        if since:     extra.append("h.timestamp>=?");    args.append(since)
        if until:     extra.append("h.timestamp<=?");    args.append(until + "T23:59:59")
        if status:    extra.append("h.status_code=?");   args.append(int(status))
        if method:    extra.append("h.method=?");        args.append(method.upper())
        if body_type: extra.append("h.req_body_type=?"); args.append(body_type)

        extra_where = ("AND " + " AND ".join(extra)) if extra else ""

        total = q1(conn, f"""
            SELECT COUNT(*) AS n
            FROM history_fts
            JOIN history h ON h.id = history_fts.rowid
            WHERE {fts_clause} {extra_where}
        """, args)["n"]

        rows = q(conn, f"""
            SELECT {FTS_COLS}
            FROM history_fts
            JOIN history h ON h.id = history_fts.rowid
            WHERE {fts_clause} {extra_where}
            ORDER BY h.timestamp DESC
            LIMIT ? OFFSET ?
        """, args + [limit, offset])

    else:
        # ── plain WHERE path ─────────────────────────────────────────────
        clauses: list[str] = []
        args:    list      = []
        if domain:    clauses.append("domain=?");        args.append(domain)
        if since:     clauses.append("timestamp>=?");    args.append(since)
        if until:     clauses.append("timestamp<=?");    args.append(until + "T23:59:59")
        if status:    clauses.append("status_code=?");   args.append(int(status))
        if method:    clauses.append("method=?");        args.append(method.upper())
        if body_type: clauses.append("req_body_type=?"); args.append(body_type)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        total = q1(conn, f"SELECT COUNT(*) AS n FROM history {where}", args)["n"]
        rows  = q(conn, f"""
            SELECT {LIST_COLS}
            FROM history {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, args + [limit, offset])

    return {"rows": rows, "total": total}


def query_request(conn, row_id: int) -> dict | None:
    """
    Return a single history row by primary key, with JSON header/cookie
    fields decoded into dicts.  Returns None when the row doesn't exist.
    """
    r = q1(conn, "SELECT * FROM history WHERE id=?", (row_id,))
    if not r:
        return None
    for field in ("req_headers", "req_cookies", "res_headers", "res_cookies"):
        try:
            r[field] = json.loads(r[field]) if r[field] else {}
        except Exception:
            pass
    return r


def query_cookies(conn, domain: str | None = None) -> dict:
    """
    Return all cookies, optionally filtered to a single domain.

    Returns ``{"cookies": [...]}``.
    """
    where = "WHERE domain=?" if domain else ""
    args  = (domain,) if domain else ()
    rows  = q(conn, f"SELECT * FROM cookies {where} ORDER BY domain, name", args)
    return {"cookies": rows}


def query_domains(conn) -> list[str]:
    """Return a sorted list of distinct domain names in history."""
    return [r["domain"] for r in q(conn, "SELECT DISTINCT domain FROM history ORDER BY domain")]


def query_history_since(conn, last_id: int, limit: int = 50) -> list[dict]:
    """
    Return up to *limit* history rows with ``id > last_id``, ordered oldest
    first.  Used by the WebSocket poller to push incremental updates.
    """
    return q(conn, """
        SELECT id, timestamp, domain, method, status_code, url,
               content_type, size_bytes, req_body_is_binary, res_body_is_binary
        FROM history
        WHERE id > ?
        ORDER BY id ASC
        LIMIT ?
    """, (last_id, limit))


# ── write / maintenance queries ──────────────────────────────────────────────

def exec_prune(
    conn,
    *,
    older_than: int | None = None,
    keep_last:  int | None = None,
) -> dict:
    """
    Delete history rows and VACUUM the database.

    Exactly one of *older_than* (days) or *keep_last* (row count) must be set.
    Returns ``{"removed": int, "remaining": int}``.
    """
    before = q1(conn, "SELECT COUNT(*) AS n FROM history")["n"]

    if older_than is not None:
        cutoff = (datetime.now() - timedelta(days=older_than)).isoformat(timespec="milliseconds")
        conn.execute("DELETE FROM history WHERE timestamp < ?", (cutoff,))
        conn.commit()
    elif keep_last is not None:
        conn.execute("""
            DELETE FROM history
            WHERE id NOT IN (
                SELECT id FROM history ORDER BY timestamp DESC LIMIT ?
            )
        """, (keep_last,))
        conn.commit()

    conn.execute("VACUUM")
    after = q1(conn, "SELECT COUNT(*) AS n FROM history")["n"]
    return {"removed": before - after, "remaining": after}


# ── WebSocket queries ────────────────────────────────────────────────────────────────

def query_ws_messages(
    conn,
    *,
    history_id: int | None = None,
    domain:     str | None = None,
    since:      str | None = None,
    until:      str | None = None,
    direction:  str | None = None,
    opcode:     int | None = None,
    limit:      int        = 200,
    offset:     int        = 0,
) -> dict:
    """
    Return a page of WebSocket frames, optionally filtered.

    When *history_id* is supplied only frames from that connection are returned.
    Returns ``{"rows": [...], "total": int}``.
    """
    clauses: list[str] = []
    args:    list      = []

    if history_id is not None:
        clauses.append("history_id = ?");  args.append(history_id)
    if domain:
        clauses.append("domain = ?");      args.append(domain)
    if since:
        clauses.append("timestamp >= ?");  args.append(since)
    if until:
        clauses.append("timestamp <= ?");  args.append(until + "T23:59:59")
    if direction:
        clauses.append("direction = ?");   args.append(direction.lower())
    if opcode is not None:
        clauses.append("opcode = ?");      args.append(opcode)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    total = q1(conn, f"SELECT COUNT(*) AS n FROM ws_messages {where}", args)["n"]
    rows  = q(conn, f"""
        SELECT id, history_id, timestamp, domain, url, direction,
               opcode, opcode_label, payload, is_binary, size_bytes
        FROM ws_messages {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, args + [limit, offset])

    return {"rows": rows, "total": total}


def query_ws_domains(conn) -> list[dict]:
    """
    Summary stats per domain for WebSocket traffic.

    Returns a list of dicts with keys:
      domain, connections, total_frames, client_frames, server_frames,
      total_bytes, last_seen
    """
    return q(conn, """
        SELECT
            w.domain,
            COUNT(DISTINCT w.history_id) AS connections,
            COUNT(w.id)                  AS total_frames,
            SUM(w.direction = 'client')  AS client_frames,
            SUM(w.direction = 'server')  AS server_frames,
            SUM(w.size_bytes)            AS total_bytes,
            MAX(w.timestamp)             AS last_seen
        FROM ws_messages w
        GROUP BY w.domain
        ORDER BY last_seen DESC
    """)
