"""
hooks/my_plugin.py — starter plugin for network-proxy.

Demonstrates every major PluginContext capability:
  • Request-side inspection  (on_request)
  • Response-side inspection (on_response)
  • ctx.meta  — passing data between the two hooks for the same flow
  • Selective DB skip        — return False from on_request to suppress recording
  • Pattern alerting         — flag auth leaks, 4xx/5xx errors, large payloads
  • Rotating file logger     — separate log file with timestamps

Tune the CONFIG block below, then save the file — the proxy hot-reloads it
within ~1 second with no restart required.
"""

import json
import logging
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# CONFIG  — edit these to match your needs
# ─────────────────────────────────────────────────────────────

# Domains to silently skip (no DB record, no log line).
# Supports suffix matching, e.g. "example.com" also skips "api.example.com".
SKIP_DOMAINS: list[str] = [
    "google-analytics.com",
    "doubleclick.net",
    "googletagmanager.com",
    "hotjar.com",
    "sentry.io",
]

# URL substrings whose requests are skipped regardless of domain.
SKIP_URL_PATTERNS: list[str] = [
    "/favicon.ico",
    "/robots.txt",
    "/_next/static/",   # Next.js static assets
]

# Regex patterns to flag in request headers, body, or URL.
# A match prints a WARNING and records a note in ctx.meta.
ALERT_PATTERNS: dict[str, str] = {
    "Bearer token in URL": r"[?&](?:token|access_token|api_key)=[A-Za-z0-9._\-]{16,}",
    "Private key material": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "AWS key":              r"AKIA[0-9A-Z]{16}",
}

# Response status codes to highlight as warnings.
ALERT_STATUS_CODES: set[int] = {400, 401, 403, 404, 429, 500, 502, 503, 504}

# Response bodies larger than this (bytes) get a warning.
LARGE_RESPONSE_BYTES: int = 512 * 1024   # 512 KB

# Write a dedicated rotating log file alongside this plugin.
# Set to None to disable file logging (proxy's own log still works).
LOG_FILE: str | None = str(Path(__file__).parent.parent / "proxy_data" / "my_plugin.log")
LOG_MAX_BYTES: int   = 5 * 1024 * 1024   # 5 MB per file
LOG_BACKUP_COUNT: int = 3

# ─────────────────────────────────────────────────────────────
# Logger setup  (one-time on load / hot-reload)
# ─────────────────────────────────────────────────────────────

log = logging.getLogger("plugin.my_plugin")
log.setLevel(logging.DEBUG)

if LOG_FILE and not any(isinstance(h, RotatingFileHandler) for h in log.handlers):
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    log.addHandler(_fh)

# Pre-compile alert patterns once at load time.
_COMPILED_ALERTS: list[tuple[str, re.Pattern]] = [
    (name, re.compile(pattern)) for name, pattern in ALERT_PATTERNS.items()
]

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _should_skip(url: str, domain: str) -> bool:
    """Return True if this request should be dropped from DB recording."""
    if any(domain == d or domain.endswith("." + d) for d in SKIP_DOMAINS):
        return True
    if any(pat in url for pat in SKIP_URL_PATTERNS):
        return True
    return False


def _scan_alerts(label: str, text: str | None, url: str) -> list[str]:
    """
    Run all ALERT_PATTERNS against *text*.
    Returns a list of triggered alert names (empty = clean).
    """
    if not text:
        return []
    hits: list[str] = []
    for name, pattern in _COMPILED_ALERTS:
        if pattern.search(text):
            log.warning(f"[ALERT] {name}  ({label})  {url[:80]}")
            hits.append(name)
    return hits


def _short(url: str, max_len: int = 90) -> str:
    return url if len(url) <= max_len else url[:max_len] + "…"

# ─────────────────────────────────────────────────────────────
# Plugin hooks
# ─────────────────────────────────────────────────────────────

def on_request(ctx) -> bool | None:
    """
    Called for every intercepted request before the DB record is written.

    Return False  → skip this flow entirely (no DB row, no on_response call).
    Return None   → continue normally.
    """
    # ── 1. Domain / URL filtering ──────────────────────────────────────────
    if _should_skip(ctx.url, ctx.domain):
        log.debug(f"[SKIP]  {ctx.method} {_short(ctx.url)}")
        return False   # suppress DB recording for noise/tracker traffic

    # ── 2. Log the outgoing request ───────────────────────────────────────
    ct = ctx.req_headers.get("content-type", "")
    log.info(f"[REQ]  {ctx.method:6s}  {_short(ctx.url)}  ct={ct or '-'}")

    # ── 3. Scan request surface for sensitive data leaks ──────────────────
    alert_hits = (
        _scan_alerts("url",     ctx.url,      ctx.url) +
        _scan_alerts("body",    ctx.req_body, ctx.url) +
        _scan_alerts("headers",
                     json.dumps(ctx.req_headers, ensure_ascii=False),
                     ctx.url)
    )

    # ── 4. Stash data in ctx.meta for on_response to pick up ──────────────
    ctx.meta["req_time"]    = datetime.now().isoformat(timespec="milliseconds")
    ctx.meta["alert_hits"]  = alert_hits
    ctx.meta["method"]      = ctx.method

    # Continue normally — proxy forwards the request and records it.
    return None


def on_response(ctx) -> None:
    """
    Called after the server responds.

    ctx.status_code, ctx.res_headers, and ctx.res_body are now populated.
    ctx.meta carries anything on_request stored.
    """
    # Flows that were skipped in on_request never reach here,
    # so no need to re-check SKIP_DOMAINS / SKIP_URL_PATTERNS.

    method = ctx.meta.get("method", ctx.method)

    # ── 1. Elapsed time ───────────────────────────────────────────────────
    elapsed_ms: str = "-"
    req_time = ctx.meta.get("req_time")
    if req_time:
        try:
            delta = datetime.now() - datetime.fromisoformat(req_time)
            elapsed_ms = f"{int(delta.total_seconds() * 1000)}ms"
        except Exception:
            pass

    # ── 2. Log the response ───────────────────────────────────────────────
    ct   = ctx.res_headers.get("content-type", "-")
    size = ctx.res_headers.get("content-length", "?")
    log.info(
        f"[RES]  {method:6s}  {ctx.status_code}  {elapsed_ms:>7s}  "
        f"{_short(ctx.url)}  ct={ct}  size={size}B"
    )

    # ── 3. Status-code alerts ─────────────────────────────────────────────
    if ctx.status_code in ALERT_STATUS_CODES:
        log.warning(
            f"[ALERT] HTTP {ctx.status_code}  {method} {_short(ctx.url)}"
        )

    # ── 4. Large-response alert ───────────────────────────────────────────
    try:
        raw_size = int(ctx.res_headers.get("content-length", 0))
        if raw_size >= LARGE_RESPONSE_BYTES:
            log.warning(
                f"[ALERT] Large response: {raw_size:,} bytes  {_short(ctx.url)}"
            )
    except (ValueError, TypeError):
        pass

    # ── 5. Scan response body for sensitive leaks ─────────────────────────
    _scan_alerts("res_body", ctx.res_body, ctx.url)

    # ── 6. Report any request-side alerts that fired ──────────────────────
    prior_hits = ctx.meta.get("alert_hits", [])
    if prior_hits:
        log.warning(
            f"[ALERT] Request-side hits for completed flow: "
            f"{', '.join(prior_hits)}  {_short(ctx.url)}"
        )
