"""
hooks/alert_on_error.py — print a loud log line whenever a 4xx/5xx lands.

Demonstrates on_response and how to use ctx.meta to pass data from the
request side to the response side within the same plugin.
"""
import logging
import json

log = logging.getLogger("plugin.alert_on_error")

# Only alert on these domains; empty list = alert on all domains.
WATCH_DOMAINS: list[str] = []

# Minimum status code to alert on (e.g. 400 = all errors, 500 = server errors only).
MIN_STATUS = 400


def on_request(ctx):
    # Stash the request timestamp in meta so the response side can log it.
    import time
    ctx.meta["started_at"] = time.monotonic()


def on_response(ctx):
    if ctx.status_code is None or ctx.status_code < MIN_STATUS:
        return

    if WATCH_DOMAINS and not any(
        ctx.domain == d or ctx.domain.endswith("." + d) for d in WATCH_DOMAINS
    ):
        return

    import time
    elapsed = time.monotonic() - ctx.meta.get("started_at", time.monotonic())

    # Try to pull an error message out of a JSON body
    hint = ""
    if ctx.res_body:
        try:
            data = json.loads(ctx.res_body[:2000])
            for key in ("error", "message", "detail", "msg", "description"):
                if key in data:
                    hint = f"  hint: {str(data[key])[:120]}"
                    break
        except Exception:
            pass

    log.warning(
        f"[alert_on_error]  HTTP {ctx.status_code}  {ctx.method}  {ctx.url}"
        f"  ({elapsed*1000:.0f}ms){hint}"
    )
