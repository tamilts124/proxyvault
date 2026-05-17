"""
hooks/rewrite_headers.py — mutate request or response headers on the fly.

Demonstrates direct flow mutation via ctx.flow (the raw mitmproxy HTTPFlow).
Changes here affect what the server/client actually receives, not just what
gets logged.

Common uses:
  - Strip tracking headers before they reach the server
  - Inject an Authorization header for testing
  - Force a response header (e.g. disable HSTS in a dev environment)
"""
import logging

log = logging.getLogger("plugin.rewrite_headers")

# Headers to remove from every outgoing request (case-insensitive).
STRIP_REQUEST_HEADERS = [
    "x-forwarded-for",
    "via",
]

# Headers to inject into every outgoing request.
# Existing values are overwritten.
INJECT_REQUEST_HEADERS: dict[str, str] = {
    # "x-debug-proxy": "1",
}

# Headers to remove from every response.
STRIP_RESPONSE_HEADERS = [
    "strict-transport-security",   # disable HSTS locally
    "x-frame-options",
]


def on_request(ctx):
    flow = ctx.flow

    for h in STRIP_REQUEST_HEADERS:
        if h in flow.request.headers:
            del flow.request.headers[h]
            log.debug(f"[rewrite_headers] stripped request header '{h}'  {ctx.url[:60]}")

    for h, v in INJECT_REQUEST_HEADERS.items():
        flow.request.headers[h] = v
        log.debug(f"[rewrite_headers] injected request header '{h}: {v}'  {ctx.url[:60]}")


def on_response(ctx):
    flow = ctx.flow
    if flow.response is None:
        return

    for h in STRIP_RESPONSE_HEADERS:
        if h in flow.response.headers:
            del flow.response.headers[h]
            log.debug(f"[rewrite_headers] stripped response header '{h}'  {ctx.url[:60]}")
