"""
hooks/block_domains.py — block requests to specified domains.

Returning False from on_request short-circuits the chain: subsequent plugins
are skipped, and the response is NOT recorded in the database.  The request
is still forwarded to the server (this proxy sits in-line and can't cancel
a request mid-flight); what this controls is what gets stored and observed.

To also block the network response, set flow.response in on_request:

    from mitmproxy import http as mhttp
    ctx.flow.response = mhttp.Response.make(403, b"Blocked by proxy plugin")
"""
import logging

log = logging.getLogger("plugin.block_domains")

# Edit this list freely — the file hot-reloads, so changes take effect
# within ~1 second without restarting the proxy.
BLOCKED_DOMAINS = [
    "ads.example.com",
    "tracking.example.com",
]


def on_request(ctx):
    for blocked in BLOCKED_DOMAINS:
        if ctx.domain == blocked or ctx.domain.endswith("." + blocked):
            log.info(f"[block_domains] blocked  {ctx.method}  {ctx.url}")
            return False   # short-circuit: skip remaining plugins + DB write
