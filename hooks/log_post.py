"""
hooks/log_post.py — log every POST/PUT/PATCH body to the proxy log.

The simplest possible plugin: one hook, no state, no dependencies.
Edit and save while the proxy is running — it reloads in ~1 second.
"""
import logging

log = logging.getLogger("plugin.log_post")


def on_request(ctx):
    if ctx.method not in ("POST", "PUT", "PATCH"):
        return

    body = ctx.req_body or "(empty)"
    if len(body) > 400:
        body = body[:400] + " …"

    log.info(f"[log_post]  {ctx.method}  {ctx.url}\n  body: {body}")
