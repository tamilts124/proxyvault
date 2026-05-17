#!/usr/bin/env python3
"""
Debug proxy — verbose hook tracing.

Usage:
  python debug_proxy.py                        # runs on 127.0.0.1:9090
  python debug_proxy.py --port 9091
  python debug_proxy.py --log-file debug.log   # also write traces to a file
"""

__version__ = "2.0.0"

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http as mhttp


class DebugAddon:
    def __init__(self, logger: logging.Logger):
        self.log = logger

    def client_connected(self, client):
        self.log.info(f"[CONNECT ]  client connected from {client.peername}")

    def client_disconnected(self, client):
        self.log.info("[DISCONN ]  client disconnected")

    def tls_start_client(self, tls_handshake):
        self.log.info("[TLS     ]  handshake starting...")

    def tls_established_client(self, tls_handshake):
        self.log.info("[TLS  OK ]  ✅ TLS established!")

    def tls_failed_client(self, tls_handshake):
        self.log.info("[TLS FAIL]  ❌ TLS failed")

    def tls_start_server(self, tls_handshake):
        self.log.info("[TLS SRV ]  connecting to upstream server...")

    def tls_established_server(self, tls_handshake):
        self.log.info("[TLS SRV ]  ✅ upstream TLS established!")

    def tls_failed_server(self, tls_handshake):
        self.log.info("[TLS SRV ]  ❌ upstream TLS failed")

    def http_connect(self, flow: mhttp.HTTPFlow):
        self.log.info(f"[TUNNEL  ]  CONNECT → {flow.request.host}:{flow.request.port}")

    def request(self, flow: mhttp.HTTPFlow):
        self.log.info(f"[REQUEST ]  ✅ {flow.request.method}  {flow.request.pretty_url[:100]}")

    def response(self, flow: mhttp.HTTPFlow):
        self.log.info(f"[RESPONSE]  ✅ {flow.response.status_code}  {flow.request.pretty_url[:100]}")

    def error(self, flow: mhttp.HTTPFlow):
        self.log.info(f"[ERROR   ]  ❌ {flow.error}")


async def run(host: str, port: int, logger: logging.Logger):
    opts = Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=True,
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(DebugAddon(logger))

    print(f"""
============================================================
  Debug Proxy on {host}:{port}
  Visit https://example.com — expect:
    [TUNNEL  ]  CONNECT → example.com:443
    [TLS  OK ]  ✅ TLS established!
    [TLS SRV ]  ✅ upstream TLS established!
    [REQUEST ]  ✅ GET https://example.com/
    [RESPONSE]  ✅ 200 https://example.com/
============================================================
""")

    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()
        print("\nStopped.")


def main():
    parser = argparse.ArgumentParser(description="Debug Proxy — verbose TLS/hook tracer")
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--host",     default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    parser.add_argument("--port",     type=int, default=9090, help="Listen port (default: 9090)")
    parser.add_argument("--log-file", metavar="FILE", help="Also write traces to this log file")
    args = parser.parse_args()

    # Build logger — always writes to stdout; optionally also to a file
    logger = logging.getLogger("debug_proxy")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    logger.addHandler(stdout_handler)

    if args.log_file:
        log_path = Path(args.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
        print(f"[*] Logging to: {log_path.resolve()}")

    asyncio.run(run(args.host, args.port, logger))


if __name__ == "__main__":
    main()
