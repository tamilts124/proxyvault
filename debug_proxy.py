#!/usr/bin/env python3
"""
Debug proxy — verbose hook tracing.
"""

import asyncio
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http as mhttp

class DebugAddon:

    def client_connected(self, client):
        print(f"[CONNECT ]  client connected from {client.peername}")

    def client_disconnected(self, client):
        print(f"[DISCONN ]  client disconnected")

    def tls_start_client(self, tls_handshake):
        print(f"[TLS     ]  handshake starting...")

    def tls_established_client(self, tls_handshake):
        print(f"[TLS  OK ]  ✅ TLS established!")

    def tls_failed_client(self, tls_handshake):
        print(f"[TLS FAIL]  ❌ TLS failed")

    def tls_start_server(self, tls_handshake):
        print(f"[TLS SRV ]  connecting to upstream server...")

    def tls_established_server(self, tls_handshake):
        print(f"[TLS SRV ]  ✅ upstream TLS established!")

    def tls_failed_server(self, tls_handshake):
        print(f"[TLS SRV ]  ❌ upstream TLS failed")

    def http_connect(self, flow: mhttp.HTTPFlow):
        print(f"[TUNNEL  ]  CONNECT → {flow.request.host}:{flow.request.port}")

    def request(self, flow: mhttp.HTTPFlow):
        print(f"[REQUEST ]  ✅ {flow.request.method}  {flow.request.pretty_url[:100]}")

    def response(self, flow: mhttp.HTTPFlow):
        print(f"[RESPONSE]  ✅ {flow.response.status_code}  {flow.request.pretty_url[:100]}")

    def error(self, flow: mhttp.HTTPFlow):
        print(f"[ERROR   ]  ❌ {flow.error}")


async def main():
    opts = Options(
        listen_host="127.0.0.1",
        listen_port=9090,
        ssl_insecure=True,
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(DebugAddon())

    print("""
============================================================
  Debug Proxy on 127.0.0.1:9090
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

asyncio.run(main())
