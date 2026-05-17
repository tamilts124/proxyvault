# 🌐 Network Proxy

A Python CLI proxy that intercepts HTTP/HTTPS traffic and stores **cookies** and **browsing history** in a local SQLite database — with a CLI viewer, web dashboard, multi-format export, response mocking, and a hot-reloadable plugin system.

---

## 📁 Project Structure

```
network-proxy/
├── proxy.py          ← Proxy server (mitmproxy + SQLite)
├── plugin_loader.py  ← Hot-reloadable plugin engine
├── viewer.py         ← CLI viewer & exporter
├── dashboard.py      ← Web dashboard server (no extra deps)
├── dashboard.html    ← Dashboard UI (loaded at runtime — edit freely)
├── debug_proxy.py    ← Verbose TLS/hook tracer
├── find_cert.py      ← CA certificate installer (Windows / macOS / Linux)
├── db_queries.py     ← Shared read/write query layer
├── config.json       ← Optional config file (CLI flags override it)
├── requirements.txt
├── Makefile          ← Convenience targets (make proxy, make dashboard, …)
├── hooks/            ← Plugin directory (drop *.py files here)
│   └── my_plugin.py  ← Starter plugin (logging, filtering, alerting)
├── mock_responses/   ← Mock response fixture files
└── proxy_data/
    ├── proxy.db      ← SQLite database (auto-created)
    └── my_plugin.log ← Plugin rotating log (auto-created)
```

---

## 🗄️ Database Schema

Everything is stored in a single SQLite file (`proxy_data/proxy.db`).

### `cookies` table
One row per `(domain, name)` pair — upserted on every `Set-Cookie`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | PK |
| `domain` | TEXT | e.g. `github.com` |
| `name` | TEXT | Cookie name |
| `value` | TEXT | Cookie value |
| `path` | TEXT | |
| `expires` | TEXT | Raw expires string |
| `http_only` | INTEGER | 0 / 1 |
| `secure` | INTEGER | 0 / 1 |
| `same_site` | TEXT | |
| `source` | TEXT | `server` or `browser` |
| `updated_at` | TEXT | ISO timestamp |

### `history` table
One row per intercepted HTTP request/response pair.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | PK |
| `timestamp` | TEXT | ISO timestamp |
| `domain` | TEXT | |
| `url` | TEXT | Full URL |
| `method` | TEXT | GET, POST, … |
| `req_headers` | TEXT | JSON object |
| `req_cookies` | TEXT | JSON object |
| `req_body` | TEXT | Decoded body (NULL if binary) |
| `req_body_is_binary` | INTEGER | 0 / 1 |
| `req_body_type` | TEXT | `json` \| `form` \| `multipart` \| `text` \| `binary` |
| `status_code` | INTEGER | HTTP status |
| `res_headers` | TEXT | JSON object |
| `res_cookies` | TEXT | JSON object |
| `res_body` | TEXT | HTML body (NULL if not HTML or binary) |
| `res_body_is_binary` | INTEGER | 0 / 1 |
| `content_type` | TEXT | |
| `size_bytes` | INTEGER | Response size |

### `ws_messages` table
One row per WebSocket frame.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | PK |
| `history_id` | INTEGER | FK → `history.id` (the Upgrade request) |
| `timestamp` | TEXT | ISO timestamp |
| `domain` | TEXT | |
| `url` | TEXT | |
| `direction` | TEXT | `client` or `server` |
| `opcode` | INTEGER | RFC 6455 opcode |
| `opcode_label` | TEXT | `text`, `binary`, `close`, … |
| `payload` | TEXT | NULL if binary frame |
| `is_binary` | INTEGER | 0 / 1 |
| `size_bytes` | INTEGER | |

### `errors` table
Internal hook errors logged automatically.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | PK |
| `timestamp` | TEXT | |
| `hook` | TEXT | e.g. `response` |
| `url` | TEXT | |
| `error` | TEXT | Exception message |

---

## 🚀 Setup

```bash
# 1. Install dependencies
pip install mitmproxy
pip install watchdog      # optional — enables plugin hot-reload
# or
make install

# 2. Start the proxy
python proxy.py
# or
make proxy

# 3. Configure browser/OS proxy settings:
#    HTTP  Proxy → 127.0.0.1:8080
#    HTTPS Proxy → 127.0.0.1:8080

# 4. For HTTPS, install the mitmproxy CA certificate (once):
python find_cert.py
#    Works on Windows (certutil), macOS (security), and Linux (update-ca-certificates)
#    — or visit http://mitm.it in your proxied browser
```

---

## 🖥️ Proxy Usage

```bash
python proxy.py                         # Default: 127.0.0.1:8080
python proxy.py --port 9090             # Custom port
python proxy.py --host 0.0.0.0         # All interfaces (LAN proxy)
python proxy.py --no-save-pages         # Don't save HTML response bodies
python proxy.py --data-dir /my/path     # Custom data directory
python proxy.py --verbose               # Debug logging
python proxy.py --config my.json        # Use a specific config file

# Domain filtering
python proxy.py --include-domains "github.com,api.example.com"
python proxy.py --exclude-domains "google-analytics.com,doubleclick.net"

# Sensitive data redaction (on by default)
python proxy.py --no-redact             # Store auth headers / tokens unredacted

# Deduplication — skip DB writes for repeated identical requests
python proxy.py --dedup 30             # suppress duplicates within a 30-second window

# Plugin hooks directory
python proxy.py --hooks-dir ./hooks    # default; change to load plugins from elsewhere
```

### Config file (`config.json`)

CLI flags always win. Edit `config.json` for persistent defaults:

```json
{
  "host":             "127.0.0.1",
  "port":             8080,
  "save_pages":       true,
  "data_dir":         "proxy_data",
  "redact":           true,
  "verbose":          false,
  "include_domains":  "",
  "exclude_domains":  "google-analytics.com,doubleclick.net,googletagmanager.com",
  "hooks_dir":        "hooks",
  "dedup_window":     0,
  "mock_rules":       []
}
```

### CLI ↔ config.json mapping

| CLI flag | config.json key | Default |
|---|---|---|
| `--host` | `host` | `127.0.0.1` |
| `--port` | `port` | `8080` |
| `--no-save-pages` | `save_pages` | `true` |
| `--data-dir` | `data_dir` | `proxy_data` |
| `--include-domains` | `include_domains` | `""` |
| `--exclude-domains` | `exclude_domains` | `""` |
| `--no-redact` | `redact` | `true` |
| `--dedup` | `dedup_window` | `0` (off) |
| `--hooks-dir` | `hooks_dir` | `hooks` |
| `--verbose` | `verbose` | `false` |
| *(config only)* | `mock_rules` | `[]` |

---

## 🔌 Plugin System

Drop any `*.py` file into `hooks/` and the proxy loads it automatically. Edit or replace the file while the proxy is running and it reloads within ~1 second — **no restart required** (requires `pip install watchdog`).

### Plugin contract

```python
def on_request(ctx) -> bool | None:
    # Runs before the DB row is written.
    # Return False → skip DB recording for this flow (request still forwarded).
    # Return None  → continue normally.
    pass

def on_response(ctx) -> None:
    # Runs after the server responds.
    # ctx.status_code, ctx.res_headers, ctx.res_body are now populated.
    pass
```

A plugin file needs at least one of the two functions. Both are optional.

### `PluginContext` fields

| Field | Type | Available in | Notes |
|---|---|---|---|
| `url` | `str` | both | Full URL |
| `domain` | `str` | both | netloc only, e.g. `api.example.com` |
| `method` | `str` | both | `GET`, `POST`, … |
| `req_headers` | `dict` | both | `{lowercase-name: value}` |
| `req_body` | `str\|None` | both | Decoded body; `None` if binary |
| `status_code` | `int\|None` | `on_response` | `None` in `on_request` |
| `res_headers` | `dict` | `on_response` | Empty dict in `on_request` |
| `res_body` | `str\|None` | `on_response` | HTML body when saved, else `None` |
| `flow` | `object` | both | Raw mitmproxy `HTTPFlow` (advanced) |
| `meta` | `dict` | both | Mutable scratch space — shared between `on_request` and `on_response` for the **same flow** |

### Pass-through mode (no DB recording)

To proxy traffic without writing anything to the database, return `False` from `on_request`:

```python
def on_request(ctx):
    return False   # forward only — no DB row, on_response not called
```

### `ctx.meta` — passing data between hooks

```python
def on_request(ctx):
    ctx.meta["started"] = time.time()

def on_response(ctx):
    elapsed = time.time() - ctx.meta.get("started", time.time())
    print(f"{elapsed*1000:.0f}ms  {ctx.url}")
```

### Execution order

Plugins run in **filename-alphabetical order**. If `on_request` in any plugin returns `False`, subsequent plugins and the DB write are both skipped.

### Starter plugin (`hooks/my_plugin.py`)

The included starter plugin demonstrates all capabilities out of the box:

| Feature | Details |
|---|---|
| Domain/URL filtering | Skip noisy tracker domains — returns `False` (no DB row) |
| Request logging | Logs method, URL, content-type to a rotating log file |
| Alert patterns | Regex scan for auth leaks (Bearer tokens in URLs, AWS keys, private key material) |
| Status-code alerts | Warns on 4xx / 5xx responses |
| Large-response alert | Warns when `content-length` ≥ 512 KB |
| `ctx.meta` usage | Passes `req_time` and alert hits from `on_request` → `on_response` |
| Elapsed time | Computes round-trip ms per flow |

Tune it by editing the `CONFIG` block at the top of the file — it hot-reloads on save.

**Log output** → `proxy_data/my_plugin.log` (5 MB rotating, 3 backups).

---

## 🎭 Response Mocking

Drop fixture files in `mock_responses/` and reference them in `config.json`. Rules are evaluated in order; the first match wins.

```json
"mock_rules": [
  {
    "match":   "/api/feature-flags",
    "file":    "mock_responses/feature_flags.json",
    "status":  200
  },
  {
    "match":   "regex:^https://api\\.example\\.com/v1/user",
    "file":    "mock_responses/user.json",
    "methods": ["GET"],
    "enabled": true
  }
]
```

| Field | Required | Notes |
|---|---|---|
| `match` | ✅ | Substring or `regex:…` prefix |
| `file` | ✅ | Path relative to `config.json` |
| `status` | | Default `200` |
| `headers` | | Extra response headers |
| `methods` | | `["GET"]` etc.; omit to match all |
| `enabled` | | Default `true`; toggle at runtime via dashboard |

Rules can be toggled at runtime via the **Mocks** panel in the dashboard or the `/api/mock_rules` endpoints — no proxy restart required.

---

## 🔍 Viewer CLI

```bash
# Overview — list all captured domains
python viewer.py

# Domain detail — cookies + last N requests
python viewer.py --domain google.com
python viewer.py --domain google.com --limit 200

# All cookies
python viewer.py --cookies
python viewer.py --cookies --domain github.com

# Browsing history
python viewer.py --history
python viewer.py --history --domain twitter.com --limit 500
python viewer.py --history --since 2025-05-01 --until 2025-05-15

# Full request / response for one row
python viewer.py --request 42

# Replay a saved request live (re-sends using urllib)
python viewer.py --replay 42

# Search — URLs and request/response bodies
python viewer.py --search "Authorization"
python viewer.py --search "password" --domain mybank.com
python viewer.py --search "token" --since 2025-05-10

# Database statistics
python viewer.py --stats

# Live-tail new requests (like tail -f)
python viewer.py --watch
python viewer.py --watch --domain api.example.com

# Prune old data
python viewer.py --prune --older-than 7       # delete rows older than 7 days
python viewer.py --prune --keep-last 5000     # keep only 5000 most recent rows

# Export
python viewer.py --export report.json        # Full JSON dump
python viewer.py --export report.har         # HAR — import into Chrome DevTools or Burp Suite
python viewer.py --export report.csv         # CSV — open in Excel / pandas
python viewer.py --export report.har --domain api.example.com --since 2025-05-01
```

### Export formats

| Format | Use |
|--------|-----|
| `.json` | Full dump — cookies + history with parsed header objects |
| `.har` | HTTP Archive 1.2 — import into Chrome DevTools (Network → ⬆ Import HAR), Burp Suite, or Insomnia |
| `.csv` | Spreadsheet-friendly — open directly in Excel (UTF-8 BOM) or pandas |

All exports support `--domain`, `--since`, and `--until` filters.

---

## 📊 Web Dashboard

No extra dependencies — uses only Python's built-in `http.server`.

```bash
python dashboard.py                          # http://127.0.0.1:5500
python dashboard.py --port 8888
python dashboard.py --db /path/to/proxy.db
python dashboard.py --password mysecret      # enable HTTP Basic Auth
```

Open **http://127.0.0.1:5500** in your browser.

### Features

- **Overview** — stat cards, requests-over-time timeline, method/status bar charts, top domains table
- **Auto-refresh** — overview refreshes every 5 seconds automatically
- **History** — paginated table with search, method, status, date filters
- **Request detail** — click any row to open a side drawer with full headers, cookies, and body
- **Cookies** — browse all cookies by domain, filterable
- **Mocks** — toggle mock rules on/off at runtime without restarting the proxy
- **Domain sidebar** — click any domain to jump straight to its history
- **Prune DB** — delete old rows without the CLI
- **HTTP Basic Auth** — pass `--password` to gate the entire dashboard

### Editing the UI

`dashboard.html` is loaded fresh on every page load — edit it without restarting `dashboard.py`.

---

## 🛠️ Debug Tools

```bash
# Verbose hook tracer — see every TLS handshake and request
python debug_proxy.py                      # runs on 127.0.0.1:9090
python debug_proxy.py --port 9091
python debug_proxy.py --log-file debug.log

# Find and install the mitmproxy CA certificate
python find_cert.py   # Windows (certutil), macOS (security), Linux (update-ca-certificates)
```

---

## 🔒 Security Notes

- **HTTPS requires CA cert installation** — mitmproxy uses a self-signed CA. Install it once via `python find_cert.py`.
- This tool is for **personal / educational use** on traffic you own or have permission to inspect.
- Cookie and header data is stored **unencrypted** in SQLite — keep `proxy_data/` private.
- Sensitive headers (`Authorization`, `x-api-key`, `Cookie`) and body keys (`password`, `token`, `secret`) are **redacted by default**. Pass `--no-redact` to opt out.
- The dashboard has **no authentication by default** — pass `--password` to enable HTTP Basic Auth if you expose it on a network.
- The proxy uses WAL journal mode — `proxy.db-shm` and `proxy.db-wal` are normal SQLite WAL files; don't delete them while the proxy is running.

---

## ⚡ Quick Reference (Makefile)

```
make proxy          # start the proxy
make dashboard      # open the web dashboard
make viewer         # domain summary
make debug          # verbose TLS tracer
make cert           # install CA cert
make install        # pip install -r requirements.txt
make export         # dump to HAR + JSON + CSV
make prune          # delete rows older than 7 days
make watch          # live-tail new requests
make stats          # DB statistics
```
