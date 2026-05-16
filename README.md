# 🌐 Network Proxy

A Python CLI proxy that intercepts HTTP/HTTPS traffic and stores **cookies** and **browsing history** in a local SQLite database — with a CLI viewer, web dashboard, and multi-format export.

---

## 📁 Project Structure

```
network-proxy/
├── proxy.py          ← Proxy server (mitmproxy + SQLite)
├── viewer.py         ← CLI viewer & exporter
├── dashboard.py      ← Web dashboard (no extra deps)
├── debug_proxy.py    ← Verbose TLS/hook tracer
├── find_cert.py      ← CA certificate installer helper
├── requirements.txt
└── proxy_data/
    └── proxy.db      ← SQLite database (auto-created)
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
| `req_body` | TEXT | Text body (NULL if binary) |
| `req_body_is_binary` | INTEGER | 0 / 1 |
| `status_code` | INTEGER | HTTP status |
| `res_headers` | TEXT | JSON object |
| `res_cookies` | TEXT | JSON object |
| `res_body` | TEXT | HTML body (NULL if not HTML or binary) |
| `res_body_is_binary` | INTEGER | 0 / 1 |
| `content_type` | TEXT | |
| `size_bytes` | INTEGER | Response size |

---

## 🚀 Setup

```bash
# 1. Install dependency
pip install mitmproxy

# 2. Start the proxy
python proxy.py

# 3. Configure browser/OS proxy settings:
#    HTTP  Proxy → 127.0.0.1:8080
#    HTTPS Proxy → 127.0.0.1:8080

# 4. For HTTPS, install the mitmproxy CA certificate (once):
python find_cert.py
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
```

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

# Search — URLs and request/response bodies
python viewer.py --search "Authorization"
python viewer.py --search "password" --domain mybank.com
python viewer.py --search "token" --since 2025-05-10

# Database statistics
python viewer.py --stats

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
python dashboard.py                  # http://127.0.0.1:5500
python dashboard.py --port 8888
python dashboard.py --db /path/to/proxy.db
```

Open **http://127.0.0.1:5500** in your browser.

Features:
- **Overview** — stat cards, method/status bar charts, top domains table
- **History** — paginated table with search, method, status, date filters
- **Request detail** — click any row to open a side drawer with full headers, cookies, and body
- **Cookies** — browse all cookies by domain, filterable
- **Domain sidebar** — click any domain to jump straight to its history

---

## 🛠️ Debug Tools

```bash
# Verbose hook tracer — see every TLS handshake and request
python debug_proxy.py          # runs on 127.0.0.1:9090

# Find and install the mitmproxy CA certificate (Windows)
python find_cert.py
```

---

## ⚠️ Notes

- **HTTPS requires CA cert installation** — mitmproxy uses a self-signed CA. Install it once via `python find_cert.py` or `http://mitm.it`.
- This tool is for **personal / educational use** on traffic you own or have permission to inspect.
- Cookie data is stored **unencrypted** in SQLite — keep `proxy_data/` private.
- The proxy uses WAL journal mode — `proxy.db-shm` and `proxy.db-wal` are normal SQLite WAL files; don't delete them while the proxy is running.
