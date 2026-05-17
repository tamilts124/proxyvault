# mock_responses/

Drop response fixture files here and reference them from `mock_rules` in `config.json`.

The proxy intercepts any matching request and returns the file contents instead of the real server response. The request is **still recorded** in the SQLite history database, so you can inspect it in the dashboard or viewer.

---

## config.json reference

```json
"mock_rules": [
  {
    "match":   "/api/feature-flags",
    "file":    "mock_responses/feature_flags.json",
    "status":  200,
    "headers": {"Content-Type": "application/json"}
  },
  {
    "match":   "regex:^https://api\\.example\\.com/v1/user",
    "file":    "mock_responses/user.json",
    "status":  200,
    "methods": ["GET"],
    "headers": {"Content-Type": "application/json", "X-Mocked": "true"}
  },
  {
    "match":   "/checkout/payment",
    "file":    "mock_responses/payment_error.json",
    "status":  503
  }
]
```

### Rule fields

| Field     | Required | Default | Description |
|-----------|----------|---------|-------------|
| `match`   | ✅       | —       | URL substring **or** `regex:<pattern>` (Python `re.search`) |
| `file`    | ✅       | —       | Path to response file, relative to `config.json` |
| `status`  | —        | `200`   | HTTP status code to return |
| `headers` | —        | `{}`    | Response headers to set or override |
| `methods` | —        | all     | Array of HTTP methods this rule applies to, e.g. `["GET","POST"]` |

### Content-Type inference

If `Content-Type` is not set in `headers`, it is inferred from the file extension:

| Extension | Content-Type |
|-----------|-------------|
| `.json`   | `application/json` |
| `.html`   | `text/html` |
| `.xml`    | `application/xml` |
| `.txt`    | `text/plain` |
| `.js`     | `application/javascript` |
| `.css`    | `text/css` |

### Toggling rules at runtime

Rules can be enabled or disabled live via the web dashboard (**Mocks** panel) without restarting the proxy. The toggle state is in-memory only; it resets to all-enabled on proxy restart.

### match syntax

- **Substring** (default): `"/api/users"` matches any URL that contains that string.
- **Regex**: `"regex:^https://api\\.example\\.com"` — full Python regex, anchored or not, case-sensitive.

Rules are evaluated **in order**; the first match wins. Put more specific rules before broad ones.

---

## Example files in this folder

| File | Description |
|------|-------------|
| `feature_flags.json` | Sample feature-flag API response |
| `user.json`          | Sample user profile response |
| `payment_error.json` | Sample 503 error body |

These examples are **not** active until you add them to `mock_rules` in `config.json`.
