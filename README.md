# api_check.py

A small, single-file Python script that checks how an API endpoint handles **written data**:

1. **Authentication**: does the endpoint require login, and which kind (Bearer, Basic, Digest, OAuth/OIDC...)
2. **HTTP methods**: which methods the endpoint accepts
3. **Max content size**: the largest value the server accepts
4. **Rate limit**: how many requests per time window the server allows

The script uses only `httpx` plus the Python standard library. Results are printed as text and can also be saved as JSON.

> ⚠️ The script sends real write requests (POST/PUT/PATCH/DELETE), large payloads and request bursts. Use it only against servers you are allowed to test.

## Requirements

- Python 3.8+
- `httpx`

```
pip install httpx
```

## Usage

```
python api_check.py <url> [options]
```

### Examples

```bash
# Insert test data into the JSON body field "name"
python api_check.py https://api.example.com/items --field name

# Several fields, with a Bearer token, save the result as JSON
python api_check.py https://api.example.com/items --field title --field content --token abc123 --json result.json

# Put the data in the query string, use Basic auth
python api_check.py https://api.example.com/search --field q --location query --basic user:pass

# No --field: the value is sent as a raw request body
python api_check.py https://api.example.com/upload

# Custom headers / cookies
python api_check.py https://api.example.com/items --field name --header "X-API-Key: abc" --cookie "sid=xyz"

# Only methods + auth, skip the slow checks
python api_check.py https://api.example.com/items --field name --skip-size --skip-rate
```

### Options

| Option | Default | Description |
|---|---|---|
| `url` | (required) | API URL to test |
| `--field NAME` | none | Field/param that receives the test data. Repeatable. Omit to send a raw body |
| `--location body\|query` | `body` | Put the data in a JSON body or in the query string |
| `--method` | `POST` | Method used for the size and rate checks |
| `--value` | `test` | Value inserted into the fields |
| `--token` | none | Bearer token (`Authorization: Bearer ...`) |
| `--basic user:pass` | none | Basic auth |
| `--cookie` | none | Cookie header, e.g. `"sid=abc; x=1"` |
| `--header "Key: Value"` | none | Extra header. Repeatable |
| `--timeout` | `10` | Request timeout in seconds |
| `--max-size` | `10485760` (10MB) | Largest size (bytes) to try in the size check |
| `--rate-start` | `5` | Requests in the first rate round |
| `--rate-max` | `200` | Stop the rate check after this many requests per round |
| `--rate-window` | `1.0` | Length of one rate round in seconds |
| `--skip-size` | off | Skip the max size check |
| `--skip-rate` | off | Skip the rate limit check |
| `--json FILE` | none | Save the full result to a JSON file |

If you pass any of `--token`, `--basic`, `--cookie` or `--header`, the script is in **credentials mode**. It sends them with every request and skips the authentication check.

## How each check works

### 1. Authentication (`check_auth`)
This check only runs when you give no credentials.
- The script sends the request without credentials, first with `--method` and then with the other methods. A single `401`/`403` means login is required. It tries every method because the test method may not be supported at all (`405`).
- It reads the `WWW-Authenticate` header to find the scheme (`Bearer`, `Basic`, `Digest`, `Negotiate`, `NTLM`...). A Bearer header with `error=` or `scope=` is reported as OAuth2.
- It looks for keywords in the error body (`api key`, `token`, `jwt`, `oauth`, `session`, `login`) and reports them as hints.
- It requests `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` on the same host and reports the issuer, authorization endpoint and token endpoint if found.

### 2. HTTP methods (`check_methods`)
- Sends `OPTIONS` and reports the `Allow` and `Access-Control-Allow-Methods` headers.
- Sends `GET`, `POST`, `PUT`, `PATCH`, `DELETE` and `HEAD` with the test data.
  - `405` / `501` → not supported
  - `401` / `403` → the method exists, but auth/permission was denied
  - anything else → supported

### 3. Max content size (`check_max_size`)
- First checks that a tiny payload (10 bytes) is accepted. If it is rejected, the size check is skipped.
- Doubles the value size starting at 1KB until the server rejects it (status ≥ 400 or a network error), up to `--max-size`.
- Then runs a binary search between the last accepted and the first rejected size, down to 1KB precision.
- The size is the length of the inserted **value**, not the whole request.

### 4. Rate limit (`check_rate_limit`)
- Each round sends `n` requests spread evenly over `--rate-window` seconds, then waits until the window ends.
- If every request is accepted, `n` doubles (5 → 10 → 20 → ...) and a new round starts.
- It stops when the server answers `429`/`503`, when a request times out, or when `n` passes `--rate-max`.
- It also reports any `RateLimit-*`, `X-RateLimit-*` and `Retry-After` headers it sees.
- This check runs last because it may get you temporarily blocked.

In the auth, method and size checks, a `429` response is not treated as a result. The script waits for `Retry-After` and resends (`send_patiently`), so a rate limit does not get reported as a size limit.

## Output

The result is printed as a text report:

```
[2] HTTP METHODS
  Allow header: None
  CORS allow methods: GET, POST, HEAD, PUT, DELETE, PATCH, QUERY, OPTIONS
  GET     405    not supported
  POST    200    supported
  ...
  => supported: POST

[3] MAX CONTENT SIZE
  limit_found: False
  max_accepted_bytes: 200000
  note: no limit found up to 200000 bytes

[4] RATE LIMIT
  rate headers: {'ratelimit-policy': '"body-echo";q=2;w=1', 'retry-after': '1'}
     5 req in 1.41s -> {'200': 3, '429': 2}
  => rejected by server at 5 requests / 1.0s
```

With `--json FILE` the same data is saved as JSON:

```json
{
  "url": "...",
  "method": "POST",
  "fields": ["name"],
  "location": "body",
  "credentials": {"token": null, "basic": null, "cookie": null, "headers": []},
  "auth": {"required": false, "statuses": {}, "www_authenticate": null, "schemes": [], "body_hints": [], "oauth_discovery": {}},
  "methods": {"allow_header": null, "cors_allow_methods": "...", "methods": {"POST": {"status": 200, "result": "supported"}}, "supported": ["POST"]},
  "max_size": {"limit_found": true, "max_accepted_bytes": 1048576, "first_rejected_bytes": 1049600, "reject_status": 413, "requests_used": 13},
  "rate_limit": {"rate_headers": {}, "rounds": [], "max_ok_per_window": 20, "window_seconds": 1.0, "stopped_reason": "..."}
}
```

When credentials mode is on, `auth` is `{"skipped": "credentials provided"}`. A skipped check is shown as `{"skipped": "--skip-size"}` or `{"skipped": "--skip-rate"}`.

> Credentials are written **as-is** to both the text output and the JSON file. Do not share the output if it contains real secrets.

## Limitations

- Results are inferred from status codes and headers. Servers that always return `200`, or that hide errors, can give misleading results.
- The JSON body is flat: `{"field": value}`. Nested bodies are not supported.
- Size and rate are measured with one method (`--method`) and one field set.
- The rate check measures bursts within a short window. Long-window limits (per hour or per day) are only visible through the rate headers, if the server sends them.
