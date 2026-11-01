"""
api_check.py - Quick checker for an API that accepts written data.

Checks:
  1. Auth       : does the API require login, and which kind (Bearer, Basic, OAuth...).
                  Skipped when the user provides credentials.
  2. HTTP method: which methods the server accepts.
  3. Max size   : largest data size the server accepts (binary search).
  4. Rate limit : send n requests within a time window, increasing n until
                  the server rejects (429/503) or times out.

Examples:
  python api_check.py https://httpbin.org/post --field name
  python api_check.py https://api.example.com/items --field title --token abc123 --json out.json
"""

import argparse
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
AUTH_SCHEMES = ["Bearer", "Basic", "Digest", "Negotiate", "NTLM", "OAuth", "ApiKey"]
WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]
# Keywords in an error body -> hint about the login type
AUTH_HINT_WORDS = {
    "api key": "API key",
    "apikey": "API key",
    "api_key": "API key",
    "x-api-key": "API key",
    "jwt": "JWT token",
    "token": "Token",
    "oauth": "OAuth",
    "session": "Session cookie",
    "login": "Login (session/cookie)",
}


# ---------------------------------------------------------------------------
# Helpers: build client, build payload, send request
# ---------------------------------------------------------------------------

def make_client(args, use_credentials=True):
    """Create an httpx.Client, attaching credentials if given and use_credentials=True."""
    headers = {}
    if use_credentials:
        if args.token:
            headers["Authorization"] = "Bearer " + args.token
        if args.basic:
            encoded = base64.b64encode(args.basic.encode()).decode()
            headers["Authorization"] = "Basic " + encoded
        if args.cookie:
            headers["Cookie"] = args.cookie
        for line in args.header:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return httpx.Client(headers=headers, timeout=args.timeout)


def has_credentials(args):
    return bool(args.token or args.basic or args.cookie or args.header)


def build_payload(args, value):
    """Insert value into the fields (JSON body or query). No fields -> send a raw body."""
    if args.location == "query":
        return {"params": {field: value for field in args.field}}
    if args.field:
        return {"json": {field: value for field in args.field}}
    return {"content": value}


def send(client, method, args, value):
    """Send one request. Return (response, error); one of them is None."""
    try:
        resp = client.request(method, args.url, **build_payload(args, value))
        return resp, None
    except httpx.TimeoutException:
        return None, "timeout"
    except httpx.HTTPError as e:
        return None, "error: " + type(e).__name__


def send_patiently(client, method, args, value, max_retries=5):
    """Like send(), but on 429 wait for Retry-After and resend.
    Used by the non rate-limit checks so a 429 does not skew their results."""
    for _ in range(max_retries):
        resp, err = send(client, method, args, value)
        if resp is None or resp.status_code != 429:
            return resp, err
        wait = resp.headers.get("retry-after", "1")
        time.sleep(float(wait) if wait.replace(".", "").isdigit() else 1)
    return resp, err


# ---------------------------------------------------------------------------
# 1. Authentication check
# ---------------------------------------------------------------------------

def check_auth(args):
    result = {
        "required": None,
        "statuses": {},
        "www_authenticate": None,
        "schemes": [],
        "body_hints": [],
        "oauth_discovery": {},
    }
    client = make_client(args, use_credentials=False)

    # Send without credentials using every method (the test method may not be supported).
    # A single 401/403 from any method means login is required.
    resp = None
    for method in [args.method] + ALL_METHODS:
        if method in result["statuses"]:
            continue
        r, err = send_patiently(client, method, args, args.value)
        result["statuses"][method] = err if err else r.status_code
        if r is not None and (resp is None or r.status_code in (401, 403)):
            resp = r
        if r is not None and r.status_code in (401, 403):
            break

    if resp is None:
        client.close()
        return result

    result["required"] = resp.status_code in (401, 403)

    # The WWW-Authenticate header tells the auth scheme
    www = resp.headers.get("www-authenticate", "")
    if www:
        result["www_authenticate"] = www
        for scheme in AUTH_SCHEMES:
            if scheme.lower() in www.lower():
                result["schemes"].append(scheme)
        if "Bearer" in result["schemes"] and ("error=" in www or "scope=" in www):
            result["schemes"].append("OAuth2 (Bearer token)")

    # Extra guesses from the error body
    if result["required"]:
        body = resp.text.lower()
        for word, hint in AUTH_HINT_WORDS.items():
            if word in body and hint not in result["body_hints"]:
                result["body_hints"].append(hint)

    # Look for OAuth / OpenID Connect configuration
    parts = urlparse(args.url)
    origin = parts.scheme + "://" + parts.netloc
    for path in WELL_KNOWN_PATHS:
        try:
            r = client.get(origin + path)
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                data = r.json()
                result["oauth_discovery"][path] = {
                    "issuer": data.get("issuer"),
                    "authorization_endpoint": data.get("authorization_endpoint"),
                    "token_endpoint": data.get("token_endpoint"),
                }
        except (httpx.HTTPError, ValueError):
            pass

    client.close()
    return result


# ---------------------------------------------------------------------------
# 2. HTTP method check
# ---------------------------------------------------------------------------

def check_methods(client, args):
    result = {"allow_header": None, "cors_allow_methods": None, "methods": {}, "supported": []}

    # OPTIONS: read the Allow header
    resp, err = send_patiently(client, "OPTIONS", args, args.value)
    if resp is not None:
        result["allow_header"] = resp.headers.get("allow")
        result["cors_allow_methods"] = resp.headers.get("access-control-allow-methods")

    # Try each method
    for method in ALL_METHODS:
        resp, err = send_patiently(client, method, args, args.value)
        if err:
            status, verdict = None, err
        elif resp.status_code in (405, 501):
            status, verdict = resp.status_code, "not supported"
        elif resp.status_code in (401, 403):
            status, verdict = resp.status_code, "exists, but auth/permission denied"
        else:
            status, verdict = resp.status_code, "supported"
            result["supported"].append(method)
        result["methods"][method] = {"status": status, "result": verdict}

    return result


# ---------------------------------------------------------------------------
# 3. Max content size check
# ---------------------------------------------------------------------------

def check_max_size(client, args):
    request_count = 0

    def is_accepted(size):
        nonlocal request_count
        request_count += 1
        resp, err = send_patiently(client, args.method, args, "A" * size)
        if err:
            return False, err
        return resp.status_code < 400, resp.status_code

    # A small payload must be accepted, otherwise the test is meaningless
    ok, status = is_accepted(10)
    if not ok:
        return {"result": "skipped - small payload already rejected", "status": status}

    # Step 1: double the size until it is rejected
    low, high, reject_status = 10, None, None
    size = 1024
    while True:
        ok, status = is_accepted(size)
        if not ok:
            high, reject_status = size, status
            break
        low = size
        if size >= args.max_size:
            break
        size = min(size * 2, args.max_size)

    if high is None:
        return {
            "limit_found": False,
            "max_accepted_bytes": low,
            "note": "no limit found up to %d bytes" % args.max_size,
            "requests_used": request_count,
        }

    # Step 2: binary search between low (accepted) and high (rejected), 1KB precision
    while high - low > 1024:
        mid = (low + high) // 2
        ok, status = is_accepted(mid)
        if ok:
            low = mid
        else:
            high, reject_status = mid, status

    return {
        "limit_found": True,
        "max_accepted_bytes": low,
        "first_rejected_bytes": high,
        "reject_status": reject_status,
        "requests_used": request_count,
    }


# ---------------------------------------------------------------------------
# 4. Rate limit check
# ---------------------------------------------------------------------------

def read_rate_headers(resp):
    """Collect rate limit related headers (X-RateLimit-*, RateLimit-*, Retry-After)."""
    found = {}
    for key, value in resp.headers.items():
        if "ratelimit" in key.lower() or key.lower() == "retry-after":
            found[key] = value
    return found


def send_burst(client, args, n, window):
    """Send n requests spread evenly over `window` seconds (in parallel threads)."""
    def worker(i):
        time.sleep(i * window / n)
        return send(client, args.method, args, args.value)

    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(worker, range(n)))


def check_rate_limit(client, args):
    result = {"rate_headers": {}, "rounds": [], "max_ok_per_window": None,
              "window_seconds": args.rate_window, "stopped_reason": None}

    n = args.rate_start
    while n <= args.rate_max:
        start = time.time()
        responses = send_burst(client, args, n, args.rate_window)

        # Wait until the window ends before the next round
        elapsed = time.time() - start
        if elapsed < args.rate_window:
            time.sleep(args.rate_window - elapsed)

        # Count the results of this round
        counts = {}
        for resp, err in responses:
            key = err if err else str(resp.status_code)
            counts[key] = counts.get(key, 0) + 1
            if resp is not None:
                headers = read_rate_headers(resp)
                if headers:
                    result["rate_headers"] = headers
        result["rounds"].append({"requests": n, "elapsed_s": round(elapsed, 2), "statuses": counts})

        # Stop when rejected or timed out
        if "429" in counts or "503" in counts:
            result["stopped_reason"] = "rejected by server at %d requests / %ss" % (n, args.rate_window)
            break
        if "timeout" in counts:
            result["stopped_reason"] = "timeout at %d requests / %ss" % (n, args.rate_window)
            break

        result["max_ok_per_window"] = n
        n *= 2

    if result["stopped_reason"] is None:
        result["stopped_reason"] = "no limit found up to %d requests / %ss" % (args.rate_max, args.rate_window)
    return result


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------

def print_report(report):
    print("=" * 60)
    print("API CHECK:", report["url"])
    print("Method used for tests:", report["method"], "| fields:", report["fields"] or "(raw body)")
    print("=" * 60)

    auth = report["auth"]
    print("\n[1] AUTHENTICATION")
    if auth.get("skipped"):
        print("  skipped -", auth["skipped"])
    else:
        print("  statuses without credentials:", auth["statuses"])
        print("  login required:", auth["required"])
        print("  WWW-Authenticate:", auth["www_authenticate"])
        print("  schemes:", ", ".join(auth["schemes"]) or "-")
        print("  hints from error body:", ", ".join(auth["body_hints"]) or "-")
        for path, info in auth["oauth_discovery"].items():
            print("  OAuth/OIDC found at", path)
            for key, value in info.items():
                print("    %s: %s" % (key, value))

    methods = report["methods"]
    print("\n[2] HTTP METHODS")
    print("  Allow header:", methods["allow_header"])
    print("  CORS allow methods:", methods["cors_allow_methods"])
    for name, info in methods["methods"].items():
        print("  %-7s %-6s %s" % (name, info["status"], info["result"]))
    print("  => supported:", ", ".join(methods["supported"]) or "-")

    print("\n[3] MAX CONTENT SIZE")
    for key, value in report["max_size"].items():
        print("  %s: %s" % (key, value))

    rate = report["rate_limit"]
    print("\n[4] RATE LIMIT")
    if rate.get("skipped"):
        print("  skipped -", rate["skipped"])
    else:
        print("  rate headers:", rate["rate_headers"] or "-")
        for r in rate["rounds"]:
            print("  %4d req in %.2fs -> %s" % (r["requests"], r["elapsed_s"], r["statuses"]))
        print("  => max accepted: %s requests / %ss" % (rate["max_ok_per_window"], rate["window_seconds"]))
        print("  =>", rate["stopped_reason"])
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Simple checker for write-capable APIs.")
    p.add_argument("url", help="API URL to test")
    p.add_argument("--field", action="append", default=[],
                   help="param/field name to insert data into (repeatable). Omit to send a raw body")
    p.add_argument("--location", choices=["body", "query"], default="body",
                   help="put data in JSON body or query string (default: body)")
    p.add_argument("--method", default="POST", help="method used for size/rate tests (default: POST)")
    p.add_argument("--value", default="test", help="value inserted into fields (default: 'test')")

    p.add_argument("--token", help="Bearer token")
    p.add_argument("--basic", help="Basic auth as user:pass")
    p.add_argument("--cookie", help="Cookie header, e.g. 'sid=abc; x=1'")
    p.add_argument("--header", action="append", default=[], help="extra header 'Key: Value' (repeatable)")

    p.add_argument("--timeout", type=float, default=10, help="request timeout in seconds (default: 10)")
    p.add_argument("--max-size", type=int, default=10 * 1024 * 1024,
                   help="largest size to try in bytes (default: 10MB)")
    p.add_argument("--rate-start", type=int, default=5, help="requests in first rate round (default: 5)")
    p.add_argument("--rate-max", type=int, default=200, help="stop rate test after this many requests/round (default: 200)")
    p.add_argument("--rate-window", type=float, default=1.0, help="time window per round in seconds (default: 1)")
    p.add_argument("--skip-size", action="store_true", help="skip max size check")
    p.add_argument("--skip-rate", action="store_true", help="skip rate limit check")
    p.add_argument("--json", help="save result to this JSON file")
    return p.parse_args()


def main():
    args = parse_args()
    args.method = args.method.upper()

    report = {
        "url": args.url,
        "method": args.method,
        "fields": args.field,
        "location": args.location,
        "credentials": {
            "token": args.token, "basic": args.basic,
            "cookie": args.cookie, "headers": args.header,
        },
    }

    # 1. Authentication (only without credentials)
    if has_credentials(args):
        report["auth"] = {"skipped": "credentials provided"}
    else:
        print("Checking authentication...")
        report["auth"] = check_auth(args)

    client = make_client(args)

    # 2. HTTP methods
    print("Checking HTTP methods...")
    report["methods"] = check_methods(client, args)

    # 3. Max size
    if args.skip_size:
        report["max_size"] = {"skipped": "--skip-size"}
    else:
        print("Checking max content size...")
        report["max_size"] = check_max_size(client, args)

    # 4. Rate limit (last, since it may get us temporarily blocked)
    if args.skip_rate:
        report["rate_limit"] = {"skipped": "--skip-rate"}
    else:
        print("Checking rate limit...")
        report["rate_limit"] = check_rate_limit(client, args)

    client.close()
    print_report(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print("Saved JSON to", args.json)


if __name__ == "__main__":
    main()
