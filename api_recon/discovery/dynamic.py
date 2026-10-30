"""Lớp 4: phân tích động bằng Playwright.

Mở trình duyệt, đi theo link điều hướng (navbar/menu) trong phạm vi domain
cho phép, và BẮT mọi network request/response. Từ đó lấy API thật đang được
gọi: method, header xác thực, content-type, status, dấu hiệu rate-limit, và
JSON Schema của response mẫu.

Hỗ trợ:
- --login: mở trình duyệt có giao diện để người dùng tự đăng nhập, sau đó lưu
  storage_state để tái sử dụng.
- dùng lại storage_state đã lưu.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin, urldefrag, urlsplit

try:
    from genson import SchemaBuilder
except Exception:  # pragma: no cover
    SchemaBuilder = None

from ..auth import Credentials
from ..classifier import classify
from ..models import (
    AuthKind,
    AuthMechanism,
    Confidence,
    Endpoint,
    Evidence,
    Parameter,
    RateLimitSignal,
    Source,
)
from ..normalize import endpoint_id, template_from_url

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
    "x-rate-limit-limit",
]

_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".map")


def _same_scope(url: str, scope_hosts: list[str]) -> bool:
    host = urlsplit(url).netloc.lower()
    return any(host == h or host.endswith("." + h) for h in scope_hosts)


def _looks_like_api(url: str, ctype: str, resource_type: str) -> bool:
    if resource_type in ("xhr", "fetch"):
        return True
    if "json" in ctype or "graphql" in ctype:
        return True
    path = urlsplit(url).path.lower()
    if path.endswith(_ASSET_EXT):
        return False
    return "/api/" in path or "/graphql" in path or "/v1/" in path or "/v2/" in path


def run_dynamic(
    target: str,
    scope_hosts: list[str],
    creds: Credentials,
    depth: int,
    max_pages: int,
    login: bool,
    storage_state: Optional[str],
) -> tuple[list[Endpoint], list[AuthMechanism], list[str]]:
    from playwright.sync_api import sync_playwright

    endpoints: dict[tuple[str, str], Endpoint] = {}
    auth_kinds: dict[AuthKind, AuthMechanism] = {}
    schema_builders: dict[tuple[str, str], object] = {}
    notes: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not login)
        ctx_kwargs: dict = {}
        if storage_state and not login:
            try:
                ctx_kwargs["storage_state"] = storage_state
            except Exception:
                pass
        context = browser.new_context(**ctx_kwargs)

        if creds.headers:
            context.set_extra_http_headers(creds.headers)
        if creds.cookies:
            cookies = [
                {"name": k, "value": v, "url": f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"}
                for k, v in creds.cookies.items()
            ]
            try:
                context.add_cookies(cookies)
            except Exception:
                pass

        page = context.new_page()

        def on_response(response) -> None:
            try:
                req = response.request
                url = req.url
            except Exception:
                return
            if not _same_scope(url, scope_hosts):
                return
            try:
                ctype = response.headers.get("content-type", "")
            except Exception:
                ctype = ""
            if not _looks_like_api(url, ctype, req.resource_type):
                return
            _record(url, req, response, ctype, endpoints, auth_kinds, schema_builders)

        page.on("response", on_response)

        if login:
            notes.append("Chế độ --login: hãy đăng nhập trong cửa sổ trình duyệt, xong rồi quay lại terminal.")
            page.goto(target, wait_until="domcontentloaded")
            input("Đăng nhập xong thì nhấn Enter để tiếp tục thu thập... ")
            if storage_state:
                context.storage_state(path=storage_state)
                notes.append(f"Đã lưu phiên đăng nhập vào {storage_state}")

        # Crawl theo link điều hướng
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(target, 0)]
        while queue and len(visited) < max_pages:
            url, d = queue.pop(0)
            url = urldefrag(url)[0]
            if url in visited or not _same_scope(url, scope_hosts):
                continue
            visited.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception:
                continue
            if d < depth:
                for link in _collect_links(page, url, scope_hosts):
                    if link not in visited:
                        queue.append((link, d + 1))

        context.close()
        browser.close()

    # gắn response_schema đã build
    for key, builder in schema_builders.items():
        if key in endpoints and builder is not None:
            try:
                endpoints[key].response_schema = builder.to_schema()
            except Exception:
                pass

    notes.append(f"Phân tích động: thăm {len(visited)} trang, bắt {len(endpoints)} endpoint")
    return list(endpoints.values()), list(auth_kinds.values()), notes


def _collect_links(page, current: str, scope_hosts: list[str]) -> list[str]:
    try:
        hrefs = page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        return []
    out = []
    for h in hrefs or []:
        if not h or h.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        full = urldefrag(urljoin(current, h))[0]
        if _same_scope(full, scope_hosts):
            out.append(full)
    return list(dict.fromkeys(out))


def _record(url, req, response, ctype, endpoints, auth_kinds, schema_builders) -> None:
    method = req.method.upper()
    tmpl = template_from_url(url)
    key = (method, tmpl)
    access, destructive = classify(method, tmpl)

    if key not in endpoints:
        ep = Endpoint(
            id=endpoint_id(method, tmpl),
            method=method,
            url=url,
            path_template=tmpl,
            access=access,
            destructive=destructive,
            evidence=[Evidence(source=Source.network, detail=urlsplit(url).path, confidence=Confidence.high)],
            confidence=Confidence.high,
        )
        endpoints[key] = ep
    else:
        ep = endpoints[key]

    if ctype and ctype not in ep.content_types:
        ep.content_types.append(ctype.split(";")[0])

    try:
        status = response.status
        if status not in ep.status_codes:
            ep.status_codes.append(status)
        if status in (401, 403):
            ep.auth_required = True
        elif status < 400 and ep.auth_required is None:
            ep.auth_required = False
    except Exception:
        pass

    # query params quan sát được
    q = urlsplit(url).query
    if q:
        for pair in q.split("&"):
            name = pair.split("=")[0]
            if name and not any(p.name == name for p in ep.parameters):
                ep.parameters.append(Parameter(name=name, location="query"))

    # header xác thực trên request
    try:
        headers = {k.lower(): v for k, v in req.headers.items()}
    except Exception:
        headers = {}
    _detect_auth_from_headers(headers, url, auth_kinds)

    # dấu hiệu rate-limit trên response
    try:
        rheaders = {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        rheaders = {}
    for h in RATE_LIMIT_HEADERS:
        if h in rheaders and not any(s.header == h for s in ep.rate_limit_signals):
            ep.rate_limit_signals.append(RateLimitSignal(header=h, value=rheaders[h]))

    # build JSON schema từ response body (chỉ JSON)
    if SchemaBuilder is not None and "json" in ctype:
        try:
            body = response.json()
            b = schema_builders.get(key)
            if b is None:
                b = SchemaBuilder()
                schema_builders[key] = b
            b.add_object(body)
        except Exception:
            pass


def _detect_auth_from_headers(headers: dict, url: str, auth_kinds: dict) -> None:
    authz = headers.get("authorization", "")
    if authz.lower().startswith("bearer") and AuthKind.bearer not in auth_kinds:
        auth_kinds[AuthKind.bearer] = AuthMechanism(
            kind=AuthKind.bearer, location="header:Authorization", scheme="Bearer",
            evidence=[Evidence(source=Source.network, detail=urlsplit(url).path, confidence=Confidence.high)],
        )
    elif authz.lower().startswith("basic") and AuthKind.basic not in auth_kinds:
        auth_kinds[AuthKind.basic] = AuthMechanism(
            kind=AuthKind.basic, location="header:Authorization", scheme="Basic",
            evidence=[Evidence(source=Source.network, detail=urlsplit(url).path, confidence=Confidence.high)],
        )
    if "x-api-key" in headers and AuthKind.api_key not in auth_kinds:
        auth_kinds[AuthKind.api_key] = AuthMechanism(
            kind=AuthKind.api_key, location="header:x-api-key",
            evidence=[Evidence(source=Source.network, detail=urlsplit(url).path, confidence=Confidence.high)],
        )
    if "cookie" in headers and AuthKind.cookie not in auth_kinds:
        auth_kinds[AuthKind.cookie] = AuthMechanism(
            kind=AuthKind.cookie, location="header:Cookie",
            evidence=[Evidence(source=Source.network, detail=urlsplit(url).path, confidence=Confidence.medium)],
        )
