"""Lớp 3: phân tích JS tĩnh.

Tải HTML trang gốc, tìm các file .js cùng domain, rồi dùng regex trích:
- lời gọi fetch('...') / axios.get('...') ...
- chuỗi đường dẫn dạng '/api/...'
- dấu hiệu xác thực (Bearer, x-api-key, client_id, access_token)

Đây là heuristic: chỉ phát hiện được path tĩnh (không dựng động bằng biến).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from ..classifier import classify
from ..models import AuthKind, AuthMechanism, Confidence, Endpoint, Evidence, Source
from ..normalize import endpoint_id, path_template

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)

# fetch("/api/x", {method: "POST"})  |  axios.post("/api/x")  |  "/api/x"
_FETCH = re.compile(
    r"""fetch\(\s*["'`]([^"'`]+)["'`]\s*(?:,\s*\{([^}]*)\})?""",
    re.IGNORECASE,
)
_AXIOS = re.compile(
    r"""axios\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_PATH_LITERAL = re.compile(r"""["'`](/(?:api|v\d|rest|graphql|gql)/[A-Za-z0-9_\-/{}.:]+)["'`]""")
_METHOD_IN_OPTS = re.compile(r"""method\s*:\s*["'`]([A-Za-z]+)["'`]""", re.IGNORECASE)

_AUTH_PATTERNS = [
    (re.compile(r"""Authorization['"]?\s*[:=]\s*['"`]\s*Bearer""", re.IGNORECASE), AuthKind.bearer, "header:Authorization", "Bearer"),
    (re.compile(r"""x-api-key""", re.IGNORECASE), AuthKind.api_key, "header:x-api-key", None),
    (re.compile(r"""[?&]api[_-]?key=""", re.IGNORECASE), AuthKind.api_key, "query:api_key", None),
    (re.compile(r"""client_id""", re.IGNORECASE), AuthKind.oauth2, None, None),
    (re.compile(r"""access_token""", re.IGNORECASE), AuthKind.oauth2, None, None),
]

MAX_JS_FILES = 40
MAX_JS_BYTES = 3_000_000


def _same_host(url: str, scope_hosts: list[str]) -> bool:
    host = urlsplit(url).netloc.lower()
    return any(host == h or host.endswith("." + h) for h in scope_hosts)


def discover_from_js(
    client: httpx.Client, target: str, scope_hosts: list[str], root_html: str | None = None
) -> tuple[list[Endpoint], list[AuthMechanism], list[str]]:
    base = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
    notes: list[str] = []

    if root_html is not None:
        html = root_html
    else:
        try:
            html = client.get(target, timeout=15.0).text
        except httpx.HTTPError:
            return [], [], [f"Không tải được HTML gốc: {target}"]

    js_urls = []
    for m in _SCRIPT_SRC.finditer(html):
        u = urljoin(target, m.group(1))
        if _same_host(u, scope_hosts) and u.endswith(".js"):
            js_urls.append(u)
    js_urls = list(dict.fromkeys(js_urls))[:MAX_JS_FILES]

    found: dict[tuple[str, str], Endpoint] = {}
    auth_kinds: dict[AuthKind, AuthMechanism] = {}

    # phân tích luôn cả HTML gốc + từng file JS
    corpus = [(target, html)]
    for ju in js_urls:
        try:
            jr = client.get(ju, timeout=15.0)
        except httpx.HTTPError:
            continue
        if jr.status_code == 200 and len(jr.content) <= MAX_JS_BYTES:
            corpus.append((ju, jr.text))

    for src_url, text in corpus:
        _scan_text(text, base, src_url, found, auth_kinds)

    if js_urls:
        notes.append(f"Phân tích {len(corpus) - 1} file JS tĩnh")
    return list(found.values()), list(auth_kinds.values()), notes


def _add_endpoint(
    found: dict, base: str, src_url: str, method: str, raw_path: str
) -> None:
    if raw_path.startswith("http"):
        path = urlsplit(raw_path).path
        url = raw_path
    elif raw_path.startswith("/"):
        path = raw_path
        url = urljoin(base + "/", raw_path.lstrip("/"))
    else:
        return  # bỏ path tương đối không rõ ràng

    tmpl = path_template(path)
    key = (method.upper(), tmpl)
    if key in found:
        return
    access, destructive = classify(method, tmpl)
    found[key] = Endpoint(
        id=endpoint_id(method, tmpl),
        method=method.upper(),
        url=url,
        path_template=tmpl,
        access=access,
        destructive=destructive,
        evidence=[Evidence(source=Source.js_static, detail=src_url, confidence=Confidence.low)],
        confidence=Confidence.low,
    )


def _scan_text(text: str, base: str, src_url: str, found: dict, auth_kinds: dict) -> None:
    for m in _FETCH.finditer(text):
        path, opts = m.group(1), m.group(2) or ""
        method = "GET"
        mm = _METHOD_IN_OPTS.search(opts)
        if mm:
            method = mm.group(1).upper()
        _add_endpoint(found, base, src_url, method, path)

    for m in _AXIOS.finditer(text):
        _add_endpoint(found, base, src_url, m.group(1).upper(), m.group(2))

    for m in _PATH_LITERAL.finditer(text):
        _add_endpoint(found, base, src_url, "GET", m.group(1))

    for pat, kind, loc, scheme in _AUTH_PATTERNS:
        if pat.search(text) and kind not in auth_kinds:
            auth_kinds[kind] = AuthMechanism(
                kind=kind,
                location=loc,
                scheme=scheme,
                evidence=[Evidence(source=Source.js_static, detail=src_url, confidence=Confidence.low)],
            )
