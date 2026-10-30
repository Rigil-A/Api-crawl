"""Lớp 1: tìm spec có sẵn (OpenAPI/Swagger) và metadata .well-known.

Dò một số đường dẫn quen thuộc. Nếu tìm thấy OpenAPI thì trích toàn bộ
endpoint + securitySchemes. Nếu tìm thấy OIDC/OAuth metadata thì trích
authorize/token endpoint, scopes, grant types.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx

from ..classifier import classify
from ..models import (
    AuthKind,
    AuthMechanism,
    Confidence,
    Endpoint,
    Evidence,
    Parameter,
    Source,
)
from ..normalize import endpoint_id, path_template

OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
]

# Trích URL spec nhúng trong trang Swagger UI / Redoc / RapiDoc:
#   url: "/v2/swagger.json"   |   spec-url="..."   |   <redoc spec-url="...">
_SPEC_IN_HTML = re.compile(
    r"""(?:["']?url["']?\s*:\s*|spec-url\s*=\s*|specUrl\s*:\s*)["']([^"']+\.(?:json|yaml|yml))["']""",
    re.IGNORECASE,
)

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


def _base(url: str) -> str:
    s = urlsplit(url)
    return f"{s.scheme}://{s.netloc}"


def discover_specs(
    client: httpx.Client, target: str, root_html: Optional[str] = None
) -> tuple[list[Endpoint], list[AuthMechanism], list[str]]:
    endpoints: list[Endpoint] = []
    auth: list[AuthMechanism] = []
    notes: list[str] = []
    base = _base(target)

    # Gom danh sách URL spec ứng viên: path quen thuộc + URL nhúng trong HTML gốc
    candidates = [urljoin(base + "/", p.lstrip("/")) for p in OPENAPI_PATHS]
    html = root_html if root_html is not None else _fetch_html(client, target)
    for ref in _spec_urls_in_html(html):
        full = urljoin(target, ref)
        if full not in candidates:
            candidates.insert(0, full)  # ưu tiên URL trang tự khai báo

    for url in candidates:
        doc = _get_json(client, url)
        if doc and _looks_like_openapi(doc):
            notes.append(f"Tìm thấy OpenAPI tại {url}")
            eps, auths = _parse_openapi(doc, base, url)
            endpoints.extend(eps)
            auth.extend(auths)
            break  # thường chỉ cần 1 spec

    for p in WELL_KNOWN_PATHS:
        url = urljoin(base + "/", p.lstrip("/"))
        doc = _get_json(client, url)
        if doc and ("authorization_endpoint" in doc or "token_endpoint" in doc):
            notes.append(f"Tìm thấy metadata OAuth/OIDC tại {url}")
            auth.append(_parse_oauth_metadata(doc, url, p))

    return endpoints, auth, notes


def _fetch_html(client: httpx.Client, target: str) -> Optional[str]:
    try:
        r = client.get(target, timeout=10.0)
    except httpx.HTTPError:
        return None
    if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
        return None
    return r.text


def _spec_urls_in_html(html: Optional[str]) -> list[str]:
    """Tìm URL spec do Swagger UI/Redoc/RapiDoc khai báo trong HTML trang gốc."""
    if not html:
        return []
    found = []
    for m in _SPEC_IN_HTML.finditer(html):
        ref = m.group(1)
        if ref not in found:
            found.append(ref)
    return found


def _get_json(client: httpx.Client, url: str) -> Optional[dict]:
    try:
        r = client.get(url, timeout=10.0)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    ctype = r.headers.get("content-type", "")
    if "json" not in ctype and not url.endswith((".json",)):
        # thử parse dù content-type không chuẩn
        pass
    try:
        return r.json()
    except Exception:
        return None


def _looks_like_openapi(doc: dict) -> bool:
    return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc


def _parse_openapi(doc: dict, base: str, spec_url: str) -> tuple[list[Endpoint], list[AuthMechanism]]:
    endpoints: list[Endpoint] = []

    # base URL từ servers (OpenAPI 3) hoặc host+basePath (Swagger 2)
    server = base
    servers = doc.get("servers")
    if isinstance(servers, list) and servers:
        su = servers[0].get("url", "")
        if su.startswith("http"):
            server = su
        elif su:
            server = urljoin(base + "/", su.lstrip("/"))

    paths = doc.get("paths", {})
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            op = op if isinstance(op, dict) else {}
            tmpl = path_template(raw_path)
            op_name = op.get("operationId", "")
            access, destructive = classify(method, tmpl, op_name)
            params = []
            for prm in op.get("parameters", []):
                if isinstance(prm, dict) and "name" in prm:
                    params.append(
                        Parameter(
                            name=prm["name"],
                            location=prm.get("in", "query"),
                            required=prm.get("required"),
                            type=(prm.get("schema") or {}).get("type"),
                        )
                    )
            endpoints.append(
                Endpoint(
                    id=endpoint_id(method, tmpl),
                    method=method.upper(),
                    url=urljoin(server.rstrip("/") + "/", raw_path.lstrip("/")),
                    path_template=tmpl,
                    access=access,
                    destructive=destructive,
                    parameters=params,
                    evidence=[Evidence(source=Source.openapi, detail=spec_url, confidence=Confidence.high)],
                    confidence=Confidence.high,
                )
            )

    auth = _parse_openapi_security(doc, spec_url)
    return endpoints, auth


def _parse_openapi_security(doc: dict, spec_url: str) -> list[AuthMechanism]:
    out: list[AuthMechanism] = []
    comp = doc.get("components", {}) if "openapi" in doc else {}
    schemes = comp.get("securitySchemes") or doc.get("securityDefinitions") or {}
    for name, sch in schemes.items():
        if not isinstance(sch, dict):
            continue
        t = (sch.get("type") or "").lower()
        ev = [Evidence(source=Source.openapi, detail=spec_url, confidence=Confidence.high)]
        if t in ("oauth2",):
            flows = sch.get("flows") or {}
            scopes: list[str] = []
            grants: list[str] = []
            auth_ep = token_ep = None
            for gname, flow in flows.items():
                grants.append(gname)
                if isinstance(flow, dict):
                    scopes.extend((flow.get("scopes") or {}).keys())
                    auth_ep = auth_ep or flow.get("authorizationUrl")
                    token_ep = token_ep or flow.get("tokenUrl")
            out.append(
                AuthMechanism(
                    kind=AuthKind.oauth2,
                    scopes=sorted(set(scopes)),
                    grant_types=grants,
                    authorization_endpoint=auth_ep,
                    token_endpoint=token_ep,
                    evidence=ev,
                )
            )
        elif t in ("http",):
            scheme = (sch.get("scheme") or "").lower()
            if scheme == "basic":
                out.append(AuthMechanism(kind=AuthKind.basic, location="header:Authorization", scheme="Basic", evidence=ev))
            else:
                out.append(AuthMechanism(kind=AuthKind.bearer, location="header:Authorization", scheme="Bearer", evidence=ev))
        elif t in ("apikey",):
            loc = f"{sch.get('in', 'header')}:{sch.get('name', '')}"
            out.append(AuthMechanism(kind=AuthKind.api_key, location=loc, evidence=ev))
        elif t in ("openidconnect",):
            out.append(AuthMechanism(kind=AuthKind.openid_connect, evidence=ev))
    return out


def _parse_oauth_metadata(doc: dict, url: str, path: str) -> AuthMechanism:
    kind = AuthKind.openid_connect if "openid" in path else AuthKind.oauth2
    return AuthMechanism(
        kind=kind,
        authorization_endpoint=doc.get("authorization_endpoint"),
        token_endpoint=doc.get("token_endpoint"),
        scopes=list(doc.get("scopes_supported", []) or []),
        grant_types=list(doc.get("grant_types_supported", []) or []),
        evidence=[Evidence(source=Source.well_known, detail=url, confidence=Confidence.high)],
    )
