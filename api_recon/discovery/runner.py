"""Điều phối phần 1: chạy lần lượt các lớp, gộp và khử trùng kết quả."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from ..auth import Credentials
from ..models import (
    AuthMechanism,
    DiscoveryResult,
    Endpoint,
    ServiceInfo,
)
from . import authdetect, graphql, jsanalysis, spec

USER_AGENT = "api-recon/0.1 (+authorized-testing)"


def _merge_endpoints(groups: list[list[Endpoint]]) -> list[Endpoint]:
    """Gộp theo (method, path_template). Ưu tiên bản có confidence cao hơn,
    gộp parameters / evidence / content_types."""
    order = {"high": 3, "medium": 2, "low": 1}
    merged: dict[tuple[str, str], Endpoint] = {}
    for group in groups:
        for ep in group:
            key = (ep.method, ep.path_template)
            if key not in merged:
                merged[key] = ep.model_copy(deep=True)
                continue
            cur = merged[key]
            # gộp evidence
            cur.evidence.extend(e for e in ep.evidence if e not in cur.evidence)
            # gộp parameters theo tên
            names = {p.name for p in cur.parameters}
            for p in ep.parameters:
                if p.name not in names:
                    cur.parameters.append(p)
                    names.add(p.name)
            for c in ep.content_types:
                if c not in cur.content_types:
                    cur.content_types.append(c)
            for s in ep.status_codes:
                if s not in cur.status_codes:
                    cur.status_codes.append(s)
            for rl in ep.rate_limit_signals:
                if not any(x.header == rl.header for x in cur.rate_limit_signals):
                    cur.rate_limit_signals.append(rl)
            if cur.auth_required is None:
                cur.auth_required = ep.auth_required
            if cur.response_schema is None:
                cur.response_schema = ep.response_schema
            # nâng confidence lên mức cao nhất
            if order.get(ep.confidence.value, 0) > order.get(cur.confidence.value, 0):
                cur.confidence = ep.confidence
                cur.url = ep.url
    return list(merged.values())


def _merge_auth(groups: list[list[AuthMechanism]]) -> list[AuthMechanism]:
    merged: dict[tuple, AuthMechanism] = {}
    for group in groups:
        for a in group:
            key = (a.kind, a.location)
            if key not in merged:
                merged[key] = a.model_copy(deep=True)
            else:
                cur = merged[key]
                cur.evidence.extend(e for e in a.evidence if e not in cur.evidence)
                cur.scopes = sorted(set(cur.scopes) | set(a.scopes))
                cur.grant_types = sorted(set(cur.grant_types) | set(a.grant_types))
                cur.authorization_endpoint = cur.authorization_endpoint or a.authorization_endpoint
                cur.token_endpoint = cur.token_endpoint or a.token_endpoint
    return list(merged.values())


def run_discovery(
    target: str,
    creds: Credentials,
    depth: int = 2,
    max_pages: int = 40,
    use_dynamic: bool = True,
    login: bool = False,
    storage_state: str | None = None,
) -> DiscoveryResult:
    # Phạm vi thu thập LUÔN cố định là host của URL mục tiêu.
    scope_hosts = [urlsplit(target).netloc.lower()]

    ep_groups: list[list[Endpoint]] = []
    auth_groups: list[list[AuthMechanism]] = []
    notes: list[str] = []

    headers = {"User-Agent": USER_AGENT, **creds.httpx_headers()}
    with httpx.Client(headers=headers, params=creds.query_params or None, follow_redirects=True) as client:
        # Tải HTML trang gốc MỘT lần, dùng chung cho lớp spec + lớp JS (bớt request).
        root_html = _fetch_text(client, target)

        # Lớp 1: spec + well-known
        eps, auths, n = spec.discover_specs(client, target, root_html=root_html)
        ep_groups.append(eps)
        auth_groups.append(auths)
        notes += n

        # Lớp 2: GraphQL
        geps, gn = graphql.discover_graphql(client, target)
        ep_groups.append(geps)
        notes += gn

        # Lớp 3: JS tĩnh
        jeps, jauths, jn = jsanalysis.discover_from_js(client, target, scope_hosts, root_html=root_html)
        ep_groups.append(jeps)
        auth_groups.append(jauths)
        notes += jn

        # Lớp 4: động (Playwright)
        if use_dynamic or login:
            try:
                deps, dauths, dn = _run_dynamic_safe(
                    target, scope_hosts, creds, depth, max_pages, login, storage_state
                )
                ep_groups.append(deps)
                auth_groups.append(dauths)
                notes += dn
            except Exception as e:  # pragma: no cover
                notes.append(f"Phân tích động lỗi/bỏ qua: {e}")

        # Dò WWW-Authenticate nếu chưa có credential
        if creds.is_empty():
            all_eps_so_far = [ep for g in ep_groups for ep in g if ep.method == "GET"]
            urls = [ep.url for ep in all_eps_so_far][:5]
            if urls:
                wa = authdetect.probe_www_authenticate(client, urls)
                auth_groups.append(wa)
                if wa:
                    notes.append("Dò WWW-Authenticate: phát hiện cơ chế xác thực")

    endpoints = _merge_endpoints(ep_groups)
    endpoints.sort(key=lambda e: (e.path_template, e.method))
    auth = _merge_auth(auth_groups)

    return DiscoveryResult(
        service=ServiceInfo(target=target, scope_hosts=scope_hosts),
        auth=auth,
        endpoints=endpoints,
        notes=notes,
    )


def _fetch_text(client: httpx.Client, url: str) -> str | None:
    try:
        r = client.get(url, timeout=15.0)
    except httpx.HTTPError:
        return None
    if r.status_code == 200 and "html" in r.headers.get("content-type", ""):
        return r.text
    return None


def _run_dynamic_safe(target, scope_hosts, creds, depth, max_pages, login, storage_state):
    from . import dynamic

    return dynamic.run_dynamic(target, scope_hosts, creds, depth, max_pages, login, storage_state)
