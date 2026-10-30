"""Điều phối phần 2: nạp discovery.json, chọn endpoint, chạy các kiểm tra."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import httpx

from ..auth import Credentials
from . import checks
from .budget import RequestBudget
from .checks import RequestSpec
from .models import InspectedEndpoint, InspectionResult

USER_AGENT = "api-recon/0.1 (+authorized-testing)"
_PLACEHOLDER = re.compile(r"\{([^/}]+)\}")


def _load_endpoint(discovery_path: Path, endpoint_id: str) -> dict:
    data = json.loads(discovery_path.read_text(encoding="utf-8"))
    for ep in data.get("endpoints", []):
        if ep.get("id") == endpoint_id:
            return ep
    ids = [ep.get("id") for ep in data.get("endpoints", [])]
    raise KeyError(
        f"Không tìm thấy endpoint id={endpoint_id!r} trong {discovery_path}. "
        f"Có {len(ids)} endpoint; vài id đầu: {ids[:8]}"
    )


def _resolve_url(ep: dict, path_params: dict[str, str]) -> tuple[str, list[str]]:
    """Thay {name} trong URL bằng path param người dùng cung cấp."""
    url = ep.get("url", "")
    missing: list[str] = []

    def repl(m: re.Match) -> str:
        name = m.group(1)
        if name in path_params:
            return str(path_params[name])
        missing.append(name)
        return m.group(0)

    return _PLACEHOLDER.sub(repl, url), missing


def _baseline_fields(query: dict, body: Optional[dict]) -> list[str]:
    """Danh sách field có trong request baseline (body trước, rồi query)."""
    fields: list[str] = []
    if isinstance(body, dict):
        fields.extend(body.keys())
    fields.extend(k for k in query.keys() if k not in fields)
    return fields


def _auto_size_field(query: dict, body: Optional[dict]) -> Optional[str]:
    """Tự chọn field đo size: ưu tiên field body (đo được giới hạn server thật),
    nếu không có body thì lấy field query đầu tiên."""
    if isinstance(body, dict) and body:
        return next(iter(body))
    if query:
        return next(iter(query))
    return None


def run_inspection(
    discovery_path: Path,
    endpoint_id: str,
    creds: Credentials,
    *,
    query: dict[str, str],
    path_params: dict[str, str],
    body: Optional[dict[str, Any]],
    size_field: Optional[str] = None,
    do_size: bool = True,
    do_probe: bool = True,
    do_rate: bool = True,
    max_requests: int = 60,
    delay: float = 0.0,
) -> InspectionResult:
    ep = _load_endpoint(discovery_path, endpoint_id)
    resolved_url, missing = _resolve_url(ep, path_params)

    inspected = InspectedEndpoint(
        id=ep["id"],
        method=ep["method"],
        resolved_url=resolved_url,
        path_template=ep.get("path_template", ""),
        access=ep.get("access", "unknown"),
    )
    result = InspectionResult(
        endpoint=inspected,
        request_budget=max_requests,
        credentials_used=creds.redacted_summary(),
    )
    if missing:
        result.notes.append(
            f"URL còn placeholder chưa gán: {missing}. Hãy cung cấp qua --path <name>=<value>."
        )

    spec = RequestSpec(method=ep["method"], url=resolved_url, query=dict(query), body=body)

    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(headers=headers, follow_redirects=True, timeout=20.0) as client:
        budget = RequestBudget(client, creds, max_requests=max_requests, delay=delay)
        has_creds = not creds.is_empty()

        # 1) baseline
        result.baseline_status = checks.baseline(budget, spec)

        # 2) method support
        result.method_support = checks.check_methods(budget, spec)

        # 3) auth required
        result.auth = checks.check_auth(budget, spec, has_creds)

        # 4) required params
        result.required_params = checks.check_required_params(budget, spec)

        # 5) field probes (validation) — tự probe mọi field trong baseline
        if do_probe:
            fields = _baseline_fields(query, body)
            if fields:
                result.field_probes = checks.probe_fields(budget, spec, fields)

        # 6) size limit — tự chọn field nếu người dùng không ép.
        #    Nếu rate limit cũng bật, chỉ cho size dùng tối đa nửa ngân sách còn lại
        #    để rate limit không bị bỏ đói.
        if do_size:
            field = size_field or _auto_size_field(query, body)
            if field:
                size_cap = None
                if do_rate:
                    size_cap = max(8, budget.remaining // 2)
                result.size_limit = checks.check_size_limit(budget, spec, field, max_spend=size_cap)
            else:
                result.notes.append("Bỏ qua size limit: không có field nào trong request để đo.")

        # 7) rate limit — chạy cuối, dùng phần ngân sách còn lại
        if do_rate:
            result.rate_limit = checks.check_rate_limit(budget, spec)

        result.requests_spent = budget.spent
        if budget.remaining <= 0:
            result.notes.append("Đã dùng hết ngân sách request; một số kiểm tra có thể bị cắt ngắn.")

    return result
