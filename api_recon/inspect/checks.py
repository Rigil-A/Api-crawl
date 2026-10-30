"""Các phép kiểm tra chi tiết cho một endpoint.

Mỗi hàm nhận RequestBudget + một RequestSpec (baseline) và trả về model kết quả.
Tất cả đều tôn trọng ngân sách request; hết ngân sách thì dừng và ghi chú.
"""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .budget import BudgetExceeded, RequestBudget
from .models import (
    AuthCheck,
    FieldProbe,
    MethodSupport,
    ParamRequirement,
    RateLimit,
    SizeLimit,
)

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
    "x-rate-limit-limit",
]

_SIZE_REJECT_STATUSES = {400, 413, 414, 422, 431}


@dataclass
class RequestSpec:
    method: str
    url: str
    query: dict[str, str] = field(default_factory=dict)
    body: Optional[dict[str, Any]] = None  # None = không gửi body

    def clone(self) -> "RequestSpec":
        return RequestSpec(
            method=self.method,
            url=self.url,
            query=dict(self.query),
            body=copy.deepcopy(self.body) if self.body is not None else None,
        )


def _send(budget: RequestBudget, spec: RequestSpec, *, no_credentials: bool = False):
    return budget.send(
        spec.method,
        spec.url,
        params=spec.query or None,
        json=spec.body if spec.body is not None else None,
        no_credentials=no_credentials,
    )


# --- baseline ---------------------------------------------------------------

def baseline(budget: RequestBudget, spec: RequestSpec) -> Optional[int]:
    try:
        r = _send(budget, spec)
    except BudgetExceeded:
        return None
    return r.status


# --- method support ---------------------------------------------------------

def check_methods(budget: RequestBudget, spec: RequestSpec) -> Optional[MethodSupport]:
    if not budget.can_spend(1):
        return None
    try:
        r = budget.send("OPTIONS", spec.url, params=spec.query or None)
    except BudgetExceeded:
        return None
    allow = r.headers.get("allow", "")
    cors = r.headers.get("access-control-allow-methods", "")
    return MethodSupport(
        allowed_methods=[m.strip().upper() for m in allow.split(",") if m.strip()],
        cors_methods=[m.strip().upper() for m in cors.split(",") if m.strip()],
    )


# --- auth required ----------------------------------------------------------

def check_auth(budget: RequestBudget, spec: RequestSpec, has_creds: bool) -> Optional[AuthCheck]:
    if not budget.can_spend(2 if has_creds else 1):
        return None
    out = AuthCheck()
    try:
        if has_creds:
            with_r = _send(budget, spec)
            out.status_with_credentials = with_r.status
        without_r = _send(budget, spec, no_credentials=True)
        out.status_without_credentials = without_r.status
        out.www_authenticate = without_r.headers.get("www-authenticate")
    except BudgetExceeded:
        return out

    if out.status_without_credentials in (401, 403):
        # nếu có cred mà request thành công hơn -> auth thực sự bắt buộc
        if not has_creds or (out.status_with_credentials or 0) < 400:
            out.required = True
    elif out.status_without_credentials is not None and out.status_without_credentials < 400:
        out.required = False
    return out


# --- required params --------------------------------------------------------

def check_required_params(
    budget: RequestBudget, spec: RequestSpec
) -> list[ParamRequirement]:
    out: list[ParamRequirement] = []
    # query params
    for name in list(spec.query.keys()):
        if not budget.can_spend(1):
            break
        trial = spec.clone()
        trial.query.pop(name, None)
        try:
            r = _send(budget, trial)
        except BudgetExceeded:
            break
        out.append(
            ParamRequirement(
                name=name,
                location="query",
                status_when_omitted=r.status,
                appears_required=r.status in (400, 422),
            )
        )
    # body fields (một cấp)
    if isinstance(spec.body, dict):
        for name in list(spec.body.keys()):
            if not budget.can_spend(1):
                break
            trial = spec.clone()
            trial.body.pop(name, None)
            try:
                r = _send(budget, trial)
            except BudgetExceeded:
                break
            out.append(
                ParamRequirement(
                    name=name,
                    location="body",
                    status_when_omitted=r.status,
                    appears_required=r.status in (400, 422),
                )
            )
    return out


# --- field probes (validation / thông báo lỗi lộ giới hạn) ------------------

def probe_fields(
    budget: RequestBudget, spec: RequestSpec, fields: list[str]
) -> list[FieldProbe]:
    out: list[FieldProbe] = []
    variants = [
        ("chuỗi rỗng", ""),
        ("sai kiểu (số)", 999999999),
        ("null", None),
    ]
    for fname in fields:
        loc = _locate_field(spec, fname)
        if loc is None:
            continue
        for desc, val in variants:
            if not budget.can_spend(1):
                return out
            trial = spec.clone()
            _set_field(trial, loc, fname, val)
            try:
                r = _send(budget, trial)
            except BudgetExceeded:
                return out
            out.append(
                FieldProbe(
                    field=fname,
                    sent_value_desc=desc,
                    status=r.status,
                    error_excerpt=_error_excerpt(r.text),
                )
            )
    return out


# --- size limit (tìm kiếm nhị phân) -----------------------------------------

def check_size_limit(
    budget: RequestBudget,
    spec: RequestSpec,
    fname: str,
    max_probe: int = 20,
    max_spend: Optional[int] = None,
) -> Optional[SizeLimit]:
    loc = _locate_field(spec, fname)
    if loc is None:
        return SizeLimit(field=fname, location="?", note="Không tìm thấy field trong request baseline")

    result = SizeLimit(field=fname, location=loc)
    start_spent = budget.spent

    def can_probe() -> bool:
        if not budget.can_spend(1):
            return False
        if max_spend is not None and (budget.spent - start_spent) >= max_spend:
            return False
        return True

    def rejected(n: int) -> Optional[bool]:
        """True nếu bị từ chối vì kích thước; None nếu phải dừng (note được gán)."""
        if not can_probe():
            result.note = f"Dừng do hết hạn mức request cho size-check (mốc cuối thử: {n} bytes)"
            return None
        trial = spec.clone()
        _set_field(trial, loc, fname, "A" * n)
        try:
            r = _send(budget, trial)
        except BudgetExceeded:
            result.note = "Dừng do hết ngân sách request"
            return None
        if r.status == -2:
            # giới hạn phía client (httpx không dựng nổi URL/query dài)
            result.note = (
                "Gặp giới hạn độ dài URL phía client (httpx ~65k ký tự) khi field nằm ở query. "
                "Để đo size limit THỰC của server, hãy dùng field ở body (POST/PUT)."
            )
            return None
        if r.status == -1:
            result.note = (
                f"Tại ~{n} bytes: lỗi mạng/timeout hoặc server đóng kết nối — "
                f"có thể server cắt khi body quá lớn (không có mã trạng thái rõ ràng)."
            )
            return None
        if r.status in _SIZE_REJECT_STATUSES:
            result.reject_status = r.status
            return True
        return False

    # 1) tăng theo cấp số nhân để tìm cận trên bị từ chối
    low_ok = 0
    high_bad = None
    n = 16
    probes = 0
    while probes < max_probe:
        probes += 1
        rj = rejected(n)
        if rj is None:
            result.note = "Dừng do hết ngân sách request hoặc lỗi mạng"
            result.max_accepted = low_ok or None
            return result
        if rj:
            high_bad = n
            break
        low_ok = n
        n *= 4
        if n > 50_000_000:  # trần an toàn ~50MB
            result.max_accepted = low_ok
            result.note = "Không gặp giới hạn tới ~50MB (dừng)"
            return result

    if high_bad is None:
        result.max_accepted = low_ok
        result.note = f"Không gặp giới hạn trong {probes} lần thử (tối đa {low_ok} bytes)"
        return result

    # 2) tìm kiếm nhị phân giữa low_ok và high_bad
    while high_bad - low_ok > 1 and can_probe():
        mid = (low_ok + high_bad) // 2
        rj = rejected(mid)
        if rj is None:
            break
        if rj:
            high_bad = mid
        else:
            low_ok = mid

    result.max_accepted = low_ok
    result.first_rejected = high_bad
    return result


# --- rate limit (tăng dần tần suất tới khi 429) -----------------------------

def check_rate_limit(budget: RequestBudget, spec: RequestSpec) -> RateLimit:
    out = RateLimit()
    t0 = time.perf_counter()
    delay = 0.5  # giãn cách ban đầu (giây), giảm dần -> tăng tần suất
    sent = 0
    while budget.can_spend(1):
        try:
            # gửi trực tiếp, bỏ qua delay mặc định của budget (tự điều nhịp ở đây)
            r = budget.send(spec.method, spec.url, params=spec.query or None,
                            json=spec.body if spec.body is not None else None)
        except BudgetExceeded:
            break
        sent += 1
        # ghi lại header rate-limit nếu có
        for h in RATE_LIMIT_HEADERS:
            if h in r.headers:
                out.observed_headers[h] = r.headers[h]
        if r.status == 429:
            out.limit_hit = True
            out.threshold_requests = sent
            out.retry_after = r.headers.get("retry-after")
            break
        if delay > 0.01:
            time.sleep(delay)
            delay *= 0.6  # tăng dần tần suất
    out.requests_sent = sent
    out.elapsed_seconds = round(time.perf_counter() - t0, 3)
    if not out.limit_hit:
        out.note = f"Không gặp 429 trong {sent} request (ngân sách còn {budget.remaining})"
    return out


# --- helpers ----------------------------------------------------------------

def _locate_field(spec: RequestSpec, fname: str) -> Optional[str]:
    if isinstance(spec.body, dict) and fname in spec.body:
        return "body"
    if fname in spec.query:
        return "query"
    return None


def _set_field(spec: RequestSpec, loc: str, fname: str, value: Any) -> None:
    if loc == "body" and isinstance(spec.body, dict):
        spec.body[fname] = value
    elif loc == "query":
        spec.query[fname] = "" if value is None else str(value)


def _error_excerpt(text: str) -> Optional[str]:
    if not text:
        return None
    snippet = re.sub(r"\s+", " ", text).strip()
    return snippet[:300] or None
