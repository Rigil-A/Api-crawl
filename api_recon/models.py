"""Pydantic models cho file discovery.json (phần 1).

Mỗi trường dữ liệu suy luận được đều kèm `evidence` (tìm thấy ở đâu) và
`confidence` để người dùng biết độ tin cậy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Access(str, Enum):
    read = "read"
    write = "write"
    destructive = "destructive"
    unknown = "unknown"


class Source(str, Enum):
    """Nguồn phát hiện ra endpoint / thông tin."""

    openapi = "openapi"
    graphql = "graphql"
    well_known = "well_known"
    js_static = "js_static"
    network = "network"
    sitemap = "sitemap"
    robots = "robots"


class AuthKind(str, Enum):
    oauth2 = "oauth2"
    openid_connect = "openid_connect"
    bearer = "bearer"
    api_key = "api_key"
    cookie = "cookie"
    basic = "basic"
    digest = "digest"
    unknown = "unknown"


class Evidence(BaseModel):
    """Bằng chứng cho một phát hiện."""

    source: Source
    detail: Optional[str] = None  # ví dụ: URL file JS, path trang bắt được request
    confidence: Confidence = Confidence.medium


class Parameter(BaseModel):
    name: str
    location: str = "query"  # query | path | header | body
    required: Optional[bool] = None
    type: Optional[str] = None
    example: Optional[Any] = None


class RateLimitSignal(BaseModel):
    """Dấu hiệu rate-limit đọc được từ header (không chủ động test ở phần 1)."""

    header: str
    value: Optional[str] = None


class AuthMechanism(BaseModel):
    kind: AuthKind
    location: Optional[str] = None  # ví dụ: "header:Authorization", "query:api_key"
    scheme: Optional[str] = None  # ví dụ: "Bearer"
    realm: Optional[str] = None
    # Metadata OAuth/OIDC công khai (nếu tìm thấy ở .well-known)
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class Endpoint(BaseModel):
    id: str  # hash ổn định của method + path_template
    method: str
    url: str  # URL đầy đủ quan sát được (hoặc dựng từ base + path)
    path_template: str  # path đã chuẩn hóa: /users/{id}
    access: Access = Access.unknown
    destructive: bool = False
    content_types: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    auth_required: Optional[bool] = None
    rate_limit_signals: list[RateLimitSignal] = Field(default_factory=list)
    response_schema: Optional[dict] = None  # JSON Schema suy ra từ response mẫu
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence = Confidence.medium


class ServiceInfo(BaseModel):
    target: str
    scope_hosts: list[str] = Field(default_factory=list)
    title: Optional[str] = None
    collected_at: datetime = Field(default_factory=_utcnow)
    tool_version: str = "0.1.0"


class DiscoveryResult(BaseModel):
    service: ServiceInfo
    auth: list[AuthMechanism] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    pricing_page_url: Optional[str] = None
    notes: list[str] = Field(default_factory=list)

    def model_dump_json_file(self) -> str:
        return self.model_dump_json(indent=2, exclude_none=True)
