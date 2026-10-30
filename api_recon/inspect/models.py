"""Pydantic models cho file inspection.json (phần 2)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MethodSupport(BaseModel):
    allowed_methods: list[str] = Field(default_factory=list)  # từ Allow / CORS
    cors_methods: list[str] = Field(default_factory=list)
    source: str = "OPTIONS"


class AuthCheck(BaseModel):
    required: Optional[bool] = None
    status_with_credentials: Optional[int] = None
    status_without_credentials: Optional[int] = None
    www_authenticate: Optional[str] = None


class ParamRequirement(BaseModel):
    name: str
    location: str
    status_when_omitted: Optional[int] = None
    appears_required: Optional[bool] = None


class FieldProbe(BaseModel):
    field: str
    sent_value_desc: str
    status: Optional[int] = None
    error_excerpt: Optional[str] = None


class SizeLimit(BaseModel):
    field: str
    location: str
    unit: str = "bytes"
    max_accepted: Optional[int] = None
    first_rejected: Optional[int] = None
    reject_status: Optional[int] = None
    note: Optional[str] = None


class RateLimit(BaseModel):
    requests_sent: int = 0
    limit_hit: bool = False
    threshold_requests: Optional[int] = None  # số request tới khi gặp 429
    elapsed_seconds: Optional[float] = None
    retry_after: Optional[str] = None
    observed_headers: dict[str, str] = Field(default_factory=dict)
    note: Optional[str] = None


class InspectedEndpoint(BaseModel):
    id: str
    method: str
    resolved_url: str
    path_template: str
    access: str


class InspectionResult(BaseModel):
    endpoint: InspectedEndpoint
    collected_at: datetime = Field(default_factory=_utcnow)
    tool_version: str = "0.1.0"
    baseline_status: Optional[int] = None
    method_support: Optional[MethodSupport] = None
    auth: Optional[AuthCheck] = None
    required_params: list[ParamRequirement] = Field(default_factory=list)
    field_probes: list[FieldProbe] = Field(default_factory=list)
    size_limit: Optional[SizeLimit] = None
    rate_limit: Optional[RateLimit] = None
    credentials_used: dict[str, Any] = Field(default_factory=dict)
    requests_spent: int = 0
    request_budget: int = 0
    notes: list[str] = Field(default_factory=list)

    def model_dump_json_file(self) -> str:
        return self.model_dump_json(indent=2, exclude_none=True)
