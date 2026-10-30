"""Module credential dùng chung cho cả 2 phần.

Gom các cách cung cấp thông tin xác thực về một đối tượng `Credentials`:
- header tùy ý (lặp lại được)
- cookie
- api key ở header hoặc query
- basic auth
- phiên Playwright đã lưu (storage_state)

Mọi giá trị đều có thể redact khi ghi ra JSON.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Credentials:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    storage_state_path: Optional[str] = None

    # --- builders -----------------------------------------------------------

    def add_header(self, raw: str) -> None:
        name, _, value = raw.partition(":")
        if not value:
            raise ValueError(f"Header không hợp lệ (cần 'Key: Value'): {raw!r}")
        self.headers[name.strip()] = value.strip()

    def add_cookie_string(self, raw: str) -> None:
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, value = part.partition("=")
            self.cookies[name.strip()] = value.strip()

    def add_api_key_header(self, raw: str) -> None:
        name, _, value = raw.partition(":")
        if not value:
            raise ValueError(f"api-key-header cần dạng 'Name:value': {raw!r}")
        self.headers[name.strip()] = value.strip()

    def add_api_key_query(self, raw: str) -> None:
        name, _, value = raw.partition("=")
        if not value:
            raise ValueError(f"api-key-query cần dạng 'name=value': {raw!r}")
        self.query_params[name.strip()] = value.strip()

    def set_basic(self, raw: str) -> None:
        user, _, pw = raw.partition(":")
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.headers["Authorization"] = f"Basic {token}"

    # --- usage --------------------------------------------------------------

    def cookie_header(self) -> Optional[str]:
        if not self.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def httpx_headers(self) -> dict[str, str]:
        out = dict(self.headers)
        ch = self.cookie_header()
        if ch:
            out["Cookie"] = ch
        return out

    def is_empty(self) -> bool:
        return not (self.headers or self.cookies or self.query_params or self.storage_state_path)

    # --- redaction ----------------------------------------------------------

    def redacted_summary(self) -> dict:
        """Mô tả credential để ghi vào JSON mà KHÔNG lộ giá trị."""

        def mask(_: str) -> str:
            return "***"

        return {
            "headers": {k: mask(v) for k, v in self.headers.items()},
            "cookies": {k: mask(v) for k, v in self.cookies.items()},
            "query_params": {k: mask(v) for k, v in self.query_params.items()},
            "storage_state": bool(self.storage_state_path),
        }
