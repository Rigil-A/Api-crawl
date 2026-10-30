"""Ngân sách request + bộ gửi request có đếm, để không vượt --max-requests.

Credential KHÔNG bake vào client; áp theo từng request để có thể test chính xác
trường hợp "không gửi credential" (kiểm tra auth bắt buộc hay không).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from ..auth import Credentials


class BudgetExceeded(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float


class RequestBudget:
    def __init__(
        self,
        client: httpx.Client,
        creds: Credentials,
        max_requests: int,
        delay: float = 0.0,
    ):
        self.client = client
        self.creds = creds
        self.max_requests = max_requests
        self.spent = 0
        self.delay = delay

    @property
    def remaining(self) -> int:
        return self.max_requests - self.spent

    def can_spend(self, n: int = 1) -> bool:
        return self.spent + n <= self.max_requests

    def send(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        json: Any = None,
        content: Any = None,
        headers: Optional[dict] = None,
        no_credentials: bool = False,
    ) -> Response:
        """Gửi 1 request, đếm vào ngân sách. no_credentials=True để test auth."""
        if not self.can_spend(1):
            raise BudgetExceeded()
        self.spent += 1
        if self.delay:
            time.sleep(self.delay)

        req_headers = dict(headers or {})
        req_params = dict(params or {})
        cookies = httpx.Cookies()  # mặc định rỗng

        if not no_credentials:
            for k, v in self.creds.httpx_headers().items():
                req_headers.setdefault(k, v)
            for k, v in self.creds.query_params.items():
                req_params.setdefault(k, v)

        t0 = time.perf_counter()
        try:
            r = self.client.request(
                method.upper(),
                url,
                params=req_params or None,
                json=json,
                content=content,
                headers=req_headers or None,
                cookies=cookies,
            )
        except httpx.InvalidURL as e:
            # httpx từ chối tự dựng URL/query quá dài (giới hạn phía client, không phải server)
            return Response(status=-2, headers={}, text=f"<client-side URL limit: {e}>", elapsed=time.perf_counter() - t0)
        except httpx.HTTPError as e:
            return Response(status=-1, headers={}, text=f"<httpx error: {e}>", elapsed=time.perf_counter() - t0)
        except Exception as e:  # không để bất kỳ lỗi nào làm sập cả phiên inspect
            return Response(status=-1, headers={}, text=f"<error: {type(e).__name__}: {e}>", elapsed=time.perf_counter() - t0)
        return Response(
            status=r.status_code,
            headers={k.lower(): v for k, v in r.headers.items()},
            text=r.text[:2000],
            elapsed=time.perf_counter() - t0,
        )
