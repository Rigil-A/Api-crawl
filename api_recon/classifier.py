"""Phân loại endpoint read / write / destructive.

Dựa trên HTTP method, có điều chỉnh bằng heuristic theo tên path/operation
(một số POST thực chất chỉ đọc: search, query, list, batchGet...).
"""

from __future__ import annotations

import re

from .models import Access

_READ_HINTS = re.compile(
    r"(search|query|list|get|lookup|find|fetch|read|export|download|batchget)",
    re.IGNORECASE,
)
_WRITE_HINTS = re.compile(
    r"(create|update|insert|add|set|upload|import|edit|save|patch)",
    re.IGNORECASE,
)
_DESTRUCTIVE_HINTS = re.compile(
    r"(delete|remove|destroy|purge|drop|revoke|cancel|terminate)",
    re.IGNORECASE,
)


def classify(method: str, path_template: str, operation_name: str = "") -> tuple[Access, bool]:
    """Trả về (access, destructive)."""
    m = method.upper()
    hint_text = f"{path_template} {operation_name}"

    if m in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return Access.read, False

    if m == "DELETE":
        return Access.destructive, True

    if m in ("POST", "PUT", "PATCH"):
        if _DESTRUCTIVE_HINTS.search(hint_text):
            return Access.destructive, True
        # POST nhưng tên cho thấy chỉ đọc -> read
        if m == "POST" and _READ_HINTS.search(hint_text) and not _WRITE_HINTS.search(hint_text):
            return Access.read, False
        return Access.write, False

    return Access.unknown, False
