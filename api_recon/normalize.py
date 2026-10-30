"""Chuẩn hóa path và tạo id ổn định cho endpoint.

- Gộp các path có giá trị động (số, UUID, hash dài) thành template: /users/{id}
- Tạo endpoint id = hash(method + path_template) để phần 2 tham chiếu tới.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUMERIC = re.compile(r"^\d+$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_HAS_DIGIT = re.compile(r"\d")


def _is_dynamic_segment(seg: str) -> bool:
    if _UUID.match(seg) or _NUMERIC.match(seg) or _LONG_HEX.match(seg):
        return True
    # chuỗi dài lẫn chữ và số (vd slug id) -> coi là động
    if len(seg) >= 20 and _HAS_DIGIT.search(seg):
        return True
    return False


def path_template(path: str) -> str:
    """/users/123/posts/abcd-... -> /users/{id}/posts/{id}"""
    if not path:
        return "/"
    parts = path.split("/")
    out = []
    for seg in parts:
        if seg and _is_dynamic_segment(seg):
            out.append("{id}")
        else:
            out.append(seg)
    tmpl = "/".join(out)
    return tmpl or "/"


def template_from_url(url: str) -> str:
    return path_template(urlsplit(url).path)


def endpoint_id(method: str, template: str) -> str:
    h = hashlib.sha1(f"{method.upper()} {template}".encode()).hexdigest()
    return h[:10]
