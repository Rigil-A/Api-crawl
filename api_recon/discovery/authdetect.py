"""Dò cơ chế xác thực khi CHƯA có credential.

Chỉ dựa trên tín hiệu công khai, không xâm nhập:
- Gọi một số endpoint đã tìm thấy mà không kèm credential, đọc header
  `WWW-Authenticate` (Bearer / Basic / Digest + realm) khi bị 401.

Chỉ ghi nhận LOẠI và VỊ TRÍ của cơ chế, không dò tìm giá trị bí mật.
"""

from __future__ import annotations

import httpx

from ..models import AuthKind, AuthMechanism, Confidence, Evidence, Source

_SCHEME_MAP = {
    "bearer": AuthKind.bearer,
    "basic": AuthKind.basic,
    "digest": AuthKind.digest,
}


def probe_www_authenticate(
    client: httpx.Client, endpoint_urls: list[str], max_probes: int = 5
) -> list[AuthMechanism]:
    found: dict[AuthKind, AuthMechanism] = {}
    for url in endpoint_urls[:max_probes]:
        try:
            r = client.get(url, timeout=10.0)
        except httpx.HTTPError:
            continue
        if r.status_code != 401:
            continue
        header = r.headers.get("www-authenticate", "")
        if not header:
            continue
        scheme = header.split(" ", 1)[0].strip().lower()
        kind = _SCHEME_MAP.get(scheme, AuthKind.unknown)
        realm = None
        if "realm=" in header.lower():
            try:
                realm = header.lower().split("realm=", 1)[1].split(",")[0].strip().strip('"')
            except Exception:
                realm = None
        if kind not in found:
            found[kind] = AuthMechanism(
                kind=kind,
                location="header:Authorization",
                scheme=scheme.capitalize(),
                realm=realm,
                evidence=[Evidence(source=Source.network, detail=f"WWW-Authenticate @ {url}", confidence=Confidence.high)],
            )
    return list(found.values())
