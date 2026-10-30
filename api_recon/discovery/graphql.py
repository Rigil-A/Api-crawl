"""Lớp 2: GraphQL introspection.

Dò vài đường dẫn GraphQL quen thuộc, gửi introspection query. Nếu có schema,
mỗi field của Query/Mutation được ghi thành một 'endpoint' logic.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import httpx

from ..models import Access, Confidence, Endpoint, Evidence, Parameter, Source
from ..normalize import endpoint_id

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name args { name type { name kind ofType { name } } } }
        }
      }
    }
    """
}


def _base(url: str) -> str:
    s = urlsplit(url)
    return f"{s.scheme}://{s.netloc}"


def discover_graphql(client: httpx.Client, target: str) -> tuple[list[Endpoint], list[str]]:
    base = _base(target)
    for p in GRAPHQL_PATHS:
        url = urljoin(base + "/", p.lstrip("/"))
        try:
            r = client.post(url, json=_INTROSPECTION, timeout=10.0)
        except httpx.HTTPError:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json().get("data", {}).get("__schema")
        except Exception:
            continue
        if not data:
            continue
        return _parse_schema(data, url), [f"GraphQL introspection thành công tại {url}"]
    return [], []


def _parse_schema(schema: dict, url: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")
    types = {t.get("name"): t for t in schema.get("types", []) if isinstance(t, dict)}

    def emit(type_name: str | None, access: Access, label: str) -> None:
        if not type_name or type_name not in types:
            return
        for f in types[type_name].get("fields") or []:
            fname = f.get("name")
            if not fname:
                continue
            tmpl = f"/graphql#{label}.{fname}"
            params = [
                Parameter(name=a.get("name", ""), location="body")
                for a in (f.get("args") or [])
                if a.get("name")
            ]
            endpoints.append(
                Endpoint(
                    id=endpoint_id("POST", tmpl),
                    method="POST",
                    url=url,
                    path_template=tmpl,
                    access=access,
                    parameters=params,
                    evidence=[Evidence(source=Source.graphql, detail=url, confidence=Confidence.high)],
                    confidence=Confidence.high,
                )
            )

    emit(query_type, Access.read, "Query")
    emit(mutation_type, Access.write, "Mutation")
    return endpoints
