"""CLI của api-recon. Phần 1: `discover`. (Phần 2: `inspect` — sẽ bổ sung.)"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .auth import Credentials
from .discovery.runner import run_discovery

app = typer.Typer(
    add_completion=False,
    help="Thu thập (discover) và kiểm tra (inspect) API của một ứng dụng web. "
    "Chỉ dùng trên hệ thống bạn được phép kiểm thử.",
)


def _build_creds(
    header: list[str],
    cookie: Optional[str],
    api_key_header: Optional[str],
    api_key_query: Optional[str],
    basic: Optional[str],
    storage_state: Optional[str],
) -> Credentials:
    creds = Credentials()
    for h in header or []:
        creds.add_header(h)
    if cookie:
        creds.add_cookie_string(cookie)
    if api_key_header:
        creds.add_api_key_header(api_key_header)
    if api_key_query:
        creds.add_api_key_query(api_key_query)
    if basic:
        creds.set_basic(basic)
    if storage_state:
        creds.storage_state_path = storage_state
    return creds


@app.command()
def discover(
    target: str = typer.Argument(..., help="URL gốc của ứng dụng, vd https://example.com"),
    output: Path = typer.Option("discovery.json", "-o", "--output", help="File JSON đầu ra"),
    login: bool = typer.Option(False, "--login", help="Mở trình duyệt để đăng nhập thủ công, rồi lưu phiên"),
    storage_state: Optional[str] = typer.Option(None, "--storage-state", help="File lưu/đọc phiên đăng nhập"),
    no_dynamic: bool = typer.Option(False, "--no-dynamic", help="Bỏ phân tích động (nhanh hơn, ít kết quả hơn)"),
    depth: int = typer.Option(2, "--depth", help="Độ sâu crawl link (phân tích động)"),
    max_pages: int = typer.Option(40, "--max-pages", help="Số trang tối đa khi crawl"),
    # credential
    header: list[str] = typer.Option(None, "--header", "-H", help="Header 'Key: Value' (lặp lại được)"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Chuỗi cookie 'a=1; b=2'"),
    api_key_header: Optional[str] = typer.Option(None, "--api-key-header", help="'Name:value'"),
    api_key_query: Optional[str] = typer.Option(None, "--api-key-query", help="'name=value'"),
    basic: Optional[str] = typer.Option(None, "--basic", help="'user:pass'"),
):
    """Phần 1: chạy TOÀN BỘ các lớp thu thập, chỉ trong domain của URL, xuất ra JSON.

    Mặc định chạy đầy đủ: spec/OpenAPI + .well-known + GraphQL + JS tĩnh + phân tích
    động (Playwright). Chỉ cần: api-recon discover <url>
    """
    creds = _build_creds(header, cookie, api_key_header, api_key_query, basic, storage_state)

    typer.echo(f"[*] Thu thập toàn bộ: {target}")
    result = run_discovery(
        target=target,
        creds=creds,
        depth=depth,
        max_pages=max_pages,
        use_dynamic=not no_dynamic,
        login=login,
        storage_state=storage_state,
    )

    output.write_text(result.model_dump_json_file(), encoding="utf-8")

    typer.echo(f"[+] Tìm thấy {len(result.endpoints)} endpoint, {len(result.auth)} cơ chế xác thực "
               f"(phạm vi: {', '.join(result.service.scope_hosts)})")
    for note in result.notes:
        typer.echo(f"    - {note}")
    if not creds.is_empty():
        typer.echo(f"[i] Credential đã dùng (đã che): {creds.redacted_summary()}")
    typer.echo(f"[+] Đã ghi: {output}")
    typer.echo(f"[>] Bước 2: xem id bằng  api-recon inspect {output} --list")


def _parse_kv(items: list[str] | None, kind: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for it in items or []:
        name, sep, value = it.partition("=")
        if not sep:
            raise typer.BadParameter(f"{kind} cần dạng 'name=value': {it!r}")
        out[name.strip()] = value
    return out


@app.command()
def inspect(
    discovery: Path = typer.Argument(..., help="File discovery.json từ phần 1"),
    endpoint: str = typer.Option(None, "--endpoint", "-e", help="endpoint_id cần kiểm tra"),
    output: Path = typer.Option("inspection.json", "-o", "--output", help="File JSON đầu ra"),
    list_endpoints: bool = typer.Option(False, "--list", help="Chỉ liệt kê endpoint trong discovery.json rồi thoát"),
    # dữ liệu request do người dùng chỉ định
    query: list[str] = typer.Option(None, "--query", "-q", help="Query param 'name=value' (lặp lại được)"),
    path: list[str] = typer.Option(None, "--path", help="Path param 'name=value' để thay {name} trong URL"),
    body_field: list[str] = typer.Option(None, "--body-field", help="Field body 'name=value' (lặp lại được)"),
    body_json: Optional[Path] = typer.Option(None, "--body-json", help="File JSON làm body (ghi đè --body-field)"),
    # tinh chỉnh (tùy chọn — mặc định chạy TẤT CẢ kiểm tra)
    size_field: Optional[str] = typer.Option(None, "--size-field", help="Ép field đo size limit (mặc định tự chọn)"),
    no_size: bool = typer.Option(False, "--no-size", help="Bỏ đo size limit"),
    no_rate: bool = typer.Option(False, "--no-rate", help="Bỏ đo rate limit"),
    no_probe: bool = typer.Option(False, "--no-probe", help="Bỏ probe validation field"),
    max_requests: int = typer.Option(60, "--max-requests", help="Trần số request của toàn phiên inspect"),
    delay: float = typer.Option(0.0, "--delay", help="Giãn cách mặc định giữa request (giây)"),
    # credential
    header: list[str] = typer.Option(None, "--header", "-H", help="Header 'Key: Value' (lặp lại được)"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Chuỗi cookie 'a=1; b=2'"),
    api_key_header: Optional[str] = typer.Option(None, "--api-key-header", help="'Name:value'"),
    api_key_query: Optional[str] = typer.Option(None, "--api-key-query", help="'name=value'"),
    basic: Optional[str] = typer.Option(None, "--basic", help="'user:pass'"),
):
    """Phần 2: chạy TOÀN BỘ phép kiểm tra cho MỘT endpoint trong 1 lệnh.

    Mặc định tự chạy: method, auth, param bắt buộc, probe validation, size limit
    (tự chọn field), rate limit. Giả định môi trường test có thẩm quyền.
    Tối thiểu: api-recon inspect discovery.json -e <id>
    """
    if list_endpoints:
        import json as _json

        data = _json.loads(discovery.read_text(encoding="utf-8"))
        for ep in data.get("endpoints", []):
            typer.echo(f"{ep['id']}  {ep['method']:7} {ep['path_template']}  [{ep.get('access')}]")
        raise typer.Exit()

    if not endpoint:
        raise typer.BadParameter("Cần --endpoint <id> (hoặc dùng --list để xem danh sách).")

    creds = _build_creds(header, cookie, api_key_header, api_key_query, basic, None)

    # dựng body
    body: Optional[dict] = None
    if body_json is not None:
        import json as _json

        body = _json.loads(body_json.read_text(encoding="utf-8"))
    elif body_field:
        body = _parse_kv(body_field, "--body-field")

    from .inspect.runner import run_inspection

    typer.echo(f"[*] Inspect {endpoint} — chạy toàn bộ kiểm tra (ngân sách {max_requests} request)")
    result = run_inspection(
        discovery_path=discovery,
        endpoint_id=endpoint,
        creds=creds,
        query=_parse_kv(query, "--query"),
        path_params=_parse_kv(path, "--path"),
        body=body,
        size_field=size_field,
        do_size=not no_size,
        do_probe=not no_probe,
        do_rate=not no_rate,
        max_requests=max_requests,
        delay=delay,
    )

    output.write_text(result.model_dump_json_file(), encoding="utf-8")
    typer.echo(f"[+] baseline_status={result.baseline_status}  requests_spent={result.requests_spent}/{max_requests}")
    if result.method_support and result.method_support.allowed_methods:
        typer.echo(f"[+] methods: {', '.join(result.method_support.allowed_methods)}")
    if result.auth:
        typer.echo(f"[+] auth_required={result.auth.required}")
    if result.required_params:
        req = [p.name for p in result.required_params if p.appears_required]
        typer.echo(f"[+] param bắt buộc: {req or 'không rõ/không có'}")
    if result.size_limit:
        typer.echo(f"[+] size_limit({result.size_limit.field}): max_accepted={result.size_limit.max_accepted} first_rejected={result.size_limit.first_rejected}")
    if result.rate_limit:
        typer.echo(f"[+] rate_limit: hit={result.rate_limit.limit_hit} threshold={result.rate_limit.threshold_requests}")
    for n in result.notes:
        typer.echo(f"    - {n}")
    typer.echo(f"[+] Đã ghi: {output}")


def main() -> None:
    app()
