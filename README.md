# api-recon

Công cụ thu thập (discovery) và kiểm tra (inspection) API của một ứng dụng web,
chỉ dùng thư viện mã nguồn mở, miễn phí.

> **Chỉ dùng trên hệ thống bạn được phép kiểm thử (môi trường test có thẩm quyền).**

Tool chia làm 2 phần:

- **Phần 1 — discover**: thu thập càng nhiều endpoint càng tốt với số request tối thiểu,
  kèm thông tin suy luận được (method, loại xác thực, dấu hiệu rate-limit, read/write),
  rồi xuất ra `discovery.json`.
- **Phần 2 — inspect**: nhận `discovery.json` + một `endpoint_id` cụ thể
  và các param/body cần kiểm tra kỹ, gửi một số request **có giới hạn** (`--max-requests`)
  để đo chi tiết (method hỗ trợ, param bắt buộc, size limit, rate limit…),
  xuất ra `inspection.json`.

## Cài đặt

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# bash:
# source .venv/bin/activate

pip install -r requirements.txt
python -m playwright install chromium
```

## Dùng phần 1 (discover)

Chỉ cần URL — tool tự chạy **toàn bộ** các lớp (spec/OpenAPI + .well-known +
GraphQL + JS tĩnh + phân tích động Playwright) và **chỉ thu thập trong domain
của URL đó**.

```bash
# Chạy đầy đủ (mặc định)
python -m api_recon discover https://example.com

# Nhanh hơn, bỏ phân tích động (ít kết quả hơn)
python -m api_recon discover https://example.com --no-dynamic

# Đăng nhập tương tác: mở trình duyệt để tự login, lưu phiên lại
python -m api_recon discover https://example.com --login --storage-state auth.json

# Dùng lại phiên đã lưu / hoặc cấp credential trực tiếp
python -m api_recon discover https://example.com --storage-state auth.json
python -m api_recon discover https://api.example.com --header "Authorization: Bearer xxx"
```

Mặc định ghi ra `discovery.json` (đổi bằng `-o`). Phạm vi luôn cố định theo host
của URL, không có cờ mở rộng domain.

## Credential (dùng chung cho cả 2 phần)

- `--header "Key: Value"` (lặp lại được)
- `--cookie "name=value; name2=value2"`
- `--api-key-header Name:value`
- `--api-key-query name=value`
- `--basic user:pass`
- `--login` — mở trình duyệt để đăng nhập thủ công, lưu phiên vào `--storage-state`
- `--storage-state auth.json` — dùng lại phiên đã lưu

> Credential luôn được **che (redact)** trong file JSON xuất ra.

## Dùng phần 2 (inspect)

Một lệnh chạy **toàn bộ** phép kiểm tra cho một endpoint; tool tự chọn cấu hình
tối ưu (tự chọn field đo size, tự probe mọi field, tự chia ngân sách cho size &
rate). Chỉ cần `discovery.json` + một `endpoint_id`.

```bash
# Xem danh sách endpoint + id
python -m api_recon inspect discovery.json --list

# Chạy toàn bộ kiểm tra cho 1 endpoint (tối thiểu)
python -m api_recon inspect discovery.json -e <endpoint_id>

# Cung cấp dữ liệu request để kiểm tra sát hơn
python -m api_recon inspect discovery.json -e <id> -q q=test -q limit=10        # query
python -m api_recon inspect discovery.json -e <id> --path code=200              # thay {code}
python -m api_recon inspect discovery.json -e <id> --body-field content=hi --body-field title=x
python -m api_recon inspect discovery.json -e <id> --body-json body.json        # body từ file
```

Các phép kiểm tra (đều chạy mặc định): method hỗ trợ (OPTIONS + CORS), auth bắt
buộc hay không (so sánh có/không credential, đọc `WWW-Authenticate`), param bắt
buộc (bỏ từng param xem có 400/422), validation field (gửi rỗng/sai kiểu/null,
trích thông báo lỗi), **size limit** (tìm kiếm nhị phân độ dài field, theo
400/413/414/422/431), **rate limit** (tăng dần tần suất tới khi 429).

Tinh chỉnh khi cần: `--size-field <tên>` (ép field đo size), `--no-size`,
`--no-rate`, `--no-probe`, `--max-requests N` (mặc định 60).

> Mọi phiên inspect bị chặn trên bởi `--max-requests` và dừng ngay khi gặp 429.
> Khi cả size & rate cùng chạy, size chỉ dùng tối đa nửa ngân sách còn lại.
> Chỉ chạy trên hệ thống bạn được phép kiểm thử.

## Hai schema JSON

- `schemas/discovery.schema.json` — validate output phần 1
- `schemas/inspection.schema.json` — validate output phần 2
