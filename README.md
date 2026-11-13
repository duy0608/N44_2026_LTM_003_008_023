# Firewall quản lý IP/Port bằng Dashboard

Tường lửa Linux cho phép/chặn kết nối theo IP, port, giao thức (TCP/UDP), quản lý qua Dashboard web.
Lõi lọc gói tin là **nftables**; backend **FastAPI**; lưu rule bằng **SQLite**.

## Cấu trúc

```
backend/     FastAPI, SQLite, module nftables (người A)
dashboard/   Giao diện HTML/CSS/JS (người B)
tests/       Benchmark và kiểm thử hiệu năng (người C)
docs/        Sơ đồ, ảnh chụp, số liệu, nháp báo cáo
```

## Chạy backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Phát triển (không đụng vào firewall thật):
FW_DRY_RUN=1 uvicorn app.main:app --reload

# Trên VM firewall (cần root, đặt IP quản trị để không tự khóa):
sudo FW_ADMIN_IPS="192.168.56.1" FW_DASHBOARD_PORT=8000 .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Tài liệu API tự sinh: `http://<ip>:8000/docs`

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `FW_DRY_RUN` | `0` | `1` = chỉ sinh script, không áp dụng vào kernel |
| `FW_ADMIN_IPS` | rỗng | Danh sách IP quản trị (cách nhau dấu phẩy), luôn được phép |
| `FW_DB_PATH` | `backend/firewall.db` | Đường dẫn file SQLite |
| `FW_DASHBOARD_PORT` | `8000` | Cổng Dashboard/API |

## API chính

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| GET | `/api/rules` | Danh sách rule |
| POST | `/api/rules` | Thêm rule |
| PUT | `/api/rules/{id}` | Sửa rule |
| PATCH | `/api/rules/{id}/enabled` | Bật/tắt rule |
| DELETE | `/api/rules/{id}` | Xóa rule |
| POST | `/api/sync` | Đồng bộ lại SQLite sang nftables |
| GET | `/api/status` | Trạng thái, số rule, số gói bị chặn |

Định dạng rule (JSON):

```json
{"name": "chặn ssh", "src_ip": "203.0.113.5", "dst_ip": null, "port": "22",
 "proto": "tcp", "action": "drop", "direction": "in", "enabled": true}
```

`proto`: tcp | udp | any (cần tcp/udp khi có port) · `action`: accept | drop · `direction`: in | out ·
`src_ip`/`dst_ip` nhận IP hoặc CIDR (IPv4/IPv6) · `port` nhận `22` hoặc `1000-2000`.

## Kiểm thử

```bash
cd backend && python -m pytest -q
```
