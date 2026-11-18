# FWGuard - Firewall cho phép/chặn IP và Port quản lý bằng Dashboard

Tường lửa Linux cho phép **cho phép hoặc chặn kết nối theo địa chỉ IP, port và giao thức (TCP/UDP)**, quản lý bằng một Dashboard web thay cho việc gõ lệnh `nft`. Bộ lọc gói tin thật là **nftables** trong nhân Linux; backend viết bằng **Python + FastAPI**; rule và nhật ký lưu bằng **SQLite**; giao diện là HTML/CSS/JavaScript.

Dự án cuối kỳ môn Lập trình mạng, nhóm N44 (HK1 2026-2027).

## Chức năng

- Thêm, sửa, xóa, bật/tắt rule theo IP nguồn, IP đích (IPv4/IPv6, hỗ trợ CIDR), port hoặc dải port, giao thức TCP/UDP, chiều vào/ra, hành động ACCEPT/DROP.
- Rule có hiệu lực ngay trong nhân qua nftables và được **lưu bền vững**: khởi động lại vẫn tự áp dụng lại.
- Kiểm tra dữ liệu đầu vào chặt chẽ, chống chèn lệnh (không dùng shell, IP/port được chuẩn hóa).
- **Chống tự khóa:** loopback và các IP quản trị luôn được , đứng trước mọi rule của người dùng.
- **Đồng bộ nguyên tử có hoàn tác:** nếu nftables báo lỗi, thay đổi trong SQLite bị hoàn tác, hai bên không bao giờ lệch nhau.
- **Đăng nhập** bằng mật khẩu băm PBKDF2 và token có chữ ký; khóa tạm khi đăng nhập sai nhiều lần.
- **Nhật ký** các gói bị chặn (thời gian, IP nguồn/đích, giao thức, port, rule nào chặn), có bộ lọc.
- **Cảnh báo quét port:** một IP bị chặn quá ngưỡng trong một cửa sổ thời gian sẽ sinh cảnh báo.
- Trạng thái firewall, số rule đang bật, số gói đã bị chặn.

## Kiến trúc

```
Dashboard (HTML/CSS/JS)  ──HTTP, JSON──►  Backend FastAPI (Python)
                                           ├─ kiểm tra dữ liệu, đăng nhập
                                           ├─ quản lý rule ◄──► SQLite (nguồn sự thật duy nhất)
                                           ├─ sinh lại ruleset ──nft -f──► nftables (bảng inet fwdash)
                                           └─ đọc log nhân (FWD-DROP) ──► SQLite ──► cảnh báo
```

Nguyên tắc: **SQLite là nguồn sự thật**. Mỗi lần có thay đổi, backend sinh lại toàn bộ bảng `inet fwdash` từ các rule đang bật và nạp bằng một giao dịch của nftables. Hệ thống chỉ tạo và xóa bảng riêng này, không đụng vào các bảng khác của máy.

Quy tắc khớp: rule xếp theo mã tăng dần, **rule khớp đầu tiên quyết định**; không khớp rule nào thì **cho phép** (chính sách mặc định accept, hoạt động như danh sách chặn).

## Cấu trúc thư mục

```
backend/
  app/            FastAPI: main, auth, db, nft, logwatch, validators, config
  tests/          Kiểm thử đơn vị (pytest)
  requirements.txt
dashboard/
  dashboard_LTM.py   Giao diện: HTML/CSS/JS và một APIRouter trả trang ở "/"
tests/
  benchmark.py       Script đo hiệu năng
docs/                Mô hình toán, sơ đồ, ảnh chụp, số liệu
```

## Yêu cầu

- Máy Linux chạy firewall: Python 3.10 trở lên, `nftables`, quyền root (`sudo`).
  - Ubuntu/Debian: `sudo apt install nftables python3-venv`
  - Arch/EndeavourOS: `sudo pacman -S nftables python`
- Máy khách để thử: `curl`, `nmap`, `iperf3`
- Chỉ **chế độ dry-run** (không chặn gói tin thật) chạy được trên Windows/macOS, vì nftables chỉ có trên Linux.

## Cài đặt

```bash
git clone <link-repo>
cd <thư-mục-repo>/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Chạy

**Phát triển (dry-run, chỉ sinh script, không đụng vào firewall thật):**

```bash
cd backend
FW_DRY_RUN=1 FW_ADMIN_PASSWORD="mat-khau-cua-ban" .venv/bin/uvicorn app.main:app --reload
```

**Chạy thật trên máy firewall (cần root):**

```bash
cd backend
sudo FW_ADMIN_PASSWORD="mat-khau-cua-ban" FW_ADMIN_IPS="<ip-may-quan-tri>" \
     .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Mở `http://<ip-may-firewall>:8000/` để vào Dashboard. Tài liệu API tự sinh: `http://<ip>:8000/docs`.

Gỡ toàn bộ rule do hệ thống tạo (khi cần dọn dẹp): `sudo nft delete table inet fwdash`.

### Đăng nhập

- Tài khoản mặc định: `admin`. Mật khẩu lấy từ `FW_ADMIN_PASSWORD`; nếu không đặt, hệ thống **tự sinh và in ra console đúng một lần** ở lần chạy đầu tiên.
- Tài khoản chỉ được tạo khi cơ sở dữ liệu chưa có người dùng nào. Muốn đổi mật khẩu sau này, dừng server, xóa file `backend/firewall.db` (mất rule và nhật ký đã lưu) rồi chạy lại với mật khẩu mới.
- API đòi tiêu đề `Authorization: Bearer <token>`; lấy token bằng `POST /api/login`.
- Khi chạy benchmark hoặc phát triển có thể tắt đăng nhập bằng `FW_AUTH_DISABLED=1` (không dùng khi triển khai thật).

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `FW_DRY_RUN` | `0` | `1` = chỉ sinh script, không áp dụng vào nhân |
| `FW_ADMIN_IPS` | rỗng | Danh sách IP quản trị (cách nhau dấu phẩy), luôn được phép |
| `FW_ADMIN_USER` | `admin` | Tên tài khoản quản trị |
| `FW_ADMIN_PASSWORD` | tự sinh | Mật khẩu quản trị khởi tạo lần đầu |
| `FW_AUTH_DISABLED` | `0` | `1` = tắt đăng nhập (chỉ để phát triển/benchmark) |
| `FW_TOKEN_TTL` | `28800` | Thời hạn token (giây) |
| `FW_DB_PATH` | `backend/firewall.db` | Đường dẫn file SQLite |
| `FW_LOG_SOURCE` | `journal` | Nguồn log: `journal` (journalctl), `dmesg`, `none` hoặc đường dẫn tệp log |
| `FW_ALERT_THRESHOLD` | `20` | Số gói bị chặn để sinh cảnh báo |
| `FW_ALERT_WINDOW` | `10` | Cửa sổ thời gian cảnh báo (giây) |
| `FW_DASHBOARD_DIR` | `../dashboard` | Thư mục chứa giao diện |

## API

Trừ `/api/login`, mọi API đều cần token.

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| POST | `/api/login` | Đăng nhập, trả về token |
| GET | `/api/rules` | Danh sách rule |
| GET | `/api/rules/{id}` | Xem một rule |
| POST | `/api/rules` | Thêm rule |
| PUT | `/api/rules/{id}` | Sửa rule |
| PATCH | `/api/rules/{id}/enabled` | Bật hoặc tắt rule |
| DELETE | `/api/rules/{id}` | Xóa rule |
| POST | `/api/sync` | Đồng bộ lại SQLite sang nftables |
| GET | `/api/status` | Trạng thái, số rule, số gói bị chặn, cảnh báo gần đây |
| GET | `/api/logs` | Nhật ký gói bị chặn; lọc `src_ip`, `dport`, `rule_id`, `since`, `limit`, `offset` |
| GET | `/api/logs/top` | Các IP bị chặn nhiều nhất |
| GET | `/api/alerts` | Cảnh báo quét port |

**Định dạng rule (JSON):**

```json
{"name": "chặn ssh", "src_ip": "203.0.113.5", "dst_ip": null, "port": "22",
 "proto": "tcp", "action": "drop", "direction": "in", "enabled": true}
```

- `proto`: `tcp` | `udp` | `any` (bắt buộc là `tcp` hoặc `udp` khi có `port`).
- `action`: `accept` | `drop`. `direction`: `in` | `out`.
- `src_ip`, `dst_ip`: một IP hoặc CIDR (IPv4/IPv6); hai IP trong cùng một rule phải cùng phiên bản.
- `port`: một port (`22`) hoặc dải (`1000-2000`), trong khoảng 1-65535.
- Mỗi rule cần ít nhất một điều kiện (IP, port hoặc giao thức).

## Nhật ký và cảnh báo

Rule `drop` ghi log nhân với tiền tố `FWD-DROP id=<mã rule>`. Backend đọc nhật ký nhân qua `journalctl -k` (cần root), tách các dòng này và lưu vào SQLite để Dashboard lọc và hiển thị. Khi một IP bị chặn hơn `FW_ALERT_THRESHOLD` gói trong `FW_ALERT_WINDOW` giây, hệ thống sinh một cảnh báo (kèm số port khác nhau, để phân biệt quét port với một dịch vụ bị gọi dồn dập).

Chỉ gói bị **chặn** mới được ghi log. Máy không dùng systemd: đặt `FW_LOG_SOURCE=dmesg`. Muốn thử không cần nhân thật: đặt `FW_LOG_SOURCE=/đường/dẫn/file.log` rồi ghi các dòng `FWD-DROP ...` vào tệp đó.

## Demo nhanh với hai máy

Máy A (firewall, đã chạy backend) và máy B (Kali, đóng vai client/kẻ tấn công), cùng một mạng.

1. Trên máy A mở web thử: `python3 -m http.server 8080`.
2. Trên máy B: `curl -m 3 http://<ip-A>:8080` → truy cập được.
3. Trên Dashboard thêm rule: nguồn = IP máy B, port 8080, TCP, DROP.
4. Trên máy B chạy lại `curl -m 3 ...` → bị treo (bị chặn). Trên máy A: `sudo nft list ruleset` thấy rule, bộ đếm gói tăng.
5. Tắt rule trên Dashboard → `curl` thông lại ngay. Bật lại → bị chặn lại.
6. Trang nhật ký hiện các gói bị chặn. Chạy `nmap -p 1-100 <ip-A>` từ máy B → trang cảnh báo hiện IP của máy B.
7. Dừng và chạy lại backend → rule vẫn còn và được áp dụng lại.
8. Thử thêm rule với IP sai (`1.1.1.1; reboot`) hoặc port `70000` → bị từ chối.

## Kiểm thử

```bash
cd backend
python -m pytest -q
```

Kỳ vọng: 58 ca đạt. Một ca kiểm tra cú pháp bằng `nft -c` chỉ chạy khi có quyền root, nên với người dùng thường nó hiển thị là skipped. Chạy bằng `sudo .venv/bin/python -m pytest -q -rs` để chạy luôn ca đó.

**Benchmark hiệu năng:** `tests/benchmark.py`. Khởi động backend với `FW_AUTH_DISABLED=1` để script không cần token. Cách chạy chi tiết và kết quả nằm trong `docs/` và báo cáo. [người C bổ sung lệnh chạy cụ thể]

## Xử lý sự cố

| Hiện tượng | Cách xử lý |
|---|---|
| Mở `/` báo 404 | Kiểm tra `dashboard/dashboard_LTM.py` có trong thư mục và đã `git pull` bản mới nhất; xem console có dòng `Không nạp được ...` không |
| API trả 401 | Chưa đăng nhập hoặc token hết hạn; đăng nhập lại |
| Sai mật khẩu dù đã đặt `FW_ADMIN_PASSWORD` | Mật khẩu chỉ áp dụng lần đầu tạo cơ sở dữ liệu; xem mục Đăng nhập để đặt lại |
| Máy khác không vào được Dashboard | Chạy với `--host 0.0.0.0` (không phải `127.0.0.1`); kiểm tra mạng có chặn giao tiếp giữa các máy không (Wi-Fi công cộng thường có); dùng hotspot hoặc dây LAN |
| Rule thêm được nhưng không chặn | Kiểm tra `sudo ufw status` (tắt ufw nếu đang bật), và `sudo nft list ruleset` có bảng `inet fwdash` không |
| Trang nhật ký trống | Chạy `sudo journalctl -k -f` rồi tạo lưu lượng bị chặn xem có dòng `FWD-DROP` không; nếu không dùng systemd đặt `FW_LOG_SOURCE=dmesg`; backend phải chạy bằng `sudo` |
| Lỗi `nft: command not found` | Cài nftables theo mục Yêu cầu |

## Hạn chế

- Chính sách mặc định là cho phép; chưa hỗ trợ chính sách mặc định chặn kèm theo dõi trạng thái kết nối (conntrack).
- Mỗi thay đổi sinh lại toàn bộ ruleset nên chi phí tăng theo số rule; khớp rule rời là O(n), chưa tối ưu bằng tập (set) của nftables.
- Backend cần quyền root và Dashboard dùng HTTP; khi triển khai thật cần HTTPS và giới hạn IP truy cập Dashboard.
- Chỉ ghi log các gói bị chặn.

## Nhóm thực hiện

| Thành viên | Vai trò | Phần phụ trách |
|---|---|---|
|    [Phạm Viết Duy, 106230008]   | Backend và lõi firewall | `backend/`: API, nftables, SQLite, đăng nhập, nhật ký, cảnh báo |
|   [Hứa Quốc Cường, 106230003]  | Dashboard | `dashboard/`: giao diện quản trị |
| [Cao Minh Phụng, 106230023]  | Kiểm thử và đánh giá | `tests/`, `docs/`: benchmark, mô hình toán, số liệu |
