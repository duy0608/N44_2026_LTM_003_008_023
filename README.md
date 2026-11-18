# FWGuard — Hệ thống quản trị tường lửa Linux (IP/Port) qua Web Dashboard

**FWGuard** là giải pháp quản trị tường lửa trực quan được xây dựng phía trên bộ lọc gói tin mức nhân **nftables** của hệ điều hành Linux. Thay vì phải thao tác trực tiếp thông qua các dòng lệnh `nft` phức tạp và dễ phát sinh sai sót, người quản trị có thể dễ dàng kiểm soát lưu lượng mạng (cho phép hoặc chặn kết nối theo địa chỉ IP, cổng dịch vụ và giao thức TCP/UDP) thông qua giao diện **Web Dashboard**.

Về mặt kiến trúc, hệ thống tận dụng hiệu năng xử lý gói tin trực tiếp trong nhân của **nftables**, kết hợp với tầng dịch vụ backend viết bằng **Python (FastAPI)**, cơ sở dữ liệu nhúng **SQLite** để lưu trữ bền vững và giao diện web xây dựng từ **HTML/CSS/JavaScript**.

> **Thông tin học phần:** Đồ án cuối kỳ môn **Lập trình mạng** — Nhóm **N44** (Học kỳ 1, năm học 2026–2027).  
> **Đơn vị:** Khoa Điện tử và Trí tuệ nhân tạo — Trường Đại học Bách khoa, Đại học Đà Nẵng.  
> **Giảng viên hướng dẫn:** TS. Nguyễn Văn Hiếu.

## Tính năng chính

* **Quản lý quy tắc (Rule) toàn diện:** Hỗ trợ thêm, sửa, xóa và bật/tắt linh hoạt các quy tắc lọc gói tin dựa trên địa chỉ IP nguồn/đích (hỗ trợ cả IPv4, IPv6 và ký pháp mạng con CIDR), cổng đơn lẻ hoặc dải cổng, giao thức (`TCP`/`UDP`), chiều lưu lượng (`in`/`out`) và hành động (`ACCEPT`/`DROP`).
* **Thực thi tức thời và lưu trữ bền vững:** Mọi quy tắc được áp dụng trực tiếp vào nhân Linux thông qua `nftables` và đồng thời lưu trữ trong `SQLite`, đảm bảo cấu hình tường lửa tự động được khôi phục nguyên trạng sau khi khởi động lại hệ thống.
* **Kiểm tra dữ liệu chặt chẽ và chống chèn lệnh:** Dữ liệu đầu vào (IP, dải cổng, giao thức) được chuẩn hóa và xác thực nghiêm ngặt. Các lệnh hệ thống được thực thi trực tiếp qua luồng chuẩn mà không gọi qua `shell`, loại bỏ hoàn toàn nguy cơ tấn công chèn lệnh (Command Injection).
* **Cơ chế chống tự khóa (Anti-lockout):** Lưu lượng nội bộ (`loopback`) và danh sách địa chỉ IP quản trị viên luôn được ưu tiên cho phép (`ACCEPT`) ở vị trí đầu tiên trong bảng quy tắc, ngăn chặn triệt để rủi ro quản trị viên tự chặn mất kết nối điều khiển của chính mình.
* **Đồng bộ nguyên tử kèm hoàn tác (Atomic Sync & Rollback):** Hệ thống nạp toàn bộ tập quy tắc mới trong một giao dịch duy nhất (`nft -f`). Nếu `nftables` phát hiện lỗi cú pháp hoặc từ chối áp dụng, mọi thay đổi vừa ghi trong `SQLite` sẽ tự động được hoàn tác để đảm bảo tính nhất quán tuyệt đối giữa cơ sở dữ liệu và nhân hệ điều hành.
* **Xác thực và bảo vệ phiên truy cập:** Tích hợp cơ chế đăng nhập sử dụng mật khẩu băm `PBKDF2`, cấp phát token có chữ ký xác thực và tự động khóa tạm thời khi phát hiện đăng nhập sai nhiều lần.
* **Giám sát nhật ký tập trung:** Tự động thu thập, phân tách và lưu trữ thông tin các gói tin bị chặn (thời gian, IP nguồn/đích, giao thức, cổng đích, mã quy tắc áp dụng) kèm bộ lọc tra cứu trực quan trên giao diện web.
* **Cảnh báo dò quét cổng (Port Scan Detection):** Theo dõi tần suất gói tin bị chặn theo từng địa chỉ IP trong một cửa sổ thời gian xác định và phát cảnh báo sớm khi vượt ngưỡng bất thường.
* **Thống kê trạng thái thời gian thực:** Hiển thị tổng quan tình trạng hoạt động của tường lửa, số lượng quy tắc đang kích hoạt và bộ đếm số gói tin đã bị chặn.

## Kiến trúc hệ thống

Hệ thống được thiết kế theo mô hình phân lớp rõ ràng gồm 4 thành phần chính:

```text
Dashboard (HTML/CSS/JS)  ──HTTP, JSON──►  Backend FastAPI (Python)
                                           ├─ Kiểm tra dữ liệu, xác thực đăng nhập
                                           ├─ Quản lý rule ◄──► SQLite (Nguồn sự thật duy nhất)
                                           ├─ Sinh lại ruleset ──nft -f──► nftables (Bảng inet fwdash)
                                           └─ Đọc log nhân (FWD-DROP) ──► SQLite ──► Cảnh báo
```

### Nguyên lý vận hành cốt lõi

1. **SQLite là nguồn sự thật duy nhất (Single Source of Truth):** Mọi thay đổi về quy tắc đều được cập nhật vào cơ sở dữ liệu trước. Sau đó, backend sẽ biên dịch lại toàn bộ tập quy tắc từ danh sách các rule đang bật và nạp nguyên tử vào bảng riêng biệt có tên `inet fwdash`. Cách tiếp cận này giúp hệ thống hoạt động độc lập, không làm ảnh hưởng đến các bảng tường lửa sẵn có khác của hệ điều hành.
2. **Nguyên tắc khớp đầu tiên (First-Match Semantics):** Các quy tắc trong mỗi chuỗi (`input` hoặc `output`) được sắp xếp theo thứ tự mã định danh tăng dần. Khi một gói tin đi qua, quy tắc hợp lệ đầu tiên khớp với thông số gói tin sẽ quyết định hành động xử lý. Nếu gói tin không khớp với bất kỳ quy tắc nào, hệ thống áp dụng chính sách mặc định là cho phép (`ACCEPT`), vận hành tương tự mô hình danh sách chặn (Blacklist).

## Cấu trúc thư mục

```text
N44_2026_LTM_003_008_023/
├── backend/
│   ├── app/               # Mã nguồn FastAPI: main, auth, db, nft, logwatch, validators, config
│   ├── tests/             # Bộ kiểm thử đơn vị tự động (pytest)
│   └── requirements.txt   # Danh sách thư viện Python phụ thuộc
├── dashboard/
│   └── dashboard_LTM.py   # Giao diện Web Dashboard (HTML/CSS/JS) và APIRouter phục vụ trang chủ
├── tests/
│   └── benchmark.py       # Kịch bản đo đạc và đánh giá hiệu năng hệ thống (E1–E5)
└── docs/
    └── data/              # Dữ liệu đo hiệu năng (.csv), mô hình toán học, sơ đồ và ảnh chụp thực nghiệm
```

## Yêu cầu môi trường

* **Máy chủ chạy tường lửa (Firewall Host):** Hệ điều hành Linux (thử nghiệm trên Kali Linux / Ubuntu) có cài đặt sẵn `nftables` (`v1.1.7`), môi trường **Python 3.10 trở lên** (đã kiểm thử trên Python `3.14.8`, FastAPI `0.163.1`) và quyền quản trị hệ thống (`root`/`sudo`).
  * *Trên Ubuntu / Debian / Kali Linux:*
    ```bash
    sudo apt update && sudo apt install -y nftables python3-venv
    ```
* **Máy khách phục vụ kiểm thử (Client / Attacker):** Cài đặt các công cụ mạng tiêu chuẩn gồm `curl`, `nmap` và `iperf3`.
* **Lưu ý về tính tương thích:** Do `nftables` là thành phần đặc thù của nhân Linux, hệ thống chỉ hỗ trợ chạy ở **chế độ mô phỏng (`dry-run`)** trên các nền tảng như Windows hoặc macOS để phục vụ mục đích phát triển giao diện và kiểm tra cú pháp.

## Cài đặt

Thực hiện sao chép kho mã nguồn và thiết lập môi trường ảo Python theo các bước sau:

```bash
git clone https://github.com/duy0608/N44_2026_LTM_003_008_023.git
cd N44_2026_LTM_003_008_023

python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

## Hướng dẫn vận hành

### 1. Chế độ phát triển (Dry-Run)

Ở chế độ này, hệ thống chỉ thực hiện kiểm tra dữ liệu, lưu vào `SQLite` và sinh kịch bản cấu hình mà không can thiệp vào tường lửa thật của hệ điều hành:

```bash
FW_DRY_RUN=1 FW_ADMIN_PASSWORD="mat-khau-cua-ban" .venv/bin/uvicorn backend.app.main:app --reload
```

### 2. Chế độ vận hành thực tế (Yêu cầu quyền root)

Để áp dụng các quy tắc lọc gói tin vào nhân Linux và đọc nhật ký hệ thống, cần khởi chạy dịch vụ với quyền `sudo -E` (giữ nguyên biến môi trường):

```bash
export FW_DRY_RUN=0
export FW_ADMIN_PASSWORD="mat-khau-cua-ban"
export FW_ADMIN_IPS="<ip-may-quan-tri>"
sudo -E .venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

* **Truy cập Dashboard:** Mở trình duyệt tại địa chỉ `http://<ip-may-firewall>:8000/`.
* **Tài liệu API tương tác (Swagger UI):** Truy cập `http://<ip-may-firewall>:8000/docs`.
* **Dọn dẹp cấu hình tường lửa (khi cần):** Chạy lệnh `sudo nft delete table inet fwdash` để gỡ bỏ hoàn toàn bảng quy tắc do FWGuard quản lý.

### 3. Cơ chế đăng nhập và quản lý tài khoản

* Tài khoản quản trị mặc định có tên đăng nhập là `admin`. Mật khẩu khởi tạo được lấy từ biến môi trường `FW_ADMIN_PASSWORD`; nếu biến này để trống, hệ thống sẽ **tự động sinh một mật khẩu ngẫu nhiên và hiển thị duy nhất một lần** trên cửa sổ dòng lệnh khi khởi chạy lần đầu.
* Thông tin tài khoản chỉ được khởi tạo khi cơ sở dữ liệu chưa có người dùng. Để đặt lại mật khẩu mới, cần dừng dịch vụ, xóa tệp cơ sở dữ liệu `backend/firewall.db` (lưu ý thao tác này sẽ xóa toàn bộ quy tắc và nhật ký hiện có) rồi khởi động lại với giá trị `FW_ADMIN_PASSWORD` mới.
* Mọi yêu cầu gọi API quản trị (ngoại trừ `/api/login`) đều phải đính kèm tiêu đề xác thực `Authorization: Bearer <token>`.
* Trong quá trình chạy kịch bản đo hiệu năng tự động, có thể tạm tắt cơ chế xác thực bằng cách đặt `FW_AUTH_DISABLED=1` *(khuyến cáo không sử dụng tùy chọn này trong môi trường vận hành thực tế)*.

## Cấu hình biến môi trường

Hệ thống hỗ trợ tùy chỉnh linh hoạt các tham số vận hành thông qua biến môi trường:

| Biến môi trường | Giá trị mặc định | Mô tả chức năng |
| :--- | :--- | :--- |
| `FW_DRY_RUN` | `0` | Đặt bằng `1` để chạy mô phỏng (chỉ sinh kịch bản, không nạp vào nhân Linux). |
| `FW_ADMIN_IPS` | *(rỗng)* | Danh sách các địa chỉ IP quản trị (phân tách bằng dấu phẩy) luôn được ưu tiên cho phép. |
| `FW_ADMIN_USER` | `admin` | Tên đăng nhập của tài khoản quản trị viên. |
| `FW_ADMIN_PASSWORD` | *(tự sinh)* | Mật khẩu khởi tạo cho tài khoản quản trị trong lần chạy đầu tiên. |
| `FW_AUTH_DISABLED` | `0` | Đặt bằng `1` để bỏ qua bước kiểm tra token (chỉ dùng khi phát triển hoặc chạy benchmark). |
| `FW_TOKEN_TTL` | `28800` | Thời gian hiệu lực của phiên đăng nhập tính bằng giây (mặc định 8 giờ). |
| `FW_DB_PATH` | `backend/firewall.db` | Đường dẫn lưu trữ tệp cơ sở dữ liệu SQLite. |
| `FW_LOG_SOURCE` | `journal` | Nguồn thu thập log nhân: `journal` (qua `journalctl`), `dmesg`, `none` hoặc đường dẫn tệp log cụ thể. |
| `FW_ALERT_THRESHOLD` | `20` | Ngưỡng số lượng gói tin bị chặn tối đa từ một IP trước khi phát cảnh báo. |
| `FW_ALERT_WINDOW` | `10` | Cửa sổ thời gian (tính bằng giây) dùng để thống kê tần suất gói tin bị chặn. |
| `FW_DASHBOARD_DIR` | `../dashboard` | Đường dẫn tới thư mục chứa mã nguồn giao diện Dashboard. |

## Danh sách giao diện lập trình ứng dụng (API)

Tất cả các điểm cuối (endpoint) dưới đây đều yêu cầu xác thực bằng token hợp lệ, ngoại trừ API đăng nhập:

| Phương thức | Đường dẫn | Chức năng |
| :--- | :--- | :--- |
| `POST` | `/api/login` | Xác thực thông tin đăng nhập và cấp phát token. |
| `GET` | `/api/rules` | Truy xuất danh sách toàn bộ quy tắc hiện có. |
| `GET` | `/api/rules/{id}` | Xem thông tin chi tiết của một quy tắc theo mã định danh. |
| `POST` | `/api/rules` | Tạo mới một quy tắc và đồng bộ vào `nftables`. |
| `PUT` | `/api/rules/{id}` | Cập nhật nội dung của một quy tắc đã tồn tại. |
| `PATCH` | `/api/rules/{id}/enabled` | Thay đổi trạng thái kích hoạt (bật hoặc tắt) của quy tắc. |
| `DELETE` | `/api/rules/{id}` | Xóa bỏ một quy tắc khỏi hệ thống. |
| `POST` | `/api/sync` | Ép buộc đồng bộ lại toàn bộ dữ liệu từ `SQLite` sang `nftables`. |
| `GET` | `/api/status` | Lấy thông tin trạng thái tường lửa, số lượng quy tắc, tổng gói bị chặn và cảnh báo mới nhất. |
| `GET` | `/api/logs` | Truy vấn danh sách nhật ký gói tin bị chặn (hỗ trợ lọc theo `src_ip`, `dport`, `rule_id`, `since`, `limit`, `offset`). |
| `GET` | `/api/logs/top` | Thống kê danh sách các địa chỉ IP bị chặn nhiều nhất. |
| `GET` | `/api/alerts` | Truy xuất danh sách cảnh báo hành vi dò quét cổng. |

### Cấu trúc dữ liệu quy tắc (JSON Payload)

```json
{
  "name": "Chặn truy cập SSH trái phép",
  "src_ip": "203.0.113.5",
  "dst_ip": null,
  "port": "22",
  "proto": "tcp",
  "action": "drop",
  "direction": "in",
  "enabled": true
}
```

**Các ràng buộc dữ liệu đầu vào:**

* `proto`: Nhận một trong các giá trị `tcp`, `udp` hoặc `any` *(bắt buộc phải là `tcp` hoặc `udp` nếu quy tắc có chỉ định `port`)*.
* `action`: Nhận giá trị `accept` (cho phép) hoặc `drop` (chặn).
* `direction`: Nhận giá trị `in` (luồng đi vào) hoặc `out` (luồng đi ra).
* `src_ip`, `dst_ip`: Một địa chỉ IP đơn lẻ hoặc dải mạng CIDR (hỗ trợ cả IPv4 và IPv6); hai địa chỉ trong cùng một quy tắc phải thuộc cùng một phiên bản giao thức IP.
* `port`: Một số hiệu cổng đơn lẻ (ví dụ `"22"`) hoặc một dải cổng liên tục (ví dụ `"1000-2000"`), nằm trong miền giá trị hợp lệ từ $1$ đến $65535$.
* Mỗi quy tắc phải xác định tối thiểu một điều kiện lọc (địa chỉ IP, cổng hoặc giao thức).

## Cơ chế ghi nhật ký và phát hiện quét cổng

Mỗi quy tắc mang hành động `drop` khi biên dịch sang `nftables` đều được gắn kèm chỉ thị ghi log mức nhân với tiền tố định danh `FWD-DROP id=<mã_quy_tắc>`. Tiến trình nền của backend sẽ liên tục đọc luồng nhật ký thông qua lệnh `journalctl -k` hoặc `dmesg` (yêu cầu quyền `root`), phân tích cú pháp để trích xuất các thông tin cốt lõi và lưu trữ vào bảng nhật ký trong `SQLite`.

Khi một địa chỉ IP nguồn có số lượng gói tin bị chặn vượt quá ngưỡng `FW_ALERT_THRESHOLD` trong khoảng thời gian `FW_ALERT_WINDOW` giây, hệ thống sẽ khởi tạo một bản ghi cảnh báo. Cảnh báo này thống kê kèm theo số lượng cổng đích khác nhau mà IP đó đã gửi gói tin tới, giúp quản trị viên dễ dàng phân biệt giữa hành vi dò quét cổng diện rộng (port scan) với tình huống một dịch vụ đơn lẻ bị gửi yêu cầu dồn dập.

> **Mẹo triển khai:** Trên các hệ thống không sử dụng `systemd` hoặc cần đọc trực tiếp từ bộ đệm vòng của nhân, có thể thiết lập `FW_LOG_SOURCE=dmesg`. Đối với môi trường thử nghiệm không can thiệp nhân thật, có thể trỏ `FW_LOG_SOURCE=/duong/dan/file.log` để hệ thống đọc dữ liệu mô phỏng từ tệp văn bản.

## Kịch bản kiểm thử thực tế với hai máy

Mô hình thử nghiệm thực tế được triển khai trên mạng nội bộ (`192.168.1.0/24`) gồm hai máy: **Máy Firewall** (máy ảo Kali Linux `192.168.1.182` chạy FWGuard) và **Máy Client / Giả lập tấn công** (máy thật Windows `192.168.1.180`).

1. **Khởi tạo dịch vụ mẫu trên máy Firewall:** Mở một máy chủ web thử nghiệm ở cổng `8080`:
   ```bash
   python3 -m http.server 8080
   ```
2. **Kiểm tra kết nối ban đầu từ máy Client (PowerShell):** Chạy lệnh `curl.exe -I --connect-timeout 3 http://192.168.1.182:8080`. Kết quả trả về `HTTP/1.0 200 OK` chứng tỏ kết nối thông suốt.
3. **Thiết lập quy tắc chặn trên Dashboard:** Truy cập giao diện FWGuard, tạo quy tắc mới với thông số: *IP nguồn = `192.168.1.180`*, *Cổng = `8080`*, *Giao thức = `TCP`*, *Hướng = `Inbound`*, *Hành động = `DROP`*.
4. **Xác minh hiệu lực chặn:** Thực hiện lại lệnh `curl.exe -I --connect-timeout 3 http://192.168.1.182:8080` từ máy Client; kết nối bị treo và báo lỗi `Connection timed out`. Kiểm tra trên máy Firewall bằng lệnh `sudo nft list ruleset` để xác nhận quy tắc đã xuất hiện trong bảng `inet fwdash` và bộ đếm gói tin (`counter`) tăng lên.
5. **Kiểm tra tính năng bật/tắt tức thời:** Tắt trạng thái quy tắc vừa tạo trên Dashboard và thử kết nối lại từ máy Client; lưu lượng được khôi phục ngay lập tức (`200 OK`). Khi bật lại quy tắc, kết nối tiếp tục bị chặn.
6. **Kiểm tra nhật ký và cảnh báo quét cổng:** Quan sát các gói tin bị từ chối hiển thị tại trang **Nhật ký chặn** (bao gồm cả lưu lượng UDP tới cổng `5353`). Tiếp theo, tạo quy tắc chặn dải cổng `1-1000` và chạy lệnh quét cổng từ máy Client:
   ```powershell
   nmap -Pn -sT -T4 -p 1-1000 192.168.1.182
   ```
   Hệ thống sẽ phát hiện hành vi bất thường và hiển thị cảnh báo đối với địa chỉ IP `192.168.1.180` tại trang **Cảnh báo quét port**.
7. **Kiểm tra tính bền vững sau khởi động lại:** Dừng tiến trình backend và khởi chạy lại; toàn bộ quy tắc đã lưu vẫn được bảo toàn và tự động nạp lại vào nhân Linux.
8. **Kiểm thử khả năng phòng vệ đầu vào:** Thử tạo quy tắc chứa chuỗi độc hại (ví dụ IP là `1.1.1.1; reboot`) hoặc cổng ngoài phạm vi (`70000`); hệ thống lập tức từ chối và trả về mã lỗi xác thực dữ liệu (`422 Unprocessable Entity`).

## Kiểm thử tự động và đánh giá hiệu năng

### 1. Kiểm thử đơn vị (Unit Testing)

Chạy bộ kiểm thử tự động trong thư mục `backend` bằng công cụ `pytest`:

```bash
cd backend
../.venv/bin/python -m pytest -q
```

* **Kết quả kỳ vọng:** Toàn bộ **58 ca kiểm thử** đều đạt trạng thái thành công. Lưu ý rằng ca kiểm thử xác minh cú pháp trực tiếp qua nhân (`nft -c`) yêu cầu quyền quản trị hệ thống, do đó sẽ hiển thị trạng thái bỏ qua (`skipped`) nếu chạy dưới quyền người dùng thông thường. Để thực thi đầy đủ toàn bộ bộ kiểm thử, sử dụng lệnh:
  ```bash
  sudo ../.venv/bin/python -m pytest -q -rs
  ```

### 2. Đo đạc và đánh giá hiệu năng (Benchmarking)

Trước khi chạy kịch bản đo tự động `tests/benchmark.py`, khởi chạy backend ở chế độ thực tế và tạm tắt xác thực token (`FW_AUTH_DISABLED=1`):

```bash
export FW_DRY_RUN=0
export FW_AUTH_DISABLED=1
export FW_ADMIN_IPS="127.0.0.1"
export FW_LOG_SOURCE="dmesg"
sudo -E .venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

* **Đo thời gian nạp quy tắc thủ công (Baseline E1):**
  ```bash
  sudo .venv/bin/python tests/benchmark.py rule-time
  ```
* **Đo thời gian thêm/xóa quy tắc qua API hệ thống (E1):**
  ```bash
  .venv/bin/python tests/benchmark.py --api http://127.0.0.1:8000 api-rule-time
  ```
* **Nạp tải quy tắc phục vụ đo độ trễ RTT và thông lượng TCP (E2 & E3):**
  ```bash
  # Nạp N = 10, 100 hoặc 1000 quy tắc rời qua API
  .venv/bin/python tests/benchmark.py --api http://127.0.0.1:8000 load-api --mode rules --n 1000

  # Dọn dẹp quy tắc API và nạp đối chứng 1.000 IP vào cấu trúc nftables set
  .venv/bin/python tests/benchmark.py --api http://127.0.0.1:8000 cleanup-api
  sudo .venv/bin/python tests/benchmark.py load --mode set --n 1000
  ```

### Tóm tắt kết quả thực nghiệm (E1–E5)

| Thí nghiệm | Chỉ số đánh giá | Kết quả đo đạc thực tế |
| :--- | :--- | :--- |
| **E1: Thời gian ghi quy tắc** | Tốc độ thêm trung bình mỗi rule (`ms/rule`) | Hệ thống đạt **$22,3 \pm 1,9\text{ ms}$** ($N=10$), **$22,6 \pm 0,5\text{ ms}$** ($N=100$) và **$39,0 \pm 8,3\text{ ms}$** ($N=1.000$); so với lệnh `nft` thủ công là $2,21\text{–}2,78\text{ ms/rule}$. |
| **E2: Độ trễ mạng** | Thời gian khứ hồi trung bình (RTT) | Duy trì ở mức **$< 1\text{ ms}$** xuyên suốt các mốc từ $0$ đến $1.000$ quy tắc. |
| **E3: Thông lượng TCP** | Băng thông truyền tải qua `iperf3` | Đạt **$2.190\text{ Mbit/s}$** (Baseline) và **$2.680\text{ Mbit/s}$** với $1.000$ rule rời (không suy giảm hiệu năng); tăng lên **$5.410\text{ Mbit/s}$** khi gom $1.000$ IP vào `nftables set`. |
| **E4: Độ chính xác lọc gói** | Tỷ lệ xử lý đúng trên 8 ca kiểm thử | Đạt **$8/8\text{ ca}$ ($100\%$)** cho cả TCP, UDP, CIDR, bật/tắt tức thời và quy tắc ưu tiên khớp đầu tiên. |
| **E5: Phát hiện quét cổng** | Thời gian cảnh báo & tỷ lệ báo nhầm | Phát hiện quét `nmap` sau **$\approx 5\text{ giây}$** (ngưỡng $\theta = 20\text{ gói} / T = 10\text{ giây}$); **0 bỏ sót** và **0 báo nhầm** với lưu lượng HTTP hợp lệ. |

## Xử lý sự cố thường gặp

| Hiện tượng gặp phải | Nguyên nhân và hướng khắc phục |
| :--- | :--- |
| Truy cập đường dẫn `/` báo lỗi `404 Not Found` | Kiểm tra sự tồn tại của tệp `dashboard/dashboard_LTM.py` và đảm bảo đã đồng bộ mã nguồn mới nhất; kiểm tra log console xem có thông báo lỗi nạp giao diện hay không. |
| Các yêu cầu API trả về mã lỗi `401 Unauthorized` | Phiên làm việc chưa được xác thực hoặc token đã hết thời hạn hiệu lực; thực hiện đăng nhập lại để lấy token mới. |
| Đăng nhập báo sai mật khẩu dù đã thiết lập `FW_ADMIN_PASSWORD` | Biến môi trường mật khẩu chỉ có tác dụng trong lần khởi tạo cơ sở dữ liệu đầu tiên; xem hướng dẫn đặt lại cơ sở dữ liệu tại mục **Cơ chế đăng nhập**. |
| Máy tính khác trong mạng không thể truy cập Dashboard | Đảm bảo backend được khởi chạy với tham số `--host 0.0.0.0` (thay vì `127.0.0.1`). Kiểm tra cấu hình mạng (sử dụng Bridged Adapter trên máy ảo, mạng LAN hoặc điểm phát sóng di động thay vì Wi-Fi công cộng có bật cô lập thiết bị). |
| Quy tắc đã thêm thành công nhưng lưu lượng không bị chặn | Kiểm tra và tắt các trình quản lý tường lửa khác đang chạy song song (ví dụ `sudo ufw disable`); dùng lệnh `sudo nft list ruleset` để xác nhận bảng `inet fwdash` đã được nạp. |
| Trang nhật ký không hiển thị dữ liệu gói tin bị chặn | Đảm bảo backend được chạy dưới quyền `sudo`. Kiểm tra luồng log nhân bằng lệnh `sudo journalctl -k -f` hoặc chuyển cấu hình sang `FW_LOG_SOURCE=dmesg`. |
| Báo lỗi `nft: command not found` | Gói công cụ `nftables` chưa được cài đặt trên máy chủ; cài đặt lại theo hướng dẫn tại mục **Yêu cầu môi trường**. |

## Hạn chế hiện tại và hướng phát triển

* **Mô hình chính sách mặc định:** Hệ thống hiện áp dụng chính sách mặc định cho phép (`ACCEPT`) và chưa tích hợp cơ chế theo dõi trạng thái kết nối (`conntrack`) để hỗ trợ mô hình chặn mặc định (`Default-Deny`).
* **Độ phức tạp xử lý và đồng bộ:** Việc duyệt các quy tắc rời rạc có độ phức tạp tuyến tính $O(n)$ theo số lượng quy tắc, đồng thời mỗi thao tác ghi đều biên dịch lại toàn bộ bảng cấu hình (tổng thời gian nạp $N$ quy tắc tăng theo $O(N^2)$). Trong các phiên bản tiếp theo, hệ thống có thể tối ưu hóa bằng cách tích hợp cấu trúc tập hợp (`nftables sets`) trực tiếp vào API/Dashboard để giảm độ phức tạp tra cứu xuống $O(1)$ hoặc $O(\log n)$, kết hợp cập nhật tăng dần.
* **Bảo mật kênh truyền quản trị:** Giao diện Dashboard hiện giao tiếp qua giao thức `HTTP` cơ bản và yêu cầu backend chạy với quyền `root`. Khi triển khai trong môi trường sản xuất thực tế, cần cấu hình thêm lớp mã hóa `HTTPS` (thông qua Reverse Proxy như Nginx) và giới hạn chặt chẽ dải IP được phép truy cập cổng quản trị.
* **Phạm vi ghi nhận nhật ký:** Hệ thống hiện chỉ trích xuất và lưu trữ log đối với các gói tin bị từ chối (`DROP`) nhằm tối ưu hiệu năng lưu trữ.

## Nhóm thực hiện

| Thành viên | Mã số sinh viên | Vai trò chính | Phân công phụ trách | Tỷ lệ đóng góp |
| :--- | :--- | :--- | :--- | :---: |
| **Phạm Viết Duy** | `106230008` | Kiến trúc Backend & Lõi Firewall | Phát triển thư mục `backend/`: thiết kế API RESTful, module biên dịch và đồng bộ `nftables`, quản trị `SQLite`, xác thực người dùng, thu thập nhật ký và phát hiện quét cổng. | 33,33% |
| **Hứa Quốc Cường** | `106230003` | Giao diện người dùng (Frontend) | Phát triển thư mục `dashboard/`: thiết kế và xây dựng giao diện Web Dashboard quản lý quy tắc, theo dõi nhật ký, trạng thái hệ thống và cảnh báo. | 33,33% |
| **Cao Minh Phụng** | `106230023` | Kiểm thử & Đánh giá hiệu năng | Phát triển thư mục `tests/` và `docs/`: xây dựng mô hình toán học, thiết lập kịch bản đo đạc benchmark (E1–E5), kiểm thử độ chính xác và tổng hợp số liệu báo cáo. | 33,33% |
