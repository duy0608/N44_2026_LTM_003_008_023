"""Cấu hình backend. Đọc từ biến môi trường để không phải sửa code khi triển khai."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Đường dẫn file SQLite
DB_PATH = os.environ.get("FW_DB_PATH", str(BASE_DIR / "firewall.db"))

# Tên bảng nftables do ứng dụng quản lý (không đụng vào bảng khác của hệ thống)
NFT_FAMILY = "inet"
NFT_TABLE = "fwdash"

# DRY_RUN=1: chỉ sinh script nftables, không áp dụng vào kernel (dùng khi phát triển / chạy test)
DRY_RUN = os.environ.get("FW_DRY_RUN", "0") == "1"

# Chống tự khóa: các IP quản trị luôn được phép, ngăn rule chặn nhầm chính mình.
# Ví dụ: FW_ADMIN_IPS="192.168.56.1,192.168.56.10"
ADMIN_IPS = [ip.strip() for ip in os.environ.get("FW_ADMIN_IPS", "").split(",") if ip.strip()]

# Cổng của Dashboard/API và SSH, luôn được mở cho IP quản trị
DASHBOARD_PORT = int(os.environ.get("FW_DASHBOARD_PORT", "8000"))
SSH_PORT = int(os.environ.get("FW_SSH_PORT", "22"))

NFT_BIN = os.environ.get("FW_NFT_BIN", "nft")
NFT_TIMEOUT = 10  # giây

# ----- Đăng nhập -----
# FW_AUTH_DISABLED=1 tắt đăng nhập (chỉ dùng khi phát triển hoặc chạy benchmark).
AUTH_ENABLED = os.environ.get("FW_AUTH_DISABLED", "0") != "1"
ADMIN_USER = os.environ.get("FW_ADMIN_USER", "admin")
# Mật khẩu quản trị khởi tạo lần đầu. Nếu để trống, hệ thống tự sinh và in ra console một lần.
ADMIN_PASSWORD = os.environ.get("FW_ADMIN_PASSWORD", "")
TOKEN_TTL = int(os.environ.get("FW_TOKEN_TTL", "28800"))  # 8 giờ
LOGIN_MAX_FAILS = 5        # số lần sai tối đa
LOGIN_FAIL_WINDOW = 60     # trong khoảng (giây) thì khóa tạm

# ----- Nhật ký và cảnh báo quét port -----
# FW_LOG_SOURCE: "journal" (mặc định, đọc nhật ký nhân qua journalctl), "dmesg",
# "none" (không đọc), hoặc đường dẫn một tệp để theo dõi (dùng khi demo/kiểm thử).
LOG_SOURCE = os.environ.get("FW_LOG_SOURCE", "journal")
# Cảnh báo khi một IP bị chặn hơn ALERT_THRESHOLD gói trong ALERT_WINDOW giây.
ALERT_THRESHOLD = int(os.environ.get("FW_ALERT_THRESHOLD", "20"))
ALERT_WINDOW = int(os.environ.get("FW_ALERT_WINDOW", "10"))

# Thư mục chứa Dashboard (HTML/CSS/JS của người B), FastAPI sẽ phục vụ ở đường dẫn gốc "/"
DASHBOARD_DIR = os.environ.get("FW_DASHBOARD_DIR", str(BASE_DIR.parent / "dashboard"))
