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
