"""Lớp giao tiếp với nftables.

Chiến lược: mỗi khi danh sách rule thay đổi, SINH LẠI toàn bộ bảng `inet fwdash`
từ SQLite rồi áp dụng bằng MỘT giao dịch nguyên tử (`nft -f -`). Ưu điểm:
  - Không bao giờ lệch giữa SQLite và kernel (SQLite là nguồn sự thật duy nhất).
  - Đồng bộ lúc khởi động chỉ là gọi lại hàm này.
  - Nếu script lỗi, nftables hoàn tác cả giao dịch, ruleset cũ giữ nguyên.
Không dùng shell: lệnh chạy dạng danh sách tham số, script gửi qua stdin.
"""
import ipaddress
import json
import subprocess
from typing import Optional

from . import config


class NftError(RuntimeError):
    pass


_last_script: str = ""  # script gần nhất (dùng cho dry-run và kiểm thử)


def last_script() -> str:
    return _last_script


# ----- Sinh script -----------------------------------------------------------

def _ip_match(direction_word: str, cidr: str) -> str:
    """direction_word: 'saddr' hoặc 'daddr'. Tự chọn ip/ip6 theo phiên bản địa chỉ."""
    version = ipaddress.ip_network(cidr).version
    return f"{'ip' if version == 4 else 'ip6'} {direction_word} {cidr}"


def rule_to_nft(rule: dict) -> str:
    """Chuyển một rule (dict từ SQLite) thành một dòng rule nftables."""
    parts = []
    if rule["src_ip"]:
        parts.append(_ip_match("saddr", rule["src_ip"]))
    if rule["dst_ip"]:
        parts.append(_ip_match("daddr", rule["dst_ip"]))
    if rule["port"]:
        parts.append(f"{rule['proto']} dport {rule['port']}")
    elif rule["proto"] != "any":
        parts.append(f"meta l4proto {rule['proto']}")
    parts.append("counter")
    if rule["action"] == "drop":
        parts.append(f'log prefix "FWD-DROP id={int(rule["id"])} "')
    parts.append(rule["action"])
    parts.append(f'comment "id={int(rule["id"])}"')
    return " ".join(parts)


def build_ruleset(rules: list) -> str:
    """Sinh script nftables hoàn chỉnh từ danh sách rule đang bật."""
    fam, tbl = config.NFT_FAMILY, config.NFT_TABLE
    inp = ['iifname "lo" accept']
    out = ['oifname "lo" accept']

    # Chống tự khóa: IP quản trị luôn được phép, đứng trước mọi rule của người dùng
    for ip in config.ADMIN_IPS:
        inp.append(_ip_match("saddr", ip) + " accept")
        out.append(_ip_match("daddr", ip) + " accept")

    for r in rules:
        if not r["enabled"]:
            continue
        line = rule_to_nft(r)
        (inp if r["direction"] == "in" else out).append(line)

    def chain(name: str, hook: str, lines: list) -> str:
        body = "\n".join(f"        {ln}" for ln in lines)
        return (
            f"    chain {name} {{\n"
            f"        type filter hook {hook} priority 0; policy accept;\n"
            f"{body}\n"
            f"    }}"
        )

    return (
        f"add table {fam} {tbl}\n"
        f"delete table {fam} {tbl}\n"  # add + delete: không lỗi khi bảng chưa tồn tại
        f"table {fam} {tbl} {{\n"
        f"{chain('input', 'input', inp)}\n"
        f"{chain('output', 'output', out)}\n"
        f"}}\n"
    )


# ----- Thực thi --------------------------------------------------------------

def _run(args: list, stdin: Optional[str] = None) -> str:
    try:
        proc = subprocess.run(
            [config.NFT_BIN, *args],
            input=stdin, capture_output=True, text=True,
            timeout=config.NFT_TIMEOUT, check=False,
        )
    except FileNotFoundError:
        raise NftError("Không tìm thấy lệnh nft. Cài đặt: apt install nftables")
    except subprocess.TimeoutExpired:
        raise NftError("nft chạy quá thời gian cho phép")
    if proc.returncode != 0:
        raise NftError(proc.stderr.strip() or f"nft thoát với mã {proc.returncode}")
    return proc.stdout


def check_ruleset(script: str) -> None:
    """Kiểm tra cú pháp bằng `nft -c` (không áp dụng vào kernel)."""
    _run(["-c", "-f", "-"], stdin=script)


def apply_rules(rules: list) -> str:
    """Sinh và áp dụng ruleset. Trả về script đã dùng."""
    global _last_script
    script = build_ruleset(rules)
    _last_script = script
    if config.DRY_RUN:
        return script
    _run(["-f", "-"], stdin=script)
    return script


def table_exists() -> bool:
    if config.DRY_RUN:
        return bool(_last_script)
    try:
        _run(["list", "table", config.NFT_FAMILY, config.NFT_TABLE])
        return True
    except NftError:
        return False


def counters() -> dict:
    """Trả về {rule_id: {'packets': n, 'bytes': n}} đọc từ bộ đếm của nftables."""
    if config.DRY_RUN or not table_exists():
        return {}
    data = json.loads(_run(["-j", "list", "table", config.NFT_FAMILY, config.NFT_TABLE]))
    result = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        comment = rule.get("comment", "")
        if not comment.startswith("id="):
            continue
        for expr in rule.get("expr", []):
            if "counter" in expr:
                result[int(comment[3:])] = {
                    "packets": expr["counter"]["packets"],
                    "bytes": expr["counter"]["bytes"],
                }
    return result
