"""Kiểm tra dữ liệu đầu vào chặt chẽ.

Mọi giá trị đưa vào script nftables đều đi qua đây. Không bao giờ ghép chuỗi
người dùng nhập thẳng vào lệnh: IP được chuẩn hóa bằng module ipaddress,
port là số nguyên, còn proto/action/direction chỉ nhận giá trị trong danh sách cho phép.
"""
import ipaddress
import re
from typing import Optional

PROTOS = ("tcp", "udp", "any")
ACTIONS = ("accept", "drop")
DIRECTIONS = ("in", "out")

_PORT_RANGE_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Nhận IP hoặc CIDR (IPv4/IPv6). Trả về chuỗi chuẩn hóa, hoặc None nếu để trống."""
    if value is None or str(value).strip() == "":
        return None
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise ValueError(f"Địa chỉ IP/CIDR không hợp lệ: {value!r}")
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def normalize_port(value) -> Optional[str]:
    """Nhận '22' hoặc '1000-2000' (1-65535). Trả về chuỗi chuẩn hóa hoặc None."""
    if value is None or str(value).strip() == "":
        return None
    m = _PORT_RANGE_RE.match(str(value).strip())
    if not m:
        raise ValueError(f"Port không hợp lệ: {value!r}")
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
        raise ValueError("Port phải nằm trong khoảng 1-65535")
    if lo > hi:
        raise ValueError("Port đầu phải nhỏ hơn hoặc bằng port cuối")
    return str(lo) if lo == hi else f"{lo}-{hi}"


def check_choice(name: str, value: str, allowed: tuple) -> str:
    v = str(value).strip().lower()
    if v not in allowed:
        raise ValueError(f"{name} phải là một trong {allowed}, nhận được {value!r}")
    return v


def validate_rule(data: dict) -> dict:
    """Kiểm tra toàn bộ một rule, trả về dict đã chuẩn hóa. Ném ValueError nếu sai."""
    out = {
        "name": (data.get("name") or "").strip()[:100],
        "src_ip": normalize_ip(data.get("src_ip")),
        "dst_ip": normalize_ip(data.get("dst_ip")),
        "port": normalize_port(data.get("port")),
        "proto": check_choice("proto", data.get("proto", "any"), PROTOS),
        "action": check_choice("action", data.get("action", "drop"), ACTIONS),
        "direction": check_choice("direction", data.get("direction", "in"), DIRECTIONS),
        "enabled": 1 if data.get("enabled", True) else 0,
    }
    if out["port"] and out["proto"] == "any":
        raise ValueError("Khi chỉ định port phải chọn giao thức tcp hoặc udp")
    # Không trộn IPv4 và IPv6 trong cùng một rule
    if out["src_ip"] and out["dst_ip"]:
        v1 = ipaddress.ip_network(out["src_ip"]).version
        v2 = ipaddress.ip_network(out["dst_ip"]).version
        if v1 != v2:
            raise ValueError("IP nguồn và IP đích phải cùng phiên bản (IPv4 hoặc IPv6)")
    if not (out["src_ip"] or out["dst_ip"] or out["port"] or out["proto"] != "any"):
        raise ValueError("Rule phải có ít nhất một điều kiện (IP, port hoặc giao thức)")
    return out
