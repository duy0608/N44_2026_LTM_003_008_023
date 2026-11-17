"""Đọc nhật ký nhân, tách các dòng `FWD-DROP`, lưu vào SQLite và phát hiện quét port.

Rule `drop` do hệ thống sinh ra có `log prefix "FWD-DROP id=<mã rule> "`, nên nhân ghi mỗi gói
bị chặn thành một dòng kiểu:
    FWD-DROP id=7 IN=eth0 OUT= ... SRC=10.0.0.5 DST=10.0.0.1 ... PROTO=TCP SPT=51514 DPT=22 ...
Phần phân tích (parse) và phát hiện (ScanDetector) là hàm thuần, kiểm thử được không cần nhân thật.
"""
import os
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, Optional

from . import config, db

_RE_PREFIX = re.compile(r"FWD-DROP id=(\d+)")
_RE_SRC = re.compile(r"\bSRC=(\S+)")
_RE_DST = re.compile(r"\bDST=(\S+)")
_RE_PROTO = re.compile(r"\bPROTO=(\S+)")
_RE_SPT = re.compile(r"\bSPT=(\d+)")
_RE_DPT = re.compile(r"\bDPT=(\d+)")


def parse_log_line(line: str, now: Optional[datetime] = None) -> Optional[dict]:
    """Trả về dict nhật ký nếu là dòng FWD-DROP, ngược lại None."""
    m = _RE_PREFIX.search(line)
    if not m:
        return None
    def grab(rx):
        x = rx.search(line)
        return x.group(1) if x else None
    spt, dpt = grab(_RE_SPT), grab(_RE_DPT)
    proto = grab(_RE_PROTO)
    ts = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    return {
        "ts": ts,
        "rule_id": int(m.group(1)),
        "src_ip": grab(_RE_SRC),
        "dst_ip": grab(_RE_DST),
        "proto": proto.lower() if proto else None,
        "sport": int(spt) if spt else None,
        "dport": int(dpt) if dpt else None,
        "action": "drop",
    }


class ScanDetector:
    """Cảnh báo khi một IP bị chặn hơn `threshold` gói trong `window` giây (mô hình mục 4: N_s(T) > θ).

    Kèm số port đích khác nhau để phân biệt quét port (nhiều port) với một dịch vụ bị gọi dồn dập.
    Sau khi cảnh báo, IP đó được bỏ qua trong một cửa sổ để không báo lặp liên tục.
    """

    def __init__(self, threshold: int, window: int):
        self.threshold = threshold
        self.window = window
        self._events = defaultdict(deque)   # ip -> deque[(thời điểm, dport)]
        self._muted_until = {}              # ip -> thời điểm hết im lặng

    def feed(self, src_ip: Optional[str], dport: Optional[int], t: float) -> Optional[dict]:
        if not src_ip:
            return None
        q = self._events[src_ip]
        q.append((t, dport))
        cutoff = t - self.window
        while q and q[0][0] < cutoff:
            q.popleft()
        if len(q) <= self.threshold:
            return None
        if self._muted_until.get(src_ip, 0) > t:
            return None
        self._muted_until[src_ip] = t + self.window
        return {
            "src_ip": src_ip,
            "drops": len(q),
            "distinct_ports": len({p for _, p in q if p is not None}),
            "window_s": self.window,
            "threshold": self.threshold,
        }


def process_line(line: str, detector: ScanDetector, now: Optional[datetime] = None,
                 clock: Callable[[], float] = time.time) -> Optional[dict]:
    """Xử lý một dòng log: lưu nhật ký, chạy bộ phát hiện, lưu cảnh báo nếu có."""
    entry = parse_log_line(line, now)
    if not entry:
        return None
    db.add_log(entry)
    alert = detector.feed(entry["src_ip"], entry["dport"], clock())
    if alert:
        alert["ts"] = entry["ts"]
        db.add_alert(alert)
        print(f"[CẢNH BÁO] {alert['src_ip']} bị chặn {alert['drops']} gói "
              f"({alert['distinct_ports']} port) trong {alert['window_s']}s")
    return entry


# ----- Nguồn log -----

def _follow_command(cmd: list, stop: threading.Event) -> Iterator[str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            if stop.is_set():
                break
            yield line
    finally:
        proc.terminate()


def _follow_file(path: str, stop: threading.Event) -> Iterator[str]:
    """Theo dõi tệp như `tail -f`, bắt đầu từ cuối tệp (hoặc từ đầu nếu tệp mới tạo)."""
    while not os.path.exists(path) and not stop.is_set():
        time.sleep(0.2)
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while not stop.is_set():
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)


def line_source(stop: threading.Event) -> Optional[Iterable[str]]:
    src = config.LOG_SOURCE
    if src == "none":
        return None
    if src == "journal":
        return _follow_command(["journalctl", "-k", "-f", "-n", "0", "-o", "cat"], stop)
    if src == "dmesg":
        return _follow_command(["dmesg", "--follow", "--facility=kern"], stop)
    return _follow_file(src, stop)


class LogWatcher:
    """Chạy một luồng nền đọc log và ghi vào SQLite."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.detector = ScanDetector(config.ALERT_THRESHOLD, config.ALERT_WINDOW)

    def start(self) -> bool:
        source = line_source(self._stop)
        if source is None:
            return False
        self._thread = threading.Thread(target=self._run, args=(source,), name="logwatch", daemon=True)
        self._thread.start()
        return True

    def _run(self, source: Iterable[str]) -> None:
        try:
            for line in source:
                try:
                    process_line(line, self.detector)
                except Exception as e:  # một dòng lỗi không được làm chết cả luồng
                    print(f"[CẢNH BÁO] Lỗi xử lý dòng log: {e}")
        except FileNotFoundError as e:
            print(f"[CẢNH BÁO] Không đọc được nhật ký nhân ({e}); trang nhật ký sẽ trống")

    def stop(self) -> None:
        self._stop.set()
