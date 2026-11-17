"""Kiểm thử đăng nhập, đọc log, phát hiện quét port và các API nhật ký/cảnh báo."""
import time

import pytest
from fastapi.testclient import TestClient

from app import auth, config, db, logwatch
from app.logwatch import ScanDetector, parse_log_line, process_line

TCP_LINE = ("FWD-DROP id=7 IN=eth0 OUT= MAC=aa:bb SRC=192.168.1.50 DST=192.168.1.10 LEN=60 TTL=64 "
            "PROTO=TCP SPT=51514 DPT=22 WINDOW=64240 SYN URGP=0")
ICMP_LINE = "kernel: FWD-DROP id=3 IN=eth0 OUT= SRC=10.0.0.9 DST=10.0.0.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0"
V6_LINE = "FWD-DROP id=1 IN=eth0 SRC=2001:db8::5 DST=2001:db8::1 PROTO=UDP SPT=5000 DPT=53"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DRY_RUN", True)
    monkeypatch.setattr(config, "ADMIN_IPS", [])
    monkeypatch.setattr(config, "ADMIN_USER", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "matkhau-test")
    monkeypatch.setattr(config, "AUTH_ENABLED", True)
    monkeypatch.setattr(config, "LOG_SOURCE", "none")
    auth._fails.clear()
    db.init_db()
    return tmp_path


@pytest.fixture()
def client(env):
    from app.main import app
    with TestClient(app) as c:
        yield c


def _login(client, pw="matkhau-test"):
    return client.post("/api/login", json={"username": "admin", "password": pw})


def _hdr(client):
    return {"Authorization": "Bearer " + _login(client).json()["token"]}


# ---------- Phân tích dòng log ----------

def test_parse_tcp():
    e = parse_log_line(TCP_LINE)
    assert (e["rule_id"], e["src_ip"], e["dst_ip"], e["proto"], e["sport"], e["dport"]) == \
        (7, "192.168.1.50", "192.168.1.10", "tcp", 51514, 22)


def test_parse_icmp_no_ports_and_prefix_noise():
    e = parse_log_line(ICMP_LINE)
    assert e["proto"] == "icmp" and e["sport"] is None and e["dport"] is None and e["rule_id"] == 3


def test_parse_ipv6():
    e = parse_log_line(V6_LINE)
    assert e["src_ip"] == "2001:db8::5" and e["proto"] == "udp" and e["dport"] == 53


@pytest.mark.parametrize("line", ["", "random kernel message", "IN=eth0 SRC=1.1.1.1 PROTO=TCP DPT=80"])
def test_parse_ignores_other_lines(line):
    assert parse_log_line(line) is None


# ---------- Bộ phát hiện quét port ----------

def test_detector_fires_over_threshold_and_counts_ports():
    d = ScanDetector(threshold=5, window=10)
    results = [d.feed("1.2.3.4", 1000 + i, 100.0 + i * 0.1) for i in range(8)]
    fired = [r for r in results if r]
    assert len(fired) == 1                       # chỉ báo một lần, không báo lặp
    assert fired[0]["drops"] == 6 and fired[0]["distinct_ports"] == 6 and fired[0]["threshold"] == 5


def test_detector_below_threshold_no_alert():
    d = ScanDetector(threshold=5, window=10)
    assert all(d.feed("1.2.3.4", 80, 100.0 + i) is None for i in range(5))


def test_detector_window_expires_old_events():
    d = ScanDetector(threshold=3, window=10)
    for i in range(3):
        d.feed("1.2.3.4", 80, 100.0 + i)
    assert d.feed("1.2.3.4", 80, 200.0) is None  # các gói cũ đã ra khỏi cửa sổ


def test_detector_separates_ips_and_realerts_after_mute():
    d = ScanDetector(threshold=2, window=10)
    assert d.feed("1.1.1.1", 1, 0) is None and d.feed("2.2.2.2", 1, 0.1) is None
    assert d.feed("1.1.1.1", 2, 0.2) is None
    assert d.feed("1.1.1.1", 3, 0.3) is not None           # IP 1 vượt ngưỡng
    assert d.feed("1.1.1.1", 4, 0.4) is None               # đang im lặng
    for i in range(3):
        a = d.feed("1.1.1.1", 10 + i, 50 + i)              # sau hết im lặng, lại vượt ngưỡng
    assert a is not None


def test_process_line_stores_log_and_alert(env):
    det = ScanDetector(threshold=2, window=10)
    for i in range(4):
        process_line(TCP_LINE.replace("DPT=22", f"DPT={20 + i}"), det, clock=lambda i=i: 1000.0 + i)
    assert db.count_logs() == 4
    alerts = db.list_alerts()
    assert len(alerts) == 1 and alerts[0]["src_ip"] == "192.168.1.50"
    assert process_line("không phải log chặn", det) is None


# ---------- Đăng nhập ----------

def test_password_hash_roundtrip():
    h = auth.hash_password("abc")
    assert auth.verify_password("abc", h) and not auth.verify_password("abd", h)
    assert not auth.verify_password("abc", "rác")


def test_token_valid_tampered_expired():
    t = auth.make_token("admin")
    assert auth.verify_token(t) == "admin"
    body, sig = t.split(".")
    assert auth.verify_token(body + "." + "0" * len(sig)) is None
    assert auth.verify_token("khong-hop-le") is None
    assert auth.verify_token(auth.make_token("admin", ttl=-1)) is None


def test_api_requires_login(client):
    for path in ["/api/rules", "/api/status", "/api/logs", "/api/alerts"]:
        assert client.get(path).status_code == 401
    assert client.post("/api/rules", json={"src_ip": "1.1.1.1"}).status_code == 401
    assert client.get("/api/rules", headers={"Authorization": "Bearer sai"}).status_code == 401


def test_login_ok_and_wrong_password(client):
    r = _login(client)
    assert r.status_code == 200 and r.json()["token"]
    assert _login(client, "sai").status_code == 401
    assert client.post("/api/login", json={"username": "khong-co", "password": "x"}).status_code == 401
    assert client.get("/api/rules", headers=_hdr(client)).status_code == 200


def test_login_lockout(client):
    for _ in range(config.LOGIN_MAX_FAILS):
        assert _login(client, "sai").status_code == 401
    assert _login(client).status_code == 429       # đúng mật khẩu cũng bị khóa tạm


def test_auto_generated_admin_password(env, monkeypatch, capsys):
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "")
    monkeypatch.setattr(config, "DB_PATH", str(env / "fresh.db"))
    db.init_db()
    pw = auth.ensure_admin()
    assert pw and len(pw) >= 8 and auth.verify_password(pw, db.get_user_hash("admin"))
    assert auth.ensure_admin() is None             # lần sau không tạo lại


# ---------- API nhật ký, cảnh báo, trạng thái ----------

def test_logs_alerts_api_with_filters(client):
    det = ScanDetector(threshold=2, window=10)
    for ip, port in [("10.0.0.1", 22), ("10.0.0.1", 23), ("10.0.0.1", 24), ("10.0.0.2", 80)]:
        process_line(TCP_LINE.replace("192.168.1.50", ip).replace("DPT=22", f"DPT={port}"), det, clock=lambda: 5.0)
    h = _hdr(client)
    assert len(client.get("/api/logs", headers=h).json()) == 4
    only = client.get("/api/logs?src_ip=10.0.0.1", headers=h).json()
    assert len(only) == 3 and all(x["src_ip"] == "10.0.0.1" for x in only)
    assert len(client.get("/api/logs?dport=80", headers=h).json()) == 1
    assert len(client.get("/api/logs?limit=2", headers=h).json()) == 2
    assert client.get("/api/logs?src_ip=1.1.1.1;DROP", headers=h).status_code == 422
    top = client.get("/api/logs/top", headers=h).json()
    assert top[0] == {"src_ip": "10.0.0.1", "drops": 3}
    assert client.get("/api/alerts", headers=h).json()[0]["src_ip"] == "10.0.0.1"
    st = client.get("/api/status", headers=h).json()
    assert st["log_entries"] == 4 and len(st["recent_alerts"]) == 1


def test_sql_injection_in_log_filter_is_inert(client):
    h = _hdr(client)
    process_line(TCP_LINE, ScanDetector(99, 10))
    # Nếu bị ghép chuỗi vào SQL thì "OR '1'='1" làm điều kiện luôn đúng và trả về 1 dòng.
    # Vì tham số hóa, nó chỉ là một chuỗi so sánh thường (lớn hơn mọi mốc thời gian) nên trả về rỗng.
    r = client.get("/api/logs", params={"since": "9999' OR '1'='1"}, headers=h)
    assert r.status_code == 200 and r.json() == []
    assert db.count_logs() == 1                      # bảng vẫn còn nguyên


# ---------- Luồng nền đọc tệp log (đầu-cuối) ----------

def test_watcher_end_to_end_with_log_file(env, monkeypatch):
    logfile = env / "kern.log"
    logfile.write_text("dòng cũ có từ trước\n")
    monkeypatch.setattr(config, "LOG_SOURCE", str(logfile))
    monkeypatch.setattr(config, "ALERT_THRESHOLD", 3)
    monkeypatch.setattr(config, "ALERT_WINDOW", 10)
    from app.main import app
    with TestClient(app) as c:
        time.sleep(0.6)                              # chờ luồng nền mở tệp và nhảy tới cuối tệp
        with open(logfile, "a") as f:
            for i in range(6):
                f.write(TCP_LINE.replace("DPT=22", f"DPT={100 + i}") + "\n")
            f.write("một dòng nhiễu khác\n")
            f.flush()
        deadline = time.time() + 5
        while time.time() < deadline and db.count_logs() < 6:
            time.sleep(0.1)
        assert db.count_logs() == 6                  # dòng cũ và dòng nhiễu bị bỏ qua
        assert len(db.list_alerts()) == 1
        h = {"Authorization": "Bearer " + auth.make_token("admin")}
        assert len(c.get("/api/logs", headers=h).json()) == 6


def test_static_dashboard_served_without_login(env, monkeypatch, tmp_path):
    """Trang đăng nhập của B phải mở được khi chưa có token; API thì không."""
    import importlib
    from app import main
    dash = tmp_path / "dash"
    dash.mkdir()
    (dash / "index.html").write_text("<h1>Dashboard</h1>")
    monkeypatch.setattr(config, "DASHBOARD_DIR", str(dash))
    main = importlib.reload(main)
    try:
        with TestClient(main.app) as c:
            r = c.get("/")
            assert r.status_code == 200 and "Dashboard" in r.text
            assert c.get("/api/rules").status_code == 401
    finally:
        monkeypatch.undo()
        importlib.reload(main)
