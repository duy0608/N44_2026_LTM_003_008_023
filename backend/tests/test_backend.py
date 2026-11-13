import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from app import config, db, nft
from app.validators import normalize_ip, normalize_port, validate_rule


# ---------- Validators ----------

@pytest.mark.parametrize("raw,expected", [
    ("203.0.113.5", "203.0.113.5"),
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("10.0.0.7/32", "10.0.0.7"),
    ("2001:db8::1", "2001:db8::1"),
    ("", None),
    (None, None),
])
def test_ip_valid(raw, expected):
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["999.1.1.1", "abc", "1.1.1.1; reboot", "10.0.0.0/33", "1.1.1.1 drop"])
def test_ip_invalid(raw):
    with pytest.raises(ValueError):
        normalize_ip(raw)


@pytest.mark.parametrize("raw,expected", [("22", "22"), (" 80 ", "80"), ("1000-2000", "1000-2000"), ("443-443", "443"), (None, None)])
def test_port_valid(raw, expected):
    assert normalize_port(raw) == expected


@pytest.mark.parametrize("raw", ["0", "65536", "abc", "-1", "2000-1000", "22; ls", "80 80"])
def test_port_invalid(raw):
    with pytest.raises(ValueError):
        normalize_port(raw)


def test_rule_needs_proto_when_port():
    with pytest.raises(ValueError):
        validate_rule({"port": "22", "proto": "any", "action": "drop"})


def test_rule_needs_condition():
    with pytest.raises(ValueError):
        validate_rule({"action": "drop"})


def test_rule_mixed_ip_versions():
    with pytest.raises(ValueError):
        validate_rule({"src_ip": "1.1.1.1", "dst_ip": "2001:db8::1", "action": "drop"})


def test_rule_bad_action():
    with pytest.raises(ValueError):
        validate_rule({"src_ip": "1.1.1.1", "action": "reject; flush ruleset"})


# ---------- Sinh script nftables ----------

def _rule(**kw):
    base = {"id": 1, "src_ip": None, "dst_ip": None, "port": None, "proto": "any",
            "action": "drop", "direction": "in", "enabled": 1}
    base.update(kw)
    return base


def test_rule_to_nft_drop_ssh():
    line = nft.rule_to_nft(_rule(id=7, src_ip="203.0.113.5", port="22", proto="tcp"))
    assert line == 'ip saddr 203.0.113.5 tcp dport 22 counter log prefix "FWD-DROP id=7 " drop comment "id=7"'


def test_rule_to_nft_accept_proto_only():
    line = nft.rule_to_nft(_rule(id=2, proto="udp", action="accept"))
    assert line == 'meta l4proto udp counter accept comment "id=2"'


def test_rule_to_nft_ipv6():
    assert "ip6 saddr 2001:db8::/32" in nft.rule_to_nft(_rule(src_ip="2001:db8::/32"))


def test_build_ruleset_directions_and_disabled(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_IPS", ["192.168.56.1"])
    rules = [
        _rule(id=1, src_ip="1.2.3.4", direction="in"),
        _rule(id=2, dst_ip="5.6.7.8", direction="out"),
        _rule(id=3, src_ip="9.9.9.9", enabled=0),
    ]
    script = nft.build_ruleset(rules)
    assert "id=1" in script and "id=2" in script and "id=3" not in script
    # IP quản trị đứng trước rule của người dùng
    assert script.index("ip saddr 192.168.56.1 accept") < script.index("ip saddr 1.2.3.4")


@pytest.mark.skipif(shutil.which("nft") is None, reason="không có nft")
def test_syntax_with_nft_check():
    script = nft.build_ruleset([
        _rule(id=1, src_ip="203.0.113.5", port="22", proto="tcp"),
        _rule(id=2, dst_ip="10.0.0.0/8", direction="out", proto="udp", port="1000-2000"),
        _rule(id=3, src_ip="2001:db8::/32", action="accept"),
    ])
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=script, capture_output=True, text=True)
    if "Operation not permitted" in proc.stderr or "Permission denied" in proc.stderr:
        pytest.skip("không đủ quyền chạy nft -c trong môi trường này")
    assert proc.returncode == 0, proc.stderr


# ---------- API (dry-run + DB tạm) ----------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(config, "DRY_RUN", True)
    monkeypatch.setattr(config, "ADMIN_IPS", [])
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_crud_flow(client):
    r = client.post("/api/rules", json={"src_ip": "203.0.113.5", "port": "22", "proto": "tcp", "action": "drop", "name": "chặn ssh"})
    assert r.status_code == 201
    rid = r.json()["id"]
    assert "id=%d" % rid in nft.last_script()

    assert len(client.get("/api/rules").json()) == 1

    r = client.put(f"/api/rules/{rid}", json={"src_ip": "203.0.113.6", "port": "2222", "proto": "tcp", "action": "drop"})
    assert r.status_code == 200 and r.json()["port"] == "2222"
    assert "203.0.113.6" in nft.last_script() and "203.0.113.5" not in nft.last_script()

    r = client.patch(f"/api/rules/{rid}/enabled", json={"enabled": False})
    assert r.json()["enabled"] == 0
    assert "id=%d" % rid not in nft.last_script()

    assert client.delete(f"/api/rules/{rid}").status_code == 204
    assert client.get(f"/api/rules/{rid}").status_code == 404


def test_invalid_input_rejected(client):
    r = client.post("/api/rules", json={"src_ip": "1.1.1.1; rm -rf /", "action": "drop"})
    assert r.status_code == 422
    assert client.get("/api/rules").json() == []


def test_status(client):
    client.post("/api/rules", json={"src_ip": "1.2.3.4", "action": "drop"})
    s = client.get("/api/status").json()
    assert s["total_rules"] == 1 and s["enabled_rules"] == 1 and s["dry_run"] is True


def test_rollback_when_nft_fails(client, monkeypatch):
    def boom(rules):
        raise nft.NftError("giả lập lỗi")
    monkeypatch.setattr(nft, "apply_rules", boom)
    r = client.post("/api/rules", json={"src_ip": "1.2.3.4", "action": "drop"})
    assert r.status_code == 500
    assert db.list_rules() == []  # SQLite đã được hoàn tác


def test_sync_restores_rules_on_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DRY_RUN", True)
    from app.main import app
    with TestClient(app) as c:
        c.post("/api/rules", json={"src_ip": "1.2.3.4", "action": "drop"})
    nft._last_script = ""
    with TestClient(app):  # khởi động lại: lifespan phải áp dụng lại rule từ SQLite
        assert "1.2.3.4" in nft.last_script()
