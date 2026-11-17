"""API FastAPI quản lý rule firewall.

Luồng: Dashboard -> API (có đăng nhập) -> kiểm tra dữ liệu -> SQLite -> sinh lại ruleset -> nftables.
Nếu nftables từ chối, thay đổi trong SQLite bị hoàn tác để hai bên luôn khớp nhau.
Một luồng nền đọc log nhân (FWD-DROP) vào SQLite và cảnh báo khi có dấu hiệu quét port.
"""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth, config, db, nft
from .logwatch import LogWatcher
from .validators import normalize_ip, validate_rule


class RuleIn(BaseModel):
    name: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[str] = None
    proto: str = "any"
    action: str = "drop"
    direction: str = "in"
    enabled: bool = True


class EnabledIn(BaseModel):
    enabled: bool


class LoginIn(BaseModel):
    username: str
    password: str


def sync() -> str:
    """Áp dụng toàn bộ rule đang bật trong SQLite vào nftables."""
    try:
        return nft.apply_rules(db.list_rules(only_enabled=True))
    except nft.NftError as e:
        raise HTTPException(status_code=500, detail=f"Lỗi nftables: {e}")


_watcher: Optional[LogWatcher] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _watcher
    db.init_db()
    generated = auth.ensure_admin()
    if generated:
        print("=" * 60)
        print(f"Tài khoản quản trị mới: {config.ADMIN_USER} / {generated}")
        print("Hãy lưu mật khẩu này (chỉ hiện một lần), hoặc đặt FW_ADMIN_PASSWORD.")
        print("=" * 60)
    try:
        nft.apply_rules(db.list_rules(only_enabled=True))  # khôi phục rule sau khi khởi động lại
    except nft.NftError as e:
        print(f"[CẢNH BÁO] Không áp dụng được rule lúc khởi động: {e}")

    # Ở chế độ dry-run không đọc log nhân thật (chỉ đọc khi chỉ định rõ một tệp log)
    if not (config.DRY_RUN and config.LOG_SOURCE in ("journal", "dmesg")):
        _watcher = LogWatcher()
        if not _watcher.start():
            _watcher = None
    yield
    if _watcher:
        _watcher.stop()
        _watcher = None


app = FastAPI(title="Firewall Dashboard API", version="0.2.0", lifespan=lifespan)
api = APIRouter(prefix="/api", dependencies=[Depends(auth.require_auth)])


def _clean(body: RuleIn) -> dict:
    try:
        return validate_rule(body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ----- Đăng nhập (công khai) -----

@app.post("/api/login")
def login(body: LoginIn, request: Request):
    token = auth.login(body.username, body.password, request)
    return {"token": token, "token_type": "bearer", "expires_in": config.TOKEN_TTL}


# ----- Rule -----

@api.get("/rules")
def get_rules():
    return db.list_rules()


@api.get("/rules/{rule_id}")
def get_rule(rule_id: int):
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Không tìm thấy rule")
    return rule


@api.post("/rules", status_code=201)
def create_rule(body: RuleIn):
    data = _clean(body)
    rule = db.create_rule(data)
    try:
        sync()
    except HTTPException:
        db.delete_rule(rule["id"])  # hoàn tác
        raise
    return rule


@api.put("/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleIn):
    old = db.get_rule(rule_id)
    if not old:
        raise HTTPException(status_code=404, detail="Không tìm thấy rule")
    rule = db.update_rule(rule_id, _clean(body))
    try:
        sync()
    except HTTPException:
        db.update_rule(rule_id, old)  # hoàn tác
        raise
    return rule


@api.patch("/rules/{rule_id}/enabled")
def toggle_rule(rule_id: int, body: EnabledIn):
    old = db.get_rule(rule_id)
    if not old:
        raise HTTPException(status_code=404, detail="Không tìm thấy rule")
    rule = db.set_enabled(rule_id, body.enabled)
    try:
        sync()
    except HTTPException:
        db.set_enabled(rule_id, bool(old["enabled"]))
        raise
    return rule


@api.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int):
    old = db.get_rule(rule_id)
    if not old:
        raise HTTPException(status_code=404, detail="Không tìm thấy rule")
    db.delete_rule(rule_id)
    try:
        sync()
    except HTTPException:
        db.create_rule({c: old[c] for c in db.COLUMNS})  # hoàn tác (id mới, nội dung cũ)
        raise


@api.post("/sync")
def force_sync():
    """Đồng bộ lại toàn bộ rule từ SQLite vào nftables (dùng khi nghi ngờ bị lệch)."""
    sync()
    return {"synced": True, "active_rules": len(db.list_rules(only_enabled=True))}


# ----- Nhật ký và cảnh báo -----

@api.get("/logs")
def get_logs(limit: int = 100, offset: int = 0, src_ip: Optional[str] = None,
             dport: Optional[int] = None, rule_id: Optional[int] = None,
             since: Optional[str] = None):
    """Nhật ký gói bị chặn, mới nhất trước. Lọc theo IP nguồn, port đích, mã rule, thời gian (ISO)."""
    if src_ip:
        try:
            src_ip = normalize_ip(src_ip)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    return db.list_logs(limit=limit, offset=offset, src_ip=src_ip, dport=dport,
                        rule_id=rule_id, since=since)


@api.get("/logs/top")
def top_logs(limit: int = 10):
    """Các IP bị chặn nhiều nhất (dùng cho thống kê trên Dashboard)."""
    return db.top_blocked_ips(limit)


@api.get("/alerts")
def get_alerts(limit: int = 50):
    """Cảnh báo quét port: IP, số gói bị chặn, số port khác nhau, cửa sổ thời gian."""
    return db.list_alerts(limit)


# ----- Trạng thái -----

@api.get("/status")
def status():
    rules = db.list_rules()
    stats = nft.counters()
    return {
        "firewall_active": nft.table_exists(),
        "dry_run": config.DRY_RUN,
        "total_rules": len(rules),
        "enabled_rules": sum(1 for r in rules if r["enabled"]),
        "admin_ips": config.ADMIN_IPS,
        "blocked_packets": sum(
            stats.get(r["id"], {}).get("packets", 0) for r in rules if r["action"] == "drop"
        ),
        "log_entries": db.count_logs(),
        "recent_alerts": db.list_alerts(5),
        "alert_threshold": config.ALERT_THRESHOLD,
        "alert_window_s": config.ALERT_WINDOW,
        "counters": stats,
    }


app.include_router(api)

# Phục vụ Dashboard của người B ở đường dẫn gốc. Đặt SAU các route API để không che chúng.
if Path(config.DASHBOARD_DIR).is_dir():
    app.mount("/", StaticFiles(directory=config.DASHBOARD_DIR, html=True), name="dashboard")
