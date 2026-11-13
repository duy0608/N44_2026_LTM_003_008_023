"""API FastAPI quản lý rule firewall.

Luồng: Dashboard -> API -> kiểm tra dữ liệu -> SQLite -> sinh lại ruleset -> nftables.
Nếu nftables từ chối, thay đổi trong SQLite bị hoàn tác để hai bên luôn khớp nhau.
"""
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import config, db, nft
from .validators import validate_rule


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


def sync() -> str:
    """Áp dụng toàn bộ rule đang bật trong SQLite vào nftables."""
    try:
        return nft.apply_rules(db.list_rules(only_enabled=True))
    except nft.NftError as e:
        raise HTTPException(status_code=500, detail=f"Lỗi nftables: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    try:
        nft.apply_rules(db.list_rules(only_enabled=True))  # khôi phục rule sau khi khởi động lại
    except nft.NftError as e:
        print(f"[CẢNH BÁO] Không áp dụng được rule lúc khởi động: {e}")
    yield


app = FastAPI(title="Firewall Dashboard API", version="0.1.0", lifespan=lifespan)


def _clean(body: RuleIn) -> dict:
    try:
        return validate_rule(body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/api/rules")
def get_rules():
    return db.list_rules()


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: int):
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Không tìm thấy rule")
    return rule


@app.post("/api/rules", status_code=201)
def create_rule(body: RuleIn):
    data = _clean(body)
    rule = db.create_rule(data)
    try:
        sync()
    except HTTPException:
        db.delete_rule(rule["id"])  # hoàn tác
        raise
    return rule


@app.put("/api/rules/{rule_id}")
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


@app.patch("/api/rules/{rule_id}/enabled")
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


@app.delete("/api/rules/{rule_id}", status_code=204)
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


@app.post("/api/sync")
def force_sync():
    """Đồng bộ lại toàn bộ rule từ SQLite vào nftables (dùng khi nghi ngờ bị lệch)."""
    sync()
    return {"synced": True, "active_rules": len(db.list_rules(only_enabled=True))}


@app.get("/api/status")
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
        "counters": stats,
    }
