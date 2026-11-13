"""Lớp truy cập SQLite cho bảng rules."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL DEFAULT '',
    src_ip     TEXT,
    dst_ip     TEXT,
    port       TEXT,
    proto      TEXT    NOT NULL DEFAULT 'any' CHECK (proto IN ('tcp','udp','any')),
    action     TEXT    NOT NULL CHECK (action IN ('accept','drop')),
    direction  TEXT    NOT NULL DEFAULT 'in' CHECK (direction IN ('in','out')),
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
"""

COLUMNS = ("name", "src_ip", "dst_ip", "port", "proto", "action", "direction", "enabled")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def list_rules(only_enabled: bool = False) -> list:
    sql = "SELECT * FROM rules"
    if only_enabled:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id ASC"  # thứ tự id = thứ tự ưu tiên: rule khớp đầu tiên thắng
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql).fetchall()]


def get_rule(rule_id: int) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
        return dict(row) if row else None


def create_rule(data: dict) -> dict:
    now = _now()
    with connect() as conn:
        cur = conn.execute(
            f"INSERT INTO rules ({', '.join(COLUMNS)}, created_at, updated_at) "
            f"VALUES ({', '.join('?' * len(COLUMNS))}, ?, ?)",
            [data[c] for c in COLUMNS] + [now, now],
        )
        rule_id = cur.lastrowid
    return get_rule(rule_id)


def update_rule(rule_id: int, data: dict) -> Optional[dict]:
    if get_rule(rule_id) is None:
        return None
    sets = ", ".join(f"{c} = ?" for c in COLUMNS)
    with connect() as conn:
        conn.execute(
            f"UPDATE rules SET {sets}, updated_at = ? WHERE id = ?",
            [data[c] for c in COLUMNS] + [_now(), rule_id],
        )
    return get_rule(rule_id)


def set_enabled(rule_id: int, enabled: bool) -> Optional[dict]:
    if get_rule(rule_id) is None:
        return None
    with connect() as conn:
        conn.execute(
            "UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, _now(), rule_id),
        )
    return get_rule(rule_id)


def delete_rule(rule_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        return cur.rowcount > 0
