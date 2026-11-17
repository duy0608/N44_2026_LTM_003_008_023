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

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    pw_hash  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    src_ip  TEXT,
    dst_ip  TEXT,
    proto   TEXT,
    sport   INTEGER,
    dport   INTEGER,
    rule_id INTEGER,
    action  TEXT NOT NULL DEFAULT 'drop'
);
CREATE INDEX IF NOT EXISTS idx_logs_ts  ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    src_ip         TEXT NOT NULL,
    drops          INTEGER NOT NULL,
    distinct_ports INTEGER NOT NULL,
    window_s       INTEGER NOT NULL,
    threshold      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
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


# ----- Người dùng -----

def get_user_hash(username: str) -> Optional[str]:
    with connect() as conn:
        row = conn.execute("SELECT pw_hash FROM users WHERE username = ?", (username,)).fetchone()
        return row["pw_hash"] if row else None


def set_user(username: str, pw_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO users (username, pw_hash) VALUES (?, ?) "
            "ON CONFLICT(username) DO UPDATE SET pw_hash = excluded.pw_hash",
            (username, pw_hash),
        )


def count_users() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# ----- Nhật ký kết nối bị chặn -----

def add_log(entry: dict) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO logs (ts, src_ip, dst_ip, proto, sport, dport, rule_id, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entry["ts"], entry.get("src_ip"), entry.get("dst_ip"), entry.get("proto"),
             entry.get("sport"), entry.get("dport"), entry.get("rule_id"), entry.get("action", "drop")),
        )


def list_logs(limit: int = 100, offset: int = 0, src_ip: Optional[str] = None,
              dport: Optional[int] = None, rule_id: Optional[int] = None,
              since: Optional[str] = None) -> list:
    """Truy vấn có tham số hóa (không ghép chuỗi người dùng nhập vào SQL)."""
    where, args = [], []
    if src_ip:
        where.append("src_ip = ?"); args.append(src_ip)
    if dport is not None:
        where.append("dport = ?"); args.append(dport)
    if rule_id is not None:
        where.append("rule_id = ?"); args.append(rule_id)
    if since:
        where.append("ts >= ?"); args.append(since)
    sql = "SELECT * FROM logs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [max(1, min(limit, 1000)), max(0, offset)]
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def top_blocked_ips(limit: int = 10) -> list:
    with connect() as conn:
        rows = conn.execute(
            "SELECT src_ip, COUNT(*) AS drops FROM logs WHERE src_ip IS NOT NULL "
            "GROUP BY src_ip ORDER BY drops DESC LIMIT ?", (max(1, min(limit, 100)),)
        ).fetchall()
        return [dict(r) for r in rows]


def count_logs() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]


# ----- Cảnh báo quét port -----

def add_alert(alert: dict) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO alerts (ts, src_ip, drops, distinct_ports, window_s, threshold) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (alert["ts"], alert["src_ip"], alert["drops"], alert["distinct_ports"],
             alert["window_s"], alert["threshold"]),
        )


def list_alerts(limit: int = 50) -> list:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
        ).fetchall()
        return [dict(r) for r in rows]
