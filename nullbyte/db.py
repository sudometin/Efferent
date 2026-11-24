"""SQLite storage. Small, synchronous, and fine for a personal bot."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS capsules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    label TEXT,
    created_at REAL NOT NULL,
    unlock_at REAL NOT NULL,
    drand_round INTEGER,
    armored TEXT NOT NULL,
    opened_at REAL
);
CREATE TABLE IF NOT EXISTS hp_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, client TEXT,
    username TEXT, password TEXT,
    country TEXT, cc TEXT, city TEXT, asn TEXT,
    started REAL, ended REAL
);
CREATE TABLE IF NOT EXISTS hp_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, username TEXT, password TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS hp_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER, ts REAL, cmd TEXT
);
CREATE TABLE IF NOT EXISTS hp_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER, ts REAL, url TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS idx_cmd_session ON hp_commands(session_id);
CREATE INDEX IF NOT EXISTS idx_caps_due ON capsules(opened_at, unlock_at);
"""


class DB:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def x(self, sql: str, args: tuple = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.lastrowid

    # ------------------------------------------------------------- kv
    def get(self, key: str, default: str | None = None) -> str | None:
        rows = self.q("SELECT v FROM kv WHERE k=?", (key,))
        return rows[0]["v"] if rows else default

    def set(self, key: str, value: str) -> None:
        self.x("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))

    # ------------------------------------------------------------- capsules
    def add_capsule(self, chat_id, user_id, label, unlock_at, drand_round, armored) -> int:
        return self.x(
            "INSERT INTO capsules(chat_id,user_id,label,created_at,unlock_at,drand_round,armored) VALUES(?,?,?,?,?,?,?)",
            (chat_id, user_id, label, time.time(), unlock_at, drand_round, armored))

    def due_capsules(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM capsules WHERE opened_at IS NULL AND unlock_at <= ?", (time.time(),))

    def pending_capsules(self, user_id: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM capsules WHERE opened_at IS NULL AND user_id=? ORDER BY unlock_at", (user_id,))

    def capsule(self, cid: int) -> sqlite3.Row | None:
        rows = self.q("SELECT * FROM capsules WHERE id=?", (cid,))
        return rows[0] if rows else None

    def mark_opened(self, cid: int) -> None:
        self.x("UPDATE capsules SET opened_at=? WHERE id=?", (time.time(), cid))

    def postpone(self, cid: int, seconds: float) -> None:
        self.x("UPDATE capsules SET unlock_at=? WHERE id=?", (time.time() + seconds, cid))
