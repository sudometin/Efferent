"""Server-side state for Ops. Never stores passwords or private keys: those live encrypted in the user's own
Telegram CloudStorage and only pass through the gateway's memory for the length of a session."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS ops_servers (
  id INTEGER PRIMARY KEY, owner_id INTEGER, name TEXT, host TEXT, port INTEGER DEFAULT 22, user TEXT,
  fingerprint TEXT, knock TEXT DEFAULT '', monitor INTEGER DEFAULT 1, created REAL,
  last_ok REAL, last_alert REAL, alert_state TEXT DEFAULT '', UNIQUE(owner_id, name));
CREATE TABLE IF NOT EXISTS ops_health (server_id INTEGER, ts REAL, ok INTEGER, load REAL, cpus INTEGER,
  mem REAL, disk REAL, uptime REAL);
CREATE INDEX IF NOT EXISTS idx_health ON ops_health(server_id, ts);
CREATE TABLE IF NOT EXISTS ops_grants (
  id INTEGER PRIMARY KEY, token TEXT UNIQUE, server_id INTEGER, principal TEXT, created_by INTEGER,
  grantee_id INTEGER, grantee_name TEXT, created REAL, expires REAL, revoked INTEGER DEFAULT 0, readonly INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ops_cards (id TEXT PRIMARY KEY, owner_id INTEGER, data TEXT, created REAL);
CREATE TABLE IF NOT EXISTS ops_audit (id INTEGER PRIMARY KEY, ts REAL, user_id INTEGER, action TEXT,
  target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS ops_sessions (id INTEGER PRIMARY KEY, user_id INTEGER, target TEXT, started REAL,
  ended REAL, bytes INTEGER DEFAULT 0, cast TEXT, via TEXT);
CREATE TABLE IF NOT EXISTS ops_jobs (id INTEGER PRIMARY KEY, token TEXT, owner_id INTEGER, server_id INTEGER,
  label TEXT, cmd TEXT, started REAL, finished REAL, exit INTEGER, state TEXT DEFAULT 'running', last_poll REAL,
  gpu_idle INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ops_reflexes (id INTEGER PRIMARY KEY, owner_id INTEGER, server_id INTEGER, trigger TEXT,
  signal TEXT, trusted INTEGER DEFAULT 0, cooldown INTEGER DEFAULT 1800, last_fired REAL DEFAULT 0, enabled INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS ops_trust (user_id INTEGER, device TEXT, until REAL, PRIMARY KEY(user_id, device));
"""


class OpsStore:
    def __init__(self, db):
        self.db = db                      # nullbyte.db.DB (shared connection + lock)
        with db.lock:
            db.conn.executescript(SCHEMA)
            cols = {r[1] for r in db.conn.execute("PRAGMA table_info(ops_health)")}
            if "gpu" not in cols:
                db.conn.execute("ALTER TABLE ops_health ADD COLUMN gpu TEXT")
            db.conn.commit()

    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        rows = self.db.q(sql, args)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ audit
    def audit(self, user_id: int | None, action: str, target: str = "", detail: str = "") -> None:
        self.db.x("INSERT INTO ops_audit(ts,user_id,action,target,detail) VALUES(?,?,?,?,?)",
                  (time.time(), user_id, action, target, detail[:500]))

    def audit_tail(self, n: int = 25) -> list[sqlite3.Row]:
        return self.db.q("SELECT * FROM ops_audit ORDER BY id DESC LIMIT ?", (n,))

    # ------------------------------------------------------------------ servers (non-secret registry)
    def upsert_server(self, owner_id: int, name: str, host: str, port: int, user: str, fingerprint: str,
                      knock: str = "", monitor: bool = True) -> int:
        self.db.x("""INSERT INTO ops_servers(owner_id,name,host,port,user,fingerprint,knock,monitor,created)
                     VALUES(?,?,?,?,?,?,?,?,?)
                     ON CONFLICT(owner_id,name) DO UPDATE SET host=excluded.host, port=excluded.port,
                       user=excluded.user, fingerprint=excluded.fingerprint, knock=excluded.knock,
                       monitor=excluded.monitor""",
                  (owner_id, name, host, port, user, fingerprint, knock, int(monitor), time.time()))
        return self.one("SELECT id FROM ops_servers WHERE owner_id=? AND name=?", (owner_id, name))["id"]

    def servers(self, owner_id: int | None = None) -> list[sqlite3.Row]:
        if owner_id is None:
            return self.db.q("SELECT * FROM ops_servers ORDER BY name")
        return self.db.q("SELECT * FROM ops_servers WHERE owner_id=? ORDER BY name", (owner_id,))

    def server(self, sid: int) -> sqlite3.Row | None:
        return self.one("SELECT * FROM ops_servers WHERE id=?", (sid,))

    def server_by_name(self, owner_id: int, name: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM ops_servers WHERE owner_id=? AND lower(name)=lower(?)", (owner_id, name))

    def delete_server(self, owner_id: int, sid: int) -> None:
        self.db.x("DELETE FROM ops_servers WHERE id=? AND owner_id=?", (sid, owner_id))
        self.db.x("UPDATE ops_grants SET revoked=1 WHERE server_id=?", (sid,))

    # ------------------------------------------------------------------ grants (short-lived access for friends)
    def create_grant(self, server_id: int, principal: str, created_by: int, ttl: float, readonly: bool = False) -> str:
        token = secrets.token_urlsafe(9)
        self.db.x("""INSERT INTO ops_grants(token,server_id,principal,created_by,created,expires,readonly)
                     VALUES(?,?,?,?,?,?,?)""",
                  (token, server_id, principal, created_by, time.time(), time.time() + ttl, int(readonly)))
        return token

    def claim_grant(self, token: str, user_id: int, name: str) -> sqlite3.Row | None:
        g = self.one("SELECT * FROM ops_grants WHERE token=?", (token,))
        if not g or g["revoked"] or g["expires"] < time.time():
            return None
        if g["grantee_id"] and g["grantee_id"] != user_id:
            return None                                       # already claimed by someone else
        self.db.x("UPDATE ops_grants SET grantee_id=?, grantee_name=? WHERE id=?", (user_id, name, g["id"]))
        return self.one("SELECT * FROM ops_grants WHERE id=?", (g["id"],))

    def grants_for(self, user_id: int) -> list[sqlite3.Row]:
        return self.db.q("""SELECT g.*, s.name, s.host, s.port, s.fingerprint, s.knock FROM ops_grants g
                            JOIN ops_servers s ON s.id=g.server_id
                            WHERE g.grantee_id=? AND g.revoked=0 AND g.expires>?""", (user_id, time.time()))

    def grant(self, gid: int) -> sqlite3.Row | None:
        return self.one("SELECT * FROM ops_grants WHERE id=?", (gid,))

    def active_grants(self, created_by: int) -> list[sqlite3.Row]:
        return self.db.q("""SELECT g.*, s.name FROM ops_grants g JOIN ops_servers s ON s.id=g.server_id
                            WHERE g.created_by=? AND g.revoked=0 AND g.expires>? ORDER BY g.expires""",
                         (created_by, time.time()))

    def revoke_grant(self, gid: int, by: int) -> bool:
        g = self.grant(gid)
        if not g or g["created_by"] != by:
            return False
        self.db.x("UPDATE ops_grants SET revoked=1 WHERE id=?", (gid,))
        return True

    # ------------------------------------------------------------------ connection cards (shareable, secret-free)
    def create_card(self, owner_id: int, data: dict) -> str:
        allowed = {k: data.get(k) for k in ("name", "host", "port", "user", "fingerprint", "knock", "note")}
        cid = secrets.token_urlsafe(6)
        self.db.x("INSERT INTO ops_cards(id,owner_id,data,created) VALUES(?,?,?,?)",
                  (cid, owner_id, json.dumps(allowed), time.time()))
        return cid

    def card(self, cid: str) -> dict | None:
        r = self.one("SELECT * FROM ops_cards WHERE id=?", (cid,))
        return json.loads(r["data"]) if r else None

    # ------------------------------------------------------------------ 2FA device trust
    def trusted(self, user_id: int, device: str) -> bool:
        r = self.one("SELECT until FROM ops_trust WHERE user_id=? AND device=?", (user_id, device))
        return bool(r and r["until"] > time.time())

    def trust(self, user_id: int, device: str, seconds: float) -> None:
        self.db.x("INSERT INTO ops_trust(user_id,device,until) VALUES(?,?,?) "
                  "ON CONFLICT(user_id,device) DO UPDATE SET until=excluded.until",
                  (user_id, device, time.time() + seconds))

    # ------------------------------------------------------------------ sessions + health
    def session_start(self, user_id: int, target: str, via: str) -> int:
        return self.db.x("INSERT INTO ops_sessions(user_id,target,started,via) VALUES(?,?,?,?)",
                         (user_id, target, time.time(), via))

    def session_end(self, sid: int, nbytes: int, cast: str | None) -> None:
        self.db.x("UPDATE ops_sessions SET ended=?, bytes=?, cast=? WHERE id=?", (time.time(), nbytes, cast, sid))

    def sessions(self, user_id: int, n: int = 10) -> list[sqlite3.Row]:
        return self.db.q("SELECT * FROM ops_sessions WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, n))

    def session(self, sid: int) -> sqlite3.Row | None:
        return self.one("SELECT * FROM ops_sessions WHERE id=?", (sid,))

    def add_health(self, server_id: int, ok: bool, load=None, cpus=None, mem=None, disk=None, uptime=None,
                   gpu: list | None = None) -> None:
        self.db.x("INSERT INTO ops_health(server_id,ts,ok,load,cpus,mem,disk,uptime,gpu) VALUES(?,?,?,?,?,?,?,?,?)",
                  (server_id, time.time(), int(ok), load, cpus, mem, disk, uptime, json.dumps(gpu) if gpu else None))
        self.db.x("DELETE FROM ops_health WHERE server_id=? AND ts<?", (server_id, time.time() - 7 * 86400))
        if ok:
            self.db.x("UPDATE ops_servers SET last_ok=? WHERE id=?", (time.time(), server_id))

    def health(self, server_id: int, since: float) -> list[sqlite3.Row]:
        return self.db.q("SELECT * FROM ops_health WHERE server_id=? AND ts>=? ORDER BY ts", (server_id, since))

    def set_alert_state(self, server_id: int, state: str) -> None:
        self.db.x("UPDATE ops_servers SET alert_state=?, last_alert=? WHERE id=?", (state, time.time(), server_id))

    # ------------------------------------------------------------------ jobs (training watch)
    def add_job(self, owner_id: int, server_id: int, label: str, cmd: str) -> tuple[int, str]:
        tok = secrets.token_hex(4)
        jid = self.db.x("INSERT INTO ops_jobs(token,owner_id,server_id,label,cmd,started) VALUES(?,?,?,?,?,?)",
                        (tok, owner_id, server_id, label, cmd, time.time()))
        return jid, tok

    def job(self, jid: int) -> sqlite3.Row | None:
        return self.one("SELECT j.*, s.name AS server FROM ops_jobs j JOIN ops_servers s ON s.id=j.server_id WHERE j.id=?", (jid,))

    def jobs(self, owner_id: int | None = None, state: str | None = "running") -> list[sqlite3.Row]:
        sql = "SELECT j.*, s.name AS server FROM ops_jobs j JOIN ops_servers s ON s.id=j.server_id WHERE 1=1"
        args: list = []
        if owner_id is not None:
            sql += " AND j.owner_id=?"
            args.append(owner_id)
        if state:
            sql += " AND j.state=?"
            args.append(state)
        return self.db.q(sql + " ORDER BY j.id DESC LIMIT 30", tuple(args))

    def update_job(self, jid: int, **f) -> None:
        cols = ", ".join(f"{k}=?" for k in f)
        self.db.x(f"UPDATE ops_jobs SET {cols} WHERE id=?", (*f.values(), jid))

    # ------------------------------------------------------------------ reflex arcs
    def add_reflex(self, owner_id: int, server_id: int, trigger: str, signal: str) -> int:
        return self.db.x("INSERT INTO ops_reflexes(owner_id,server_id,trigger,signal) VALUES(?,?,?,?)",
                         (owner_id, server_id, trigger, signal))

    def reflexes(self, owner_id: int | None = None, server_id: int | None = None) -> list[sqlite3.Row]:
        sql = "SELECT r.*, s.name AS server FROM ops_reflexes r JOIN ops_servers s ON s.id=r.server_id WHERE 1=1"
        args: list = []
        if owner_id is not None:
            sql += " AND r.owner_id=?"
            args.append(owner_id)
        if server_id is not None:
            sql += " AND r.server_id=?"
            args.append(server_id)
        return self.db.q(sql + " ORDER BY r.id", tuple(args))

    def reflex(self, rid: int) -> sqlite3.Row | None:
        return self.one("SELECT r.*, s.name AS server FROM ops_reflexes r JOIN ops_servers s ON s.id=r.server_id WHERE r.id=?", (rid,))

    def update_reflex(self, rid: int, **f) -> None:
        cols = ", ".join(f"{k}=?" for k in f)
        self.db.x(f"UPDATE ops_reflexes SET {cols} WHERE id=?", (*f.values(), rid))

    def delete_reflex(self, rid: int, owner_id: int) -> None:
        self.db.x("DELETE FROM ops_reflexes WHERE id=? AND owner_id=?", (rid, owner_id))
