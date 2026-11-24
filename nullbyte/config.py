from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _ints(raw: str) -> set[int]:
    return {int(x) for x in raw.replace(" ", "").split(",") if x.strip().lstrip("-").isdigit()}


@dataclass
class Config:
    token: str = field(default_factory=lambda: os.environ.get("BOT_TOKEN", ""))
    owner_id: int = field(default_factory=lambda: int(os.environ.get("OWNER_ID", "0") or 0))
    allowed: set[int] = field(default_factory=lambda: _ints(os.environ.get("ALLOWED_USERS", "")))
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("DATA_DIR", "./data")))
    honeypot_port: int = field(default_factory=lambda: int(os.environ.get("HONEYPOT_PORT", "2222") or 0))
    honeypot_enabled: bool = field(default_factory=lambda: os.environ.get("HONEYPOT_ENABLED", "1") not in ("0", "false", "no"))
    kiddie_hour_utc: int = field(default_factory=lambda: int(os.environ.get("KIDDIE_HOUR_UTC", "18")))
    brand: str = field(default_factory=lambda: os.environ.get("BOT_BRAND", "efferent").strip().lower())  # efferent | nullbyte
    proxy: str = field(default_factory=lambda: os.environ.get("PROXY_URL", "").strip())   # http://… or socks5://…
    # ---- Ops (SSH manager Mini App)
    ops_enabled: bool = field(default_factory=lambda: os.environ.get("OPS_ENABLED", "1") not in ("0", "false", "no"))
    webapp_url: str = field(default_factory=lambda: os.environ.get("WEBAPP_URL", "").strip())       # public https URL
    webapp_host: str = field(default_factory=lambda: os.environ.get("WEBAPP_HOST", "127.0.0.1"))
    webapp_port: int = field(default_factory=lambda: int(os.environ.get("WEBAPP_PORT", "8088") or 8088))
    ops_users: set[int] = field(default_factory=lambda: _ints(os.environ.get("OPS_USERS", "")))
    ops_ca_passphrase: str = field(default_factory=lambda: os.environ.get("OPS_CA_PASSPHRASE", ""))
    ops_health_min: int = field(default_factory=lambda: int(os.environ.get("OPS_HEALTH_MIN", "5") or 5))
    ops_job_poll: int = field(default_factory=lambda: int(os.environ.get("OPS_JOB_POLL", "60") or 60))
    hp_stream_chat: str = field(default_factory=lambda: os.environ.get("HP_STREAM_CHAT", "").strip())

    @property
    def db_path(self) -> Path:
        return self.data_dir / "nullbyte.db"

    @property
    def host_key(self) -> Path:
        return self.data_dir / "honeypot_host_ed25519"

    def can_use(self, user_id: int | None) -> bool:
        if user_id is None:
            return False
        if not self.allowed:
            return True
        return user_id in self.allowed or user_id == self.owner_id
