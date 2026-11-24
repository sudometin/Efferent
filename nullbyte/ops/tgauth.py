"""Telegram Mini App initData verification.

https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
secret = HMAC_SHA256(key="WebAppData", msg=bot_token)
hash   = HMAC_SHA256(key=secret, msg=data_check_string)   (sorted "k=v" lines, without hash)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl


class AuthError(Exception):
    pass


def verify(init_data: str, bot_token: str, max_age: int = 86400) -> dict:
    if not init_data:
        raise AuthError("missing initData")
    pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=False))
    their = pairs.pop("hash", "")
    if not their:
        raise AuthError("missing hash")
    # every other field (including Bot API 8.0's "signature") stays in the check string
    check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    mine = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mine, their):
        raise AuthError("bad signature")
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError as e:
        raise AuthError("bad auth_date") from e
    if max_age and time.time() - auth_date > max_age:
        raise AuthError("initData expired · reopen the Mini App")
    user = json.loads(pairs.get("user", "{}") or "{}")
    if not user.get("id"):
        raise AuthError("no user")
    return {"user": user, "start_param": pairs.get("start_param", ""), "auth_date": auth_date}


def sign(fields: dict, bot_token: str) -> str:
    """Test helper: build a valid initData string."""
    from urllib.parse import urlencode
    check = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    h = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": h})
