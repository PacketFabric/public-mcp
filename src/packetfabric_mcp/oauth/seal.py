from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Sequence
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

Kind = Literal["client", "request", "code", "access"]

PREFIXES: dict[Kind, str] = {
    "client": "pfmcp_c_",
    "request": "pfmcp_r_",
    "code": "pfmcp_code_",
    "access": "pfmcp_at_",
}


def is_access_token(token: str) -> bool:
    return token.startswith(PREFIXES["access"])


class Sealer:
    """Seals OAuth artifacts into opaque tokens so the server keeps no state.

    The first secret seals and signs; all secrets are accepted when unsealing,
    which allows key rotation. Expiry lives in the sealed body, not in Fernet's
    own timestamp.
    """

    def __init__(self, secrets: Sequence[str]) -> None:
        if not secrets:
            raise ValueError("at least one sealing secret is required")
        self._fernet = MultiFernet([Fernet(k) for k in secrets])
        self._hmac_key = base64.urlsafe_b64decode(secrets[0])

    def seal(self, kind: Kind, payload: dict[str, Any], expires_at: int | None) -> str:
        body = json.dumps(
            {"k": kind, "exp": expires_at, "p": payload}, separators=(",", ":")
        )
        return PREFIXES[kind] + self._fernet.encrypt(body.encode()).decode()

    def unseal(self, kind: Kind, token: str, now: int | None = None) -> dict[str, Any] | None:
        # Token text is attacker-controlled: every failure returns None.
        prefix = PREFIXES[kind]
        if not isinstance(token, str) or not token.startswith(prefix):
            return None
        try:
            body = json.loads(self._fernet.decrypt(token[len(prefix) :].encode()))
        except (InvalidToken, ValueError, UnicodeError):
            return None
        if not isinstance(body, dict) or body.get("k") != kind:
            return None
        payload = body.get("p")
        if not isinstance(payload, dict):
            return None
        exp = body.get("exp")
        if exp is not None:
            if isinstance(exp, bool) or not isinstance(exp, int):
                return None
            if exp <= (int(time.time()) if now is None else now):
                return None
        return payload

    def client_secret(self, client_id: str) -> str:
        return hmac.new(self._hmac_key, client_id.encode(), hashlib.sha256).hexdigest()
