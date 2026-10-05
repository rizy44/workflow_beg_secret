"""Revoke the client token: POST /v1/auth/token/revoke-self.

Idempotent: a token that is already revoked/expired (HTTP 403) counts as done,
so the cleanup step never fails a build that already succeeded.
"""

from __future__ import annotations

from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger

log = get_logger("revoke")


def revoke_self(http: OpenBaoHttpClient, token: str) -> bool:
    """Return True if OpenBao revoked the token now, False if there was nothing to revoke."""
    if not token:
        log.warning("No token to revoke (OPENBAO_TOKEN is empty)")
        return False
    try:
        http.request("POST", "auth/token/revoke-self", token=token)
    except OpenBaoHttpError as exc:
        if exc.status == 403:
            log.info("Token already revoked or expired")
            return False
        raise
    log.info("Token revoked")
    return True
