"""Validate a client token and its remaining TTL via GET /v1/auth/token/lookup-self."""

from __future__ import annotations

from dataclasses import dataclass

from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger

log = get_logger("auth")


class TokenInvalidError(Exception):
    pass


@dataclass(frozen=True)
class TokenInfo:
    ttl: int  # seconds left; 0 = never expires (e.g. root token)
    expire_time: str | None
    policies: tuple[str, ...]
    renewable: bool


def lookup_self(http: OpenBaoHttpClient, token: str) -> TokenInfo:
    try:
        data = http.request("GET", "auth/token/lookup-self", token=token).get("data") or {}
    except OpenBaoHttpError as exc:
        if exc.status == 403:
            raise TokenInvalidError("token is invalid, expired or revoked") from None
        raise
    return TokenInfo(
        ttl=int(data.get("ttl") or 0),
        expire_time=data.get("expire_time"),
        policies=tuple(data.get("policies") or ()),
        renewable=bool(data.get("renewable")),
    )


def validate_token(http: OpenBaoHttpClient, token: str, min_ttl: int = 0) -> TokenInfo:
    """Raise TokenInvalidError if the token is unusable or expires in less than `min_ttl` seconds."""
    info = lookup_self(http, token)
    if info.ttl and info.ttl < min_ttl:
        raise TokenInvalidError(f"token expires in {info.ttl}s, less than the required {min_ttl}s")
    log.info("Token valid (ttl=%ss, expire_time=%s)", info.ttl or "none", info.expire_time or "never")
    return info
