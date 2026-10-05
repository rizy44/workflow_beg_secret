"""AppRole login: role_id + secret_id -> client_token (kept in memory only)."""

from __future__ import annotations

from dataclasses import dataclass

from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger, register_secret

log = get_logger("auth")


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class LoginResult:
    client_token: str
    lease_duration: int  # seconds
    policies: tuple[str, ...]

    def __repr__(self) -> str:  # never show the token, even in tracebacks
        return f"LoginResult(client_token=***, lease_duration={self.lease_duration}, policies={self.policies})"


def approle_login(http: OpenBaoHttpClient, role_id: str, secret_id: str, mount: str = "approle") -> LoginResult:
    """POST /v1/auth/<mount>/login with {"role_id", "secret_id"}."""
    if not role_id or not secret_id:
        raise AuthError("AppRole credentials missing: set OPENBAO_ROLE_ID and OPENBAO_SECRET_ID")
    register_secret(secret_id)
    try:
        data = http.request("POST", f"auth/{mount.strip('/')}/login", body={"role_id": role_id, "secret_id": secret_id})
    except OpenBaoHttpError as exc:
        hint = " (wrong role_id/secret_id, expired secret_id, or wrong namespace)" if exc.status in (400, 403) else ""
        raise AuthError(f"AppRole login failed: {exc}{hint}") from None

    auth = data.get("auth") or {}
    token = auth.get("client_token")
    if not token:
        raise AuthError("AppRole login returned no client_token")
    register_secret(token)
    result = LoginResult(
        client_token=token,
        lease_duration=int(auth.get("lease_duration") or 0),
        policies=tuple(auth.get("token_policies") or auth.get("policies") or ()),
    )
    log.info("Authenticated with AppRole (ttl=%ss, policies=%s)", result.lease_duration, ",".join(result.policies))
    return result
