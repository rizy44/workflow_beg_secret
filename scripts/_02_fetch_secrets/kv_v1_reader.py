"""Read a KV version 1 secret: GET /v1/<mount>/<path> -> response["data"]."""

from __future__ import annotations

from typing import Any

from scripts._02_fetch_secrets.kv_v2_reader import SecretReadError
from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger

log = get_logger("fetch")


def read_kv_v1(http: OpenBaoHttpClient, token: str, mount: str, path: str) -> dict[str, Any]:
    mount, path = mount.strip("/"), path.strip("/")
    try:
        body = http.request("GET", f"{mount}/{path}", token=token)
    except OpenBaoHttpError as exc:
        if exc.status == 404:
            raise SecretReadError(f"secret not found: {mount}/{path}") from None
        if exc.status == 403:
            raise SecretReadError(
                f"permission denied on {mount}/{path}: policy needs read on '{mount}/{path}'"
            ) from None
        raise SecretReadError(f"cannot read {mount}/{path}: {exc}") from None
    data = body.get("data") or {}
    log.info("Fetched %d key(s) from %s/%s (kv v1)", len(data), mount, path)
    return data
