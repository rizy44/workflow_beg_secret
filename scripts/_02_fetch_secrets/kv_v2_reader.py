"""Read a KV version 2 secret: GET /v1/<mount>/data/<path> -> response["data"]["data"]."""

from __future__ import annotations

from typing import Any

from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger

log = get_logger("fetch")


class SecretReadError(Exception):
    pass


def read_kv_v2(
    http: OpenBaoHttpClient, token: str, mount: str, path: str, version: int | None = None
) -> dict[str, Any]:
    mount, path = mount.strip("/"), path.strip("/")
    api_path = f"{mount}/data/{path}" + (f"?version={version}" if version else "")
    try:
        body = http.request("GET", api_path, token=token)
    except OpenBaoHttpError as exc:
        raise SecretReadError(_explain(exc, mount, path)) from None
    data = (body.get("data") or {}).get("data")
    if data is None:  # deleted/destroyed version, or not a KV v2 mount
        raise SecretReadError(f"no data at {mount}/{path} (deleted version, or the mount is not KV v2?)")
    log.info("Fetched %d key(s) from %s/%s (kv v2)", len(data), mount, path)
    return data


def _explain(exc: OpenBaoHttpError, mount: str, path: str) -> str:
    if exc.status == 404:
        return f"secret not found: {mount}/{path}"
    if exc.status == 403:
        return f"permission denied on {mount}/{path}: the token policy needs read on '{mount}/data/{path}'"
    return f"cannot read {mount}/{path}: {exc}"
