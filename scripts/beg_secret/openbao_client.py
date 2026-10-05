"""Minimal OpenBao client: login (token / GitHub OIDC JWT / AppRole) + KV v2 read.

OpenBao keeps the Vault HTTP API, so plain REST calls are enough and we avoid
pinning a Vault SDK version. Environment variables follow the `bao` CLI:

    BAO_ADDR          https://openbao.example.com:8200   (required)
    BAO_NAMESPACE     optional namespace
    BAO_CACERT        optional CA bundle path for a private CA
    BAO_AUTH_METHOD   token | jwt | approle             (default: token)
    BAO_TOKEN         when BAO_AUTH_METHOD=token
    BAO_JWT_ROLE      when BAO_AUTH_METHOD=jwt
    BAO_JWT_MOUNT     default: jwt
    BAO_JWT_AUDIENCE  default: openbao  (audience requested from GitHub OIDC)
    BAO_JWT           optional: pre-fetched JWT (otherwise fetched from GitHub Actions)
    BAO_ROLE_ID / BAO_SECRET_ID / BAO_APPROLE_MOUNT   when BAO_AUTH_METHOD=approle
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

from beg_secret.config import SecretRef

log = logging.getLogger(__name__)


class OpenBaoError(Exception):
    pass


def fetch_github_oidc_token(audience: str) -> str:
    """Request an OIDC ID token from the GitHub Actions runtime.

    Requires `permissions: id-token: write` on the job.
    """
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise OpenBaoError(
            "GitHub OIDC is not available: ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN missing. "
            "Add `permissions: id-token: write` to the job."
        )
    resp = requests.get(
        url,
        params={"audience": audience},
        headers={"Authorization": f"Bearer {bearer}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise OpenBaoError(f"failed to fetch GitHub OIDC token: HTTP {resp.status_code}")
    return resp.json()["value"]


class OpenBaoClient:
    def __init__(
        self,
        addr: str,
        token: str | None = None,
        namespace: str | None = None,
        verify: bool | str = True,
        timeout: int = 30,
    ):
        self.addr = addr.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        if namespace:
            self.session.headers["X-Vault-Namespace"] = namespace
        self._kv_cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._owns_token = False  # True only for tokens obtained by login_*()

    # ------------------------------------------------------------------ http

    def _request(self, method: str, api_path: str, **kwargs: Any) -> dict[str, Any]:
        headers = kwargs.pop("headers", {})
        if self.token:
            headers["X-Vault-Token"] = self.token
        url = f"{self.addr}/v1/{api_path.lstrip('/')}"
        resp = self.session.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
        if resp.status_code == 404:
            raise OpenBaoError(f"{method} {api_path}: not found (404)")
        if resp.status_code >= 400:
            # Response bodies from OpenBao never contain secret values on error.
            raise OpenBaoError(f"{method} {api_path}: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json() if resp.content else {}

    # ------------------------------------------------------------------ auth

    def login_jwt(self, role: str, jwt: str, mount: str = "jwt") -> None:
        data = self._request("POST", f"auth/{mount}/login", json={"role": role, "jwt": jwt})
        self.token = data["auth"]["client_token"]
        self._owns_token = True
        log.info("OpenBao: logged in via %s (role=%s)", mount, role)

    def login_approle(self, role_id: str, secret_id: str, mount: str = "approle") -> None:
        data = self._request("POST", f"auth/{mount}/login", json={"role_id": role_id, "secret_id": secret_id})
        self.token = data["auth"]["client_token"]
        self._owns_token = True
        log.info("OpenBao: logged in via %s", mount)

    def revoke_self(self) -> None:
        """Best-effort revoke of the short-lived login token at the end of a run.

        A token passed in via BAO_TOKEN belongs to the caller and is left alone.
        """
        if not self.token or not self._owns_token:
            return
        try:
            self._request("POST", "auth/token/revoke-self")
        except Exception as exc:  # noqa: BLE001 - cleanup must not fail the run
            log.debug("token revoke failed: %s", exc)

    @classmethod
    def from_env(cls) -> OpenBaoClient:
        addr = os.environ.get("BAO_ADDR")
        if not addr:
            raise OpenBaoError("BAO_ADDR is not set")
        client = cls(
            addr=addr,
            namespace=os.environ.get("BAO_NAMESPACE") or None,
            verify=os.environ.get("BAO_CACERT") or True,
        )
        method = os.environ.get("BAO_AUTH_METHOD", "token").lower()
        if method == "token":
            token = os.environ.get("BAO_TOKEN")
            if not token:
                raise OpenBaoError("BAO_AUTH_METHOD=token but BAO_TOKEN is not set")
            client.token = token
        elif method == "jwt":
            role = os.environ.get("BAO_JWT_ROLE")
            if not role:
                raise OpenBaoError("BAO_AUTH_METHOD=jwt but BAO_JWT_ROLE is not set")
            jwt = os.environ.get("BAO_JWT") or fetch_github_oidc_token(os.environ.get("BAO_JWT_AUDIENCE", "openbao"))
            client.login_jwt(role, jwt, os.environ.get("BAO_JWT_MOUNT", "jwt"))
        elif method == "approle":
            role_id, secret_id = os.environ.get("BAO_ROLE_ID"), os.environ.get("BAO_SECRET_ID")
            if not role_id or not secret_id:
                raise OpenBaoError("BAO_AUTH_METHOD=approle needs BAO_ROLE_ID and BAO_SECRET_ID")
            client.login_approle(role_id, secret_id, os.environ.get("BAO_APPROLE_MOUNT", "approle"))
        else:
            raise OpenBaoError(f"unknown BAO_AUTH_METHOD={method!r}")
        return client

    # ------------------------------------------------------------------ kv v2

    def read_kv(self, mount: str, path: str) -> dict[str, Any]:
        """Return the latest version's data dict for a KV v2 secret (cached per run)."""
        cache_key = (mount, path)
        if cache_key not in self._kv_cache:
            data = self._request("GET", f"{mount}/data/{path}")
            self._kv_cache[cache_key] = (data.get("data") or {}).get("data") or {}
        return self._kv_cache[cache_key]

    def resolve(self, ref: SecretRef) -> str:
        data = self.read_kv(ref.mount, ref.path)
        if ref.key not in data:
            raise OpenBaoError(f"key '{ref.key}' not found at {ref.mount}/{ref.path}")
        value = data[ref.key]
        if not isinstance(value, str):
            raise OpenBaoError(f"{ref}: value must be a string, got {type(value).__name__}")
        mask(value)
        return value


def mask(value: str) -> None:
    """Ask GitHub Actions to redact the value from logs (no-op elsewhere)."""
    if os.environ.get("GITHUB_ACTIONS") == "true" and value:
        for line in value.splitlines():
            if line.strip():
                print(f"::add-mask::{line}", flush=True)
