"""OpenBao client (standard library only) shared by every stage script.

OpenBao keeps the Vault HTTP API. Configuration comes from environment
variables, named like the `bao` CLI where one exists:

    BAO_ADDR            https://openbao.example.com:8200            (required)
    BAO_NAMESPACE       namespace, e.g. "team-a" or "parent/child"  (optional)
    BAO_CACERT          path to a CA bundle                          (optional)
    BAO_CACERT_PEM      CA bundle content (written to a temp file)   (optional)
    BAO_AUTH_METHOD     token | jwt | approle   (default: auto, see below)
    BAO_TOKEN                                   token
    BAO_ROLE, BAO_JWT_MOUNT=jwt, BAO_JWT_AUDIENCE=openbao, BAO_JWT   jwt (GitHub OIDC)
    BAO_ROLE_ID, BAO_SECRET_ID, BAO_APPROLE_MOUNT=approle            approle (Jenkins)

Auto-detection when BAO_AUTH_METHOD is empty: BAO_TOKEN -> token,
BAO_ROLE_ID + BAO_SECRET_ID -> approle, GitHub OIDC available -> jwt.
"""

from __future__ import annotations

import json
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from common import ci


class OpenBaoError(Exception):
    pass


def github_oidc_token(audience: str, env: Mapping[str, str] = os.environ) -> str:
    """Request an OIDC ID token from the GitHub Actions runtime (`id-token: write`)."""
    url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise OpenBaoError("GitHub OIDC unavailable: add `permissions: id-token: write` to the job")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}audience={urllib.parse.quote(audience)}")
    req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["value"]
    except urllib.error.URLError as exc:
        raise OpenBaoError(f"cannot get GitHub OIDC token: {exc}") from None


class OpenBao:
    def __init__(self, addr: str, namespace: str = "", cacert: str | None = None, timeout: int = 30):
        if not addr:
            raise OpenBaoError("BAO_ADDR is not set")
        self.addr = addr.rstrip("/")
        self.namespace = namespace.strip("/")
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else None
        self.timeout = timeout
        self.token: str | None = None
        self._owns_token = False  # only tokens from login_*() are revoked
        self._kv_cache: dict[tuple[str, str], dict[str, Any]] = {}

    # ------------------------------------------------------------------ http

    def call(self, method: str, api_path: str, body: dict | None = None) -> dict[str, Any]:
        req = urllib.request.Request(f"{self.addr}/v1/{api_path.lstrip('/')}", method=method)
        if body is not None:
            req.data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("X-Vault-Token", self.token)
        if self.namespace:
            req.add_header("X-Vault-Namespace", self.namespace)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # OpenBao error bodies never contain secret values.
            detail = exc.read()[:300].decode(errors="replace").strip()
            raise OpenBaoError(f"{method} {api_path}: HTTP {exc.code} {detail}") from None
        except urllib.error.URLError as exc:
            raise OpenBaoError(f"{method} {api_path}: cannot reach OpenBao at {self.addr} ({exc.reason})") from None
        return json.loads(raw) if raw else {}

    # ------------------------------------------------------------------ auth

    def _login(self, mount: str, payload: dict) -> None:
        self.token = self.call("POST", f"auth/{mount}/login", payload)["auth"]["client_token"]
        self._owns_token = True
        ci.mask(self.token)

    def login_jwt(self, role: str, jwt: str, mount: str = "jwt") -> None:
        self._login(mount, {"role": role, "jwt": jwt})

    def login_approle(self, role_id: str, secret_id: str, mount: str = "approle") -> None:
        self._login(mount, {"role_id": role_id, "secret_id": secret_id})

    def revoke(self) -> None:
        """Best-effort revoke of the login token (a token passed via BAO_TOKEN is left alone)."""
        if self.token and self._owns_token:
            try:
                self.call("POST", "auth/token/revoke-self")
            except OpenBaoError:
                pass
            self.token = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> OpenBao:
        cacert = env.get("BAO_CACERT") or None
        if not cacert and env.get("BAO_CACERT_PEM"):
            fd, cacert = tempfile.mkstemp(suffix=".pem", dir=env.get("RUNNER_TEMP") or env.get("WORKSPACE_TMP"))
            with os.fdopen(fd, "w") as fh:
                fh.write(env["BAO_CACERT_PEM"])
        client = cls(env.get("BAO_ADDR", ""), env.get("BAO_NAMESPACE", ""), cacert)

        method = (env.get("BAO_AUTH_METHOD") or "").lower()
        if not method:
            if env.get("BAO_TOKEN"):
                method = "token"
            elif env.get("BAO_ROLE_ID") and env.get("BAO_SECRET_ID"):
                method = "approle"
            elif env.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
                method = "jwt"
            else:
                raise OpenBaoError(
                    "no OpenBao credentials: set BAO_TOKEN, BAO_ROLE_ID/BAO_SECRET_ID, or use GitHub OIDC"
                )

        if method == "token":
            if not env.get("BAO_TOKEN"):
                raise OpenBaoError("BAO_AUTH_METHOD=token but BAO_TOKEN is empty")
            client.token = env["BAO_TOKEN"]
        elif method == "jwt":
            role = env.get("BAO_ROLE") or env.get("BAO_JWT_ROLE")
            if not role:
                raise OpenBaoError("BAO_AUTH_METHOD=jwt needs BAO_ROLE")
            jwt = env.get("BAO_JWT") or github_oidc_token(env.get("BAO_JWT_AUDIENCE") or "openbao", env)
            client.login_jwt(role, jwt, env.get("BAO_JWT_MOUNT") or "jwt")
        elif method == "approle":
            if not env.get("BAO_ROLE_ID") or not env.get("BAO_SECRET_ID"):
                raise OpenBaoError("BAO_AUTH_METHOD=approle needs BAO_ROLE_ID and BAO_SECRET_ID")
            client.login_approle(env["BAO_ROLE_ID"], env["BAO_SECRET_ID"], env.get("BAO_APPROLE_MOUNT") or "approle")
        else:
            raise OpenBaoError(f"unknown BAO_AUTH_METHOD={method!r} (token | jwt | approle)")
        return client

    # ------------------------------------------------------------------ kv v2

    def read_kv(self, mount: str, path: str) -> dict[str, Any]:
        """Latest version of a KV v2 secret. `mount` may contain '/', e.g. 'kv/test'."""
        key = (mount.strip("/"), path.strip("/"))
        if key not in self._kv_cache:
            data = self.call("GET", f"{key[0]}/data/{key[1]}")
            self._kv_cache[key] = (data.get("data") or {}).get("data") or {}
        return self._kv_cache[key]

    def get(self, mount: str, path: str, key: str) -> str:
        data = self.read_kv(mount, path)
        if key not in data:
            raise OpenBaoError(f"key '{key}' not found at {mount.strip('/')}/{path.strip('/')}")
        value = data[key]
        value = value if isinstance(value, str) else json.dumps(value)
        ci.mask(value)
        return value
