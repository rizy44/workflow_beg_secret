#!/usr/bin/env python3
"""Fetch secrets from OpenBao (KV v2) into the current GitHub Actions job.

Standard library only, so the action needs no `pip install` on the runner.

Secret spec (input `secrets`, one entry per line or separated by `;`):

    <path> <key>                -> env KEY (key upper-cased)
    <path> <key> | ENV_NAME     -> env ENV_NAME
    <path> *                    -> every key of the secret, env KEY
    <path> * | PREFIX_          -> every key of the secret, env PREFIX_KEY
    # comment lines are ignored

<path> is relative to the KV mount (input `mount`, default `kv`), e.g.
`github/dockerhub token | DOCKERHUB_TOKEN` reads kv/data/github/dockerhub.
"""

from __future__ import annotations

import json
import os
import re
import secrets as pyrandom
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RESERVED_PREFIXES = ("GITHUB_", "RUNNER_", "ACTIONS_")


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    key: str  # "*" = all keys
    env: str | None  # explicit env name, or prefix when key == "*"


def parse_spec(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for raw in re.split(r"[;\n]", text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        left, _, right = line.partition("|")
        parts = left.split()
        if len(parts) != 2:
            raise FetchError(f"invalid secret spec {line!r}: expected '<path> <key> [| ENV_NAME]'")
        path, key = parts[0].strip("/"), parts[1]
        env = right.strip() or None
        if env and key != "*" and not ENV_NAME_RE.match(env):
            raise FetchError(f"invalid env name {env!r} in {line!r}")
        entries.append(Entry(path, key, env))
    if not entries:
        raise FetchError("input 'secrets' is empty")
    return entries


def env_name_for(key: str, prefix: str = "") -> str:
    name = prefix + re.sub(r"[^A-Za-z0-9_]", "_", key).upper()
    if name[0].isdigit():
        name = "_" + name
    return name


def resolve(entries: list[Entry], read_kv) -> dict[str, str]:
    """Map env name -> value. `read_kv(path)` returns the secret's data dict."""
    out: dict[str, str] = {}
    for e in entries:
        data = read_kv(e.path)
        if e.key == "*":
            pairs = [(env_name_for(k, e.env or ""), v) for k, v in data.items()]
        else:
            if e.key not in data:
                raise FetchError(f"key '{e.key}' not found at {e.path}")
            pairs = [(e.env or env_name_for(e.key), data[e.key])]
        for name, value in pairs:
            if not isinstance(value, str):
                value = json.dumps(value)
            if name.upper().startswith(RESERVED_PREFIXES):
                raise FetchError(f"env name {name} uses a reserved prefix")
            if name in out:
                raise FetchError(f"env name {name} is produced twice")
            out[name] = value
    return out


def mask(value: str) -> None:
    for line in value.splitlines():
        if line.strip():
            print(f"::add-mask::{line}", flush=True)


def write_env_file(path: str, values: dict[str, str]) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        for name, value in values.items():
            delim = f"ghadelim_{pyrandom.token_hex(16)}"
            fh.write(f"{name}<<{delim}\n{value}\n{delim}\n")


# --------------------------------------------------------------------------- HTTP


class Bao:
    def __init__(self, addr: str, namespace: str = "", cafile: str | None = None, timeout: int = 30):
        self.addr = addr.rstrip("/")
        self.namespace = namespace
        self.ctx = ssl.create_default_context(cafile=cafile) if cafile else None
        self.timeout = timeout
        self.token: str | None = None

    def call(self, method: str, api_path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(f"{self.addr}/v1/{api_path}", method=method)
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
            detail = exc.read()[:300].decode(errors="replace")
            raise FetchError(f"{method} {api_path}: HTTP {exc.code} {detail}") from None
        except urllib.error.URLError as exc:
            raise FetchError(f"{method} {api_path}: cannot reach OpenBao ({exc.reason})") from None
        return json.loads(raw) if raw else {}

    def login(self, mount: str, payload: dict) -> None:
        self.token = self.call("POST", f"auth/{mount}/login", payload)["auth"]["client_token"]
        mask(self.token)

    def read_kv(self, mount: str, path: str) -> dict:
        return (self.call("GET", f"{mount}/data/{path}").get("data") or {}).get("data") or {}

    def revoke(self) -> None:
        try:
            self.call("POST", "auth/token/revoke-self")
        except FetchError:
            pass


def github_oidc_token(audience: str) -> str:
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise FetchError("GitHub OIDC unavailable: add `permissions: id-token: write` to the calling job")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}audience={urllib.parse.quote(audience)}")
    req.add_header("Authorization", f"Bearer {bearer}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["value"]


def main() -> int:
    env = os.environ
    try:
        entries = parse_spec(env.get("SECRETS_SPEC", ""))
        addr = env.get("BAO_ADDR", "")
        if not addr:
            raise FetchError("input 'bao_addr' is empty (set the org/repo variable BAO_ADDR)")

        cafile = None
        if env.get("BAO_CACERT_PEM"):
            fd, cafile = tempfile.mkstemp(suffix=".pem", dir=env.get("RUNNER_TEMP"))
            with os.fdopen(fd, "w") as fh:
                fh.write(env["BAO_CACERT_PEM"])

        bao = Bao(addr, env.get("BAO_NAMESPACE", ""), cafile)
        method = env.get("BAO_AUTH_METHOD", "jwt")
        if method == "jwt":
            jwt = github_oidc_token(env.get("BAO_AUDIENCE", "openbao"))
            bao.login(env.get("BAO_JWT_MOUNT", "jwt"), {"role": env.get("BAO_ROLE", "github-actions"), "jwt": jwt})
        elif method == "approle":
            if not env.get("BAO_ROLE_ID") or not env.get("BAO_SECRET_ID"):
                raise FetchError("auth_method=approle needs role_id and secret_id")
            bao.login(
                env.get("BAO_APPROLE_MOUNT", "approle"),
                {"role_id": env["BAO_ROLE_ID"], "secret_id": env["BAO_SECRET_ID"]},
            )
        else:
            raise FetchError(f"unknown auth_method {method!r} (jwt | approle)")

        mount = env.get("BAO_MOUNT", "kv").strip("/")
        cache: dict[str, dict] = {}

        def read(path: str) -> dict:
            if path not in cache:
                cache[path] = bao.read_kv(mount, path)
            return cache[path]

        try:
            values = resolve(entries, read)
        finally:
            bao.revoke()

        for value in values.values():
            mask(value)  # mask BEFORE the value is written anywhere
        if env.get("GITHUB_ENV"):
            write_env_file(env["GITHUB_ENV"], values)
        print(f"Exported {len(values)} secret(s) from OpenBao: {', '.join(sorted(values))}")
        return 0
    except FetchError as exc:
        print(f"::error title=openbao-secrets::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
