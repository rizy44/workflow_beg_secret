"""Parse `--secret` specs, filter keys and map them to environment variable names.

Spec syntax (one per `--secret`, or one per line in OPENBAO_SECRETS / a secrets file):

    PATH=ci/artifactory,PREFIX=ARTIFACTORY_
    PATH=ci/dockerhub,KEYS=username|token,PREFIX=DOCKERHUB_
    PATH=legacy/app,MOUNT=secret-v1,KV=1

Fields (names are case-insensitive):
    PATH    (required) secret path inside the mount
    PREFIX  env name prefix; default "SECRET_"; `PREFIX=` (empty) means no prefix
    KEYS    `|`-separated keys to keep; default: every key of the secret
    MOUNT   override the engine mount for this secret
    KV      override the KV version (1 or 2) for this secret

Env name = PREFIX + KEY upper-cased, non [A-Z0-9_] chars -> "_":
    api_key -> SECRET_API_KEY ;  PREFIX=ARTIFACTORY_ + user-name -> ARTIFACTORY_USER_NAME
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

DEFAULT_PREFIX = "SECRET_"
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# Names a secret must never overwrite in the CI environment.
RESERVED_PREFIXES = ("GITHUB_", "RUNNER_", "ACTIONS_", "OPENBAO_", "JENKINS_")
RESERVED_NAMES = {"PATH", "HOME", "SHELL", "USER", "PWD", "WORKSPACE", "BUILD_ID", "BUILD_NUMBER", "LD_PRELOAD"}
_FIELDS = {"PATH", "PREFIX", "KEYS", "MOUNT", "KV"}


class SecretSpecError(Exception):
    pass


@dataclass(frozen=True)
class SecretSpec:
    path: str
    prefix: str = DEFAULT_PREFIX
    keys: tuple[str, ...] = ()  # empty = all keys
    mount: str | None = None
    kv_version: int | None = None


def parse_spec(text: str, default_prefix: str = DEFAULT_PREFIX) -> SecretSpec:
    fields: dict[str, str] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip().upper()
        if not sep:
            raise SecretSpecError(f"invalid field {part!r} in {text!r}: expected NAME=value")
        if name not in _FIELDS:
            raise SecretSpecError(f"unknown field {name!r} in {text!r} (allowed: {', '.join(sorted(_FIELDS))})")
        if name in fields:
            raise SecretSpecError(f"field {name} given twice in {text!r}")
        fields[name] = value.strip()

    path = fields.get("PATH", "").strip("/")
    if not path:
        raise SecretSpecError(f"PATH is required in {text!r}")
    prefix = fields.get("PREFIX", default_prefix).upper()
    if prefix and not re.match(r"^[A-Z_][A-Z0-9_]*$", prefix):
        raise SecretSpecError(f"invalid PREFIX {prefix!r} in {text!r}")
    keys = tuple(k.strip() for k in fields.get("KEYS", "").split("|") if k.strip())
    kv = fields.get("KV")
    if kv not in (None, "1", "2"):
        raise SecretSpecError(f"KV must be 1 or 2 in {text!r}")
    return SecretSpec(
        path=path,
        prefix=prefix,
        keys=keys,
        mount=fields.get("MOUNT") or None,
        kv_version=int(kv) if kv else None,
    )


def parse_specs(lines: Iterable[str], default_prefix: str = DEFAULT_PREFIX) -> list[SecretSpec]:
    """Parse many specs; blank lines and `#` comments are ignored."""
    specs = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(parse_spec(line, default_prefix))
    if not specs:
        raise SecretSpecError("no secret given: use --secret, OPENBAO_SECRETS or --secrets-file")
    return specs


def env_name(prefix: str, key: str) -> str:
    name = prefix + re.sub(r"[^A-Za-z0-9_]", "_", key).upper()
    return "_" + name if name[0].isdigit() else name


def to_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def map_secrets(specs: list[SecretSpec], read: Callable[[SecretSpec], dict[str, Any]]) -> dict[str, str]:
    """Read each spec with `read(spec)` and return {ENV_NAME: value}, validating names."""
    env: dict[str, str] = {}
    origin: dict[str, str] = {}
    for spec in specs:
        data = read(spec)
        keys = spec.keys or tuple(data)
        missing = [k for k in keys if k not in data]
        if missing:
            raise SecretSpecError(f"key(s) {', '.join(missing)} not found at {spec.path}")
        for key in keys:
            name = env_name(spec.prefix, key)
            if not ENV_NAME_RE.match(name) or name in RESERVED_NAMES or name.startswith(RESERVED_PREFIXES):
                raise SecretSpecError(f"{spec.path}#{key} -> {name}: reserved or invalid env name, use another PREFIX")
            if name in env:
                raise SecretSpecError(f"env name {name} produced by both {origin[name]} and {spec.path}#{key}")
            env[name] = to_str(data[key])
            origin[name] = f"{spec.path}#{key}"
    return env
