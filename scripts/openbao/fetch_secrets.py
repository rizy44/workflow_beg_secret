#!/usr/bin/env python3
"""Stage: fetch secrets from OpenBao (KV v2) for the current CI job.

Standard library only: no `pip install` needed on the agent/runner.

    # GitHub Actions: exported to $GITHUB_ENV (masked) for the next steps
    python3 scripts/openbao/fetch_secrets.py --spec "github/dockerhub token | DOCKERHUB_TOKEN"

    # Jenkins / anywhere: run a command with the secrets in its environment (nothing on disk)
    python3 scripts/openbao/fetch_secrets.py --spec-file .ci/secrets.txt --exec -- ./scripts/build.sh

    # write a dotenv file (mode 600) to `source` later
    python3 scripts/openbao/fetch_secrets.py --spec-file .ci/secrets.txt --output "$WORKSPACE_TMP/bao.env"

    # print `export` lines for eval:  eval "$(python3 .../fetch_secrets.py --format shell ...)"
    python3 scripts/openbao/fetch_secrets.py --spec-file .ci/secrets.txt --format shell

Spec (one per line, or separated by `;`; `#` starts a comment):

    <path> <key>                -> env KEY
    <path> <key> | ENV_NAME     -> env ENV_NAME
    <path> *                    -> every key of the secret
    <path> * | PREFIX_          -> every key, prefixed: PREFIX_KEY

<path> is relative to the KV v2 mount (--mount / BAO_MOUNT, e.g. kv/test).
OpenBao connection/auth: see scripts/common/openbao.py (BAO_* variables).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import ci  # noqa: E402
from common.openbao import OpenBao, OpenBaoError  # noqa: E402

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RESERVED_PREFIXES = ("GITHUB_", "RUNNER_", "ACTIONS_", "BAO_")


class SpecError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    key: str  # "*" = all keys
    env: str | None  # explicit env name, or prefix when key == "*"


def parse_spec(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for raw in re.split(r"[;\n]", text):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        left, _, right = line.partition("|")
        parts = left.split()
        if len(parts) != 2:
            raise SpecError(f"invalid spec {line!r}: expected '<path> <key> [| ENV_NAME]'")
        path, key = parts[0].strip("/"), parts[1]
        env = right.strip() or None
        if env and not ENV_NAME_RE.match(env):
            raise SpecError(f"invalid env name/prefix {env!r} in {line!r}")
        entries.append(Entry(path, key, env))
    if not entries:
        raise SpecError("secret spec is empty")
    return entries


def env_name_for(key: str, prefix: str = "") -> str:
    name = prefix + re.sub(r"[^A-Za-z0-9_]", "_", key).upper()
    return "_" + name if name[0].isdigit() else name


def resolve(entries: list[Entry], read_kv: Callable[[str], dict], get: Callable[[str, str], str]) -> dict[str, str]:
    """Return {ENV_NAME: value}. `read_kv(path)` lists keys, `get(path, key)` returns a string value."""
    out: dict[str, str] = {}
    for e in entries:
        if e.key == "*":
            pairs = [(env_name_for(k, e.env or ""), get(e.path, k)) for k in read_kv(e.path)]
        else:
            pairs = [(e.env or env_name_for(e.key), get(e.path, e.key))]
        for name, value in pairs:
            if name.upper().startswith(RESERVED_PREFIXES):
                raise SpecError(f"env name {name} uses a reserved prefix {RESERVED_PREFIXES}")
            if name in out:
                raise SpecError(f"env name {name} is produced twice")
            out[name] = value
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fetch secrets from OpenBao for a CI job.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--spec", help="secret spec text (default: $SECRETS_SPEC)")
    src.add_argument("--spec-file", help="file containing the secret spec")
    p.add_argument(
        "--mount", default=os.environ.get("BAO_MOUNT") or "kv", help="KV v2 mount (default: $BAO_MOUNT or kv)"
    )
    p.add_argument("--format", choices=["auto", "github-env", "dotenv", "shell"], default="auto")
    p.add_argument("--output", help="file for --format dotenv (written with mode 600)")
    p.epilog = "--exec [--] CMD [ARGS...]   run CMD with the secrets in its environment (must be last)"
    return p


def split_exec(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Split `... --exec [--] cmd args` into (own args, command)."""
    if "--exec" not in argv:
        return argv, None
    i = argv.index("--exec")
    command = argv[i + 1 :]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SpecError("--exec needs a command")
    return argv[:i], command


def main(argv: list[str] | None = None) -> int:
    try:
        own_argv, command = split_exec(sys.argv[1:] if argv is None else argv)
    except SpecError as exc:
        ci.error(f"fetch_secrets: {exc}")
        return 2
    args = build_parser().parse_args(own_argv)
    try:
        if args.spec_file:
            spec = Path(args.spec_file).read_text(encoding="utf-8")
        else:
            spec = args.spec if args.spec is not None else os.environ.get("SECRETS_SPEC", "")
        entries = parse_spec(spec)

        fmt = args.format
        if fmt == "auto" and not command:
            if args.output:
                fmt = "dotenv"
            elif os.environ.get("GITHUB_ENV"):
                fmt = "github-env"
            else:
                raise SpecError("nowhere to put the secrets: use --exec, --output FILE or --format shell")
        if fmt == "dotenv" and not args.output:
            raise SpecError("--format dotenv needs --output FILE")

        bao = OpenBao.from_env()
        try:
            values = resolve(
                entries,
                lambda path: bao.read_kv(args.mount, path),
                lambda path, key: bao.get(args.mount, path, key),
            )
        finally:
            bao.revoke()
    except (SpecError, OpenBaoError, OSError) as exc:
        ci.error(f"fetch_secrets: {exc}")
        return 1

    names = ", ".join(sorted(values))
    if command:
        print(f"fetch_secrets: running {command[0]} with {len(values)} secret(s): {names}", file=sys.stderr, flush=True)
        os.execvpe(command[0], command, {**os.environ, **values})
    if fmt == "github-env":
        ci.write_github_env(os.environ["GITHUB_ENV"], values)
    elif fmt == "dotenv":
        ci.write_dotenv(args.output, values)
    else:  # shell
        sys.stdout.write(ci.shell_exports(values))
    print(f"fetch_secrets: exported {len(values)} secret(s): {names}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
