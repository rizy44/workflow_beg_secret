#!/usr/bin/env python3
"""CLI orchestrator for the OpenBao secret stages.

    # stages 1-4: login, fetch, mask, export
    python3 scripts/main.py fetch --secret "PATH=ci/artifactory,PREFIX=ARTIFACTORY_"

    # stage 5: revoke the token exported as OPENBAO_TOKEN (run in post/cleanup)
    python3 scripts/main.py revoke

    # optional: check OPENBAO_TOKEN is still valid
    python3 scripts/main.py check-token

Configuration (flags override environment variables):
    OPENBAO_URL            --url             https://openbao.example.com:8200   (required)
    OPENBAO_NAMESPACE      --namespace       OpenBao namespace (optional)
    OPENBAO_CACERT         --cacert          CA bundle for a private CA (optional)
    OPENBAO_ROLE_ID                          AppRole role_id   (env only, never a flag)
    OPENBAO_SECRET_ID                        AppRole secret_id (env only, never a flag)
    OPENBAO_APPROLE_MOUNT  --approle-mount   default: approle
    OPENBAO_MOUNT          --mount           secret engine mount, default: secret
    OPENBAO_KV_VERSION     --kv-version      1 or 2, default: 2
    OPENBAO_SECRETS        --secret          secret specs, one per line (see _02_fetch_secrets/secret_parser.py)
    OPENBAO_TOKEN                            token used by `revoke` / `check-token` (set by `fetch`)

Exit codes: 0 ok, 1 OpenBao/runtime error, 2 invalid input.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if __package__ in (None, ""):  # executed as a file: make `scripts.*` importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._01_authenticate.approle_login import AuthError, approle_login  # noqa: E402
from scripts._01_authenticate.token_validator import TokenInvalidError, validate_token  # noqa: E402
from scripts._02_fetch_secrets.kv_v1_reader import read_kv_v1  # noqa: E402
from scripts._02_fetch_secrets.kv_v2_reader import SecretReadError, read_kv_v2  # noqa: E402
from scripts._02_fetch_secrets.secret_parser import (  # noqa: E402
    DEFAULT_PREFIX,
    SecretSpec,
    SecretSpecError,
    map_secrets,
    parse_specs,
)
from scripts._03_mask_secrets.github_masker import mask_values  # noqa: E402
from scripts._03_mask_secrets.jenkins_masker import masked_names  # noqa: E402
from scripts._04_export_env.github_exporter import ExportError, export_github_env, export_github_output  # noqa: E402
from scripts._04_export_env.jenkins_exporter import export_jenkins_properties  # noqa: E402
from scripts._05_revoke.token_revoker import revoke_self  # noqa: E402
from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError  # noqa: E402
from scripts.utils.logger import get_logger, register_secret  # noqa: E402

log = get_logger()
TOKEN_ENV = "OPENBAO_TOKEN"  # noqa: S105 - env var name, not a secret


def detect_platform(env=os.environ) -> str:
    if env.get("GITHUB_ACTIONS") == "true":
        return "github"
    if env.get("JENKINS_URL") and env.get("BUILD_ID"):
        return "jenkins"
    return "local"


# --------------------------------------------------------------------------- CLI


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name) or default


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=_env("OPENBAO_URL"))
    common.add_argument("--namespace", default=_env("OPENBAO_NAMESPACE"))
    common.add_argument("--cacert", default=_env("OPENBAO_CACERT") or None)
    common.add_argument("--timeout", type=float, default=10)
    common.add_argument("--retries", type=int, default=3)

    p = argparse.ArgumentParser(prog="main.py", description="Fetch CI secrets from OpenBao.")
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch", parents=[common], help="stages 1-4: login, fetch, mask, export")
    f.add_argument("--secret", action="append", default=[], help='"PATH=ci/app,PREFIX=APP_" (repeatable)')
    f.add_argument("--secrets-file", help="file with one secret spec per line")
    f.add_argument("--mount", default=_env("OPENBAO_MOUNT", "secret"))
    f.add_argument("--kv-version", type=int, choices=(1, 2), default=int(_env("OPENBAO_KV_VERSION", "2")))
    f.add_argument("--approle-mount", default=_env("OPENBAO_APPROLE_MOUNT", "approle"))
    f.add_argument("--default-prefix", default=DEFAULT_PREFIX)
    f.add_argument("--platform", choices=("auto", "github", "jenkins", "local"), default="auto")
    f.add_argument(
        "--output", help="properties file for jenkins/local (default: $WORKSPACE_TMP/.openbao_env.properties)"
    )
    f.add_argument("--min-ttl", type=int, default=60, help="fail if the token lives less than N seconds")
    f.add_argument(
        "--no-export-token",
        action="store_true",
        help="revoke the token right after fetching instead of exporting OPENBAO_TOKEN for a later revoke",
    )

    sub.add_parser("revoke", parents=[common], help="stage 5: revoke OPENBAO_TOKEN")
    sub.add_parser("check-token", parents=[common], help="validate OPENBAO_TOKEN and print its TTL")
    return p


def _http(args: argparse.Namespace) -> OpenBaoHttpClient:
    return OpenBaoHttpClient(args.url, args.namespace, args.cacert, timeout=args.timeout, retries=args.retries)


def _collect_specs(args: argparse.Namespace) -> list[SecretSpec]:
    lines = list(args.secret)
    if args.secrets_file:
        lines += Path(args.secrets_file).read_text(encoding="utf-8").splitlines()
    if not lines:
        lines = _env("OPENBAO_SECRETS").splitlines()
    return parse_specs(lines, args.default_prefix.upper())


# --------------------------------------------------------------------------- commands


def cmd_fetch(args: argparse.Namespace) -> int:
    platform = detect_platform() if args.platform == "auto" else args.platform
    try:
        specs = _collect_specs(args)  # validate input before touching OpenBao
        if platform == "github" and not os.environ.get("GITHUB_ENV"):
            raise SecretSpecError("platform github but GITHUB_ENV is not set")
        http = _http(args)
    except (SecretSpecError, OSError, OpenBaoHttpError) as exc:
        log.error("%s", exc)
        return 2

    token = None
    exported_token = False
    try:
        # Stage 1: authenticate
        login = approle_login(http, _env("OPENBAO_ROLE_ID"), _env("OPENBAO_SECRET_ID"), args.approle_mount)
        token = login.client_token
        validate_token(http, token, min_ttl=args.min_ttl)

        # Stage 2: fetch
        def read(spec: SecretSpec) -> dict:
            mount = spec.mount or args.mount
            if (spec.kv_version or args.kv_version) == 1:
                return read_kv_v1(http, token, mount, spec.path)
            return read_kv_v2(http, token, mount, spec.path)

        values = map_secrets(specs, read)
        for value in values.values():
            register_secret(value)

        export_token = not args.no_export_token
        exported = dict(values)
        if export_token:
            exported[TOKEN_ENV] = token

        # Stage 3 + 4: mask, then export
        if platform == "github":
            mask_values(exported.values())
            export_github_env(exported)
            export_github_output({"keys": ",".join(sorted(values))})
        else:
            names = masked_names(values, include_token=export_token)
            path = export_jenkins_properties(exported, names, args.output)
            log.info("Wrote %s (load with readProperties, then delete it)", path)
        exported_token = export_token
        log.info("Exported %d secret(s): %s", len(values), ", ".join(sorted(values)) or "-")
        return 0
    except (AuthError, TokenInvalidError, SecretReadError, SecretSpecError, ExportError, OpenBaoHttpError) as exc:
        log.error("%s", exc)
        return 1
    finally:
        # Stage 5 now if the token was not handed to the pipeline (error, or --no-export-token).
        if token and not exported_token:
            try:
                revoke_self(http, token)
            except OpenBaoHttpError as exc:
                log.warning("Could not revoke token: %s", exc)


def cmd_revoke(args: argparse.Namespace) -> int:
    token = _env(TOKEN_ENV)
    register_secret(token)
    try:
        revoke_self(_http(args), token)
    except OpenBaoHttpError as exc:
        log.error("%s", exc)
        return 1
    return 0


def cmd_check_token(args: argparse.Namespace) -> int:
    token = _env(TOKEN_ENV)
    if not token:
        log.error("%s is empty", TOKEN_ENV)
        return 2
    register_secret(token)
    try:
        validate_token(_http(args), token)
    except (TokenInvalidError, OpenBaoHttpError) as exc:
        log.error("%s", exc)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "fetch":
            return cmd_fetch(args)
        if args.command == "revoke":
            return cmd_revoke(args)
        return cmd_check_token(args)
    except OpenBaoHttpError as exc:  # e.g. empty URL
        log.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
