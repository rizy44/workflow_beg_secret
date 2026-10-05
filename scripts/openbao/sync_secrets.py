#!/usr/bin/env python3
"""Stage: copy OpenBao secrets into Jenkins credentials (or GitHub secrets) from a manifest.

Needs `pip install -r scripts/requirements.txt`.

    python3 scripts/openbao/sync_secrets.py validate     --config config/secrets.yaml
    python3 scripts/openbao/sync_secrets.py sync-jenkins --config config/secrets.yaml [--dry-run] [--only system]
    python3 scripts/openbao/sync_secrets.py sync-github  --config config/secrets.yaml [--dry-run] [--only org:NAME]

`--dry-run` still logs in to OpenBao and resolves every referenced value (so a
wrong path/key fails the run) and checks write access on the destination, but
does not write anything.

Environment (besides the BAO_* variables, see scripts/common/openbao.py):
    GH_TOKEN            token allowed to write Actions secrets on the targets
    GITHUB_API_URL      set automatically on Actions (default https://api.github.com)
    JENKINS_URL         overrides jenkins.url from the manifest
    JENKINS_USER        Jenkins user   (else read from jenkins.auth in OpenBao)
    JENKINS_API_TOKEN   Jenkins token  (else read from jenkins.auth in OpenBao)
    JENKINS_CACERT      CA bundle for a Jenkins behind a private CA
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import ci  # noqa: E402
from common.github_api import GitHubSecretsClient  # noqa: E402
from common.jenkins_api import JenkinsClient  # noqa: E402
from common.manifest import ConfigError, Manifest, SecretRef, load_manifest  # noqa: E402
from common.openbao import OpenBao, OpenBaoError  # noqa: E402

log = logging.getLogger("sync_secrets")


def resolve(bao: OpenBao, ref: SecretRef) -> str:
    return bao.get(ref.mount, ref.path, ref.key)


@dataclass
class Result:
    destination: str
    name: str
    source: str
    status: str  # created | updated | ok (dry-run) | skipped | FAILED: ...

    @property
    def failed(self) -> bool:
        return self.status.startswith("FAILED")


# --------------------------------------------------------------------------- github


def sync_github(manifest: Manifest, bao: OpenBao, dry_run: bool, only: list[str]) -> list[Result]:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    gh = GitHubSecretsClient(token, os.environ.get("GITHUB_API_URL", "https://api.github.com")) if token else None
    if not gh and not dry_run:
        raise SystemExit("GH_TOKEN is required for sync-github")

    results: list[Result] = []
    for target in manifest.github_targets:
        if only and target.label not in only:
            continue
        access_error = None
        if gh:
            try:
                gh.check_access(target)
            except Exception as exc:  # noqa: BLE001
                access_error = str(exc)
        for secret in target.secrets:
            res = Result(target.label, secret.name, str(secret.ref), "")
            try:
                value = resolve(bao, secret.ref)
                if access_error:
                    raise RuntimeError(f"no access to target: {access_error}")
                if dry_run:
                    res.status = "ok (dry-run)" if gh else "ok (dry-run, access not checked: no GH_TOKEN)"
                else:
                    res.status = gh.put_secret(target, secret.name, value)
            except Exception as exc:  # noqa: BLE001 - keep going, report at the end
                res.status = f"FAILED: {exc}"
            log.info("[github] %-40s %-30s %s", res.destination, res.name, res.status)
            results.append(res)
    return results


# --------------------------------------------------------------------------- jenkins


def _jenkins_client(manifest: Manifest, bao: OpenBao) -> JenkinsClient:
    url = os.environ.get("JENKINS_URL") or manifest.jenkins_url
    if not url:
        raise SystemExit("Jenkins URL missing: set jenkins.url in the manifest or JENKINS_URL")
    user = os.environ.get("JENKINS_USER")
    token = os.environ.get("JENKINS_API_TOKEN")
    if not user and manifest.jenkins_auth.username_ref:
        user = resolve(bao, manifest.jenkins_auth.username_ref)
    if not token and manifest.jenkins_auth.token_ref:
        token = resolve(bao, manifest.jenkins_auth.token_ref)
    if not user or not token:
        raise SystemExit("Jenkins credentials missing: set JENKINS_USER/JENKINS_API_TOKEN or jenkins.auth")
    ci.mask(token)
    return JenkinsClient(url, user, token, verify=os.environ.get("JENKINS_CACERT") or True)


def sync_jenkins(manifest: Manifest, bao: OpenBao, dry_run: bool, only: list[str]) -> list[Result]:
    if not manifest.jenkins_stores:
        log.info("[jenkins] no stores in manifest, nothing to do")
        return []
    jenkins = _jenkins_client(manifest, bao)
    log.info("[jenkins] authenticated to %s as %s", jenkins.url, jenkins.whoami())

    results: list[Result] = []
    for store in manifest.jenkins_stores:
        if only and store.label not in only:
            continue
        store_error = None
        try:
            jenkins.check_store(store)
        except Exception as exc:  # noqa: BLE001
            store_error = str(exc)
        for cred in store.credentials:
            res = Result(store.label, cred.id, ", ".join(str(r) for r in cred.refs.values()), "")
            try:
                values = {field: resolve(bao, ref) for field, ref in cred.refs.items()}
                if cred.username:
                    values["username"] = cred.username
                if store_error:
                    raise RuntimeError(f"store not reachable: {store_error}")
                if dry_run:
                    res.status = (
                        "ok (dry-run, " + ("exists" if jenkins.exists(store, cred.id) else "would create") + ")"
                    )
                else:
                    res.status = jenkins.upsert(store, cred, values)
            except Exception as exc:  # noqa: BLE001
                res.status = f"FAILED: {exc}"
            log.info("[jenkins] %-30s %-30s %s", res.destination, res.name, res.status)
            results.append(res)
    return results


# --------------------------------------------------------------------------- reporting


def write_summary(title: str, results: list[Result]) -> None:
    lines = [f"### {title}", "", "| Destination | Name | OpenBao source | Status |", "|---|---|---|---|"]
    for r in results:
        icon = "❌" if r.failed else "✅"
        lines.append(f"| `{r.destination}` | `{r.name}` | `{r.source}` | {icon} {r.status} |")
    if not results:
        lines.append("| - | - | - | nothing to sync |")
    ci.step_summary("\n".join(lines))


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sync_secrets.py", description="Copy OpenBao secrets into Jenkins / GitHub.")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("validate", "sync-github", "sync-jenkins"):
        sp = sub.add_parser(name)
        sp.add_argument("--config", required=True, help="path to secrets.yaml")
        if name != "validate":
            sp.add_argument("--dry-run", action="store_true")
            sp.add_argument(
                "--only",
                action="append",
                default=[],
                help="destination label: owner/repo, owner/repo@env, org:NAME, system, folder:PATH (repeatable)",
            )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")

    try:
        manifest = load_manifest(args.config)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    log.info(
        "manifest OK: %d github target(s), %d jenkins store(s), %d secret reference(s)",
        len(manifest.github_targets),
        len(manifest.jenkins_stores),
        len(manifest.all_refs()),
    )
    if args.command == "validate":
        return 0

    try:
        bao = OpenBao.from_env()
    except OpenBaoError as exc:
        ci.error(f"sync_secrets: {exc}")
        return 1
    try:
        if args.command == "sync-github":
            results = sync_github(manifest, bao, args.dry_run, args.only)
            write_summary("GitHub secrets" + (" (dry-run)" if args.dry_run else ""), results)
        else:
            results = sync_jenkins(manifest, bao, args.dry_run, args.only)
            write_summary("Jenkins credentials" + (" (dry-run)" if args.dry_run else ""), results)
    finally:
        bao.revoke()

    failed = [r for r in results if r.failed]
    log.info("done: %d ok, %d failed", len(results) - len(failed), len(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
