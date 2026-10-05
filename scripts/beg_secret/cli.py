"""Command line entrypoint.

    python -m beg_secret validate     --config ../config/secrets.yaml
    python -m beg_secret sync-github  --config ../config/secrets.yaml [--dry-run] [--only owner/repo]
    python -m beg_secret sync-jenkins --config ../config/secrets.yaml [--dry-run] [--only system]

`--dry-run` still logs in to OpenBao and resolves every referenced value (so a
wrong path/key fails the run) and checks write access on the destination, but
does not write anything.

Environment (besides the BAO_* variables, see openbao_client.py):
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

from beg_secret import __version__
from beg_secret.config import ConfigError, Manifest, load_manifest
from beg_secret.github_secrets import GitHubSecretsClient
from beg_secret.jenkins_credentials import JenkinsClient
from beg_secret.openbao_client import OpenBaoClient, mask

log = logging.getLogger("beg_secret")


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


def sync_github(manifest: Manifest, bao: OpenBaoClient, dry_run: bool, only: list[str]) -> list[Result]:
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
                value = bao.resolve(secret.ref)
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


def _jenkins_client(manifest: Manifest, bao: OpenBaoClient) -> JenkinsClient:
    url = os.environ.get("JENKINS_URL") or manifest.jenkins_url
    if not url:
        raise SystemExit("Jenkins URL missing: set jenkins.url in the manifest or JENKINS_URL")
    user = os.environ.get("JENKINS_USER")
    token = os.environ.get("JENKINS_API_TOKEN")
    if not user and manifest.jenkins_auth.username_ref:
        user = bao.resolve(manifest.jenkins_auth.username_ref)
    if not token and manifest.jenkins_auth.token_ref:
        token = bao.resolve(manifest.jenkins_auth.token_ref)
    if not user or not token:
        raise SystemExit("Jenkins credentials missing: set JENKINS_USER/JENKINS_API_TOKEN or jenkins.auth")
    mask(token)
    return JenkinsClient(url, user, token, verify=os.environ.get("JENKINS_CACERT") or True)


def sync_jenkins(manifest: Manifest, bao: OpenBaoClient, dry_run: bool, only: list[str]) -> list[Result]:
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
                values = {field: bao.resolve(ref) for field, ref in cred.refs.items()}
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
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = [f"### {title}", "", "| Destination | Name | OpenBao source | Status |", "|---|---|---|---|"]
    for r in results:
        icon = "❌" if r.failed else "✅"
        lines.append(f"| `{r.destination}` | `{r.name}` | `{r.source}` | {icon} {r.status} |")
    if not results:
        lines.append("| - | - | - | nothing to sync |")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="beg_secret", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=__version__)
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

    bao = OpenBaoClient.from_env()
    try:
        if args.command == "sync-github":
            results = sync_github(manifest, bao, args.dry_run, args.only)
            write_summary("GitHub secrets" + (" (dry-run)" if args.dry_run else ""), results)
        else:
            results = sync_jenkins(manifest, bao, args.dry_run, args.only)
            write_summary("Jenkins credentials" + (" (dry-run)" if args.dry_run else ""), results)
    finally:
        bao.revoke_self()

    failed = [r for r in results if r.failed]
    log.info("done: %d ok, %d failed", len(results) - len(failed), len(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
