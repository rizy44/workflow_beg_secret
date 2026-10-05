"""Load and validate the secrets manifest (config/secrets.yaml in beg_secret_management)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

GITHUB_SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
JENKINS_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

GITHUB_TARGET_KINDS = ("repo", "environment", "org")
ORG_VISIBILITIES = ("all", "private", "selected")
JENKINS_CRED_TYPES = ("string", "usernamePassword", "file", "sshPrivateKey")


class ConfigError(Exception):
    """Raised when the manifest is invalid. `errors` lists every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("Invalid manifest:\n  - " + "\n  - ".join(errors))


@dataclass(frozen=True)
class SecretRef:
    """Pointer to one value in OpenBao KV v2: <mount>/data/<path> -> data[key]."""

    mount: str
    path: str
    key: str

    def __str__(self) -> str:
        return f"{self.mount}/{self.path}#{self.key}"


@dataclass
class GitHubSecret:
    name: str
    ref: SecretRef


@dataclass
class GitHubTarget:
    kind: str  # repo | environment | org
    repo: str | None = None  # owner/name (kind=repo|environment)
    environment: str | None = None
    org: str | None = None
    visibility: str = "private"  # kind=org only
    selected_repositories: list[str] = field(default_factory=list)  # kind=org, visibility=selected
    secrets: list[GitHubSecret] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.kind == "org":
            return f"org:{self.org}"
        if self.kind == "environment":
            return f"{self.repo}@{self.environment}"
        return f"{self.repo}"


@dataclass
class JenkinsCredential:
    id: str
    type: str
    description: str
    # Field name -> SecretRef. Which fields exist depends on `type`:
    #   string:           secret
    #   usernamePassword: username, password
    #   file:             content            (+ file_name, plain string)
    #   sshPrivateKey:    username, private_key, passphrase (optional)
    refs: dict[str, SecretRef]
    file_name: str | None = None
    username: str | None = None  # literal username (alternative to username ref)


@dataclass
class JenkinsStore:
    folder: str | None  # None => system (global) store; "team/app" => folder store
    domain: str
    credentials: list[JenkinsCredential]

    @property
    def label(self) -> str:
        return f"folder:{self.folder}" if self.folder else "system"


@dataclass
class JenkinsAuth:
    """Where to find Jenkins API credentials in OpenBao (optional; env vars win)."""

    username_ref: SecretRef | None = None
    token_ref: SecretRef | None = None


@dataclass
class Manifest:
    default_mount: str
    github_targets: list[GitHubTarget]
    jenkins_url: str | None
    jenkins_auth: JenkinsAuth
    jenkins_stores: list[JenkinsStore]

    def all_refs(self) -> list[SecretRef]:
        refs: list[SecretRef] = []
        for t in self.github_targets:
            refs.extend(s.ref for s in t.secrets)
        for st in self.jenkins_stores:
            for c in st.credentials:
                refs.extend(c.refs.values())
        return refs


# --------------------------------------------------------------------------- parsing


class _Parser:
    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.errors: list[str] = []
        self.default_mount = str((raw.get("openbao") or {}).get("mount", "kv")).strip("/")

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def ref(self, where: str, node: dict[str, Any], key_field: str = "key", required: bool = True) -> SecretRef | None:
        path = node.get("path")
        key = node.get(key_field)
        if not path and not key and not required:
            return None
        if not path:
            self.err(where, "missing 'path'")
        if not key:
            self.err(where, f"missing '{key_field}'")
        if not path or not key:
            return None
        mount = str(node.get("mount", self.default_mount)).strip("/")
        return SecretRef(mount=mount, path=str(path).strip("/"), key=str(key))

    # ---- github

    def github(self) -> list[GitHubTarget]:
        targets: list[GitHubTarget] = []
        for i, node in enumerate(self.raw.get("github") or []):
            where = f"github[{i}]"
            kind = node.get("target", "repo")
            if kind not in GITHUB_TARGET_KINDS:
                self.err(where, f"target must be one of {GITHUB_TARGET_KINDS}, got {kind!r}")
                continue
            t = GitHubTarget(kind=kind)
            if kind in ("repo", "environment"):
                t.repo = node.get("repo")
                if not t.repo or t.repo.count("/") != 1:
                    self.err(where, "'repo' must be 'owner/name'")
            if kind == "environment":
                t.environment = node.get("environment")
                if not t.environment:
                    self.err(where, "'environment' is required when target=environment")
            if kind == "org":
                t.org = node.get("org")
                if not t.org:
                    self.err(where, "'org' is required when target=org")
                t.visibility = node.get("visibility", "private")
                if t.visibility not in ORG_VISIBILITIES:
                    self.err(where, f"visibility must be one of {ORG_VISIBILITIES}")
                t.selected_repositories = list(node.get("selected_repositories") or [])
                if t.visibility == "selected" and not t.selected_repositories:
                    self.err(where, "visibility=selected needs 'selected_repositories'")

            seen: set[str] = set()
            for j, s in enumerate(node.get("secrets") or []):
                swhere = f"{where}.secrets[{j}]"
                name = str(s.get("name", ""))
                if not GITHUB_SECRET_NAME_RE.match(name):
                    self.err(swhere, f"invalid GitHub secret name {name!r} (A-Z, 0-9, _; not starting with a digit)")
                elif name.upper().startswith("GITHUB_"):
                    self.err(swhere, f"secret name {name!r} must not start with GITHUB_")
                if name.upper() in seen:
                    self.err(swhere, f"duplicate secret name {name!r} in the same target")
                seen.add(name.upper())
                r = self.ref(swhere, s)
                if r:
                    t.secrets.append(GitHubSecret(name=name, ref=r))
            if not t.secrets:
                self.err(where, "no secrets defined")
            targets.append(t)
        return targets

    # ---- jenkins

    def jenkins(self) -> tuple[str | None, JenkinsAuth, list[JenkinsStore]]:
        node = self.raw.get("jenkins") or {}
        if not node:
            return None, JenkinsAuth(), []
        url = node.get("url")
        auth_node = node.get("auth") or {}
        auth = JenkinsAuth()
        if auth_node:
            auth.username_ref = self.ref("jenkins.auth", auth_node, "username_key")
            auth.token_ref = self.ref("jenkins.auth", auth_node, "token_key")

        stores: list[JenkinsStore] = []
        for i, st in enumerate(node.get("stores") or []):
            where = f"jenkins.stores[{i}]"
            folder = st.get("folder")
            store = JenkinsStore(
                folder=str(folder).strip("/") if folder else None, domain=st.get("domain", "_"), credentials=[]
            )
            seen: set[str] = set()
            for j, c in enumerate(st.get("credentials") or []):
                cwhere = f"{where}.credentials[{j}]"
                cid = str(c.get("id", ""))
                if not JENKINS_ID_RE.match(cid):
                    self.err(cwhere, f"invalid credential id {cid!r}")
                if cid in seen:
                    self.err(cwhere, f"duplicate credential id {cid!r} in store {store.label}")
                seen.add(cid)
                ctype = c.get("type", "string")
                if ctype not in JENKINS_CRED_TYPES:
                    self.err(cwhere, f"type must be one of {JENKINS_CRED_TYPES}")
                    continue
                cred = JenkinsCredential(id=cid, type=ctype, description=str(c.get("description", "")), refs={})
                self._jenkins_fields(cwhere, c, cred)
                store.credentials.append(cred)
            if not store.credentials:
                self.err(where, "no credentials defined")
            stores.append(store)

        if stores and not url:
            self.err("jenkins", "'url' is required when stores are defined")
        return url, auth, stores

    def _jenkins_fields(self, where: str, c: dict[str, Any], cred: JenkinsCredential) -> None:
        def add(field_name: str, key_field: str, required: bool = True) -> None:
            r = self.ref(where, c, key_field, required=required) if c.get(key_field) or required else None
            if r:
                cred.refs[field_name] = r

        if cred.type == "string":
            add("secret", "key")
        elif cred.type == "usernamePassword":
            self._username(where, c, cred)
            add("password", "password_key")
        elif cred.type == "file":
            add("content", "key")
            cred.file_name = c.get("file_name")
            if not cred.file_name:
                self.err(where, "'file_name' is required for type=file")
        elif cred.type == "sshPrivateKey":
            self._username(where, c, cred)
            add("private_key", "private_key_key")
            add("passphrase", "passphrase_key", required=False)

    def _username(self, where: str, c: dict[str, Any], cred: JenkinsCredential) -> None:
        if c.get("username"):
            cred.username = str(c["username"])
        elif c.get("username_key"):
            r = self.ref(where, c, "username_key")
            if r:
                cred.refs["username"] = r
        else:
            self.err(where, "set either 'username' (literal) or 'username_key'")


def parse_manifest(raw: dict[str, Any]) -> Manifest:
    if not isinstance(raw, dict):
        raise ConfigError(["manifest root must be a mapping"])
    p = _Parser(raw)
    gh = p.github()
    jurl, jauth, jstores = p.jenkins()
    if p.errors:
        raise ConfigError(p.errors)
    return Manifest(
        default_mount=p.default_mount,
        github_targets=gh,
        jenkins_url=jurl,
        jenkins_auth=jauth,
        jenkins_stores=jstores,
    )


def load_manifest(path: str | Path) -> Manifest:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return parse_manifest(raw)
