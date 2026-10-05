"""Write GitHub Actions secrets (repo / environment / org) via the REST API.

Secrets are encrypted client-side with the target's libsodium public key
(sealed box), as required by the API. GitHub never returns secret values,
so every sync is an idempotent overwrite.

Token permissions needed (GitHub App or fine-grained PAT):
  repo / environment secrets -> Repository permission "Secrets: Read and write"
                                (+ "Environments: Read" for environment secrets)
  org secrets                -> Organization permission "Secrets: Read and write"
"""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import quote

import requests
from nacl import encoding, public

from beg_secret.config import GitHubTarget

log = logging.getLogger(__name__)


class GitHubError(Exception):
    pass


def encrypt_secret(public_key_b64: str, value: str) -> str:
    pk = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder())
    sealed = public.SealedBox(pk).encrypt(value.encode("utf-8"))
    return base64.b64encode(sealed).decode("utf-8")


class GitHubSecretsClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com", timeout: int = 30):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        self._key_cache: dict[str, dict[str, str]] = {}
        self._repo_id_cache: dict[str, int] = {}

    def _call(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        resp = self.session.request(method, f"{self.api_url}{path}", timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            raise GitHubError(f"{method} {path}: HTTP {resp.status_code} {resp.text[:300]}")
        return resp

    @staticmethod
    def base_path(target: GitHubTarget) -> str:
        if target.kind == "repo":
            return f"/repos/{target.repo}/actions/secrets"
        if target.kind == "environment":
            return f"/repos/{target.repo}/environments/{quote(target.environment or '', safe='')}/secrets"
        return f"/orgs/{target.org}/actions/secrets"

    def public_key(self, target: GitHubTarget) -> dict[str, str]:
        base = self.base_path(target)
        if base not in self._key_cache:
            self._key_cache[base] = self._call("GET", f"{base}/public-key").json()
        return self._key_cache[base]

    def repo_id(self, full_name: str) -> int:
        if full_name not in self._repo_id_cache:
            self._repo_id_cache[full_name] = self._call("GET", f"/repos/{full_name}").json()["id"]
        return self._repo_id_cache[full_name]

    def check_access(self, target: GitHubTarget) -> None:
        """Dry-run helper: fetching the public key proves the token can manage secrets there."""
        self.public_key(target)

    def put_secret(self, target: GitHubTarget, name: str, value: str) -> str:
        """Create or update a secret. Returns 'created' or 'updated'."""
        key = self.public_key(target)
        body: dict[str, Any] = {"encrypted_value": encrypt_secret(key["key"], value), "key_id": key["key_id"]}
        if target.kind == "org":
            body["visibility"] = target.visibility
            if target.visibility == "selected":
                body["selected_repository_ids"] = [self.repo_id(r) for r in target.selected_repositories]
        resp = self._call("PUT", f"{self.base_path(target)}/{name}", json=body)
        return "created" if resp.status_code == 201 else "updated"
