"""Create/update Jenkins credentials through the Credentials plugin REST API.

Endpoints used (store = system or folder):
  GET  {store}/domain/{domain}/credential/{id}/api/json   -> exists?
  POST {store}/domain/{domain}/credential/{id}/config.xml -> update
  POST {store}/domain/{domain}/createCredentials          -> create

Authentication is HTTP basic with a Jenkins user + API token. Requests
authenticated by API token are exempt from CSRF, but we still send a crumb
when the crumb issuer is reachable, to support older setups.

Required Jenkins plugins: credentials, plain-credentials, ssh-credentials
(all part of the default/suggested plugin set).
"""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import escape

import requests

from beg_secret.config import JenkinsCredential, JenkinsStore

log = logging.getLogger(__name__)

STRING_CLASS = "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
USERPASS_CLASS = "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
FILE_CLASS = "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl"
SSH_CLASS = "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey"
SSH_DIRECT_SOURCE = SSH_CLASS + "$DirectEntryPrivateKeySource"


class JenkinsError(Exception):
    pass


def _el(tag: str, value: str) -> str:
    return f"<{tag}>{escape(value)}</{tag}>"


def build_credential_xml(cred: JenkinsCredential, values: dict[str, str]) -> str:
    """Render the credential as the XML the Credentials plugin accepts.

    `values` maps the logical field names of JenkinsCredential.refs to resolved
    plaintext values (plus 'username' when given literally).
    """
    head = _el("scope", "GLOBAL") + _el("id", cred.id) + _el("description", cred.description)
    if cred.type == "string":
        body = head + _el("secret", values["secret"])
        cls = STRING_CLASS
    elif cred.type == "usernamePassword":
        body = head + _el("username", values["username"]) + _el("password", values["password"])
        cls = USERPASS_CLASS
    elif cred.type == "file":
        content_b64 = base64.b64encode(values["content"].encode("utf-8")).decode("ascii")
        body = head + _el("fileName", cred.file_name or cred.id) + _el("secretBytes", content_b64)
        cls = FILE_CLASS
    elif cred.type == "sshPrivateKey":
        body = (
            head
            + _el("username", values["username"])
            + f'<privateKeySource class="{SSH_DIRECT_SOURCE}">'
            + _el("privateKey", values["private_key"])
            + "</privateKeySource>"
        )
        if values.get("passphrase"):
            body += _el("passphrase", values["passphrase"])
        cls = SSH_CLASS
    else:  # pragma: no cover - guarded by config validation
        raise JenkinsError(f"unsupported credential type {cred.type}")
    return f"<{cls}>{body}</{cls}>"


class JenkinsClient:
    def __init__(self, url: str, username: str, api_token: str, verify: bool | str = True, timeout: int = 30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (username, api_token)
        self.session.verify = verify
        self._crumb_loaded = False

    def _load_crumb(self) -> None:
        if self._crumb_loaded:
            return
        self._crumb_loaded = True
        try:
            resp = self.session.get(f"{self.url}/crumbIssuer/api/json", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                self.session.headers[data["crumbRequestField"]] = data["crumb"]
        except requests.RequestException as exc:
            log.debug("crumb issuer not available: %s", exc)

    def _call(self, method: str, path: str, ok: tuple[int, ...] = (200,), **kwargs: Any) -> requests.Response:
        if method != "GET":
            self._load_crumb()
        resp = self.session.request(method, f"{self.url}{path}", timeout=self.timeout, **kwargs)
        if resp.status_code not in ok:
            # Never echo the request body (it contains the secret).
            raise JenkinsError(f"{method} {path}: HTTP {resp.status_code}")
        return resp

    def whoami(self) -> str:
        return self._call("GET", "/whoAmI/api/json").json().get("name", "?")

    @staticmethod
    def store_path(store: JenkinsStore) -> str:
        if store.folder:
            folder = "".join(f"/job/{quote(part, safe='')}" for part in store.folder.split("/"))
            return f"{folder}/credentials/store/folder/domain/{quote(store.domain, safe='')}"
        return f"/credentials/store/system/domain/{quote(store.domain, safe='')}"

    def check_store(self, store: JenkinsStore) -> None:
        self._call("GET", f"{self.store_path(store)}/api/json")

    def exists(self, store: JenkinsStore, cred_id: str) -> bool:
        resp = self._call(
            "GET", f"{self.store_path(store)}/credential/{quote(cred_id, safe='')}/api/json", ok=(200, 404)
        )
        return resp.status_code == 200

    def upsert(self, store: JenkinsStore, cred: JenkinsCredential, values: dict[str, str]) -> str:
        xml = build_credential_xml(cred, values).encode("utf-8")
        headers = {"Content-Type": "application/xml; charset=utf-8"}
        base = self.store_path(store)
        if self.exists(store, cred.id):
            self._call("POST", f"{base}/credential/{quote(cred.id, safe='')}/config.xml", data=xml, headers=headers)
            return "updated"
        self._call("POST", f"{base}/createCredentials", ok=(200, 302), data=xml, headers=headers, allow_redirects=False)
        return "created"
