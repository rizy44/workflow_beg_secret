"""Fake OpenBao server (AppRole, lookup-self, KV v1/v2, revoke-self) for tests."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scripts.utils import logger

NAMESPACE = "team-ns"
ROLE_ID, SECRET_ID, TOKEN = "role-123", "secret-456", "s.client-token-789"


class FakeOpenBao(BaseHTTPRequestHandler):
    kv2: dict = {}  # path -> data, mount kv/test
    kv1: dict = {}  # path -> data, mount legacy
    calls: list = []
    revoked: bool = False
    ttl: int = 600
    fail_next: list = []  # status codes to return before succeeding (retry tests)

    def log_message(self, *a):
        pass

    def _send(self, code, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self):
        return self.headers.get("X-Vault-Token") == TOKEN and not FakeOpenBao.revoked

    def do_GET(self):
        FakeOpenBao.calls.append(("GET", self.path))
        assert self.headers.get("X-Vault-Namespace") == NAMESPACE
        if FakeOpenBao.fail_next:
            return self._send(FakeOpenBao.fail_next.pop(0), {"errors": ["temporary"]})
        if not self._authorized():
            return self._send(403, {"errors": ["permission denied"]})
        if self.path == "/v1/auth/token/lookup-self":
            return self._send(200, {"data": {"ttl": FakeOpenBao.ttl, "policies": ["ci-read"], "expire_time": "x"}})
        for prefix, store, wrap in (
            ("/v1/kv/test/data/", FakeOpenBao.kv2, True),
            ("/v1/legacy/", FakeOpenBao.kv1, False),
        ):
            if self.path.startswith(prefix):
                path = self.path[len(prefix) :]
                if path not in store:
                    return self._send(404, {"errors": []})
                return self._send(200, {"data": {"data": store[path]}} if wrap else {"data": store[path]})
        self._send(404, {"errors": []})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        FakeOpenBao.calls.append(("POST", self.path))
        assert self.headers.get("X-Vault-Namespace") == NAMESPACE
        if self.path == "/v1/auth/approle/login":
            req = json.loads(body)
            if req != {"role_id": ROLE_ID, "secret_id": SECRET_ID}:
                return self._send(400, {"errors": ["invalid role or secret ID"]})
            FakeOpenBao.revoked = False
            return self._send(
                200, {"auth": {"client_token": TOKEN, "lease_duration": 600, "token_policies": ["ci-read"]}}
            )
        if self.path == "/v1/auth/token/revoke-self":
            if not self._authorized():
                return self._send(403, {"errors": ["permission denied"]})
            FakeOpenBao.revoked = True
            return self._send(204)
        self._send(404, {"errors": []})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "GITHUB_ACTIONS",
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "JENKINS_URL",
        "BUILD_ID",
        "WORKSPACE_TMP",
        "OPENBAO_URL",
        "OPENBAO_NAMESPACE",
        "OPENBAO_ROLE_ID",
        "OPENBAO_SECRET_ID",
        "OPENBAO_MOUNT",
        "OPENBAO_KV_VERSION",
        "OPENBAO_SECRETS",
        "OPENBAO_TOKEN",
        "OPENBAO_CACERT",
    ):
        monkeypatch.delenv(var, raising=False)
    logger.clear_secrets()


@pytest.fixture
def bao(monkeypatch):
    FakeOpenBao.kv2 = {
        "ci/artifactory": {"username": "art-user", "api_key": "art-key-secret", "port": 8081},
        "ci/dockerhub": {"username": "dh-user", "token": "dh-token\nsecond-line"},
    }
    FakeOpenBao.kv1 = {"app/legacy": {"password": "legacy-pw"}}
    FakeOpenBao.calls, FakeOpenBao.revoked, FakeOpenBao.ttl, FakeOpenBao.fail_next = [], False, 600, []
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenBao)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    monkeypatch.setenv("OPENBAO_URL", url)
    monkeypatch.setenv("OPENBAO_NAMESPACE", NAMESPACE)
    monkeypatch.setenv("OPENBAO_ROLE_ID", ROLE_ID)
    monkeypatch.setenv("OPENBAO_SECRET_ID", SECRET_ID)
    monkeypatch.setenv("OPENBAO_MOUNT", "kv/test")
    yield url
    srv.shutdown()
