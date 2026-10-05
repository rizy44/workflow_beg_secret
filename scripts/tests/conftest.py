import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class FakeOpenBao(BaseHTTPRequestHandler):
    """Tiny OpenBao + GitHub OIDC stand-in. KV lives under mount `kv/test`, namespace `ns1`."""

    kv: dict = {}
    calls: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.startswith("/oidc"):
            assert "audience=openbao" in self.path
            return self._send(200, {"value": "gh-jwt"})
        assert self.headers["X-Vault-Token"] == "bao-tok"
        assert self.headers["X-Vault-Namespace"] == "ns1"
        path = self.path.removeprefix("/v1/kv/test/data/")
        if path in self.kv:
            return self._send(200, {"data": {"data": self.kv[path]}})
        self._send(404, {"errors": []})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.calls.append(self.path)
        assert self.headers["X-Vault-Namespace"] == "ns1"
        if self.path == "/v1/auth/jwt/login":
            assert json.loads(body) == {"role": "github-actions", "jwt": "gh-jwt"}
            return self._send(200, {"auth": {"client_token": "bao-tok"}})
        if self.path == "/v1/auth/approle/login":
            assert json.loads(body) == {"role_id": "rid", "secret_id": "sid"}
            return self._send(200, {"auth": {"client_token": "bao-tok"}})
        self._send(204)


@pytest.fixture
def bao_server(monkeypatch):
    FakeOpenBao.kv = {"github/dockerhub": {"username": "me", "token": "line1\nline2"}}
    FakeOpenBao.calls = []
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenBao)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    for var in ("BAO_TOKEN", "BAO_ROLE_ID", "BAO_SECRET_ID", "BAO_AUTH_METHOD", "GITHUB_ACTIONS", "GITHUB_ENV"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("BAO_ADDR", url)
    monkeypatch.setenv("BAO_NAMESPACE", "ns1")
    monkeypatch.setenv("BAO_MOUNT", "kv/test")
    yield url
    srv.shutdown()


@pytest.fixture
def github_oidc(bao_server, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", bao_server + "/oidc?x=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t")
    monkeypatch.setenv("BAO_ROLE", "github-actions")
    return bao_server
