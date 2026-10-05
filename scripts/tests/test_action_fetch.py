"""Tests for .github/actions/openbao-secrets/fetch.py (stdlib-only runtime action)."""

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / ".github" / "actions" / "openbao-secrets" / "fetch.py"
_spec = importlib.util.spec_from_file_location("fetch", _SRC)
fetch = importlib.util.module_from_spec(_spec)
sys.modules["fetch"] = fetch
_spec.loader.exec_module(fetch)


def test_parse_spec_forms():
    entries = fetch.parse_spec(
        """
        # comment
        github/dockerhub token | DOCKERHUB_TOKEN
        /common/sonar/ token
        github/nexus * | NEXUS_ ; github/npm *
        """
    )
    assert entries == [
        fetch.Entry("github/dockerhub", "token", "DOCKERHUB_TOKEN"),
        fetch.Entry("common/sonar", "token", None),
        fetch.Entry("github/nexus", "*", "NEXUS_"),
        fetch.Entry("github/npm", "*", None),
    ]


@pytest.mark.parametrize("bad", ["", "onlypath", "a b c", "p k | 1BAD", "p k | has-dash"])
def test_parse_spec_rejects(bad):
    with pytest.raises(fetch.FetchError):
        fetch.parse_spec(bad)


def test_resolve_names_and_errors():
    data = {"g/n": {"user-name": "u", "password": "p"}, "g/x": {"token": "t", "n": 5}}
    values = fetch.resolve(fetch.parse_spec("g/n * | NEXUS_\ng/x token\ng/x n | NUM"), data.__getitem__)
    assert values == {"NEXUS_USER_NAME": "u", "NEXUS_PASSWORD": "p", "TOKEN": "t", "NUM": "5"}
    with pytest.raises(fetch.FetchError, match="not found"):
        fetch.resolve(fetch.parse_spec("g/x missing"), data.__getitem__)
    with pytest.raises(fetch.FetchError, match="twice"):
        fetch.resolve(fetch.parse_spec("g/x token\ng/n password | TOKEN"), data.__getitem__)
    with pytest.raises(fetch.FetchError, match="reserved"):
        fetch.resolve(fetch.parse_spec("g/x token | GITHUB_TOKEN"), data.__getitem__)


class _Handler(BaseHTTPRequestHandler):
    kv = {"github/dockerhub": {"username": "me", "token": "line1\nline2"}}
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
        path = self.path.removeprefix("/v1/kv/data/")
        if path in self.kv:
            return self._send(200, {"data": {"data": self.kv[path]}})
        self._send(404, {"errors": []})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.calls.append(self.path)
        if self.path == "/v1/auth/jwt/login":
            assert json.loads(body) == {"role": "github-actions", "jwt": "gh-jwt"}
            return self._send(200, {"auth": {"client_token": "bao-tok"}})
        self._send(204)


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_main_end_to_end(server, tmp_path, monkeypatch, capsys):
    env_file = tmp_path / "github_env"
    env_file.write_text("")
    monkeypatch.setenv("BAO_ADDR", server)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server + "/oidc?x=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t")
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    monkeypatch.setenv("SECRETS_SPEC", "github/dockerhub * | DOCKERHUB_")
    _Handler.calls.clear()

    assert fetch.main() == 0

    out = capsys.readouterr().out
    for secret in ("bao-tok", "me", "line1", "line2"):
        assert f"::add-mask::{secret}" in out
    assert out.index("::add-mask::line1") < out.index("Exported")
    content = env_file.read_text()
    assert content.startswith("DOCKERHUB_USERNAME<<ghadelim_")
    assert "\nline1\nline2\n" in content
    assert _Handler.calls == ["/v1/auth/jwt/login", "/v1/auth/token/revoke-self"]


def test_main_missing_path_fails_and_revokes(server, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BAO_ADDR", server)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server + "/oidc")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t")
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "e"))
    monkeypatch.setenv("SECRETS_SPEC", "github/nope token")
    _Handler.calls.clear()
    assert fetch.main() == 1
    assert "HTTP 404" in capsys.readouterr().out
    assert _Handler.calls[-1] == "/v1/auth/token/revoke-self"
    assert not (tmp_path / "e").exists()
