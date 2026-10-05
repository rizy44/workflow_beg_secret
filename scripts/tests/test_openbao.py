import pytest

from common.openbao import OpenBao, OpenBaoError


def test_token_auth_is_not_revoked(bao_server, monkeypatch):
    monkeypatch.setenv("BAO_TOKEN", "bao-tok")
    bao = OpenBao.from_env()
    assert bao.get("kv/test", "github/dockerhub", "username") == "me"
    bao.revoke()
    assert FakeCalls.get() == []


def test_approle_auto_detect_and_revoke(bao_server, monkeypatch):
    monkeypatch.setenv("BAO_ROLE_ID", "rid")
    monkeypatch.setenv("BAO_SECRET_ID", "sid")
    bao = OpenBao.from_env()
    assert bao.read_kv("/kv/test/", "/github/dockerhub/")["username"] == "me"
    bao.revoke()
    assert FakeCalls.get() == ["/v1/auth/approle/login", "/v1/auth/token/revoke-self"]


def test_errors(bao_server, monkeypatch):
    with pytest.raises(OpenBaoError, match="no OpenBao credentials"):
        OpenBao.from_env()
    monkeypatch.setenv("BAO_TOKEN", "bao-tok")
    bao = OpenBao.from_env()
    with pytest.raises(OpenBaoError, match="HTTP 404"):
        bao.read_kv("kv/test", "nope")
    with pytest.raises(OpenBaoError, match="key 'x' not found"):
        bao.get("kv/test", "github/dockerhub", "x")
    monkeypatch.setenv("BAO_ADDR", "http://127.0.0.1:1")
    with pytest.raises(OpenBaoError, match="cannot reach"):
        OpenBao.from_env().read_kv("kv/test", "a")


class FakeCalls:
    @staticmethod
    def get():
        from conftest import FakeOpenBao

        return FakeOpenBao.calls
