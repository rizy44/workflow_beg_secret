import io
import logging
import re

import pytest

from scripts._01_authenticate.approle_login import AuthError, approle_login
from scripts._01_authenticate.token_validator import TokenInvalidError, validate_token
from scripts._02_fetch_secrets.kv_v1_reader import read_kv_v1
from scripts._02_fetch_secrets.kv_v2_reader import SecretReadError, read_kv_v2
from scripts._03_mask_secrets.github_masker import mask_values
from scripts._04_export_env.github_exporter import export_github_env
from scripts._04_export_env.jenkins_exporter import render_properties
from scripts._05_revoke.token_revoker import revoke_self
from scripts.utils.http_client import OpenBaoHttpClient, OpenBaoHttpError
from scripts.utils.logger import get_logger, register_secret
from tests.conftest import NAMESPACE, ROLE_ID, SECRET_ID, TOKEN, FakeOpenBao


@pytest.fixture
def http(bao):
    return OpenBaoHttpClient(bao, NAMESPACE, retries=2, backoff=0, sleep=lambda s: None)


def test_login_validate_read_revoke(http):
    login = approle_login(http, ROLE_ID, SECRET_ID)
    assert login.client_token == TOKEN and login.lease_duration == 600
    assert TOKEN not in repr(login)
    assert validate_token(http, TOKEN, min_ttl=60).ttl == 600
    assert read_kv_v2(http, TOKEN, "kv/test", "/ci/artifactory/")["api_key"] == "art-key-secret"
    assert read_kv_v1(http, TOKEN, "legacy", "app/legacy") == {"password": "legacy-pw"}
    assert revoke_self(http, TOKEN) is True
    assert revoke_self(http, TOKEN) is False  # idempotent
    with pytest.raises(TokenInvalidError):
        validate_token(http, TOKEN)


def test_login_errors(http):
    with pytest.raises(AuthError, match="missing"):
        approle_login(http, "", SECRET_ID)
    with pytest.raises(AuthError, match="wrong role_id/secret_id"):
        approle_login(http, ROLE_ID, "bad")


def test_min_ttl(http):
    FakeOpenBao.ttl = 30
    with pytest.raises(TokenInvalidError, match="expires in 30s"):
        validate_token(http, TOKEN, min_ttl=60)


def test_read_errors(http):
    with pytest.raises(SecretReadError, match="not found: kv/test/ci/nope"):
        read_kv_v2(http, TOKEN, "kv/test", "ci/nope")
    with pytest.raises(SecretReadError, match="permission denied"):
        read_kv_v2(http, "bad-token", "kv/test", "ci/artifactory")


def test_retry_on_5xx_but_not_4xx(http):
    FakeOpenBao.fail_next = [503, 502]
    assert read_kv_v2(http, TOKEN, "kv/test", "ci/dockerhub")["username"] == "dh-user"
    FakeOpenBao.fail_next = [503, 503, 503]
    with pytest.raises(SecretReadError, match="HTTP 503"):
        read_kv_v2(http, TOKEN, "kv/test", "ci/dockerhub")
    FakeOpenBao.calls.clear()
    FakeOpenBao.fail_next = [400]
    with pytest.raises(SecretReadError):
        read_kv_v2(http, TOKEN, "kv/test", "ci/dockerhub")
    assert len(FakeOpenBao.calls) == 1


def test_unreachable():
    client = OpenBaoHttpClient("http://127.0.0.1:1", retries=1, backoff=0, sleep=lambda s: None)
    with pytest.raises(OpenBaoHttpError, match="cannot reach"):
        client.request("GET", "sys/health")
    with pytest.raises(OpenBaoHttpError, match="empty"):
        OpenBaoHttpClient("")


def test_logger_redacts_registered_secrets(capsys):
    log = get_logger("test")
    register_secret("top-secret\nline-two")
    log.info("value=%s and %s", "top-secret", "line-two")
    log.log(logging.WARNING, "nested: xx-top-secret-xx")
    err = capsys.readouterr().err
    assert "top-secret" not in err and "line-two" not in err
    assert err.count("***") == 3


def test_github_masker():
    out = io.StringIO()
    assert mask_values(["abc", "line1\nline2", "100%", "abc", ""], out) == 4
    assert out.getvalue() == "::add-mask::abc\n::add-mask::line1\n::add-mask::line2\n::add-mask::100%25\n"


def test_github_env_heredoc(tmp_path):
    env_file = tmp_path / "env"
    export_github_env({"A": "x=y", "B": "l1\nl2"}, str(env_file))
    blocks = re.findall(r"^(\w+)<<(ghadelimiter_\w+)\n(.*?)\n\2$", env_file.read_text(), re.M | re.S)
    assert [(n, v) for n, _, v in blocks] == [("A", "x=y"), ("B", "l1\nl2")]


def _load_java_properties(text):
    """Minimal java.util.Properties.load() for the escapes render_properties emits."""
    out = {}
    for line in text.splitlines():
        key, value, cur, i, in_key = [], [], None, 0, True
        cur = key
        while i < len(line):
            ch = line[i]
            if ch == "\\":
                nxt = line[i + 1]
                if nxt == "u":
                    cur.append(chr(int(line[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                cur.append({"n": "\n", "r": "\r", "t": "\t", "f": "\f"}.get(nxt, nxt))
                i += 2
                continue
            if in_key and ch == "=":
                in_key, cur = False, value
            else:
                cur.append(ch)
            i += 1
        k = "".join(key)
        v = "".join(value).encode("utf-16", "surrogatepass").decode("utf-16")
        out[k] = v
    return out


def test_properties_roundtrip():
    values = {"A": "p@ss=w:rd#!\\x", "B": " lead space", "C": "multi\nline\ttab", "D": "việt 🔑"}
    text = render_properties(values)
    assert text.isascii() and len(text.splitlines()) == 4
    assert _load_java_properties(text) == values
