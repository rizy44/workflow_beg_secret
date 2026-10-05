import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FakeOpenBao
from openbao import fetch_secrets as fetch

SCRIPT = Path(__file__).resolve().parents[1] / "openbao" / "fetch_secrets.py"


def test_parse_spec_forms():
    entries = fetch.parse_spec(
        """
        # comment
        github/dockerhub token | DOCKERHUB_TOKEN   # trailing comment
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


@pytest.mark.parametrize("bad", ["", "# only comment", "onlypath", "a b c", "p k | 1BAD", "p k | has-dash"])
def test_parse_spec_rejects(bad):
    with pytest.raises(fetch.SpecError):
        fetch.parse_spec(bad)


def _resolve(spec, data):
    return fetch.resolve(fetch.parse_spec(spec), data.__getitem__, lambda p, k: data[p][k])


def test_resolve_names_and_errors():
    data = {"g/n": {"user-name": "u", "password": "p"}, "g/x": {"token": "t"}}
    assert _resolve("g/n * | NEXUS_\ng/x token", data) == {"NEXUS_USER_NAME": "u", "NEXUS_PASSWORD": "p", "TOKEN": "t"}
    with pytest.raises(fetch.SpecError, match="twice"):
        _resolve("g/x token\ng/n password | TOKEN", data)
    for reserved in ("GITHUB_TOKEN", "BAO_TOKEN"):
        with pytest.raises(fetch.SpecError, match="reserved"):
            _resolve(f"g/x token | {reserved}", data)


def test_github_env_mode(github_oidc, tmp_path, monkeypatch, capsys):
    env_file = tmp_path / "github_env"
    env_file.write_text("")
    monkeypatch.setenv("GITHUB_ENV", str(env_file))

    assert fetch.main(["--spec", "github/dockerhub * | DOCKERHUB_"]) == 0

    out = capsys.readouterr().out
    for secret in ("bao-tok", "me", "line1", "line2"):
        assert f"::add-mask::{secret}" in out
    content = env_file.read_text()
    assert content.startswith("DOCKERHUB_USERNAME<<ghadelim_")
    assert "\nline1\nline2\n" in content
    assert FakeOpenBao.calls == ["/v1/auth/jwt/login", "/v1/auth/token/revoke-self"]


def test_dotenv_mode_with_approle(bao_server, tmp_path, monkeypatch):
    monkeypatch.setenv("BAO_ROLE_ID", "rid")
    monkeypatch.setenv("BAO_SECRET_ID", "sid")
    spec = tmp_path / "secrets.txt"
    spec.write_text("github/dockerhub token | DH_TOKEN\n")
    out = tmp_path / "bao.env"
    assert fetch.main(["--spec-file", str(spec), "--output", str(out)]) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.read_text() == "export DH_TOKEN='line1\nline2'\n"


def test_no_destination_is_an_error(bao_server, monkeypatch, capsys):
    monkeypatch.setenv("BAO_TOKEN", "bao-tok")
    assert fetch.main(["--spec", "github/dockerhub token"]) == 1
    assert "nowhere to put the secrets" in capsys.readouterr().err
    assert FakeOpenBao.calls == []  # failed before contacting OpenBao


def test_missing_path_fails_and_revokes(github_oidc, tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "e"))
    assert fetch.main(["--spec", "github/nope token"]) == 1
    assert FakeOpenBao.calls[-1] == "/v1/auth/token/revoke-self"
    assert not (tmp_path / "e").exists()


def test_exec_mode_runs_command_with_secrets(bao_server):
    """Run as a real subprocess (Jenkins style): secrets only exist in the child's environment."""
    env = {**os.environ, "BAO_TOKEN": "bao-tok"}
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--spec", "github/dockerhub username | DH_USER", "--exec", "--",
         sys.executable, "-c", "import os; print('user=' + os.environ['DH_USER'])"],
        env=env, capture_output=True, text=True, timeout=30,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "user=me"
    assert "with 1 secret(s): DH_USER" in proc.stderr
