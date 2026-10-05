import os
import stat
import subprocess
import sys
from pathlib import Path

from scripts import main
from tests.conftest import TOKEN, FakeOpenBao
from tests.test_stages import _load_java_properties

ROOT = Path(__file__).resolve().parents[1]
ALL_SECRETS = ["art-key-secret", "art-user", "dh-token", "second-line", "dh-user", "legacy-pw", TOKEN, "secret-456"]


def _no_leak(text):
    for value in ALL_SECRETS:
        assert value not in text, f"leaked {value!r}"


def _github_env(tmp_path, monkeypatch):
    env_file, out_file = tmp_path / "github_env", tmp_path / "github_output"
    env_file.write_text("")
    out_file.write_text("")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    return env_file, out_file


def test_github_fetch_then_revoke(bao, tmp_path, monkeypatch, capsys):
    env_file, out_file = _github_env(tmp_path, monkeypatch)
    rc = main.main(
        ["fetch", "--secret", "PATH=ci/artifactory,PREFIX=ARTIFACTORY_,KEYS=username|api_key",
         "--secret", "PATH=ci/dockerhub"]
    )  # fmt: skip
    assert rc == 0
    out, err = capsys.readouterr()
    for value in ("art-key-secret", "art-user", "dh-token", "second-line", "dh-user", TOKEN):
        assert f"::add-mask::{value}" in out
    _no_leak(err)
    env = env_file.read_text()
    for name in (
        "ARTIFACTORY_USERNAME<<",
        "ARTIFACTORY_API_KEY<<",
        "SECRET_USERNAME<<",
        "SECRET_TOKEN<<",
        "OPENBAO_TOKEN<<",
    ):
        assert name in env
    assert "keys<<" in out_file.read_text()
    assert not FakeOpenBao.revoked  # token handed to the pipeline

    monkeypatch.setenv("OPENBAO_TOKEN", TOKEN)
    assert main.main(["revoke"]) == 0
    assert FakeOpenBao.revoked
    assert main.main(["revoke"]) == 0  # second revoke is a no-op
    assert main.main(["check-token"]) == 1


def test_jenkins_properties(bao, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("JENKINS_URL", "http://jenkins")
    monkeypatch.setenv("BUILD_ID", "7")
    monkeypatch.setenv("WORKSPACE_TMP", str(tmp_path))
    monkeypatch.setenv(
        "OPENBAO_SECRETS", "PATH=ci/dockerhub,PREFIX=DOCKERHUB_\nPATH=app/legacy,MOUNT=legacy,KV=1,PREFIX=APP_"
    )
    assert main.main(["fetch"]) == 0
    _no_leak(capsys.readouterr().err)

    path = tmp_path / ".openbao_env.properties"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    props = _load_java_properties(path.read_text())
    assert props["DOCKERHUB_TOKEN"] == "dh-token\nsecond-line"
    assert props["APP_PASSWORD"] == "legacy-pw"
    assert props["OPENBAO_TOKEN"] == TOKEN
    assert props["OPENBAO_MASKED_KEYS"] == "APP_PASSWORD,DOCKERHUB_TOKEN,DOCKERHUB_USERNAME,OPENBAO_TOKEN"


def test_no_export_token_revokes_immediately(bao, tmp_path, monkeypatch):
    out = tmp_path / "p.properties"
    assert main.main(["fetch", "--platform", "local", "--output", str(out), "--secret", "PATH=ci/dockerhub",
                      "--no-export-token"]) == 0  # fmt: skip
    props = _load_java_properties(out.read_text())
    assert "OPENBAO_TOKEN" not in props and props["OPENBAO_MASKED_KEYS"] == "SECRET_TOKEN,SECRET_USERNAME"
    assert FakeOpenBao.revoked


def test_failure_after_login_revokes_and_writes_nothing(bao, tmp_path, monkeypatch, capsys):
    env_file, _ = _github_env(tmp_path, monkeypatch)
    assert main.main(["fetch", "--secret", "PATH=ci/dockerhub", "--secret", "PATH=ci/missing"]) == 1
    assert "secret not found: kv/test/ci/missing" in capsys.readouterr().err
    assert env_file.read_text() == ""
    assert FakeOpenBao.revoked


def test_invalid_input_never_calls_openbao(bao, capsys):
    assert main.main(["fetch", "--platform", "local", "--secret", "PREFIX=X_"]) == 2
    assert main.main(["fetch", "--platform", "local"]) == 2  # no secret at all
    assert FakeOpenBao.calls == []


def test_wrong_credentials(bao, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OPENBAO_SECRET_ID", "wrong")
    assert main.main(["fetch", "--platform", "local", "--output", str(tmp_path / "x"), "--secret", "PATH=ci/a"]) == 1
    assert "AppRole login failed" in capsys.readouterr().err
    assert not (tmp_path / "x").exists()


def test_runs_as_a_file_like_ci_does(bao, tmp_path):
    """`python3 scripts/main.py ...` from any directory (action.yml / Jenkins call it this way)."""
    out = tmp_path / "jenkins.properties"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "main.py"), "fetch", "--platform", "jenkins", "--output", str(out),
         "--secret", "PATH=ci/artifactory,PREFIX=ART_"],
        env={k: v for k, v in os.environ.items()}, cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    _no_leak(proc.stdout + proc.stderr)
    assert "Exported 3 secret(s): ART_API_KEY, ART_PORT, ART_USERNAME" in proc.stderr
    assert _load_java_properties(out.read_text())["ART_PORT"] == "8081"
