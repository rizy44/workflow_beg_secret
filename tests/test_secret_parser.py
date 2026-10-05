import pytest

from scripts._02_fetch_secrets.secret_parser import (
    SecretSpec,
    SecretSpecError,
    env_name,
    map_secrets,
    parse_spec,
    parse_specs,
)


def test_parse_full_spec():
    spec = parse_spec("path=/ci/dockerhub/, PREFIX=docker_ ,KEYS=username|token,MOUNT=kv/test,KV=1")
    assert spec == SecretSpec("ci/dockerhub", "DOCKER_", ("username", "token"), "kv/test", 1)


def test_defaults_and_empty_prefix():
    assert parse_spec("PATH=ci/a").prefix == "SECRET_"
    assert parse_spec("PATH=ci/a", default_prefix="X_").prefix == "X_"
    assert parse_spec("PATH=ci/a,PREFIX=").prefix == ""


@pytest.mark.parametrize(
    "bad",
    ["PREFIX=A_", "PATH=", "PATH=a,FOO=1", "PATH=a,PATH=b", "PATH=a,KV=3", "PATH=a,PREFIX=1A", "justtext"],
)
def test_parse_errors(bad):
    with pytest.raises(SecretSpecError):
        parse_spec(bad)


def test_parse_specs_skips_comments_and_requires_one():
    specs = parse_specs(["# header", "", "PATH=ci/a  # inline", "PATH=ci/b"])
    assert [s.path for s in specs] == ["ci/a", "ci/b"]
    with pytest.raises(SecretSpecError, match="no secret"):
        parse_specs(["# nothing"])


def test_env_name():
    assert env_name("SECRET_", "api_key") == "SECRET_API_KEY"
    assert env_name("ARTIFACTORY_", "user-name") == "ARTIFACTORY_USER_NAME"
    assert env_name("", "1st") == "_1ST"


def test_map_secrets_filters_and_converts():
    data = {"ci/a": {"user": "u", "pw": "p", "port": 8081, "cfg": {"a": 1}}}
    specs = [parse_spec("PATH=ci/a,PREFIX=A_,KEYS=user|port|cfg")]
    assert map_secrets(specs, lambda s: data[s.path]) == {"A_USER": "u", "A_PORT": "8081", "A_CFG": '{"a":1}'}


@pytest.mark.parametrize(
    "spec,match",
    [
        ("PATH=ci/a,KEYS=nope", "not found"),
        ("PATH=ci/a,PREFIX=", "reserved"),  # key `path` -> PATH
        ("PATH=ci/a,PREFIX=GITHUB_", "reserved"),
        ("PATH=ci/a,PREFIX=OPENBAO_", "reserved"),
    ],
)
def test_map_secrets_rejects(spec, match):
    data = {"ci/a": {"path": "x"}}
    with pytest.raises(SecretSpecError, match=match):
        map_secrets([parse_spec(spec)], lambda s: data[s.path])


def test_map_secrets_duplicate_names():
    data = {"ci/a": {"token": "1"}, "ci/b": {"token": "2"}}
    with pytest.raises(SecretSpecError, match="both"):
        map_secrets(parse_specs(["PATH=ci/a,PREFIX=X_", "PATH=ci/b,PREFIX=X_"]), lambda s: data[s.path])
