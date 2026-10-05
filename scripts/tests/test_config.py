import pytest

from beg_secret.config import ConfigError, SecretRef, parse_manifest


def _gh(**over):
    target = {"target": "repo", "repo": "o/r", "secrets": [{"name": "A_TOKEN", "path": "ci/x", "key": "token"}]}
    target.update(over)
    return {"github": [target]}


def test_minimal_repo_target():
    m = parse_manifest(_gh())
    assert m.github_targets[0].label == "o/r"
    assert m.github_targets[0].secrets[0].ref == SecretRef("kv", "ci/x", "token")


def test_mount_override_and_default():
    raw = _gh()
    raw["openbao"] = {"mount": "/secret/"}
    raw["github"][0]["secrets"].append({"name": "B", "mount": "other", "path": "/p/", "key": "k"})
    refs = parse_manifest(raw).all_refs()
    assert refs == [SecretRef("secret", "ci/x", "token"), SecretRef("other", "p", "k")]


@pytest.mark.parametrize("name", ["1ABC", "GITHUB_TOKEN", "has-dash", ""])
def test_invalid_github_names(name):
    with pytest.raises(ConfigError):
        parse_manifest(_gh(secrets=[{"name": name, "path": "p", "key": "k"}]))


def test_environment_requires_env_name():
    with pytest.raises(ConfigError, match="environment"):
        parse_manifest(_gh(target="environment"))


def test_errors_are_collected():
    raw = {"github": [{"target": "repo", "repo": "bad", "secrets": [{"name": "X"}]}]}
    with pytest.raises(ConfigError) as exc:
        parse_manifest(raw)
    assert len(exc.value.errors) >= 3  # repo format, missing path, missing key


def test_jenkins_types():
    raw = {
        "jenkins": {
            "url": "https://j",
            "auth": {"path": "ci/j", "username_key": "u", "token_key": "t"},
            "stores": [
                {
                    "folder": "team/app",
                    "credentials": [
                        {"id": "s", "type": "string", "path": "p", "key": "k"},
                        {
                            "id": "up",
                            "type": "usernamePassword",
                            "path": "p",
                            "username_key": "u",
                            "password_key": "pw",
                        },
                        {"id": "f", "type": "file", "path": "p", "key": "k", "file_name": "kubeconfig"},
                        {"id": "ssh", "type": "sshPrivateKey", "path": "p", "username": "git", "private_key_key": "pk"},
                    ],
                }
            ],
        }
    }
    m = parse_manifest(raw)
    store = m.jenkins_stores[0]
    assert store.label == "folder:team/app"
    creds = {c.id: c for c in store.credentials}
    assert set(creds["up"].refs) == {"username", "password"}
    assert set(creds["ssh"].refs) == {"private_key"} and creds["ssh"].username == "git"
    assert m.jenkins_auth.token_ref == SecretRef("kv", "ci/j", "t")


def test_jenkins_requires_url():
    raw = {"jenkins": {"stores": [{"credentials": [{"id": "s", "path": "p", "key": "k"}]}]}}
    with pytest.raises(ConfigError, match="url"):
        parse_manifest(raw)


def test_sample_manifest_is_valid():
    from pathlib import Path

    from beg_secret.config import load_manifest

    sample = Path(__file__).parent / "fixtures" / "secrets.yaml"
    m = load_manifest(sample)
    assert m.github_targets and m.jenkins_stores
