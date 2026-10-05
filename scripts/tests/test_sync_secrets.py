from common.manifest import parse_manifest
from openbao import sync_secrets


class FakeBao:
    def __init__(self, data):
        self.data = data

    def get(self, mount, path, key):
        if (path, key) not in self.data:
            raise KeyError(key)
        return self.data[(path, key)]


def test_sync_github_dry_run_without_token(monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    m = parse_manifest(
        {
            "github": [
                {
                    "repo": "o/r",
                    "secrets": [
                        {"name": "OK", "path": "p", "key": "k"},
                        {"name": "MISSING", "path": "p", "key": "nope"},
                    ],
                }
            ]
        }
    )
    results = sync_secrets.sync_github(m, FakeBao({("p", "k"): "v"}), dry_run=True, only=[])
    assert [r.failed for r in results] == [False, True]


def test_validate_command(tmp_path):
    cfg = tmp_path / "s.yaml"
    cfg.write_text("github:\n  - repo: o/r\n    secrets:\n      - {name: A, path: p, key: k}\n")
    assert sync_secrets.main(["validate", "--config", str(cfg)]) == 0
    cfg.write_text("github:\n  - repo: bad\n")
    assert sync_secrets.main(["validate", "--config", str(cfg)]) == 2


def test_missing_openbao_config_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.delenv("BAO_ADDR", raising=False)
    cfg = tmp_path / "s.yaml"
    cfg.write_text("github:\n  - repo: o/r\n    secrets:\n      - {name: A, path: p, key: k}\n")
    assert sync_secrets.main(["sync-github", "--config", str(cfg), "--dry-run"]) == 1
