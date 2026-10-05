from beg_secret import cli
from beg_secret.config import parse_manifest


class FakeBao:
    def __init__(self, data):
        self.data = data

    def resolve(self, ref):
        return self.data[(ref.path, ref.key)]


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
    results = cli.sync_github(m, FakeBao({("p", "k"): "v"}), dry_run=True, only=[])
    assert [r.failed for r in results] == [False, True]


def test_validate_command(tmp_path):
    cfg = tmp_path / "s.yaml"
    cfg.write_text("github:\n  - repo: o/r\n    secrets:\n      - {name: A, path: p, key: k}\n")
    assert cli.main(["validate", "--config", str(cfg)]) == 0
    cfg.write_text("github:\n  - repo: bad\n")
    assert cli.main(["validate", "--config", str(cfg)]) == 2
