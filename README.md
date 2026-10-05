# workflow_beg_secret

Tooling dùng chung cho [`beg_secret_management-`](https://github.com/rizy44/beg_secret_management-):
đồng bộ secret từ **OpenBao** sang **GitHub Actions secrets** và **Jenkins credentials**.

```
workflow_beg_secret/
├── .github/workflows/
│   ├── sync.yml              # reusable workflow (workflow_call), target=github|jenkins
│   └── ci.yml                # ruff + pytest cho scripts/
├── scripts/
│   ├── beg_secret/
│   │   ├── __main__.py       # python -m beg_secret ...
│   │   ├── cli.py            # validate | sync-github | sync-jenkins, --dry-run, --only
│   │   ├── config.py         # đọc + validate manifest secrets.yaml
│   │   ├── openbao_client.py # login token/jwt(GitHub OIDC)/approle, đọc KV v2
│   │   ├── github_secrets.py # mã hóa sealed box + PUT repo/environment/org secret
│   │   └── jenkins_credentials.py # create/update string, usernamePassword, file, sshPrivateKey
│   ├── tests/
│   ├── requirements.txt / requirements-dev.txt / pyproject.toml
├── helm/                     # (để sau) chart Jenkins + seed job
└── jenkins/                  # flow Jenkinsfile (xem jenkins/README.md)
```

## CLI

```bash
cd scripts
pip install -r requirements.txt
python -m beg_secret validate     --config path/to/secrets.yaml
python -m beg_secret sync-github  --config path/to/secrets.yaml --dry-run
python -m beg_secret sync-jenkins --config path/to/secrets.yaml --only system
```

| Biến môi trường | Ý nghĩa |
|---|---|
| `BAO_ADDR` | địa chỉ OpenBao (bắt buộc) |
| `BAO_AUTH_METHOD` | `token` (mặc định) \| `jwt` \| `approle` |
| `BAO_TOKEN` | khi `token` |
| `BAO_JWT_ROLE`, `BAO_JWT_MOUNT`=jwt, `BAO_JWT_AUDIENCE`=openbao | khi `jwt`; JWT tự lấy từ GitHub OIDC |
| `BAO_ROLE_ID`, `BAO_SECRET_ID`, `BAO_APPROLE_MOUNT`=approle | khi `approle` (Jenkins) |
| `BAO_NAMESPACE`, `BAO_CACERT` | tùy chọn |
| `GH_TOKEN` | token ghi được secret ở repo/org đích |
| `JENKINS_URL`, `JENKINS_USER`, `JENKINS_API_TOKEN`, `JENKINS_CACERT` | ghi đè `jenkins.*` trong manifest |

Exit code: `0` thành công, `1` có ít nhất một mục lỗi (các mục khác vẫn chạy tiếp),
`2` manifest không hợp lệ. Khi chạy trên Actions, bảng kết quả được ghi vào job summary.

## Dev

```bash
cd scripts && pip install -r requirements-dev.txt && ruff check . && python -m pytest -q
```
