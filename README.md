# workflow_beg_secret

**Generic CI workflow** dùng chung cho mọi repo. Logic nằm trong `scripts/` theo
từng stage, nên **GitHub Actions và Jenkins gọi cùng một script**. Secret lấy từ
**OpenBao** lúc chạy, GitHub không cần lưu secret nào.

```
workflow_beg_secret/
├── .github/
│   ├── workflows/
│   │   ├── pipeline.yml          # generic reusable workflow: checkout → secrets → setup/lint/test/build/deploy
│   │   ├── sync.yml              # reusable: copy OpenBao → Jenkins credentials (beg_secret_management dùng)
│   │   └── ci.yml                # ruff + pytest cho scripts/
│   └── actions/openbao-secrets/  # composite action, chỉ bọc scripts/openbao/fetch_secrets.py
├── scripts/                      # ← toàn bộ logic, gọi được từ GitHub Actions lẫn Jenkins
│   ├── common/                   # module dùng chung
│   │   ├── openbao.py            #   client OpenBao (stdlib): token / jwt (GitHub OIDC) / approle, namespace, KV v2
│   │   ├── ci.py                 #   nhận diện GitHub/Jenkins/local, mask, GITHUB_ENV, dotenv
│   │   ├── manifest.py           #   manifest cho stage sync
│   │   ├── github_api.py         #   ghi GitHub secret (dùng cho ngoại lệ)
│   │   └── jenkins_api.py        #   ghi Jenkins credential
│   ├── openbao/                  # stage "secrets"
│   │   ├── fetch_secrets.py      #   lấy secret cho job (KHÔNG cần pip install)
│   │   └── sync_secrets.py       #   sync sang Jenkins (cần requirements.txt)
│   ├── tests/
│   └── requirements*.txt, pyproject.toml
├── jenkins/Jenkinsfile.example   # Jenkins gọi cùng scripts/
├── examples/                     # pipeline mẫu cho repo khác + file spec mẫu
└── helm/                         # (để sau)
```

## OpenBao

| Biến | Mặc định trong workflow | Ghi chú |
|---|---|---|
| `BAO_ADDR` | variable `BAO_ADDR` | bắt buộc |
| `BAO_NAMESPACE` | variable `BAO_NAMESPACE` | namespace của bạn |
| `BAO_MOUNT` | `kv/test` | mount KV v2; path trong spec tính từ mount này |
| `BAO_AUTH_METHOD` | `jwt` trên GitHub | tự nhận diện nếu để trống: `BAO_TOKEN` → token, `BAO_ROLE_ID`+`BAO_SECRET_ID` → approle, có OIDC → jwt |
| `BAO_ROLE` | `github-actions` | jwt role |
| `BAO_CACERT` / `BAO_CACERT_PEM` | | CA riêng (đường dẫn file / nội dung PEM) |

## Spec secret

Viết inline (input `secrets:`) hoặc trong một file, ví dụ `.ci/secrets.txt` trong repo
gọi tới. Cùng một file dùng được cho cả GitHub (`secrets_file:`) và Jenkins (`--spec-file`).

```
# <path> <key> [| ENV_NAME]        <path> * [| PREFIX_]
github/dockerhub token | DOCKERHUB_TOKEN     -> DOCKERHUB_TOKEN
github/dockerhub token                      -> TOKEN
github/aws-prod * | AWS_                    -> AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ...
```
Lỗi (path/key không tồn tại, trùng tên, tên bắt đầu bằng `GITHUB_`/`RUNNER_`/`ACTIONS_`/`BAO_`)
làm stage fail và không export gì.

## GitHub Actions: gọi generic pipeline

```yaml
jobs:
  ci:
    uses: rizy44/workflow_beg_secret/.github/workflows/pipeline.yml@main
    permissions:
      contents: read
      id-token: write
    with:
      bao_addr: ${{ vars.BAO_ADDR }}
      bao_namespace: ${{ vars.BAO_NAMESPACE }}
      secrets_file: .ci/secrets.txt
      test: ./scripts/test.sh
      build: ./scripts/build.sh
```

- Thứ tự: checkout → **secrets** → setup → lint → test → build → deploy. Stage để trống thì bỏ qua.
- Mỗi stage là một lệnh bash (`set -euo pipefail`) chạy trong `working_directory` của repo gọi tới.
- `$CI_SCRIPTS` trỏ tới `scripts/` của repo này, để gọi script dùng chung.
- Secret có trong env của mọi stage và đã được mask.
- Input khác: `runs_on`, `environment`, `timeout_minutes`, `bao_mount`, `bao_auth_method`, `bao_role`, `ci_ref`.

Repo muốn giữ workflow riêng thì chỉ cần dùng step: `uses: rizy44/workflow_beg_secret/.github/actions/openbao-secrets@main`
(xem `examples/own-workflow-action.yml`).

## Jenkins: gọi cùng script

```groovy
dir('.workflow_beg_secret') { git url: 'https://github.com/rizy44/workflow_beg_secret.git', branch: 'main' }
withCredentials([string(credentialsId: 'bao-role-id', variable: 'BAO_ROLE_ID'),
                 string(credentialsId: 'bao-secret-id', variable: 'BAO_SECRET_ID')]) {
  sh 'python3 .workflow_beg_secret/scripts/openbao/fetch_secrets.py --spec-file .ci/secrets.txt --exec -- ./scripts/build.sh'
}
```
`--exec` chạy script của stage với secret nằm trong env của nó: không ghi ra đĩa, và token
OpenBao bị revoke trước khi script chạy. Jenkins **không tự mask** giá trị lấy từ OpenBao,
nên script không được echo secret. Đầy đủ: `jenkins/Jenkinsfile.example`.

Các chế độ khác của `fetch_secrets.py`: `--output FILE` (dotenv, mode 600), `--format shell` (để `eval`).

## Dev

```bash
cd scripts && pip install -r requirements-dev.txt
ruff check . && ruff format --check . && python -m pytest -q
```
