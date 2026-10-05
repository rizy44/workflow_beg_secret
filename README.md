# workflow-beg-secret

Lấy secret từ **OpenBao** cho pipeline **GitHub Actions** và **Jenkins** bằng cùng một bộ script.
Secret chỉ được quản lý trên OpenBao. CI chỉ giữ một credential khởi tạo (AppRole `role_id` + `secret_id`).

```
[role_id + secret_id]
   → _01_authenticate   AppRole login → client_token (RAM), kiểm tra TTL
   → _02_fetch_secrets  đọc KV v1/v2 → {ENV_NAME: value}
   → _03_mask_secrets   GitHub ::add-mask:: / Jenkins Mask Passwords
   → _04_export_env     $GITHUB_ENV  |  file .properties (đọc xong xoá ngay)
   → (pipeline chạy)
   → _05_revoke         revoke-self token
```

```
workflow-beg-secret/
├── .github/workflows/test-secret-flow.yml   # unit (fake OpenBao) + integration (OpenBao thật)
├── action.yml                               # GitHub composite action: command fetch | revoke
├── vars/withOpenBao.groovy                  # Jenkins shared library step
├── AGENTS.md                                # quy tắc cho agent/dev
├── pyproject.toml, ruff.toml
├── scripts/
│   ├── main.py                              # CLI điều phối: fetch | revoke | check-token
│   ├── _01_authenticate/  approle_login.py, token_validator.py
│   ├── _02_fetch_secrets/ kv_v2_reader.py, kv_v1_reader.py, secret_parser.py
│   ├── _03_mask_secrets/  github_masker.py, jenkins_masker.py
│   ├── _04_export_env/    github_exporter.py, jenkins_exporter.py
│   ├── _05_revoke/        token_revoker.py
│   └── utils/             http_client.py, logger.py
└── tests/
```

Chỉ dùng thư viện chuẩn của Python (>= 3.8), nên runner/agent không cần `pip install`.

## Cú pháp secret

```
PATH=ci/artifactory,PREFIX=ARTIFACTORY_                  → ARTIFACTORY_<KEY> cho mọi key
PATH=ci/dockerhub,KEYS=username|token,PREFIX=DOCKERHUB_  → DOCKERHUB_USERNAME, DOCKERHUB_TOKEN
PATH=ci/app                                              → SECRET_<KEY> (prefix mặc định)
PATH=legacy/app,MOUNT=secret-v1,KV=1                      → đọc engine KV v1
```

## GitHub Actions

Variables: `OPENBAO_URL`, `OPENBAO_NAMESPACE`. Secrets: `OPENBAO_ROLE_ID`, `OPENBAO_SECRET_ID`.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: rizy44/workflow_beg_secret@main
    with:
      url: ${{ vars.OPENBAO_URL }}
      namespace: ${{ vars.OPENBAO_NAMESPACE }}
      role-id: ${{ secrets.OPENBAO_ROLE_ID }}
      secret-id: ${{ secrets.OPENBAO_SECRET_ID }}
      secrets: |
        PATH=ci/artifactory,PREFIX=ARTIFACTORY_
  - run: ./scripts/build.sh                 # $ARTIFACTORY_API_KEY có sẵn, log hiện ***
  - if: always()                            # stage 5
    uses: rizy44/workflow_beg_secret@main
    with:
      command: revoke
      url: ${{ vars.OPENBAO_URL }}
      namespace: ${{ vars.OPENBAO_NAMESPACE }}
```
`export-token: false` sẽ revoke ngay sau khi lấy secret; khi đó không cần step revoke.

## Jenkins

Đăng ký repo này là Global Pipeline Library tên `workflow-beg-secret`. Tạo credential
*Username with password* `openbao-approle` (username = role_id, password = secret_id).
Plugin cần có: Pipeline Utility Steps, Credentials Binding, Git, Mask Passwords.

```groovy
@Library('workflow-beg-secret') _

pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        withOpenBao(url: 'https://openbao.example.com:8200', namespace: 'my-ns',
                    credentialsId: 'openbao-approle',
                    secrets: ['PATH=ci/artifactory,PREFIX=ARTIFACTORY_']) {
          sh './scripts/build.sh'
        }
      }
    }
  }
}
```

## Chạy local

```bash
export OPENBAO_URL=https://openbao.example.com:8200 OPENBAO_NAMESPACE=my-ns OPENBAO_MOUNT=kv/test
export OPENBAO_ROLE_ID=... OPENBAO_SECRET_ID=...
python3 scripts/main.py fetch --platform local --output /tmp/bao.properties --secret "PATH=ci/test"
```

## Dev

```bash
uv sync && uv run ruff check . && uv run pytest -q     # hoặc: pip install pytest ruff
```
