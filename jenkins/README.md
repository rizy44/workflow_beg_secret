# Jenkins flow (bạn tự triển khai Jenkinsfile qua Helm)

Có 3 cách để Jenkins có secret từ OpenBao. Repo đã implement sẵn **A**;
**B** dùng lại cùng CLI; **C** là hướng thay thế.

## A. Push từ GitHub Actions (đã có)

```
beg_secret_management (sync-secrets.yml, target=jenkins)
  -> runner: OIDC login OpenBao
  -> đọc kv/ci/jenkins-admin (user + API token của Jenkins)
  -> đọc giá trị các credential
  -> Jenkins REST: GET .../credential/<id>/api/json
                   200 -> POST .../credential/<id>/config.xml   (update)
                   404 -> POST .../createCredentials             (create)
```
Yêu cầu: runner gọi được Jenkins.

## B. Pull từ Jenkins (Jenkinsfile, khi Jenkins nằm trong mạng kín)

Một pipeline job (vd. `secret-sync`), tạo bằng JCasC/Job DSL trong Helm values:

```
trigger: cron H/30 * * * *  +  build tay  (+ webhook từ beg_secret_management nếu muốn)
agent:   pod template image python:3.12-slim (kubernetes plugin)

stage('Checkout')
    checkout workflow_beg_secret  -> ./tooling
    checkout beg_secret_management-  -> ./config-repo
stage('Install')
    pip install -r tooling/scripts/requirements.txt
stage('Validate')
    python -m beg_secret validate --config config-repo/config/secrets.yaml
stage('Dry-run')
    withCredentials([string(credentialsId: 'bao-role-id',   variable: 'BAO_ROLE_ID'),
                     string(credentialsId: 'bao-secret-id', variable: 'BAO_SECRET_ID')]) {
        env BAO_ADDR=<url>  BAO_AUTH_METHOD=approle  JENKINS_URL=http://jenkins:8080
        python -m beg_secret sync-jenkins --config ... --dry-run
    }
stage('Sync')            # (tùy chọn) input/approval trước stage này
    same env -> python -m beg_secret sync-jenkins --config ...
post
    archive log, báo Slack/email khi fail
```

Ghi chú:
- `bao-role-id` / `bao-secret-id` là **credential bootstrap duy nhất** không do hệ thống
  này quản lý → tạo bằng Kubernetes Secret + JCasC trong Helm
  (xem `docs/openbao-setup.md` mục 5 ở repo beg_secret_management-).
- Jenkins API user/token vẫn đọc từ `kv/ci/jenkins-admin` như mô hình A.
- Nếu Jenkins chỉ dùng B thì xóa job `jenkins` khỏi `sync-secrets.yml` để tránh ghi 2 nơi.

## C. Pipeline đọc thẳng OpenBao lúc chạy (không copy credential)

Plugin "HashiCorp Vault" (tương thích API OpenBao), `withVault(...)` trong Jenkinsfile,
auth AppRole hoặc Kubernetes auth. Ưu: không có bản sao secret trong Jenkins.
Nhược: mỗi pipeline phải sửa để dùng `withVault`, phụ thuộc OpenBao lúc build.
