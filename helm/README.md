# helm (để sau)

Dự kiến dùng chart `jenkinsci/jenkins`:
- `controller.installPlugins`: credentials, plain-credentials, ssh-credentials, cloudbees-folder,
  kubernetes, workflow-aggregator, git, configuration-as-code, job-dsl
- JCasC: tạo user dịch vụ `secret-sync` + phân quyền (matrix-auth), seed job `secret-sync` (xem `../jenkins/README.md`)
- Kubernetes Secret chứa AppRole `role_id`/`secret_id` của OpenBao, map vào JCasC credentials
- KHÔNG khai báo trong JCasC các credential ID do beg_secret_management quản lý (tránh bị ghi đè khi reload)
