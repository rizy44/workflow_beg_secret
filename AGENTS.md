# AGENTS.md - Instructions for workflow-beg-secret

## Overview
`workflow-beg-secret` is a generic Python CLI tool and CI workflow component to:
1. Authenticate to OpenBao using a single bootstrap credential (AppRole `role_id` + `secret_id`).
2. Retrieve a dynamic `client_token`.
3. Extract secrets from OpenBao secret engines (KV v1/v2).
4. Mask secrets and export them into CI environment variables (GitHub Actions and Jenkins).
5. Revoke the `client_token` on pipeline completion.

Secrets are managed **only in OpenBao**. GitHub stores just `OPENBAO_ROLE_ID` / `OPENBAO_SECRET_ID`
(secrets) and `OPENBAO_URL` / `OPENBAO_NAMESPACE` (variables); Jenkins stores one
"Username with password" credential (username = role_id, password = secret_id).

## Constraints & Rules
1. **Zero Internal Library Dependency:** Do NOT use or assume `pps` or Bosch-internal libraries.
   Runtime code uses the **Python standard library only** (`urllib.request`), so runners/agents
   need nothing but `python3 >= 3.8`. Do not add runtime dependencies.
2. **Security & Anti-Leak:**
   - NEVER print secrets or tokens to standard output/logs (except GitHub Actions mask syntax `::add-mask::<value>`).
   - Keep secrets strictly in-memory during execution. The only file ever written is the Jenkins
     properties file (mode 600, outside the workspace, deleted right after `readProperties`).
   - Call `utils.logger.register_secret(value)` as soon as a secret/token is known; the logger then
     replaces it with `***` even if logged by mistake. Log counts and names, never values:
     `"Fetched 5 key(s) from kv/test/ci/artifactory"`.
   - Error messages must not include request bodies (they contain role_id/secret_id).
   - Mask (stage 3) BEFORE export (stage 4).
   - If anything fails after login, revoke the token before exiting (see `cmd_fetch` in `main.py`).
3. **Architecture:** Follow the numbered stage layout in `scripts/`:
   - `_01_authenticate`: OpenBao AppRole login (`approle_login.py`), token check (`token_validator.py`).
   - `_02_fetch_secrets`: KV v1 / KV v2 REST calls, spec parsing and env-name mapping (`secret_parser.py`).
   - `_03_mask_secrets`: GitHub mask strings (`::add-mask::`), Jenkins list of names to mask.
   - `_04_export_env`: Export to `$GITHUB_ENV`/`$GITHUB_OUTPUT` or a Jenkins properties file.
   - `_05_revoke`: Self-revoke token (idempotent: 403 = already revoked).
   - `utils`: HTTP client with retries/timeouts/namespace header, and the secret-redacting logger.
   - `main.py` only orchestrates; logic lives in the stage modules. New stages get the next number.
4. **Imports:** absolute, from the repo root: `from scripts._02_fetch_secrets.kv_v2_reader import read_kv_v2`.
   `main.py` must keep working when run as a file: `python3 scripts/main.py ...` (action.yml and
   `vars/withOpenBao.groovy` call it that way, from any working directory).
5. **Python 3.8 compatible:** `from __future__ import annotations` in every module; no `match`,
   no `str.removeprefix`, no runtime use of `list[str]`/`X | None` outside annotations.

## CLI
```
python3 scripts/main.py fetch  [--secret SPEC]... [--secrets-file F] [--mount M] [--kv-version 1|2]
                               [--platform auto|github|jenkins|local] [--output FILE] [--no-export-token]
python3 scripts/main.py revoke         # uses OPENBAO_TOKEN
python3 scripts/main.py check-token    # uses OPENBAO_TOKEN
```
Environment: `OPENBAO_URL`, `OPENBAO_NAMESPACE`, `OPENBAO_CACERT`, `OPENBAO_ROLE_ID`, `OPENBAO_SECRET_ID`
(env only, never flags), `OPENBAO_APPROLE_MOUNT` (approle), `OPENBAO_MOUNT` (secret), `OPENBAO_KV_VERSION` (2),
`OPENBAO_SECRETS` (specs, one per line), `OPENBAO_TOKEN` (exported by fetch, read by revoke).
Exit codes: `0` ok, `1` OpenBao/runtime error, `2` invalid input (OpenBao not contacted).

Secret spec: `PATH=ci/artifactory,PREFIX=ARTIFACTORY_[,KEYS=user|token][,MOUNT=kv/test][,KV=1|2]`.
Env name = PREFIX (default `SECRET_`) + key upper-cased (`api_key` -> `SECRET_API_KEY`). Names that
would override `PATH`, `HOME`, `GITHUB_*`, `RUNNER_*`, `ACTIONS_*`, `OPENBAO_*`, `JENKINS_*` are rejected.

Defaults: the CLI mount default is `secret`; `action.yml` and `withOpenBao.groovy` default to the
team's mount `kv/test`.

## OpenBao REST Endpoints Reference
All requests: header `X-Vault-Token: {token}` (after login) and `X-Vault-Namespace: {ns}` when a namespace is set.
- Login: `POST /v1/auth/approle/login` (Body: `{"role_id": "...", "secret_id": "..."}`) -> `auth.client_token`, `auth.lease_duration`
- Lookup Token: `GET /v1/auth/token/lookup-self` -> `data.ttl`
- Read KV v2: `GET /v1/{mount}/data/{path}` -> `data.data` (e.g. `/v1/kv/test/data/ci/artifactory`)
- Read KV v1: `GET /v1/{mount}/{path}` -> `data`
- Revoke Token: `POST /v1/auth/token/revoke-self`

Retry only network errors, 429 and 5xx. Never retry 4xx.

## CI integration
- GitHub: `action.yml` (composite). Composite actions have no `post:` hook, so stage 5 is a second
  call with `command: revoke` and `if: always()`.
- Jenkins: `vars/withOpenBao.groovy` (shared library step) checks out this repo on the agent,
  runs `fetch --platform jenkins --output <tmp>`, `readProperties`, deletes the file, injects with
  `withEnv`, masks with the Mask Passwords plugin, and runs `revoke` in `finally`.

## Development
```
uv sync                     # or: pip install pytest ruff
uv run ruff check . && uv run ruff format --check .
uv run pytest -q            # tests/ uses a fake OpenBao HTTP server (tests/conftest.py)
```
Every change needs tests. `tests/test_main.py` asserts that no secret value appears in logs;
keep that true. `.github/workflows/test-secret-flow.yml` runs unit tests on Python 3.8 and 3.12,
and an integration run against the real instance when `vars.OPENBAO_URL` is set.
