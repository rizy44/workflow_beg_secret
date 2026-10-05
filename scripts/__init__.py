"""workflow-beg-secret: fetch secrets from OpenBao into GitHub Actions / Jenkins jobs.

Stages run in order (see scripts/main.py):
_01_authenticate -> _02_fetch_secrets -> _03_mask_secrets -> _04_export_env -> (pipeline) -> _05_revoke
"""
