"""Small HTTP client for the OpenBao REST API (standard library only).

- Base URL + `/v1/` prefix, JSON in/out
- Headers: `X-Vault-Token`, `X-Vault-Namespace`
- Timeout, and retries with exponential backoff on network errors, 429 and 5xx
  (4xx are never retried: a wrong path or a denied policy will not fix itself)
- Error messages never include request bodies (they carry role_id/secret_id)
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable

RETRY_STATUSES = {429, 500, 502, 503, 504}


class OpenBaoHttpError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class OpenBaoHttpClient:
    def __init__(
        self,
        url: str,
        namespace: str = "",
        cacert: str | None = None,
        timeout: float = 10,
        retries: int = 3,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not url:
            raise OpenBaoHttpError("OpenBao URL is empty (set OPENBAO_URL or --url)")
        self.url = url.rstrip("/")
        self.namespace = namespace.strip("/")
        self.ssl_context = ssl.create_default_context(cafile=cacert) if cacert else None
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self._sleep = sleep

    def request(
        self,
        method: str,
        path: str,
        token: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call `{url}/v1/{path}` and return the decoded JSON body ({} when empty)."""
        api_path = "/v1/" + path.lstrip("/")
        last_error: OpenBaoHttpError | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(self.backoff * (2 ** (attempt - 1)))
            try:
                return self._once(method, api_path, token, body)
            except OpenBaoHttpError as exc:
                last_error = exc
                if exc.status is not None and exc.status not in RETRY_STATUSES:
                    raise
        assert last_error is not None
        raise last_error

    def _once(self, method: str, api_path: str, token: str | None, body: dict[str, Any] | None) -> dict[str, Any]:
        req = urllib.request.Request(self.url + api_path, method=method)
        req.add_header("Accept", "application/json")
        if body is not None:
            req.data = json.dumps(body).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        if self.namespace:
            req.add_header("X-Vault-Namespace", self.namespace)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise OpenBaoHttpError(f"{method} {api_path} -> HTTP {exc.code}{_errors(exc)}", status=exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise OpenBaoHttpError(f"{method} {api_path} -> cannot reach {self.url}: {reason}") from None
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise OpenBaoHttpError(f"{method} {api_path} -> response is not JSON") from None


def _errors(exc: urllib.error.HTTPError) -> str:
    """OpenBao error bodies look like {"errors": ["permission denied"]}; never contain secrets."""
    try:
        errors = json.loads(exc.read() or b"{}").get("errors") or []
    except ValueError:
        return ""
    return f" ({'; '.join(str(e) for e in errors)[:300]})" if errors else ""
