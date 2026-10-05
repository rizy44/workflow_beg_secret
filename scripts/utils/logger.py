"""Secret-safe logging.

Every value passed to `register_secret()` is replaced by `***` in any log record,
so even an accidental `log.info("%s", token)` cannot leak it. Logs go to stderr:
stdout is reserved for GitHub workflow commands (`::add-mask::`).
"""

from __future__ import annotations

import logging
import sys

REDACTED = "***"
_secrets: set[str] = set()


def register_secret(value: str) -> None:
    """Remember a value (and each of its lines) so it is redacted from logs."""
    if not value:
        return
    _secrets.add(value)
    for line in value.splitlines():
        if line.strip():
            _secrets.add(line)


def redact(text: str) -> str:
    # Longest first, so a secret containing another secret is fully hidden.
    for value in sorted(_secrets, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    return text


def clear_secrets() -> None:
    """Forget registered values (used by tests)."""
    _secrets.clear()


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


class _StderrHandler(logging.StreamHandler):
    """Always write to the current sys.stderr (survives stream redirection)."""

    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, _value):
        pass


_configured = False


def get_logger(name: str = "openbao") -> logging.Logger:
    global _configured
    root = logging.getLogger("openbao")
    if not _configured:
        handler = _StderrHandler()
        handler.setFormatter(logging.Formatter("[openbao] %(levelname)s %(message)s"))
        handler.addFilter(RedactingFilter())
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        root.propagate = False
        _configured = True
    return root if name == "openbao" else root.getChild(name)
