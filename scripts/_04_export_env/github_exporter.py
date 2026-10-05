"""Export to GitHub Actions: append to $GITHUB_ENV (and $GITHUB_OUTPUT).

Uses the multi-line `NAME<<DELIMITER` syntax with a random delimiter, so values
containing newlines or `=` are safe. Values must already be masked (stage 3).
"""

from __future__ import annotations

import os
import secrets
from typing import Mapping


class ExportError(Exception):
    pass


def _append(path: str, values: Mapping[str, str]) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        for name, value in values.items():
            delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
            if delimiter in value:  # practically impossible, but never write a broken file
                raise ExportError(f"cannot export {name}: delimiter collision")
            fh.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def export_github_env(values: Mapping[str, str], env_file: str | None = None) -> None:
    path = env_file or os.environ.get("GITHUB_ENV")
    if not path:
        raise ExportError("GITHUB_ENV is not set: not running inside a GitHub Actions step?")
    _append(path, values)


def export_github_output(outputs: Mapping[str, str], output_file: str | None = None) -> None:
    """Step outputs (names of exported vars, never values)."""
    path = output_file or os.environ.get("GITHUB_OUTPUT")
    if path:
        _append(path, outputs)
