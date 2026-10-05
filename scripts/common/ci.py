"""CI platform helpers so the same stage script runs on GitHub Actions, Jenkins or locally."""

from __future__ import annotations

import os
import secrets
import shlex
import sys
from collections.abc import Mapping


def platform(env: Mapping[str, str] = os.environ) -> str:
    if env.get("GITHUB_ACTIONS") == "true":
        return "github"
    if env.get("JENKINS_URL") and env.get("BUILD_ID"):
        return "jenkins"
    return "local"


def mask(value: str) -> None:
    """Redact a value from GitHub Actions logs. Jenkins has no equivalent: never print values there."""
    if platform() == "github" and value:
        for line in value.splitlines():
            if line.strip():
                print(f"::add-mask::{line}", flush=True)


def error(message: str) -> None:
    if platform() == "github":
        print(f"::error::{message}", flush=True)
    else:
        print(f"ERROR: {message}", file=sys.stderr, flush=True)


def group(title: str) -> None:
    if platform() == "github":
        print(f"::group::{title}", flush=True)
    else:
        print(f"==> {title}", flush=True)


def endgroup() -> None:
    if platform() == "github":
        print("::endgroup::", flush=True)


def write_github_env(path: str, values: Mapping[str, str]) -> None:
    """Append to $GITHUB_ENV using random heredoc delimiters (safe for multiline values)."""
    with open(path, "a", encoding="utf-8") as fh:
        for name, value in values.items():
            delim = f"ghadelim_{secrets.token_hex(16)}"
            fh.write(f"{name}<<{delim}\n{value}\n{delim}\n")


def write_dotenv(path: str, values: Mapping[str, str]) -> None:
    """Write `export NAME='value'` lines, readable only by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(shell_exports(values))


def shell_exports(values: Mapping[str, str]) -> str:
    return "".join(f"export {name}={shlex.quote(value)}\n" for name, value in values.items())


def step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown.rstrip() + "\n\n")
