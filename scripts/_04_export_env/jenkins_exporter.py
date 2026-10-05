"""Export for Jenkins: a temporary Java .properties file (mode 600).

`vars/withOpenBao.groovy` loads it with `readProperties` (Pipeline Utility Steps)
and deletes it immediately, then injects the values with `withEnv`. Write it
outside the workspace (e.g. `$WORKSPACE_TMP`) so it can never be archived.

Escaping follows java.util.Properties.load(): `\\`, newlines, tabs, leading
spaces and `= : # !` are escaped; non-ASCII is written as \\uXXXX.
"""

from __future__ import annotations

import os
import tempfile
from typing import Mapping

from scripts._03_mask_secrets.jenkins_masker import MASKED_KEYS_PROPERTY, masked_keys_value

DEFAULT_FILE_NAME = ".openbao_env.properties"


def _escape(text: str, is_key: bool) -> str:
    out = []
    for i, ch in enumerate(text):
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\f":
            out.append("\\f")
        elif ch in "=:#!":
            out.append("\\" + ch)
        elif ch == " " and (is_key or i == 0):
            out.append("\\ ")
        elif code < 0x20 or code > 0x7E:
            if code > 0xFFFF:  # outside the BMP: write the UTF-16 surrogate pair
                code -= 0x10000
                out.append(f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}")
            else:
                out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def render_properties(values: Mapping[str, str]) -> str:
    return "".join(f"{_escape(k, True)}={_escape(v, False)}\n" for k, v in values.items())


def default_output_path() -> str:
    base = os.environ.get("WORKSPACE_TMP") or tempfile.gettempdir()
    return os.path.join(base, DEFAULT_FILE_NAME)


def export_jenkins_properties(
    values: Mapping[str, str],
    masked_names: list[str],
    output: str | None = None,
) -> str:
    """Write the properties file and return its path."""
    path = output or default_output_path()
    content = dict(values)
    content[MASKED_KEYS_PROPERTY] = masked_keys_value(masked_names)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    if os.path.lexists(path):
        os.remove(path)  # never follow a pre-existing file/symlink
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(render_properties(content))
    return path
