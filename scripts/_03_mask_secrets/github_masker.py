"""GitHub Actions masking: print `::add-mask::<value>` so the runner shows *** in every later log line.

Must run BEFORE the values are exported or used anywhere. Multi-line values are
masked line by line (GitHub matches masks per line).
"""

from __future__ import annotations

import sys
from typing import Iterable, TextIO


def mask_values(values: Iterable[str], out: TextIO | None = None) -> int:
    """Emit one add-mask command per non-empty line. Returns how many masks were sent."""
    out = out or sys.stdout
    sent = set()
    for value in values:
        for line in (value or "").splitlines():
            line = line.strip()
            if line and line not in sent:
                # Escape the characters GitHub workflow commands treat specially.
                escaped = line.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                out.write(f"::add-mask::{escaped}\n")
                sent.add(line)
    out.flush()
    return len(sent)
