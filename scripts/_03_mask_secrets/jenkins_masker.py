"""Jenkins masking: decide which env vars must be masked by the Mask Passwords plugin.

Jenkins only auto-masks values bound by `withCredentials`. Values coming from
OpenBao are injected with `withEnv`, so `vars/withOpenBao.groovy` wraps the body
with the Mask Passwords plugin (`MaskPasswordsBuildWrapper`) using this list.
Only NAMES go into the properties file key `OPENBAO_MASKED_KEYS`; values stay
in their own entries.
"""

from __future__ import annotations

from typing import Iterable

MASKED_KEYS_PROPERTY = "OPENBAO_MASKED_KEYS"


def masked_names(env_names: Iterable[str], include_token: bool = True) -> list[str]:
    names = sorted(set(env_names))
    if include_token:
        names.append("OPENBAO_TOKEN")
    return names


def masked_keys_value(names: Iterable[str]) -> str:
    return ",".join(names)
