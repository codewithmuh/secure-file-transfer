"""The one rule for an email address the service sends to (ADR-0015).

An address goes into a mail header as it is, so it has no whitespace (which covers line and
paragraph separators), no `@` but the one, none of `< > " , ;`, and no control or invisible format
character such as a bidi override or a zero-width space. The mail adapter (`sft.data.mail`), the
email catalog (`sft.service.email`) and the API (`inviteUser`) all apply this rule, so the API never
accepts an address the mail adapter would refuse. The mail system is the final judge of whether
the address exists.
"""

from __future__ import annotations

import re
from typing import Final

_ADDRESS_CHAR: Final = r"[^\s@<>\",;\x00-\x1f\x7f-\x9f­​-‏‪-‮⁠-⁯﻿]"
PLAIN_ADDRESS: Final = re.compile(f"{_ADDRESS_CHAR}+@{_ADDRESS_CHAR}+")


def is_plain_address(value: str) -> bool:
    """One plain address the mail adapter takes: `local@domain`, with nothing else in it."""
    return PLAIN_ADDRESS.fullmatch(value) is not None
