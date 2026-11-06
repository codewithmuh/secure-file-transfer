"""The `link-hmac` and `code-hmac` keyrings: link tokens and verification codes (data model 2.2,
2.4; encryption and keys 6.2, 6.5).

Both keyrings have the shape of every HMAC keyring (`sft.core.keyrings`). New values are made with
the one `active` key, and every loaded key can make a value again, so a value records the ID of
the key it was made with, in a sibling column (`link_key_id`, `verification_codes.hmac_key_id`):

- **Link tokens.** `HMAC-SHA-256(K_link, "link/v1/" + subject_id + "/" + link_issued_at)`, where
  `link_issued_at` is written as microseconds since the Unix epoch, as base64url: 256 bits, more
  than NFR-14's 128. Only the notification worker holds `K_link`. A retried notify message
  rebuilds the same token from the row, so a delivered link keeps working whichever attempt
  delivered it. A key version stays loaded at least 14 days after a newer one takes over, the
  longest a notify message waits in a dead-letter queue (data model 2.2), so the rotation job
  removes a `verify` key only after that.
- **Verification codes.** `HMAC-SHA-256(K_code, "code/v1/" + code_id + "/" + code)`. The row ID
  binds an HMAC to its own row, so one code's HMAC never matches another's. The notification
  worker makes it, the API checks it, in constant time. The previous key verifies for 24 hours.

No message, repr or log line ever holds a key, a token or a code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar, Final, Self
from uuid import UUID

from sft.core.keyrings import KeyringError, parse_keyring

LINK_KEY_ID: Final = re.compile(r"[A-Za-z0-9-]{1,32}")
"""A link-hmac key ID, as `transfer_recipients.link_key_id` records it."""
CODE_KEY_ID: Final = re.compile(r"[A-Za-z0-9-]{1,32}")
"""A code-hmac key ID, as `verification_codes.hmac_key_id` records it."""

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

__all__ = [
    "CODE_KEY_ID",
    "LINK_KEY_ID",
    "CodeKeyring",
    "KeyringError",
    "LinkKeyring",
    "UnknownKeyError",
    "epoch_micros",
]


class UnknownKeyError(KeyringError):
    """A value names a key this keyring no longer (or never) held."""


def epoch_micros(value: datetime) -> int:
    """`value` as whole microseconds since the Unix epoch, exactly, with no float on the way."""
    if value.tzinfo is None:
        raise ValueError("a link's issue time is an aware datetime")
    return (value - _EPOCH) // timedelta(microseconds=1)


@dataclass(frozen=True, slots=True)
class _Keyring:
    NAME: ClassVar[str]
    KEY_ID: ClassVar[re.Pattern[str]]

    active_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    @classmethod
    def from_json(cls, raw: str) -> Self:
        """Read the keyring; `KeyringError`, which never holds a key, if it is malformed."""
        entries = parse_keyring(raw, name=cls.NAME, key_id=cls.KEY_ID)
        [active] = [entry.id for entry in entries if entry.state == "active"]
        return cls(active, {entry.id: entry.key for entry in entries})

    def _mac(self, key_id: str, message: bytes) -> bytes:
        key = self.keys.get(key_id)
        if key is None:
            raise UnknownKeyError(f"the {self.NAME} keyring has no key {key_id}")
        return hmac.new(key, message, hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class LinkKeyring(_Keyring):
    """`K_link`, which only the notification worker loads."""

    NAME: ClassVar[str] = "link"
    KEY_ID: ClassVar[re.Pattern[str]] = LINK_KEY_ID

    def token(self, key_id: str, subject_id: UUID, issued_at: datetime) -> str:
        """The link token of a recipient or upload request issued at `issued_at`, under `key_id`."""
        message = f"link/v1/{subject_id}/{epoch_micros(issued_at)}".encode()
        return base64.urlsafe_b64encode(self._mac(key_id, message)).rstrip(b"=").decode()

    def knows(self, key_id: str) -> bool:
        return key_id in self.keys


@dataclass(frozen=True, slots=True)
class CodeKeyring(_Keyring):
    """`K_code`: the notification worker makes codes' HMACs, the API checks them."""

    NAME: ClassVar[str] = "code"
    KEY_ID: ClassVar[re.Pattern[str]] = CODE_KEY_ID

    def knows(self, key_id: str) -> bool:
        """Whether this keyring still holds the key a code was made with."""
        return key_id in self.keys

    def code_hmac(self, key_id: str, code_id: UUID, code: str) -> bytes:
        return self._mac(key_id, f"code/v1/{code_id}/{code}".encode())

    def matches(self, key_id: str, code_id: UUID, code: str, stored: bytes) -> bool:
        """Whether `code` is the code of row `code_id`, compared in constant time. False when the
        key that made it is gone: such a code can't be checked, so it can't be used."""
        try:
            computed = self.code_hmac(key_id, code_id, code)
        except UnknownKeyError:
            return False
        return hmac.compare_digest(computed, stored)
