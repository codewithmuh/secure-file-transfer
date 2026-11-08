"""Email pseudonyms: what logs, rate-limit keys and the suppression list hold instead of an address.

A pseudonym is `"e" + key_id + ":" + base64url(HMAC-SHA-256(key, "email/v1/" + email_normalized))`,
truncated to 128 bits (encryption and keys 6.2). Anyone holding the key can test guesses, so the
key is a secret like any other, and so is a pseudonym's link to its address.

The keys form a keyring that rotates once a year (encryption and keys 6.5). For 25 hours after a
new key becomes active, each per-address rate limit adds the previous key's count to the new one's,
so a rotation never resets a cap: `EmailKeyring.for_limits` gives the active pseudonym and those
still in that overlap. The API reads the keyring (`sft/{env}/app/email-hmac`) from its settings
(`EMAIL_HMAC_KEYRING`, `EmailKeyring.from_json`), or from Secrets Manager every 5 minutes when the
setting names the secret (`sft.runtime.secrets`), in the shape of every HMAC keyring
(`sft.core.keyrings`), with `activated_at` on the active key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, NamedTuple

from sft.core.keyrings import EMAIL_KEY_ID, parse_keyring

LIMIT_OVERLAP = timedelta(hours=25)
"""How long a per-address limit still counts the previous key's pseudonym after a rotation."""

_KEY_ID = re.compile(r"[A-Za-z0-9-]{1,32}")


def email_pseudonym(key_id: str, key: bytes, email_normalized: str) -> str:
    """The pseudonym of a normalized (lowercase) address under one key of the keyring."""
    if not _KEY_ID.fullmatch(key_id):
        raise ValueError("a key ID is 1 to 32 letters, digits or hyphens")
    digest = hmac.new(key, b"email/v1/" + email_normalized.encode(), hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
    return f"e{key_id}:{encoded}"


@dataclass(frozen=True)
class EmailPseudonyms:
    """One address for a rate limit: the pseudonym it counts under, and older ones it adds."""

    active: str
    overlap: tuple[str, ...] = ()

    def within(self, scope: str) -> EmailPseudonyms:
        """The same address counted inside one scope, such as a tenant (abuse design 2.2, G)."""
        return EmailPseudonyms(
            f"{scope}:{self.active}", tuple(f"{scope}:{p}" for p in self.overlap)
        )


@dataclass(frozen=True)
class EmailKey:
    id: str
    key: bytes = field(repr=False)
    state: Literal["staged", "active", "verify"]
    activated_at: datetime | None = None
    """When it became active; needed for the active key, which starts the overlap."""


class _Ring(NamedTuple):
    active: EmailKey
    overlap_ends: datetime
    verify: tuple[EmailKey, ...]


class EmailKeyring:
    """The loaded keyring. `reload` swaps in a new version of its secret whole
    (`sft.runtime.secrets`), and each method reads the ring once, so it never mixes two versions."""

    __slots__ = ("_ring",)

    @classmethod
    def from_json(cls, raw: str) -> EmailKeyring:
        """Read the keyring; `KeyringError`, which never holds a key, if it is malformed."""
        return cls(_read(raw))

    def __init__(self, keys: list[EmailKey]) -> None:
        self._ring = _ring_of(keys)

    def reload(self, raw: str) -> None:
        """Take a new version of the secret; a malformed one raises `KeyringError` and changes
        nothing."""
        self._ring = _ring_of(_read(raw))

    def for_limits(self, email_normalized: str, now: datetime) -> EmailPseudonyms:
        """The address's pseudonyms for a rate limit at `now`."""
        ring = self._ring
        in_overlap = now < ring.overlap_ends
        return EmailPseudonyms(
            email_pseudonym(ring.active.id, ring.active.key, email_normalized),
            tuple(
                email_pseudonym(k.id, k.key, email_normalized) for k in ring.verify if in_overlap
            ),
        )

    @property
    def active_key_id(self) -> str:
        return self._ring.active.id

    def active(self, email_normalized: str) -> str:
        """The address's pseudonym under the active key: what a new suppression entry holds."""
        active = self._ring.active
        return email_pseudonym(active.id, active.key, email_normalized)

    def every_version(self, email_normalized: str) -> tuple[str, ...]:
        """The address's pseudonym under every key that may still have rows: the active key and
        each one kept to verify. A suppression lookup checks them all (data model 2.5)."""
        ring = self._ring
        keys = (ring.active, *ring.verify)
        return tuple(email_pseudonym(k.id, k.key, email_normalized) for k in keys)


def _read(raw: str) -> list[EmailKey]:
    entries = parse_keyring(raw, name="email", key_id=EMAIL_KEY_ID, needs_activation=True)
    return [EmailKey(e.id, e.key, e.state, e.activated_at) for e in entries]


def _ring_of(keys: list[EmailKey]) -> _Ring:
    active = [k for k in keys if k.state == "active"]
    if len(active) != 1 or active[0].activated_at is None:
        raise ValueError("the keyring needs exactly one active key, with its activation time")
    verify = tuple(k for k in keys if k.state == "verify")
    return _Ring(active[0], active[0].activated_at + LIMIT_OVERLAP, verify)
