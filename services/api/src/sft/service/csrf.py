"""CSRF tokens derived from session tokens, never stored (authentication and authorization 3.4).

    token = key_id + "." + base64url(HMAC-SHA-256(K_csrf, raw session token))

`K_csrf` is the keyring `sft/{env}/app/csrf-hmac` (encryption and keys 6.5), read only by the API,
in the shape of every HMAC keyring (`sft.core.keyrings`). New tokens use the one `active` key.
Every key in the ring verifies: a `verify` key is the previous one, kept for the 24-hour overlap,
and a `staged` key is loaded before any pod issues with it, so no pod makes a token another can't
check.
The rotation job removes a key when its overlap ends, and from then on its tokens fail.

The token changes whenever the session token does, and reveals nothing about it, because the key
never leaves the API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping

from sft.core.keyrings import CSRF_KEY_ID, KeyringError, parse_keyring

__all__ = ["CsrfKeyring", "KeyringError"]


class CsrfKeyring:
    """The loaded keyring: the key that issues tokens, and every key that verifies them.

    `reload` swaps in a new version of the secret whole (`sft.runtime.secrets`); each method reads
    the ring once, so it never mixes two versions.
    """

    __slots__ = ("_ring",)

    def __init__(self, active_id: str, keys: Mapping[str, bytes]) -> None:
        if active_id not in keys:
            raise KeyringError("the CSRF keyring's active key must be one of its keys")
        self._ring: tuple[str, Mapping[str, bytes]] = (active_id, dict(keys))

    @classmethod
    def from_json(cls, raw: str) -> CsrfKeyring:
        """Read the keyring; `KeyringError`, which never holds a key, if it is malformed."""
        return cls(*_read(raw))

    def reload(self, raw: str) -> None:
        """Take a new version of the secret; a malformed one raises `KeyringError` and changes
        nothing."""
        self._ring = _read(raw)

    @property
    def active_id(self) -> str:
        return self._ring[0]

    def token_for(self, session_token: str) -> str:
        """The CSRF token of the session whose raw token this is, under the active key."""
        active_id, keys = self._ring
        return f"{active_id}.{_mac(keys[active_id], session_token)}"

    def verify(self, session_token: str, presented: str | None) -> bool:
        """Whether `presented` is this session's token under any key in the ring."""
        if not presented:
            return False
        key_id, dot, mac = presented.partition(".")
        key = self._ring[1].get(key_id)
        if not dot or key is None:
            return False
        return hmac.compare_digest(mac.encode(), _mac(key, session_token).encode())


def _read(raw: str) -> tuple[str, dict[str, bytes]]:
    entries = parse_keyring(raw, name="CSRF", key_id=CSRF_KEY_ID)
    [active] = [entry.id for entry in entries if entry.state == "active"]
    return active, {entry.id: entry.key for entry in entries}


def _mac(key: bytes, session_token: str) -> str:
    digest = hmac.new(key, session_token.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
