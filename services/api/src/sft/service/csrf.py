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
from dataclasses import dataclass

from sft.core.keyrings import CSRF_KEY_ID, KeyringError, parse_keyring

__all__ = ["CsrfKeyring", "KeyringError"]


@dataclass(frozen=True, slots=True)
class CsrfKeyring:
    """The loaded keyring: the key that issues tokens, and every key that verifies them."""

    active_id: str
    keys: dict[str, bytes]

    @classmethod
    def from_json(cls, raw: str) -> CsrfKeyring:
        """Read the keyring; `KeyringError`, which never holds a key, if it is malformed."""
        entries = parse_keyring(raw, name="CSRF", key_id=CSRF_KEY_ID)
        [active] = [entry.id for entry in entries if entry.state == "active"]
        return cls(active, {entry.id: entry.key for entry in entries})

    def token_for(self, session_token: str) -> str:
        """The CSRF token of the session whose raw token this is, under the active key."""
        return f"{self.active_id}.{_mac(self.keys[self.active_id], session_token)}"

    def verify(self, session_token: str, presented: str | None) -> bool:
        """Whether `presented` is this session's token under any key in the ring."""
        if not presented:
            return False
        key_id, dot, mac = presented.partition(".")
        key = self.keys.get(key_id)
        if not dot or key is None:
            return False
        return hmac.compare_digest(mac.encode(), _mac(key, session_token).encode())


def _mac(key: bytes, session_token: str) -> str:
    digest = hmac.new(key, session_token.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
