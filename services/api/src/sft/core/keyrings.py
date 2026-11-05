"""The HMAC keyrings' shape, read from their secrets (encryption and keys 6.4, 6.5).

Each keyring (`csrf-hmac`, `email-hmac`, and later `code-hmac` and `link-hmac`) is one secret: a
JSON list of keys, each an object with

- `id`: what a value made with the key carries, so the key that checks it can be found;
- `state`: `staged` (loaded, not used yet), `active` (makes new values; exactly one) or `verify`
  (the previous key, kept for its overlap);
- `key`: at least 256 bits, in base64;
- `created_at`, and for a keyring whose overlap counts from the switch, `activated_at` on the
  active key: ISO 8601 times with a time zone.

`parse_keyring` checks that shape and nothing about the keyring's use; each keyring's class adds
its own rules (`sft.service.csrf.CsrfKeyring`, `sft.core.pseudonyms.EmailKeyring`). The settings
call it too, so a bad keyring stops the process at startup (`sft.core.settings`). No message ever
contains a key.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal

KeyState = Literal["staged", "active", "verify"]

CSRF_KEY_ID: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")
"""A CSRF key ID: what goes before the dot of a token (the contract's `CsrfToken`)."""
EMAIL_KEY_ID: Final = re.compile(r"[A-Za-z0-9-]{1,32}")
"""An email-hmac key ID: what a pseudonym carries after its `e` (encryption and keys 6.2)."""
_STATES: Final = ("staged", "active", "verify")
MIN_KEY_BYTES: Final = 32


class KeyringError(ValueError):
    """The keyring can't be read. The message names the keyring and the key ID, never a key."""


@dataclass(frozen=True, slots=True)
class KeyEntry:
    id: str
    state: KeyState
    key: bytes = field(repr=False)
    activated_at: datetime | None = None


def parse_keyring(
    raw: str,
    *,
    name: str,
    key_id: re.Pattern[str],
    needs_activation: bool = False,
) -> list[KeyEntry]:
    """The keys of one keyring, checked: IDs that match `key_id` and appear once, known states,
    keys of 256 bits or more, and exactly one `active` key, with its `activated_at` when
    `needs_activation`."""
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KeyringError(f"the {name} keyring isn't JSON") from exc
    if not isinstance(entries, list) or not entries:
        raise KeyringError(f"the {name} keyring must be a non-empty JSON list")
    keys: list[KeyEntry] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise KeyringError(f"each {name} key must be a JSON object")
        ident, state = entry.get("id"), entry.get("state")
        if not isinstance(ident, str) or not key_id.fullmatch(ident):
            raise KeyringError(f"a {name} key ID must match {key_id.pattern}")
        if state not in _STATES:
            raise KeyringError(f"{name} key {ident}: state must be staged, active or verify")
        if any(k.id == ident for k in keys):
            raise KeyringError(f"{name} key {ident} appears twice")
        try:
            secret = base64.b64decode(str(entry.get("key")), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyringError(f"{name} key {ident}: the key isn't base64") from exc
        if len(secret) < MIN_KEY_BYTES:
            raise KeyringError(f"{name} key {ident}: the key needs at least 256 bits")
        activated = _time(entry.get("activated_at"), name, ident)
        keys.append(KeyEntry(ident, state, secret, activated))
    active = [k for k in keys if k.state == "active"]
    if len(active) != 1:
        raise KeyringError(f"the {name} keyring needs exactly one active key")
    if needs_activation and active[0].activated_at is None:
        raise KeyringError(f"{name} key {active[0].id}: the active key needs its activated_at")
    return keys


def _time(value: object, name: str, ident: str) -> datetime | None:
    if value is None:
        return None
    try:
        when = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise KeyringError(f"{name} key {ident}: activated_at isn't an ISO 8601 time") from exc
    if when.tzinfo is None:
        raise KeyringError(f"{name} key {ident}: activated_at needs a time zone")
    return when
