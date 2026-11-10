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

A keyring setting holds either the keyring itself (the local stack and the tests) or, in AWS, a
reference to its secret, `secretsmanager:sft/<env>/app/<name>` (encryption and keys 6.4). The
process reads a referenced secret at startup and every 5 minutes after (`sft.runtime.secrets`),
and each keyring's `reload` swaps in the new version whole, so a rotation takes effect without a
restart. A malformed new version is refused and the loaded one stays.

`active_since` reads when the active key took over (`activated_at`, else `created_at`), which the
process reports as `keyring_active_key_age_seconds{keyring}`, so a rotation that stops running
alerts (6.5, #162).
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

SECRET_REFERENCE: Final = "secretsmanager:"  # noqa: S105 - a prefix, not a secret
"""What a keyring setting starts with when it names the keyring's secret instead of holding it."""
_SECRET_ID: Final = re.compile(r"[A-Za-z0-9/_+=.@-]{1,512}")


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


def secret_reference(raw: str, *, name: str) -> str | None:
    """The secret ID a keyring setting names (`secretsmanager:<id>`), or None if it holds the
    keyring itself."""
    if not raw.startswith(SECRET_REFERENCE):
        return None
    secret_id = raw.removeprefix(SECRET_REFERENCE)
    if not _SECRET_ID.fullmatch(secret_id):
        raise KeyringError(f"the {name} keyring's reference must name a secret ID")
    return secret_id


def check_keyring_setting(
    raw: str, *, name: str, key_id: re.Pattern[str], needs_activation: bool = False
) -> None:
    """For the settings: a reference to a secret, or a keyring that `parse_keyring` accepts."""
    if secret_reference(raw, name=name) is None:
        parse_keyring(raw, name=name, key_id=key_id, needs_activation=needs_activation)


def active_since(raw: str) -> datetime | None:
    """When the keyring's active key took over: its `activated_at`, or else its `created_at`, as
    the key rotation job counts a key's period (6.5). None when the keyring has neither, or isn't
    one `parse_keyring` would accept; the caller has parsed it already. Reads no key."""
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(entries, list):
        return None
    active = [e for e in entries if isinstance(e, dict) and e.get("state") == "active"]
    if len(active) != 1:
        return None
    for field_name in ("activated_at", "created_at"):
        try:
            when = _time(active[0].get(field_name), "", "")
        except KeyringError:
            continue
        if when is not None:
            return when
    return None


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
