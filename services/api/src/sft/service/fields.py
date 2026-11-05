"""Sealing file names and messages for their `*_ct` columns (encryption and keys 3.2).

The design stores names and messages only as AES-256-GCM ciphertext under the tenant's data key,
unwrapped with KMS. That needs KMS and `tenant_data_keys`, which arrive with field encryption in M6.
Until then this module is the one place values pass through on their way to and from those
columns, so M6 changes this module and a data migration, not the callers:

- `seal` writes format 0: a zero byte, then the UTF-8 text. **Format 0 is not encrypted.** It
  exists so the columns are `bytea` from the start and every read and write already goes through
  here. `data_key_version` stays empty for it.
- `open` reads format 0 and refuses any other format, so nothing is ever shown that this code
  can't vouch for.

The tenant is the caller's scope, never the row's: M6's format binds it into the additional
authenticated data, and a row of another tenant fails to open (the third isolation layer).
Nothing here logs a value.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

PLAINTEXT_FORMAT: Final = 0
"""The stand-in format of M2: not encrypted. Field encryption (M6) adds format 1."""


class SealedValueError(ValueError):
    """A stored value in a format this code can't open."""


def seal(tenant_id: UUID, text: str) -> bytes:
    """`text` as stored in a `*_ct` column of `tenant_id`'s row."""
    if not isinstance(tenant_id, UUID):
        raise TypeError("tenant_id must be the scope's tenant")
    return bytes([PLAINTEXT_FORMAT]) + text.encode("utf-8")


def open_sealed(tenant_id: UUID, value: bytes) -> str:
    """The text of a `*_ct` value, read in `tenant_id`'s scope."""
    if not isinstance(tenant_id, UUID):
        raise TypeError("tenant_id must be the scope's tenant")
    if not value or value[0] != PLAINTEXT_FORMAT:
        raise SealedValueError("unknown sealed-value format")
    return value[1:].decode("utf-8")
