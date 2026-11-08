"""The stored form of an encrypted field: what a `*_ct` column holds (encryption and keys 3.2, 3.3).

Two formats, told apart by the first byte:

- **Format 0**, M2's stand-in: a zero byte, then the UTF-8 text. **Not encrypted.** Rows written
  before field encryption (#236) hold it until the backfill job re-seals them; it is read, never
  written.
- **Format 1**, AES-256-GCM under a tenant's data key:

      0x01 | key version (4 bytes, big-endian) | nonce (12 bytes) | ciphertext | tag (16 bytes)

  The additional authenticated data binds the value to where it belongs: the data key's purpose
  (`field-dek` or `dlp-dek`), the tenant, the table, the column, the row's ID and the key version.
  A value copied to another row, column or tenant, or read with another tenant's key, fails
  authentication instead of decrypting.

This module is the format and nothing else: no key handling, no I/O. The data layer reads the key
version from a value to fill a row's `data_key_version` or `dlp_key_version` column
(`key_version`), and `sft.service.fields` does the rest. The cipher is `cryptography`'s AESGCM, a
standard AEAD implementation; nothing here is our own cryptography. No message here ever holds a
value or a key.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PLAINTEXT_FORMAT: Final = 0
"""M2's stand-in: not encrypted. Read until the backfill has re-sealed every row, never written."""
AEAD_FORMAT: Final = 1
"""AES-256-GCM under a tenant's data key (#236)."""

KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
TAG_BYTES: Final = 16
MAX_KEY_VERSION: Final = 2**31 - 1
"""A key version fits PostgreSQL's `integer`, which the version columns are."""

_HEADER: Final = struct.Struct(">BI")
_PREFIX: Final = _HEADER.size + NONCE_BYTES
_AAD_TAG: Final = b"sft-sealed-field"


class SealedValueError(ValueError):
    """A stored value this code can't open: an unknown format, a short value, a bad key."""


class SealedAuthenticationError(SealedValueError):
    """The value didn't authenticate: another tenant's, row's or column's value, or tampered with.

    Read in the caller's tenant (encryption and keys 3.2, point 3), a row of another tenant ends
    here, so the service counts it and pages as a possible isolation breach."""


@dataclass(frozen=True, slots=True)
class Column:
    """A column that holds sealed values: part of every value's additional authenticated data."""

    table: str
    column: str

    def __str__(self) -> str:
        return f"{self.table}.{self.column}"


def value_format(value: bytes) -> int:
    """The format byte of a stored value."""
    if not value:
        raise SealedValueError("an empty sealed value")
    return value[0]


def key_version(value: bytes | None) -> int | None:
    """The data key version a format 1 value names; None for no value or format 0.

    What the data layer stores in the row's version column, so the database refuses to delete a
    key version a row still uses (data model 2.1)."""
    if not value or value[0] != AEAD_FORMAT or len(value) < _PREFIX + TAG_BYTES:
        return None
    return int(_HEADER.unpack_from(value)[1])


def associated_data(
    purpose: str, tenant_id: UUID, column: Column, row_id: UUID, version: int
) -> bytes:
    """What a value is bound to, length-prefixed so no two bindings encode alike."""
    if not isinstance(tenant_id, UUID) or not isinstance(row_id, UUID):
        raise TypeError("the tenant and the row are UUIDs")
    parts = (
        _AAD_TAG,
        bytes([AEAD_FORMAT]),
        purpose.encode(),
        tenant_id.bytes,
        column.table.encode(),
        column.column.encode(),
        row_id.bytes,
        struct.pack(">I", version),
    )
    return b"".join(struct.pack(">H", len(p)) + p for p in parts)


def encrypt(
    key: bytes,
    *,
    purpose: str,
    tenant_id: UUID,
    column: Column,
    row_id: UUID,
    version: int,
    plaintext: bytes,
) -> bytes:
    """`plaintext` sealed in format 1 under `key`, version `version`, with a fresh random nonce."""
    if len(key) != KEY_BYTES:
        raise SealedValueError("a data key is 256 bits")
    if not 1 <= version <= MAX_KEY_VERSION:
        raise SealedValueError("a key version is 1 or more")
    nonce = os.urandom(NONCE_BYTES)
    aad = associated_data(purpose, tenant_id, column, row_id, version)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return _HEADER.pack(AEAD_FORMAT, version) + nonce + sealed


def decrypt(
    key: bytes, *, purpose: str, tenant_id: UUID, column: Column, row_id: UUID, value: bytes
) -> bytes:
    """The plaintext of a format 1 value, or `SealedAuthenticationError`."""
    version = key_version(value)
    if version is None:
        raise SealedValueError("not a format 1 sealed value")
    if len(key) != KEY_BYTES:
        raise SealedValueError("a data key is 256 bits")
    nonce = value[_HEADER.size : _PREFIX]
    aad = associated_data(purpose, tenant_id, column, row_id, version)
    try:
        return AESGCM(key).decrypt(nonce, value[_PREFIX:], aad)
    except InvalidTag:
        raise SealedAuthenticationError("the sealed value didn't authenticate") from None


def plaintext_of(value: bytes) -> bytes:
    """The bytes of a format 0 value (M2's stand-in, not encrypted)."""
    if value_format(value) != PLAINTEXT_FORMAT:
        raise SealedValueError("not a format 0 value")
    return value[1:]
