"""What the database keeps in place of a bearer token (data model 2.2, 2.4; #192).

A link token, a link session token, a member or operator session token, an invitation token or an
API key is never stored. Its row holds the SHA-256 of the token as the caller sends it, and the
credential lookup hashes what arrives to find the row. The token
carries at least 256 bits of entropy, so a fast hash is enough: there is nothing to guess, and no
salt is needed for the unique index the lookup uses.
"""

from __future__ import annotations

import hashlib


def token_hash(token: str) -> bytes:
    """The SHA-256 of the token's UTF-8 encoding: 32 bytes, what every `*token_hash` column
    holds."""
    return hashlib.sha256(token.encode()).digest()


__all__ = ["token_hash"]
