"""The sign-in state between the redirect and the callback, in the Valkey store (ADR-0016).

`startSignIn` stores the state, the PKCE verifier, the nonce, the connection chosen and the return
path under the SHA-256 of a new random `__Host-sft_auth` cookie value, for 10 minutes. The callback
takes it with `GETDEL`, so it is used at most once, even by two callbacks racing. Nothing is
signed, and the verifier never leaves the server (authn and authz 2.4).

Two more fields, both hashes, never a credential (#159, #239):

- `previous_session`: the SHA-256 of the `__Host-sft_session` cookie the browser sent to the start,
  hex. The start is a same-site navigation from the web app, so the Strict cookie arrives there; the
  callback is a cross-site redirect from the user pool and gets none. The callback ends that session
  by its hash, so a session planted before sign-in never outlives it (authn and authz 3.3).
- `invited_user_id` and `invitation`: for `startInvitationSignIn`, the invited user and the SHA-256
  of their invitation token, hex. The callback binds the subject to that user and consumes the
  token (authn and authz 2.5).

A record written by an older pod has none of them, and reads as a sign-in without them.

The key holds a hash, never the cookie value (abuse and rate limits 4.2). Any error from the store
is `StateStoreUnavailableError`, and the sign-in routes answer 503: sign-in fails closed (abuse and
rate limits 4.5).
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from typing import Final, Protocol
from uuid import UUID

import valkey.asyncio as valkey
from valkey.exceptions import ValkeyError

from sft.data.counters import ValkeyIam, iam_url

log = logging.getLogger(__name__)

LIFETIME_SECONDS: Final = 600
_PREFIX: Final = "signin:state:"
TIMEOUT_SECONDS: Final = 0.5
_DIGEST_HEX: Final = 64


class StateStoreUnavailableError(Exception):
    """The Valkey store couldn't be reached or answered badly: refuse the sign-in."""


@dataclass(frozen=True, slots=True)
class PendingSignIn:
    state: str
    verifier: str
    nonce: str
    connection_id: UUID
    return_to: str
    previous_session: str | None = None
    """The SHA-256 of the session cookie sent to the start, hex (the module docstring)."""
    invited_user_id: UUID | None = None
    invitation: str | None = None
    """The SHA-256 of the invitation token, hex, with `invited_user_id`."""

    def to_json(self) -> str:
        return json.dumps(
            {
                **asdict(self),
                "connection_id": str(self.connection_id),
                "invited_user_id": None
                if self.invited_user_id is None
                else str(self.invited_user_id),
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> PendingSignIn:
        data = json.loads(raw)
        invited = data.get("invited_user_id")
        return cls(
            state=str(data["state"]),
            verifier=str(data["verifier"]),
            nonce=str(data["nonce"]),
            connection_id=UUID(str(data["connection_id"])),
            return_to=str(data["return_to"]),
            previous_session=_hex_digest(data.get("previous_session")),
            invited_user_id=None if invited is None else UUID(str(invited)),
            invitation=_hex_digest(data.get("invitation")),
        )


def _hex_digest(value: object) -> str | None:
    """A SHA-256 in hex, or None for anything else: a record never carries a raw credential."""
    if not isinstance(value, str) or len(value) != _DIGEST_HEX:
        return None
    try:
        bytes.fromhex(value)
    except ValueError:
        return None
    return value


class StateStore(Protocol):
    async def put(self, cookie: str, pending: PendingSignIn) -> None: ...

    async def take(self, cookie: str) -> PendingSignIn | None: ...

    async def aclose(self) -> None: ...


def _key(cookie: str) -> str:
    return _PREFIX + hashlib.sha256(cookie.encode()).hexdigest()


class ValkeyStateStore:
    """The pre-auth records in Valkey, one key each with a 10-minute TTL."""

    def __init__(self, client: valkey.Valkey) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str, *, iam: ValkeyIam | None = None) -> ValkeyStateStore:
        """The store at `url`; with `iam`, each connection signs in with an IAM token."""
        address, extra = iam_url(url, iam)
        client = valkey.from_url(  # type: ignore[no-untyped-call]
            address,
            **extra,
            socket_timeout=TIMEOUT_SECONDS,
            socket_connect_timeout=TIMEOUT_SECONDS,
            retry_on_timeout=False,
            decode_responses=True,
        )
        return cls(client)

    async def put(self, cookie: str, pending: PendingSignIn) -> None:
        try:
            stored = await self._client.set(
                _key(cookie), pending.to_json(), ex=LIFETIME_SECONDS, nx=True
            )
        except (ValkeyError, OSError) as exc:
            log.warning("sign-in state store unavailable", extra={"error": type(exc).__name__})
            raise StateStoreUnavailableError from exc
        if not stored:  # 256 random bits never collide; a store that says so is broken
            raise StateStoreUnavailableError

    async def take(self, cookie: str) -> PendingSignIn | None:
        try:
            raw = await self._client.getdel(_key(cookie))
        except (ValkeyError, OSError) as exc:
            log.warning("sign-in state store unavailable", extra={"error": type(exc).__name__})
            raise StateStoreUnavailableError from exc
        if raw is None:
            return None
        try:
            return PendingSignIn.from_json(str(raw))
        except (ValueError, KeyError, TypeError):
            log.warning("sign-in state record unreadable")
            return None

    async def aclose(self) -> None:
        await self._client.aclose()
