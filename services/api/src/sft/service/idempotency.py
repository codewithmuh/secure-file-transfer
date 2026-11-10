"""`Idempotency-Key` for the creating operations (architecture 5.4, API README 5, #144).

A creating `POST` that takes the header runs its work through `once`, in the transaction that
creates the resource:

    async with database.transaction(scope) as session:
        outcome = await idempotency.once(
            session, caller, request, status=201, resource_type="user",
            create=lambda: users.create_invitation(session, ...),
            rebuild=lambda user_id: users.get_user(session, user_id),
            resource_id=lambda user: user.id,
        )

- **No key:** `create` runs, and nothing is kept.
- **A new key:** `create` runs, and the key's row (status, resource) commits with what it made.
- **The same key, method, path and body again**, within 24 hours: `create` doesn't run, so no
  second resource, audit event, outbox message or rate-limit charge. `rebuild` reads the resource
  as it is now, and the answer has the first request's status (`Outcome.replayed`).
- **The same key with another method, path or body:** `409 idempotency_conflict`, so a key reused
  on another resource is refused, not answered with the first.
- **The same key while the first request still runs:** `409 idempotency_in_progress`. The first
  holds the key's lock until its transaction ends; the second doesn't wait for it.

A key belongs to its caller: a member's user (so it survives a new sign-in), an API key, or a link
session. Response bodies are never kept, so no secret or address is stored, and an operation whose
answer holds a secret (`createApiKey`) takes no key at all.

`delete_expired_keys` is the daily job's step (data model 6), run as `sft_jobs`, in the `cleanup`
job (#162).

**An operator's keys** (#160, revision 0036): `createTenant` and `recoverTenantAdmin`. The key
belongs to the operator, by their Identity Center user name (`OperatorKey`), so a retry with a new
15-minute token still finds it. It is kept in the scope of the tenant the call made or acted on,
committed with the change:

- `operator_replay` runs first, in platform scope: the same key, method, path and body within 24
  hours is answered as the first request was, with nothing done again; another request with the
  key is `409 idempotency_conflict`, and so is a key used more than 24 hours ago that the daily
  job hasn't deleted yet, which is never written again.
- `operator_claim` runs in the creating transaction, before the work: it takes the key's lock
  (else `409 idempotency_in_progress`, as for `inviteUser`) and writes the key's row. A second
  request that raced past `operator_replay` can't write the row again, so it is refused the same
  way and rolls back: one tenant, one invitation, one email.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final
from uuid import UUID, uuid5

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, NotFound
from sft.data import idempotency
from sft.data.database import Database
from sft.data.scope import Scope
from sft.service.caller import Caller, CallerKind

log = logging.getLogger(__name__)

JOB_BATCH: Final = 1000
"""Rows the daily job deletes per transaction, and tenants it finds per pass."""

_OPERATORS: Final = UUID("0195f3c0-7a1e-7c4e-9b2d-6f1d0c2a8e51")
"""The namespace of the UUIDs that stand for operators' Identity Center user names (#160). Fixed:
changing it would orphan every live operator key."""


@dataclass(frozen=True, slots=True)
class IdempotentRequest:
    """A request's `Idempotency-Key` and its fingerprint (`fingerprint`)."""

    key: str
    fingerprint: bytes


@dataclass(frozen=True, slots=True)
class Outcome[T]:
    """What `once` returns: the resource, the status to answer with, and whether it is a replay."""

    value: T
    status: int
    replayed: bool = False


def fingerprint(method: str, path: str, body: bytes) -> bytes:
    """The SHA-256 of the method, the path with its resource IDs and the canonical body.

    A JSON body is compared as JSON: the same members in another order, or other white space,
    are the same body. Anything else is compared byte for byte.
    """
    try:
        canonical = json.dumps(
            json.loads(body), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    except ValueError:
        canonical = body
    digest = hashlib.sha256()
    for part in (method.upper().encode(), path.encode(), canonical):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def key_owner(caller: Caller) -> tuple[str, UUID]:
    """Whose key it is: a member's user, an API key or a link session (architecture 5.4)."""
    if caller.kind is CallerKind.MEMBER and caller.user_id is not None:
        return caller.kind.value, caller.user_id
    if (
        caller.kind in (CallerKind.API_KEY, CallerKind.RECIPIENT, CallerKind.UPLOADER)
        and caller.credential_id is not None
    ):
        return caller.kind.value, caller.credential_id
    raise ValueError(f"a {caller.kind} caller has no idempotency keys")


async def once[T](
    session: AsyncSession,
    caller: Caller,
    request: IdempotentRequest | None,
    *,
    status: int,
    resource_type: str,
    create: Callable[[], Awaitable[T]],
    rebuild: Callable[[UUID], Awaitable[T | None]],
    resource_id: Callable[[T], UUID],
) -> Outcome[T]:
    """Run `create` once per key, or answer a retry as the first request was answered."""
    if request is None:
        return Outcome(await create(), status)
    caller_type, caller_id = key_owner(caller)
    if not await idempotency.lock(session, caller_type, caller_id, request.key):
        raise Conflict("idempotency_in_progress", "A request with this key is still running.")
    replayed = await _replayed(session, caller, request, resource_type, rebuild)
    if replayed is not None:
        return replayed
    value = await create()
    saved = await idempotency.save(
        session,
        caller_type,
        caller_id,
        request.key,
        fingerprint=request.fingerprint,
        status=status,
        resource_type=resource_type,
        resource_id=resource_id(value),
    )
    if not saved:
        # Another transaction wrote the key first, which the lock rules out; refuse, so this
        # one rolls back rather than make a second resource.
        raise Conflict("idempotency_in_progress", "A request with this key is still running.")
    return Outcome(value, status)


async def replay[T](
    session: AsyncSession,
    caller: Caller,
    request: IdempotentRequest | None,
    *,
    resource_type: str,
    rebuild: Callable[[UUID], Awaitable[T | None]],
) -> Outcome[T] | None:
    """The first answer to a retry, read without the key's lock; None without a key or for a new
    one.

    For an operation that does work outside its transaction before `once` runs: `addTransferFile`
    starts its multipart upload in S3 first, so a retry checks here and starts no second upload.
    `once` still decides: a key that another request writes in the meantime is replayed there.
    """
    if request is None:
        return None
    return await _replayed(session, caller, request, resource_type, rebuild)


async def _replayed[T](
    session: AsyncSession,
    caller: Caller,
    request: IdempotentRequest,
    resource_type: str,
    rebuild: Callable[[UUID], Awaitable[T | None]],
) -> Outcome[T] | None:
    caller_type, caller_id = key_owner(caller)
    stored = await idempotency.find(session, caller_type, caller_id, request.key)
    if stored is None:
        return None
    if stored.fingerprint != request.fingerprint or stored.resource_type != resource_type:
        raise Conflict("idempotency_conflict", "This key was used for a different request.")
    value = await rebuild(stored.resource_id)
    if value is None:
        raise NotFound
    return Outcome(value, stored.status, replayed=True)


@dataclass(frozen=True, slots=True)
class OperatorKey:
    """An operator's `Idempotency-Key`, owned by the operator rather than their token."""

    caller_id: UUID
    request: IdempotentRequest

    @classmethod
    def of(cls, operator_name: str, request: IdempotentRequest | None) -> OperatorKey | None:
        if request is None:
            return None
        return cls(uuid5(_OPERATORS, operator_name), request)


@dataclass(frozen=True, slots=True)
class OperatorReplay:
    """What the first request with an operator's key did: in which tenant, to which resource."""

    tenant_id: UUID
    resource_id: UUID
    status: int


async def operator_replay(
    database: Database, key: OperatorKey | None, *, resource_type: str
) -> OperatorReplay | None:
    """The first answer's tenant, resource and status for a retry; None without a key or for a
    new one (the module docstring)."""
    if key is None:
        return None
    async with database.transaction(Scope.platform()) as session:
        found = await idempotency.find_operator(session, key.caller_id, key.request.key)
    if found is None:
        return None
    stored = found.stored
    if not found.live:
        raise Conflict(
            "idempotency_conflict", "This key was used more than 24 hours ago. Use a new key."
        )
    if stored.fingerprint != key.request.fingerprint or stored.resource_type != resource_type:
        raise Conflict("idempotency_conflict", "This key was used for a different request.")
    return OperatorReplay(found.tenant_id, stored.resource_id, stored.status)


async def operator_claim(
    session: AsyncSession,
    key: OperatorKey | None,
    *,
    status: int,
    resource_type: str,
    resource_id: UUID,
) -> None:
    """Lock and write the operator's key in the creating transaction, before its work; nothing
    without a key."""
    if key is None:
        return
    in_progress = Conflict("idempotency_in_progress", "A request with this key is still running.")
    if not await idempotency.lock_operator(session, key.caller_id, key.request.key):
        raise in_progress
    saved = await idempotency.save_operator(
        session,
        key.caller_id,
        key.request.key,
        fingerprint=key.request.fingerprint,
        status=status,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    if not saved:
        # Written by a request that committed after this one's `operator_replay`: its retry
        # gets the first answer.
        raise in_progress


async def delete_expired_keys(database: Database, *, batch: int = JOB_BATCH) -> int:
    """The daily job's step: delete every expired key, tenant by tenant; how many went.

    Find across, act within (ADR-0020): the tenants with expired keys in system scope, then each
    tenant's rows in its own scope, `batch` at a time, one short transaction each.
    """
    deleted = 0
    while True:
        async with database.transaction(Scope.system()) as session:
            tenants = await idempotency.tenants_with_expired(session, limit=batch)
        if not tenants:
            break
        for tenant_id in tenants:
            while True:
                async with database.transaction(Scope.tenant(tenant_id)) as session:
                    gone = await idempotency.delete_expired(session, limit=batch)
                deleted += gone
                if gone < batch:
                    break
    log.info("expired idempotency keys deleted", extra={"count": deleted})
    return deleted
