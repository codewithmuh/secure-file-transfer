"""Tenant API keys: create, list, revoke, resolve, and audit every use (#215; FR-32, FR-27; authn
and authz 5, 6.3; data model 2.1).

**The key** (authn and authz 5.1) is `sft_<env>_<secret>_<check>`: the environment (`dev`, `stg`
or `prd`, `API_KEY_ENVIRONMENT`), 43 base62 characters from the operating system's generator (256
bits) and 6 base62 characters of a CRC-32 over the rest. `parse_key` refuses a malformed key, one
of another environment or one whose check doesn't match before any database query, so a typo or a
random string costs nothing. The database holds only the key's SHA-256 and `key_prefix`; the key
appears once, in `createApiKey`'s answer, and never in a log, trace, audit record or error.

**Operations** (table 6.3), each checked against the permission registry first:

- `createApiKey` (`api_key.create`): an admin of the web app, acting as one (a local admin needs a
  passkey), with a sign-in in the last 15 minutes. At most 25 active keys per tenant (`422
  validation_failed`, under a transaction lock so two at once can't pass 25) and 20 new keys a day
  (group J, `429`). Expiry defaults to 90 days, at most 365. No `Idempotency-Key`: the secret is
  never stored, so a retry couldn't return it.
- `listApiKeys` (`api_key.read`): newest first, never the secret or hash.
- `revokeApiKey` (`api_key.revoke`): any admin, without a passkey (3.3). A security-critical
  record: the revocation commits, then its record goes to both regions' archive, and the call
  answers `200` only once both hold it, `503` otherwise, with the key revoked. A key revoked
  already comes back unchanged, and its record is written if still missing.

**Owners** (5.2). `revoke_owner_keys` revokes every key of a user being deactivated or demoted, in
that change's transaction (`sft.service.members`), one security-critical `api_key.revoked` each,
with the reason.

**Resolving a key** (`resolve`): the credential lookup in lookup scope finds the key's ID and
tenant by its hash, then the tenant's scope checks it is live: not revoked, not expired, its owner
an active admin, its tenant active (`sft.data.api_keys.live_key`). Lookups aren't cached, so a
revocation applies to the next request. The caller acts as its owner, limited to its scopes.

**Every use is audited** (FR-27, 5.2): `record_use` writes one `api_key.used` event per request,
with the operation ID and the answer's status and nothing of the body, in a short transaction of
its own after the handler and before the answer (`sft.api.caller.ApiKeyUse`). If it can't be
written, the request answers `503` (NFR-15): fail closed. A write the request made has already
committed with its own event, which names the key as the actor, so nothing it did goes unaudited.

**Expiry emails** (5.2): `queue_expiry_notices`, a step of the daily cleanup job, asks the
notification worker to email the owner and the tenant's admins 14 and 3 days before a key
expires: once per notice, recorded on the key, so a second run asks nothing again.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Final, Literal, get_args
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import FieldError, InvalidRequest, NotFound, Unprocessable, json_pointer
from sft.core.ids import uuid7
from sft.data import api_keys, audit
from sft.data.audit import Actor, ArchivedEvent, Origin, Target
from sft.data.database import Database
from sft.data.models import ActorType, ApiKey, ApiKeyRevokedReason, ApiKeyScope, Role
from sft.data.outbox import API_KEY_EXPIRING, enqueue
from sft.data.scope import Scope
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller, CallerKind
from sft.service.permissions import BY_OPERATION, authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import CREATE_API_KEY

KeyEnvironment = Literal["dev", "stg", "prd"]
KEY_ENVIRONMENTS: Final[tuple[KeyEnvironment, ...]] = get_args(KeyEnvironment)

BASE62: Final = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SECRET_LENGTH: Final = 43
"""43 base62 characters: 256 bits (62^43 > 2^256)."""
CHECK_LENGTH: Final = 6
"""A CRC-32 in base62 (62^6 > 2^32)."""
PREFIX_SECRET_CHARS: Final = 8
_KEY = re.compile(
    rf"sft_(dev|stg|prd)_([0-9A-Za-z]{{{SECRET_LENGTH}}})_([0-9A-Za-z]{{{CHECK_LENGTH}}})"
)

MAX_ACTIVE: Final = 25
"""Active keys per tenant (authn and authz 5.2)."""
DEFAULT_LIFETIME: Final = timedelta(days=90)
MAX_LIFETIME: Final = timedelta(days=365)
MAX_PAGE: Final = 100
NOTICE_DAYS: Final = (14, 3)
"""The expiry emails, in days before expiry (5.2)."""
BATCH: Final = 1000
TARGET: Final = api_keys.TARGET


class RevokeReason(StrEnum):
    """`api_key.revoked`'s `reason`."""

    ADMIN = ApiKeyRevokedReason.ADMIN.value
    OWNER_DEACTIVATED = ApiKeyRevokedReason.OWNER_DEACTIVATED.value
    OWNER_DEMOTED = ApiKeyRevokedReason.OWNER_DEMOTED.value


class NoticeStage(IntEnum):
    """Which expiry email the daily job asked for (`api_key.expiry_notice_queued`)."""

    DAYS_14 = 14
    DAYS_3 = 3


class SystemActor(StrEnum):
    CLEANUP_JOB = "cleanup_job"


Operation = StrEnum("Operation", [(name, name) for name in sorted(BY_OPERATION)])  # type: ignore[misc]
"""Every operation ID of the registry, as `api_key.used`'s `operation`: a code, never text."""


# ---- the key's format (authn and authz 5.1) ----


def _base62(value: int, length: int) -> str:
    digits = []
    for _ in range(length):
        value, digit = divmod(value, 62)
        digits.append(BASE62[digit])
    if value:
        raise ValueError("the value doesn't fit")
    return "".join(reversed(digits))


def _check(body: str) -> str:
    return _base62(zlib.crc32(body.encode()), CHECK_LENGTH)


def new_key(environment: KeyEnvironment) -> str:
    """A new key for `environment`: its secret is 256 bits from the operating system."""
    if environment not in KEY_ENVIRONMENTS:
        raise ValueError("the key environment is dev, stg or prd")
    secret = "".join(secrets.choice(BASE62) for _ in range(SECRET_LENGTH))
    body = f"sft_{environment}_{secret}"
    return f"{body}_{_check(body)}"


def parse_key(raw: str, environment: KeyEnvironment) -> str | None:
    """`raw` if it is a well-formed key of this environment whose check matches; else None.
    No database query: a typo or a random string is refused here (5.1)."""
    match = _KEY.fullmatch(raw)
    if match is None or match.group(1) != environment:
        return None
    body = raw[: -(CHECK_LENGTH + 1)]
    if not secrets.compare_digest(_check(body), match.group(3)):
        return None
    return raw


def key_hash(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


def key_prefix(key: str) -> str:
    """`sft_<env>_` and the secret's first 8 characters, as lists show it."""
    return key[: len("sft_xxx_") + PREFIX_SECRET_CHARS]


# ---- createApiKey, listApiKeys, revokeApiKey ----


@dataclass(frozen=True, slots=True)
class CreatedKey:
    key: ApiKey
    secret: str

    def __repr__(self) -> str:  # never the secret
        return f"CreatedKey(key_id={self.key.id})"


@dataclass(frozen=True, slots=True)
class KeyPage:
    items: Sequence[ApiKey]
    next_cursor: str | None


def _invalid(field: str, detail: str) -> Unprocessable:
    return Unprocessable(
        "validation_failed", detail, errors=[FieldError(detail, pointer=json_pointer(field))]
    )


def _scope_flags(scopes: Sequence[str]) -> dict[str, audit.Detail]:
    return {f"scope_{s.replace(':', '_')}": True for s in sorted(scopes)}


async def create_api_key(
    database: Database,
    caller: Caller,
    *,
    name: str,
    scopes: Sequence[ApiKeyScope],
    expires_at: datetime | None,
    environment: KeyEnvironment,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> CreatedKey:
    """`createApiKey` (module docstring)."""
    authorize(caller, "createApiKey", now=now)
    tenant_id, owner = _tenant_and_user(caller)
    if not name.strip() or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in name):
        raise _invalid("name", "The name is 1 to 100 characters, without control characters.")
    expiry = now + DEFAULT_LIFETIME if expires_at is None else expires_at
    if expiry <= now or expiry > now + MAX_LIFETIME:
        raise _invalid("expires_at", "A key expires in the future, at most 365 days from now.")
    chosen = sorted({ApiKeyScope(s).value for s in scopes})
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        # One creation at a time per tenant, so two can't both pass 25.
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:name, 0))"),
            {"name": f"api_keys:{tenant_id}"},
        )
        if await api_keys.count_active(session) >= MAX_ACTIVE:
            raise Unprocessable(
                "validation_failed",
                f"A tenant has at most {MAX_ACTIVE} active keys: revoke one first.",
            )
        # Group J (20 a day), charged once the key can be made.
        await limiter.check(CREATE_API_KEY, caller.rate_limit_keys())
        secret = new_key(environment)
        key = await api_keys.insert_key(
            session,
            key_id=uuid7(),
            created_by=owner,
            name=name,
            key_prefix=key_prefix(secret),
            key_hash=key_hash(secret),
            scopes=chosen,
            expires_at=expiry,
        )
        await audit.record(
            session,
            action="api_key.created",
            actor=caller.actor(),
            target=Target(TARGET, key.id),
            origin=origin,
            details={
                "owner_id": owner,
                "expires_at": key.expires_at,
                **_scope_flags(chosen),
            },
        )
    return CreatedKey(key, secret)


def encode_cursor(key_id: UUID) -> str:
    return key_id.hex


def decode_cursor(cursor: str) -> UUID:
    try:
        return UUID(hex=cursor)
    except ValueError as exc:
        raise InvalidRequest("invalid_cursor") from exc


async def list_api_keys(
    database: Database, caller: Caller, *, cursor: str | None, limit: int, now: datetime
) -> KeyPage:
    """`listApiKeys`: the tenant's keys, newest first."""
    authorize(caller, "listApiKeys", now=now)
    tenant_id, _ = _tenant_and_user(caller)
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 keys")
    before = None if cursor is None else decode_cursor(cursor)
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        found = await api_keys.list_keys(session, before=before, limit=limit + 1)
    items = found[:limit]
    return KeyPage(items, encode_cursor(items[-1].id) if len(found) > limit else None)


async def revoke_api_key(
    database: Database,
    caller: Caller,
    key_id: UUID,
    *,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> ApiKey:
    """`revokeApiKey` (module docstring): a security-critical record."""
    authorize(caller, "revokeApiKey", now=now)
    tenant_id, _ = _tenant_and_user(caller)
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        key = await api_keys.get_key(session, key_id, for_update=True)
        if key is None:
            raise NotFound
        if key.revoked_at is None:
            revoked = await api_keys.revoke_key(session, key_id, reason=ApiKeyRevokedReason.ADMIN)
            if revoked is None:  # pragma: no cover - the row is locked
                raise NotFound
            key = revoked
            await _record_revoked(
                session, caller.actor(), key.id, key.created_by, RevokeReason.ADMIN, origin
            )
        event = await audit.latest_critical_event(
            session, action="api_key.revoked", target=Target(TARGET, key.id)
        )
    await archive.confirm([event] if event else [])
    return key


async def _record_revoked(
    session: AsyncSession,
    actor: Actor,
    key_id: UUID,
    owner_id: UUID,
    reason: RevokeReason,
    origin: Origin | None,
) -> UUID:
    return await audit.record(
        session,
        action="api_key.revoked",
        actor=actor,
        target=Target(TARGET, key_id),
        origin=origin,
        security_critical=True,
        details={"reason": reason, "owner_id": owner_id},
    )


async def revoke_owner_keys(
    session: AsyncSession,
    user_id: UUID,
    *,
    reason: Literal[RevokeReason.OWNER_DEACTIVATED, RevokeReason.OWNER_DEMOTED],
    actor: Actor,
    origin: Origin,
) -> list[ArchivedEvent]:
    """Revoke every key `user_id` owns, in the caller's transaction, one security-critical
    `api_key.revoked` each; with the records of keys an earlier attempt revoked for the same reason,
    so a retry can complete their archive. The caller confirms them after the commit."""
    model_reason = ApiKeyRevokedReason(reason.value)
    for revoked in await api_keys.revoke_owner_keys(session, user_id, reason=model_reason):
        await _record_revoked(session, actor, revoked, user_id, reason, origin)
    events = []
    for revoked in await api_keys.owner_keys(session, user_id, reason=model_reason):
        event = await audit.latest_critical_event(
            session, action="api_key.revoked", target=Target(TARGET, revoked)
        )
        if event is not None:
            events.append(event)
    return events


def _tenant_and_user(caller: Caller) -> tuple[UUID, UUID]:
    if caller.tenant_id is None or caller.user_id is None:  # pragma: no cover - authorize's
        raise ValueError("a tenant caller has a tenant and a user")
    return caller.tenant_id, caller.user_id


# ---- resolving a key, and auditing its use ----


async def resolve(database: Database, key: str) -> Caller | None:
    """The caller a well-formed key stands for, or None if no live key has it (module
    docstring). `key` has passed `parse_key`."""
    async with database.transaction(Scope.lookup()) as session:
        found = await api_keys.lookup_key(session, key_hash(key))
    if found is None:
        return None
    async with database.transaction(Scope.tenant(found.tenant_id)) as session:
        live = await api_keys.live_key(session, found.key_id)
    if live is None:
        return None
    return Caller(
        CallerKind.API_KEY,
        tenant_id=live.tenant_id,
        user_id=live.owner_id,
        role=Role.ADMIN,
        credential_id=live.key_id,
        scopes=live.scopes,
    )


async def record_use(
    database: Database, caller: Caller, *, operation: str | None, status: int, origin: Origin
) -> None:
    """One `api_key.used` event for one request of a key: the operation and the status, nothing
    of the body. Raises if it can't be written, so the request fails closed."""
    if caller.kind is not CallerKind.API_KEY or caller.tenant_id is None:
        raise ValueError("only an API key's requests are recorded as uses")
    assert caller.credential_id is not None  # noqa: S101 - every key caller has its key
    details: dict[str, audit.Detail] = {"status": status, "owner_id": caller.user_id}
    if operation is not None and operation in BY_OPERATION:
        details["operation"] = Operation(operation)
    async with database.transaction(Scope.tenant(caller.tenant_id)) as session:
        await audit.record(
            session,
            action="api_key.used",
            actor=Actor(ActorType.API_KEY, caller.credential_id),
            target=Target(TARGET, caller.credential_id),
            origin=origin,
            details=details,
        )


# ---- the daily expiry notices ----


def notice_due(expires_at: datetime, last: int | None, now: datetime) -> NoticeStage | None:
    """The expiry email a key is due, if any: 14 days before, then 3; a key made with less
    than 3 days left gets only the 3-day one."""
    left = expires_at - now
    if left <= timedelta(0):
        return None
    if left <= timedelta(days=NoticeStage.DAYS_3):
        return None if last == NoticeStage.DAYS_3 else NoticeStage.DAYS_3
    if left <= timedelta(days=NoticeStage.DAYS_14):
        return None if last is not None else NoticeStage.DAYS_14
    return None


async def queue_expiry_notices(database: Database, *, now: datetime) -> int:
    """Ask for each expiry email due (module docstring); how many were asked for. Finds across
    tenants in system scope, then acts in each key's tenant scope (data model 4.2)."""
    queued = 0
    window = timedelta(days=NoticeStage.DAYS_14)
    async with database.transaction(Scope.system()) as session:
        found = await api_keys.expiring(session, now=now, within=window, limit=BATCH)
    for key in found:
        stage = notice_due(key.expires_at, key.expiry_notice, now)
        if stage is None:
            continue
        async with database.transaction(Scope.tenant(key.tenant_id)) as session:
            if not await api_keys.mark_notice(
                session, key.key_id, stage=int(stage), before=key.expiry_notice
            ):
                continue  # another run asked first, or the key was revoked meanwhile
            await enqueue(session, API_KEY_EXPIRING, {"api_key_id": key.key_id})
            await audit.record(
                session,
                action="api_key.expiry_notice_queued",
                actor=Actor(ActorType.SYSTEM),
                target=Target(TARGET, key.key_id),
                details={"system_actor": SystemActor.CLEANUP_JOB, "days": stage},
            )
        queued += 1
    return queued


__all__ = [
    "BASE62",
    "DEFAULT_LIFETIME",
    "KEY_ENVIRONMENTS",
    "MAX_ACTIVE",
    "MAX_LIFETIME",
    "CreatedKey",
    "KeyEnvironment",
    "KeyPage",
    "NoticeStage",
    "Operation",
    "RevokeReason",
    "create_api_key",
    "key_hash",
    "key_prefix",
    "list_api_keys",
    "new_key",
    "notice_due",
    "parse_key",
    "queue_expiry_notices",
    "record_use",
    "resolve",
    "revoke_api_key",
    "revoke_owner_keys",
]
