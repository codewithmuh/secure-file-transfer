"""Members and admins of a tenant: invite, list, read, change and deactivate (FR-22, FR-27).

Each function checks the caller against the permission registry first (`authorize`, authn and
authz 6.1), then works in one transaction of the caller's tenant: the change, its audit event and,
for an invitation, the outbox message commit together (`sft.data.users` writes the last two).

The rules of the contract's member operations live here:

- An invitation never changes an existing user; the address is checked within the tenant only.
- The tenant always keeps at least one active admin (`409 last_admin`). A change that could break
  that (demoting or deactivating an active admin) locks the tenant's active admins before the
  user, so two at once can't both pass; any other change locks only the user (`_change`).
- A deactivated user can't be changed (`409 invalid_state`); deactivating one again returns them.
  Deactivation clears `dlp_approver` and `sso_fallback`.
- Setting the values a user already has changes nothing and writes no event.
- `sso_fallback` needs a tenant that uses SSO, which arrives in M6, so naming a fallback admin is
  `422 validation_failed` for now. `dlp_approver` names only an active user.

A change of `dlp_approver` writes `user.dlp_approver_changed` and an outbox message that emails
every active admin `dlp_policy_changed` with `approvers_changed` (#220, FR-54), in its transaction.
A deactivation that clears the designation writes `dlp_approval.approver_deactivated` in its
transaction (#230): the notification worker tells the admins at once when fewer than two approvers
are left, and otherwise adds the change to the coalesced policy notice.
An admin may name themselves an approver: they still can't approve their own transfers (T-100).

A role change and a deactivation end every session of the user in the same transaction (authn and
authz 3.3), so the next request of a session signs in again with the new role, or not at all. A
demotion or a deactivation also revokes every API key the user owns, in that transaction too, one
security-critical `api_key.revoked` each with the reason (#215, authn and authz 5.2), archived with
the change's own record. The admins' emails about role changes come with the notification
worker.

**Security-critical records** (#177, architecture 5.2): a deactivation and a demotion commit first,
then their record goes to the audit archive of both regions (`sft.service.audit_archive`), and the
call answers `200` only once both hold it, `503` otherwise, with the change kept. A retry finds the
change already made and writes the record of its latest event if it is still missing, then
answers `200` (API README 5).

**Forced sign-out and sign-in reset** (#197; authn and authz 2.5, 3.3, 3.6), both security-critical
records the same way:

- `sign_out_user` ends every session of the user, without deactivating them; they can sign in
  again. Every call is the admin's own action and writes its own event, naming the sessions it
  ended, even none.
- `reset_user_sign_in` ends every session and deletes the user's identities on the user pool's
  connections in one transaction, so no old credential maps to the user any more, and starts a new
  reset: a new `sign_in_reset_id` and the outbox message `member.sign_in_reset` with it. The
  notification worker then makes the pool user again and emails a new invitation, unless a newer
  reset has superseded that message meanwhile: so a reset while one is still being processed
  replaces its invitation, and a reset whose message was dead-lettered never blocks the next. A
  deactivated user can't be reset (`409 invalid_state`). SSO members reset at their own identity
  provider: they have no identity on the pool to delete (M6 refuses them by name).
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    FieldError,
    Forbidden,
    InvalidRequest,
    NotFound,
    Unprocessable,
    json_pointer,
)
from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, identities, member_sessions, users
from sft.data.audit import ArchivedEvent, Origin, Target
from sft.data.database import Database
from sft.data.models import Role, User, UserStatus
from sft.data.outbox import (
    DLP_APPROVER_DEACTIVATED,
    DLP_POLICY_CHANGED,
    MEMBER_SIGN_IN_RESET,
    enqueue,
)
from sft.data.scope import Scope
from sft.service import api_keys
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import INVITE_USER, KeyType

log = logging.getLogger(__name__)

MAX_PAGE: Final = users.MAX_PAGE

INVITE_LIMITS: Final = INVITE_USER
"""Group G's invitation limits: the caller's emails, the address's 3 a day within the tenant, and
the tenant's invitations (abuse and rate limits 2.2). The address counts under its pseudonym from
the `email-hmac` keyring, so the counter store never holds the address (`sft.core.pseudonyms`).
Until a re-invitation exists, an address gets one invitation per tenant anyway (`409
user_exists`), so the cap starts to bite once one does."""


@dataclass(frozen=True, slots=True)
class UserPage:
    items: Sequence[User]
    next_cursor: str | None


def _tenant_scope(caller: Caller) -> Scope:
    if caller.tenant_id is None:
        # authorize admits only tenant callers to these operations; this is a guard.
        raise Forbidden("permission_denied")
    return Scope.tenant(caller.tenant_id)


def _invalid(field: str, detail: str) -> Unprocessable:
    """`422 validation_failed`, pointing at the body field that breaks the rule."""
    return Unprocessable(
        "validation_failed", detail, errors=[FieldError(detail, pointer=json_pointer(field))]
    )


def _last_admin() -> Conflict:
    return Conflict("last_admin", "The tenant keeps at least one active admin.")


def encode_cursor(user_id: UUID) -> str:
    """An opaque cursor: the last user of the page."""
    return base64.urlsafe_b64encode(user_id.bytes).decode().rstrip("=")


def decode_cursor(cursor: str) -> UUID:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        return UUID(bytes=raw)
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequest("invalid_cursor") from exc


async def invite_user(
    database: Database,
    caller: Caller,
    *,
    email: str,
    role: Role,
    limiter: RateLimiter,
    emails: EmailKeyring,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[User]:
    """`inviteUser`: a new `invited` user, its audit event and its invitation email.

    The invitation limits (abuse and rate limits 2.2, G) count only an invitation that is made:
    after `authorize`, so a member can't use up their tenant's invitations, and after the insert,
    so a `409 user_exists` uses none. A refusal raises inside the transaction, which then writes
    nothing. Only a commit that fails after the count (a database outage) costs one.

    With an `Idempotency-Key`, a retry of the same request gets the first answer, with the user
    as they are now, and invites no one, audits nothing and charges no invitation limit again
    (`sft.service.idempotency`).
    """
    authorize(caller, "inviteUser", now=now)
    scope = _tenant_scope(caller)
    address = emails.for_limits(users.normalize_email(email), now).within(str(scope.tenant_id))
    limit_keys = {**caller.rate_limit_keys(), KeyType.TENANT_EMAIL: address}
    try:
        async with database.transaction(scope) as session:

            async def invite() -> User:
                user = await users.create_invitation(
                    session, email=email, role=role, actor=caller.actor(), origin=origin
                )
                await limiter.check(INVITE_LIMITS, limit_keys)
                return user

            async def rebuild(user_id: UUID) -> User | None:
                return await users.get_user(session, user_id)

            return await once(
                session,
                caller,
                idempotency,
                status=201,
                resource_type=users.TARGET,
                create=invite,
                rebuild=rebuild,
                resource_id=lambda user: user.id,
            )
    except users.UserExistsError as exc:
        raise Conflict("user_exists", "The address is already a user of this tenant.") from exc


async def list_users(
    database: Database,
    caller: Caller,
    *,
    role: Role | None = None,
    status: UserStatus | None = None,
    dlp_approver: bool | None = None,
    cursor: str | None = None,
    limit: int = 25,
    now: datetime,
) -> UserPage:
    """`listUsers`: one page of the tenant's users, oldest first. `limit` is 1 to `MAX_PAGE`, as
    the route's query validation has it; `users.list_users` refuses any other."""
    authorize(caller, "listUsers", now=now)
    after = None if cursor is None else decode_cursor(cursor)
    async with database.transaction(_tenant_scope(caller)) as session:
        found = await users.list_users(
            session,
            role=role,
            status=status,
            dlp_approver=dlp_approver,
            after=after,
            limit=limit,
        )
    items = found[:limit]
    more = len(found) > limit
    return UserPage(items, encode_cursor(items[-1].id) if more else None)


async def get_user(database: Database, caller: Caller, user_id: UUID, *, now: datetime) -> User:
    """`getUser`: one user of the tenant, or 404."""
    authorize(caller, "getUser", now=now)
    async with database.transaction(_tenant_scope(caller)) as session:
        user = await users.get_user(session, user_id)
    if user is None:
        raise NotFound
    return user


class _AdminAtStake(Exception):  # noqa: N818 - a signal, not an error
    """The user became an active admin between the first read and the lock: start again, with
    the tenant's active admins locked first."""


async def _change[T](
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    at_stake: Callable[[User], bool],
    apply: Callable[[AsyncSession, User, Sequence[UUID]], Awaitable[T]],
) -> T:
    """Run `apply` on the user, locked, in one transaction of the caller's tenant.

    `at_stake` says whether the change could take an active admin away. Only then are the tenant's
    active admins locked, before the user: one lock order for every such change, so two at once
    run one after the other. The user is read first to decide, then locked and read again. If the
    user became an active admin in between, the transaction is rolled back and run again with the
    admins locked first, since locking them after the user could deadlock with another change.
    `apply` gets the locked admins' IDs, or none.
    """
    lock_admins = False
    while True:
        try:
            async with database.transaction(_tenant_scope(caller)) as session:
                if not lock_admins:
                    seen = await users.get_user(session, user_id)
                    if seen is None:
                        raise NotFound
                    lock_admins = at_stake(seen)
                admins = await users.lock_active_admins(session) if lock_admins else ()
                user = await users.get_user(session, user_id, for_update=True)
                if user is None:
                    raise NotFound
                if at_stake(user) and not lock_admins:
                    raise _AdminAtStake
                return await apply(session, user, admins)
        except _AdminAtStake:
            lock_admins = True


def _active_admin(user: User) -> bool:
    return user.status == UserStatus.ACTIVE and user.role == Role.ADMIN


async def update_user(
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    role: Role | None = None,
    sso_fallback: bool | None = None,
    dlp_approver: bool | None = None,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> User:
    """`updateUser`: the role, the fallback admin flag and the DLP approver flag. A demotion is a
    security-critical record: `200` only once both regions' archive hold it."""
    authorize(caller, "updateUser", now=now)
    actor = caller.actor()

    def demotes_an_admin(user: User) -> bool:
        return role is Role.MEMBER and _active_admin(user)

    demoted = False
    revoked_keys: list[ArchivedEvent] = []

    async def apply(
        session: AsyncSession, user: User, admins: Sequence[UUID]
    ) -> tuple[User, ArchivedEvent | None]:
        nonlocal demoted
        was_admin = user.role == Role.ADMIN.value
        user = await change(session, user, admins)
        demoted = was_admin and user.role == Role.MEMBER.value
        # A demotion's record: this call's, or an earlier call's that a retry completes (#177).
        demotion = None
        if role is Role.MEMBER and user.role == Role.MEMBER.value:
            demotion = await audit.latest_critical_event(
                session, action="user.role_changed", target=Target(users.TARGET, user.id)
            )
            # The keys a demotion revoked, now or on the call a retry completes (#215).
            revoked_keys[:] = await api_keys.revoke_owner_keys(
                session,
                user.id,
                reason=api_keys.RevokeReason.OWNER_DEMOTED,
                actor=actor,
                origin=origin,
            )
        return user, demotion

    async def change(session: AsyncSession, user: User, admins: Sequence[UUID]) -> User:
        if user.status == UserStatus.DEACTIVATED:
            raise Conflict(
                "invalid_state",
                "A deactivated user can't be changed.",
                current_state=UserStatus.DEACTIVATED,
            )
        new_role = Role(user.role) if role is None else Role(role)
        if sso_fallback and not user.sso_fallback:
            # Only an admin of a tenant that uses SSO can be one (authn and authz 2.5); SSO is M6.
            raise _invalid("sso_fallback", "Only a tenant that uses SSO has fallback admins.")
        if sso_fallback and new_role is Role.MEMBER:
            raise _invalid("sso_fallback", "Only an admin can be a fallback admin.")
        if dlp_approver and not user.dlp_approver and user.status != UserStatus.ACTIVE:
            raise _invalid("dlp_approver", "Only an active user can be a DLP approver.")

        if new_role.value != user.role:
            if demotes_an_admin(user) and list(admins) == [user.id]:
                raise _last_admin()
            user = await users.change_role(session, user.id, new_role, actor=actor, origin=origin)
            await member_sessions.revoke_user_sessions(
                session, user.id, reason=member_sessions.RevokedReason.ROLE_CHANGED
            )
        if dlp_approver is not None and dlp_approver != user.dlp_approver:
            user = await users.set_dlp_approver(
                session, user.id, dlp_approver, actor=actor, origin=origin
            )
            # Every active admin is told (FR-54, #220): the notice carries IDs only.
            await enqueue(session, DLP_POLICY_CHANGED["approvers_changed"], {})
        if sso_fallback is not None and sso_fallback != user.sso_fallback:
            user = await users.set_sso_fallback(
                session, user.id, sso_fallback, actor=actor, origin=origin
            )
        return user

    user, demotion = await _change(
        database, caller, user_id, at_stake=demotes_an_admin, apply=apply
    )
    if demotion is None:
        return user
    if demoted:
        await archive.confirm([demotion, *revoked_keys])
    elif await archive.write([demotion, *revoked_keys]):
        # Not a demotion now: an earlier one's record, completed if the archive allows, but
        # this call answers for its own change only, so an outage doesn't fail it.
        log.warning("an earlier demotion's record is still not in both regions")
    return user


async def deactivate_user(
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> User:
    """`deactivateUser`: the user can't sign in any more; a retry returns the same user. A
    security-critical record: `200` only once both regions' archive hold it, and a retry after a
    `503` writes it if it is still missing (#177)."""
    authorize(caller, "deactivateUser", now=now)
    revoked_keys: list[ArchivedEvent] = []

    async def apply(
        session: AsyncSession, user: User, admins: Sequence[UUID]
    ) -> tuple[User, ArchivedEvent | None]:
        if user.status != UserStatus.DEACTIVATED:
            if _active_admin(user) and list(admins) == [user.id]:
                raise _last_admin()
            was_approver = user.dlp_approver
            user = await users.deactivate_user(
                session, user.id, actor=caller.actor(), origin=origin
            )
            if was_approver:  # the admins learn of it (#230)
                await enqueue(session, DLP_APPROVER_DEACTIVATED, {"user_id": user.id})
            await member_sessions.revoke_user_sessions(
                session, user.id, reason=member_sessions.RevokedReason.DEACTIVATED
            )
        # Every key they own, revoked in this transaction (#215); or, on a retry, the keys the
        # deactivation revoked, whose records it completes.
        revoked_keys[:] = await api_keys.revoke_owner_keys(
            session,
            user.id,
            reason=api_keys.RevokeReason.OWNER_DEACTIVATED,
            actor=caller.actor(),
            origin=origin,
        )
        event = await audit.latest_critical_event(
            session, action="user.deactivated", target=Target(users.TARGET, user.id)
        )
        return user, event

    user, event = await _change(database, caller, user_id, at_stake=_active_admin, apply=apply)
    await archive.confirm([*([event] if event else []), *revoked_keys])
    return user


SIGNED_OUT_BY_ADMIN: Final = "user.signed_out_by_admin"
SIGN_IN_RESET: Final = "user.sign_in_reset"

PoolConnections = Callable[[], Awaitable[Sequence[UUID]]]
"""The user pools' connection IDs, resolved once and kept (`sft.api.members`), only after the
caller may reset a sign-in."""


async def sign_out_user(
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> User:
    """`signOutUser`: every session of the user ends; the user stays as they are. Every call is an
    admin action with its own security-critical event, naming how many sessions it ended (0 if
    none were left): `200` only once both regions' archive hold it (#177)."""
    authorize(caller, "signOutUser", now=now)
    async with database.transaction(_tenant_scope(caller)) as session:
        user = await users.get_user(session, user_id, for_update=True)
        if user is None:
            raise NotFound
        ended = await member_sessions.revoke_user_sessions(
            session, user.id, reason=member_sessions.RevokedReason.SIGNED_OUT_BY_ADMIN
        )
        target = Target(users.TARGET, user.id)
        earlier = await audit.latest_critical_event(
            session, action=SIGNED_OUT_BY_ADMIN, target=target
        )
        await audit.record(
            session,
            action=SIGNED_OUT_BY_ADMIN,
            actor=caller.actor(),
            target=target,
            origin=origin,
            details={"sessions_ended": ended},
            security_critical=True,
        )
        event = await audit.latest_critical_event(
            session, action=SIGNED_OUT_BY_ADMIN, target=target
        )
    # The earlier sign-out's record too: a retry after a `503` completes it.
    await archive.confirm([e for e in (earlier, event) if e is not None])
    return user


async def reset_user_sign_in(
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    pool_connections: PoolConnections,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> User:
    """`resetUserSignIn`: every call ends the user's sessions, deletes their pool identities and
    starts a new reset (a new `sign_in_reset_id`) with its outbox message, in one transaction. The
    new reset supersedes one still being processed, whose message then sends nothing, so only the
    newest invitation goes out; a reset whose message was dead-lettered never blocks the next. A
    security-critical record: `202` only once both regions' archive hold it and the previous
    reset's, which a retry after a `503` completes (#177)."""
    authorize(caller, "resetUserSignIn", now=now)
    pools = await pool_connections()
    async with database.transaction(_tenant_scope(caller)) as session:
        user = await users.get_user(session, user_id, for_update=True)
        if user is None:
            raise NotFound
        if user.status == UserStatus.DEACTIVATED:
            raise Conflict(
                "invalid_state",
                "A deactivated user's sign-in can't be reset.",
                current_state=UserStatus.DEACTIVATED,
            )
        target = Target(users.TARGET, user.id)
        earlier = await audit.latest_critical_event(session, action=SIGN_IN_RESET, target=target)
        ended = await member_sessions.revoke_user_sessions(
            session, user.id, reason=member_sessions.RevokedReason.SIGN_IN_RESET
        )
        removed = await identities.delete_identities(session, user.id, pools)
        user, reset_id = await users.start_sign_in_reset(session, user.id)
        await audit.record(
            session,
            action=SIGN_IN_RESET,
            actor=caller.actor(),
            target=target,
            origin=origin,
            details={"sessions_ended": ended, "identities_removed": removed, "reset_id": reset_id},
            security_critical=True,
        )
        await enqueue(session, MEMBER_SIGN_IN_RESET, {"user_id": user.id, "reset_id": reset_id})
        event = await audit.latest_critical_event(session, action=SIGN_IN_RESET, target=target)
    await archive.confirm([e for e in (earlier, event) if e is not None])
    return user


class CachedPoolConnections:
    """The user pools' connection IDs by provider name, looked up once (lookup scope) and kept:
    they don't change while the process runs. Nothing is looked up until a reset needs them."""

    def __init__(self, database: Database, provider_names: Sequence[str]) -> None:
        self.database = database
        self.provider_names = tuple(provider_names)
        self.lookups = 0
        self._ids: tuple[UUID, ...] | None = None

    async def __call__(self) -> Sequence[UUID]:
        if self._ids is None:
            self.lookups += 1
            found: list[UUID] = []
            async with self.database.transaction(Scope.lookup()) as session:
                for name in self.provider_names:
                    connection = await identities.find_connection(session, name)
                    if connection is not None and connection.tenant_id is None:
                        found.append(connection.id)
            if not found:
                return ()  # not seeded yet: look again next time
            self._ids = tuple(found)
        return self._ids
