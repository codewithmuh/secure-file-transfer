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

Not here yet, each with its issue: a role change and a deactivation also end the user's sessions
(#113's member sessions), and a demotion or a deactivation revokes the user's API keys (M5); both
go in the same transaction as the change. The admins' emails about role and approver changes come
with the notification worker. Security-critical records reach the archive with the audit archive
job.
"""

from __future__ import annotations

import base64
import binascii
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
from sft.data import users
from sft.data.audit import Origin
from sft.data.database import Database
from sft.data.models import Role, User, UserStatus
from sft.data.scope import Scope
from sft.service.caller import Caller
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import INVITE_USER, KeyType

MAX_PAGE: Final = users.MAX_PAGE

INVITE_LIMITS: Final = tuple(lim for lim in INVITE_USER if KeyType.TENANT_EMAIL not in lim.keys)
"""`INVITE_USER` without the per-address cap, which needs the `email-hmac` keyring the API doesn't
load yet. Until a re-invitation exists, an address gets one invitation per tenant anyway
(`409 user_exists`)."""


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
    origin: Origin,
    now: datetime,
) -> User:
    """`inviteUser`: a new `invited` user, its audit event and its invitation email.

    The invitation limits (abuse and rate limits 2.2, G) count only an invitation that is made:
    after `authorize`, so a member can't use up their tenant's invitations, and after the insert,
    so a `409 user_exists` uses none. A refusal raises inside the transaction, which then writes
    nothing. Only a commit that fails after the count (a database outage) costs one.
    """
    authorize(caller, "inviteUser", now=now)
    try:
        async with database.transaction(_tenant_scope(caller)) as session:
            user = await users.create_invitation(
                session, email=email, role=role, actor=caller.actor(), origin=origin
            )
            await limiter.check(INVITE_LIMITS, caller.rate_limit_keys())
            return user
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


async def _change(
    database: Database,
    caller: Caller,
    user_id: UUID,
    *,
    at_stake: Callable[[User], bool],
    apply: Callable[[AsyncSession, User, Sequence[UUID]], Awaitable[User]],
) -> User:
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
    origin: Origin,
    now: datetime,
) -> User:
    """`updateUser`: the role, the fallback admin flag and the DLP approver flag."""
    authorize(caller, "updateUser", now=now)
    actor = caller.actor()

    def demotes_an_admin(user: User) -> bool:
        return role is Role.MEMBER and _active_admin(user)

    async def apply(session: AsyncSession, user: User, admins: Sequence[UUID]) -> User:
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
            # Here every session of the user ends, once member sessions exist (#113), and a
            # demotion revokes the keys they own (M5), in this transaction.
        if dlp_approver is not None and dlp_approver != user.dlp_approver:
            user = await users.set_dlp_approver(
                session, user.id, dlp_approver, actor=actor, origin=origin
            )
        if sso_fallback is not None and sso_fallback != user.sso_fallback:
            user = await users.set_sso_fallback(
                session, user.id, sso_fallback, actor=actor, origin=origin
            )
        return user

    return await _change(database, caller, user_id, at_stake=demotes_an_admin, apply=apply)


async def deactivate_user(
    database: Database, caller: Caller, user_id: UUID, *, origin: Origin, now: datetime
) -> User:
    """`deactivateUser`: the user can't sign in any more; a retry returns the same user."""
    authorize(caller, "deactivateUser", now=now)

    async def apply(session: AsyncSession, user: User, admins: Sequence[UUID]) -> User:
        if user.status == UserStatus.DEACTIVATED:
            return user
        if _active_admin(user) and list(admins) == [user.id]:
            raise _last_admin()
        # Here every session of the user ends (#113) and every key they own is revoked (M5), in
        # this transaction.
        return await users.deactivate_user(session, user.id, actor=caller.actor(), origin=origin)

    return await _change(database, caller, user_id, at_stake=_active_admin, apply=apply)
