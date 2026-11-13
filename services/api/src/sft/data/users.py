"""Data access for `users`: members, admins and their invitations (data model 2.1, FR-22).

A user belongs to one tenant, with one role (`admin` or `member`) and one status (`invited` until
their first sign-in, then `active`, or `deactivated`). The invitation lives on the user's row:
`invitation_token_hash`, the SHA-256 of a one-time invitation link, and when it stops working
(authentication and authorization 2.5). The notification worker mints it for a tenant with an
active SSO connection (`issue_invitation_link`, #273). A local member gets no link; their first
sign-in activates them.

Every function that changes a user writes its audit event in the same transaction (FR-27), and the
database refuses to commit the change otherwise (`audit_required`, revision 0004). The caller says
who acted (`Actor`) and from where (`Origin`). An invitation also writes its outbox message
(`MEMBER_INVITED`), so the email can't be forgotten either.

Like every data-access function, these filter with `in_scope` and write the scope's tenant, so
they never reach another tenant's user. Changes run in tenant scope only: a link session's
resource scope reads no user and changes none. Business rules (who may do what, the last admin,
ending sessions) are the service layer's: `sft.service.members`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data import audit
from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.audit import Actor, Origin, Target
from sft.data.models import Role, User, UserStatus
from sft.data.outbox import MEMBER_INVITED, enqueue
from sft.data.scope import ScopeKind

INVITATION_LIFETIME: Final = timedelta(days=7)
"""How long an invitation link works (authentication and authorization 2.5)."""

TOKEN_HASH_BYTES: Final = 32
"""A SHA-256 digest. Tokens carry 256 random bits, so a plain hash is enough (data model 1)."""

TARGET: Final = "user"
"""The audit target type of every user event."""

MAX_PAGE: Final = 100
"""The most users one page of `listUsers` holds (contract: `limit` 1 to 100). The route, the
service and `list_users` all read it from here."""


class UserExistsError(Exception):
    """The address is already a user of this tenant: `409 user_exists`. Other tenants are never
    checked, so it reveals nothing about them (NFR-12)."""


@dataclass(frozen=True, slots=True)
class InvitationMatch:
    """What the invitation lookup returns: the invited user and their tenant, IDs only."""

    user_id: UUID
    tenant_id: UUID


def normalize_email(email: str) -> str:
    """The form lookups and the unique key use: lowercase (data model 1)."""
    return email.lower()


def _token_hash(token_hash: bytes | None) -> bytes | None:
    if token_hash is not None and len(token_hash) != TOKEN_HASH_BYTES:
        raise ValueError("an invitation token hash is a 32-byte SHA-256 digest")
    return token_hash


# ---- reads ----


async def get_user(
    session: AsyncSession, user_id: UUID, *, for_update: bool = False
) -> User | None:
    """The user, if the session's scope reaches them. `for_update` locks the row and reads it
    again from the database, so a lock after an earlier read sees what other transactions have
    committed meanwhile, not the session's copy."""
    statement = select(User).where(User.id == user_id, in_scope(User, session))
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    user: User | None = await session.scalar(statement)
    return user


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """The user of this tenant with this address, compared in its normalized form."""
    statement = select(User).where(
        User.email_normalized == normalize_email(email), in_scope(User, session)
    )
    user: User | None = await session.scalar(statement)
    return user


async def list_users(
    session: AsyncSession,
    *,
    role: Role | None = None,
    status: UserStatus | None = None,
    dlp_approver: bool | None = None,
    after: UUID | None = None,
    limit: int = 25,
) -> Sequence[User]:
    """A page of `limit` users of the tenant and one more, oldest first, after the user `after`
    (keyset paging). The extra user, when there is one, tells the caller that more follow.

    IDs are UUIDv7, so their order is the order of creation. `limit` is 1 to `MAX_PAGE`.
    """
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError(f"a page holds 1 to {MAX_PAGE} users")
    statement = select(User).where(in_scope(User, session))
    if role is not None:
        statement = statement.where(User.role == Role(role).value)
    if status is not None:
        statement = statement.where(User.status == UserStatus(status).value)
    if dlp_approver is not None:
        statement = statement.where(User.dlp_approver.is_(dlp_approver))
    if after is not None:
        statement = statement.where(User.id > after)
    return (await session.scalars(statement.order_by(User.id).limit(limit + 1))).all()


async def lock_active_admins(session: AsyncSession) -> Sequence[UUID]:
    """The tenant's active admins, locked until the transaction ends.

    Every change that could leave a tenant without an active admin calls this first. Two such
    changes at once then run one after the other, and the second sees the first's result, so
    "keeps one active admin" holds under concurrency.
    """
    statement = (
        select(User.id)
        .where(
            User.role == Role.ADMIN.value,
            User.status == UserStatus.ACTIVE.value,
            in_scope(User, session),
        )
        .order_by(User.id)
        .with_for_update()
    )
    return (await session.scalars(statement)).all()


# ---- invitations ----


async def create_invitation(
    session: AsyncSession,
    *,
    email: str,
    role: Role,
    actor: Actor,
    origin: Origin | None = None,
    token_hash: bytes | None = None,
) -> User:
    """Invite `email` to the scope's tenant as `role`: a new user, `invited`.

    Writes the audit event `user.invited` and the outbox message `MEMBER_INVITED`, whose consumer
    (the notification worker) creates the sign-in and sends the email. `token_hash` is the SHA-256
    of a one-time invitation link, for a tenant that uses SSO; the link works for
    `INVITATION_LIFETIME`. Raises `UserExistsError` if the address is already a user of this
    tenant, whatever their status: an invitation never changes an existing user (authn and authz
    2.5).
    """
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    token_hash = _token_hash(token_hash)
    statement = (
        insert(User)
        .values(
            id=uuid7(),
            tenant_id=tenant_id,
            email=email,
            email_normalized=normalize_email(email),
            role=Role(role).value,
            status=UserStatus.INVITED.value,
            invitation_token_hash=token_hash,
            invitation_expires_at=None if token_hash is None else func.now() + INVITATION_LIFETIME,
        )
        .on_conflict_do_nothing(index_elements=[User.tenant_id, User.email_normalized])
        .returning(User)
    )
    user: User | None = await session.scalar(
        statement, execution_options={"populate_existing": True}
    )
    if user is None:
        raise UserExistsError("the address is already a user of this tenant")
    await audit.record(
        session,
        action="user.invited",
        actor=actor,
        target=Target(TARGET, user.id),
        origin=origin,
        details={"role": Role(role)},
    )
    await enqueue(session, MEMBER_INVITED, {"user_id": user.id})
    return user


async def find_invitation(session: AsyncSession, token_hash: bytes) -> InvitationMatch | None:
    """The credential lookup for `startInvitationSignIn` (data model 4.2): the user a live
    invitation belongs to, and their tenant. Only in lookup scope; continue in the tenant's."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text("SELECT user_id, owner_tenant_id FROM lookup_invitation(:hash)"),
            {"hash": _token_hash(token_hash)},
        )
    ).first()
    return None if row is None else InvitationMatch(user_id=row[0], tenant_id=row[1])


async def accept_invitation(
    session: AsyncSession,
    user_id: UUID,
    *,
    actor: Actor,
    origin: Origin | None = None,
    token_hash: bytes | None = None,
) -> User:
    """Activate an invited user at their first sign-in, and consume their invitation link.

    With `token_hash` (an SSO invitation), the user's live invitation must have that hash. Raises
    `NotFoundError` if the scope doesn't reach the user, they aren't `invited`, or the link is
    wrong or expired: the caller can't tell which. Writes `user.activated`.
    """
    conditions = [
        User.id == user_id,
        User.status == UserStatus.INVITED.value,
        in_scope(User, session),
    ]
    if token_hash is not None:
        conditions += [
            User.invitation_token_hash == _token_hash(token_hash),
            User.invitation_expires_at > func.now(),
        ]
    user = await _update_one(
        session,
        conditions,
        status=UserStatus.ACTIVE.value,
        invitation_token_hash=None,
        invitation_expires_at=None,
    )
    await audit.record(
        session, action="user.activated", actor=actor, target=Target(TARGET, user.id), origin=origin
    )
    return user


async def issue_invitation_link(
    session: AsyncSession, user_id: UUID, token_hash: bytes
) -> datetime | None:
    """A new one-time invitation link for an invited user of an SSO tenant (authn and authz 2.5,
    #273): its SHA-256, working for `INVITATION_LIFETIME` from now, replacing any earlier link.
    When it stops working; None if the scope doesn't reach the user or they aren't `invited` any
    more. The notification worker's (revision 0042); the caller writes the audit event in the same
    transaction."""
    require_scope(session, ScopeKind.TENANT)
    expires_at: datetime | None = await session.scalar(
        update(User)
        .where(
            User.id == user_id,
            User.status == UserStatus.INVITED.value,
            in_scope(User, session),
        )
        .values(
            invitation_token_hash=_token_hash(token_hash),
            invitation_expires_at=func.now() + INVITATION_LIFETIME,
        )
        .returning(User.invitation_expires_at)
        .execution_options(synchronize_session=False)
    )
    return expires_at


# ---- changes ----


async def change_role(
    session: AsyncSession,
    user_id: UUID,
    role: Role,
    *,
    actor: Actor,
    origin: Origin | None = None,
) -> User:
    """Give a user another role; a demotion to `member` also clears `sso_fallback`.

    Writes `user.role_changed`. A demotion is a security-critical record, like a deactivation
    (contract, `updateUser`). Raises `NotFoundError` if the scope doesn't reach the user.
    """
    role = Role(role)
    values: dict[str, object] = {"role": role.value}
    if role is Role.MEMBER:
        values["sso_fallback"] = False
    user = await _update_one(session, [User.id == user_id, in_scope(User, session)], **values)
    await audit.record(
        session,
        action="user.role_changed",
        actor=actor,
        target=Target(TARGET, user.id),
        origin=origin,
        security_critical=role is Role.MEMBER,
        details={"role": role},
    )
    return user


async def start_sign_in_reset(session: AsyncSession, user_id: UUID) -> tuple[User, UUID]:
    """Give the user a new pending sign-in reset (#197, revision 0016): its ID supersedes any reset
    still being processed. The caller writes the reset's audit event and its outbox message with
    the ID, in the same transaction."""
    reset_id = uuid7()
    user = await _update_one(
        session, [User.id == user_id, in_scope(User, session)], sign_in_reset_id=reset_id
    )
    return user, reset_id


async def set_dlp_approver(
    session: AsyncSession,
    user_id: UUID,
    dlp_approver: bool,
    *,
    actor: Actor,
    origin: Origin | None = None,
) -> User:
    """Name a user a DLP approver, or take it away (FR-43). Writes `user.dlp_approver_changed`."""
    user = await _update_one(
        session, [User.id == user_id, in_scope(User, session)], dlp_approver=bool(dlp_approver)
    )
    await audit.record(
        session,
        action="user.dlp_approver_changed",
        actor=actor,
        target=Target(TARGET, user.id),
        origin=origin,
        details={"dlp_approver": bool(dlp_approver)},
    )
    return user


async def set_sso_fallback(
    session: AsyncSession,
    user_id: UUID,
    sso_fallback: bool,
    *,
    actor: Actor,
    origin: Origin | None = None,
) -> User:
    """Name an admin an SSO fallback admin, or take it away (authn and authz 2.5). The database
    refuses it for a member. Writes `user.sso_fallback_changed`."""
    user = await _update_one(
        session, [User.id == user_id, in_scope(User, session)], sso_fallback=bool(sso_fallback)
    )
    await audit.record(
        session,
        action="user.sso_fallback_changed",
        actor=actor,
        target=Target(TARGET, user.id),
        origin=origin,
        details={"sso_fallback": bool(sso_fallback)},
    )
    return user


async def deactivate_user(
    session: AsyncSession,
    user_id: UUID,
    *,
    actor: Actor,
    origin: Origin | None = None,
) -> User:
    """Deactivate a user, void any invitation link they have, and clear `dlp_approver` and
    `sso_fallback`: a deactivated user approves nothing and is no fallback admin, so neither flag
    outlives the user (data model 2.1). A security-critical record, `user.deactivated`. Raises
    `NotFoundError` if the scope doesn't reach the user."""
    user = await _update_one(
        session,
        [User.id == user_id, in_scope(User, session)],
        status=UserStatus.DEACTIVATED.value,
        invitation_token_hash=None,
        invitation_expires_at=None,
        dlp_approver=False,
        sso_fallback=False,
    )
    await audit.record(
        session,
        action="user.deactivated",
        actor=actor,
        target=Target(TARGET, user.id),
        origin=origin,
        security_critical=True,
    )
    return user


async def _update_one(
    session: AsyncSession, conditions: Sequence[object], **values: object
) -> User:
    # Users change in a tenant's scope only, never through a link session's resource scope.
    require_scope(session, ScopeKind.TENANT)
    statement = update(User).where(*conditions).values(**values).returning(User)  # type: ignore[arg-type]
    user: User | None = await session.scalar(
        statement, execution_options={"populate_existing": True, "synchronize_session": False}
    )
    if user is None:
        raise NotFoundError("no such user in this scope")
    return user


async def invited_everywhere(
    session: AsyncSession, *, after: UUID | None = None, limit: int = MAX_PAGE
) -> Sequence[tuple[UUID, UUID]]:
    """`(tenant ID, user ID)` of up to `limit` users still `invited`, in every tenant, after the
    user `after`, oldest first: the notification worker's invitation backlog (#193, revision
    0017). System scope, read only."""
    require_scope(session, ScopeKind.SYSTEM)
    statement = select(User.tenant_id, User.id).where(User.status == UserStatus.INVITED.value)
    if after is not None:
        statement = statement.where(User.id > after)
    rows = await session.execute(statement.order_by(User.id).limit(limit))
    return [(row[0], row[1]) for row in rows]


async def active_everywhere(
    session: AsyncSession, *, after: UUID | None = None, limit: int = MAX_PAGE
) -> Sequence[tuple[UUID, UUID]]:
    """`(tenant ID, user ID)` of up to `limit` active users, in every tenant, after the user
    `after`, oldest first: the standby enrolment after a regional failover (#258, authn and authz
    2.6), as the notification worker, through revision 0017's `notify_find` policy. System scope,
    read only."""
    require_scope(session, ScopeKind.SYSTEM)
    statement = select(User.tenant_id, User.id).where(User.status == UserStatus.ACTIVE.value)
    if after is not None:
        statement = statement.where(User.id > after)
    rows = await session.execute(statement.order_by(User.id).limit(limit))
    return [(row[0], row[1]) for row in rows]


async def invite_again(session: AsyncSession, user_id: UUID) -> UUID:
    """A new `member.invited` message for a user left `invited` (#193): the notifier invites
    them through the pool as it does any new member. In the user's tenant scope."""
    require_scope(session, ScopeKind.TENANT)
    return await enqueue(session, MEMBER_INVITED, {"user_id": user_id})
