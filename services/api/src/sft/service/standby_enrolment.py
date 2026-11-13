"""The standby enrolment after a regional failover (#258; authn and authz 2.6; architecture 7,
step 6; docs/operations/disaster-recovery.md 5, gap 6).

Cognito can't export password hashes or MFA factors, so a member who signs in with a password
(a local member) can't sign in through the standby pool in Osaka until they enrol there again. SSO
members need nothing: every tenant's provider exists in both pools under the same name. After the
recovery job's replay, so that no member a replayed deactivation removed is enrolled, the failover
runbook runs `python -m sft.workers.standby_enrolment` once, as the notification worker (its
service account, its IAM role `sft-<env>-notify` with Cognito's admin API on its region's pool, its
database role `sft_notify` and its mail settings). For every **active local member** of an active
tenant, one at a time:

1. **The pool user**: `AdminCreateUser` in this region's pool with `MessageAction=SUPPRESS`, our
   user ID as the username and a new temporary password (`sft.runtime.cognito`), made for the
   enrolment `failover`. A user an earlier run made is taken over, with the new password.
2. **The re-enrolment invitation** (`member_reenrolment`, in the tenant's language): the temporary
   password, which the pool makes them replace at the first sign-in, with a new MFA factor.
3. **The identity and its audit event**, in one transaction in the member's tenant: the pool's
   `sub` for the user on this pool's connection, and `email.sent` naming the user and the email
   type, as an invitation records it. Tenant admins see each re-enrolment in their log.

A local member is an active user with an identity on another user pool (the lost region's); one
with an identity on this pool already is done, so a second run sends nothing to them. A user
whose address another tenant's local member signs in with here can't be created (`AliasExists`):
counted and left, as the original pool left them. The job sends the emails itself, rather than
through the outbox, because nothing else needs to see them and it holds the password only while it
runs; it runs after the replay, while the workers are still held, so no other email waits on it.

The address and the password are never logged; the report is counts.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Final
from uuid import UUID

from sft.data import audit, identities, tenants, users
from sft.data.audit import Actor, ActorType, Target
from sft.data.database import Database
from sft.data.mail import OutgoingEmail
from sft.data.models import UserStatus
from sft.data.scope import Scope
from sft.service.email import EmailRenderer
from sft.service.email.catalog import EmailType, Locale, MemberReenrolment
from sft.service.notifications import SystemActor
from sft.service.user_pool import (
    TEMPORARY_PASSWORD_DAYS,
    PoolUserExistsError,
    UserPool,
    new_temporary_password,
)

log = logging.getLogger(__name__)

ENROLMENT: Final = "failover"
"""The enrolment a standby pool user is made for (`custom:enrolment_id`)."""
PAGE: Final = 200

Send = Callable[[OutgoingEmail], Awaitable[str]]


class Result(StrEnum):
    ENROLLED = "enrolled"
    ALREADY = "already_enrolled"
    NOT_LOCAL = "not_local"
    """An SSO member, or one with no pool identity: nothing to do."""
    INACTIVE = "inactive"
    """Deactivated since the listing, or their tenant isn't active."""
    ADDRESS_IN_USE = "address_in_use"


class PoolConnectionMissingError(RuntimeError):
    """This pool has no active connection row: nothing can be recorded, so nothing is created."""


async def enrol_member(
    database: Database,
    *,
    tenant_id: UUID,
    user_id: UUID,
    pool: UserPool,
    send: Send,
    renderer: EmailRenderer,
) -> Result:
    """Enrol one member in this region's pool (module docstring), or say why not."""
    scope = Scope.tenant(tenant_id)
    async with database.transaction(scope) as session:
        user = await users.get_user(session, user_id)
        sender = await tenants.sender(session)
        if user is None or user.status != UserStatus.ACTIVE.value:
            return Result.INACTIVE
        if sender is None or not sender.active:
            return Result.INACTIVE
        connection = await identities.pool_connection(session, pool.provider_name)
        if connection is None or connection.status != "active":
            raise PoolConnectionMissingError(pool.provider_name)
        if await identities.has_identity(session, user_id=user_id, connection_id=connection.id):
            return Result.ALREADY
        if not await identities.has_other_pool_identity(
            session, user_id=user_id, connection_id=connection.id
        ):
            return Result.NOT_LOCAL
        address, locale, tenant_name = user.email, Locale(sender.default_locale), sender.name
    password = new_temporary_password()
    try:
        subject = await pool.create_user(
            username=str(user_id),
            email=address,
            tenant_id=tenant_id,
            temporary_password=password,
            enrolment=ENROLMENT,
        )
    except PoolUserExistsError:
        return Result.ADDRESS_IN_USE
    email = MemberReenrolment(
        tenant_name=tenant_name, temporary_password=password, valid_days=TEMPORARY_PASSWORD_DAYS
    )
    await send(renderer.compose(email, locale, to=address, tenant_id=tenant_id))
    async with database.transaction(scope) as session:
        await identities.record_identity(
            session, user_id=user_id, connection_id=connection.id, subject=subject
        )
        await audit.record(
            session,
            action="email.sent",
            actor=Actor(ActorType.SYSTEM),
            target=Target(users.TARGET, user_id),
            details={
                "system_actor": SystemActor.NOTIFICATION_WORKER,
                "email_type": EmailType.MEMBER_REENROLMENT,
            },
        )
    return Result.ENROLLED


async def enrol_standby(
    database: Database, *, pool: UserPool, send: Send, renderer: EmailRenderer
) -> Counter[Result]:
    """Every active local member, enrolled in this region's pool (module docstring); how many of
    each result. A failure of the pool or the mail provider stops the run: running it again is
    safe, and resumes after the members already enrolled."""
    results: Counter[Result] = Counter()
    after: UUID | None = None
    while True:
        async with database.transaction(Scope.system()) as session:
            page = await users.active_everywhere(session, after=after, limit=PAGE)
        if not page:
            break
        for tenant_id, user_id in page:
            results[
                await enrol_member(
                    database,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    pool=pool,
                    send=send,
                    renderer=renderer,
                )
            ] += 1
        after = page[-1][1]
    log.info("standby enrolment done", extra={"results": {r.value: n for r, n in results.items()}})
    return results
