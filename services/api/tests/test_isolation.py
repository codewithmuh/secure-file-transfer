"""The tenant isolation suite (NFR-12): each data-access function, given the other tenant's IDs.

One case per data-access function, and later per endpoint (delivery plan 2, point 3). The harness
is `isolation.py`; the README's "The isolation suite" says how to add a case.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Tenants
from sft.data import audit, idempotency, member_sessions
from sft.data.access import in_scope
from sft.data.audit import Actor
from sft.data.identities import find_connection, find_identity
from sft.data.member_sessions import (
    create_session,
    get_live_session,
    lookup_session,
    revoke_session,
    revoke_tenant_sessions,
    revoke_user_sessions,
)
from sft.data.models import ActorType, ProcessedMessage, Role
from sft.data.operator_sessions import (
    create_operator_session,
    find_operator_session,
    signature_seen,
)
from sft.data.outbox import (
    Queue,
    Topic,
    claim_due,
    enqueue,
    mark_failed,
    mark_published,
    oldest_unpublished_age,
)
from sft.data.processed import record_processed
from sft.data.roles import API, ARCHIVE, JOBS, NOTIFY, OPERATOR, RELAY, SCAN
from sft.data.scope import ScopeKind
from sft.data.tenants import (
    directory_tenant,
    get_tenant,
    insert_tenant,
    list_directory,
    suspend_tenant,
)
from sft.data.users import (
    accept_invitation,
    change_role,
    create_invitation,
    deactivate_user,
    find_invitation,
    get_user,
    get_user_by_email,
    list_users,
    lock_active_admins,
    set_dlp_approver,
    set_sso_fallback,
)

TENANT, RESOURCE, SYSTEM = ScopeKind.TENANT, ScopeKind.RESOURCE, ScopeKind.SYSTEM
LOOKUP, PLATFORM = ScopeKind.LOOKUP, ScopeKind.PLATFORM

cases = Cases()


@cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
async def get_tenant_of_another_tenant(session: AsyncSession, tenants: Tenants) -> object:
    return await get_tenant(session, tenants.theirs.tenant_id)


# ---- the outbox and processed messages (#51) ----

ISOLATION_TOPIC = Topic("isolation.check", Queue.NOTIFY)

# Every role but the relay, in every scope it opens: none may read or mark outbox rows.
NOT_THE_RELAY = {
    API: [TENANT],
    OPERATOR: [TENANT],
    SCAN: [TENANT],
    NOTIFY: [TENANT],
    JOBS: [SYSTEM, TENANT],
    ARCHIVE: [SYSTEM],
}


@cases.add(scopes={API: [TENANT], OPERATOR: [TENANT], SCAN: [TENANT], JOBS: [TENANT]})
async def enqueue_names_no_other_tenant(session: AsyncSession, tenants: Tenants) -> object:
    # The tenant is the scope's, whatever IDs the payload carries.
    return await enqueue(session, ISOLATION_TOPIC, {"file_id": tenants.theirs.rows["outbox"]})


@cases.add(scopes={SCAN: [TENANT], NOTIFY: [TENANT]})
async def record_another_tenants_message(session: AsyncSession, tenants: Tenants) -> object:
    message_id = str(tenants.theirs.rows["processed_message"])
    return await record_processed(session, consumer="isolation", message_id=message_id)


@cases.add(scopes={SCAN: [TENANT], NOTIFY: [TENANT]})
async def read_processed_messages(session: AsyncSession, tenants: Tenants) -> object:
    query = select(ProcessedMessage.message_id).where(in_scope(ProcessedMessage, session))
    return (await session.scalars(query)).all()


@cases.add(scopes=NOT_THE_RELAY)
async def claim_another_tenants_messages(session: AsyncSession, tenants: Tenants) -> object:
    return await claim_due(session, 10)


@cases.add(scopes=NOT_THE_RELAY)
async def mark_another_tenants_message_published(session: AsyncSession, tenants: Tenants) -> object:
    await mark_published(session, [tenants.theirs.rows["outbox"]])
    return None


@cases.add(scopes=NOT_THE_RELAY)
async def mark_another_tenants_message_failed(session: AsyncSession, tenants: Tenants) -> object:
    await mark_failed(session, {tenants.theirs.rows["outbox"]: ("isolation", 1.0)})
    return None


@cases.add(scopes={**NOT_THE_RELAY, RELAY: [SYSTEM]})
async def outbox_age(session: AsyncSession, tenants: Tenants) -> object:
    return await oldest_unpublished_age(session)


# The relay reads across tenants by design: its claim, in system scope, must change no one's rows.
@cases.add(scopes={RELAY: [SYSTEM]})
async def relay_claims_without_changing_anything(session: AsyncSession, tenants: Tenants) -> object:
    return await claim_due(session, 10)


# ---- users (#112) ----

# Every role granted `users`, in every scope it reads them in.
USER_READERS = {API: [TENANT, RESOURCE], OPERATOR: [TENANT], NOTIFY: [TENANT]}
# Every role that may change users, and the roles that may not (they must be refused too).
USER_WRITERS = {API: [TENANT, RESOURCE], OPERATOR: [TENANT], NOTIFY: [TENANT], SCAN: [TENANT]}
ADMIN = Actor(ActorType.ADMIN, uuid.uuid4())


def their_token_hash(tenants: Tenants) -> bytes:
    # The seed's invitation link is the SHA-256 of this text (isolation.seed_tenant).
    return hashlib.sha256(str(tenants.theirs.rows["invitation"]).encode()).digest()


@cases.add(scopes=USER_READERS)
async def get_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    return await get_user(session, tenants.theirs.rows["user"], for_update=True)


@cases.add(scopes=USER_READERS)
async def get_another_tenants_user_by_email(session: AsyncSession, tenants: Tenants) -> object:
    return await get_user_by_email(session, f"{tenants.theirs.marker}@example.test")


@cases.add(scopes=USER_READERS)
async def list_another_tenants_users(session: AsyncSession, tenants: Tenants) -> object:
    return await list_users(session, limit=100)


@cases.add(scopes={API: [TENANT], OPERATOR: [TENANT]})
async def lock_another_tenants_admins(session: AsyncSession, tenants: Tenants) -> object:
    return await lock_active_admins(session)


@cases.add(scopes=USER_WRITERS)
async def invite_into_no_other_tenant(session: AsyncSession, tenants: Tenants) -> object:
    # The tenant is the scope's; the address is new, so only the scope decides where it lands.
    email = f"new-{uuid.uuid4().hex}@example.test"
    return await create_invitation(session, email=email, role=Role.ADMIN, actor=ADMIN)


@cases.add(scopes={API: [LOOKUP]})
async def find_another_tenants_invitation(session: AsyncSession, tenants: Tenants) -> object:
    # Across tenants by design: the lookup must change nothing.
    return await find_invitation(session, their_token_hash(tenants))


@cases.add(scopes=USER_WRITERS)
async def accept_another_tenants_invitation(session: AsyncSession, tenants: Tenants) -> object:
    return await accept_invitation(
        session, tenants.theirs.rows["user"], actor=ADMIN, token_hash=their_token_hash(tenants)
    )


@cases.add(scopes=USER_WRITERS)
async def promote_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    return await change_role(session, tenants.theirs.rows["user"], Role.ADMIN, actor=ADMIN)


@cases.add(scopes=USER_WRITERS)
async def name_another_tenants_approver(session: AsyncSession, tenants: Tenants) -> object:
    return await set_dlp_approver(session, tenants.theirs.rows["user"], True, actor=ADMIN)


@cases.add(scopes=USER_WRITERS)
async def name_another_tenants_fallback(session: AsyncSession, tenants: Tenants) -> object:
    return await set_sso_fallback(session, tenants.theirs.rows["user"], False, actor=ADMIN)


@cases.add(scopes=USER_WRITERS)
async def deactivate_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    return await deactivate_user(session, tenants.theirs.rows["user"], actor=ADMIN)


# ---- the operator API (#111) ----


@cases.add(scopes={OPERATOR: [TENANT]})
async def create_a_tenant_over_mine(session: AsyncSession, tenants: Tenants) -> object:
    # The new tenant's ID is the scope's, so the most it can reach is mine, which exists: nothing.
    return await insert_tenant(
        session, name="isolation", recovery_contact="isolation", default_locale="en"
    )


@cases.add(scopes={OPERATOR: [TENANT]})
async def suspend_mine_not_theirs(session: AsyncSession, tenants: Tenants) -> object:
    suspended = await suspend_tenant(session)
    # As the service does: the change commits only with its audit event (audit_required).
    await audit.record(session, action="tenant.suspended", actor=Actor(ActorType.SYSTEM))
    return suspended


# The directory reads tenant rows across tenants by design, and changes nothing. In every other
# scope, and for every other role, it is refused.
@cases.add(scopes={OPERATOR: [PLATFORM, TENANT], API: [TENANT, RESOURCE]}, across=[PLATFORM])
async def read_the_directory(session: AsyncSession, tenants: Tenants) -> object:
    return [
        await directory_tenant(session, tenants.theirs.tenant_id),
        await list_directory(session, limit=100),
    ]


@cases.add(scopes={OPERATOR: [PLATFORM], API: [PLATFORM]})
async def operator_sessions_hold_no_tenant_rows(session: AsyncSession, tenants: Tenants) -> object:
    signature = secrets.token_bytes(32)
    created = await create_operator_session(
        session,
        token_hash=secrets.token_bytes(32),
        signature_hash=signature,
        aws_account_id="111111111111",
        operator_name="isolation",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
    )
    return [
        created,
        await signature_seen(session, signature),
        await find_operator_session(session, secrets.token_bytes(32)),
    ]


# ---- member sign-in (#113) ----

SESSION_WRITERS = {API: [TENANT, RESOURCE], OPERATOR: [TENANT], NOTIFY: [TENANT], SCAN: [TENANT]}


@cases.add(scopes={API: [LOOKUP]})
async def find_another_tenants_connection_and_identity(
    session: AsyncSession, tenants: Tenants
) -> object:
    # Across tenants by design: the lookups must change nothing.
    theirs = tenants.theirs
    connection = await find_connection(session, theirs.marker)
    return [connection, await find_identity(session, theirs.rows["connection"], theirs.marker)]


@cases.add(scopes={API: [LOOKUP]})
async def find_another_tenants_session(session: AsyncSession, tenants: Tenants) -> object:
    return await lookup_session(session, str(tenants.theirs.rows["session_token"]))


@cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
async def read_another_tenants_session(session: AsyncSession, tenants: Tenants) -> object:
    their_session = tenants.theirs.rows["session"]
    return [
        await get_live_session(session, their_session),
        await member_sessions.expires_at(session, their_session),
    ]


@cases.add(scopes=SESSION_WRITERS)
async def create_a_session_for_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs
    created = await create_session(
        session,
        user_id=theirs.rows["user"],
        identity_id=theirs.rows["identity"],
        auth_method="sso",
        auth_time=datetime.now(UTC),
        created_ip=None,
        user_agent=None,
    )
    await audit.record(session, action="member.signed_in", actor=ADMIN)
    return created


@cases.add(scopes=SESSION_WRITERS)
async def revoke_another_tenants_sessions(session: AsyncSession, tenants: Tenants) -> object:
    reason = member_sessions.RevokedReason.SIGNED_OUT_BY_ADMIN
    ended = [
        await revoke_session(session, tenants.theirs.rows["session"], reason=reason),
        await revoke_user_sessions(session, tenants.theirs.rows["user"], reason=reason),
        await revoke_tenant_sessions(session, reason=reason),
    ]
    await audit.record(session, action="user.signed_out", actor=ADMIN)
    return ended


# ---- idempotency keys (#144) ----

# Every role but the API and the jobs: none may reach the keys at all.
NOT_THE_KEY_ROLES = {OPERATOR: [TENANT], SCAN: [TENANT], NOTIFY: [TENANT]}


@cases.add(scopes={API: [TENANT, RESOURCE], **NOT_THE_KEY_ROLES})
async def read_another_tenants_key(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    return [
        await idempotency.find(session, "member", theirs.rows["user"], theirs.marker),
        # The lock names the scope's tenant, so theirs is never held here.
        await idempotency.lock(session, "member", theirs.rows["user"], theirs.marker),
    ]


@cases.add(scopes={API: [TENANT, RESOURCE], **NOT_THE_KEY_ROLES})
async def overwrite_another_tenants_key(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    return [
        await idempotency.save(
            session,
            "member",
            theirs.rows["user"],
            key,
            fingerprint=secrets.token_bytes(32),
            status=201,
            resource_type="user",
            resource_id=theirs.rows["user"],
        )
        for key in (theirs.marker, f"{theirs.marker}-old")
    ]


# The job finds across tenants in system scope by design, and changes nothing there.
@cases.add(scopes={JOBS: [SYSTEM], **NOT_THE_KEY_ROLES})
async def find_tenants_with_expired_keys(session: AsyncSession, tenants: Tenants) -> object:
    return await idempotency.tenants_with_expired(session)


@cases.add(scopes={JOBS: [TENANT], API: [TENANT], **NOT_THE_KEY_ROLES})
async def delete_another_tenants_expired_keys(session: AsyncSession, tenants: Tenants) -> object:
    return await idempotency.delete_expired(session)


test_isolation = cases.test()
