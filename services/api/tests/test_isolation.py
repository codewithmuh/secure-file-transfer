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
from sft.data import (
    audit,
    files,
    findings,
    idempotency,
    member_sessions,
    suppressions,
    transfers,
    usage,
)
from sft.data import tenants as tenant_data
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
from sft.data.models import (
    ActorType,
    FileState,
    InspectionState,
    ProcessedMessage,
    Role,
    ScanDetail,
    ScanEngine,
    SuppressionReason,
    TransferState,
)
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


# ---- transfers, files and storage usage (#114) ----
# The API is the only role that changes drafts and files.

API_TENANT = {API: [TENANT]}


@cases.add(scopes=API_TENANT)
async def get_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.get_transfer(session, tenants.theirs.rows["transfer"], lock=True)


@cases.add(scopes=API_TENANT)
async def list_another_tenants_recipients(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.list_recipients(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=API_TENANT)
async def add_recipients_to_another_tenants_transfer(
    session: AsyncSession, tenants: Tenants
) -> object:
    recipient = transfers.NewRecipient(uuid.uuid4(), "x@example.test", "en")
    return await transfers.insert_recipients(session, tenants.theirs.rows["transfer"], [recipient])


@cases.add(scopes=API_TENANT)
async def touch_another_tenants_draft(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.touch_draft(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=API_TENANT)
async def get_another_tenants_file(session: AsyncSession, tenants: Tenants) -> object:
    return await files.get_file(session, tenants.theirs.rows["file"])


@cases.add(scopes=API_TENANT)
async def list_another_tenants_files(session: AsyncSession, tenants: Tenants) -> object:
    return await files.list_transfer_files(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=API_TENANT)
async def count_another_tenants_files(session: AsyncSession, tenants: Tenants) -> object:
    return await files.counted_totals(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=API_TENANT)
async def add_a_file_to_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    return await files.insert_file(
        session,
        file_id=uuid.uuid4(),
        transfer_id=tenants.theirs.rows["transfer"],
        display_name_ct=b"x",
        content_type="text/plain",
        declared_size=1,
        storage_class="standard",
        s3_upload_id="isolation",
        part_size=5_242_880,
        part_count=1,
    )


@cases.add(scopes=API_TENANT)
async def touch_another_tenants_parts(session: AsyncSession, tenants: Tenants) -> object:
    return await files.touch_parts(session, tenants.theirs.rows["file"])


@cases.add(scopes=API_TENANT)
async def start_another_tenants_completion(session: AsyncSession, tenants: Tenants) -> object:
    return await files.start_completion(session, tenants.theirs.rows["file"])


@cases.add(scopes=API_TENANT)
async def resume_another_tenants_upload(session: AsyncSession, tenants: Tenants) -> object:
    return await files.resume_uploading(session, tenants.theirs.rows["completing_file"])


@cases.add(scopes=API_TENANT)
async def mark_another_tenants_file_scanning(session: AsyncSession, tenants: Tenants) -> object:
    return await files.mark_scanning(
        session,
        tenants.theirs.rows["completing_file"],
        actual_size=10,
        s3_version_id="isolation",
        scan_deadline=datetime.now(UTC),
    )


@cases.add(scopes=API_TENANT)
async def reject_another_tenants_file(session: AsyncSession, tenants: Tenants) -> object:
    return await files.reject_file(session, tenants.theirs.rows["completing_file"])


@cases.add(scopes=API_TENANT)
async def remove_another_tenants_file(session: AsyncSession, tenants: Tenants) -> object:
    return await files.remove_file(session, tenants.theirs.rows["file"])


# Usage is the scope's tenant's own row: these must neither read nor change theirs.
@cases.add(scopes=API_TENANT)
async def reserve_storage_leaves_others_alone(session: AsyncSession, tenants: Tenants) -> object:
    await usage.reserve_storage(session, 5, quota=100)
    return None


@cases.add(scopes=API_TENANT)
async def release_storage_leaves_others_alone(session: AsyncSession, tenants: Tenants) -> object:
    await usage.release_storage(session, 5)
    return None


@cases.add(scopes=API_TENANT)
async def reserved_bytes_are_the_scopes_own(session: AsyncSession, tenants: Tenants) -> object:
    return await usage.reserved_bytes(session)


# ---- sending, the evaluation and the tenant's policy (#174) ----
# The evaluation runs as the API, the scan worker and the lifecycle jobs (data model 3.2).

EVALUATORS = {API: [TENANT], SCAN: [TENANT], JOBS: [TENANT]}


@cases.add(scopes=API_TENANT)
async def list_another_tenants_transfers(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.list_transfers(
        session,
        created_by=None,
        states=[TransferState.EXPIRED, TransferState.DRAFT],
        limit=100,
        now=datetime.now(UTC),
    )


@cases.add(scopes=EVALUATORS)
async def lock_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.lock_for_evaluation(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=EVALUATORS)
async def send_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.change_state(
        session,
        tenants.theirs.rows["transfer"],
        from_states=(TransferState.DRAFT,),
        to=TransferState.CANCELLED,
    )


@cases.add(scopes=EVALUATORS)
async def list_another_tenants_recipient_ids(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.recipient_ids(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=EVALUATORS)
async def queue_another_tenants_recipients(session: AsyncSession, tenants: Tenants) -> object:
    return await transfers.queue_recipients(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=EVALUATORS)
async def count_downloads_for_another_tenant(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return await transfers.insert_download_counters(
        session,
        recipient_ids=[theirs["recipient"]],
        file_ids=[theirs["file"]],
        download_limit=1,
    )


@cases.add(scopes=EVALUATORS)
async def another_tenants_counted_files(session: AsyncSession, tenants: Tenants) -> object:
    return await files.counted_states(session, tenants.theirs.rows["transfer"])


@cases.add(scopes=API_TENANT)
async def cancel_another_tenants_files(session: AsyncSession, tenants: Tenants) -> object:
    return await files.cancel_files(session, tenants.theirs.rows["transfer"])


@cases.add(scopes={API: [TENANT], SCAN: [TENANT]})
async def read_the_scopes_own_policy(session: AsyncSession, tenants: Tenants) -> object:
    if session.info.get("role") == SCAN:
        return await tenant_data.unscannable_policy(session)
    return await tenant_data.get_policy(session)


@cases.add(scopes=API_TENANT)
async def change_the_scopes_own_policy(session: AsyncSession, tenants: Tenants) -> object:
    policy = await tenant_data.update_policy(session, received_file_retention_days=7)
    await audit.record(session, action="tenant_policy.updated", actor=ADMIN)
    return policy


@cases.add(scopes=API_TENANT)
async def look_up_another_tenants_suppression(session: AsyncSession, tenants: Tenants) -> object:
    return await suppressions.suppressed(session, [f"eiso:{tenants.theirs.marker}"])


@cases.add(scopes={NOTIFY: [TENANT]})
async def suppress_for_no_other_tenant(session: AsyncSession, tenants: Tenants) -> object:
    # Its pseudonym's entry is theirs; the scope's tenant gets an entry of its own.
    entry = await suppressions.add_suppression(
        session,
        pseudonym=f"eiso:{tenants.theirs.marker}",
        key_id="iso",
        reason=SuppressionReason.HARD_BOUNCE,
    )
    await audit.record(session, action="email_suppression.added", actor=Actor(ActorType.SYSTEM))
    return entry


# ---- scans and inspections (#175, #176) ----


@cases.add(scopes={SCAN: [TENANT], JOBS: [TENANT]})
async def read_another_tenants_scan_target(session: AsyncSession, tenants: Tenants) -> object:
    return await files.scan_target(session, tenants.theirs.rows["scanning_file"])


@cases.add(scopes={SCAN: [TENANT]})
async def record_another_tenants_scan(session: AsyncSession, tenants: Tenants) -> object:
    return await files.record_scan(
        session,
        tenants.theirs.rows["scanning_file"],
        state=FileState.CLEAN,
        engine=ScanEngine.CLAMAV,
        detail=None,
        attempts=1,
        unscannable_allowed=False,
        inspection_state=InspectionState.INSPECTED,
    )


@cases.add(scopes={SCAN: [TENANT]})
async def add_findings_to_another_tenants_file(session: AsyncSession, tenants: Tenants) -> object:
    found = [findings.Counts("jp_my_number", 0, 0, 1)]
    return await findings.insert_findings(session, tenants.theirs.rows["scanning_file"], found)


@cases.add(scopes=API_TENANT)
async def read_another_tenants_findings(session: AsyncSession, tenants: Tenants) -> object:
    file_id = tenants.theirs.rows["scanning_file"]
    return (
        await findings.file_findings(session, file_id),
        await findings.detectors_by_file(session, [file_id]),
    )


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_overdue_scans(session: AsyncSession, tenants: Tenants) -> object:
    # The sweep's find step reads across tenants in system scope, by design; in tenant scope the
    # policy refuses it before any row.
    return await files.overdue_scans(session, limit=10)


@cases.add(scopes={JOBS: [TENANT]})
async def fail_another_tenants_overdue_scan(session: AsyncSession, tenants: Tenants) -> object:
    return await files.fail_overdue_scan(
        session,
        tenants.theirs.rows["scanning_file"],
        detail=ScanDetail.DEADLINE_PASSED,
        inspection_state=InspectionState.FAILED,
    )


test_isolation = cases.test()
