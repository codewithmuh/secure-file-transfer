"""The tenant isolation suite (NFR-12): each data-access function, given the other tenant's IDs.

One case per data-access function, and later per endpoint (delivery plan 2, point 3). The harness
is `isolation.py`; the README's "The isolation suite" says how to add a case.
"""

import contextlib
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Seeded, Tenants
from sft.data import (
    api_keys,
    archive_cursor,
    audit,
    audit_reads,
    codes,
    data_keys,
    dlp_approvals,
    dlp_decisions,
    dlp_policy,
    dlp_reports,
    downloads,
    files,
    findings,
    idempotency,
    link_sessions,
    link_subjects,
    member_sessions,
    notice_windows,
    purge,
    recipients,
    sso,
    suppressions,
    transfers,
    upload_requests,
    usage,
)
from sft.data import tenants as tenant_data
from sft.data.access import NotFoundError, ScopeNotAllowedError, in_scope
from sft.data.audit import Actor
from sft.data.dlp_policy import DetectorFields, RuleFields, detector_ref
from sft.data.identities import (
    delete_identities,
    find_connection,
    find_identity,
    pool_connection,
    record_identity,
)
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
    ApiKeyRevokedReason,
    ApprovalDecisionKind,
    ApprovalState,
    DeliveryState,
    DlpDirection,
    FileState,
    InspectionState,
    NoticeKind,
    ProcessedMessage,
    Role,
    ScanDetail,
    ScanEngine,
    SuppressionReason,
    TransferState,
    UploadRequestState,
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
from sft.data.scope import ScopeKind, Subject
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
    issue_invitation_link,
    list_users,
    lock_active_admins,
    set_dlp_approver,
    set_sso_fallback,
    start_sign_in_reset,
)
from sft.service.api_keys import key_hash

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
    return await get_live_session(session, tenants.theirs.rows["session"])


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


# ---- local identities written by the worker, removed by a reset (#197, revision 0016) ----

# The roles granted `user_identities` in a tenant's scope, and roles that must be refused.
IDENTITY_READERS = {API: [TENANT], NOTIFY: [TENANT], OPERATOR: [TENANT], SCAN: [TENANT]}


@cases.add(scopes=IDENTITY_READERS)
async def read_another_tenants_identity_or_provider(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs
    # Their SSO connection is a tenant's provider, never a pool row: nobody reaches it this way.
    return await pool_connection(session, theirs.marker)


@cases.add(scopes=USER_WRITERS)
async def reset_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    started = await start_sign_in_reset(session, tenants.theirs.rows["user"])
    await audit.record(session, action="user.sign_in_reset", actor=ADMIN)
    return started


@cases.add(scopes={API: [TENANT], NOTIFY: [TENANT], OPERATOR: [TENANT]})
async def delete_another_tenants_identity(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    removed = await delete_identities(session, theirs["user"], [theirs["connection"]])
    await audit.record(session, action="user.sign_in_reset", actor=ADMIN)
    return removed


@cases.add(scopes={NOTIFY: [TENANT], API: [TENANT], SCAN: [TENANT]})
async def bind_a_subject_to_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    bound = await record_identity(
        session,
        user_id=theirs["user"],
        connection_id=theirs["connection"],
        subject=f"new-{uuid.uuid4()}",
    )
    await audit.record(session, action="email.sent", actor=Actor(ActorType.SYSTEM))
    return bound


# ---- links, codes and link sessions (#178, #179) ----

NOTIFY_TENANT = {NOTIFY: [TENANT]}


@cases.add(scopes={API: [LOOKUP]})
async def find_another_tenants_link_and_sessions(session: AsyncSession, tenants: Tenants) -> object:
    # The credential lookups read across tenants by design, in lookup scope only: IDs and a
    # status, never a hash; the harness checks that nothing changed.
    return (
        await recipients.find_by_token(session, str(tenants.theirs.rows["link_token"])),
        await link_sessions.lookup(session, [str(tenants.theirs.rows["link_session_token"])]),
    )


@cases.add(scopes=NOTIFY_TENANT)
async def read_another_tenants_link_target(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return (
        await recipients.link_target(session, theirs["recipient"], lock=True),
        await transfers.notice(session, theirs["transfer"]),
        await transfers.recipient_ids(session, theirs["transfer"]),
        await tenant_data.sender(session),
    )


@cases.add(scopes=NOTIFY_TENANT)
async def issue_another_tenants_link(session: AsyncSession, tenants: Tenants) -> object:
    recipient_id = tenants.theirs.rows["recipient"]
    issued = await recipients.issue_link(
        session,
        recipient_id,
        key_id="iso",
        issued_at=datetime.now(UTC),
        hashed=hashlib.sha256(b"x").digest(),
        replace=True,
    )
    await recipients.set_delivery(session, recipient_id, DeliveryState.SENT, notified=True)
    await audit.record(session, action="recipient.link_issued", actor=Actor(ActorType.SYSTEM))
    return issued


@cases.add(scopes=NOTIFY_TENANT)
async def make_a_code_for_another_tenants_recipient(
    session: AsyncSession, tenants: Tenants
) -> object:
    made = await codes.create(
        session,
        tenants.theirs.rows["recipient"],
        code_id=uuid.uuid4(),
        code_hmac=hashlib.sha256(b"c").digest(),
        key_id="iso",
    )
    await audit.record(session, action="verification.code_created", actor=Actor(ActorType.SYSTEM))
    return made


@cases.add(scopes={API: [TENANT, RESOURCE]})
async def read_another_tenants_recipient_and_counters(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    return (
        await recipients.counters(session, theirs["recipient"]),
        await link_sessions.get_live(session, theirs["link_session"]),
        await recipients.link_view(session, theirs["recipient"]),
    )


@cases.add(scopes=API_TENANT)
async def read_another_tenants_statuses_and_codes(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    return (
        await recipients.statuses(session, theirs["transfer"]),
        await codes.newest(session, theirs["recipient"]),
        await codes.why_unusable(session, theirs["code"]),
        await link_sessions.live_for_recipient(session, theirs["recipient"]),
    )


@cases.add(scopes=API_TENANT)
async def check_a_code_of_another_tenants_recipient(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    locked = await recipients.lock_unlocked(session, theirs["recipient"])
    taken = await codes.take_attempt(session, theirs["code"])
    await codes.consume(session, theirs["code"])
    await recipients.mark_verified(session, theirs["recipient"])
    await audit.record(session, action="verification.attempted", actor=Actor(ActorType.SYSTEM))
    return locked, taken, await recipients.count_failure(session, theirs["recipient"])


@cases.add(scopes=API_TENANT)
async def unlock_another_tenants_recipient(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    await recipients.unlock(session, theirs["recipient"], by=tenants.mine.rows["user"])
    await audit.record(session, action="recipient.unlocked", actor=Actor(ActorType.SYSTEM))
    return await recipients.lock_recipient(session, theirs["transfer"], theirs["recipient"])


@cases.add(scopes={API: [TENANT, RESOURCE]})
async def end_another_tenants_link_session(session: AsyncSession, tenants: Tenants) -> object:
    ended = await link_sessions.revoke(session, tenants.theirs.rows["link_session"])
    await audit.record(session, action="link_session.ended", actor=Actor(ActorType.SYSTEM))
    return ended


@cases.add(scopes=API_TENANT)
async def start_a_session_for_another_tenants_recipient(
    session: AsyncSession, tenants: Tenants
) -> object:
    made = await link_sessions.create(session, tenants.theirs.rows["recipient"], ends_by=None)
    await audit.record(session, action="link_session.started", actor=Actor(ActorType.SYSTEM))
    return made


# ---- download grants and revocation (#180) ----

GRANT_USERS = {API: [TENANT, RESOURCE]}


def mine_as_recipient(mine: Seeded) -> Subject:
    return Subject.recipient(mine.rows["recipient"])


@cases.add(scopes=GRANT_USERS, subject=mine_as_recipient)
async def read_another_tenants_grant_and_counter(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return (
        await downloads.get_grant(session, theirs["download_grant"]),
        await downloads.counter(session, theirs["recipient"], theirs["scanning_file"]),
    )


@cases.add(scopes=GRANT_USERS, subject=mine_as_recipient)
async def count_and_grant_another_tenants_download(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    counted = await downloads.count_download(session, theirs["recipient"], theirs["scanning_file"])
    made = await downloads.insert_grant(
        session,
        grant_id=uuid.uuid4(),
        file_id=theirs["scanning_file"],
        s3_version_id="x",
        recipient_id=theirs["recipient"],
        link_session_id=theirs["link_session"],
        size=10,
        ends_by=datetime.now(UTC) + timedelta(hours=1),
    )
    await audit.record(session, action="download.granted", actor=Actor(ActorType.SYSTEM))
    return counted, made


@cases.add(scopes=GRANT_USERS, subject=mine_as_recipient)
async def stream_another_tenants_grant(session: AsyncSession, tenants: Tenants) -> object:
    grant_id = tenants.theirs.rows["download_grant"]
    stream = uuid.uuid4()
    admitted = await downloads.admit(session, grant_id, stream)
    held = await downloads.record_progress(session, grant_id, stream, 5)
    await downloads.mark_archived(session, grant_id)
    return admitted, held


@cases.add(scopes=API_TENANT)
async def revoke_another_tenants_sessions_by_transfer(
    session: AsyncSession, tenants: Tenants
) -> object:
    return await link_sessions.revoke_for_transfer(session, tenants.theirs.rows["transfer"])


# ---- extending the expiry and the first-download notice (#214) ----


@cases.add(scopes=API_TENANT)
async def extend_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows["transfer"]
    later = datetime.now(UTC) + timedelta(days=3)
    moved = (
        await transfers.extend_expiry(session, theirs, later),
        await link_sessions.extend_for_transfer(session, theirs, later),
        await downloads.extend_for_transfer(session, theirs),
    )
    await audit.record(session, action="transfer.expiry_extended", actor=Actor(ActorType.SYSTEM))
    return moved


@cases.add(scopes=GRANT_USERS, subject=mine_as_recipient)
async def claim_another_tenants_first_download(session: AsyncSession, tenants: Tenants) -> object:
    claimed = await transfers.claim_first_download_notice(session, tenants.theirs.rows["transfer"])
    await audit.record(session, action="download.granted", actor=Actor(ActorType.SYSTEM))
    return claimed


# ---- the lifecycle jobs (#181) ----

FAR = datetime.now(UTC) + timedelta(days=36500)
PAST = datetime.now(UTC) - timedelta(days=36500)


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_due_lifecycle_work(session: AsyncSession, tenants: Tenants) -> object:
    # The jobs' find steps read across tenants in system scope, by design; in tenant scope the
    # data layer refuses them before any row.
    return (
        await transfers.due_for_expiry(session, now=FAR, limit=10),
        await transfers.stale_drafts(session, before=FAR, limit=10),
        await files.due_for_deletion(session, now=FAR, limit=10),
        await files.abandoned_uploads(session, before=FAR, limit=10),
        await files.stuck_completions(session, before=FAR, limit=10),
        await files.overdue_deletions(session, before=FAR),
        await files.oldest_due_deletion(session, now=FAR),
        await downloads.unarchived(session, created_before=FAR, limit=10),
    )


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_storage_and_expired_rows(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    key = f"tenants/{theirs.tenant_id}/files/{theirs.rows['file']}"
    return (
        await files.known_keys(session, [key]),
        await files.open_upload_ids(session, [theirs.marker]),
        await codes.tenants_with_expired(session, before=FAR, limit=10),
        await link_sessions.tenants_with_expired(session, before=FAR, limit=10),
        await downloads.tenants_with_expired(session, before=FAR, limit=10),
    )


@cases.add(scopes={JOBS: [TENANT]})
async def act_on_another_tenants_files(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    now = datetime.now(UTC)
    found = (
        await files.mark_deleted(session, theirs["scanning_file"], now=FAR),
        await files.due_now(session, theirs["transfer"], now=now),
        await files.reject_open(session, theirs["file"], now=now),
        await files.resume_open(session, theirs["completing_file"]),
        await files.mark_scanning(
            session,
            theirs["completing_file"],
            actual_size=10,
            s3_version_id="x",
            scan_deadline=now,
        ),
        await transfers.idle_since(session, theirs["transfer"], before=FAR),
    )
    await audit.record(session, action="file.deleted", actor=Actor(ActorType.SYSTEM))
    return found, await files.job_file(session, theirs["file"])


@cases.add(scopes={JOBS: [TENANT]})
async def delete_another_tenants_expired_rows(session: AsyncSession, tenants: Tenants) -> object:
    deleted = (
        await codes.delete_expired(session, before=FAR, limit=10),
        await downloads.delete_expired(session, before=FAR, limit=10),
        await link_sessions.delete_expired(session, before=FAR, limit=10),
    )
    await audit.record(session, action="retention.rows_deleted", actor=Actor(ActorType.SYSTEM))
    return deleted


# ---- the metadata purge (#224) and the audit archive job (#183) ----

# What the purge counts as due: everything that ended before now, so their rows qualify.
PURGE_CUTOFF = datetime.now(UTC) + timedelta(days=1)


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_due_purges(session: AsyncSession, tenants: Tenants) -> object:
    # The purge's finds read across tenants in system scope, by design, and change nothing; in
    # tenant scope the data layer refuses them before any row.
    return (
        await purge.due_transfers(session, cutoff=PURGE_CUTOFF, limit=10),
        await purge.due_upload_requests(session, cutoff=PURGE_CUTOFF, limit=10),
        await purge.backlog(session, cutoff=PURGE_CUTOFF),
    )


@cases.add(scopes={JOBS: [TENANT]})
async def purge_another_tenants_metadata(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    purged = (
        await purge.purge_transfers(session, [theirs["ended_transfer"]], cutoff=PURGE_CUTOFF),
        await purge.purge_upload_requests(session, [theirs["ended_request"]], cutoff=PURGE_CUTOFF),
    )
    await audit.record(session, action="retention.rows_deleted", actor=Actor(ActorType.SYSTEM))
    return purged


@cases.add(scopes={ARCHIVE: [SYSTEM]})
async def read_every_event_for_the_archive(session: AsyncSession, tenants: Tenants) -> object:
    # The archive job reads every tenant's audit events in system scope, by design (data model
    # 2.5); the harness checks it changes no tenant's row. Its cursor has no tenant.
    claimed = await archive_cursor.claim(session, max_rows=10)
    found = [] if claimed is None else await archive_cursor.events(session, claimed)
    return claimed, found, await archive_cursor.unarchived_age(session)


# ---- upload requests (#212) ----


def mine_as_uploader(mine: Seeded) -> Subject:
    return Subject.upload_request(mine.rows["upload_request"])


@cases.add(scopes={API: [LOOKUP]})
async def find_another_tenants_upload_link_and_session(
    session: AsyncSession, tenants: Tenants
) -> object:
    # Lookup scope reads across tenants by design: IDs and a status only.
    theirs = tenants.theirs.rows
    return (
        await link_subjects.find_by_token(session, str(theirs["upload_link_token"])),
        await link_subjects.find_by_token(session, str(theirs["link_token"])),
        await link_sessions.lookup(session, [str(theirs["upload_session_token"])]),
    )


@cases.add(scopes={API: [TENANT, RESOURCE]}, subject=mine_as_uploader)
async def read_another_tenants_upload_request(session: AsyncSession, tenants: Tenants) -> object:
    return await upload_requests.get_request(session, tenants.theirs.rows["upload_request"])


@cases.add(scopes={API: [TENANT, RESOURCE]}, subject=mine_as_uploader)
async def read_another_tenants_uploader_link(session: AsyncSession, tenants: Tenants) -> object:
    return await upload_requests.link_view(session, tenants.theirs.rows["upload_request"])


@cases.add(scopes={API: [TENANT, RESOURCE]}, subject=mine_as_uploader)
async def read_and_end_another_tenants_uploader_session(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows["upload_session"]
    live = await link_sessions.get_live(session, theirs)
    ended = await link_sessions.revoke(session, theirs)
    await audit.record(session, action="link_session.ended", actor=Actor(ActorType.SYSTEM))
    return live, ended


@cases.add(scopes=API_TENANT)
async def list_and_count_another_tenants_upload_requests(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    return (
        await upload_requests.list_requests(
            session, created_by=None, limit=100, now=datetime.now(UTC)
        ),
        await upload_requests.live_session_ids(session, [theirs["upload_request"]]),
        await codes.newest_for(session, Subject.upload_request(theirs["upload_request"])),
    )


@cases.add(scopes=API_TENANT)
async def create_an_upload_request_for_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    # The tenant is the scope's; their user isn't one of its users (a foreign key refusal).
    made = await upload_requests.insert_request(
        session,
        request_id=uuid.uuid4(),
        created_by=tenants.theirs.rows["user"],
        email="x@example.test",
        locale="en",
        message_ct=None,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    await audit.record(session, action="upload_request.created", actor=Actor(ActorType.SYSTEM))
    return made


@cases.add(scopes=API_TENANT)
async def revoke_and_unlock_another_tenants_upload_request(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows["upload_request"]
    changed = (
        await upload_requests.change_state(
            session,
            theirs,
            from_states=(UploadRequestState.OPEN,),
            to=UploadRequestState.REVOKED,
            ended_at=datetime.now(UTC),
        ),
        await link_sessions.revoke_for_upload_request(session, theirs),
    )
    await upload_requests.unlock(session, theirs, by=tenants.mine.rows["user"])
    await audit.record(session, action="upload_request.revoked", actor=Actor(ActorType.SYSTEM))
    return changed


@cases.add(scopes=API_TENANT)
async def check_a_code_of_another_tenants_uploader(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    locked = await upload_requests.lock_unlocked(session, theirs["upload_request"])
    taken = await codes.take_attempt(session, theirs["upload_code"])
    await codes.consume(session, theirs["upload_code"])
    await audit.record(session, action="verification.attempted", actor=Actor(ActorType.SYSTEM))
    return locked, taken, await upload_requests.count_failure(session, theirs["upload_request"])


@cases.add(scopes=API_TENANT)
async def start_a_session_for_another_tenants_uploader(
    session: AsyncSession, tenants: Tenants
) -> object:
    subject = Subject.upload_request(tenants.theirs.rows["upload_request"])
    made = await link_sessions.create_for(session, subject, ends_by=None)
    await audit.record(session, action="link_session.started", actor=Actor(ActorType.SYSTEM))
    return made


@cases.add(scopes=NOTIFY_TENANT)
async def notify_another_tenants_uploader(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows["upload_request"]
    found = await upload_requests.link_target(session, theirs, lock=True)
    issued = await upload_requests.issue_link(
        session,
        theirs,
        key_id="iso",
        issued_at=datetime.now(UTC),
        hashed=hashlib.sha256(b"u").digest(),
        replace=True,
    )
    await upload_requests.set_delivery(session, theirs, DeliveryState.SENT, notified=True)
    made = await codes.create_for(
        session,
        Subject.upload_request(theirs),
        code_id=uuid.uuid4(),
        code_hmac=hashlib.sha256(b"c").digest(),
        key_id="iso",
    )
    await audit.record(session, action="uploader.link_issued", actor=Actor(ActorType.SYSTEM))
    return found, issued, made


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_upload_requests_due_for_expiry(session: AsyncSession, tenants: Tenants) -> object:
    # The find step reads across tenants in system scope, by design; tenant scope is refused.
    return await upload_requests.due_for_expiry(session, now=FAR, limit=10)


@cases.add(scopes={JOBS: [TENANT]})
async def expire_another_tenants_upload_request(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows["upload_request"]
    expired = await upload_requests.change_state(
        session,
        theirs,
        from_states=(UploadRequestState.OPEN,),
        to=UploadRequestState.EXPIRED,
        ended_at=FAR,
    )
    ended = await link_sessions.revoke_for_upload_request(session, theirs)
    await audit.record(session, action="upload_request.expired", actor=Actor(ActorType.SYSTEM))
    return expired, ended, await upload_requests.lock_for_expiry(session, theirs)


# ---- received files (#213) ----


@cases.add(scopes={API: [TENANT, RESOURCE]}, subject=mine_as_uploader)
async def read_another_tenants_received_files(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    found = []
    for call in (
        files.get_request_file(session, theirs["upload_request"], theirs["received_file"]),
        files.get_file(session, theirs["received_file"]),
    ):
        try:
            found.append(await call)
        except NotFoundError:
            found.append(None)
    return (
        found,
        await files.list_request_files(session, theirs["upload_request"]),
        await files.request_totals(session, theirs["upload_request"]),
        await files.received_counts(session, [theirs["upload_request"]]),
    )


@cases.add(scopes=API_TENANT)
async def declare_a_file_on_another_tenants_request(
    session: AsyncSession, tenants: Tenants
) -> object:
    file_id = uuid.uuid4()
    made = await files.insert_file(
        session,
        file_id=file_id,
        upload_request_id=tenants.theirs.rows["upload_request"],
        display_name_ct=b"x",
        content_type="text/plain",
        declared_size=10,
        storage_class="standard",
        s3_upload_id="iso",
        part_size=5242880,
        part_count=1,
    )
    await audit.record(session, action="file.added", actor=Actor(ActorType.SYSTEM))
    return made


@cases.add(scopes=API_TENANT)
async def delete_another_tenants_received_file_early(
    session: AsyncSession, tenants: Tenants
) -> object:
    removed = await files.remove_received_file(session, tenants.theirs.rows["received_file"])
    await audit.record(session, action="file.removed", actor=Actor(ActorType.SYSTEM))
    return removed


@cases.add(scopes={API: [TENANT], JOBS: [TENANT]})
async def reject_another_tenants_open_request_uploads(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    found = await files.open_request_uploads(session, theirs["upload_request"])
    rejected = await files.reject_open(session, theirs["received_upload"], now=FAR)
    await audit.record(session, action="file.rejected", actor=Actor(ActorType.SYSTEM))
    return found, rejected


@cases.add(scopes={API: [TENANT], JOBS: [TENANT]})
async def accept_another_tenants_received_upload_with_retention(
    session: AsyncSession, tenants: Tenants
) -> object:
    days = await tenant_data.received_file_retention_days(session)
    marked = await files.mark_scanning(
        session,
        tenants.theirs.rows["received_upload"],
        actual_size=10,
        s3_version_id="iso",
        scan_deadline=FAR,
        retention_days=days,
    )
    await audit.record(session, action="file.uploaded", actor=Actor(ActorType.SYSTEM))
    return days, marked


@cases.add(scopes={API: [TENANT], SCAN: [TENANT], JOBS: [TENANT]})
async def count_another_tenants_received_file_for_its_notice(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows["upload_request"]
    noted = await upload_requests.note_settled(session, theirs, shareable=True)
    blocked = await upload_requests.note_settled(session, theirs, shareable=False)
    await audit.record(session, action="file.scanned", actor=Actor(ActorType.SYSTEM))
    return noted, blocked


@cases.add(scopes=NOTIFY_TENANT)
async def send_another_tenants_received_file_notice(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows["upload_request"]
    found = await upload_requests.notice(session, theirs, lock=True)
    more = await upload_requests.settle_notice(session, theirs, arrived=1, blocked=0)
    await audit.record(session, action="upload_request.notice_sent", actor=Actor(ActorType.SYSTEM))
    return found, more


@cases.add(scopes=API_TENANT)
async def withdraw_another_tenants_received_file_from_its_notice(
    session: AsyncSession, tenants: Tenants
) -> object:
    # #229: the uploader's removal takes a file off its request's next notice.
    theirs = tenants.theirs.rows["upload_request"]
    withdrawn = await upload_requests.withdraw_arrival(session, theirs, settled_at=FAR)
    await audit.record(session, action="file.removed", actor=Actor(ActorType.SYSTEM))
    return withdrawn


@cases.add(scopes=API_TENANT)
async def grant_another_tenants_received_file(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    try:
        found: object = await downloads.get_grant(session, theirs["member_grant"])
    except NotFoundError:
        found = None
    made = await downloads.insert_member_grant(
        session,
        grant_id=uuid.uuid4(),
        file_id=theirs["received_file"],
        s3_version_id="iso",
        user_id=theirs["user"],
        member_session_id=theirs["session"],
        size=10,
        ends_by=FAR,
    )
    await audit.record(session, action="download.granted", actor=Actor(ActorType.SYSTEM))
    return found, made


@cases.add(scopes={JOBS: [TENANT]})
async def clear_another_tenants_finding_details(session: AsyncSession, tenants: Tenants) -> object:
    await findings.clear_details(session, tenants.theirs.rows["scanning_file"])
    await audit.record(session, action="file.deleted", actor=Actor(ActorType.SYSTEM))
    return None


# ---- API keys, audit reads, domain rules and suppression clearing (#215, #216, #217) ----


@cases.add(scopes={API: [TENANT, LOOKUP]})
async def look_up_and_use_another_tenants_key(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    # The service's own hash: an API key is a random token, not a password, so SHA-256 fits it.
    hashed = key_hash(str(theirs["api_key_token"]))
    try:
        found = await api_keys.lookup_key(session, hashed)
    except ScopeNotAllowedError:
        found = None
    try:
        live = await api_keys.live_key(session, theirs["api_key"])
    except ScopeNotAllowedError:
        live = None
    # The lookup finds their key's ID and tenant by design (data model 4.2); the tenant scope
    # that follows is the key's own tenant's, never the caller's, so nothing else of theirs.
    return None if found is None else (found.key_id, found.tenant_id), live


@cases.add(scopes={API: [TENANT]})
async def read_and_revoke_another_tenants_keys(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    found = (
        await api_keys.get_key(session, theirs["api_key"], for_update=True),
        await api_keys.list_keys(session, limit=10),
        await api_keys.count_active(session),
        await api_keys.revoke_key(session, theirs["api_key"], reason=ApiKeyRevokedReason.ADMIN),
        await api_keys.revoke_owner_keys(
            session, theirs["user"], reason=ApiKeyRevokedReason.OWNER_DEACTIVATED
        ),
        await api_keys.owner_keys(
            session, theirs["user"], reason=ApiKeyRevokedReason.OWNER_DEACTIVATED
        ),
        await api_keys.mark_first_export(session, theirs["api_key"]),
        await api_keys.notice_key(session, theirs["api_key"]),
    )
    await audit.record(session, action="api_key.revoked", actor=ADMIN)
    return found


@cases.add(scopes={API: [TENANT]})
async def create_a_key_for_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    # The tenant is the scope's; their user is no user of it, so the composite key refuses.
    key = await api_keys.insert_key(
        session,
        key_id=uuid.uuid4(),
        created_by=tenants.theirs.rows["user"],
        name="isolation",
        key_prefix="sft_dev_Isolatn1",
        key_hash=secrets.token_bytes(32),
        scopes=["transfers:read"],
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    await audit.record(session, action="api_key.created", actor=ADMIN)
    return key.id


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_and_mark_expiring_keys(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    found: object = None
    with contextlib.suppress(ScopeNotAllowedError):  # system scope only
        found = await api_keys.expiring(
            session, now=datetime.now(UTC), within=timedelta(days=14), limit=10
        )
    try:
        marked = await api_keys.mark_notice(session, theirs["api_key"], stage=14, before=None)
    except ScopeNotAllowedError:
        marked = None
    return found, marked


@cases.add(scopes={NOTIFY: [TENANT]})
async def read_another_tenants_key_for_an_email(session: AsyncSession, tenants: Tenants) -> object:
    return await api_keys.notice_key(session, tenants.theirs.rows["api_key"])


@cases.add(scopes=API_TENANT)
async def search_another_tenants_audit_log(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    filters = (
        audit_reads.EventFilter(),
        audit_reads.EventFilter(target_id=theirs.rows["transfer"]),
        audit_reads.EventFilter(target_type="transfer", target_id=theirs.rows["transfer"]),
        audit_reads.EventFilter(actor_id=theirs.rows["user"]),
        audit_reads.EventFilter(people=frozenset({theirs.rows["user"], theirs.rows["recipient"]})),
    )
    now = datetime.now(UTC)
    found: list[object] = []
    for events in filters:
        rows = await audit_reads.read_events(session, events, after=None, until=now, limit=100)
        found.append(rows)
        found.append(await audit_reads.count_events(session, events, until=now, cap=100))
        found.append(await audit_reads.actor_emails(session, rows))
    found.append(await audit_reads.people_with_email(session, f"{theirs.marker}@example.test"))
    found.append(await audit_reads.people_with_email(session, f"{theirs.marker}@recipient.test"))
    return found


@cases.add(scopes=API_TENANT)
async def clear_another_tenants_suppression(session: AsyncSession, tenants: Tenants) -> object:
    ended = await suppressions.end_entries(session, [f"eiso:{tenants.theirs.marker}"])
    await audit.record(session, action="email_suppression.cleared", actor=ADMIN)
    return ended


@cases.add(scopes={NOTIFY: [TENANT]})
async def release_another_tenants_suppression(session: AsyncSession, tenants: Tenants) -> object:
    due = await suppressions.release_due(session, [f"eiso:{tenants.theirs.marker}"])
    await suppressions.mark_released(session, tenants.theirs.rows["suppression"])
    await audit.record(session, action="email_suppression.released", actor=Actor(ActorType.SYSTEM))
    return due


@cases.add(scopes=API_TENANT)
async def set_the_scopes_own_domain_rules(session: AsyncSession, tenants: Tenants) -> object:
    policy = await tenant_data.update_policy(
        session, allowed_domains=["example.com"], blocked_domains=["bad.example.com"]
    )
    await audit.record(session, action="tenant_policy.updated", actor=ADMIN)
    return policy


# ---- the DLP policy, rules and detectors (#218, revision 0024) ----

# The roles that read the policy in a tenant's scope, and roles that must be refused.
DLP_READERS = {API: [TENANT, RESOURCE], SCAN: [TENANT], JOBS: [TENANT], NOTIFY: [TENANT]}
DLP_WRITERS = {API: [TENANT], OPERATOR: [TENANT], SCAN: [TENANT], JOBS: [TENANT]}


def _rule_fields(marker: str) -> RuleFields:
    return RuleFields(
        name=marker,
        direction="sent",
        condition="new_domain",
        detectors=(),
        min_confidence="medium",
        threshold=1,
        reasons=(),
        include_sender_24h=False,
        recipient_scope="any",
        action="warn",
        approvals_required=1,
        enabled=True,
    )


@cases.add(scopes=DLP_READERS)
async def read_another_tenants_dlp_policy(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return (
        await dlp_policy.get_policy(session),
        await dlp_policy.list_live_rules(session),
        await dlp_policy.get_live_rule(session, theirs["dlp_rule"]),
        await dlp_policy.count_live_rules(session),
        await dlp_policy.live_rules_using(session, detector_ref(theirs["dlp_detector"])),
        await dlp_policy.list_live_detectors(session),
        await dlp_policy.get_live_detector(session, theirs["dlp_detector"]),
        await dlp_policy.scan_detectors(session),
        await dlp_policy.detector_names(
            session, [theirs["dlp_detector"], theirs["dlp_deleted_detector"]]
        ),
    )


@cases.add(scopes=API_TENANT)
async def read_another_tenants_approvers_and_admins(
    session: AsyncSession, tenants: Tenants
) -> object:
    return (
        await dlp_policy.get_policy(session, lock=True),
        await dlp_policy.count_active_approvers(session),
        await dlp_policy.active_admin_ids(session),
    )


@cases.add(scopes=DLP_WRITERS)
async def raise_the_dlp_version_as_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    policy = await dlp_policy.raise_version(session, updated_by=tenants.theirs.rows["user"])
    await audit.record(session, action="dlp_policy.updated", actor=ADMIN)
    return policy


@cases.add(scopes=DLP_WRITERS)
async def raise_the_dlp_version_of_no_other_tenant(
    session: AsyncSession, tenants: Tenants
) -> object:
    policy = await dlp_policy.raise_version(
        session, updated_by=None, trusted_domains=["mine.example"]
    )
    await audit.record(session, action="dlp_policy.updated", actor=ADMIN)
    return policy


@cases.add(scopes=DLP_WRITERS)
async def retire_another_tenants_rule_and_detector(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    found = (
        await dlp_policy.retire_rule(session, theirs["dlp_rule"], 2),
        await dlp_policy.retire_detector(session, theirs["dlp_detector"], 2),
    )
    await audit.record(session, action="dlp_rule.deleted", actor=ADMIN)
    return found


@cases.add(scopes=DLP_WRITERS)
async def write_a_rule_made_by_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    rule = await dlp_policy.insert_rule(
        session,
        uuid.uuid4(),
        1,
        _rule_fields(tenants.mine.marker),
        created_by=tenants.theirs.rows["user"],
    )
    await audit.record(session, action="dlp_rule.created", actor=ADMIN)
    return rule


@cases.add(scopes=DLP_WRITERS)
async def write_a_detector_made_by_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    detector = await dlp_policy.insert_detector(
        session,
        uuid.uuid4(),
        1,
        DetectorFields(
            name=tenants.mine.marker, kind="keywords", definition_ct=b"\x00{}", enabled=True
        ),
        created_by=tenants.theirs.rows["user"],
    )
    await audit.record(session, action="dlp_detector.created", actor=ADMIN)
    return detector


@cases.add(scopes={OPERATOR: [TENANT], API: [TENANT]})
async def write_a_default_policy_naming_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    # Mine has its policy already: the function writes nothing, and names no one of theirs.
    await dlp_policy.insert_default_policy(
        session, created_by=tenants.theirs.rows["user"], locale="ja"
    )
    await audit.record(session, action="tenant.created", actor=ADMIN)
    return None


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_retired_dlp_revisions(session: AsyncSession, tenants: Tenants) -> object:
    # The cleanup's find steps read across tenants in system scope, by design; in tenant scope
    # the data layer refuses them before any row.
    return (
        await dlp_policy.tenants_with_retired_rules(session, before=FAR, limit=10),
        await dlp_policy.tenants_with_retired_detectors(session, before=FAR, limit=10),
    )


@cases.add(scopes={JOBS: [TENANT], API: [TENANT], SCAN: [TENANT]})
async def delete_another_tenants_retired_revisions(
    session: AsyncSession, tenants: Tenants
) -> object:
    deleted = (
        await dlp_policy.delete_retired_rules(session, before=FAR, limit=10),
        await dlp_policy.delete_retired_detectors(session, before=FAR, limit=10),
    )
    await audit.record(session, action="retention.rows_deleted", actor=Actor(ActorType.SYSTEM))
    return deleted


# ---- the DLP decision (#219, revision 0025) ----

DECISION_READERS = {API: [TENANT], SCAN: [TENANT], JOBS: [TENANT]}


@cases.add(scopes=DECISION_READERS)
async def read_another_tenants_decision_inputs(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    return (
        await dlp_decisions.decision_policy(session),
        await transfers.recipient_domains(session, theirs.rows["transfer"]),
        await findings.counts_by_file(session, [theirs.rows["scanning_file"]]),
        await dlp_decisions.known_since(
            session, [f"{theirs.marker}.example", f"old-{theirs.marker}.example"], since=PAST
        ),
    )


@cases.add(scopes=API_TENANT)
async def read_another_tenants_decision(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    return (
        await dlp_decisions.get_decision(session, theirs.rows["dlp_decision"]),
        await dlp_decisions.decision_summary(session, theirs.rows["dlp_decision"]),
        await dlp_decisions.known_before(session, [f"{theirs.marker}.example"], at=FAR),
    )


@cases.add(scopes=DECISION_READERS)
async def decide_on_another_tenants_transfer(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    await dlp_decisions.insert_decision(
        session,
        decision_id=uuid.uuid4(),
        transfer_id=theirs["transfer"],
        policy_version=1,
        mode="enforce",
        outcome="warn",
        enforced=True,
        untrusted_recipients=0,
        new_domains=0,
        rules=[dlp_decisions.MatchedRule(theirs["dlp_rule"], 2, "warn", 1)],
    )
    await audit.record(session, action="dlp.decided", actor=Actor(ActorType.SYSTEM))
    return None


@cases.add(scopes=DECISION_READERS)
async def apply_another_tenants_rule_to_my_transfer(
    session: AsyncSession, tenants: Tenants
) -> object:
    await dlp_decisions.insert_decision(
        session,
        decision_id=uuid.uuid4(),
        transfer_id=tenants.mine.rows["transfer"],
        policy_version=1,
        mode="enforce",
        outcome="warn",
        enforced=True,
        untrusted_recipients=0,
        new_domains=0,
        rules=[dlp_decisions.MatchedRule(tenants.theirs.rows["dlp_rule"], 2, "warn", 1)],
    )
    await audit.record(session, action="dlp.decided", actor=Actor(ActorType.SYSTEM))
    return None


@cases.add(scopes=DECISION_READERS)
async def point_another_tenants_transfer_at_a_decision(
    session: AsyncSession, tenants: Tenants
) -> object:
    changed = (
        await transfers.change_state(
            session,
            tenants.theirs.rows["transfer"],
            from_states=(TransferState.DRAFT,),
            to=TransferState.DRAFT,
            dlp_decision_id=tenants.mine.rows["dlp_decision"],
        ),
        await transfers.change_state(
            session,
            tenants.mine.rows["transfer"],
            from_states=(TransferState.DRAFT,),
            to=TransferState.DRAFT,
            dlp_decision_id=tenants.theirs.rows["dlp_decision"],
        ),
    )
    await audit.record(session, action="dlp.decided", actor=Actor(ActorType.SYSTEM))
    return changed


@cases.add(scopes=API_TENANT)
async def confirm_another_tenants_decision(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    await dlp_decisions.insert_confirmation(
        session,
        confirmation_id=uuid.uuid4(),
        transfer_id=tenants.mine.rows["transfer"],
        decision_id=theirs["dlp_decision"],
        confirmed_by=theirs["user"],
        justification_ct=tenants.mine.marker.encode(),
    )
    await audit.record(session, action="transfer.confirmed", actor=ADMIN)
    return None


@cases.add(scopes=DECISION_READERS)
async def record_a_domain_another_tenant_knows(session: AsyncSession, tenants: Tenants) -> object:
    # Theirs is untouched: the upsert writes the scope's tenant's row, never their `last_sent_at`.
    recorded = await dlp_decisions.record_known_domains(
        session, [f"{tenants.theirs.marker}.example", f"{tenants.mine.marker}.example"]
    )
    await audit.record(session, action="transfer.sent", actor=Actor(ActorType.SYSTEM))
    return recorded


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_stale_known_domains(session: AsyncSession, tenants: Tenants) -> object:
    # The cleanup's find step reads across tenants in system scope, by design; in tenant scope
    # the data layer refuses it before any row.
    return await dlp_decisions.tenants_with_stale_domains(session, before=FAR, limit=10)


@cases.add(scopes={JOBS: [TENANT], API: [TENANT], SCAN: [TENANT]})
async def delete_another_tenants_known_domains(session: AsyncSession, tenants: Tenants) -> object:
    deleted = await dlp_decisions.delete_stale_domains(session, before=FAR, limit=10)
    await audit.record(session, action="retention.rows_deleted", actor=Actor(ActorType.SYSTEM))
    return deleted


# ---- DLP approvals (#220, revision 0026) ----

APPROVAL_ENDERS = {API: [TENANT], JOBS: [TENANT]}


@cases.add(scopes=API_TENANT)
async def read_another_tenants_approval_requests(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return (
        await dlp_approvals.count_requests(session, theirs["transfer"]),
        await dlp_approvals.get_request(session, theirs["dlp_approval_request"]),
        await dlp_approvals.latest_request(session, theirs["transfer"]),
        await dlp_approvals.list_requests(session, now=FAR, limit=10),
        await dlp_approvals.list_requests(
            session, now=PAST, sent_by=theirs["user"], states=[ApprovalState.PENDING], limit=10
        ),
        await dlp_approvals.list_requests(
            session, now=FAR, not_sent_by=theirs["user"], states=[ApprovalState.EXPIRED], limit=10
        ),
        await dlp_approvals.approvals(session, [theirs["dlp_approval_request"]]),
        await dlp_approvals.rule_names(session, [theirs["dlp_decision"]]),
        await dlp_approvals.approvals_required(session, theirs["dlp_decision"]),
        await dlp_approvals.justification(session, theirs["dlp_confirmation"]),
        await dlp_approvals.list_decisions(session, theirs["dlp_approval_request"]),
        await dlp_approvals.eligible_approvers(session, sender=theirs["user"]),
    )


async def _request_approval_naming(
    session: AsyncSession,
    mine: dict[str, uuid.UUID],
    decision: uuid.UUID,
    confirmation: uuid.UUID,
    user: uuid.UUID,
) -> object:
    # Each transfer holds one pending request (the seed's), and the index allowing one pending
    # request per transfer answers before a foreign key would: mine is withdrawn first, and their
    # transfer, which keeps its pending request, isn't named.
    await dlp_approvals.end_pending(
        session, mine["transfer"], to=ApprovalState.WITHDRAWN, ended_at=datetime.now(UTC)
    )
    await dlp_approvals.insert_request(
        session,
        request_id=uuid.uuid4(),
        transfer_id=mine["transfer"],
        decision_id=decision,
        confirmation_id=confirmation,
        requested_by=user,
        approvals_required=1,
        expires_at=FAR,
    )
    await audit.record(session, action="dlp_approval.requested", actor=ADMIN)
    return None


@cases.add(scopes=API_TENANT)
async def request_approval_under_another_tenants_decision(
    session: AsyncSession, tenants: Tenants
) -> object:
    mine, theirs = tenants.mine.rows, tenants.theirs.rows
    return await _request_approval_naming(
        session, mine, theirs["dlp_decision"], mine["dlp_confirmation"], mine["user"]
    )


@cases.add(scopes=API_TENANT)
async def request_approval_with_another_tenants_confirmation_and_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    mine, theirs = tenants.mine.rows, tenants.theirs.rows
    return await _request_approval_naming(
        session, mine, mine["dlp_decision"], theirs["dlp_confirmation"], theirs["user"]
    )


@cases.add(scopes=APPROVAL_ENDERS)
async def end_another_tenants_approval_request(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    ended = (
        await dlp_approvals.end_request(
            session, theirs["dlp_approval_request"], to=ApprovalState.EXPIRED, ended_at=FAR
        ),
        await dlp_approvals.end_request(
            session,
            theirs["dlp_approval_request"],
            to=ApprovalState.EXPIRED,
            ended_at=FAR,
            due_by=FAR,
        ),
        await dlp_approvals.end_pending(
            session, theirs["transfer"], to=ApprovalState.WITHDRAWN, ended_at=FAR
        ),
    )
    await audit.record(session, action="dlp_approval.expired", actor=Actor(ActorType.SYSTEM))
    return ended


@cases.add(scopes=API_TENANT)
async def decide_another_tenants_approval_request(
    session: AsyncSession, tenants: Tenants
) -> object:
    mine, theirs = tenants.mine.rows, tenants.theirs.rows
    for request, approver in (
        (theirs["dlp_approval_request"], mine["user"]),
        (mine["dlp_approval_request"], theirs["user"]),
    ):
        await dlp_approvals.insert_decision(
            session,
            decision_id=uuid.uuid4(),
            request_id=request,
            approver_id=approver,
            decision=ApprovalDecisionKind.REJECT,
            comment_ct=tenants.mine.marker.encode(),
        )
    await audit.record(session, action="dlp_approval.rejected", actor=ADMIN)
    return None


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_expired_approval_requests(session: AsyncSession, tenants: Tenants) -> object:
    # The expiry job's find reads across tenants in system scope, by design; in tenant scope the
    # data layer refuses it before any row.
    return await dlp_approvals.due_for_expiry(session, now=FAR, limit=10)


@cases.add(scopes={NOTIFY: [TENANT], API: [TENANT]})
async def read_another_tenants_approval_notice(session: AsyncSession, tenants: Tenants) -> object:
    return await dlp_approvals.notice(session, tenants.theirs.rows["dlp_approval_request"])


# ---- notice windows (#230) ----


@cases.add(scopes=NOTIFY_TENANT)
async def lock_and_save_another_tenants_notice_windows(
    session: AsyncSession, tenants: Tenants
) -> object:
    # `lock` makes the scope's own rows when missing; another tenant's never reach it.
    # A digest window of their user can't be made in this scope: the user key refuses it.
    theirs = tenants.theirs.rows["user"]
    await notice_windows.save(
        session, NoticeKind.DLP_APPROVAL_DIGEST, theirs, window_started_at=FAR, sent=0
    )
    await notice_windows.save(
        session, NoticeKind.DLP_POLICY_CHANGED, None, window_started_at=FAR, sent=0
    )
    found = await notice_windows.lock(session, NoticeKind.DLP_POLICY_CHANGED, [None])
    digests = await notice_windows.lock(session, NoticeKind.DLP_APPROVAL_DIGEST, [theirs])
    return found, digests


@cases.add(scopes=NOTIFY_TENANT)
async def count_another_tenants_pending_approvals(
    session: AsyncSession, tenants: Tenants
) -> object:
    return await notice_windows.pending_approvals(session, tenants.mine.rows["user"])


# ---- DLP-6 and DLP-7 (#221, #222, revision 0027) ----


@cases.add(scopes=API_TENANT)
async def add_message_findings_to_another_tenants_transfer(
    session: AsyncSession, tenants: Tenants
) -> object:
    found = [findings.Counts("payment_card", 0, 1, 0)]
    return await findings.insert_message_findings(session, tenants.theirs.rows["transfer"], found)


@cases.add(scopes=DECISION_READERS)
async def read_another_tenants_message_and_sender_findings(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs.rows
    return (
        await findings.message_counts(session, theirs["transfer"]),
        await findings.sender_recent_counts(
            session, theirs["user"], since=PAST, other_than=tenants.mine.rows["transfer"]
        ),
    )


@cases.add(scopes={SCAN: [TENANT]})
async def block_another_tenants_received_file(session: AsyncSession, tenants: Tenants) -> object:
    return await files.block_received(session, tenants.theirs.rows["received_file"])


@cases.add(scopes={SCAN: [TENANT]})
async def stop_another_tenants_pattern(session: AsyncSession, tenants: Tenants) -> object:
    # The row is the scope's own tenant's, whatever detector ID it names.
    await dlp_policy.record_pattern_stops(session, [tenants.theirs.rows["dlp_detector"]])
    await audit.record(session, action="dlp.pattern_budget_exceeded", actor=Actor(ActorType.SYSTEM))
    return None


@cases.add(scopes=API_TENANT)
async def read_another_tenants_pattern_stops(session: AsyncSession, tenants: Tenants) -> object:
    return await dlp_policy.pattern_stops(session, tenants.theirs.rows["dlp_detector"])


@cases.add(scopes={SCAN: [TENANT]})
async def read_another_tenants_received_rules(session: AsyncSession, tenants: Tenants) -> object:
    return await dlp_decisions.decision_policy(session, DlpDirection.RECEIVED)


@cases.add(scopes=API_TENANT)
async def report_another_tenants_decisions(session: AsyncSession, tenants: Tenants) -> object:
    query = dlp_reports.DecisionQuery(since=PAST, until=FAR)
    return (
        await dlp_reports.list_decisions(session, query, before=None, limit=100),
        await dlp_reports.list_decisions(
            session,
            dlp_reports.DecisionQuery(
                since=PAST,
                until=FAR,
                rule_id=tenants.theirs.rows["dlp_rule"],
                sender_id=tenants.theirs.rows["user"],
            ),
            before=None,
            limit=100,
        ),
        await dlp_reports.report(session, since=PAST, until=FAR),
    )


# ---- field and DLP data keys (#236, #233) ----


@cases.add(scopes={API: [TENANT, RESOURCE], SCAN: [TENANT]})
async def read_another_tenants_data_keys(session: AsyncSession, tenants: Tenants) -> object:
    # Only the scope's own tenant's versions, whatever the caller asks for.
    return [
        await data_keys.list_keys(session, data_keys.KeyPurpose.FIELD),
        await data_keys.list_keys(session, data_keys.KeyPurpose.DLP),
    ]


@cases.add(scopes={API: [TENANT]})
async def change_another_tenants_data_keys(session: AsyncSession, tenants: Tenants) -> object:
    marker = tenants.mine.marker.encode()
    for purpose in data_keys.KeyPurpose:
        await data_keys.insert_key(session, purpose, version=9, wrapped=marker * 2)
        await data_keys.retire_live(session, purpose, now=FAR)
        await data_keys.rewrap(session, purpose, version=1, before=marker, wrapped=marker * 2)
        await data_keys.delete_retired(session, purpose, [1, 2])
    return None


@cases.add(scopes={API: [TENANT]})
async def reseal_another_tenants_values(session: AsyncSession, tenants: Tenants) -> object:
    found: list[object] = []
    for column in data_keys.SEALED_COLUMNS:
        stale = await data_keys.stale_values(session, column, current=99, limit=50)
        found.append(stale)
        theirs = data_keys.StoredValue(tenants.theirs.rows["file"], None, b"\x00x")
        await data_keys.reseal(session, column, theirs, tenants.mine.marker.encode())
    found.append(await data_keys.versions_in_use(session, data_keys.KeyPurpose.FIELD))
    found.append(await findings.details_by_file(session, [tenants.theirs.rows["file"]]))
    await audit.record(session, action="fields.resealed", actor=Actor(ActorType.SYSTEM))
    return found


@cases.add(scopes={API: [LOOKUP]})
async def find_tenants_for_the_field_key_job(session: AsyncSession, tenants: Tenants) -> object:
    # Across tenants by design, IDs only (revision 0031): the find must change nothing.
    return await data_keys.tenants_after(session, None)


# ---- tenant SSO (#231, revision 0029) ----

SSO_ADMINS = {API: [TENANT], OPERATOR: [TENANT]}


@cases.add(scopes=SSO_ADMINS)
async def read_another_tenants_sso_settings(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    return (
        await sso.get_connection(session),
        await sso.list_domains(session),
        await sso.get_domain(session, theirs["sso_domain"], for_update=True),
        await sso.connection_domains(session, theirs["connection"]),
        await sso.group_roles(session) if session.info.get("role") == API else None,
    )


@cases.add(scopes=API_TENANT)
async def change_another_tenants_sso_domains(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs.rows
    changed: list[object] = [await sso.delete_domain(session, theirs["sso_domain_pending"])]
    with contextlib.suppress(NoResultFound):
        changed.append(await sso.mark_verified(session, theirs["sso_domain_pending"]))
    # A claim of their proven domain is this tenant's own pending claim, never theirs.
    claim, _ = await sso.claim_domain(
        session,
        domain=f"{tenants.theirs.marker}.example",
        token="t" * 32,
        created_by=tenants.mine.rows["user"],
    )
    await audit.record(session, action="sso_domain.claimed", actor=ADMIN)
    return changed, claim.tenant_id


@cases.add(scopes=API_TENANT)
async def replace_group_roles_never_reaches_another_tenant(
    session: AsyncSession, tenants: Tenants
) -> object:
    result = await sso.replace_group_roles(session, [(tenants.mine.marker, Role.MEMBER)])
    await audit.record(session, action="tenant_sso.updated", actor=ADMIN)
    return result


@cases.add(scopes={OPERATOR: [TENANT]})
async def link_another_tenants_domains(session: AsyncSession, tenants: Tenants) -> object:
    with contextlib.suppress(NoResultFound):
        await sso.put_connection(
            session,
            kind="oidc",
            provider_name=f"{tenants.mine.marker}-x",
            issuer="x",
            status="active",
        )
    linked = await sso.link_domains(
        session, tenants.theirs.rows["connection"], [f"{tenants.theirs.marker}.example"]
    )
    await audit.record(session, action="tenant_sso.configured", actor=ADMIN)
    return linked


@cases.add(scopes={API: [TENANT], SCAN: [TENANT], JOBS: [TENANT]})
async def another_tenants_proven_domains_are_not_trusted(
    session: AsyncSession, tenants: Tenants
) -> object:
    return await sso.verified_domains(session)


@cases.add(scopes=API_TENANT)
async def bind_an_identity_to_another_tenants_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    bound = await sso.bind_identity(
        session,
        user_id=tenants.theirs.rows["user"],
        connection_id=tenants.theirs.rows["connection"],
        subject=f"bind-{tenants.mine.marker}",
    )
    await audit.record(session, action="user.identity_bound", actor=ADMIN)
    return bound


@cases.add(scopes={API: [TENANT, LOOKUP]})
async def route_another_tenants_domain(session: AsyncSession, tenants: Tenants) -> object:
    # A credential lookup, across tenants in lookup scope by design: it returns IDs and status.
    return await sso.route_domain(session, f"pending-{tenants.theirs.marker}.example")


# ---- the notification worker's SSO invitations (#273, revision 0042) ----


@cases.add(scopes={NOTIFY: [TENANT]})
async def read_another_tenants_connection_as_the_worker(
    session: AsyncSession, tenants: Tenants
) -> object:
    # The worker's test for an SSO invitation: the scope's own tenant's connection, by its ID.
    return await sso.active_connection_id(session)


@cases.add(scopes={NOTIFY: [TENANT]})
async def issue_a_link_to_another_tenants_invited_user(
    session: AsyncSession, tenants: Tenants
) -> object:
    issued = await issue_invitation_link(session, tenants.theirs.rows["user"], bytes(32))
    # As the worker does: the change's event in its transaction, which the audit trigger requires.
    await audit.record(session, action="user.invitation_link_issued", actor=Actor(ActorType.SYSTEM))
    return issued


test_isolation = cases.test()
