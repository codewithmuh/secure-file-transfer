"""The lifecycle jobs: expiry, deletion, reconciliation and the daily cleanup (#181; FR-21, NFR-8;
architecture 4.5; data model 3.1, 3.2, 6; encryption and keys 8.1).

Each job runs as `sft_jobs`, a named system actor (authn and authz 6.1) that names itself in its
audit events' details (`system_actor`). It finds due work with one read across tenants in system
scope, then handles each item in its own short transaction in that item's tenant scope (data
model 4.2: find across, act within), in batches of at most 1,000, and never holds a transaction
open across an S3 call (data model 6). Each is safe to run twice at once: every change is a
conditional statement on the state it found, under the transfer's row lock where the evaluation
needs it, so the second run finds nothing left to do. "Now" is the jobs' clock
(`sft.core.clock`), which only the test hook moves.

- **Expiry** (`expire_transfers`): a `submitted`, `awaiting_confirmation`, `pending_approval`,
  `held` or `sent` transfer past `expires_at` becomes `expired`, with `ended_at`, `delete_after`
  on every file and `transfer.expired` (FR-21); its pending approval request, if any, expires
  with it (`dlp_approval.expired`, #220). The API already answers its link `410
  link_expired` from `expires_at` (architecture 4.2).
- **Upload requests** (`expire_upload_requests`, #212): an `open` request past `expires_at`
  becomes `expired`, with `ended_at`, every link session of its uploader ending in the same
  transaction, its uploads still open rejected (#213, NFR-6), and `upload_request.expired` (data
  model 3.3). The API already answers its link `410 link_expired` from `expires_at`. Received files
  keep their own retention (FR-13): the request's expiry never shortens it.
- **Approval requests** (`expire_approval_requests`, #220; data model 3.6): a pending request
  past `expires_at` becomes `expired`, under its transfer's row lock, with `dlp_approval.expired`;
  unless the transfer has expired itself, the transfer goes back to `awaiting_confirmation` and
  its sender gets `dlp_approval_expired`, and may ask again, up to 3 requests in all.
- **Drafts** (`cancel_stale_drafts`): a draft with no activity for 7 days is cancelled, its files
  due for deletion and an open upload rejected (data model 2.2).
- **Deletion** (`delete_due_files`): a file past `delete_after`, not `completing` or `scanning`
  and not deleted yet. With no transaction open: abort every multipart upload still under its key,
  in every region, then delete every object version and delete marker of its key in the bucket
  pair its `storage_class` names, in every region, and list again to confirm. Then, in one
  transaction, the file becomes `deleted` with `deleted_at` and `file.deleted`, its findings'
  location hints and previews (`detail_ct`) are cleared, and the storage reservation is released
  unless a rejection or removal released it already (data model 2.5, 6). Infected and rejected
  files are deleted the same way, and so are received files (#213), at the `delete_after` their
  retention set, or that the member's early delete moved forward (FR-13): `file.deleted` says
  which (`trigger`).
- **Reconciliation** (`reconcile`), every few minutes: an upload with no new part for 24 hours is
  rejected (its upload left to deletion); a file `completing` for 15 minutes runs completion's
  phases 2 and 3 again, so it is finished or rejected, under its transfer's or, for a received
  file, its upload request's row lock (#213); the scan sweep (#175,
  `sft.workers.scan_sweep`); and a grant whose
  `archived_at` is still empty a minute after creation gets its committed record written again,
  then `archived_at`.
- **Storage audit** (`audit_storage`), daily: every object version in every files bucket is
  compared with the metadata, one listing page at a time, so memory stays bounded. A version no
  file row names, or whose file is deleted, is deleted once it is over 24 hours old, and kept
  while younger (an upload in flight). An unfinished
  multipart upload over 24 hours old that no `uploading` or `completing` file holds is aborted.
  The report (NFR-8) counts what it removed, and files still not deleted 7 days after their
  trigger.
- **Cleanup** (`clean_up`), daily: expired verification codes, link sessions (their grants go
  with them) and grants are deleted, each batch with one `retention.rows_deleted` event; so are
  retired DLP rule revisions no decision refers to (#219), retired detector revisions that a later
  revision replaced, or that no live rule and no finding names (#218), and known recipient domains
  365 days after `last_sent_at` (#219; the event counts rows, never names a domain). It also asks
  for the API key expiry emails due, 14 and 3 days before a key expires
  (`sft.service.api_keys.queue_expiry_notices`, #215). A grant whose committed record isn't
  confirmed, and its session, are never deleted: reconciliation retries the record, and
  `lifecycle_unarchived_grants` shows how many wait.

Metrics, for NFR-8 and the jobs (`JobMetrics`): items done per job and result, the age of the
oldest file whose deletion is due and not done (`lifecycle_deletion_lag_seconds`), the files past
7 days (`lifecycle_overdue_deletions`), and each job's last success. Their alert rules come with
M7's alerting as code.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter, Gauge
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import (
    audit,
    codes,
    dlp_approvals,
    dlp_decisions,
    dlp_policy,
    downloads,
    files,
    findings,
    link_sessions,
    transfers,
    upload_requests,
    usage,
)
from sft.data.access import NotFoundError
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.files import JobFile
from sft.data.models import (
    ActorType,
    ApprovalState,
    FileState,
    StorageClass,
    TransferState,
    UploadRequestState,
)
from sft.data.outbox import DLP_APPROVAL_EXPIRED, enqueue
from sft.data.scope import Scope
from sft.service import api_keys, scan_timing
from sft.service.audit_archive import AuditArchive
from sft.service.dlp_decision import KNOWN_FOR
from sft.service.downloads import committed_record
from sft.service.evaluation import APPROVAL_REQUEST, evaluate
from sft.service.objects import ObjectStore, ObjectStoreError, StorageCleaner
from sft.service.uploads import (
    Assembled,
    Gone,
    Missing,
    RejectReason,
    assemble,
    owner_details,
    reject_request_uploads,
    to_scanning,
)

log = logging.getLogger(__name__)

BATCH: Final = 1000
"""Rows per find, each handled in its own transaction (data model 6)."""
DRAFT_IDLE: Final = timedelta(days=7)
UPLOAD_IDLE: Final = timedelta(hours=24)
COMPLETION_STUCK: Final = timedelta(minutes=15)
GRANT_UNARCHIVED: Final = timedelta(minutes=1)
ORPHAN_AGE: Final = timedelta(hours=24)
OVERDUE: Final = timedelta(days=7)
"""NFR-8: a file's contents leave every copy within 7 days of its trigger."""
SYSTEM: Final = Actor(ActorType.SYSTEM)
TRANSFER: Final = "transfer"
FILE: Final = "file"


class SystemActor(StrEnum):
    """The lifecycle jobs as named system actors (authn and authz 6.1)."""

    EXPIRY_JOB = "expiry_job"
    DELETION_JOB = "deletion_job"
    RECONCILIATION_JOB = "reconciliation_job"
    STORAGE_AUDIT_JOB = "storage_audit_job"
    CLEANUP_JOB = "cleanup_job"


class Job(StrEnum):
    EXPIRY = "expiry"
    DELETION = "deletion"
    RECONCILIATION = "reconciliation"
    STORAGE_AUDIT = "storage-audit"
    CLEANUP = "cleanup"


class Reason(StrEnum):
    """Why a job cancelled a transfer, in `transfer.cancelled`."""

    DRAFT_ABANDONED = "draft_abandoned"


class DeletionTrigger(StrEnum):
    """What made a received file due for deletion, in its `file.deleted` (#213, FR-13)."""

    RETENTION = "retention"
    EARLY_DELETE = "early_delete"
    REJECTED = "rejected"


class ExpiryReason(StrEnum):
    """Why a pending approval request expired, in `dlp_approval.expired` (data model 3.6)."""

    APPROVAL_TIMEOUT = "approval_timeout"
    TRANSFER_EXPIRED = "transfer_expired"


class Table(StrEnum):
    """The tables the daily cleanup deletes from, in `retention.rows_deleted`."""

    VERIFICATION_CODES = "verification_codes"
    LINK_SESSIONS = "link_sessions"
    DOWNLOAD_GRANTS = "download_grants"
    DLP_RULES = "dlp_rules"
    DLP_DETECTORS = "dlp_detectors"
    DLP_KNOWN_DOMAINS = "dlp_known_domains"


@dataclass(frozen=True)
class JobMetrics:
    items: Counter
    deletion_lag: Gauge
    overdue: Gauge
    unarchived: Gauge
    last_success: Gauge

    @classmethod
    def create(cls, registry: CollectorRegistry) -> JobMetrics:
        return cls(
            Counter(
                "lifecycle_items_total",
                "Items a lifecycle job handled, by job and result.",
                ["job", "result"],
                registry=registry,
            ),
            Gauge(
                "lifecycle_deletion_lag_seconds",
                "Age of the oldest file whose deletion is due and not done (NFR-8: under 7 days).",
                registry=registry,
            ),
            Gauge(
                "lifecycle_overdue_deletions",
                "Files still not deleted 7 days after their trigger (NFR-8).",
                registry=registry,
            ),
            Gauge(
                "lifecycle_unarchived_grants",
                "Download grants over a minute old whose committed record isn't confirmed: "
                "reconciliation retries them and the cleanup keeps them (NFR-15).",
                registry=registry,
            ),
            Gauge(
                "lifecycle_job_last_success_timestamp_seconds",
                "When each lifecycle job last finished without an error.",
                ["job"],
                registry=registry,
            ),
        )

    def count(self, job: Job, result: str, n: int = 1) -> None:
        if n:
            self.items.labels(job.value, result).inc(n)


@dataclass
class Jobs:
    """What the jobs act on: the database as `sft_jobs`, the files buckets of every region, the
    audit archive of both regions, and their clock."""

    database: Database
    metrics: JobMetrics
    now: Callable[[], datetime]
    cleaner: StorageCleaner | None = None
    objects: ObjectStore | None = None
    archive: AuditArchive | None = None
    small_pool_max: int = scan_timing.SMALL_POOL_MAX_BYTES
    """ADR-0019's split between the scan pools: SCAN_SMALL_POOL_MAX_BYTES, as the API has it."""
    sweep: Callable[[], Awaitable[int]] | None = None
    """The scan sweep, which reconciliation runs (`sft.workers.scan_sweep.sweep`)."""
    report: dict[str, int] = field(default_factory=dict)

    def done(self, key: str, n: int = 1) -> None:
        self.report[key] = self.report.get(key, 0) + n


async def _batches[T](
    find: Callable[[], Awaitable[Sequence[T]]], act: Callable[[T], Awaitable[bool]]
) -> int:
    """Find up to a batch, act on each, and again while a batch changed something: a second run at
    once finds what the first left, and an item a run can't change isn't found forever."""
    total = 0
    while True:
        found = await find()
        changed = 0
        for item in found:
            if await act(item):
                changed += 1
        total += changed
        if len(found) < BATCH or not changed:
            return total


def _details(actor: SystemActor, **details: audit.Detail) -> dict[str, audit.Detail]:
    return {"system_actor": actor, **details}


async def _reject(
    session: AsyncSession, file: JobFile, reason: RejectReason, actor: SystemActor, now: datetime
) -> bool:
    """Reject an open upload, release its reservation, audit it (data model 3.1)."""
    if not await files.reject_open(session, file.id, now=now):
        return False
    if file.removed_at is None:  # a removal released it already
        await usage.release_storage(session, file.declared_size)
    await audit.record(
        session,
        action="file.rejected",
        actor=SYSTEM,
        target=Target(FILE, file.id),
        details=_details(actor, **owner_details(file), reason=reason),
    )
    return True


# ---- expiry and stale drafts ----


async def expire_transfers(jobs: Jobs) -> int:
    """Expiry (module docstring)."""
    database, now = jobs.database, jobs.now()

    async def find() -> list[transfers.Due]:
        async with database.transaction(Scope.system()) as session:
            return await transfers.due_for_expiry(session, now=now, limit=BATCH)

    async def act(item: transfers.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            locked = await transfers.lock_for_evaluation(session, item.transfer_id)
            due = locked.expires_at is not None and locked.expires_at <= now
            if locked.state not in transfers.EXPIRES_FROM or not due:
                return False  # another run, or a revocation, came first
            await transfers.change_state(
                session,
                locked.id,
                from_states=(locked.state,),
                to=TransferState.EXPIRED,
                ended_at=now,
                hold_reason=None,
            )
            if locked.state is TransferState.PENDING_APPROVAL:
                await _expire_pending_request(session, locked.id, now)
            for file in await files.due_now(session, locked.id, now=now):
                await _reject(
                    session, file, RejectReason.TRANSFER_NOT_OPEN, SystemActor.EXPIRY_JOB, now
                )
            await audit.record(
                session,
                action="transfer.expired",
                actor=SYSTEM,
                target=Target(TRANSFER, locked.id),
                details=_details(SystemActor.EXPIRY_JOB, from_state=locked.state),
            )
        return True

    expired = await _batches(find, act)
    jobs.metrics.count(Job.EXPIRY, "expired", expired)
    jobs.done("transfers_expired", expired)
    return expired


async def expire_upload_requests(jobs: Jobs) -> int:
    """Upload requests past `expires_at` (module docstring)."""
    database, now = jobs.database, jobs.now()

    async def find() -> list[upload_requests.Due]:
        async with database.transaction(Scope.system()) as session:
            return await upload_requests.due_for_expiry(session, now=now, limit=BATCH)

    async def act(item: upload_requests.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            locked = await upload_requests.lock_for_expiry(session, item.request_id)
            if locked.state is not UploadRequestState.OPEN or locked.expires_at > now:
                return False  # another run, or a revocation, came first
            await upload_requests.change_state(
                session,
                locked.id,
                from_states=(UploadRequestState.OPEN,),
                to=UploadRequestState.EXPIRED,
                ended_at=now,
            )
            sessions = await link_sessions.revoke_for_upload_request(session, locked.id)
            rejected = await reject_request_uploads(
                session,
                locked.id,
                actor=SYSTEM,
                details=_details(SystemActor.EXPIRY_JOB),
                now=now,
            )
            await audit.record(
                session,
                action="upload_request.expired",
                actor=SYSTEM,
                target=Target(upload_requests.TARGET, locked.id),
                details=_details(
                    SystemActor.EXPIRY_JOB, link_sessions_ended=sessions, uploads_rejected=rejected
                ),
            )
        return True

    expired = await _batches(find, act)
    jobs.metrics.count(Job.EXPIRY, "upload_requests_expired", expired)
    jobs.done("upload_requests_expired", expired)
    return expired


async def _expire_pending_request(session: AsyncSession, transfer_id: UUID, now: datetime) -> None:
    """The pending approval request of a transfer that expires expires with it (data model 3.6);
    the transfer's own expiry tells the sender nothing more."""
    request_id = await dlp_approvals.end_pending(
        session, transfer_id, to=ApprovalState.EXPIRED, ended_at=now
    )
    if request_id is not None:
        await audit.record(
            session,
            action="dlp_approval.expired",
            actor=SYSTEM,
            target=Target(APPROVAL_REQUEST, request_id),
            details=_details(
                SystemActor.EXPIRY_JOB,
                transfer_id=transfer_id,
                reason=ExpiryReason.TRANSFER_EXPIRED,
                returned=False,
            ),
        )


async def expire_approval_requests(jobs: Jobs) -> int:
    """Approval requests past `expires_at` (module docstring)."""
    database, now = jobs.database, jobs.now()

    async def find() -> list[dlp_approvals.Due]:
        async with database.transaction(Scope.system()) as session:
            return await dlp_approvals.due_for_expiry(session, now=now, limit=BATCH)

    async def act(item: dlp_approvals.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            locked = await transfers.lock_for_evaluation(session, item.transfer_id)
            ended = await dlp_approvals.end_request(
                session, item.request_id, to=ApprovalState.EXPIRED, ended_at=now, due_by=now
            )
            if not ended:
                return False  # another run, an approver or a withdrawal came first
            transfer_expired = locked.expires_at is not None and locked.expires_at <= now
            returned = locked.state is TransferState.PENDING_APPROVAL and not transfer_expired
            await audit.record(
                session,
                action="dlp_approval.expired",
                actor=SYSTEM,
                target=Target(APPROVAL_REQUEST, item.request_id),
                details=_details(
                    SystemActor.EXPIRY_JOB,
                    transfer_id=locked.id,
                    reason=ExpiryReason.APPROVAL_TIMEOUT,
                    returned=returned,
                ),
            )
            if returned:
                # Back to the sender, under the same decision: they may ask again (FR-43).
                await transfers.change_state(
                    session,
                    locked.id,
                    from_states=(TransferState.PENDING_APPROVAL,),
                    to=TransferState.AWAITING_CONFIRMATION,
                )
                await audit.record(
                    session,
                    action="transfer.awaiting_confirmation",
                    actor=SYSTEM,
                    target=Target(TRANSFER, locked.id),
                    details=_details(
                        SystemActor.EXPIRY_JOB,
                        from_state=locked.state,
                        decision_id=locked.dlp_decision_id,
                        approval_request_id=item.request_id,
                    ),
                )
                await enqueue(
                    session, DLP_APPROVAL_EXPIRED, {"approval_request_id": item.request_id}
                )
        return True

    expired = await _batches(find, act)
    jobs.metrics.count(Job.EXPIRY, "approval_expired", expired)
    jobs.done("approval_requests_expired", expired)
    return expired


async def cancel_stale_drafts(jobs: Jobs) -> int:
    """Drafts with no activity for 7 days are cancelled (module docstring)."""
    database, now = jobs.database, jobs.now()
    before = now - DRAFT_IDLE

    async def find() -> list[transfers.Due]:
        async with database.transaction(Scope.system()) as session:
            return await transfers.stale_drafts(session, before=before, limit=BATCH)

    async def act(item: transfers.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            locked = await transfers.lock_for_evaluation(session, item.transfer_id)
            if locked.state is not TransferState.DRAFT:
                return False
            # The find read last_activity_at; a file call since moved it, under this lock.
            if not await transfers.idle_since(session, locked.id, before=before):
                return False
            await transfers.change_state(
                session,
                locked.id,
                from_states=(TransferState.DRAFT,),
                to=TransferState.CANCELLED,
                ended_at=now,
            )
            rejected = 0
            for file in await files.due_now(session, locked.id, now=now):
                rejected += await _reject(
                    session, file, RejectReason.TRANSFER_NOT_OPEN, SystemActor.EXPIRY_JOB, now
                )
            await audit.record(
                session,
                action="transfer.cancelled",
                actor=SYSTEM,
                target=Target(TRANSFER, locked.id),
                details=_details(
                    SystemActor.EXPIRY_JOB,
                    from_state=TransferState.DRAFT,
                    rejected_files=rejected,
                    reason=Reason.DRAFT_ABANDONED,
                ),
            )
        return True

    cancelled = await _batches(find, act)
    jobs.metrics.count(Job.EXPIRY, "draft_cancelled", cancelled)
    jobs.done("drafts_cancelled", cancelled)
    return cancelled


# ---- deletion ----


async def _remove_copies(cleaner: StorageCleaner, file: JobFile) -> tuple[int, int]:
    """Abort the file's upload and delete every version of its key, in every region; the
    uploads aborted and the versions deleted. Raises `ObjectStoreError` if any copy remains."""
    aborted = 0
    for upload in await cleaner.uploads(file.storage_class, file.storage_key):
        if await cleaner.abort_upload(
            file.storage_class, upload.region, upload.key, upload.upload_id
        ):
            aborted += 1
    found = await cleaner.versions(file.storage_class, file.storage_key)
    await cleaner.delete_versions(file.storage_class, found)
    if await cleaner.versions(file.storage_class, file.storage_key):
        raise ObjectStoreError("VersionsRemain")
    return aborted, len(found)


async def delete_due_files(jobs: Jobs) -> int:
    """Deletion (module docstring)."""
    database, now, cleaner = jobs.database, jobs.now(), jobs.cleaner
    if cleaner is None:
        raise RuntimeError("the deletion job needs the files buckets")
    skipped: set[UUID] = set()

    async def find() -> list[files.Due]:
        async with database.transaction(Scope.system()) as session:
            due = await files.due_for_deletion(session, now=now, limit=BATCH + len(skipped))
        return [d for d in due if d.file_id not in skipped][:BATCH]

    async def act(item: files.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            try:
                file = await files.job_file(session, item.file_id)
            except NotFoundError:
                return False
        try:
            aborted, deleted = await _remove_copies(cleaner, file)
        except ObjectStoreError as exc:
            # Tried again on the next run; the lag metric shows a file that keeps failing.
            log.warning(
                "a file's objects couldn't be deleted",
                extra={"code": exc.code, "file_id": str(item.file_id)},
            )
            skipped.add(item.file_id)
            jobs.metrics.count(Job.DELETION, "failed")
            return False
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            if not await files.mark_deleted(session, file.id, now=now):
                return False  # another run came first, or it is completing or scanning again
            if file.state is not FileState.REJECTED and file.removed_at is None:
                await usage.release_storage(session, file.declared_size)
            # Location hints and previews go with the contents; the counts stay (data model 6).
            await findings.clear_details(session, file.id)
            trigger: dict[str, audit.Detail] = {}
            if file.upload_request_id is not None:
                trigger["trigger"] = _deletion_trigger(file)
            await audit.record(
                session,
                action="file.deleted",
                actor=SYSTEM,
                target=Target(FILE, file.id),
                details=_details(
                    SystemActor.DELETION_JOB,
                    **owner_details(file),
                    from_state=file.state,
                    versions_deleted=deleted,
                    uploads_aborted=aborted,
                    **trigger,
                ),
            )
        return True

    deleted = await _batches(find, act)
    jobs.metrics.count(Job.DELETION, "deleted", deleted)
    jobs.done("files_deleted", deleted)
    await measure_lag(jobs)
    return deleted


def _deletion_trigger(file: JobFile) -> DeletionTrigger:
    if file.removed_at is not None:
        return DeletionTrigger.EARLY_DELETE
    if file.state is FileState.REJECTED:
        return DeletionTrigger.REJECTED
    return DeletionTrigger.RETENTION


async def measure_lag(jobs: Jobs) -> None:
    """NFR-8's numbers: the oldest due deletion's age, and the files past 7 days."""
    now = jobs.now()
    async with jobs.database.transaction(Scope.system()) as session:
        oldest = await files.oldest_due_deletion(session, now=now)
        overdue = await files.overdue_deletions(session, before=now - OVERDUE)
    jobs.metrics.deletion_lag.set(0 if oldest is None else (now - oldest).total_seconds())
    jobs.metrics.overdue.set(overdue)
    jobs.report["overdue_deletions"] = overdue


# ---- reconciliation ----


async def reject_abandoned_uploads(jobs: Jobs) -> int:
    database, now = jobs.database, jobs.now()

    async def find() -> list[files.Due]:
        async with database.transaction(Scope.system()) as session:
            return await files.abandoned_uploads(session, before=now - UPLOAD_IDLE, limit=BATCH)

    async def act(item: files.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            file = await files.job_file(session, item.file_id)
            await _lock_owner(session, file)
            file = await files.job_file(session, item.file_id)
            if file.state is not FileState.UPLOADING:
                return False
            rejected = await _reject(
                session, file, RejectReason.UPLOAD_ABANDONED, SystemActor.RECONCILIATION_JOB, now
            )
            if file.transfer_id is not None:
                await _evaluate(session, file.transfer_id, now)
        return rejected

    rejected = await _batches(find, act)
    jobs.metrics.count(Job.RECONCILIATION, "upload_abandoned", rejected)
    jobs.done("uploads_rejected", rejected)
    return rejected


async def _lock_owner(session: AsyncSession, file: JobFile) -> None:
    """The row lock a file's change is made under: its transfer's, or its upload request's."""
    if file.upload_request_id is not None:
        await upload_requests.lock_for_expiry(session, file.upload_request_id)
    elif file.transfer_id is not None:
        await transfers.lock_for_evaluation(session, file.transfer_id)


async def _owner_open(session: AsyncSession, file: JobFile, now: datetime) -> RejectReason | None:
    """Lock the file's owner; None while it takes the file, else why it doesn't: a transfer no
    longer a draft, a request revoked or expired (#213)."""
    if file.upload_request_id is not None:
        request = await upload_requests.lock_for_expiry(session, file.upload_request_id)
        if request.state is UploadRequestState.OPEN and request.expires_at > now:
            return None
        return RejectReason.REQUEST_NOT_OPEN
    if file.transfer_id is None:  # pragma: no cover - the owner check holds exactly one
        return RejectReason.TRANSFER_NOT_OPEN
    locked = await transfers.lock_for_evaluation(session, file.transfer_id)
    return None if locked.state is TransferState.DRAFT else RejectReason.TRANSFER_NOT_OPEN


async def _evaluate(session: AsyncSession, transfer_id: UUID, now: datetime) -> None:
    await evaluate(
        session,
        transfer_id,
        actor=SYSTEM,
        now=now,
        details={"system_actor": SystemActor.RECONCILIATION_JOB},
    )


async def finish_stuck_completions(jobs: Jobs) -> int:
    """Completion's phases 2 and 3 again for a file left `completing` (data model 3.1)."""
    database, now, objects = jobs.database, jobs.now(), jobs.objects
    if objects is None:
        raise RuntimeError("reconciliation needs the files buckets")
    actor = SystemActor.RECONCILIATION_JOB

    async def find() -> list[files.Due]:
        async with database.transaction(Scope.system()) as session:
            return await files.stuck_completions(
                session, before=now - COMPLETION_STUCK, limit=BATCH
            )

    async def act(item: files.Due) -> bool:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            file = await files.job_file(session, item.file_id)
        if file.state is not FileState.COMPLETING:
            return False
        try:
            outcome = await assemble(objects, file)
        except ObjectStoreError as exc:
            log.warning("a stuck completion couldn't reach S3", extra={"code": exc.code})
            return False
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            closed = await _owner_open(session, file, now)
            file = await files.job_file(session, item.file_id)
            if file.state is not FileState.COMPLETING:
                return False
            target = Target(FILE, file.id)
            if (
                closed is not None
                or file.removed_at is not None
                or not isinstance(outcome, Assembled | Missing)
                or (isinstance(outcome, Assembled) and outcome.size != file.declared_size)
            ):
                reason = RejectReason.SIZE_MISMATCH
                if closed is not None:
                    reason = closed
                elif file.removed_at is not None:
                    reason = RejectReason.REMOVED
                elif isinstance(outcome, Gone):
                    reason = RejectReason.UPLOAD_GONE
                await _reject(session, file, reason, actor, now)
                if file.transfer_id is not None:
                    await _evaluate(session, file.transfer_id, now)
                jobs.metrics.count(Job.RECONCILIATION, "completion_rejected")
                return True
            if isinstance(outcome, Missing):
                await files.resume_open(session, file.id)
                await audit.record(
                    session,
                    action="file.upload_incomplete",
                    actor=SYSTEM,
                    target=target,
                    details=_details(actor, **owner_details(file)),
                )
                jobs.metrics.count(Job.RECONCILIATION, "completion_incomplete")
                return True
            await to_scanning(
                session,
                file,
                outcome,
                actor=SYSTEM,
                details={"system_actor": actor},
                now=now,
                small_pool_max=jobs.small_pool_max,
            )
            jobs.metrics.count(Job.RECONCILIATION, "completion_finished")
        return True

    finished = await _batches(find, act)
    jobs.done("completions_settled", finished)
    return finished


async def rewrite_committed_records(jobs: Jobs) -> int:
    """A grant whose committed record isn't confirmed a minute after creation gets it written
    again, then `archived_at` (data model 2.3). The record is made from the row alone, so it is
    the same object the API wrote, which the archive keeps once."""
    database, now, archive = jobs.database, jobs.now(), jobs.archive
    if archive is None:
        raise RuntimeError("reconciliation needs the audit archive")
    failed: set[UUID] = set()

    async def find() -> list[downloads.Unarchived]:
        async with database.transaction(Scope.system()) as session:
            found = await downloads.unarchived(
                session, created_before=now - GRANT_UNARCHIVED, limit=BATCH + len(failed)
            )
        return [g for g in found if g.id not in failed][:BATCH]

    async def act(grant: downloads.Unarchived) -> bool:
        if await archive.write([committed_record(grant)]):
            failed.add(grant.id)
            return False
        async with database.transaction(Scope.tenant(grant.tenant_id)) as session:
            await downloads.mark_archived(session, grant.id)
        return True

    written = await _batches(find, act)
    jobs.metrics.count(Job.RECONCILIATION, "grant_record_written", written)
    jobs.metrics.count(Job.RECONCILIATION, "grant_record_failed", len(failed))
    jobs.done("grant_records_written", written)
    await measure_unarchived(jobs)
    return written


async def measure_unarchived(jobs: Jobs) -> int:
    """How many grants still wait for their committed record: a gauge, and the report."""
    async with jobs.database.transaction(Scope.system()) as session:
        waiting = await downloads.count_unarchived(
            session, created_before=jobs.now() - GRANT_UNARCHIVED
        )
    jobs.metrics.unarchived.set(waiting)
    jobs.report["unarchived_grants_waiting"] = waiting
    return waiting


async def reconcile(jobs: Jobs) -> dict[str, int]:
    """Reconciliation (module docstring)."""
    await reject_abandoned_uploads(jobs)
    await finish_stuck_completions(jobs)
    if jobs.sweep is not None:  # the scan sweep (#175), with the scan worker's metric
        jobs.done("scans_failed", await jobs.sweep())
    await rewrite_committed_records(jobs)
    return jobs.report


# ---- the daily storage audit ----


async def audit_storage(jobs: Jobs) -> dict[str, int]:
    """Compare every bucket with the metadata; remove orphans and stale uploads (module
    docstring). Read across tenants in system scope; it changes no row."""
    cleaner, now = jobs.cleaner, jobs.now()
    if cleaner is None:
        raise RuntimeError("the storage audit needs the files buckets")
    for storage_class in StorageClass:
        # One listing page at a time (up to 1,000 versions), looked up and acted on before the
        # next is read, so memory stays one page whatever the bucket's size (#181 review). A key
        # whose versions span two pages is judged the same way on each.
        async for page in cleaner.version_pages(storage_class):
            keys = sorted({version.key for version in page})
            async with jobs.database.transaction(Scope.system()) as session:
                known = await files.known_keys(session, keys)
            stale = []
            for version in page:
                if known.get(version.key) is False:
                    continue  # a file that isn't deleted: its object belongs
                jobs.done("orphans_found")
                if version.last_modified <= now - ORPHAN_AGE:
                    stale.append(version)
            if stale:
                await cleaner.delete_versions(storage_class, stale)
                jobs.done("orphans_deleted", len(stale))
        async for uploads in cleaner.upload_pages(storage_class):
            old = [u for u in uploads if u.initiated <= now - ORPHAN_AGE]
            if not old:
                continue
            async with jobs.database.transaction(Scope.system()) as session:
                held = await files.open_upload_ids(session, [u.upload_id for u in old])
            for upload in old:
                if upload.upload_id in held:
                    continue
                if await cleaner.abort_upload(
                    storage_class, upload.region, upload.key, upload.upload_id
                ):
                    jobs.done("uploads_aborted")
    jobs.metrics.count(Job.STORAGE_AUDIT, "orphan_deleted", jobs.report.get("orphans_deleted", 0))
    jobs.metrics.count(Job.STORAGE_AUDIT, "upload_aborted", jobs.report.get("uploads_aborted", 0))
    await measure_lag(jobs)
    log.info("storage audit report", extra={"report": dict(jobs.report)})
    return jobs.report


# ---- the daily cleanup ----


async def _tenants_with_stale_domains(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    return await dlp_decisions.tenants_with_stale_domains(
        session, before=before - KNOWN_FOR, limit=limit
    )


async def _delete_stale_domains(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Known recipient domains 365 days after `last_sent_at` (FR-46, data model 6)."""
    return await dlp_decisions.delete_stale_domains(session, before=before - KNOWN_FOR, limit=limit)


async def clean_up(jobs: Jobs) -> dict[str, int]:
    """Expired codes, link sessions and grants are deleted, retired DLP rule and detector
    revisions nothing needs, and known recipient domains not sent to for 365 days (data model
    6)."""
    database, now = jobs.database, jobs.now()
    kinds: tuple[
        tuple[
            Table,
            Callable[..., Awaitable[list[UUID]]],
            Callable[..., Awaitable[int]],
        ],
        ...,
    ] = (
        (Table.VERIFICATION_CODES, codes.tenants_with_expired, codes.delete_expired),
        (Table.DOWNLOAD_GRANTS, downloads.tenants_with_expired, downloads.delete_expired),
        (Table.LINK_SESSIONS, link_sessions.tenants_with_expired, link_sessions.delete_expired),
        (
            Table.DLP_RULES,
            dlp_policy.tenants_with_retired_rules,
            dlp_policy.delete_retired_rules,
        ),
        (
            Table.DLP_DETECTORS,
            dlp_policy.tenants_with_retired_detectors,
            dlp_policy.delete_retired_detectors,
        ),
        (Table.DLP_KNOWN_DOMAINS, _tenants_with_stale_domains, _delete_stale_domains),
    )
    for table, tenants_of, delete in kinds:
        total = 0
        while True:
            async with database.transaction(Scope.system()) as session:
                tenant_ids = await tenants_of(session, before=now, limit=BATCH)
            if not tenant_ids:
                break
            before_pass = total
            for tenant_id in tenant_ids:
                async with database.transaction(Scope.tenant(tenant_id)) as session:
                    deleted = await delete(session, before=now, limit=BATCH)
                    if deleted:
                        await audit.record(
                            session,
                            action="retention.rows_deleted",
                            actor=SYSTEM,
                            details=_details(SystemActor.CLEANUP_JOB, table=table, rows=deleted),
                        )
                total += deleted
            if total == before_pass:
                break  # what the find saw, the tenant's scope keeps: never loop on it
        jobs.metrics.count(Job.CLEANUP, f"{table.value}_deleted", total)
        jobs.done(f"{table.value}_deleted", total)
    # API keys close to expiry: their 14- and 3-day emails (#215, authn and authz 5.2).
    notices = await api_keys.queue_expiry_notices(database, now=now)
    jobs.metrics.count(Job.CLEANUP, "api_key_notices_queued", notices)
    jobs.done("api_key_notices_queued", notices)
    # Grants waiting for their committed record, and their sessions, stay; the report says how
    # many, so a growing number shows (NFR-15).
    await measure_unarchived(jobs)
    return jobs.report


RUNS: Final[dict[Job, Callable[[Jobs], Awaitable[object]]]] = {}


async def _expiry(jobs: Jobs) -> object:
    await expire_transfers(jobs)
    await expire_upload_requests(jobs)
    await expire_approval_requests(jobs)
    await cancel_stale_drafts(jobs)
    return jobs.report


RUNS.update(
    {
        Job.EXPIRY: _expiry,
        Job.DELETION: delete_due_files,
        Job.RECONCILIATION: reconcile,
        Job.STORAGE_AUDIT: audit_storage,
        Job.CLEANUP: clean_up,
    }
)
