"""Files of a draft transfer: declare, upload in parts, complete, remove (architecture 4.1, FR-1,
FR-2; data model 2.3, 3.1; abuse and rate limits 6).

File bytes go from the browser straight to S3 in parts; the API never handles them, but it decides
every state change. No transaction is ever open across an S3 call (data model 2.5):

- **Declaring a file** checks the draft, starts the multipart upload, then, in one short
  transaction under the transfer's row lock, re-checks the draft and the limits, reserves the
  tenant's storage and inserts the file. If that transaction fails, the upload is aborted (best
  effort: the bucket's 7-day lifecycle rule and reconciliation catch the rest).
- **Completing a file** runs the three phases of data model 3.1: lock and re-check, then S3 with no
  transaction, then lock and re-check again, so a revocation or a removal that lands while S3 is
  assembling wins. The file reaches `scanning` with its outbox scan message only in phase 3.
- **Rejecting a file** sets `rejected` and `delete_after`, and releases its reservation, with no S3
  call. Only the lifecycle jobs delete objects (ADR-0012).

A file's reservation is released once: when it is rejected, or when it is removed, whichever comes
first (data model 2.5). Every change writes its audit event in its transaction, and the database
refuses to commit one without it (NFR-15).

Every function checks the caller with `authorize` first (authn and authz 6.1), then the resource
rule through the transfer (`sft.service.transfers.require_reach`). `addTransferFile` takes
`Idempotency-Key`: a retry is answered from the stored key before any S3 call, so it starts no
second upload (`sft.service.idempotency.replay`).

**Scanning** (#175): a completed file gets its scan message by its real size, to the small or the
large ClamAV pool, and a scan deadline that grows with its size (`sft.service.scan_timing`). Above
2,000,000,000 bytes only GuardDuty scans, which isn't connected before M6, so such a file is
recorded `scan_failed` (`large_file_scanning_unavailable`) at completion.

**The evaluation** (#174, data model 3.2) runs after every removal of a file from a transfer that
isn't a draft and after every rejection, under the transfer's row lock, so removing the blocked
file of a held transfer sends the rest, and removing its last counted file makes it a draft again.

Not here yet: group F's per-file part-URL count and the tenant's daily upload volume (abuse and
rate limits 2.2, 6.1) are byte and per-item budgets the limiter doesn't count yet.
"""

from __future__ import annotations

import contextlib
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    NotFound,
    ProblemError,
    ServiceUnavailable,
    TooLarge,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.data import audit, files, transfers, usage
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import (
    File,
    FileState,
    InspectionState,
    ScanDetail,
    StorageClass,
    Transfer,
    TransferState,
)
from sft.data.outbox import enqueue
from sft.service import fields, scan_timing
from sft.service.caller import Caller
from sft.service.evaluation import evaluate
from sft.service.idempotency import IdempotentRequest, Outcome, once, replay
from sft.service.objects import PART_URL_SECONDS, ObjectStore, ObjectStoreError
from sft.service.permissions import Reach, authorize
from sft.service.transfers import (
    FileView,
    audit_details,
    draft_conflict,
    effective_state,
    file_view,
    invalid,
    require_reach,
    tenant_scope,
)

MAX_FILE_SIZE: Final = 5_000_000_000
"""FR-2: 5 GB per file."""
MAX_TOTAL_SIZE: Final = 20_000_000_000
"""FR-2: 20 GB per transfer."""
MAX_FILES: Final = 50
"""FR-1: 50 files per transfer."""
LARGE_FILE_THRESHOLD: Final = 2_000_000_000
"""Files over this go to the large-files bucket pair, which GuardDuty scans (ADR-0012, ADR-0019).
Only the bucket: the scan pool follows the real size (`sft.service.scan_timing.scan_topic`)."""
MIN_PART_SIZE: Final = 5 * 1024 * 1024
"""S3's smallest part but the last."""
MAX_PARTS: Final = 1000
"""Abuse and rate limits 6.1: a file has at most 1,000 parts."""
MAX_PART_URLS: Final = 100
"""Part URLs per call (abuse and rate limits 6.1)."""
DEFAULT_STORAGE_QUOTA: Final = 2 * 10**12
"""2 TB per tenant (abuse and rate limits 6.1), the default of the API's setting."""
STORE_RETRY_AFTER: Final = 5
"""`Retry-After` of the `503` an object storage failure answers."""
FILE: Final = "file"
"""The audit target and idempotency resource type of a file."""

REMOVABLE: Final = frozenset(
    {
        TransferState.DRAFT,
        TransferState.SUBMITTED,
        TransferState.HELD,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
    }
)
"""A file can be removed from a transfer in these states, but not once it is sent (data model
3.2)."""


class RejectReason(StrEnum):
    """Why a file was rejected, in its audit event."""

    TRANSFER_NOT_OPEN = "transfer_not_open"
    TOO_MANY_FILES = "too_many_files"
    TOTAL_TOO_LARGE = "total_too_large"
    SIZE_MISMATCH = "size_mismatch"
    REMOVED = "removed"
    UPLOAD_GONE = "upload_gone"


@dataclass(frozen=True, slots=True)
class UploadPolicy:
    """What the API's settings decide about uploads."""

    storage_quota: int = DEFAULT_STORAGE_QUOTA
    small_pool_max: int = scan_timing.SMALL_POOL_MAX_BYTES
    """The largest file the small scan pool takes (ADR-0019's 100 MB split)."""


@dataclass(frozen=True, slots=True)
class FileRequest:
    display_name: str
    size: int
    content_type: str = "application/octet-stream"


@dataclass(frozen=True, slots=True)
class PartUrl:
    part_number: int
    size: int
    url: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class UploadedParts:
    part_size: int
    part_count: int
    parts: tuple[tuple[int, int], ...]
    """Each part S3 holds, as (number, size)."""


def upload_plan(size: int) -> tuple[int, int]:
    """`(part_size, part_count)` for a file of `size` bytes: whole MiB parts of at least 5 MiB, at
    most 1,000 of them (abuse and rate limits 6.1). Every part but the last is `part_size`."""
    if not 1 <= size <= MAX_FILE_SIZE:
        raise ValueError("a file is 1 byte to 5 GB")
    mib = 1024 * 1024
    part_size = max(MIN_PART_SIZE, math.ceil(math.ceil(size / MAX_PARTS) / mib) * mib)
    return part_size, math.ceil(size / part_size)


def part_sizes(file: File) -> dict[int, int]:
    """The exact size of each part of the file's plan, by number."""
    last = file.declared_size - (file.part_count - 1) * file.part_size
    return {
        n: file.part_size if n < file.part_count else last for n in range(1, file.part_count + 1)
    }


def storage_class_for(size: int) -> StorageClass:
    return StorageClass.LARGE if size > LARGE_FILE_THRESHOLD else StorageClass.STANDARD


def _too_many_files() -> Unprocessable:
    return Unprocessable("too_many_files", f"A transfer holds at most {MAX_FILES} files.")


def _total_too_large() -> TooLarge:
    return TooLarge("total_too_large", "A transfer holds 20 GB.")


def _file_too_large() -> TooLarge:
    return TooLarge("file_too_large", "A file is at most 5 GB.")


def _quota_exceeded() -> TooLarge:
    return TooLarge("storage_quota_exceeded", "The tenant's storage is full.")


def _size_mismatch() -> Unprocessable:
    return Unprocessable(
        "upload_size_mismatch",
        "The uploaded size differs from the declared size, so the file was rejected.",
    )


def _upload_incomplete() -> Conflict:
    return Conflict(
        "upload_incomplete",
        "Some parts are missing; send them, then complete again.",
        current_state=FileState.UPLOADING.value,
    )


def _rejected(detail: str) -> Conflict:
    return Conflict("invalid_state", detail, current_state=FileState.REJECTED.value)


def _store_unavailable() -> ServiceUnavailable:
    return ServiceUnavailable(STORE_RETRY_AFTER, "Object storage didn't answer; retry.")


async def _limits(session: AsyncSession, transfer_id: UUID, adding: int = 0) -> ProblemError | None:
    """FR-1 and FR-2 for the transfer's counted files, plus a file of `adding` bytes if given."""
    count, total = await files.counted_totals(session, transfer_id)
    if count + (1 if adding else 0) > MAX_FILES:
        return _too_many_files()
    if total + adding > MAX_TOTAL_SIZE:
        return _total_too_large()
    return None


async def _owned_file(
    session: AsyncSession,
    caller: Caller,
    file_id: UUID,
    *,
    reach: Reach,
    now: datetime,
    lock: bool,
    allow_removed: bool = False,
) -> tuple[File, Transfer]:
    """The file and its transfer, checked in the order 404, then 403 (authn and authz 6.4).

    A removed file is gone for every upload call. With `lock`, the transfer's row lock is held and
    the file is read again after it, so the state seen is the one the lock protects.
    """
    try:
        file = await files.get_file(session, file_id)
        transfer = await transfers.get_transfer(session, file.transfer_id, lock=lock)
    except NotFoundError:
        raise NotFound from None
    require_reach(caller, reach, transfer, now)
    if lock:
        file = await files.get_file(session, file_id)
    if file.removed_at is not None and not allow_removed:
        raise NotFound
    return file, transfer


async def reject(
    session: AsyncSession,
    caller: Caller,
    file: File,
    reason: RejectReason,
    origin: Origin,
) -> File:
    """Phase 1 or 3 found a reason, or the transfer was cancelled: the file is `rejected` and its
    reservation released. The caller holds the transfer's row lock, and runs the evaluation if the
    transfer may be past draft (`_reject_and_evaluate`)."""
    rejected = await files.reject_file(session, file.id)
    if rejected is None:  # pragma: no cover - the caller holds the lock and saw the state
        raise RuntimeError("the file changed under the transfer's row lock")
    if file.removed_at is None:  # a removal released it already
        await usage.release_storage(session, file.declared_size)
    await audit.record(
        session,
        action="file.rejected",
        actor=caller.actor(),
        target=Target(FILE, file.id),
        origin=origin,
        details=audit_details(caller, transfer_id=file.transfer_id, reason=reason),
    )
    return rejected


async def _reject_and_evaluate(
    session: AsyncSession,
    caller: Caller,
    file: File,
    reason: RejectReason,
    origin: Origin,
    now: datetime,
) -> File:
    """`reject`, then the evaluation: a rejection changes the transfer's counted files (data model
    3.1, 3.2). It changes nothing for a draft or an ended transfer."""
    rejected = await reject(session, caller, file, reason, origin)
    await evaluate(
        session,
        file.transfer_id,
        actor=caller.actor(),
        now=now,
        origin=origin,
        details=audit_details(caller),
    )
    return rejected


# ---- addTransferFile ----


async def add_file(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    transfer_id: UUID,
    request: FileRequest,
    *,
    policy: UploadPolicy,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[FileView]:
    """`addTransferFile`: declare a file and start its multipart upload (FR-1, FR-2).

    With an `Idempotency-Key`, a retry of the same request gets the first answer, with the file as
    it is now, and neither starts an upload nor declares a file again.
    """
    reach = authorize(caller, "addTransferFile", now=now)
    if not 1 <= request.size <= MAX_FILE_SIZE:
        raise _file_too_large()
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope

    async def rebuild(session: AsyncSession, file_id: UUID) -> FileView | None:
        try:
            return file_view(tenant_id, await files.get_file(session, file_id))
        except NotFoundError:
            return None

    # A first look, so nobody starts an S3 upload on a transfer they can't change, and a retry
    # gets its first answer without one.
    async with database.transaction(scope) as session:
        replayed = await replay(
            session,
            caller,
            idempotency,
            resource_type=FILE,
            rebuild=lambda file_id: rebuild(session, file_id),
        )
        if replayed is not None:
            return replayed
        await _check_draft(session, caller, transfer_id, request.size, reach=reach, now=now)

    file_id = uuid7()
    storage_class = storage_class_for(request.size)
    key = files.storage_key(tenant_id, file_id)
    part_size, part_count = upload_plan(request.size)
    try:
        upload_id = await objects.create_multipart_upload(storage_class, key)
    except ObjectStoreError:
        raise _store_unavailable() from None

    async def declare(session: AsyncSession) -> FileView:
        await _check_draft(
            session, caller, transfer_id, request.size, reach=reach, now=now, lock=True
        )
        if not await usage.reserve_storage(session, request.size, quota=policy.storage_quota):
            raise _quota_exceeded()
        file = await files.insert_file(
            session,
            file_id=file_id,
            transfer_id=transfer_id,
            display_name_ct=fields.seal(tenant_id, request.display_name),
            content_type=request.content_type,
            declared_size=request.size,
            storage_class=storage_class.value,
            s3_upload_id=upload_id,
            part_size=part_size,
            part_count=part_count,
        )
        await transfers.touch_draft(session, transfer_id)
        await audit.record(
            session,
            action="file.added",
            actor=caller.actor(),
            target=Target(FILE, file_id),
            origin=origin,
            details=audit_details(
                caller,
                transfer_id=transfer_id,
                declared_size=request.size,
                storage_class=storage_class,
                part_count=part_count,
            ),
        )
        return file_view(tenant_id, file)

    try:
        async with database.transaction(scope) as session:
            outcome = await once(
                session,
                caller,
                idempotency,
                status=201,
                resource_type=FILE,
                create=lambda: declare(session),
                rebuild=lambda found: rebuild(session, found),
                resource_id=lambda view: view.id,
            )
    except BaseException:
        # No row refers to the upload, so drop it; the lifecycle rule catches a failure here.
        await _abort(objects, storage_class, key, upload_id)
        raise
    if outcome.replayed:
        # A retry with the same key committed between the first look and now: this upload is
        # nobody's.
        await _abort(objects, storage_class, key, upload_id)
    return outcome


async def _abort(
    objects: ObjectStore, storage_class: StorageClass, key: str, upload_id: str
) -> None:
    with contextlib.suppress(ObjectStoreError):
        await objects.abort_multipart_upload(storage_class, key, upload_id)


async def _check_draft(
    session: AsyncSession,
    caller: Caller,
    transfer_id: UUID,
    size: int,
    *,
    reach: Reach,
    now: datetime,
    lock: bool = False,
) -> None:
    try:
        transfer = await transfers.get_transfer(session, transfer_id, lock=lock)
    except NotFoundError:
        raise NotFound from None
    require_reach(caller, reach, transfer, now)
    conflict = draft_conflict(transfer)
    if conflict is not None:
        raise conflict
    problem = await _limits(session, transfer_id, adding=size)
    if problem is not None:
        raise problem


# ---- requestUploadPartUrls, listUploadedParts ----


def _require_uploading(file: File, transfer: Transfer) -> None:
    conflict = draft_conflict(transfer)
    if conflict is not None:
        raise conflict
    if file.state != FileState.UPLOADING.value:
        raise Conflict("invalid_state", "The file is past uploading.", current_state=file.state)


async def part_urls(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    file_id: UUID,
    part_numbers: Sequence[int],
    *,
    origin: Origin,
    now: datetime,
) -> list[PartUrl]:
    """`requestUploadPartUrls`: a pre-signed URL per part, each for its exact size, valid 15
    minutes (abuse and rate limits 6.2)."""
    reach = authorize(caller, "requestUploadPartUrls", now=now)
    if not 1 <= len(part_numbers) <= MAX_PART_URLS or len(set(part_numbers)) != len(part_numbers):
        raise invalid(json_pointer("part_numbers"), "Ask for 1 to 100 different parts.")
    scope = tenant_scope(caller)
    async with database.transaction(scope) as session:
        file, transfer = await _owned_file(
            session, caller, file_id, reach=reach, now=now, lock=False
        )
        _require_uploading(file, transfer)
        sizes = part_sizes(file)
        for index, number in enumerate(part_numbers):
            if number not in sizes:
                raise invalid(
                    json_pointer("part_numbers", index),
                    "The part number is beyond the file's part_count.",
                )
        if await files.touch_parts(session, file.id) is None:
            # A completion or a removal moved the file on since it was read: it isn't uploading,
            # so no URL is issued and nothing is audited.
            moved = await files.get_file(session, file.id)
            if moved.removed_at is not None:
                raise NotFound
            raise Conflict(
                "invalid_state", "The file is past uploading.", current_state=moved.state
            )
        await audit.record(
            session,
            action="file.part_urls_issued",
            actor=caller.actor(),
            target=Target(FILE, file.id),
            origin=origin,
            details=audit_details(caller, transfer_id=file.transfer_id, parts=len(part_numbers)),
        )
    storage_class = StorageClass(file.storage_class)
    expires_at = datetime.now(UTC) + timedelta(seconds=PART_URL_SECONDS)
    urls = []
    for number in part_numbers:
        try:
            url = await objects.part_url(
                storage_class,
                file.storage_key,
                file.s3_upload_id,
                part_number=number,
                size=sizes[number],
            )
        except ObjectStoreError:
            raise _store_unavailable() from None
        urls.append(PartUrl(number, sizes[number], url, expires_at))
    return urls


async def uploaded_parts(
    database: Database, objects: ObjectStore, caller: Caller, file_id: UUID, *, now: datetime
) -> UploadedParts:
    """`listUploadedParts`: the parts S3 already holds, so a resumed upload sends only the rest
    (FR-2, NFR-3)."""
    reach = authorize(caller, "listUploadedParts", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        file, transfer = await _owned_file(
            session, caller, file_id, reach=reach, now=now, lock=False
        )
        _require_uploading(file, transfer)
    try:
        stored = await objects.list_parts(
            StorageClass(file.storage_class), file.storage_key, file.s3_upload_id
        )
    except ObjectStoreError:
        raise _store_unavailable() from None
    parts = sorted((p.number, p.size) for p in stored or [] if 1 <= p.number <= file.part_count)
    return UploadedParts(file.part_size, file.part_count, tuple(parts))


# ---- completeUpload ----


class _Missing:
    """Phase 2 found parts missing: nothing was assembled."""


class _Gone:
    """Phase 2 found neither the upload nor an object."""


@dataclass(frozen=True, slots=True)
class _Assembled:
    size: int
    version_id: str


_Outcome = _Assembled | _Missing | _Gone | None
"""None: a part has the wrong size, a size mismatch."""


async def _assemble(objects: ObjectStore, file: File) -> _Outcome:
    """Phase 2, with no transaction: list the parts in S3 itself, never the client's list, assemble
    exactly the plan's parts, then read the real size and version (abuse and rate limits 6.3)."""
    storage_class = StorageClass(file.storage_class)
    stored = await objects.list_parts(storage_class, file.storage_key, file.s3_upload_id)
    if stored is not None:
        expected = part_sizes(file)
        by_number = {p.number: p for p in stored if p.number in expected}
        if set(by_number) != set(expected):
            return _Missing()
        if any(by_number[n].size != size for n, size in expected.items()):
            return None
        await objects.complete_multipart_upload(
            storage_class,
            file.storage_key,
            file.s3_upload_id,
            [by_number[n] for n in sorted(expected)],
        )
    # Either just assembled, or a retry after an earlier phase 2 assembled it.
    attributes = await objects.object_attributes(storage_class, file.storage_key)
    if attributes is None:
        return _Gone()
    if attributes.version_id is None:
        # Downloads serve only the version scanned (ADR-0012); without versioning there is none.
        raise ObjectStoreError("VersioningOff")
    return _Assembled(attributes.size, attributes.version_id)


async def complete_upload(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    file_id: UUID,
    *,
    origin: Origin,
    now: datetime,
    small_pool_max: int = scan_timing.SMALL_POOL_MAX_BYTES,
) -> FileView:
    """`completeUpload`, in the three phases of data model 3.1. Safe to retry: a file already
    `completing` runs phases 2 and 3 again, and one past `completing` comes back unchanged."""
    reach = authorize(caller, "completeUpload", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope

    # Phase 1: a short transaction under the transfer's row lock.
    error: ProblemError | None = None
    async with database.transaction(scope) as session:
        file, transfer = await _owned_file(
            session, caller, file_id, reach=reach, now=now, lock=True, allow_removed=True
        )
        if file.state not in (FileState.UPLOADING.value, FileState.COMPLETING.value):
            if file.removed_at is not None:
                raise NotFound
            return file_view(tenant_id, file)
        conflict = draft_conflict(transfer)
        limits = None if conflict else await _limits(session, transfer.id)
        if file.removed_at is not None:
            # Removed while its upload was open: it is gone for the caller, and never assembled.
            await _reject_and_evaluate(session, caller, file, RejectReason.REMOVED, origin, now)
            error = NotFound()
        elif conflict or limits:
            reason = RejectReason.TRANSFER_NOT_OPEN if conflict else _limit_reason(limits)
            file = await _reject_and_evaluate(session, caller, file, reason, origin, now)
            error = conflict or limits
        elif file.state == FileState.UPLOADING.value:
            started = await files.start_completion(session, file.id)
            if started is None:  # pragma: no cover - the lock holds the state seen
                raise RuntimeError("the file changed under the transfer's row lock")
            file = started
            await transfers.touch_draft(session, transfer.id)
            await audit.record(
                session,
                action="file.completion_started",
                actor=caller.actor(),
                target=Target(FILE, file.id),
                origin=origin,
                details=audit_details(caller, transfer_id=transfer.id),
            )
    if error is not None:
        raise error

    # Phase 2: S3, with no transaction open.
    try:
        outcome = await _assemble(objects, file)
    except ObjectStoreError:
        raise _store_unavailable() from None  # the file stays `completing`; a retry resumes

    # Phase 3: lock again and re-check; a revocation or a removal that landed meanwhile wins.
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, file.transfer_id, lock=True)
            file = await files.get_file(session, file_id)
        except NotFoundError:  # pragma: no cover - rows aren't deleted while a file is completing
            raise NotFound from None
        if file.state != FileState.COMPLETING.value:
            # Another call finished it first.
            return file_view(tenant_id, file)
        conflict = draft_conflict(transfer)
        if (
            conflict
            or file.removed_at is not None
            or not isinstance(outcome, _Assembled | _Missing)
        ):
            if conflict:
                reason, error = RejectReason.TRANSFER_NOT_OPEN, conflict
            elif file.removed_at is not None:
                reason, error = RejectReason.REMOVED, _rejected("The file was removed.")
            elif isinstance(outcome, _Gone):
                reason, error = RejectReason.UPLOAD_GONE, _rejected("The upload no longer exists.")
            else:
                reason, error = RejectReason.SIZE_MISMATCH, _size_mismatch()
            await _reject_and_evaluate(session, caller, file, reason, origin, now)
        elif isinstance(outcome, _Missing):
            await files.resume_uploading(session, file.id)
            await audit.record(
                session,
                action="file.upload_incomplete",
                actor=caller.actor(),
                target=Target(FILE, file.id),
                origin=origin,
                details=audit_details(caller, transfer_id=transfer.id),
            )
            error = _upload_incomplete()
        elif outcome.size != file.declared_size:
            await _reject_and_evaluate(
                session, caller, file, RejectReason.SIZE_MISMATCH, origin, now
            )
            error = _size_mismatch()
        else:
            return await _to_scanning(
                session, caller, file, outcome, origin, tenant_id, small_pool_max=small_pool_max
            )
    if error is None:  # pragma: no cover - every branch above sets one or returns
        raise RuntimeError("completion ended without a result")
    raise error


def _limit_reason(error: ProblemError | None) -> RejectReason:
    if error is not None and error.code == "too_many_files":
        return RejectReason.TOO_MANY_FILES
    return RejectReason.TOTAL_TOO_LARGE


async def _to_scanning(
    session: AsyncSession,
    caller: Caller,
    file: File,
    assembled: _Assembled,
    origin: Origin,
    tenant_id: UUID,
    *,
    small_pool_max: int,
) -> FileView:
    storage_class = StorageClass(file.storage_class)
    deadline = scan_timing.scan_deadline(
        assembled.size, datetime.now(UTC), small_pool_max=small_pool_max
    )
    scanning = await files.mark_scanning(
        session,
        file.id,
        actual_size=assembled.size,
        s3_version_id=assembled.version_id,
        scan_deadline=deadline,
    )
    if scanning is None:  # pragma: no cover - the lock holds the state seen
        raise RuntimeError("the file changed under the transfer's row lock")
    # By the real size: the small or the large ClamAV pool, or GuardDuty's (no message, M6).
    topic = scan_timing.scan_topic(assembled.size, small_pool_max=small_pool_max)
    if topic is not None:
        await enqueue(session, topic, {"file_id": file.id})
    await transfers.touch_draft(session, file.transfer_id)
    await audit.record(
        session,
        action="file.uploaded",
        actor=caller.actor(),
        target=Target(FILE, file.id),
        origin=origin,
        details=audit_details(
            caller,
            transfer_id=file.transfer_id,
            actual_size=assembled.size,
            storage_class=storage_class,
        ),
    )
    if topic is None:
        scanning = await _no_engine_scans_it(session, caller, scanning, origin)
    return file_view(tenant_id, scanning)


async def _no_engine_scans_it(
    session: AsyncSession, caller: Caller, file: File, origin: Origin
) -> File:
    """A file over 2,000,000,000 bytes: only GuardDuty scans it, and nothing records its result
    before M6. Rather than wait out a deadline, it is `scan_failed` at once, with
    `large_file_scanning_unavailable`, so the member sees why, and the evaluation runs (a draft's
    is a no-op; a send holds the transfer). It is never shareable (FR-16)."""
    recorded = await files.record_scan(
        session,
        file.id,
        state=FileState.SCAN_FAILED,
        engine=None,
        detail=ScanDetail.LARGE_FILE_SCANNING_UNAVAILABLE,
        attempts=0,
        unscannable_allowed=False,
        inspection_state=InspectionState.SKIPPED,
    )
    if not recorded:  # pragma: no cover - the lock holds the state seen
        raise RuntimeError("the file changed under the transfer's row lock")
    await audit.record(
        session,
        action="file.scanned",
        actor=caller.actor(),
        target=Target(FILE, file.id),
        origin=origin,
        details=audit_details(
            caller,
            transfer_id=file.transfer_id,
            state=FileState.SCAN_FAILED,
            scan_detail=ScanDetail.LARGE_FILE_SCANNING_UNAVAILABLE,
            inspection_state=InspectionState.SKIPPED,
        ),
    )
    await evaluate(
        session,
        file.transfer_id,
        actor=caller.actor(),
        now=datetime.now(UTC),
        origin=origin,
        details=audit_details(caller),
    )
    return await files.get_file(session, file.id)


# ---- deleteFile ----


async def delete_file(
    database: Database, caller: Caller, file_id: UUID, *, origin: Origin, now: datetime
) -> None:
    """`deleteFile` for a file of a transfer that wasn't sent: set `removed_at` and `delete_after`
    and release the reservation (data model 3.2). On anything but a draft, the evaluation runs
    next, in the same transaction. The deletion job removes the contents. Removing a removed file
    again changes nothing."""
    reach = authorize(caller, "deleteFile", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            file = await files.get_file(session, file_id)
            transfer = await transfers.get_transfer(session, file.transfer_id, lock=True)
        except NotFoundError:
            raise NotFound from None
        require_reach(caller, reach, transfer, now)
        file = await files.get_file(session, file_id)
        if file.removed_at is not None:
            return
        state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
        if state not in REMOVABLE:
            raise _not_removable(state)
        await files.remove_file(session, file.id)
        if file.state != FileState.REJECTED.value:
            await usage.release_storage(session, file.declared_size)
        await transfers.touch_draft(session, transfer.id)
        await audit.record(
            session,
            action="file.removed",
            actor=caller.actor(),
            target=Target(FILE, file.id),
            origin=origin,
            details=audit_details(caller, transfer_id=transfer.id, state=FileState(file.state)),
        )
        if state is not TransferState.DRAFT:
            await evaluate(
                session,
                transfer.id,
                actor=caller.actor(),
                now=now,
                origin=origin,
                details=audit_details(caller),
            )


def _not_removable(state: TransferState) -> Conflict:
    if state is TransferState.REVOKED:
        return Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        return Conflict("transfer_expired", current_state=state.value)
    return Conflict(
        "invalid_state",
        "Files can't be removed once the transfer is sent or cancelled.",
        current_state=state.value,
    )
