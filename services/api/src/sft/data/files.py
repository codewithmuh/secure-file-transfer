"""Data access for `files` (data model 2.3, states in 3.1).

Each state change is one conditional `UPDATE … WHERE state = …`, so a change applies only from the
state the caller re-checked under the transfer's or upload request's row lock, and returns the row
as it now is, or None if the file was no longer in that state. Writes run in tenant scope only;
reads also serve a link session, through `File.reach`: a recipient's reaches its transfer's files,
an uploader's its request's (#213). State rules and permissions are the service layer's
(`sft.service.uploads`, `sft.service.received`).

A file belongs to a transfer or, received through an upload request, to that request (exactly one,
revision 0020). A received file's `retention_until` and `delete_after` are set when its upload is
accepted (`mark_scanning` with `retention_days`, FR-13).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import ColumnElement, Update, and_, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.models import (
    File,
    FileState,
    InspectionReason,
    InspectionState,
    ScanDetail,
    ScanEngine,
    StorageClass,
)
from sft.data.scope import ScopeKind


def storage_key(tenant_id: UUID, file_id: UUID) -> str:
    """The object key: IDs only, never a name (architecture 5.1, ADR-0012)."""
    return f"tenants/{tenant_id}/files/{file_id}"


async def insert_file(
    session: AsyncSession,
    *,
    file_id: UUID,
    transfer_id: UUID | None = None,
    upload_request_id: UUID | None = None,
    display_name_ct: bytes,
    content_type: str,
    declared_size: int,
    storage_class: str,
    s3_upload_id: str,
    part_size: int,
    part_count: int,
) -> File:
    """A new `uploading` file of a transfer, or of an upload request (#213), of the scope's
    tenant: exactly one of `transfer_id` and `upload_request_id`."""
    require_scope(session, ScopeKind.TENANT)
    if (transfer_id is None) == (upload_request_id is None):
        raise ValueError("a file belongs to a transfer or an upload request")
    tenant_id = tenant_of(session)
    file: File | None = await session.scalar(
        insert(File)
        .values(
            id=file_id,
            tenant_id=tenant_id,
            transfer_id=transfer_id,
            upload_request_id=upload_request_id,
            display_name_ct=display_name_ct,
            content_type=content_type,
            declared_size=declared_size,
            storage_class=storage_class,
            storage_key=storage_key(tenant_id, file_id),
            s3_upload_id=s3_upload_id,
            part_size=part_size,
            part_count=part_count,
            state=FileState.UPLOADING.value,
        )
        .returning(File)
    )
    if file is None:  # pragma: no cover - INSERT … RETURNING always returns the row
        raise RuntimeError("the insert returned no row")
    return file


async def get_file(session: AsyncSession, file_id: UUID) -> File:
    """The file, if the scope reaches it, removed or not."""
    file: File | None = await session.scalar(
        select(File)
        .where(File.id == file_id, in_scope(File, session))
        .execution_options(populate_existing=True)
    )
    if file is None:
        raise NotFoundError("file")
    return file


async def list_transfer_files(session: AsyncSession, transfer_id: UUID) -> list[File]:
    """The transfer's files that haven't been removed, oldest first."""
    rows = await session.scalars(
        select(File)
        .where(
            File.transfer_id == transfer_id,
            File.removed_at.is_(None),
            in_scope(File, session),
        )
        .order_by(File.id)
    )
    return list(rows)


async def counted_totals(session: AsyncSession, transfer_id: UUID) -> tuple[int, int]:
    """How many of the transfer's files count, and their declared bytes: every file that isn't
    `rejected` and hasn't been removed, `completing` ones included (FR-1, FR-2, data model 3.2)."""
    row = (
        await session.execute(
            select(func.count(), func.coalesce(func.sum(File.declared_size), 0)).where(
                File.transfer_id == transfer_id,
                File.state != FileState.REJECTED.value,
                File.removed_at.is_(None),
                in_scope(File, session),
            )
        )
    ).one()
    return int(row[0]), int(row[1])


# ---- received files (#213) ----


async def get_request_file(session: AsyncSession, request_id: UUID, file_id: UUID) -> File:
    """A file of the upload request, removed or not, or `NotFoundError`: the uploader's calls find
    their files only through their own request (`sft.service.received`)."""
    file: File | None = await session.scalar(
        select(File)
        .where(
            File.id == file_id,
            File.upload_request_id == request_id,
            in_scope(File, session),
        )
        .execution_options(populate_existing=True)
    )
    if file is None:
        raise NotFoundError("file")
    return file


async def list_request_files(session: AsyncSession, request_id: UUID) -> list[File]:
    """The upload request's files that haven't been removed, oldest first."""
    rows = await session.scalars(
        select(File)
        .where(
            File.upload_request_id == request_id,
            File.removed_at.is_(None),
            in_scope(File, session),
        )
        .order_by(File.id)
        .execution_options(populate_existing=True)
    )
    return list(rows)


@dataclass(frozen=True, slots=True)
class RequestTotals:
    """An upload request's files as FR-11 counts them."""

    declared: int
    """Every file ever declared, rejected and removed ones included: at most 100."""
    counted: int
    """Files that aren't `rejected` and weren't removed, `completing` ones included: at most 50."""
    total: int
    """The counted files' declared bytes: at most 20 GB."""


def _counted() -> ColumnElement[bool]:
    return and_(File.state != FileState.REJECTED.value, File.removed_at.is_(None))


async def request_totals(session: AsyncSession, request_id: UUID) -> RequestTotals:
    """The request's declarations, counted files and their bytes (FR-11, abuse 2.2 F)."""
    counted = _counted()
    row = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(counted),
                func.coalesce(func.sum(File.declared_size).filter(counted), 0),
            ).where(File.upload_request_id == request_id, in_scope(File, session))
        )
    ).one()
    return RequestTotals(int(row[0]), int(row[1]), int(row[2]))


async def received_counts(
    session: AsyncSession, request_ids: Sequence[UUID]
) -> dict[UUID, tuple[int, int]]:
    """For each request among `request_ids`, its counted files and their declared bytes; a
    request with none is left out."""
    if not request_ids:
        return {}
    rows = await session.execute(
        select(File.upload_request_id, func.count(), func.coalesce(func.sum(File.declared_size), 0))
        .where(File.upload_request_id.in_(request_ids), _counted(), in_scope(File, session))
        .group_by(File.upload_request_id)
    )
    return {r[0]: (int(r[1]), int(r[2])) for r in rows if r[0] is not None}


async def remove_received_file(session: AsyncSession, file_id: UUID) -> File | None:
    """The member's early delete of a received file (FR-13): `removed_at`, and `delete_after`
    moved forward to now, whatever its retention said; None if it was removed already."""
    require_scope(session, ScopeKind.TENANT)
    now = func.now()
    statement = update(File).where(
        File.id == file_id,
        File.upload_request_id.is_not(None),
        File.removed_at.is_(None),
        in_scope(File, session),
    )
    return await _returning(
        session,
        statement.values(
            removed_at=now, delete_after=func.least(func.coalesce(File.delete_after, now), now)
        ),
    )


def _transition(session: AsyncSession, file_id: UUID, *states: FileState) -> Update:
    require_scope(session, ScopeKind.TENANT)
    return update(File).where(
        File.id == file_id,
        File.state.in_([s.value for s in states]),
        in_scope(File, session),
    )


async def _returning(session: AsyncSession, statement: Update) -> File | None:
    file: File | None = await session.scalar(
        statement.returning(File).execution_options(populate_existing=True)
    )
    return file


async def touch_parts(session: AsyncSession, file_id: UUID) -> File | None:
    """Record upload activity on an `uploading` file that hasn't been removed: part URLs were
    issued, so the 24-hour rule for unfinished uploads counts from now (data model 3.1)."""
    statement = _transition(session, file_id, FileState.UPLOADING).where(File.removed_at.is_(None))
    return await _returning(session, statement.values(last_part_at=func.now()))


async def start_completion(session: AsyncSession, file_id: UUID) -> File | None:
    """Phase 1: `uploading` to `completing` (data model 3.1)."""
    statement = _transition(session, file_id, FileState.UPLOADING).where(File.removed_at.is_(None))
    return await _returning(
        session,
        statement.values(state=FileState.COMPLETING.value, completion_started_at=func.now()),
    )


async def resume_uploading(session: AsyncSession, file_id: UUID) -> File | None:
    """Phase 3 found parts missing: back to `uploading`, so the client sends them."""
    statement = _transition(session, file_id, FileState.COMPLETING)
    return await _returning(
        session,
        statement.values(
            state=FileState.UPLOADING.value, completion_started_at=None, last_part_at=func.now()
        ),
    )


async def reject_file(session: AsyncSession, file_id: UUID) -> File | None:
    """`uploading` or `completing` to `rejected`, due for deletion now. No S3 call: the deletion
    job aborts the upload and removes any object (data model 3.1)."""
    statement = _transition(session, file_id, FileState.UPLOADING, FileState.COMPLETING)
    return await _returning(
        session,
        statement.values(
            state=FileState.REJECTED.value,
            delete_after=func.coalesce(File.delete_after, func.now()),
        ),
    )


async def remove_file(session: AsyncSession, file_id: UUID) -> File | None:
    """Set `removed_at` and `delete_after` on a file not yet removed (data model 3.2); its state
    stays, and a `completing` file is rejected by its own phase 3."""
    require_scope(session, ScopeKind.TENANT)
    statement = update(File).where(
        and_(File.id == file_id, File.removed_at.is_(None)), in_scope(File, session)
    )
    return await _returning(
        session,
        statement.values(
            removed_at=func.now(), delete_after=func.coalesce(File.delete_after, func.now())
        ),
    )


async def cancel_files(session: AsyncSession, transfer_id: UUID) -> list[File]:
    """A cancelled transfer's files are due for deletion (data model 6): `delete_after` on each,
    if not set already. Returns the files that were `uploading` or `completing`, which the caller
    rejects: cancelling wins over an upload (contract, `cancelTransfer`)."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(File)
        .where(
            File.transfer_id == transfer_id,
            File.delete_after.is_(None),
            in_scope(File, session),
        )
        .values(delete_after=func.now())
        .execution_options(synchronize_session=False)
    )
    rows = await session.scalars(
        select(File)
        .where(
            File.transfer_id == transfer_id,
            File.state.in_([FileState.UPLOADING.value, FileState.COMPLETING.value]),
            in_scope(File, session),
        )
        .order_by(File.id)
        .execution_options(populate_existing=True)
    )
    return list(rows)


# ---- the evaluation, the scan worker and the scan sweep ----


@dataclass(frozen=True, slots=True)
class CountedFile:
    """What the evaluation needs of one counted file (data model 3.2)."""

    id: UUID
    state: FileState
    unscannable_allowed: bool
    inspection_state: InspectionState
    inspection_reasons: tuple[InspectionReason, ...] = ()
    """Why content wasn't inspected: what a `not_inspected` rule tests (#219)."""


async def counted_states(session: AsyncSession, transfer_id: UUID) -> list[CountedFile]:
    """The transfer's counted files: not `rejected` and not removed."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.execute(
        select(
            File.id,
            File.state,
            File.unscannable_allowed,
            File.inspection_state,
            File.inspection_reasons,
        )
        .where(
            File.transfer_id == transfer_id,
            File.state != FileState.REJECTED.value,
            File.removed_at.is_(None),
            in_scope(File, session),
        )
        .order_by(File.id)
    )
    return [
        CountedFile(
            r.id,
            FileState(r.state),
            r.unscannable_allowed,
            InspectionState(r.inspection_state),
            tuple(InspectionReason(reason) for reason in r.inspection_reasons),
        )
        for r in rows
    ]


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """What the scan worker needs of a file: where its recorded version is, and its state."""

    id: UUID
    transfer_id: UUID | None
    state: FileState
    storage_class: StorageClass
    storage_key: str
    s3_version_id: str | None
    actual_size: int | None
    unscannable_allowed: bool
    inspection_state: InspectionState
    upload_request_id: UUID | None = None
    """A received file's request (#213): its notices, not a transfer's evaluation, follow."""


async def scan_target(session: AsyncSession, file_id: UUID) -> ScanTarget:
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(
                File.id,
                File.transfer_id,
                File.state,
                File.storage_class,
                File.storage_key,
                File.s3_version_id,
                File.actual_size,
                File.unscannable_allowed,
                File.inspection_state,
                File.upload_request_id,
            ).where(File.id == file_id, in_scope(File, session))
        )
    ).first()
    if row is None:
        raise NotFoundError("file")
    return ScanTarget(
        id=row.id,
        transfer_id=row.transfer_id,
        state=FileState(row.state),
        storage_class=StorageClass(row.storage_class),
        storage_key=row.storage_key,
        s3_version_id=row.s3_version_id,
        actual_size=row.actual_size,
        unscannable_allowed=row.unscannable_allowed,
        inspection_state=InspectionState(row.inspection_state),
        upload_request_id=row.upload_request_id,
    )


async def record_scan(
    session: AsyncSession,
    file_id: UUID,
    *,
    state: FileState,
    engine: ScanEngine | None,
    detail: ScanDetail | None,
    attempts: int,
    unscannable_allowed: bool,
    inspection_state: InspectionState,
    inspection_reasons: Sequence[InspectionReason] = (),
    inspection_engine_version: str | None = None,
    inspection_policy_version: int | None = None,
    sha256: bytes | None = None,
) -> bool:
    """Record the scan's and the inspection's result together, only if the file is still
    `scanning` (data model 3.1, 3.5); False if it wasn't, and nothing changed. `sha256` is the
    digest of the version the worker read in full, the downloads' `ETag` (#180);
    `inspection_policy_version` the DLP policy version whose detectors ran (#218)."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(File)
        .where(
            File.id == file_id,
            File.state == FileState.SCANNING.value,
            in_scope(File, session),
        )
        .values(
            state=state.value,
            scan_engine=None if engine is None else engine.value,
            scan_detail=None if detail is None else detail.value,
            scan_attempts=attempts,
            scanned_at=func.now(),
            unscannable_allowed=unscannable_allowed,
            inspection_state=inspection_state.value,
            inspection_reasons=[r.value for r in inspection_reasons],
            inspection_engine_version=inspection_engine_version,
            inspection_policy_version=inspection_policy_version,
            **({} if sha256 is None else {"sha256": sha256}),
        )
        .returning(File.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


@dataclass(frozen=True, slots=True)
class Overdue:
    tenant_id: UUID
    file_id: UUID


async def overdue_scans(session: AsyncSession, *, limit: int) -> list[Overdue]:
    """Files still `scanning` past their deadline, across tenants: the scan sweep's find step, in
    system scope (data model 3.1, 4.2)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(File.tenant_id, File.id)
        .where(
            File.state == FileState.SCANNING.value,
            File.scan_deadline < func.now(),
            in_scope(File, session),
        )
        .order_by(File.scan_deadline)
        .limit(limit)
    )
    return [Overdue(r.tenant_id, r.id) for r in rows]


@dataclass(frozen=True, slots=True)
class Owner:
    """A file's transfer, or the upload request it was received through (#213)."""

    transfer_id: UUID | None
    upload_request_id: UUID | None


async def fail_overdue_scan(
    session: AsyncSession,
    file_id: UUID,
    *,
    detail: ScanDetail,
    inspection_state: InspectionState,
) -> Owner | None:
    """`scan_failed` for a file still `scanning` past its deadline, in its tenant's scope; its
    transfer or request, or None if a result came first and nothing changed."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            update(File)
            .where(
                File.id == file_id,
                File.state == FileState.SCANNING.value,
                File.scan_deadline < func.now(),
                in_scope(File, session),
            )
            .values(
                state=FileState.SCAN_FAILED.value,
                scan_detail=detail.value,
                scanned_at=func.now(),
                inspection_state=inspection_state.value,
            )
            .returning(File.transfer_id, File.upload_request_id)
            .execution_options(synchronize_session=False)
        )
    ).first()
    return None if row is None else Owner(row[0], row[1])


# ---- the lifecycle jobs (sft_jobs, data model 6; #181) ----
#
# The jobs' role reads neither `display_name_ct` nor the inspection's findings, so these name their
# columns and return IDs and plain values, never a whole row.

NOT_YET_DELETABLE: Final = (FileState.COMPLETING.value, FileState.SCANNING.value)
"""Deletion waits for these to settle (data model 3.1)."""
OPEN_UPLOAD: Final = (FileState.UPLOADING.value, FileState.COMPLETING.value)


@dataclass(frozen=True, slots=True)
class Due:
    tenant_id: UUID
    file_id: UUID


async def due_for_deletion(session: AsyncSession, *, now: datetime, limit: int) -> list[Due]:
    """Files whose deletion trigger has passed and that aren't deleted, `completing` or
    `scanning`, across tenants: the deletion job's find step, in system scope (data model 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(File.tenant_id, File.id)
        .where(
            File.deleted_at.is_(None),
            File.delete_after <= now,
            File.state.not_in(NOT_YET_DELETABLE),
            in_scope(File, session),
        )
        .order_by(File.delete_after)
        .limit(limit)
    )
    return [Due(r.tenant_id, r.id) for r in rows]


async def _due(session: AsyncSession, condition: Any, order: Any, limit: int) -> list[Due]:
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(File.tenant_id, File.id)
        .where(condition, in_scope(File, session))
        .order_by(order)
        .limit(limit)
    )
    return [Due(r.tenant_id, r.id) for r in rows]


async def abandoned_uploads(session: AsyncSession, *, before: datetime, limit: int) -> list[Due]:
    """Files still `uploading` with no new part since `before` (24 hours), across tenants."""
    condition = and_(File.state == FileState.UPLOADING.value, File.last_part_at < before)
    return await _due(session, condition, File.last_part_at, limit)


async def stuck_completions(session: AsyncSession, *, before: datetime, limit: int) -> list[Due]:
    """Files left `completing` since `before` (15 minutes), across tenants (data model 3.1)."""
    condition = and_(File.state == FileState.COMPLETING.value, File.completion_started_at < before)
    return await _due(session, condition, File.completion_started_at, limit)


async def overdue_deletions(session: AsyncSession, *, before: datetime) -> int:
    """Files still not deleted a long time after their trigger, across tenants: the daily
    report's leftovers (NFR-8)."""
    require_scope(session, ScopeKind.SYSTEM)
    count = await session.scalar(
        select(func.count())
        .select_from(File)
        .where(File.deleted_at.is_(None), File.delete_after < before, in_scope(File, session))
    )
    return int(count or 0)


async def oldest_due_deletion(session: AsyncSession, *, now: datetime) -> datetime | None:
    """The oldest trigger among files due for deletion and not deleted, across tenants: NFR-8's
    lag."""
    require_scope(session, ScopeKind.SYSTEM)
    oldest: datetime | None = await session.scalar(
        select(func.min(File.delete_after)).where(
            File.deleted_at.is_(None), File.delete_after <= now, in_scope(File, session)
        )
    )
    return oldest


async def known_keys(session: AsyncSession, keys: Sequence[str]) -> dict[str, bool]:
    """Which object keys a file row names, across tenants, each with whether its file is deleted:
    reconciliation's comparison of storage with metadata (data model 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    if not keys:
        return {}
    rows = await session.execute(
        select(File.storage_key, File.deleted_at.is_not(None)).where(
            File.storage_key.in_(list(keys)), in_scope(File, session)
        )
    )
    return {r[0]: bool(r[1]) for r in rows}


async def open_upload_ids(session: AsyncSession, upload_ids: Sequence[str]) -> set[str]:
    """Which multipart uploads belong to a file still `uploading` or `completing`, across
    tenants: those reconciliation never aborts."""
    require_scope(session, ScopeKind.SYSTEM)
    if not upload_ids:
        return set()
    rows = await session.scalars(
        select(File.s3_upload_id).where(
            File.s3_upload_id.in_(list(upload_ids)),
            File.state.in_(OPEN_UPLOAD),
            in_scope(File, session),
        )
    )
    return set(rows)


@dataclass(frozen=True, slots=True)
class JobFile:
    """What the jobs need of one file, in its tenant's scope: never its name."""

    id: UUID
    transfer_id: UUID | None
    state: FileState
    storage_class: StorageClass
    storage_key: str
    s3_upload_id: str
    declared_size: int
    part_size: int
    part_count: int
    removed_at: datetime | None
    delete_after: datetime | None
    deleted_at: datetime | None
    upload_request_id: UUID | None = None
    retention_until: datetime | None = None


_JOB_COLUMNS: Final = (
    File.id,
    File.transfer_id,
    File.state,
    File.storage_class,
    File.storage_key,
    File.s3_upload_id,
    File.declared_size,
    File.part_size,
    File.part_count,
    File.removed_at,
    File.delete_after,
    File.deleted_at,
    File.upload_request_id,
    File.retention_until,
)


def _job_file(row: Any) -> JobFile:
    return JobFile(
        row.id,
        row.transfer_id,
        FileState(row.state),
        StorageClass(row.storage_class),
        row.storage_key,
        row.s3_upload_id,
        row.declared_size,
        row.part_size,
        row.part_count,
        row.removed_at,
        row.delete_after,
        row.deleted_at,
        row.upload_request_id,
        row.retention_until,
    )


async def job_file(session: AsyncSession, file_id: UUID) -> JobFile:
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(*_JOB_COLUMNS).where(File.id == file_id, in_scope(File, session))
        )
    ).first()
    if row is None:
        raise NotFoundError("file")
    return _job_file(row)


async def open_request_uploads(session: AsyncSession, request_id: UUID) -> list[JobFile]:
    """The request's files still `uploading` or `completing`: what a revocation or an expiry
    rejects, so no part of them is ever assembled (NFR-6). The caller holds the request's row
    lock."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.execute(
        select(*_JOB_COLUMNS)
        .where(
            File.upload_request_id == request_id,
            File.state.in_(OPEN_UPLOAD),
            in_scope(File, session),
        )
        .order_by(File.id)
    )
    return [_job_file(row) for row in rows]


async def _changed(session: AsyncSession, statement: Update) -> bool:
    result = await session.execute(
        statement.returning(File.id).execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def mark_deleted(session: AsyncSession, file_id: UUID, *, now: datetime) -> bool:
    """`deleted`, with `deleted_at`, once every object version is gone; False if the file is
    deleted already, or `completing` or `scanning` again (data model 3.1)."""
    require_scope(session, ScopeKind.TENANT)
    return await _changed(
        session,
        update(File)
        .where(
            File.id == file_id,
            File.deleted_at.is_(None),
            File.delete_after <= now,
            File.state.not_in(NOT_YET_DELETABLE),
            in_scope(File, session),
        )
        .values(state=FileState.DELETED.value, deleted_at=now),
    )


async def due_now(session: AsyncSession, transfer_id: UUID, *, now: datetime) -> list[JobFile]:
    """An ended transfer's files are due for deletion: `delete_after` on each that has none.
    Returns those still `uploading` or `completing`, which the caller rejects."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(File)
        .where(
            File.transfer_id == transfer_id,
            File.delete_after.is_(None),
            in_scope(File, session),
        )
        .values(delete_after=now)
        .execution_options(synchronize_session=False)
    )
    ids = await session.scalars(
        select(File.id)
        .where(
            File.transfer_id == transfer_id,
            File.state.in_(OPEN_UPLOAD),
            in_scope(File, session),
        )
        .order_by(File.id)
    )
    return [await job_file(session, file_id) for file_id in ids]


async def reject_open(session: AsyncSession, file_id: UUID, *, now: datetime) -> bool:
    """`uploading` or `completing` to `rejected`, due now (data model 3.1), for the jobs."""
    statement = _transition(session, file_id, FileState.UPLOADING, FileState.COMPLETING)
    return await _changed(
        session,
        statement.values(
            state=FileState.REJECTED.value, delete_after=func.coalesce(File.delete_after, now)
        ),
    )


async def resume_open(session: AsyncSession, file_id: UUID) -> bool:
    """Completion's phase 3 found parts missing: back to `uploading`, for the jobs."""
    statement = _transition(session, file_id, FileState.COMPLETING)
    return await _changed(
        session,
        statement.values(
            state=FileState.UPLOADING.value, completion_started_at=None, last_part_at=func.now()
        ),
    )


async def mark_scanning(
    session: AsyncSession,
    file_id: UUID,
    *,
    actual_size: int,
    s3_version_id: str,
    scan_deadline: datetime,
    retention_days: int | None = None,
) -> bool:
    """Phase 3: `completing` to `scanning`, with the size and version recorded at completion. The
    scan worker scans that version, and downloads serve only it (data model 2.3). False if the file
    was no longer `completing` or was removed. Names its columns, so the jobs run it too.

    A received file gets `retention_until`, `retention_days` from now, and `delete_after` with it:
    its upload was accepted now (FR-13, #213)."""
    statement = _transition(session, file_id, FileState.COMPLETING).where(File.removed_at.is_(None))
    values: dict[str, Any] = {
        "state": FileState.SCANNING.value,
        "actual_size": actual_size,
        "s3_version_id": s3_version_id,
        "scan_deadline": scan_deadline,
    }
    if retention_days is not None:
        until = func.now() + func.make_interval(0, 0, 0, retention_days)
        values["retention_until"] = until
        values["delete_after"] = until
    return await _changed(session, statement.values(**values))
