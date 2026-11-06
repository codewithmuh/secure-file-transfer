"""Data access for `files` (data model 2.3, states in 3.1).

Each state change is one conditional `UPDATE … WHERE state = …`, so a change applies only from the
state the caller re-checked under the transfer's row lock, and returns the row as it now is, or
None if the file was no longer in that state. Writes run in tenant scope only; reads also serve a
recipient's link session later, through `File.reach`. State rules and permissions are the service
layer's (`sft.service.uploads`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import Update, and_, func, insert, select, update
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
    transfer_id: UUID,
    display_name_ct: bytes,
    content_type: str,
    declared_size: int,
    storage_class: str,
    s3_upload_id: str,
    part_size: int,
    part_count: int,
) -> File:
    """A new `uploading` file of a transfer of the scope's tenant."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    file: File | None = await session.scalar(
        insert(File)
        .values(
            id=file_id,
            tenant_id=tenant_id,
            transfer_id=transfer_id,
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


async def mark_scanning(
    session: AsyncSession,
    file_id: UUID,
    *,
    actual_size: int,
    s3_version_id: str,
    scan_deadline: datetime,
) -> File | None:
    """Phase 3: `completing` to `scanning`, with the size and version recorded at completion. The
    scan worker scans that version, and downloads serve only it (data model 2.3)."""
    statement = _transition(session, file_id, FileState.COMPLETING).where(File.removed_at.is_(None))
    return await _returning(
        session,
        statement.values(
            state=FileState.SCANNING.value,
            actual_size=actual_size,
            s3_version_id=s3_version_id,
            scan_deadline=scan_deadline,
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


async def counted_states(session: AsyncSession, transfer_id: UUID) -> list[CountedFile]:
    """The transfer's counted files: not `rejected` and not removed."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.execute(
        select(File.id, File.state, File.unscannable_allowed, File.inspection_state)
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
            r.id, FileState(r.state), r.unscannable_allowed, InspectionState(r.inspection_state)
        )
        for r in rows
    ]


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """What the scan worker needs of a file: where its recorded version is, and its state."""

    id: UUID
    transfer_id: UUID
    state: FileState
    storage_class: StorageClass
    storage_key: str
    s3_version_id: str | None
    actual_size: int | None
    unscannable_allowed: bool
    inspection_state: InspectionState


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
) -> bool:
    """Record the scan's and the inspection's result together, only if the file is still
    `scanning` (data model 3.1, 3.5); False if it wasn't, and nothing changed."""
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


async def fail_overdue_scan(
    session: AsyncSession,
    file_id: UUID,
    *,
    detail: ScanDetail,
    inspection_state: InspectionState,
) -> UUID | None:
    """`scan_failed` for a file still `scanning` past its deadline, in its tenant's scope; its
    transfer's ID, or None if a result came first and nothing changed."""
    require_scope(session, ScopeKind.TENANT)
    transfer_id: UUID | None = await session.scalar(
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
        .returning(File.transfer_id)
        .execution_options(synchronize_session=False)
    )
    return transfer_id
