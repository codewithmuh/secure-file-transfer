"""The metadata purge's data access (#224; data model 6, revision 0034).

A transfer's metadata, and an upload request's, leaves the database 365 days after its last audit
event could have been written, so every audit record's metadata stays readable for its full 365
days (NFR-9). That moment, `purge_after`, is computed here from the bounds data model 6 gives, not
stored:

- a transfer: `ended_at` + 7 days (its files are deleted within 7 days, NFR-8) + 365 days;
- an upload request: the later of `ended_at` and its last received file's `retention_until`, plus
  the same 372 days.

So a purge is due when that bound is at or before `cutoff`, which the job passes as now minus 372
days. Due and **blocked** is a parent with a file whose `deleted_at` is still empty: deleting the
row would leave the file's object with nothing pointing at it, so the purge skips it and counts it
for the alert (data model 6: this only happens on a bug).

`sft_jobs` finds due parents across tenants in system scope (`jobs_find`) and deletes them in each
tenant's scope (`tenant_isolation`); the delete checks every condition again, so a find that went
stale deletes nothing. Child rows (recipients, files, counters, codes, link sessions, grants,
findings, DLP decisions, confirmations, approval requests and their decisions) go with the parent
through `ON DELETE CASCADE`. Audit events have no foreign keys and stay. The caller writes the
audit event the child tables' trigger asks for, in the same transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import ColumnElement, delete, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope
from sft.data.models import File, Transfer, TransferState, UploadRequest, UploadRequestState
from sft.data.scope import ScopeKind

ENDED: Final = (TransferState.REVOKED, TransferState.EXPIRED, TransferState.CANCELLED)
"""The states a transfer ends in, with `ended_at` (data model 3.2)."""


@dataclass(frozen=True, slots=True)
class Due:
    """A parent whose purge is due: its ID, its tenant, and the bound its `purge_after` counts
    from (`ended_at`, or a request's later `retention_until`)."""

    id: UUID
    tenant_id: UUID
    due_from: datetime


def _undeleted_transfer_file(session: AsyncSession) -> ColumnElement[bool]:
    return exists(
        select(File.id).where(
            File.tenant_id == Transfer.tenant_id,
            File.transfer_id == Transfer.id,
            File.deleted_at.is_(None),
            in_scope(File, session),
        )
    )


def _transfer_due(session: AsyncSession, cutoff: datetime) -> list[ColumnElement[bool]]:
    return [
        Transfer.ended_at.is_not(None),
        Transfer.ended_at <= cutoff,
        Transfer.state.in_([s.value for s in ENDED]),
        in_scope(Transfer, session),
    ]


def _request_due_from() -> Any:
    """The later of a request's `ended_at` and its last received file's `retention_until`;
    `greatest` skips a NULL, so a request with no file counts from `ended_at`."""
    latest = (
        select(func.max(File.retention_until))
        .where(
            File.tenant_id == UploadRequest.tenant_id, File.upload_request_id == UploadRequest.id
        )
        .scalar_subquery()
    )
    return func.greatest(UploadRequest.ended_at, latest)


def _undeleted_request_file(session: AsyncSession) -> ColumnElement[bool]:
    return exists(
        select(File.id).where(
            File.tenant_id == UploadRequest.tenant_id,
            File.upload_request_id == UploadRequest.id,
            File.deleted_at.is_(None),
            in_scope(File, session),
        )
    )


def _request_due(session: AsyncSession, cutoff: datetime) -> list[ColumnElement[bool]]:
    return [
        UploadRequest.ended_at.is_not(None),
        UploadRequest.ended_at <= cutoff,
        UploadRequest.state != UploadRequestState.OPEN.value,
        _request_due_from() <= cutoff,
        in_scope(UploadRequest, session),
    ]


# ---- finds, across tenants in system scope ----


async def due_transfers(session: AsyncSession, *, cutoff: datetime, limit: int) -> list[Due]:
    """Up to `limit` transfers whose purge is due and not blocked, oldest first."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(Transfer.id, Transfer.tenant_id, Transfer.ended_at)
        .where(*_transfer_due(session, cutoff), ~_undeleted_transfer_file(session))
        .order_by(Transfer.ended_at, Transfer.id)
        .limit(limit)
    )
    return [Due(r.id, r.tenant_id, r.ended_at) for r in rows]


async def due_upload_requests(session: AsyncSession, *, cutoff: datetime, limit: int) -> list[Due]:
    """Up to `limit` upload requests whose purge is due and not blocked, oldest first."""
    require_scope(session, ScopeKind.SYSTEM)
    due_from = _request_due_from().label("due_from")
    rows = await session.execute(
        select(UploadRequest.id, UploadRequest.tenant_id, due_from)
        .where(*_request_due(session, cutoff), ~_undeleted_request_file(session))
        .order_by(due_from, UploadRequest.id)
        .limit(limit)
    )
    return [Due(r.id, r.tenant_id, r.due_from) for r in rows]


@dataclass(frozen=True, slots=True)
class Backlog:
    """What the purge's metrics report after a run (data model 6)."""

    blocked_transfers: int
    blocked_upload_requests: int
    oldest_due_from: datetime | None
    """The oldest bound of a purge that is due, not blocked, and still not done."""


async def backlog(session: AsyncSession, *, cutoff: datetime) -> Backlog:
    """Due parents held back by an undeleted file, and the oldest due one still there."""
    require_scope(session, ScopeKind.SYSTEM)
    blocked_transfers = await session.scalar(
        select(func.count())
        .select_from(Transfer)
        .where(*_transfer_due(session, cutoff), _undeleted_transfer_file(session))
    )
    blocked_requests = await session.scalar(
        select(func.count())
        .select_from(UploadRequest)
        .where(*_request_due(session, cutoff), _undeleted_request_file(session))
    )
    oldest_transfer = await session.scalar(
        select(func.min(Transfer.ended_at)).where(
            *_transfer_due(session, cutoff), ~_undeleted_transfer_file(session)
        )
    )
    oldest_request = await session.scalar(
        select(func.min(_request_due_from())).where(
            *_request_due(session, cutoff), ~_undeleted_request_file(session)
        )
    )
    found = [t for t in (oldest_transfer, oldest_request) if t is not None]
    return Backlog(
        blocked_transfers=int(blocked_transfers or 0),
        blocked_upload_requests=int(blocked_requests or 0),
        oldest_due_from=min(found) if found else None,
    )


# ---- the purge itself, in each tenant's scope ----


async def purge_transfers(session: AsyncSession, ids: Sequence[UUID], *, cutoff: datetime) -> int:
    """Delete those of `ids` in the scope's tenant whose purge is still due and not blocked, with
    their child rows; how many. The caller writes `retention.rows_deleted`."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        delete(Transfer)
        .where(
            Transfer.id.in_(list(ids)),
            *_transfer_due(session, cutoff),
            ~_undeleted_transfer_file(session),
        )
        .returning(Transfer.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


async def purge_upload_requests(
    session: AsyncSession, ids: Sequence[UUID], *, cutoff: datetime
) -> int:
    """Delete those of `ids` in the scope's tenant whose purge is still due and not blocked, with
    their child rows; how many. The caller writes `retention.rows_deleted`."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        delete(UploadRequest)
        .where(
            UploadRequest.id.in_(list(ids)),
            *_request_due(session, cutoff),
            ~_undeleted_request_file(session),
        )
        .returning(UploadRequest.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())
