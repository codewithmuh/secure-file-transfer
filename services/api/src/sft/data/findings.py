"""Data access for `dlp_findings`: what each detector found in a file, as counts (data model 2.7,
FR-53).

The scan worker inserts findings in the transaction that records the file's scan and inspection
result, with their location hints and masked previews sealed under the tenant's DLP data key
(`detail_ct`, #233; `sft.service.finding_details`); the API inserts a transfer's message findings
at `createTransfer` (FR-50, #221), under `transfer_id` instead of `file_id`, counts only. The scan
worker may read back only the counts, which the DLP decision adds up (`counts_by_file`, revision
0025), never `detail_ct` (revision 0011); so may the jobs. The API reads the counts, and the
details for the file's owner and approvers (`details_by_file`). No column holds a matched value
(NFR-26). The deletion job clears a deleted file's `detail_ct` in the transaction that marks the
file deleted (data model 6, `clear_details`), and keeps the counts.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.core.sealed import key_version
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import DlpFinding, File, FileState, Transfer
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class Counts:
    """One detector's distinct matches at each confidence (detectors 3)."""

    detector: str
    low: int
    medium: int
    high: int
    locations: tuple[str, ...] = field(default=(), repr=False)
    """The inspector's location hints, on their way to being sealed; never stored as such."""
    previews: tuple[str, ...] = field(default=(), repr=False)
    """The inspector's masked previews, likewise."""
    finding_id: UUID | None = None
    """The row's ID, set when details are sealed: they are bound to it."""
    detail_ct: bytes | None = field(default=None, repr=False)
    """The sealed details (`sft.service.finding_details`)."""

    def with_details(self, finding_id: UUID, detail_ct: bytes) -> Counts:
        """The same counts with sealed details in place of the plain ones."""
        return replace(self, locations=(), previews=(), finding_id=finding_id, detail_ct=detail_ct)


@dataclass(frozen=True, slots=True)
class StoredDetails:
    finding_id: UUID
    file_id: UUID
    detector: str
    detail_ct: bytes = field(repr=False)


async def insert_findings(session: AsyncSession, file_id: UUID, found: Sequence[Counts]) -> int:
    """One row per detector that matched in the file; nothing for an empty list."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    if any(c.locations or c.previews for c in found):
        raise ValueError("finding details are sealed before they are stored")
    rows = [
        {
            "id": c.finding_id or uuid7(),
            "tenant_id": tenant_id,
            "file_id": file_id,
            "detector": c.detector,
            "count_low": c.low,
            "count_medium": c.medium,
            "count_high": c.high,
            "detail_ct": c.detail_ct,
            "dlp_key_version": key_version(c.detail_ct),
        }
        for c in found
    ]
    if rows:
        await session.execute(insert(DlpFinding), rows)
    return len(rows)


async def file_findings(session: AsyncSession, file_id: UUID) -> list[Counts]:
    """The file's findings, by detector, for the API."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.execute(
        select(
            DlpFinding.detector,
            DlpFinding.count_low,
            DlpFinding.count_medium,
            DlpFinding.count_high,
        )
        .where(DlpFinding.file_id == file_id, in_scope(DlpFinding, session))
        .order_by(DlpFinding.detector)
    )
    return [Counts(r.detector, r.count_low, r.count_medium, r.count_high) for r in rows]


async def counts_by_file(
    session: AsyncSession, file_ids: Sequence[UUID]
) -> dict[UUID, list[Counts]]:
    """Each file's findings, counts only: what the DLP decision adds up over a transfer's files
    (FR-48) and `getTransferDlp` shows. Names its columns: `sft_scan` and `sft_jobs` may read the
    counts, never `detail_ct` (revision 0025)."""
    require_scope(session, ScopeKind.TENANT)
    found: dict[UUID, list[Counts]] = {}
    if not file_ids:
        return found
    rows = await session.execute(
        select(
            DlpFinding.file_id,
            DlpFinding.detector,
            DlpFinding.count_low,
            DlpFinding.count_medium,
            DlpFinding.count_high,
        )
        .where(DlpFinding.file_id.in_(list(file_ids)), in_scope(DlpFinding, session))
        .order_by(DlpFinding.file_id, DlpFinding.detector)
    )
    for row in rows:
        found.setdefault(row.file_id, []).append(
            Counts(row.detector, row.count_low, row.count_medium, row.count_high)
        )
    return found


async def detectors_by_file(
    session: AsyncSession, file_ids: Sequence[UUID]
) -> dict[UUID, list[str]]:
    """The detectors that matched in each of the files, for `File.inspection`."""
    require_scope(session, ScopeKind.TENANT)
    found: dict[UUID, list[str]] = {}
    if not file_ids:
        return found
    rows = await session.execute(
        select(DlpFinding.file_id, DlpFinding.detector)
        .where(DlpFinding.file_id.in_(list(file_ids)), in_scope(DlpFinding, session))
        .order_by(DlpFinding.file_id, DlpFinding.detector)
    )
    for file_id, detector in rows.tuples():
        if file_id is not None:  # the filter leaves only file findings
            found.setdefault(file_id, []).append(detector)
    return found


async def details_by_file(session: AsyncSession, file_ids: Sequence[UUID]) -> list[StoredDetails]:
    """The sealed details of the files' findings, for the API to open for the file's owner and
    approvers (#233). Only `sft_api` may select `detail_ct`; findings whose details were cleared
    are left out."""
    require_scope(session, ScopeKind.TENANT)
    if not file_ids:
        return []
    rows = await session.execute(
        select(DlpFinding.id, DlpFinding.file_id, DlpFinding.detector, DlpFinding.detail_ct)
        .where(
            DlpFinding.file_id.in_(list(file_ids)),
            DlpFinding.detail_ct.is_not(None),
            in_scope(DlpFinding, session),
        )
        .order_by(DlpFinding.file_id, DlpFinding.detector)
    )
    # The filter on `file_id` leaves file findings only; a message's have no details (#221).
    return [
        StoredDetails(r[0], r[1], r[2], r[3])
        for r in rows.tuples()
        if r[1] is not None and r[3] is not None
    ]


async def clear_details(session: AsyncSession, file_id: UUID) -> None:
    """The deletion job's step for a deleted file (data model 6): its findings' location hints and
    previews go with its contents; the counts stay with the metadata. `sft_jobs` may write these
    two columns, never read them (revision 0020)."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(DlpFinding)
        .where(DlpFinding.file_id == file_id, in_scope(DlpFinding, session))
        .values(detail_ct=None, dlp_key_version=None)
        .execution_options(synchronize_session=False)
    )


# ---- a transfer's message (FR-50, #221) ----


async def insert_message_findings(
    session: AsyncSession, transfer_id: UUID, found: Sequence[Counts]
) -> int:
    """One row per detector that matched in the transfer's message; nothing for an empty list.
    Counts only: no location hint or preview is kept for a message (FR-53)."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    rows = [
        {
            "id": uuid7(),
            "tenant_id": tenant_id,
            "transfer_id": transfer_id,
            "detector": c.detector,
            "count_low": c.low,
            "count_medium": c.medium,
            "count_high": c.high,
        }
        for c in found
    ]
    if rows:
        await session.execute(insert(DlpFinding), rows)
    return len(rows)


async def message_counts(session: AsyncSession, transfer_id: UUID) -> list[Counts]:
    """The message's findings, counts only. Names its columns: the evaluation's system roles read
    `transfer_id` and the counts, never `detail_ct` (revision 0027)."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.execute(
        select(
            DlpFinding.detector,
            DlpFinding.count_low,
            DlpFinding.count_medium,
            DlpFinding.count_high,
        )
        .where(DlpFinding.transfer_id == transfer_id, in_scope(DlpFinding, session))
        .order_by(DlpFinding.detector)
    )
    return [Counts(r.detector, r.count_low, r.count_medium, r.count_high) for r in rows]


async def sender_recent_counts(
    session: AsyncSession, created_by: UUID, *, since: datetime, other_than: UUID
) -> list[Counts]:
    """The findings of the sender's other transfers sent since `since` (FR-49): their counted
    files' and their messages', counts only, one entry per row. For a rule with
    `include_sender_24h`, so splitting data over several transfers doesn't keep each under the
    threshold."""
    require_scope(session, ScopeKind.TENANT)
    recent = (
        select(Transfer.id)
        .where(
            Transfer.created_by == created_by,
            Transfer.sent_at.is_not(None),
            Transfer.sent_at >= since,
            Transfer.id != other_than,
            in_scope(Transfer, session),
        )
        .scalar_subquery()
    )
    counted_files = (
        select(File.id)
        .where(
            File.transfer_id.in_(recent),
            File.removed_at.is_(None),
            File.state != FileState.REJECTED.value,
            in_scope(File, session),
        )
        .scalar_subquery()
    )
    rows = await session.execute(
        select(
            DlpFinding.detector,
            DlpFinding.count_low,
            DlpFinding.count_medium,
            DlpFinding.count_high,
        ).where(
            or_(
                DlpFinding.file_id.in_(counted_files),
                and_(DlpFinding.transfer_id.is_not(None), DlpFinding.transfer_id.in_(recent)),
            ),
            in_scope(DlpFinding, session),
        )
    )
    return [Counts(r.detector, r.count_low, r.count_medium, r.count_high) for r in rows]
