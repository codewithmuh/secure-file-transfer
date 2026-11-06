"""Data access for `dlp_findings`: what each detector found in a file, as counts (data model 2.7,
FR-53).

The scan worker inserts findings in the transaction that records the file's scan and inspection
result, and may not read them back: `sft_scan` has no `SELECT` on the table, so never on
`detail_ct` (revision 0011). The API reads them, counts only, until location hints and masked
previews arrive encrypted with DLP-8. No column holds a matched value (NFR-26).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import DlpFinding
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class Counts:
    """One detector's distinct matches at each confidence (detectors 3)."""

    detector: str
    low: int
    medium: int
    high: int


async def insert_findings(session: AsyncSession, file_id: UUID, found: Sequence[Counts]) -> int:
    """One row per detector that matched in the file; nothing for an empty list."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    rows = [
        {
            "id": uuid7(),
            "tenant_id": tenant_id,
            "file_id": file_id,
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
        found.setdefault(file_id, []).append(detector)
    return found
