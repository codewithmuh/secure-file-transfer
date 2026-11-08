"""Inspecting a transfer's message (FR-50, #221; architecture 4.6; detectors 1, 5).

A message is plain text of at most 2,000 characters, so the API inspects it in process at
`createTransfer`, in the transaction that creates the transfer, with the same detector code the
inspector runs on files (`sft.dlp.detect.inspect_text`): every built-in detector and the tenant's
live, enabled keyword lists and patterns, each pattern within its scan-time budget (detectors 5).
File content is never inspected here: only the sandboxed inspector reads files (ADR-0022).

The findings are written with `transfer_id` instead of `file_id` (revision 0027), counts only: a
message keeps no location hint or masked preview, since the sender wrote it and sees it. The
decision adds them to its `content` rules as it adds a file's (`sft.service.dlp_decision`).

Nothing here logs the message or a match.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import dlp_policy, findings
from sft.data.findings import Counts
from sft.dlp.detect import inspect_text
from sft.dlp.units import TenantDetector
from sft.service.dlp_definitions import detector_unit, open_definition


async def tenant_units(session: AsyncSession, tenant_id: UUID) -> list[TenantDetector]:
    """The tenant's live, enabled detectors as the detector library takes them."""
    found = await dlp_policy.scan_detectors(session)
    return [
        detector_unit(d.id, open_definition(tenant_id, d.definition_ct)) for d in found.detectors
    ]


async def inspect_message(
    session: AsyncSession, tenant_id: UUID, transfer_id: UUID, message: str
) -> int:
    """Inspect the transfer's message and write its findings; returns how many detectors
    matched."""
    units = await tenant_units(session, tenant_id)
    found = [
        Counts(f.detector, f.counts["low"], f.counts["medium"], f.counts["high"])
        for f in inspect_text(message, units)
    ]
    return await findings.insert_message_findings(session, transfer_id, found)
