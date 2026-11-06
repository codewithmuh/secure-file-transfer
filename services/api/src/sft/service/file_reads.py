"""Reading one file: `getFile` and `getFileInspection` (FR-16, FR-18, FR-19, FR-36, FR-47; data
model 3.1, 3.5).

**Who sees a file** (authn and authz 6.3, 6.4): the member who owns its transfer, an admin acting
as one (Tenant), and an API key whose scope matches the file's owner: `transfers:read` for a file
of a transfer. A key with only `upload_requests:read` gets 404 for it, as if the file didn't exist.
Everyone else gets 404. Admins and keys see counts only (FR-53).

**What a file shows:** its state, whether it is shareable (an `unscannable` file allowed by the
tenant's policy is, with FR-18's warning shown from its state), `scan_detail` for a file the scan
couldn't clear, and its inspection: the state, the reasons and the detectors that matched.

**`getFileInspection`** adds the engine and policy versions and one finding per detector, counts
only. Location hints and masked previews arrive encrypted with DLP-8, so `details_visible` is false
for everyone until then, and no response holds details to audit.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sft.core.errors import NotFound
from sft.data import files, findings, transfers
from sft.data.access import NotFoundError
from sft.data.database import Database
from sft.data.models import File, InspectionReason, InspectionState
from sft.service.caller import Caller, CallerKind
from sft.service.permissions import authorize
from sft.service.transfers import FileView, file_view, require_visible, tenant_scope

TRANSFERS_READ: Final = "transfers:read"

DETECTOR_NAMES: Final[Mapping[str, tuple[str, str]]] = {
    "jp_my_number": ("My Number (Individual Number)", "マイナンバー・個人番号"),
    "jp_corporate_number": ("Corporate Number", "法人番号"),
    "payment_card": ("Payment card number", "クレジットカード番号"),
    "jp_bank_account": ("Japanese bank account", "銀行口座番号"),
    "iban": ("IBAN", "IBAN"),
    "phone_number": ("Phone number", "電話番号"),
    "email_address": ("Email address", "メールアドレス"),
    "jp_passport": ("Japanese passport number", "旅券番号"),
    "passport_mrz": ("Passport machine-readable zone", "旅券の機械読取領域"),
    "jp_drivers_licence": ("Japanese driver's licence number", "運転免許証番号"),
    "cloud_credential": ("Cloud credential", "クラウドの認証情報"),
    "private_key": ("Private key", "秘密鍵"),
    "confidentiality_label": ("Confidentiality label", "機密表示"),
}
"""Built-in detectors' names in English and Japanese (detectors 4). A tenant's own detectors are
named by their admins, with DLP-4."""


def detector_name(detector: str, language: str) -> str:
    names = DETECTOR_NAMES.get(detector)
    if names is None:
        return detector
    return names[1] if language == "ja" else names[0]


async def _visible_file(
    database: Database, caller: Caller, file_id: UUID, operation: str, now: datetime
) -> tuple[File, list[findings.Counts]]:
    reach = authorize(caller, operation, now=now)
    if caller.kind is CallerKind.API_KEY and TRANSFERS_READ not in caller.scopes:
        # The file of a transfer needs `transfers:read`; `upload_requests:read` reaches received
        # files only, which arrive with upload requests.
        raise NotFound
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            file = await files.get_file(session, file_id)
            transfer = await transfers.get_transfer(session, file.transfer_id)
        except NotFoundError:
            raise NotFound from None
        require_visible(caller, reach, transfer)
        if file.removed_at is not None:
            # Removed from its transfer (`deleteFile`): gone, as for every upload call.
            raise NotFound
        found = await findings.file_findings(session, file.id)
        return file, found


async def get_file(database: Database, caller: Caller, file_id: UUID, *, now: datetime) -> FileView:
    """`getFile`: the file's state, shareability, scan detail and inspection summary."""
    tenant_id = tenant_scope(caller).tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    file, found = await _visible_file(database, caller, file_id, "getFile", now)
    return file_view(tenant_id, file, [c.detector for c in found])


@dataclass(frozen=True, slots=True)
class FindingView:
    detector: str
    detector_name: str
    count_low: int
    count_medium: int
    count_high: int
    details_visible: bool = False


@dataclass(frozen=True, slots=True)
class InspectionView:
    file_id: UUID
    state: InspectionState
    reasons: tuple[InspectionReason, ...]
    dlp_blocked: bool
    engine_version: str | None
    policy_version: int | None
    inspected_at: datetime | None
    findings: tuple[FindingView, ...]


async def get_file_inspection(
    database: Database, caller: Caller, file_id: UUID, *, language: str, now: datetime
) -> InspectionView:
    """`getFileInspection`: the inspection's result and its findings, counts only."""
    file, found = await _visible_file(database, caller, file_id, "getFileInspection", now)
    state = InspectionState(file.inspection_state)
    return InspectionView(
        file_id=file.id,
        state=state,
        reasons=tuple(InspectionReason(r) for r in file.inspection_reasons),
        dlp_blocked=False,  # received files only (FR-51), with upload requests
        engine_version=file.inspection_engine_version,
        policy_version=file.inspection_policy_version,
        inspected_at=None if state is InspectionState.PENDING else file.scanned_at,
        findings=tuple(
            FindingView(
                detector=c.detector,
                detector_name=detector_name(c.detector, language),
                count_low=c.low,
                count_medium=c.medium,
                count_high=c.high,
            )
            for c in found
        ),
    )
