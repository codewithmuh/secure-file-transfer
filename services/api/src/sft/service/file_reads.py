"""Reading one file: `getFile` and `getFileInspection` (FR-16, FR-18, FR-19, FR-36, FR-47; data
model 3.1, 3.5).

**Who sees a file** (authn and authz 6.3, 6.4): the member who owns its transfer or, for a file
received through an upload request (#213), the request; an admin acting as one (Tenant); and an
API key whose scope matches the file's owner: `transfers:read` for a file of a transfer,
`upload_requests:read` for a received file. A key with only the other scope gets 404, as if the
file didn't exist. Everyone else gets 404, and a file its owner deleted is gone. Admins and keys
see counts only (FR-53). A received file also shows its `retention_until` (FR-13).

**What a file shows:** its state, whether it is shareable (an `unscannable` file allowed by the
tenant's policy is, with FR-18's warning shown from its state), `scan_detail` for a file the scan
couldn't clear, and its inspection: the state, the reasons and the detectors that matched.

**`getFileInspection`** adds the engine and policy versions and one finding per detector, counts
only. Location hints and masked previews arrive encrypted with DLP-8, so `details_visible` is false
for everyone until then, and no response holds details to audit.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sft.core.errors import NotFound
from sft.data import dlp_policy, files, findings, transfers, upload_requests
from sft.data.access import NotFoundError
from sft.data.database import Database
from sft.data.models import File, InspectionReason, InspectionState
from sft.service.caller import Caller
from sft.service.permissions import authorize
from sft.service.received import key_scope_matches
from sft.service.transfers import FileView, file_view, require_visible, tenant_scope
from sft.service.upload_requests import require_visible as require_request_visible

TRANSFERS_READ: Final = "transfers:read"
"""The scope a key needs to read a transfer's files and its DLP decision (`getTransferDlp`)."""

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
named by their admins (#218): `custom:<id>` findings show the name of the detector's latest
revision."""


def detector_name(detector: str, language: str) -> str:
    names = DETECTOR_NAMES.get(detector)
    if names is None:
        return detector
    return names[1] if language == "ja" else names[0]


async def _visible_file(
    database: Database, caller: Caller, file_id: UUID, operation: str, now: datetime
) -> tuple[File, list[findings.Counts], dict[str, str]]:
    reach = authorize(caller, operation, now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            file = await files.get_file(session, file_id)
            if not key_scope_matches(caller, file, write=False):
                # The file of a transfer needs `transfers:read`, a received one
                # `upload_requests:read`: a key with only the other scope sees nothing.
                raise NotFound
            if file.upload_request_id is not None:
                request = await upload_requests.get_request(session, file.upload_request_id)
                require_request_visible(caller, reach, request)
            elif file.transfer_id is not None:
                transfer = await transfers.get_transfer(session, file.transfer_id)
                require_visible(caller, reach, transfer)
            else:  # pragma: no cover - the owner check holds exactly one
                raise NotFound
        except NotFoundError:
            raise NotFound from None
        if file.removed_at is not None:
            # Removed from its transfer (`deleteFile`): gone, as for every upload call.
            raise NotFound
        found = await findings.file_findings(session, file.id)
        own = {}
        for counts in found:
            if counts.detector.startswith(dlp_policy.CUSTOM_PREFIX):
                with contextlib.suppress(ValueError):
                    own[UUID(counts.detector.removeprefix(dlp_policy.CUSTOM_PREFIX))] = counts
        names = await dlp_policy.detector_names(session, list(own))
        return file, found, {dlp_policy.detector_ref(i): name for i, name in names.items()}


async def get_file(database: Database, caller: Caller, file_id: UUID, *, now: datetime) -> FileView:
    """`getFile`: the file's state, shareability, scan detail and inspection summary."""
    tenant_id = tenant_scope(caller).tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    file, found, _ = await _visible_file(database, caller, file_id, "getFile", now)
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
    file, found, names = await _visible_file(database, caller, file_id, "getFileInspection", now)
    state = InspectionState(file.inspection_state)
    return InspectionView(
        file_id=file.id,
        state=state,
        reasons=tuple(InspectionReason(r) for r in file.inspection_reasons),
        dlp_blocked=file.dlp_blocked,  # received files only (FR-51): false until #221
        engine_version=file.inspection_engine_version,
        policy_version=file.inspection_policy_version,
        inspected_at=None if state is InspectionState.PENDING else file.scanned_at,
        findings=tuple(
            FindingView(
                detector=c.detector,
                detector_name=names.get(c.detector) or detector_name(c.detector, language),
                count_low=c.low,
                count_medium=c.medium,
                count_high=c.high,
            )
            for c in found
        ),
    )
