"""Reading one file: `getFile` and `getFileInspection` (FR-16, FR-18, FR-19, FR-36, FR-47; data
model 3.1, 3.5).

**Who sees a file** (authn and authz 6.3, 6.4): the member who owns its transfer or, for a file
received through an upload request (#213), the request; an admin acting as one (Tenant); and an
API key whose scope matches the file's owner: `transfers:read` for a file of a transfer,
`upload_requests:read` for a received file. A key with only the other scope gets 404, as if the
file didn't exist. Everyone else gets 404, and a file its owner deleted is gone. Admins and keys
see counts only (FR-53). A received file also shows its `retention_until` (FR-13). For
`getFileInspection` alone, as for `getTransferDlp`, an active approver also reaches a file of a
transfer that has an approval request (#233), to see what they decide on.

**What a file shows:** its state, whether it is shareable (an `unscannable` file allowed by the
tenant's policy is, with FR-18's warning shown from its state), `scan_detail` for a file the scan
couldn't clear, and its inspection: the state, the reasons and the detectors that matched.

**`getFileInspection`** adds the engine and policy versions and one finding per detector, with its
location hints and masked previews for the file's owner and the transfer's approvers
(`sft.service.finding_details`, #233); everyone else gets counts with `details_visible: false`. A
response with details writes `dlp_findings.details_read`.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import NotFound
from sft.data import dlp_approvals, dlp_policy, files, findings, transfers, upload_requests
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import File, InspectionReason, InspectionState
from sft.service import fields, finding_details
from sft.service.approval_requests import active_approver
from sft.service.caller import Caller, CallerKind
from sft.service.finding_details import Details, Location
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


@dataclass(frozen=True, slots=True)
class _Visible:
    file: File
    found: list[findings.Counts]
    names: dict[str, str]
    keys: fields.TenantKeys
    details: dict[tuple[UUID, str], Details] | None
    """None when the caller sees counts only (FR-53)."""


async def _visible_file(
    database: Database,
    caller: Caller,
    file_id: UUID,
    operation: str,
    now: datetime,
    *,
    details: bool = False,
    origin: Origin | None = None,
) -> _Visible:
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
                owner = request.created_by
            elif file.transfer_id is not None:
                transfer = await transfers.get_transfer(session, file.transfer_id)
                try:
                    require_visible(caller, reach, transfer)
                except NotFound:
                    # As `getTransferDlp`: an approver reaches a transfer with an approval request.
                    if not (details and await _approver_reaches(session, caller, transfer.id)):
                        raise
                owner = transfer.created_by
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
        keys = await fields.tenant_keys(session, file.tenant_id)
        shown = None
        if details and await finding_details.may_see(
            session, caller, owner=owner, transfer_id=file.transfer_id
        ):
            shown = await finding_details.read(session, [file.id])
            await finding_details.record_read(
                session, caller, Target("file", file.id), len(shown), origin
            )
        return _Visible(
            file, found, {dlp_policy.detector_ref(i): n for i, n in names.items()}, keys, shown
        )


async def _approver_reaches(session: AsyncSession, caller: Caller, transfer_id: UUID) -> bool:
    if caller.kind is not CallerKind.MEMBER:
        return False
    if await dlp_approvals.latest_request(session, transfer_id) is None:
        return False
    return await active_approver(session, caller.user_id)


async def get_file(database: Database, caller: Caller, file_id: UUID, *, now: datetime) -> FileView:
    """`getFile`: the file's state, shareability, scan detail and inspection summary."""
    seen = await _visible_file(database, caller, file_id, "getFile", now)
    return file_view(seen.keys, seen.file, [c.detector for c in seen.found])


@dataclass(frozen=True, slots=True)
class FindingView:
    detector: str
    detector_name: str
    count_low: int
    count_medium: int
    count_high: int
    details_visible: bool = False
    locations: tuple[Location, ...] | None = None
    """With details only (#233); None, left out of the response, otherwise."""
    previews: tuple[str, ...] | None = None


def finding_view(
    counts: findings.Counts,
    name: str,
    details: dict[tuple[UUID, str], Details] | None,
    file_id: UUID | None,
) -> FindingView:
    """One finding as the contract shows it: with its details when the caller may see them and
    they are still there (cleared with the file's contents). A message's findings (`file_id`
    None, FR-50) have none."""
    found = None if details is None or file_id is None else details.get((file_id, counts.detector))
    return FindingView(
        detector=counts.detector,
        detector_name=name,
        count_low=counts.low,
        count_medium=counts.medium,
        count_high=counts.high,
        details_visible=found is not None,
        locations=None if found is None else found.locations,
        previews=None if found is None else found.previews,
    )


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
    database: Database,
    caller: Caller,
    file_id: UUID,
    *,
    language: str,
    now: datetime,
    origin: Origin | None = None,
) -> InspectionView:
    """`getFileInspection`: the inspection's result and its findings, with details for the owner
    and the approvers (module docstring)."""
    seen = await _visible_file(
        database, caller, file_id, "getFileInspection", now, details=True, origin=origin
    )
    file, found, names = seen.file, seen.found, seen.names
    state = InspectionState(file.inspection_state)
    return InspectionView(
        file_id=file.id,
        state=state,
        reasons=tuple(InspectionReason(r) for r in file.inspection_reasons),
        dlp_blocked=file.dlp_blocked,  # received files only (FR-51, #221)
        engine_version=file.inspection_engine_version,
        policy_version=file.inspection_policy_version,
        inspected_at=None if state is InspectionState.PENDING else file.scanned_at,
        findings=tuple(
            finding_view(
                c,
                names.get(c.detector) or detector_name(c.detector, language),
                seen.details,
                file.id,
            )
            for c in found
        ),
    )
