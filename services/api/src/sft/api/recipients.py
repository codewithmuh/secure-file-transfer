"""The recipient operations of the contract: `listTransferRecipients` (#178) and `unlockRecipient`
(#179); docs/api/openapi.yaml, tag "Transfers".

Routes only parse the request and shape the response; `sft.service.recipients` checks the caller
and applies the rules. The caller is a member session or an API key (`get_tenant_caller`).

Rate limits (abuse and rate limits 2.2): `listTransferRecipients` is group H (`TENANT_OPERATION`);
`unlockRecipient` is a safety action, which only the caller's own limit applies to
(`SAFETY_ACTION`), so a runaway automation can't keep an admin from unlocking. An unlock is a
security-critical record (#177): `200` only once both regions' audit archive hold it, `503`
otherwise, with the unlock kept.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_audit_archive, get_database
from sft.api.errors import problem_responses
from sft.api.link_schemas import RecipientStatus, RecipientStatusList
from sft.api.rate_limits import rate_limit
from sft.data.database import Database
from sft.service import recipients
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.rate_limits.limits import SAFETY_ACTION, TENANT_OPERATION

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
ArchiveDep = Annotated[AuditArchive, Depends(get_audit_archive)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
SAFETY_LIMITS: Final = rate_limit(SAFETY_ACTION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX)


def _now() -> datetime:
    return datetime.now(UTC)


@router.get(
    "/transfers/{transfer_id}/recipients",
    operation_id="listTransferRecipients",
    response_model=RecipientStatusList,
    summary="Get per-recipient status",
    tags=["Transfers"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def list_transfer_recipients(
    transfer_id: UUID, caller: CallerDep, database: DatabaseDep
) -> RecipientStatusList:
    """Each recipient's delivery, verification, lockout and downloads (FR-7)."""
    rows = await recipients.list_recipients(database, caller, transfer_id, now=_now())
    return RecipientStatusList(items=[RecipientStatus.of(r) for r in rows])


@router.post(
    "/transfers/{transfer_id}/recipients/{recipient_id}/unlock",
    operation_id="unlockRecipient",
    response_model=RecipientStatus,
    summary="Unlock a locked-out recipient",
    tags=["Transfers"],
    dependencies=[SAFETY_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429, 503),
)
async def unlock_recipient(
    transfer_id: UUID,
    recipient_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    archive: ArchiveDep,
) -> RecipientStatus:
    """Unlock the recipient and issue a new link (NFR-14, authn and authz 4.4)."""
    row = await recipients.unlock_recipient(
        database,
        caller,
        transfer_id,
        recipient_id,
        archive=archive,
        origin=origin_of(request),
        now=_now(),
    )
    return RecipientStatus.of(row)


def register(app: FastAPI) -> None:
    """Add the recipient routes to the public app."""
    app.include_router(router)
