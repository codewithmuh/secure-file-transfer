"""The upload-request operations of the contract: `createUploadRequest`, `listUploadRequests`,
`getUploadRequest`, `revokeUploadRequest` and `unlockUploader` (#212; UC-2; docs/api/openapi.yaml,
tag "Upload requests"). `listUploadRequestFiles` arrives with received files (#213).

Routes only parse the request and shape the response; `sft.service.upload_requests` checks the
caller with `authorize` and applies the rules. The caller is a member session or an API key
(`get_tenant_caller`).

Rate limits (abuse and rate limits 2.2): every operation is group H (`TENANT_OPERATION`) but the
two safety actions, `revokeUploadRequest` and `unlockUploader`, which only the caller's own limit
applies to (`SAFETY_ACTION`), so a runaway automation can't keep an admin from revoking or
unlocking. `createUploadRequest` also applies group G's email caps in the service, shared with
`sendTransfer`. Both safety actions are security-critical records (#177): `200` only once both
regions' audit archive hold it, `503` otherwise, with the change kept.

`createUploadRequest` takes `Idempotency-Key` (`sft.api.idempotency`, API README 5): a retry with
the same key and body gets the first answer, a `201` with its `Location`, and creates nothing.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_audit_archive, get_database, get_email_keyring, now_of
from sft.api.errors import problem_responses
from sft.api.idempotency import IdempotencyDep
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.api.upload_request_schemas import (
    UploadRequestCreate,
    UploadRequestOut,
    UploadRequestPageOut,
    UploadRequestStateName,
)
from sft.core.pseudonyms import EmailKeyring
from sft.data.database import Database
from sft.data.models import UploadRequestState
from sft.service import upload_requests
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import SAFETY_ACTION, TENANT_OPERATION
from sft.service.transfers import MAX_PAGE

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
EmailKeyringDep = Annotated[EmailKeyring, Depends(get_email_keyring)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
ArchiveDep = Annotated[AuditArchive, Depends(get_audit_archive)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
SAFETY_LIMITS: Final = rate_limit(SAFETY_ACTION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX)


@router.post(
    "/upload-requests",
    operation_id="createUploadRequest",
    status_code=201,
    response_model=UploadRequestOut,
    summary="Create an upload request",
    tags=["Upload requests"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 409, 422, 429),
)
async def create_upload_request(
    body: UploadRequestCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    emails: EmailKeyringDep,
    limiter: LimiterDep,
    idempotency: IdempotencyDep,
) -> UploadRequestOut:
    """Ask one outside address for files; the link is emailed (FR-10, FR-3, FR-33)."""
    outcome = await upload_requests.create_upload_request(
        database,
        caller,
        upload_requests.NewUploadRequest(
            email=body.uploader_email,
            locale=body.locale,
            expires_at=body.expires_at,
            message=body.message,
        ),
        emails=emails,
        limiter=limiter,
        origin=origin_of(request),
        now=now_of(request),
        idempotency=idempotency,
    )
    response.status_code = outcome.status
    response.headers["Location"] = f"{PREFIX}/upload-requests/{outcome.value.id}"
    return UploadRequestOut.of(outcome.value)


@router.get(
    "/upload-requests",
    operation_id="listUploadRequests",
    response_model=UploadRequestPageOut,
    summary="List upload requests",
    tags=["Upload requests"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 429),
)
async def list_upload_requests(
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    scope: Literal["own", "tenant"] = "own",
    state: Annotated[
        list[UploadRequestStateName] | None,
        Query(max_length=3, json_schema_extra={"uniqueItems": True}),
    ] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 25,
) -> UploadRequestPageOut:
    """One page of upload requests, newest first (FR-10, FR-20)."""
    page = await upload_requests.list_upload_requests(
        database,
        caller,
        tenant_wide=scope == "tenant",
        states=[UploadRequestState(s) for s in state or ()],
        cursor=cursor,
        limit=limit,
        now=now_of(request),
    )
    return UploadRequestPageOut.of(page)


@router.get(
    "/upload-requests/{upload_request_id}",
    operation_id="getUploadRequest",
    response_model=UploadRequestOut,
    summary="Get an upload request",
    tags=["Upload requests"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def get_upload_request(
    upload_request_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> UploadRequestOut:
    """The request, with whether the uploader verified or is locked (FR-10, FR-12, NFR-14)."""
    view = await upload_requests.get_upload_request(
        database, caller, upload_request_id, now=now_of(request)
    )
    return UploadRequestOut.of(view)


@router.post(
    "/upload-requests/{upload_request_id}/revoke",
    operation_id="revokeUploadRequest",
    response_model=UploadRequestOut,
    summary="Revoke an upload request",
    tags=["Upload requests"],
    dependencies=[SAFETY_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429, 503),
)
async def revoke_upload_request(
    upload_request_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    archive: ArchiveDep,
) -> UploadRequestOut:
    """Stop the request at once; `200` once the record is in both regions' archive (FR-20)."""
    view = await upload_requests.revoke_upload_request(
        database, archive, caller, upload_request_id, origin=origin_of(request), now=now_of(request)
    )
    return UploadRequestOut.of(view)


@router.post(
    "/upload-requests/{upload_request_id}/unlock",
    operation_id="unlockUploader",
    response_model=UploadRequestOut,
    summary="Unlock a locked-out uploader",
    tags=["Upload requests"],
    dependencies=[SAFETY_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429, 503),
)
async def unlock_uploader(
    upload_request_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    archive: ArchiveDep,
) -> UploadRequestOut:
    """Unlock the uploader and issue a new link (NFR-14, authn and authz 4.4)."""
    view = await upload_requests.unlock_uploader(
        database, archive, caller, upload_request_id, origin=origin_of(request), now=now_of(request)
    )
    return UploadRequestOut.of(view)


def register(app: FastAPI) -> None:
    """Add the upload-request routes to the public app."""
    app.include_router(router)
