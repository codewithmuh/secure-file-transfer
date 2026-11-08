"""The received-file operations of the contract (#213; UC-2; docs/api/openapi.yaml, tags "Recipient
session", "Upload requests" and "Files").

- **The uploader's**, on their link session: `addSessionUploadFile` (with `Idempotency-Key`),
  `requestSessionUploadPartUrls`, `listSessionUploadedParts`, `completeSessionUpload` and
  `deleteSessionUploadFile` (#229, the uploader takes a file back). As every
  `/session` call, `X-Link-Session` names the session, the `__Host-sft_link` cookie must hold it,
  and an unsafe method passes the CSRF checks with that session's token
  (`sft.api.links.get_link_session`); a revoked or expired request is `410`. Group F per link
  session and per IP (`SESSION_UPLOAD`); an uploader spends none of the tenant's budget.
- **The member's**: `listUploadRequestFiles` (group H) and `createReceivedFileDownload`, with
  `getReceivedFileDownloadContent` by navigation: no CSRF header, authorised by the grant ID and the
  member session cookie that made the grant. Group D and E are the service's, which knows the
  member, the file and the tenant.

Routes only speak HTTP; the rules are `sft.service.received`'s and `sft.service.downloads`'s.
"""

from __future__ import annotations

from typing import Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database, get_objects, get_upload_policy, now_of
from sft.api.downloads import (
    _BINARY,
    _RANGE_PATTERN,
    DownloadAccess,
    DownloadRequest,
    ServicesDep,
    _ContentResponse,
)
from sft.api.errors import problem_responses
from sft.api.idempotency import IdempotencyDep
from sft.api.link_schemas import SessionFileOut
from sft.api.links import NO_STORE, SESSION_HEADER, LinkDep, get_link_session_caller
from sft.api.rate_limits import client_ip, get_rate_limiter, rate_limit
from sft.api.transfer_schemas import (
    File,
    FileCreate,
    PartUrl,
    PartUrlList,
    PartUrlRequest,
    UploadedParts,
)
from sft.data.database import Database
from sft.service import downloads, received, uploads
from sft.service.caller import Caller
from sft.service.objects import ObjectStore
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import SESSION_UPLOAD, TENANT_OPERATION

PREFIX: Final = "/v1"

DatabaseDep = Annotated[Database, Depends(get_database)]
ObjectsDep = Annotated[ObjectStore, Depends(get_objects)]
PolicyDep = Annotated[uploads.UploadPolicy, Depends(get_upload_policy)]
CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
UPLOAD_LIMITS: Final = rate_limit(SESSION_UPLOAD, caller=get_link_session_caller)
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)

_SESSION_PARAMETER: Final[dict[str, Any]] = {
    "parameters": [
        {
            "name": SESSION_HEADER,
            "in": "header",
            "required": True,
            "schema": {"type": "string", "format": "uuid"},
        }
    ]
}

router = APIRouter(prefix=PREFIX)


class FileList(BaseModel):
    """The contract's `FileList`: a request receives at most 50 files."""

    model_config = ConfigDict(title="FileList")

    items: list[File] = Field(max_length=50)


# ---- the uploader's upload ----


@router.post(
    "/session/files",
    operation_id="addSessionUploadFile",
    status_code=201,
    response_model=SessionFileOut,
    response_model_exclude_unset=True,
    summary="Add a file to an upload request",
    tags=["Recipient session"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(400, 401, 403, 409, 410, 413, 422, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def add_session_upload_file(
    body: FileCreate,
    request: Request,
    response: Response,
    link: LinkDep,
    database: DatabaseDep,
    objects: ObjectsDep,
    policy: PolicyDep,
    idempotency: IdempotencyDep,
    limiter: LimiterDep,
) -> SessionFileOut:
    """Declare a file and start its multipart upload (FR-11)."""
    outcome = await received.add_session_file(
        database,
        objects,
        link.caller,
        uploads.FileRequest(body.display_name, body.size, body.content_type),
        policy=policy,
        limiter=limiter,
        origin=origin_of(request),
        now=now_of(request),
        idempotency=idempotency,
    )
    response.status_code = outcome.status
    response.headers.update(NO_STORE)
    return SessionFileOut.of(outcome.value)


@router.post(
    "/session/files/{file_id}/parts",
    operation_id="requestSessionUploadPartUrls",
    response_model=PartUrlList,
    summary="Get upload URLs for parts of an uploader's file",
    tags=["Recipient session"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 410, 422, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def request_session_upload_part_urls(
    file_id: UUID,
    body: PartUrlRequest,
    request: Request,
    response: Response,
    link: LinkDep,
    database: DatabaseDep,
    objects: ObjectsDep,
) -> PartUrlList:
    """Pre-signed part URLs, each for one part's exact size, valid 15 minutes (FR-11, NFR-3)."""
    urls = await received.session_part_urls(
        database,
        objects,
        link.caller,
        file_id,
        body.part_numbers,
        origin=origin_of(request),
        now=now_of(request),
    )
    response.headers.update(NO_STORE)
    return PartUrlList(parts=[PartUrl.of(u) for u in urls])


@router.get(
    "/session/files/{file_id}/parts",
    operation_id="listSessionUploadedParts",
    response_model=UploadedParts,
    summary="List the parts of an uploader's file already uploaded",
    tags=["Recipient session"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 410, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def list_session_uploaded_parts(
    file_id: UUID,
    request: Request,
    response: Response,
    link: LinkDep,
    database: DatabaseDep,
    objects: ObjectsDep,
) -> UploadedParts:
    """The parts object storage already holds, to resume an upload (FR-11, NFR-3)."""
    found = await received.session_uploaded_parts(
        database, objects, link.caller, file_id, now=now_of(request)
    )
    response.headers.update(NO_STORE)
    return UploadedParts.of(found)


@router.post(
    "/session/files/{file_id}/complete",
    operation_id="completeSessionUpload",
    response_model=SessionFileOut,
    response_model_exclude_unset=True,
    summary="Complete an uploader's file upload",
    tags=["Recipient session"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 410, 413, 422, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def complete_session_upload(
    file_id: UUID,
    request: Request,
    response: Response,
    link: LinkDep,
    database: DatabaseDep,
    objects: ObjectsDep,
    policy: PolicyDep,
) -> SessionFileOut:
    """Complete the upload in three phases under the request's lock (FR-11, FR-16, NFR-6)."""
    view = await received.complete_session_upload(
        database,
        objects,
        link.caller,
        file_id,
        origin=origin_of(request),
        now=now_of(request),
        small_pool_max=policy.small_pool_max,
    )
    response.headers.update(NO_STORE)
    return SessionFileOut.of(view)


@router.delete(
    "/session/files/{file_id}",
    operation_id="deleteSessionUploadFile",
    status_code=204,
    response_class=Response,
    summary="Remove an uploader's file",
    tags=["Recipient session"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 410, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def delete_session_upload_file(
    file_id: UUID, request: Request, link: LinkDep, database: DatabaseDep
) -> Response:
    """Take back a file declared or uploaded to an open request; it no longer counts (#229)."""
    await received.delete_session_file(
        database, link.caller, file_id, origin=origin_of(request), now=now_of(request)
    )
    return Response(status_code=204, headers=NO_STORE)


# ---- the member's side ----


@router.get(
    "/upload-requests/{upload_request_id}/files",
    operation_id="listUploadRequestFiles",
    response_model=FileList,
    response_model_exclude_unset=True,
    summary="List files received through an upload request",
    tags=["Upload requests"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def list_upload_request_files(
    upload_request_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> FileList:
    """Every file the uploader sent, with its state and `retention_until` (FR-12, FR-13)."""
    found = await received.list_request_files(
        database, caller, upload_request_id, now=now_of(request)
    )
    return FileList(items=[File.of(view) for view in found])


@router.post(
    "/files/{file_id}/downloads",
    operation_id="createReceivedFileDownload",
    response_model=DownloadAccess,
    response_model_exclude_unset=True,
    summary="Download a received file",
    tags=["Files"],
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429, 503),
)
async def create_received_file_download(
    file_id: UUID,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    services: ServicesDep,
    body: DownloadRequest | None = None,
) -> DownloadAccess:
    """A grant of one shareable received file to its request's owner (FR-12, FR-17)."""
    view = await downloads.create_received_download(
        database,
        services,
        caller,
        file_id,
        resume_grant_id=None if body is None else body.resume_grant_id,
        ip=client_ip(request),
        origin=origin_of(request),
        now=now_of(request),
    )
    response.headers.update(NO_STORE)
    return DownloadAccess.of(view)


@router.get(
    "/files/{file_id}/downloads/{grant_id}/content",
    operation_id="getReceivedFileDownloadContent",
    response_class=StreamingResponse,
    summary="Fetch the bytes of a received file",
    tags=["Files"],
    responses={
        200: {"description": "The whole file, streamed.", "content": _BINARY},
        206: {"description": "The requested range of the file, streamed.", "content": _BINARY},
        **problem_responses(401, 403, 404, 416, 429, 503),
    },
    openapi_extra={
        "parameters": [
            {
                "name": "Range",
                "in": "header",
                "required": False,
                "schema": {"type": "string", "maxLength": 100, "pattern": _RANGE_PATTERN},
            },
            {
                "name": "If-Range",
                "in": "header",
                "required": False,
                "schema": {"type": "string", "maxLength": 100},
            },
        ]
    },
)
async def get_received_file_download_content(
    file_id: UUID,
    grant_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    services: ServicesDep,
) -> StreamingResponse:
    """The file's bytes under a grant, by navigation, with the member session cookie."""
    download = await downloads.open_received_content(
        database,
        services,
        caller,
        file_id,
        grant_id,
        range_header=request.headers.get("range"),
        if_range=request.headers.get("if-range"),
        ip=client_ip(request),
        now=now_of(request),
    )
    return _ContentResponse(download)


def register(app: FastAPI) -> None:
    """Add the received-file routes to the public app."""
    app.include_router(router)
