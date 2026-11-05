"""The draft transfer and upload operations of the contract: `createTransfer`, `addTransferFile`,
`requestUploadPartUrls`, `listUploadedParts`, `completeUpload` and `deleteFile` (#114;
architecture 4.1; docs/api/openapi.yaml, tags "Transfers" and "Files").

Routes only parse the request and shape the response. The service layer (`sft.service.transfers`,
`sft.service.uploads`) checks the caller with `authorize` and applies the state rules. Its refusals
are `sft.core.errors` exceptions, which `sft.api.errors` answers as problem documents; each route
declares the error answers the contract gives it (`problem_responses`).

The caller is a member session or an API key (`get_tenant_caller`, #113). The object store and the
upload policy come from the app's lifespan (`sft.api.dependencies`).

Rate limits (abuse and rate limits 2.2): `createTransfer` and `deleteFile` are group H
(`TENANT_OPERATION`). The four upload operations are group F (`UPLOAD`): the caller's and the IP's
upload budgets, and the tenant's group H budget, which counts groups D to K too.

`createTransfer` and `addTransferFile` take `Idempotency-Key` (`sft.api.idempotency`, API README
5): a retry with the same key and body gets the first `201`, its `Location` and the resource as it
is now, and creates nothing again.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request, Response

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database, get_objects, get_upload_policy
from sft.api.errors import problem_responses
from sft.api.idempotency import IdempotencyDep
from sft.api.rate_limits import rate_limit
from sft.api.transfer_schemas import (
    File,
    FileCreate,
    PartUrl,
    PartUrlList,
    PartUrlRequest,
    Transfer,
    TransferCreate,
    UploadedParts,
)
from sft.data.database import Database
from sft.service import transfers, uploads
from sft.service.caller import Caller
from sft.service.objects import ObjectStore
from sft.service.rate_limits.limits import TENANT_OPERATION, UPLOAD

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
ObjectsDep = Annotated[ObjectStore, Depends(get_objects)]
PolicyDep = Annotated[uploads.UploadPolicy, Depends(get_upload_policy)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
UPLOAD_LIMITS: Final = rate_limit(UPLOAD, caller=get_tenant_caller)


def _now() -> datetime:
    return datetime.now(UTC)


router = APIRouter(prefix=PREFIX)


@router.post(
    "/transfers",
    operation_id="createTransfer",
    status_code=201,
    response_model=Transfer,
    response_model_exclude_unset=True,
    summary="Create a draft transfer",
    tags=["Transfers"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 409, 422, 429),
)
async def create_transfer(
    body: TransferCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    idempotency: IdempotencyDep,
) -> Transfer:
    """Create a transfer as a draft, with its recipients (FR-1, FR-3, FR-4)."""
    wanted = transfers.TransferRequest(
        recipients=[transfers.RecipientRequest(r.email, r.locale) for r in body.recipients],
        expires_in=body.expires_in,
        message=body.message,
        download_limit=body.download_limit,
        notify_on_first_download=body.notify_on_first_download,
    )
    outcome = await transfers.create_transfer(
        database, caller, wanted, origin=origin_of(request), now=_now(), idempotency=idempotency
    )
    response.status_code = outcome.status
    response.headers["Location"] = f"{PREFIX}/transfers/{outcome.value.id}"
    return Transfer.of(outcome.value)


@router.post(
    "/transfers/{transfer_id}/files",
    operation_id="addTransferFile",
    status_code=201,
    response_model=File,
    response_model_exclude_unset=True,
    summary="Declare a file and start its upload",
    tags=["Files"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 413, 422, 429),
)
async def add_transfer_file(
    transfer_id: UUID,
    body: FileCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    objects: ObjectsDep,
    policy: PolicyDep,
    idempotency: IdempotencyDep,
) -> File:
    """Declare a file and start its multipart upload (FR-1, FR-2)."""
    outcome = await uploads.add_file(
        database,
        objects,
        caller,
        transfer_id,
        uploads.FileRequest(body.display_name, body.size, body.content_type),
        policy=policy,
        origin=origin_of(request),
        now=_now(),
        idempotency=idempotency,
    )
    response.status_code = outcome.status
    response.headers["Location"] = f"{PREFIX}/files/{outcome.value.id}"
    return File.of(outcome.value)


@router.post(
    "/files/{file_id}/parts",
    operation_id="requestUploadPartUrls",
    response_model=PartUrlList,
    summary="Get pre-signed part URLs",
    tags=["Files"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429),
)
async def request_upload_part_urls(
    file_id: UUID,
    body: PartUrlRequest,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    objects: ObjectsDep,
) -> PartUrlList:
    """Pre-signed part URLs, each for one part's exact size, valid 15 minutes (FR-2, NFR-3)."""
    urls = await uploads.part_urls(
        database,
        objects,
        caller,
        file_id,
        body.part_numbers,
        origin=origin_of(request),
        now=_now(),
    )
    return PartUrlList(parts=[PartUrl.of(u) for u in urls])


@router.get(
    "/files/{file_id}/parts",
    operation_id="listUploadedParts",
    response_model=UploadedParts,
    summary="List the parts already uploaded",
    tags=["Files"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429),
)
async def list_uploaded_parts(
    file_id: UUID, caller: CallerDep, database: DatabaseDep, objects: ObjectsDep
) -> UploadedParts:
    """The parts object storage already holds, to resume an upload (FR-2, NFR-3)."""
    found = await uploads.uploaded_parts(database, objects, caller, file_id, now=_now())
    return UploadedParts.of(found)


@router.post(
    "/files/{file_id}/complete",
    operation_id="completeUpload",
    response_model=File,
    response_model_exclude_unset=True,
    summary="Complete an upload",
    tags=["Files"],
    dependencies=[UPLOAD_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 413, 422, 429),
)
async def complete_upload(
    file_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    objects: ObjectsDep,
) -> File:
    """Complete the upload in three phases; the file moves to `scanning` (FR-2, FR-16)."""
    view = await uploads.complete_upload(
        database, objects, caller, file_id, origin=origin_of(request), now=_now()
    )
    return File.of(view)


@router.delete(
    "/files/{file_id}",
    operation_id="deleteFile",
    status_code=204,
    response_class=Response,
    summary="Remove a file from a draft",
    tags=["Files"],
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429),
)
async def delete_file(
    file_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> Response:
    """Remove a file from a draft transfer (FR-5, data model 3.2)."""
    await uploads.delete_file(database, caller, file_id, origin=origin_of(request), now=_now())
    return Response(status_code=204)


def register(app: FastAPI) -> None:
    """Add the transfer and upload routes to the public app."""
    app.include_router(router)
