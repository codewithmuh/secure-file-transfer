"""The recipient's download operations: `createSessionDownload` and `getSessionDownloadContent`
(#180; docs/api/openapi.yaml, tag "Recipient session"; abuse and rate limits 5; ADR-0018).

Routes only speak HTTP; the rules are `sft.service.downloads`'s.

- `createSessionDownload` is a `/session` call like the others: `X-Link-Session` names the
  session, the `__Host-sft_link` cookie must hold it, and it passes the CSRF checks of authn and
  authz 3.4 with that session's token (`sft.api.links.get_link_session`). Group D's limits are
  the service's, which knows the recipient and the file.
- `getSessionDownloadContent` is a navigation: no `X-Link-Session` and no CSRF header, only the
  grant ID and the cookie. `Range` and `If-Range` are read from the request, so a malformed range
  is `416`, never FastAPI's `422`, and declared for the OpenAPI document by hand. The bytes stream
  from S3 with an async client (`sft.runtime.content`); when the stream ends, however it ends
  (the last byte, a re-check, the client going away, a deploy), its end is recorded in a
  cancellation-shielded step, so the bytes it sent always count against the grant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema
from starlette.types import Receive, Scope, Send

from sft.api.caller import origin_of
from sft.api.dependencies import get_database, now_of
from sft.api.errors import problem_responses
from sft.api.links import NO_STORE, SESSION_HEADER, LinkDep, link_cookie
from sft.api.rate_limits import client_ip
from sft.data.database import Database
from sft.service import downloads
from sft.service.downloads import Download, DownloadServices, DownloadView

PREFIX: Final = "/v1"
router = APIRouter(prefix=PREFIX)
DatabaseDep = Annotated[Database, Depends(get_database)]

_SHA256 = r"^[0-9a-f]{64}$"
_RANGE_PATTERN = r"^bytes=(\d+-\d*|-\d+)$"
_BINARY: Final[dict[str, Any]] = {
    "application/octet-stream": {
        "schema": {"type": "string", "contentMediaType": "application/octet-stream"}
    }
}


def get_download_services(request: Request) -> DownloadServices:
    services = getattr(request.app.state, "download_services", None)
    if not isinstance(services, DownloadServices):
        raise RuntimeError("this app was created without settings, so it has no download services")
    return services


ServicesDep = Annotated[DownloadServices, Depends(get_download_services)]


# ---- the bodies (the contract's DownloadRequest, DownloadAccess and DownloadFile) ----


class DownloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resume_grant_id: UUID | SkipJsonSchema[None] = None


class DownloadFileOut(BaseModel):
    id: UUID
    display_name: str
    content_type: str
    size: int = Field(ge=1)
    sha256: str | None = Field(default=None, pattern=_SHA256)


class DownloadAccess(BaseModel):
    grant_id: UUID
    method: Literal["stream"]
    url: str = Field(json_schema_extra={"format": "uri-reference"})
    expires_at: datetime
    byte_budget: int = Field(ge=1)
    request_limit: int = Field(ge=1, le=20)
    file: DownloadFileOut
    warning: Literal["unscannable"] | SkipJsonSchema[None] = None
    downloads_remaining: int | None = Field(default=None, ge=0)

    @classmethod
    def of(cls, view: DownloadView) -> DownloadAccess:
        out = cls(
            grant_id=view.grant_id,
            method="stream",
            url=view.url,
            expires_at=view.expires_at,
            byte_budget=view.byte_budget,
            request_limit=view.request_limit,
            file=DownloadFileOut(
                id=view.file.id,
                display_name=view.file.display_name,
                content_type=view.file.content_type,
                size=view.file.size,
                sha256=view.file.sha256,
            ),
            downloads_remaining=view.downloads_remaining,
        )
        if view.unscannable:
            out.warning = "unscannable"
        return out


# ---- the routes ----


@router.post(
    "/session/files/{file_id}/downloads",
    operation_id="createSessionDownload",
    response_model=DownloadAccess,
    response_model_exclude_unset=True,
    summary="Download a file of the transfer",
    tags=["Recipient session"],
    responses=problem_responses(400, 401, 403, 404, 409, 410, 429, 503),
    openapi_extra={
        "parameters": [
            {
                "name": SESSION_HEADER,
                "in": "header",
                "required": True,
                "schema": {"type": "string", "format": "uuid"},
            }
        ]
    },
)
async def create_session_download(
    file_id: UUID,
    request: Request,
    response: Response,
    link: LinkDep,
    database: DatabaseDep,
    services: ServicesDep,
    body: DownloadRequest | None = None,
) -> DownloadAccess:
    """A counted grant for one shareable file, or the same grant again to resume (FR-4, FR-6)."""
    view = await downloads.create_session_download(
        database,
        services,
        link,
        file_id,
        resume_grant_id=None if body is None else body.resume_grant_id,
        ip=client_ip(request),
        origin=origin_of(request),
        now=now_of(request),
    )
    response.headers.update(NO_STORE)
    return DownloadAccess.of(view)


@router.get(
    "/session/downloads/{grant_id}/content",
    operation_id="getSessionDownloadContent",
    response_class=StreamingResponse,
    summary="Fetch the bytes of a file",
    tags=["Recipient session"],
    responses={
        200: {"description": "The whole file, streamed.", "content": _BINARY},
        206: {"description": "The requested range of the file, streamed.", "content": _BINARY},
        **problem_responses(401, 403, 404, 410, 416, 429, 503),
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
async def get_session_download_content(
    grant_id: UUID, request: Request, database: DatabaseDep, services: ServicesDep
) -> StreamingResponse:
    """The file's bytes under a grant, by navigation: the cookie, never `X-Link-Session`."""
    download = await downloads.open_content(
        database,
        services,
        link_cookie(request),
        grant_id,
        range_header=request.headers.get("range"),
        if_range=request.headers.get("if-range"),
        ip=client_ip(request),
        now=now_of(request),
    )
    return _ContentResponse(download)


class _ContentResponse(StreamingResponse):
    """The stream's response: however it ends, even before its first byte (a client that went
    away at once never starts the body), the stream's end is recorded once, shielded from the
    cancellation that would otherwise stop that step at its first await."""

    def __init__(self, download: Download) -> None:
        super().__init__(
            download.stream.chunks(),
            status_code=download.status,
            headers=download.headers,
            media_type="application/octet-stream",
        )
        self.download = download

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await self.download.stream.finish()


def register(app: FastAPI) -> None:
    """Add the download routes to the public app."""
    app.include_router(router)
