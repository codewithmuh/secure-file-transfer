"""Received files: an uploader uploads to an upload request, and the member reads and deletes what
arrived (#213; UC-2, FR-11, FR-12, FR-13, FR-16, NFR-3, NFR-6; data model 2.3, 3.1, 6; abuse and
rate limits 2.2 F, 6).

**The uploader's uploads** (`addSessionUploadFile`, `requestSessionUploadPartUrls`,
`listSessionUploadedParts`, `completeSessionUpload`) work as a member's upload to a draft
(`sft.service.uploads`), with the upload request in the transfer's place. The caller is the
uploader's link session (`sft.service.links.session_caller`, which answers `410 link_revoked` or
`410 link_expired` once the request ended); a recipient's session gets `403 permission_denied`.
The request is always the session's own, never one the client names, and every file is looked up
through it, so a file of another request is `404`. As the link steps do, the calls then work in
the request's tenant scope, whose quota, policy and idempotency keys they use.

- **Limits** (FR-11; abuse 2.2 F, 6.1): 5 GB a file, 100 declarations a request (rejected and
  removed files included, `422 too_many_files`), 50 counted files (`422 too_many_files`) and
  20 GB of them (`413 total_too_large`), counted under the request's row lock, so parallel
  declarations can't pass them; the tenant's storage quota (`413 storage_quota_exceeded`). The
  routes apply group F per link session and IP; an uploader spends none of the tenant's group H
  budget.
- **Completion** runs the three phases of data model 3.1 under the request's row lock: phase 1
  re-checks that the request is open and counts its files again, so parallel completes can't
  pass the limits either; phase 2 lists and assembles the parts in S3 with no transaction open;
  phase 3 locks again, so a revocation or expiry that landed meanwhile wins (`410`), and the file
  is never accepted. An accepted file reaches `scanning` with its `retention_until`, the tenant's
  `received_file_retention_days` from now (FR-13), and its scan message. A revocation rejects every
  open upload at once (`sft.service.uploads.reject_request_uploads`), so parts sent later are
  never assembled (NFR-6).
- **Removal** (`deleteSessionUploadFile`, #229): the uploader takes back a file they declared or
  uploaded while the request is open (`410` once it ended), under the request's row lock, which a
  completion and a member's grant take too. The file is removed as the member's early delete
  removes it (`removed_at`, `delete_after` now, its reservation released), so it no longer counts
  towards the limits and the deletion job deletes it, aborting an open upload. A shareable file
  still counted in the request's next notice is taken off it (`withdraw_arrival`). A blocked file
  (infected, failed, unscannable and not allowed, inspection failed or blocked by a DLP rule) is
  the company's to see and stays: `409 invalid_state`, as for a file already deleted. Removing a
  removed file again changes nothing, so a retry gets `204`.
- **Audited** as the uploader (actor type `uploader`, its request's ID): `file.added`,
  `file.part_urls_issued`, `file.completion_started`, `file.upload_incomplete`, `file.uploaded`,
  `file.rejected`, `file.removed` (reason `uploader_removed`).

**The member's side.** `listUploadRequestFiles` lists a request's files as `getUploadRequest`
reaches it: Own for a member, Tenant for an admin acting as one and an API key with
`upload_requests:read`, metadata only. `deleteFile` on a received file is the owner's early delete
(FR-13): the file is removed at once, its `delete_after` moved to now and its reservation released;
the deletion job deletes every object version, whatever its retention said. An admin gets
`403 permission_denied` on another member's file, another member `404`, and an API key needs
`upload_requests:write` (else `404`). Downloads are `sft.service.downloads`'s.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    Gone,
    NotFound,
    ProblemError,
    TooLarge,
    Unauthenticated,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.data import audit, files, findings, upload_requests, usage
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import (
    File,
    FileState,
    InspectionState,
    StorageClass,
    UploadRequest,
    UploadRequestState,
)
from sft.data.scope import Scope, SubjectKind
from sft.service import fields, scan_timing, uploads
from sft.service.caller import Caller, CallerKind
from sft.service.evaluation import is_blocked, is_shareable
from sft.service.idempotency import IdempotentRequest, Outcome, once, replay
from sft.service.links import SessionFile, uploader_file
from sft.service.objects import PART_URL_SECONDS, ObjectStore, ObjectStoreError
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import KeyType
from sft.service.rate_limits.uploads import part_url_cap, part_urls_refused, upload_charges
from sft.service.transfers import FileView, audit_details, file_view, invalid, tenant_scope
from sft.service.upload_requests import (
    effective_state,
    require_reach,
    require_visible,
)
from sft.service.uploads import (
    FILE,
    MAX_FILE_SIZE,
    MAX_FILES,
    MAX_PART_URLS,
    MAX_TOTAL_SIZE,
    Assembled,
    FileRequest,
    Missing,
    PartUrl,
    RejectReason,
    UploadedParts,
    UploadPolicy,
    assemble,
    owner_details,
    part_sizes,
    storage_class_for,
    to_scanning,
    upload_plan,
)
from sft.service.uploads import (
    Gone as UploadGone,
)

MAX_DECLARATIONS: Final = 100
"""File declarations a request takes in all, rejected and removed ones included (abuse 2.2 F)."""
UPLOAD_REQUESTS_READ: Final = "upload_requests:read"
UPLOAD_REQUESTS_WRITE: Final = "upload_requests:write"


class RemoveReason(StrEnum):
    EARLY_DELETE = "early_delete"
    """FR-13: the member deleted a received file before its retention ended."""
    UPLOADER_REMOVED = "uploader_removed"
    """#229: the uploader took the file back while the request was open."""


def _too_many_files() -> Unprocessable:
    return Unprocessable("too_many_files", f"An upload request receives at most {MAX_FILES} files.")


def _too_many_declarations() -> Unprocessable:
    return Unprocessable(
        "too_many_files",
        f"An upload request takes at most {MAX_DECLARATIONS} file declarations.",
    )


def _total_too_large() -> TooLarge:
    return TooLarge("total_too_large", "An upload request receives 20 GB in all.")


def _file_too_large() -> TooLarge:
    return TooLarge("file_too_large", "A file is at most 5 GB.")


def _quota_exceeded() -> TooLarge:
    return TooLarge("storage_quota_exceeded", "The company's storage is full.")


def _size_mismatch() -> Unprocessable:
    return Unprocessable(
        "upload_size_mismatch",
        "The uploaded size differs from the declared size, so the file was rejected.",
    )


def _upload_incomplete() -> Conflict:
    return Conflict(
        "upload_incomplete",
        "Some parts are missing; send them, then complete again.",
        current_state=FileState.UPLOADING.value,
    )


def _rejected(detail: str) -> Conflict:
    return Conflict("invalid_state", detail, current_state=FileState.REJECTED.value)


def _past_uploading(state: str) -> Conflict:
    return Conflict("invalid_state", "The file is past uploading.", current_state=state)


def _store_unavailable() -> ProblemError:
    return uploads._store_unavailable()


# ---- the uploader (session.upload) ----


@dataclass(frozen=True, slots=True)
class _Uploader:
    tenant_id: UUID
    request_id: UUID

    @property
    def scope(self) -> Scope:
        return Scope.tenant(self.tenant_id)


def _uploader(caller: Caller, operation: str, now: datetime) -> _Uploader:
    """The uploader's request, after the permission check: a recipient's session is `403`."""
    authorize(caller, operation, now=now)
    subject = caller.subject
    if (
        caller.kind is not CallerKind.UPLOADER
        or caller.tenant_id is None
        or subject is None
        or subject.kind is not SubjectKind.UPLOAD_REQUEST
    ):  # pragma: no cover - authorize admits uploaders only, with their subject
        raise Unauthenticated("authentication_required")
    return _Uploader(caller.tenant_id, subject.id)


def _request_open(row: UploadRequest, now: datetime) -> ProblemError | None:
    """None while the request takes files; `410` once it was revoked or has expired (contract,
    `addSessionUploadFile`), read from `expires_at` before the job records it."""
    state = effective_state(UploadRequestState(row.state), row.expires_at, now)
    if state is UploadRequestState.REVOKED:
        return Gone("link_revoked")
    if state is UploadRequestState.EXPIRED:
        return Gone("link_expired")
    return None


async def _request(session: AsyncSession, request_id: UUID, *, lock: bool = False) -> UploadRequest:
    try:
        return await upload_requests.get_request(session, request_id, lock=lock)
    except NotFoundError:  # pragma: no cover - a live session's request is there
        raise Unauthenticated("session_expired") from None


async def _limits(
    session: AsyncSession, request_id: UUID, *, adding: int = 0
) -> ProblemError | None:
    """FR-11 for the request's files, plus a new file of `adding` bytes if given (abuse 2.2 F)."""
    totals = await files.request_totals(session, request_id)
    if adding and totals.declared >= MAX_DECLARATIONS:
        return _too_many_declarations()
    if totals.counted + (1 if adding else 0) > MAX_FILES:
        return _too_many_files()
    if totals.total + adding > MAX_TOTAL_SIZE:
        return _total_too_large()
    return None


async def _check_open(
    session: AsyncSession, request_id: UUID, size: int, now: datetime, *, lock: bool = False
) -> None:
    row = await _request(session, request_id, lock=lock)
    problem = _request_open(row, now) or await _limits(session, request_id, adding=size)
    if problem is not None:
        raise problem


async def add_session_file(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    request: FileRequest,
    *,
    policy: UploadPolicy,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[SessionFile]:
    """`addSessionUploadFile`: declare a file and start its multipart upload (FR-11), as
    `addTransferFile` does. A retry with the same `Idempotency-Key` gets the first answer and
    starts no second upload. The file counts against the requesting tenant's daily upload volume
    (#165, abuse 6.1), peeked first and charged as the declaration's last step."""
    who = _uploader(caller, "addSessionUploadFile", now)
    if not 1 <= request.size <= MAX_FILE_SIZE:
        raise _file_too_large()

    async def rebuild(session: AsyncSession, file_id: UUID) -> SessionFile | None:
        try:
            found = await files.get_request_file(session, who.request_id, file_id)
        except NotFoundError:
            return None
        return uploader_file(await fields.tenant_keys(session, who.tenant_id), found)

    async with database.transaction(who.scope) as session:
        replayed = await replay(
            session,
            caller,
            idempotency,
            resource_type=FILE,
            rebuild=lambda file_id: rebuild(session, file_id),
        )
        if replayed is not None:
            return replayed
        await _check_open(session, who.request_id, request.size, now)
    charges = upload_charges({KeyType.TENANT: str(who.tenant_id)}, request.size)
    await limiter.peek_all(charges)

    file_id = uuid7()
    storage_class = storage_class_for(request.size)
    key = files.storage_key(who.tenant_id, file_id)
    part_size, part_count = upload_plan(request.size)
    try:
        upload_id = await objects.create_multipart_upload(storage_class, key)
    except ObjectStoreError:
        raise _store_unavailable() from None

    async def declare(session: AsyncSession) -> SessionFile:
        # Under the request's row lock: a revocation, and parallel declarations, queue here.
        await _check_open(session, who.request_id, request.size, now, lock=True)
        if not await usage.reserve_storage(session, request.size, quota=policy.storage_quota):
            raise _quota_exceeded()
        file = await files.insert_file(
            session,
            file_id=file_id,
            upload_request_id=who.request_id,
            display_name_ct=(await fields.tenant_keys(session, who.tenant_id, write=True)).seal(
                fields.FILE_NAME, file_id, request.display_name
            ),
            content_type=request.content_type,
            declared_size=request.size,
            storage_class=storage_class.value,
            s3_upload_id=upload_id,
            part_size=part_size,
            part_count=part_count,
        )
        await audit.record(
            session,
            action="file.added",
            actor=caller.actor(),
            target=Target(FILE, file_id),
            origin=origin,
            details={
                "upload_request_id": who.request_id,
                "declared_size": request.size,
                "storage_class": storage_class,
                "part_count": part_count,
            },
        )
        # Last: a refusal rolls the declaration back; nothing before it charged anything.
        await limiter.check_all(charges)
        return uploader_file(await fields.tenant_keys(session, who.tenant_id), file)

    try:
        async with database.transaction(who.scope) as session:
            outcome = await once(
                session,
                caller,
                idempotency,
                status=201,
                resource_type=FILE,
                create=lambda: declare(session),
                rebuild=lambda found: rebuild(session, found),
                resource_id=lambda view: view.id,
            )
    except BaseException:
        await uploads._abort(objects, storage_class, key, upload_id)
        raise
    if outcome.replayed:
        await uploads._abort(objects, storage_class, key, upload_id)
    return outcome


async def _uploading(session: AsyncSession, who: _Uploader, file_id: UUID, now: datetime) -> File:
    """The uploader's file, still `uploading`, of a request that still takes files."""
    try:
        file = await files.get_request_file(session, who.request_id, file_id)
    except NotFoundError:
        raise NotFound from None
    if file.removed_at is not None:
        raise NotFound
    problem = _request_open(await _request(session, who.request_id), now)
    if problem is not None:
        raise problem
    if file.state != FileState.UPLOADING.value:
        raise _past_uploading(file.state)
    return file


async def session_part_urls(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    file_id: UUID,
    part_numbers: Sequence[int],
    *,
    origin: Origin,
    now: datetime,
) -> list[PartUrl]:
    """`requestSessionUploadPartUrls`: as `requestUploadPartUrls`, for a file of this request,
    with the same cap of 10 times its `part_count` over its life (#165)."""
    who = _uploader(caller, "requestSessionUploadPartUrls", now)
    if not 1 <= len(part_numbers) <= MAX_PART_URLS or len(set(part_numbers)) != len(part_numbers):
        raise invalid(json_pointer("part_numbers"), "Ask for 1 to 100 different parts.")
    async with database.transaction(who.scope) as session:
        file = await _uploading(session, who, file_id, now)
        sizes = part_sizes(file)
        for index, number in enumerate(part_numbers):
            if number not in sizes:
                raise invalid(
                    json_pointer("part_numbers", index),
                    "The part number is beyond the file's part_count.",
                )
        touched = await files.touch_parts(
            session, file.id, parts=len(part_numbers), cap=part_url_cap(file.part_count)
        )
        if touched is None:
            moved = await files.get_request_file(session, who.request_id, file.id)
            if moved.state != FileState.UPLOADING.value or moved.removed_at is not None:
                raise _past_uploading(moved.state)  # a completion moved it on meanwhile
            raise part_urls_refused()  # its part URLs are used up (#165)
        await audit.record(
            session,
            action="file.part_urls_issued",
            actor=caller.actor(),
            target=Target(FILE, file.id),
            origin=origin,
            details={"upload_request_id": who.request_id, "parts": len(part_numbers)},
        )
    storage_class = StorageClass(file.storage_class)
    expires_at = datetime.now(UTC) + timedelta(seconds=PART_URL_SECONDS)
    parts = [(number, sizes[number]) for number in part_numbers]
    try:
        urls = await objects.part_urls(storage_class, file.storage_key, file.s3_upload_id, parts)
    except ObjectStoreError:
        raise _store_unavailable() from None
    return [PartUrl(n, size, url, expires_at) for (n, size), url in zip(parts, urls, strict=True)]


async def session_uploaded_parts(
    database: Database, objects: ObjectStore, caller: Caller, file_id: UUID, *, now: datetime
) -> UploadedParts:
    """`listSessionUploadedParts`: the parts S3 already holds, so a resumed upload sends only
    the rest (FR-11, NFR-3)."""
    who = _uploader(caller, "listSessionUploadedParts", now)
    async with database.transaction(who.scope) as session:
        file = await _uploading(session, who, file_id, now)
    try:
        stored = await objects.list_parts(
            StorageClass(file.storage_class), file.storage_key, file.s3_upload_id
        )
    except ObjectStoreError:
        raise _store_unavailable() from None
    parts = sorted((p.number, p.size) for p in stored or [] if 1 <= p.number <= file.part_count)
    return UploadedParts(file.part_size, file.part_count, tuple(parts))


async def _reject(
    session: AsyncSession, caller: Caller, file: File, reason: RejectReason, origin: Origin
) -> None:
    """The file is `rejected`, due for deletion now, and its reservation released; the request's
    row lock is held. No S3 call: the deletion job aborts the upload (data model 3.1)."""
    if await files.reject_file(session, file.id) is None:  # pragma: no cover - under the lock
        raise RuntimeError("the file changed under the request's row lock")
    if file.removed_at is None:
        await usage.release_storage(session, file.declared_size)
    await audit.record(
        session,
        action="file.rejected",
        actor=caller.actor(),
        target=Target(FILE, file.id),
        origin=origin,
        details={**owner_details(file), "reason": reason},
    )


def _limit_reason(problem: ProblemError) -> RejectReason:
    if problem.code == "too_many_files":
        return RejectReason.TOO_MANY_FILES
    return RejectReason.TOTAL_TOO_LARGE


async def complete_session_upload(
    database: Database,
    objects: ObjectStore,
    caller: Caller,
    file_id: UUID,
    *,
    origin: Origin,
    now: datetime,
    small_pool_max: int = scan_timing.SMALL_POOL_MAX_BYTES,
) -> SessionFile:
    """`completeSessionUpload`, in the three phases of data model 3.1 under the request's row
    lock (module docstring). Safe to retry: a file already `completing` runs phases 2 and 3 again,
    and one past `completing` comes back unchanged."""
    who = _uploader(caller, "completeSessionUpload", now)

    # Phase 1: a short transaction under the request's row lock.
    error: ProblemError | None = None
    async with database.transaction(who.scope) as session:
        try:
            await files.get_request_file(session, who.request_id, file_id)
        except NotFoundError:
            raise NotFound from None
        row = await _request(session, who.request_id, lock=True)
        file = await files.get_request_file(session, who.request_id, file_id)
        if file.state not in (FileState.UPLOADING.value, FileState.COMPLETING.value):
            if file.removed_at is not None:
                raise NotFound
            return uploader_file(await fields.tenant_keys(session, who.tenant_id), file)
        closed = _request_open(row, now)
        limits = None if closed else await _limits(session, who.request_id)
        if file.removed_at is not None:
            # The member deleted it while its upload was open: never assembled.
            await _reject(session, caller, file, RejectReason.REMOVED, origin)
            error = NotFound()
        elif closed is not None:
            await _reject(session, caller, file, RejectReason.REQUEST_NOT_OPEN, origin)
            error = closed
        elif limits is not None:
            await _reject(session, caller, file, _limit_reason(limits), origin)
            error = limits
        elif file.state == FileState.UPLOADING.value:
            started = await files.start_completion(session, file.id)
            if started is None:  # pragma: no cover - the lock holds the state seen
                raise RuntimeError("the file changed under the request's row lock")
            file = started
            await audit.record(
                session,
                action="file.completion_started",
                actor=caller.actor(),
                target=Target(FILE, file.id),
                origin=origin,
                details={"upload_request_id": who.request_id},
            )
    if error is not None:
        raise error

    # Phase 2: S3, with no transaction open.
    try:
        assembled = await assemble(objects, file)
    except ObjectStoreError:
        raise _store_unavailable() from None  # the file stays `completing`; a retry resumes

    # Phase 3: lock again and re-check; a revocation, an expiry or a delete meanwhile wins.
    async with database.transaction(who.scope) as session:
        row = await _request(session, who.request_id, lock=True)
        file = await files.get_request_file(session, who.request_id, file_id)
        if file.state != FileState.COMPLETING.value:
            if file.removed_at is not None:
                raise NotFound
            return uploader_file(
                await fields.tenant_keys(session, who.tenant_id), file
            )  # another call finished it first
        closed = _request_open(row, now)
        if closed or file.removed_at is not None or not isinstance(assembled, Assembled | Missing):
            if closed:
                reason, error = RejectReason.REQUEST_NOT_OPEN, closed
            elif file.removed_at is not None:
                reason, error = RejectReason.REMOVED, NotFound()
            elif isinstance(assembled, UploadGone):
                reason, error = RejectReason.UPLOAD_GONE, _rejected("The upload no longer exists.")
            else:
                reason, error = RejectReason.SIZE_MISMATCH, _size_mismatch()
            await _reject(session, caller, file, reason, origin)
        elif isinstance(assembled, Missing):
            await files.resume_uploading(session, file.id)
            await audit.record(
                session,
                action="file.upload_incomplete",
                actor=caller.actor(),
                target=Target(FILE, file.id),
                origin=origin,
                details={"upload_request_id": who.request_id},
            )
            error = _upload_incomplete()
        elif assembled.size != file.declared_size:
            await _reject(session, caller, file, RejectReason.SIZE_MISMATCH, origin)
            error = _size_mismatch()
        else:
            await to_scanning(
                session,
                file,
                assembled,
                actor=caller.actor(),
                details={},
                now=now,
                small_pool_max=small_pool_max,
                origin=origin,
            )
            accepted = await files.get_request_file(session, who.request_id, file.id)
            return uploader_file(await fields.tenant_keys(session, who.tenant_id), accepted)
    if error is None:  # pragma: no cover - every branch above sets one or returns
        raise RuntimeError("completion ended without a result")
    raise error


def _uploader_may_remove(file: File) -> bool:
    """A file the uploader may take back: not deleted and not blocked (module docstring)."""
    if file.state == FileState.DELETED.value or file.dlp_blocked:
        return False
    state, inspection = FileState(file.state), InspectionState(file.inspection_state)
    return not is_blocked(state, file.unscannable_allowed, inspection)


async def delete_session_file(
    database: Database, caller: Caller, file_id: UUID, *, origin: Origin, now: datetime
) -> None:
    """`deleteSessionUploadFile`: the uploader removes one of their files while the request is
    open (module docstring, #229)."""
    who = _uploader(caller, "deleteSessionUploadFile", now)
    async with database.transaction(who.scope) as session:
        row = await _request(session, who.request_id, lock=True)
        try:
            file = await files.get_request_file(session, who.request_id, file_id)
        except NotFoundError:
            raise NotFound from None
        if file.removed_at is not None:
            return  # removed already: a retry, or the member's early delete
        closed = _request_open(row, now)
        if closed is not None:
            raise closed
        if not _uploader_may_remove(file):
            raise Conflict(
                "invalid_state",
                "This file was blocked, so it stays for the company to review.",
                current_state=file.state,
            )
        removed = await files.remove_received_file(session, file.id)
        if removed is None:  # pragma: no cover - read above under the request's row lock
            return
        if file.state != FileState.REJECTED.value:
            await usage.release_storage(session, file.declared_size)
        shareable = is_shareable(
            FileState(file.state),
            file.unscannable_allowed,
            InspectionState(file.inspection_state),
        )
        withdrawn = False
        if shareable and file.scanned_at is not None:
            withdrawn = await upload_requests.withdraw_arrival(
                session, who.request_id, settled_at=file.scanned_at
            )
        await audit.record(
            session,
            action="file.removed",
            actor=caller.actor(),
            target=Target(FILE, file.id),
            origin=origin,
            details={
                "upload_request_id": who.request_id,
                "state": FileState(file.state),
                "reason": RemoveReason.UPLOADER_REMOVED,
                "notice_withdrawn": withdrawn,
            },
        )


# ---- the member's side ----


async def _received(
    session: AsyncSession, file_id: UUID, *, lock: bool = False
) -> tuple[File, UploadRequest]:
    """A received file and its request, `404` if either is out of the scope's reach. `lock` takes
    the request's row lock, which a member's grant takes too, and reads the file again under it."""
    try:
        file = await files.get_file(session, file_id)
        if file.upload_request_id is None:
            raise NotFound
        request = await upload_requests.get_request(session, file.upload_request_id, lock=lock)
        if lock:
            file = await files.get_file(session, file_id)
    except NotFoundError:
        raise NotFound from None
    return file, request


def key_scope_matches(caller: Caller, file: File, *, write: bool) -> bool:
    """API key scope follows the file's owner (contract, `getFile`): `transfers:*` for a file of
    a transfer, `upload_requests:*` for a received file. Any other caller passes."""
    if caller.kind is not CallerKind.API_KEY:
        return True
    if file.upload_request_id is not None:
        wanted = UPLOAD_REQUESTS_WRITE if write else UPLOAD_REQUESTS_READ
    else:
        wanted = "transfers:write" if write else "transfers:read"
    return wanted in caller.scopes


async def list_request_files(
    database: Database, caller: Caller, request_id: UUID, *, now: datetime
) -> list[FileView]:
    """`listUploadRequestFiles`: every file the uploader sent but those the member deleted, with
    its state and `retention_until`, as `getUploadRequest` reaches the request (FR-12, FR-13)."""
    reach = authorize(caller, "listUploadRequestFiles", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            request = await upload_requests.get_request(session, request_id)
        except NotFoundError:
            raise NotFound from None
        require_visible(caller, reach, request)
        found = await files.list_request_files(session, request.id)
        detectors = await findings.detectors_by_file(session, [f.id for f in found])
        keys = await fields.tenant_keys(session, tenant_id)
    return [file_view(keys, f, detectors.get(f.id, ())) for f in found]


async def delete_file(
    database: Database, caller: Caller, file_id: UUID, *, origin: Origin, now: datetime
) -> None:
    """`deleteFile`: a file of a transfer is `sft.service.uploads.delete_file`'s; a received one
    is the owner's early delete (module docstring). Deleting it again changes nothing."""
    reach = authorize(caller, "deleteFile", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            file = await files.get_file(session, file_id)
        except NotFoundError:
            raise NotFound from None
        if not key_scope_matches(caller, file, write=True):
            raise NotFound
        received = file.upload_request_id is not None
        if received:
            file, request = await _received(session, file_id, lock=True)
            require_reach(caller, reach, request, now)
            await _delete_received(session, caller, file, origin)
    if not received:
        await uploads.delete_file(database, caller, file_id, origin=origin, now=now)


async def _delete_received(
    session: AsyncSession, caller: Caller, file: File, origin: Origin
) -> None:
    removed = await files.remove_received_file(session, file.id)
    if removed is None:
        return  # removed already: the deletion job has it
    if file.state not in (FileState.REJECTED.value, FileState.DELETED.value):
        await usage.release_storage(session, file.declared_size)
    await audit.record(
        session,
        action="file.removed",
        actor=caller.actor(),
        target=Target(FILE, file.id),
        origin=origin,
        details=audit_details(
            caller,
            upload_request_id=file.upload_request_id,
            state=FileState(file.state),
            reason=RemoveReason.EARLY_DELETE,
        ),
    )
