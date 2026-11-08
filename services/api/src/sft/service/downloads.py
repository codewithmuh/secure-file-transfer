"""Download grants and streamed content: `createSessionDownload` and `getSessionDownloadContent`
(#180; FR-4, FR-6, FR-14, NFR-6; ADR-0018; data model 2.3; abuse and rate limits 5).

**A grant** (`create_session_download`) counts one download of one file by one link session. In
order, so a `503` always means nothing was counted (data model 2.3):

1. Check the session, the transfer's revocation and expiry, that the file is shareable and that
   its limit isn't used up. Group D's request rates come first (per recipient, then per IP).
2. The tenant's grant rate and the byte caps (25 GB a recipient, 500 GB a tenant, a day) are
   spent: only a new grant costs them, never a resume.
3. A grant ID is made, and its intent record (`download.grant_intent`) goes to both regions'
   audit archive (`intent_first`); either write failing is `503`, and nothing is counted.
4. One transaction counts the download with one conditional update, inserts the grant and writes
   `download.granted`, marked security-critical. A parallel request that took the last download
   meanwhile gets `403 download_limit_reached`.
   The transfer's first counted download (any recipient, any file) also writes the member's
   `transfer.first_download` message there, once per transfer, when they asked for it (FR-8,
   #214): a conditional update of `first_download_notified_at`, so a retry, a resume or a later
   download writes none.
5. The committed record (`download.grant_committed`) is written in the background until both
   regions confirm, then `archived_at` is set; reconciliation rewrites any still missing a minute
   later (#181). Its ID is the grant's, and it holds only what the grant row holds, so a rewrite
   writes the same object.

`resume_grant_id` returns a grant of this session and this file again, uncounted, while it has
time, bytes and requests left (FR-6); otherwise `403 download_grant_exhausted`. Any other grant is
`404`. A resume is audited (`download.resumed`) and costs the request rates only.

**Content** (`open_content`) is a navigation, so it has no `X-Link-Session`: the grant ID names
the grant, and the `__Host-sft_link` cookie must hold its session. No cookie is `401`; a cookie
that doesn't hold the grant's session is `404`, so a forwarded URL grants nothing (FR-14). Then the
transfer (`410` once revoked or expired), the session (`401 session_expired` once ended) and the
file (`404` once it isn't shareable). One range per request (`206`, or `416`), a strong `ETag`
from the file's SHA-256, `If-Range`, and the security headers of abuse 5.6, for the version that
was scanned. The stream takes a place under group E's caps (6 a session, 20 an IP, 200 a tenant,
100 a pod), then one statement takes a request and the grant's stream lease; a newer request
takes the lease over.

**A running stream** re-checks every `recheck_seconds` (30), and once more when it ends: it adds
the bytes it sent (by grant ID, so a stream that was taken over still records them), renews its
lease and its places, moves the session's `last_seen_at`, and stops on a revocation, an expiry, an
ended session, a file that is no longer shareable, a lost lease, or a client that read less than
2 KB/s over 2 minutes. A request is admitted only if the grant's bytes left cover its whole span,
so a response never declares more than it sends; otherwise `403 download_grant_exhausted`, and a
smaller range may still fit. A revocation therefore stops it within two intervals
(NFR-6). `download.completed` (the file's last byte sent) and `download.stopped` (a revocation, an
expiry, an ended session or an unshareable file cut it) are written as best effort.

**A member's download of a received file** (#213, `create_received_download`,
`open_received_content`): the request's owner, through a member session only. A tenant admin sees
the metadata but gets `403 permission_denied`, another member `404`, an API key or a link session
`401`. The same order as a recipient's grant: group D's request rates (per member and IP, and the
tenant's group H budget), the checks, the tenant's grant rate and bytes of the day peeked, the
intent record in both regions, then one transaction under the request's row lock (which an early
delete takes too) that re-checks the member session and the file, inserts the grant with the
member's pair and writes `download.granted`, then the committed record in the background. No
download is counted: received files have no limit. The grant belongs to the member session: 24
hours, never past the session. Its content (`/v1/files/{file_id}/downloads/{grant_id}/content`)
is authorised by the grant ID and the member session cookie that made it: no cookie `401`,
another session's, even the same member's on another device, `404`. Ranges, the budget, the lease
and the 30-second re-checks work as for a recipient; each re-check reads the member session as a
request does, which keeps it from ending for idleness (data model 2.3), and stops the stream once
the session ended or the file is deleted, past its retention or no longer shareable. Group E caps
the streams per member (6), IP and tenant. A file past its retention, or deleted, is `404`.

Metrics: `download_grants_total{result}`, `download_streams_active`, `download_bytes_total`,
`download_streams_ended_total{reason}`.
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final
from urllib.parse import quote
from uuid import UUID, uuid4

from prometheus_client import CollectorRegistry, Counter, Gauge
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.clock import SYSTEM_CLOCK, Clock
from sft.core.errors import (
    Conflict,
    Forbidden,
    Gone,
    NotFound,
    ProblemError,
    RangeNotSatisfiable,
    ServiceUnavailable,
    Unauthenticated,
)
from sft.core.ids import uuid7
from sft.data import audit, downloads, files, link_sessions, member_sessions, recipients
from sft.data import transfers as transfer_rows
from sft.data import upload_requests as request_rows
from sft.data.access import NotFoundError
from sft.data.audit import Actor, ArchivedEvent, Origin, Target
from sft.data.database import Database
from sft.data.downloads import Grant
from sft.data.models import ActorType, File, FileState, InspectionState, Outcome, StorageClass
from sft.data.models import TransferState as State
from sft.data.outbox import TRANSFER_FIRST_DOWNLOAD, enqueue
from sft.data.scope import Scope, Subject
from sft.service import fields
from sft.service.audit_archive import AuditArchive, RecordNotConfirmed, intent_first
from sft.service.caller import Caller, CallerKind
from sft.service.evaluation import is_shareable
from sft.service.links import LinkCaller
from sft.service.objects import FileContent, ObjectStoreError
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.downloads import (
    MEMBER_STREAM_CAPS,
    DownloadLimits,
    StreamSlot,
    grant_charges,
    received_grant_charges,
)
from sft.service.rate_limits.limits import GRANT_REQUEST, RECEIVED_GRANT_REQUEST, KeyType
from sft.service.upload_requests import sees_tenant

log = logging.getLogger(__name__)

FILE: Final = "file"
METHOD: Final = "stream"
SLOW_FLOOR_BYTES_PER_SECOND: Final = 2048
SLOW_WINDOW_SECONDS: Final = 120.0
STORE_RETRY_AFTER: Final = 5
_RANGE: Final = re.compile(r"bytes=(?:(\d+)-(\d*)|-(\d+))")


class GrantResult(StrEnum):
    GRANTED = "granted"
    RESUMED = "resumed"
    LIMIT_REACHED = "limit_reached"
    EXHAUSTED = "exhausted"
    NOT_SHAREABLE = "not_shareable"
    UNAVAILABLE = "unavailable"


class Ended(StrEnum):
    """Why a stream ended, in `download_streams_ended_total{reason}` and `download.stopped`."""

    COMPLETED = "completed"
    CLIENT_CLOSED = "client_closed"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SESSION_ENDED = "session_ended"
    NOT_SHAREABLE = "not_shareable"
    TAKEN_OVER = "taken_over"
    SLOW = "slow"
    ERROR = "error"


STOPPED_BY_STATE: Final = frozenset(
    {Ended.REVOKED, Ended.EXPIRED, Ended.SESSION_ENDED, Ended.NOT_SHAREABLE}
)
"""The ends `download.stopped` records: the state changed under the stream (abuse 5.4)."""


@dataclass(frozen=True)
class DownloadMetrics:
    grants: Counter
    active: Gauge
    bytes: Counter
    ended: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> DownloadMetrics:
        grants = Counter(
            "download_grants_total",
            "Grant requests, by result: granted, resumed, limit_reached, exhausted, "
            "not_shareable, unavailable.",
            ["result"],
            registry=registry,
        )
        active = Gauge(
            "download_streams_active", "Download streams this pod serves now.", registry=registry
        )
        sent = Counter(
            "download_bytes_total", "File bytes streamed to recipients.", registry=registry
        )
        ended = Counter(
            "download_streams_ended_total",
            "Download streams that ended, by reason.",
            ["reason"],
            registry=registry,
        )
        for result in GrantResult:
            grants.labels(result.value)
        for reason in Ended:
            ended.labels(reason.value)
        return cls(grants, active, sent, ended)


@dataclass(frozen=True)
class DownloadServices:
    """What downloads use beyond the database, from the API's lifespan."""

    limiter: RateLimiter
    limits: DownloadLimits
    archive: AuditArchive
    content: FileContent
    metrics: DownloadMetrics
    recheck_seconds: float = 30.0
    clock: Clock = SYSTEM_CLOCK


# ---- what a grant looks like to the recipient (the contract's DownloadAccess) ----


@dataclass(frozen=True, slots=True)
class DownloadFile:
    id: UUID
    display_name: str
    content_type: str
    size: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class DownloadView:
    grant_id: UUID
    url: str
    expires_at: datetime
    byte_budget: int
    request_limit: int
    file: DownloadFile
    unscannable: bool
    downloads_remaining: int | None


def content_url(grant_id: UUID) -> str:
    return f"/v1/session/downloads/{grant_id}/content"


def _view(
    tenant_id: UUID, grant: Grant, file: File, counted: downloads.Counted | None
) -> DownloadView:
    remaining = None
    if counted is not None and counted.download_limit is not None:
        remaining = max(0, counted.download_limit - counted.count)
    return DownloadView(
        grant_id=grant.id,
        url=content_url(grant.id),
        expires_at=grant.expires_at,
        byte_budget=grant.byte_budget,
        request_limit=downloads.REQUEST_LIMIT,
        file=DownloadFile(
            id=file.id,
            display_name=fields.open_sealed(tenant_id, file.display_name_ct),
            content_type=file.content_type,
            size=file.actual_size or 0,
            sha256=None if file.sha256 is None else file.sha256.hex(),
        ),
        unscannable=FileState(file.state) is FileState.UNSCANNABLE,
        downloads_remaining=remaining,
    )


def committed_record(grant: Grant | downloads.Unarchived) -> ArchivedEvent:
    """A grant's committed record (data model 2.3): keyed by the grant's own ID and made from its
    row alone, so reconciliation's rewrite is the same object, which the archive keeps once. A
    member's grant (#213) names the member and their session."""
    actor_id: UUID | None
    if grant.user_id is not None:
        actor_type, actor_id = ActorType.MEMBER, grant.user_id
        session = {"member_session_id": str(grant.member_session_id)}
    else:
        actor_type, actor_id = ActorType.RECIPIENT, grant.recipient_id
        session = {"link_session_id": str(grant.link_session_id)}
    return ArchivedEvent(
        id=grant.id,
        tenant_id=grant.tenant_id,
        occurred_at=grant.created_at,
        action="download.grant_committed",
        actor_type=actor_type.value,
        actor_id=actor_id,
        target_type=FILE,
        target_id=grant.file_id,
        outcome=Outcome.SUCCESS.value,
        details={"grant_id": str(grant.id), **session, "byte_budget": grant.byte_budget},
    )


# ---- the checks every download shares ----


def _check_transfer(view: recipients.LinkView, now: datetime) -> None:
    """`410` once the transfer is revoked or has expired, whatever the job has recorded yet."""
    state = State(view.transfer_state)
    if state is State.REVOKED:
        raise Gone("link_revoked")
    expired = view.expires_at is not None and view.expires_at <= now
    if state is State.EXPIRED or expired:
        raise Gone("link_expired")
    if state is not State.SENT or not view.tenant_active:
        raise Unauthenticated("session_expired")


def _shareable(file: File) -> bool:
    return (
        is_shareable(
            FileState(file.state), file.unscannable_allowed, InspectionState(file.inspection_state)
        )
        and file.actual_size is not None
        and file.s3_version_id is not None
        and file.removed_at is None
    )


def _ids(caller_link: LinkCaller) -> tuple[UUID, UUID, UUID]:
    caller = caller_link.caller
    if caller.tenant_id is None or caller.subject is None or caller.credential_id is None:
        raise Unauthenticated("authentication_required")  # pragma: no cover - session_caller's
    return caller.tenant_id, caller.subject.id, caller.credential_id


async def _refused(
    database: Database,
    scope: Scope,
    recipient_id: UUID,
    file_id: UUID,
    reason: GrantResult,
    origin: Origin,
) -> None:
    """Audit a refused grant in a transaction of its own: it changes nothing else (FR-27)."""
    async with database.transaction(scope) as session:
        await audit.record(
            session,
            action="download.refused",
            actor=Actor(ActorType.RECIPIENT, recipient_id),
            target=Target(FILE, file_id),
            outcome=Outcome.FAILURE,
            origin=origin,
            details={"reason": reason},
        )


# ---- createSessionDownload ----


async def create_session_download(
    database: Database,
    services: DownloadServices,
    link: LinkCaller,
    file_id: UUID,
    *,
    resume_grant_id: UUID | None,
    ip: str,
    origin: Origin,
    now: datetime,
) -> DownloadView:
    """`createSessionDownload` (module docstring)."""
    authorize(link.caller, "createSessionDownload", now=now)
    tenant_id, recipient_id, session_id = _ids(link)
    metrics = services.metrics.grants
    keys = {KeyType.SUBJECT: str(recipient_id), KeyType.IP: ip, KeyType.TENANT: str(tenant_id)}
    await services.limiter.check(GRANT_REQUEST, keys)
    scope = Scope.resource(tenant_id, Subject.recipient(recipient_id))
    actor = Actor(ActorType.RECIPIENT, recipient_id)
    refusal: tuple[GrantResult, ProblemError] | None = None
    async with database.transaction(scope) as session:
        seen = await recipients.link_view(session, recipient_id)
        _check_transfer(seen, now)
        transfer_id = seen.transfer_id
        if await link_sessions.get_live(session, session_id) is None:
            raise Unauthenticated("session_expired")
        try:
            file = await files.get_file(session, file_id)
        except NotFoundError:
            raise NotFound from None
        counted = await downloads.counter(session, recipient_id, file_id)
        if resume_grant_id is not None:
            return await _resume(
                session, services, tenant_id, link, file, resume_grant_id, origin, now
            )
        if not _shareable(file) or counted is None:
            refusal = (
                GrantResult.NOT_SHAREABLE,
                Conflict("file_not_shareable", "This file can't be downloaded."),
            )
        elif counted.download_limit is not None and counted.count >= counted.download_limit:
            refusal = GrantResult.LIMIT_REACHED, Forbidden("download_limit_reached")
    if refusal is not None:
        metrics.labels(refusal[0].value).inc()
        await _refused(database, scope, recipient_id, file_id, refusal[0], origin)
        raise refusal[1]
    size = file.actual_size or 0
    version = file.s3_version_id or ""
    # The tenant's grant rate and the byte caps are only read here: they are charged, all or
    # none, in the grant's own transaction, so a 503 or a lost race costs nothing (#180 review).
    charges = grant_charges(keys, size)
    await services.limiter.peek_all(charges)

    grant_id = uuid7()
    intent = ArchivedEvent(
        id=uuid7(),
        tenant_id=tenant_id,
        occurred_at=now,
        action="download.grant_intent",
        actor_type=ActorType.RECIPIENT.value,
        actor_id=recipient_id,
        target_type=FILE,
        target_id=file_id,
        outcome=Outcome.SUCCESS.value,
        details={"grant_id": str(grant_id), "link_session_id": str(session_id)},
    )

    async def commit() -> tuple[DownloadView, ArchivedEvent]:
        async with database.transaction(scope) as session:
            # The archive writes took time: under the transfer's row lock, which a revocation
            # takes too, check again what the first read checked, and take the session's end
            # from this read, so the grant never outlives it.
            try:
                await transfer_rows.get_transfer(session, transfer_id, lock=True)
                _check_transfer(await recipients.link_view(session, recipient_id), now)
                current = await files.get_file(session, file_id)
            except NotFoundError:
                raise NotFound from None
            still = await link_sessions.get_live(session, session_id)
            if still is None:
                raise Unauthenticated("session_expired")
            if not _shareable(current) or current.s3_version_id != version:
                raise Conflict("file_not_shareable", "This file can't be downloaded.")
            count = await downloads.count_download(session, recipient_id, file_id)
            if count is None:
                raise Forbidden("download_limit_reached")
            if await transfer_rows.claim_first_download_notice(session, transfer_id):
                # The transfer's first counted download, and its member asked to be told (FR-8):
                # once per transfer, committed with the count or not at all.
                await enqueue(session, TRANSFER_FIRST_DOWNLOAD, {"transfer_id": transfer_id})
            grant = await downloads.insert_grant(
                session,
                grant_id=grant_id,
                file_id=file_id,
                s3_version_id=version,
                recipient_id=recipient_id,
                link_session_id=session_id,
                size=size,
                ends_by=still.expires_at,
            )
            await audit.record(
                session,
                action="download.granted",
                actor=actor,
                target=Target(FILE, file_id),
                origin=origin,
                security_critical=True,
                details={
                    "grant_id": grant_id,
                    "link_session_id": session_id,
                    "count": count,
                    "byte_budget": grant.byte_budget,
                },
            )
            counted_now = await downloads.counter(session, recipient_id, file_id)
            # Last before the commit: charged all or none; a refusal rolls the grant back.
            await services.limiter.check_all(charges)
        return _view(tenant_id, grant, file, counted_now), committed_record(grant)

    async def confirmed(view: DownloadView) -> None:
        async with database.transaction(scope) as session:
            await downloads.mark_archived(session, view.grant_id)

    try:
        view = await intent_first(services.archive, intent, commit, on_confirmed=confirmed)
    except RecordNotConfirmed:
        metrics.labels(GrantResult.UNAVAILABLE.value).inc()
        raise
    except Forbidden as refused:
        metrics.labels(GrantResult.LIMIT_REACHED.value).inc()
        await _refused(database, scope, recipient_id, file_id, GrantResult.LIMIT_REACHED, origin)
        raise refused from None
    except Conflict:
        metrics.labels(GrantResult.NOT_SHAREABLE.value).inc()
        raise
    metrics.labels(GrantResult.GRANTED.value).inc()
    return view


async def _resume(
    session: AsyncSession,
    services: DownloadServices,
    tenant_id: UUID,
    link: LinkCaller,
    file: File,
    grant_id: UUID,
    origin: Origin,
    now: datetime,
) -> DownloadView:
    _, recipient_id, session_id = _ids(link)
    try:
        grant = await downloads.get_grant(session, grant_id)
    except NotFoundError:
        raise NotFound from None
    if grant.link_session_id != session_id or grant.file_id != file.id:
        raise NotFound
    if not grant.usable(now) or not _shareable(file):
        services.metrics.grants.labels(GrantResult.EXHAUSTED.value).inc()
        raise Forbidden("download_grant_exhausted")
    await audit.record(
        session,
        action="download.resumed",
        actor=Actor(ActorType.RECIPIENT, recipient_id),
        target=Target(FILE, file.id),
        origin=origin,
        details={"grant_id": grant.id},
    )
    counted = await downloads.counter(session, recipient_id, file.id)
    services.metrics.grants.labels(GrantResult.RESUMED.value).inc()
    return _view(tenant_id, grant, file, counted)


# ---- getSessionDownloadContent ----


@dataclass(frozen=True, slots=True)
class ByteRange:
    start: int
    end: int
    """Inclusive."""

    @property
    def length(self) -> int:
        return self.end - self.start + 1


def parse_range(header: str | None, size: int) -> ByteRange | None:
    """One range of the contract's pattern, fitted to the file; None for the whole file.
    Anything else, several ranges included, is `416` (abuse 5.6)."""
    if header is None:
        return None
    match = _RANGE.fullmatch(header.strip())
    if match is None:
        raise RangeNotSatisfiable(size, "Ask for one range: bytes=<start>-<end>.")
    first, last, suffix = match.groups()
    if suffix is not None:
        length = int(suffix)
        if length == 0:
            raise RangeNotSatisfiable(size)
        return ByteRange(max(0, size - length), size - 1)
    start = int(first)
    end = size - 1 if not last else min(int(last), size - 1)
    if start >= size or (last and int(last) < start):
        raise RangeNotSatisfiable(size)
    return ByteRange(start, end)


def etag_for(file_id: UUID, sha256: bytes | None, version_id: str) -> str:
    """A strong validator: the file's SHA-256, or, for a file scanned before the worker recorded
    digests, its ID and recorded version, whose bytes never change either."""
    if sha256 is not None:
        return f'"{sha256.hex()}"'
    return f'"v-{file_id.hex}-{version_id}"'


def disposition(name: str) -> str:
    """`attachment; filename*=UTF-8''…`, the name percent-encoded (RFC 8187): never inline."""
    return f"attachment; filename*=UTF-8''{quote(name, safe='')}"


SECURITY_HEADERS: Final = {
    "Content-Type": "application/octet-stream",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox; default-src 'none'",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "Accept-Ranges": "bytes",
}
"""Abuse 5.6: bytes from the API's origin are never rendered, cached or embedded."""


@dataclass
class Download:
    """An admitted content request: the status and headers to send, and the stream."""

    status: int
    headers: dict[str, str]
    stream: Stream


async def _find_grant(
    database: Database, cookie: Sequence[str], grant_id: UUID
) -> tuple[link_sessions.FoundLinkSession, Grant]:
    """The grant, through the cookie's session that holds it: `401` without a usable cookie,
    `404` if none of its sessions holds the grant (authn and authz 4.3)."""
    if not cookie:
        raise Unauthenticated("authentication_required")
    async with database.transaction(Scope.lookup()) as session:
        held = await link_sessions.lookup(session, cookie)
    if not held:
        raise Unauthenticated("authentication_required")
    for found in reversed(held):  # the newest first
        if found.recipient_id is None:
            continue  # an uploader's session holds no grant (#212)
        scope = Scope.resource(found.tenant_id, Subject.recipient(found.recipient_id))
        async with database.transaction(scope) as session:
            try:
                grant = await downloads.get_grant(session, grant_id)
            except NotFoundError:
                continue
        if grant.link_session_id == found.session_id:
            return found, grant
    raise NotFound


async def open_content(
    database: Database,
    services: DownloadServices,
    cookie: Sequence[str],
    grant_id: UUID,
    *,
    range_header: str | None,
    if_range: str | None,
    ip: str,
    now: datetime,
) -> Download:
    """`getSessionDownloadContent` up to the first byte (module docstring)."""
    found, grant = await _find_grant(database, cookie, grant_id)
    tenant_id, recipient_id = found.tenant_id, found.recipient_id
    if recipient_id is None:  # pragma: no cover - _find_grant reads recipients' sessions only
        raise NotFound
    scope = Scope.resource(tenant_id, Subject.recipient(recipient_id))
    async with database.transaction(scope) as session:
        _check_transfer(await recipients.link_view(session, recipient_id), now)
        live = await link_sessions.get_live(session, found.session_id) if found.live else None
        if live is None:
            raise Unauthenticated("session_expired")
        try:
            file = await files.get_file(session, grant.file_id)
        except NotFoundError:
            raise NotFound from None
    if not _shareable(file) or file.s3_version_id != grant.s3_version_id:
        raise NotFound
    size = file.actual_size or 0
    etag = etag_for(file.id, file.sha256, grant.s3_version_id)
    wanted = parse_range(range_header, size)
    if wanted is not None and if_range is not None and if_range.strip() != etag:
        wanted = None  # the validator changed: the whole file (RFC 9110 13.1.5)
    whole = ByteRange(0, size - 1)
    span = wanted or whole

    stream_id = uuid4()
    slot = await services.limits.open_stream(
        {
            KeyType.LINK_SESSION: str(found.session_id),
            KeyType.IP: ip,
            KeyType.TENANT: str(tenant_id),
        },
        stream_id,
    )
    try:
        async with database.transaction(scope) as session:
            admitted = await downloads.admit(session, grant.id, stream_id, need=span.length)
    except BaseException:
        await slot.release()
        raise
    if admitted is None:
        await slot.release()
        services.metrics.grants.labels(GrantResult.EXHAUSTED.value).inc()
        raise Forbidden("download_grant_exhausted")
    headers = {
        **SECURITY_HEADERS,
        "ETag": etag,
        "Content-Disposition": disposition(fields.open_sealed(tenant_id, file.display_name_ct)),
        "Content-Length": str(span.length),
    }
    if wanted is not None:
        headers["Content-Range"] = f"bytes {span.start}-{span.end}/{size}"
    stream = Stream(
        database=database,
        services=services,
        scope=scope,
        grant=grant,
        session_id=found.session_id,
        stream_id=stream_id,
        slot=slot,
        storage_class=StorageClass(file.storage_class),
        storage_key=file.storage_key,
        span=span,
        size=size,
    )
    return Download(206 if wanted is not None else 200, headers, stream)


@dataclass
class Stream:
    """One running stream: its bytes, its re-checks and its end (module docstring)."""

    database: Database
    services: DownloadServices
    scope: Scope
    grant: Grant
    session_id: UUID
    stream_id: UUID
    slot: StreamSlot
    storage_class: StorageClass
    storage_key: str
    span: ByteRange
    size: int
    check: Callable[[AsyncSession], Awaitable[Ended | None]] | None = None
    """What a re-check reads besides the grant: a member's stream passes its own (#213); a
    recipient's reads the transfer, the link session and the file."""
    actor: Actor | None = None
    """Whose stream it is, in `download.completed` and `download.stopped`: the recipient unless
    given."""
    sent: int = 0
    unrecorded: int = 0
    ended: Ended | None = None
    _source: AsyncIterator[bytes] | None = None
    _last_check: float = field(default_factory=time.monotonic)
    _progress: deque[tuple[float, int]] = field(default_factory=deque)
    _finished: bool = False
    _counted: bool = False
    """Whether `download_streams_active` counts this stream: only once its body started."""

    async def chunks(self) -> AsyncIterator[bytes]:
        """The bytes of the span, which the grant's budget covered when it was admitted,
        re-checked as they go. Exactly the declared length unless a re-check stops it."""
        metrics = self.services.metrics
        metrics.active.inc()
        self._counted = True
        self._progress.append((time.monotonic(), 0))
        source = self.services.content.read(
            self.storage_class,
            self.storage_key,
            self.grant.s3_version_id,
            start=self.span.start,
            end=self.span.end,
        )
        self._source = source
        try:
            async for chunk in source:
                piece = chunk[: self.span.length - self.sent]
                # Counted as it is handed over, before the yield: a client that goes away while
                # this piece is in flight still has it counted against the grant's budget.
                self.sent += len(piece)
                self.unrecorded += len(piece)
                metrics.bytes.inc(len(piece))
                yield piece
                if time.monotonic() - self._last_check >= self.services.recheck_seconds:
                    self.ended = await self.recheck()
                    if self.ended is not None:
                        return
            if self.sent >= self.span.length:
                self.ended = Ended.COMPLETED
        except ObjectStoreError as exc:
            log.warning("download stream failed", extra={"code": exc.code})
            self.ended = Ended.ERROR

    async def recheck(self) -> Ended | None:
        """Record the bytes sent, keep the lease, and check what could stop the stream."""
        now = time.monotonic()
        self._last_check = now
        async with self.database.transaction(self.scope) as session:
            holds = await downloads.record_progress(
                session, self.grant.id, self.stream_id, self.unrecorded
            )
            self.unrecorded = 0
            if not holds:
                return Ended.TAKEN_OVER
            if self.check is not None:
                ended = await self.check(session)
                if ended is not None:
                    return ended
            else:
                stopped = await self._recipient_check(session)
                if stopped is not None:
                    return stopped
        await self.slot.renew()
        self._progress.append((now, self.sent))
        while len(self._progress) > 1 and now - self._progress[1][0] >= SLOW_WINDOW_SECONDS:
            self._progress.popleft()
        since, sent_then = self._progress[0]
        if now - since >= SLOW_WINDOW_SECONDS and (self.sent - sent_then) < (
            SLOW_FLOOR_BYTES_PER_SECOND * (now - since)
        ):
            return Ended.SLOW
        return None

    async def _recipient_check(self, session: AsyncSession) -> Ended | None:
        """A recipient's stream: the transfer, the link session and the file (NFR-6)."""
        recipient_id = self.grant.recipient_id
        if recipient_id is None:  # pragma: no cover - a recipient's grant names them
            return Ended.SESSION_ENDED
        try:
            _check_transfer(
                await recipients.link_view(session, recipient_id), self.services.clock.now()
            )
        except Gone as gone:
            return Ended.REVOKED if gone.code == "link_revoked" else Ended.EXPIRED
        except Unauthenticated:
            return Ended.SESSION_ENDED
        if await link_sessions.get_live(session, self.session_id) is None:
            return Ended.SESSION_ENDED
        try:
            file = await files.get_file(session, self.grant.file_id)
        except NotFoundError:
            return Ended.NOT_SHAREABLE
        if not _shareable(file):
            return Ended.NOT_SHAREABLE
        return None

    async def finish(self) -> None:
        """Record the last bytes and give up the lease and the places, whatever ended the stream.
        Run it once, shielded from cancellation (the route does)."""
        if self._finished:
            return
        self._finished = True
        reason = self.ended or Ended.CLIENT_CLOSED
        metrics = self.services.metrics
        try:
            # Closing the source first, on its own: a client that went away can make it raise,
            # and that must never skip the bytes or the event below (#180 review).
            if self._source is not None:
                try:
                    await self._source.aclose()  # type: ignore[attr-defined]
                except Exception as exc:
                    log.warning(
                        "a stream's source didn't close cleanly",
                        extra={"error": type(exc).__name__},
                    )
            try:
                async with self.database.transaction(self.scope) as session:
                    await downloads.record_progress(
                        session, self.grant.id, self.stream_id, self.unrecorded, ending=True
                    )
                    self.unrecorded = 0
                    await self._audit(session, reason)
            except Exception:
                log.exception("a stream's end couldn't be recorded")
        finally:
            await self.slot.release()
            if self._counted:
                metrics.active.dec()
            metrics.ended.labels(reason.value).inc()

    async def _audit(self, session: AsyncSession, reason: Ended) -> None:
        """Best effort, in the stream's last transaction: never fail closed (abuse 5.4)."""
        actor = self.actor or Actor(ActorType.RECIPIENT, self.grant.recipient_id)
        target = Target(FILE, self.grant.file_id)
        details: dict[str, audit.Detail] = {"grant_id": self.grant.id, "bytes_sent": self.sent}
        if reason is Ended.COMPLETED and self.span.end == self.size - 1:
            await audit.record(
                session, action="download.completed", actor=actor, target=target, details=details
            )
        elif reason in STOPPED_BY_STATE:
            await audit.record(
                session,
                action="download.stopped",
                actor=actor,
                target=target,
                outcome=Outcome.FAILURE,
                details={**details, "reason": reason},
            )


def store_unavailable() -> ServiceUnavailable:
    return ServiceUnavailable(STORE_RETRY_AFTER, "The file can't be read right now. Try again.")


# ---- a member's download of a received file (#213) ----


def received_content_url(file_id: UUID, grant_id: UUID) -> str:
    return f"/v1/files/{file_id}/downloads/{grant_id}/content"


def _received_available(file: File, now: datetime) -> bool:
    """A received file that is there to download: not deleted, not removed by its owner and not
    past its retention, whatever the deletion job has done yet (FR-13). Otherwise `404`."""
    return (
        file.upload_request_id is not None
        and file.removed_at is None
        and file.deleted_at is None
        and FileState(file.state) is not FileState.DELETED
        and (file.delete_after is None or file.delete_after > now)
    )


def _received_shareable(file: File) -> bool:
    return _shareable(file) and not file.dlp_blocked


@dataclass(frozen=True, slots=True)
class _Member:
    tenant_id: UUID
    user_id: UUID
    session_id: UUID

    @property
    def scope(self) -> Scope:
        return Scope.tenant(self.tenant_id)

    @property
    def record_actor(self) -> tuple[str, UUID]:
        """The archive records' actor: made from the grant's row alone, so a member."""
        return ActorType.MEMBER.value, self.user_id


def _member(caller: Caller) -> _Member:
    if (
        caller.kind is not CallerKind.MEMBER
        or caller.tenant_id is None
        or caller.user_id is None
        or caller.credential_id is None
    ):  # pragma: no cover - authorize admits member sessions only
        raise Unauthenticated("authentication_required")
    return _Member(caller.tenant_id, caller.user_id, caller.credential_id)


def _not_shareable() -> Conflict:
    return Conflict("file_not_shareable", "This file can't be downloaded.")


async def _received_file(
    session: AsyncSession, caller: Caller, file_id: UUID, now: datetime, *, lock: bool = False
) -> File:
    """The received file, if the caller owns its request: another member gets `404`, an admin
    acting as one `403 permission_denied`; a file deleted or past its retention is `404`. `lock`
    takes the request's row lock, which an early delete takes too."""
    try:
        file = await files.get_file(session, file_id)
        if file.upload_request_id is None:
            raise NotFound  # a transfer's file is downloaded by its recipients only
        request = await request_rows.get_request(session, file.upload_request_id, lock=lock)
    except NotFoundError:
        raise NotFound from None
    if request.created_by != caller.user_id:
        if sees_tenant(caller, now):
            raise Forbidden("permission_denied", "Only the request's owner may download its files.")
        raise NotFound
    if lock:
        file = await files.get_file(session, file_id)
    if not _received_available(file, now):
        raise NotFound
    return file


def _received_view(tenant_id: UUID, grant: Grant, file: File) -> DownloadView:
    view = _view(tenant_id, grant, file, None)
    return DownloadView(
        grant_id=view.grant_id,
        url=received_content_url(file.id, grant.id),
        expires_at=view.expires_at,
        byte_budget=view.byte_budget,
        request_limit=view.request_limit,
        file=view.file,
        unscannable=view.unscannable,
        downloads_remaining=None,
    )


async def create_received_download(
    database: Database,
    services: DownloadServices,
    caller: Caller,
    file_id: UUID,
    *,
    resume_grant_id: UUID | None,
    ip: str,
    origin: Origin,
    now: datetime,
) -> DownloadView:
    """`createReceivedFileDownload` (module docstring)."""
    authorize(caller, "createReceivedFileDownload", now=now)
    member = _member(caller)
    metrics = services.metrics.grants
    keys = {
        KeyType.ACCOUNT: str(member.user_id),
        KeyType.IP: ip,
        KeyType.TENANT: str(member.tenant_id),
    }
    await services.limiter.check(RECEIVED_GRANT_REQUEST, keys)
    actor = caller.actor()
    refusal: tuple[GrantResult, ProblemError] | None = None
    async with database.transaction(member.scope) as session:
        file = await _received_file(session, caller, file_id, now)
        if await member_sessions.get_live_session(session, member.session_id) is None:
            raise Unauthenticated("session_expired")
        if resume_grant_id is not None:
            return await _resume_received(
                session, services, member, actor, file, resume_grant_id, origin, now
            )
        if not _received_shareable(file):
            refusal = GrantResult.NOT_SHAREABLE, _not_shareable()
    if refusal is not None:
        metrics.labels(refusal[0].value).inc()
        async with database.transaction(member.scope) as session:
            await audit.record(
                session,
                action="download.refused",
                actor=actor,
                target=Target(FILE, file_id),
                outcome=Outcome.FAILURE,
                origin=origin,
                details={"reason": refusal[0]},
            )
        raise refusal[1]
    size = file.actual_size or 0
    version = file.s3_version_id or ""
    charges = received_grant_charges(keys, size)
    await services.limiter.peek_all(charges)

    grant_id = uuid7()
    actor_type, actor_id = member.record_actor
    intent = ArchivedEvent(
        id=uuid7(),
        tenant_id=member.tenant_id,
        occurred_at=now,
        action="download.grant_intent",
        actor_type=actor_type,
        actor_id=actor_id,
        target_type=FILE,
        target_id=file_id,
        outcome=Outcome.SUCCESS.value,
        details={"grant_id": str(grant_id), "member_session_id": str(member.session_id)},
    )

    async def commit() -> tuple[DownloadView, ArchivedEvent]:
        async with database.transaction(member.scope) as session:
            # The archive writes took time: under the request's row lock, which an early delete
            # takes too, read the session and the file again, and end the grant with the session.
            current = await _received_file(session, caller, file_id, now, lock=True)
            live = await member_sessions.get_live_session(session, member.session_id)
            if live is None:
                raise Unauthenticated("session_expired")
            if not _received_shareable(current) or current.s3_version_id != version:
                raise _not_shareable()
            grant = await downloads.insert_member_grant(
                session,
                grant_id=grant_id,
                file_id=file_id,
                s3_version_id=version,
                user_id=member.user_id,
                member_session_id=member.session_id,
                size=size,
                ends_by=live.expires_at,
            )
            await audit.record(
                session,
                action="download.granted",
                actor=actor,
                target=Target(FILE, file_id),
                origin=origin,
                security_critical=True,
                details={
                    "grant_id": grant_id,
                    "member_session_id": member.session_id,
                    "upload_request_id": current.upload_request_id,
                    "byte_budget": grant.byte_budget,
                },
            )
            # Last before the commit: charged all or none; a refusal rolls the grant back.
            await services.limiter.check_all(charges)
        return _received_view(member.tenant_id, grant, current), committed_record(grant)

    async def confirmed(view: DownloadView) -> None:
        async with database.transaction(member.scope) as session:
            await downloads.mark_archived(session, view.grant_id)

    try:
        view = await intent_first(services.archive, intent, commit, on_confirmed=confirmed)
    except RecordNotConfirmed:
        metrics.labels(GrantResult.UNAVAILABLE.value).inc()
        raise
    except Conflict:
        metrics.labels(GrantResult.NOT_SHAREABLE.value).inc()
        raise
    metrics.labels(GrantResult.GRANTED.value).inc()
    return view


async def _resume_received(
    session: AsyncSession,
    services: DownloadServices,
    member: _Member,
    actor: Actor,
    file: File,
    grant_id: UUID,
    origin: Origin,
    now: datetime,
) -> DownloadView:
    """The same grant again, while it has time, bytes and requests left (FR-6): only in the
    member session that made it, for the same file; any other grant is `404`."""
    try:
        grant = await downloads.get_grant(session, grant_id)
    except NotFoundError:
        raise NotFound from None
    if grant.member_session_id != member.session_id or grant.file_id != file.id:
        raise NotFound
    if not grant.usable(now) or not _received_shareable(file):
        services.metrics.grants.labels(GrantResult.EXHAUSTED.value).inc()
        raise Forbidden("download_grant_exhausted")
    await audit.record(
        session,
        action="download.resumed",
        actor=actor,
        target=Target(FILE, file.id),
        origin=origin,
        details={"grant_id": grant.id},
    )
    services.metrics.grants.labels(GrantResult.RESUMED.value).inc()
    return _received_view(member.tenant_id, grant, file)


async def open_received_content(
    database: Database,
    services: DownloadServices,
    caller: Caller,
    file_id: UUID,
    grant_id: UUID,
    *,
    range_header: str | None,
    if_range: str | None,
    ip: str,
    now: datetime,
) -> Download:
    """`getReceivedFileDownloadContent` up to the first byte (module docstring): the grant of
    this member session and this file only, else `404`."""
    authorize(caller, "getReceivedFileDownloadContent", now=now)
    member = _member(caller)
    scope = member.scope
    async with database.transaction(scope) as session:
        try:
            grant = await downloads.get_grant(session, grant_id)
        except NotFoundError:
            raise NotFound from None
        if grant.member_session_id != member.session_id or grant.file_id != file_id:
            raise NotFound  # another session's grant, even the same member's (FR-14)
        if await member_sessions.get_live_session(session, member.session_id) is None:
            raise Unauthenticated("session_expired")
        try:
            file = await files.get_file(session, file_id)
        except NotFoundError:
            raise NotFound from None
    if (
        not _received_available(file, now)
        or not _received_shareable(file)
        or file.s3_version_id != grant.s3_version_id
    ):
        raise NotFound
    size = file.actual_size or 0
    etag = etag_for(file.id, file.sha256, grant.s3_version_id)
    wanted = parse_range(range_header, size)
    if wanted is not None and if_range is not None and if_range.strip() != etag:
        wanted = None  # the validator changed: the whole file (RFC 9110 13.1.5)
    span = wanted or ByteRange(0, size - 1)

    stream_id = uuid4()
    slot = await services.limits.open_stream(
        {
            KeyType.ACCOUNT: str(member.user_id),
            KeyType.IP: ip,
            KeyType.TENANT: str(member.tenant_id),
        },
        stream_id,
        caps=MEMBER_STREAM_CAPS,
    )
    try:
        async with database.transaction(scope) as session:
            admitted = await downloads.admit(session, grant.id, stream_id, need=span.length)
    except BaseException:
        await slot.release()
        raise
    if admitted is None:
        await slot.release()
        services.metrics.grants.labels(GrantResult.EXHAUSTED.value).inc()
        raise Forbidden("download_grant_exhausted")
    headers = {
        **SECURITY_HEADERS,
        "ETag": etag,
        "Content-Disposition": disposition(
            fields.open_sealed(member.tenant_id, file.display_name_ct)
        ),
        "Content-Length": str(span.length),
    }
    if wanted is not None:
        headers["Content-Range"] = f"bytes {span.start}-{span.end}/{size}"

    async def check(session: AsyncSession) -> Ended | None:
        # Reading the session as a request does moves its `last_seen_at`, so a long download
        # keeps it from ending for idleness; its 12 hours still apply (data model 2.3).
        if await member_sessions.get_live_session(session, member.session_id) is None:
            return Ended.SESSION_ENDED
        try:
            current = await files.get_file(session, file_id)
        except NotFoundError:
            return Ended.NOT_SHAREABLE
        if not _received_available(current, services.clock.now()) or not _received_shareable(
            current
        ):
            return Ended.NOT_SHAREABLE
        return None

    stream = Stream(
        database=database,
        services=services,
        scope=scope,
        grant=grant,
        session_id=member.session_id,
        stream_id=stream_id,
        slot=slot,
        storage_class=StorageClass(file.storage_class),
        storage_key=file.storage_key,
        span=span,
        size=size,
        check=check,
        actor=caller.actor(),
    )
    return Download(206 if wanted is not None else 200, headers, stream)
