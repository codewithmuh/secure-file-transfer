"""Recipients' and uploaders' links, verification codes and link sessions (#179, #212; FR-14,
FR-15, NFR-14; authn and authz 4; data model 2.4; abuse and rate limits 2.2 A and C).

**Two subjects, one flow.** A link names a subject: a transfer's recipient or an upload request's
uploader (`sft.data.scope.Subject`). Every step below works the same for both, through the
subject's own data functions (`sft.data.recipients`, `sft.data.upload_requests`); where this text
says "recipient", an uploader is meant too. An upload request's link is live while the request is
`open` and before its `expires_at`; revoked it is `410 link_revoked`, past its time `410
link_expired`. A recipient's session never reaches an upload request, and an uploader's never a
transfer (T-20): each resource scope reaches its own subject's rows only (`TenantOwned.reach`).

**The link steps** (`resolveLink`, `requestVerificationCode`, `createLinkSession`) are public. Each
runs the per-IP link limits first, before the token is looked up, so a `429` reveals nothing about
a token (abuse 2.4); the limits fail closed, `503`, when the counter store is down. Then the token
is looked up by its SHA-256 (the credential lookup, `sft.data.link_subjects`), and the request
continues in the subject's tenant scope: the recipient isn't verified yet, so there is no link
session, and every query names the recipient the token found. A token no live link has is
`404 link_not_found`, and counts against the IP's 20 an hour; a revoked transfer's is
`410 link_revoked`, an expired one's `410 link_expired`. A token alone reveals only the link's
kind, its access state and the locale.

**Codes** (data model 2.4). `requestVerificationCode` refuses a locked recipient (`403
recipient_locked`) and an address the tenant suppresses (`422 recipient_undeliverable`), then
applies the per-link (with the link's issue time, so a new link starts afresh), per-address
(across tenants) and per-tenant limits, then writes an outbox message: the notification worker
makes the code and emails it to the stored address only (`sft.service.notifications`). Checking a
code in `createLinkSession` runs the five steps of data model 2.4 in one transaction: lock the
recipient unless locked; take an attempt with one conditional update; compare the HMAC in
constant time; on a match, use the code up, start a link session and record the verification; on
a mismatch, count it, and lock at the 20th. A lockout is a security-critical record: it goes to
both regions' audit archive before the answer (`503` if it can't, the lockout kept), and an outbox
notice emails the owner and the tenant admins. Every attempt is audited with the source IP and
user agent: a match, a mismatch, a code that can't be used any more, a refusal because locked.

**Link sessions** (authn and authz 4.3). A session has its own 256-bit token, stored as its
SHA-256. The `__Host-sft_link` cookie holds the tokens of up to 10, joined by `.`; verifying sets a
new value with the new session's token and the browser's other live sessions, without one for the
same recipient (which it replaces); an 11th ends the oldest. Every `/session` call names its
session in `X-Link-Session`; one this cookie doesn't hold is `401 authentication_required`, an
ended one `401 session_expired`, and the call then runs in the session's resource scope, which
reaches its recipient's transfer and files only. A session lasts 24 hours, never past the
transfer's expiry, and ends after an hour without a request. Each has its own CSRF token, derived
from its token with `csrf-hmac` (authn and authz 3.4).

Metrics (abuse 8.1): `link_lookups_total{result}`, `verification_attempts_total{result}`,
`verification_codes_total{result}`, `recipient_lockouts_total` and `uploader_lockouts_total`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Final, Literal
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Forbidden,
    Gone,
    NotFound,
    RateLimited,
    Unauthenticated,
    Unprocessable,
)
from sft.core.hmac_keyrings import CodeKeyring, epoch_micros
from sft.core.pseudonyms import EmailKeyring
from sft.data import (
    audit,
    codes,
    files,
    link_sessions,
    link_subjects,
    recipients,
    suppressions,
    tenants,
    upload_requests,
    users,
)
from sft.data import transfers as transfer_rows
from sft.data.access import NotFoundError
from sft.data.audit import Actor, ArchivedEvent, Origin, Target
from sft.data.database import Database
from sft.data.models import (
    ActorType,
    File,
    FileState,
    InspectionState,
    Outcome,
    TransferState,
    UploadRequestState,
)
from sft.data.outbox import (
    RECIPIENT_CODE_REQUESTED,
    RECIPIENT_LOCKED,
    UPLOAD_REQUEST_CODE_REQUESTED,
    UPLOAD_REQUEST_UPLOADER_LOCKED,
    enqueue,
)
from sft.data.scope import Scope, Subject, SubjectKind
from sft.service import fields, uploads
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller, CallerKind
from sft.service.csrf import CsrfKeyring
from sft.service.evaluation import is_blocked, is_shareable
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import (
    A_FAILED_CODES,
    A_NOT_FOUND,
    CODE_ATTEMPT,
    LINK_STEP,
    REQUEST_CODE,
    KeyType,
)

log = logging.getLogger(__name__)

RECIPIENT: Final = "recipient"
UPLOAD_REQUEST: Final = upload_requests.TARGET
LINK_SESSION: Final = "link_session"
CODE_VALID_FOR_SECONDS: Final = int(codes.LIFETIME.total_seconds())
MAX_ATTEMPTS: Final = codes.MAX_ATTEMPTS
_COOKIE_TOKEN: Final = re.compile(r"[A-Za-z0-9_-]{43}")

AccessState = Literal["verification_required", "verified", "locked"]
LinkKind = Literal["transfer", "upload_request"]


class Reason(StrEnum):
    """Why a link step was refused, in its audit event's details."""

    LOCKED = "locked"
    SUPPRESSED = "suppressed"
    UNUSABLE = "unusable"
    MISMATCH = "mismatch"
    UNKNOWN_KEY = "unknown_key"
    """The code was made under a key the API no longer holds: unusable, never a failure."""


class Ended(StrEnum):
    """Why a link session ended, in its audit event's details."""

    SIGNED_OUT = "signed_out"
    REPLACED = "replaced"
    SESSION_LIMIT = "session_limit"


@dataclass(frozen=True)
class LinkMetrics:
    lookups: Counter
    attempts: Counter
    codes: Counter
    lockouts: Counter
    uploader_lockouts: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> LinkMetrics:
        lookups = Counter(
            "link_lookups_total",
            "Link tokens looked up, by result: found, not_found, revoked, expired.",
            ["result"],
            registry=registry,
        )
        attempts = Counter(
            "verification_attempts_total",
            "Code checks, by result: match, mismatch, unusable, unknown_key, locked.",
            ["result"],
            registry=registry,
        )
        code_requests = Counter(
            "verification_codes_total",
            "Code requests, by result: requested, locked, undeliverable, rate_limited.",
            ["result"],
            registry=registry,
        )
        lockouts = Counter(
            "recipient_lockouts_total",
            "Recipients locked after 20 failed attempts (NFR-14).",
            registry=registry,
        )
        uploader_lockouts = Counter(
            "uploader_lockouts_total",
            "Uploaders locked after 20 failed attempts (NFR-14, #212).",
            registry=registry,
        )
        for result in ("found", "not_found", "revoked", "expired"):
            lookups.labels(result)
        for result in ("match", "mismatch", "unusable", "unknown_key", "locked"):
            attempts.labels(result)
        for result in ("requested", "locked", "undeliverable", "rate_limited"):
            code_requests.labels(result)
        return cls(lookups, attempts, code_requests, lockouts, uploader_lockouts)


@dataclass(frozen=True)
class LinkServices:
    """What the link steps use beyond the database, from the API's lifespan."""

    limiter: RateLimiter
    emails: EmailKeyring
    codes: CodeKeyring
    csrf: CsrfKeyring
    archive: AuditArchive
    metrics: LinkMetrics


def cookie_tokens(value: str | None) -> list[str]:
    """The session tokens of a `__Host-sft_link` value: well-formed ones only, each once, at most
    10. Anything else in the cookie is ignored, never an error."""
    if not value:
        return []
    found = [t for t in dict.fromkeys(value.split(".")) if _COOKIE_TOKEN.fullmatch(t)]
    return found[: link_sessions.MAX_PER_BROWSER]


def cookie_value(tokens: Sequence[str]) -> str:
    return ".".join(tokens)


def _uploader(subject: Subject) -> bool:
    return subject.kind is SubjectKind.UPLOAD_REQUEST


def _actor(subject: Subject) -> Actor:
    """The audit actor of a link step or a link session: the recipient, or the uploader by their
    request's ID."""
    return Actor(ActorType.UPLOADER if _uploader(subject) else ActorType.RECIPIENT, subject.id)


def _target(subject: Subject) -> Target:
    return Target(UPLOAD_REQUEST if _uploader(subject) else RECIPIENT, subject.id)


def _kind(subject: Subject) -> LinkKind:
    return "upload_request" if _uploader(subject) else "transfer"


# ---- the subject ----


class Status(StrEnum):
    """Where a link's item stands, read from its rows and the time (data model 3.2, 3.3)."""

    LIVE = "live"
    REVOKED = "revoked"
    EXPIRED = "expired"
    CLOSED = "closed"
    """Not shared (any longer): a transfer that isn't sent, which the link never was for."""


@dataclass(frozen=True, slots=True)
class SubjectView:
    """A recipient or an uploader as the link steps and link sessions see them."""

    subject: Subject
    email: str
    email_normalized: str
    locale: str
    link_issued_at: datetime | None
    locked_at: datetime | None
    ends_at: datetime | None
    """The transfer's or request's expiry, which no link session outlives."""
    status: Status
    tenant_active: bool
    transfer_id: UUID | None = None
    """A recipient's transfer."""


async def _subject_view(session: AsyncSession, subject: Subject, now: datetime) -> SubjectView:
    """The subject in the session's tenant or resource scope, or `NotFoundError`."""
    if _uploader(subject):
        request = await upload_requests.link_view(session, subject.id)
        if request.state is UploadRequestState.REVOKED:
            status = Status.REVOKED
        elif request.state is UploadRequestState.EXPIRED or request.expires_at <= now:
            status = Status.EXPIRED
        else:
            status = Status.LIVE
        return SubjectView(
            subject=subject,
            email=request.email,
            email_normalized=request.email_normalized,
            locale=request.locale,
            link_issued_at=request.link_issued_at,
            locked_at=request.locked_at,
            ends_at=request.expires_at,
            status=status,
            tenant_active=request.tenant_active,
        )
    view = await recipients.link_view(session, subject.id)
    state = TransferState(view.transfer_state)
    expired = view.expires_at is not None and view.expires_at <= now
    if state is TransferState.REVOKED:
        status = Status.REVOKED
    elif state is TransferState.EXPIRED or (state is TransferState.SENT and expired):
        status = Status.EXPIRED
    elif state is TransferState.SENT:
        status = Status.LIVE
    else:
        status = Status.CLOSED
    return SubjectView(
        subject=subject,
        email=view.email,
        email_normalized=view.email_normalized,
        locale=view.locale,
        link_issued_at=view.link_issued_at,
        locked_at=view.locked_at,
        ends_at=view.expires_at,
        status=status,
        tenant_active=view.tenant_active,
        transfer_id=view.transfer_id,
    )


# ---- the token ----


@dataclass(frozen=True, slots=True)
class _Link:
    found: link_subjects.FoundSubject
    view: SubjectView

    @property
    def subject(self) -> Subject:
        return self.found.subject

    @property
    def scope(self) -> Scope:
        return Scope.tenant(self.found.tenant_id)

    @property
    def target(self) -> Target:
        return _target(self.subject)


async def _link(
    database: Database, services: LinkServices, token: str, ip: str, now: datetime
) -> _Link:
    """The recipient or uploader of a live link, after the per-IP limits; 404 or 410 otherwise."""
    async with database.transaction(Scope.lookup()) as session:
        found = await link_subjects.find_by_token(session, token)
    if found is not None:
        async with database.transaction(Scope.tenant(found.tenant_id)) as session:
            try:
                view: SubjectView | None = await _subject_view(session, found.subject, now)
            except NotFoundError:
                view = None
        if view is not None and view.tenant_active:
            if view.status is Status.REVOKED:
                services.metrics.lookups.labels("revoked").inc()
                raise Gone("link_revoked")
            if view.status is Status.EXPIRED:
                services.metrics.lookups.labels("expired").inc()
                raise Gone("link_expired")
            if view.status is Status.LIVE:
                services.metrics.lookups.labels("found").inc()
                return _Link(found, view)
    services.metrics.lookups.labels("not_found").inc()
    await services.limiter.record(A_NOT_FOUND, ip)
    raise NotFound("link_not_found")


# ---- resolveLink ----


@dataclass(frozen=True, slots=True)
class Resolution:
    access_state: AccessState
    locale: str
    link_session_id: UUID | None = None
    kind: LinkKind = "transfer"


async def resolve_link(
    database: Database,
    services: LinkServices,
    token: str,
    *,
    cookie: Sequence[str],
    ip: str,
    now: datetime,
) -> Resolution:
    """`resolveLink`: the link's access state and locale, and the browser's live session for it.
    Changes nothing, so an email scanner that runs the page uses up no code and no attempt."""
    await services.limiter.check(LINK_STEP, {KeyType.IP: ip})
    link = await _link(database, services, token, ip, now)
    kind = _kind(link.subject)
    if link.view.locked_at is not None:
        return Resolution("locked", link.view.locale, kind=kind)
    async with database.transaction(Scope.lookup()) as session:
        held = await link_sessions.lookup(session, cookie)
    for found in reversed(held):  # the newest first
        if found.live and found.subject == link.subject:
            return Resolution("verified", link.view.locale, found.session_id, kind=kind)
    return Resolution("verification_required", link.view.locale, kind=kind)


# ---- requestVerificationCode ----


async def _refuse(
    database: Database,
    link: _Link,
    action: str,
    reason: Reason,
    origin: Origin,
    **details: audit.Detail,
) -> None:
    """Audit a refused link step in a transaction of its own: the request changes nothing else."""
    async with database.transaction(link.scope) as session:
        await audit.record(
            session,
            action=action,
            actor=_actor(link.subject),
            target=link.target,
            outcome=Outcome.FAILURE,
            origin=origin,
            details={"reason": reason, **details},
        )


async def request_code(
    database: Database,
    services: LinkServices,
    token: str,
    *,
    ip: str,
    origin: Origin,
    now: datetime,
) -> None:
    """`requestVerificationCode`: an outbox message for the notification worker, which makes the
    code and emails it to the stored address only."""
    await services.limiter.check(LINK_STEP, {KeyType.IP: ip})
    link = await _link(database, services, token, ip, now)
    metrics = services.metrics.codes
    if link.view.locked_at is not None:
        metrics.labels("locked").inc()
        await _refuse(database, link, "verification.code_requested", Reason.LOCKED, origin)
        raise Forbidden("recipient_locked", "Ask the sender to unlock the link.")
    async with database.transaction(link.scope) as session:
        found = await suppressions.suppressed(
            session, services.emails.every_version(link.view.email_normalized)
        )
    if found:
        metrics.labels("undeliverable").inc()
        await _refuse(database, link, "verification.code_requested", Reason.SUPPRESSED, origin)
        raise Unprocessable(
            "recipient_undeliverable", "The code couldn't be sent. Contact the sender."
        )
    issued = link.view.link_issued_at
    per_link = f"{link.subject.id}.{0 if issued is None else epoch_micros(issued)}"
    try:
        await services.limiter.check(
            REQUEST_CODE,
            {
                KeyType.SUBJECT: per_link,
                KeyType.EMAIL: services.emails.for_limits(link.view.email_normalized, now),
                KeyType.TENANT: str(link.found.tenant_id),
                KeyType.IP: ip,
            },
        )
    except RateLimited:
        metrics.labels("rate_limited").inc()
        raise
    async with database.transaction(link.scope) as session:
        if _uploader(link.subject):
            await enqueue(
                session, UPLOAD_REQUEST_CODE_REQUESTED, {"upload_request_id": link.subject.id}
            )
        else:
            await enqueue(session, RECIPIENT_CODE_REQUESTED, {"recipient_id": link.subject.id})
        await audit.record(
            session,
            action="verification.code_requested",
            actor=_actor(link.subject),
            target=link.target,
            origin=origin,
        )
    metrics.labels("requested").inc()


# ---- createLinkSession ----


@dataclass(frozen=True, slots=True)
class SessionTransfer:
    """A recipient's session: their transfer (the contract's `LinkSessionTransfer`)."""

    tenant_name: str
    sender_email: str
    message: str | None
    expires_at: datetime
    download_limit: int | None


@dataclass(frozen=True, slots=True)
class SessionUploadRequest:
    """An uploader's session: their request (the contract's `LinkSessionUploadRequest`), with
    the limits of FR-11 and what has been received so far."""

    tenant_name: str
    requester_email: str
    message: str | None
    expires_at: datetime
    max_files: int = uploads.MAX_FILES
    max_file_size: int = uploads.MAX_FILE_SIZE
    max_total_size: int = uploads.MAX_TOTAL_SIZE
    files_received: int = 0
    """The request's counted files: not `rejected`, not removed (FR-11, #213)."""
    bytes_received: int = 0
    """Their declared bytes."""


@dataclass(frozen=True, slots=True)
class SessionView:
    """What `getLinkSession` and `createLinkSession` answer (the contract's `LinkSession`): exactly
    one of `transfer` and `upload_request`."""

    id: UUID
    csrf_token: str
    email: str
    locale: str
    expires_at: datetime
    transfer: SessionTransfer | None = None
    upload_request: SessionUploadRequest | None = None

    @property
    def kind(self) -> LinkKind:
        return "upload_request" if self.upload_request is not None else "transfer"


@dataclass(frozen=True, slots=True)
class CreatedSession:
    view: SessionView
    cookie: tuple[str, ...]
    """The new `__Host-sft_link` value's tokens: the browser's other live sessions, then this."""


@dataclass(frozen=True, slots=True)
class _Matched:
    token: str
    session_id: UUID


@dataclass(frozen=True, slots=True)
class _Missed:
    remaining: int
    lockout: ArchivedEvent | None


@dataclass(frozen=True, slots=True)
class _Unusable:
    code: codes.Unusable
    unknown_key: bool = False


class _Locked:
    pass


async def create_session(
    database: Database,
    services: LinkServices,
    token: str,
    code: str,
    *,
    cookie: Sequence[str],
    ip: str,
    origin: Origin,
    now: datetime,
) -> CreatedSession:
    """`createLinkSession`: check the code (data model 2.4) and start a link session."""
    await services.limiter.check(CODE_ATTEMPT, {KeyType.IP: ip})
    link = await _link(database, services, token, ip, now)
    async with database.transaction(Scope.lookup()) as session:
        held = await link_sessions.lookup(session, cookie)
    replaced = [s.session_id for s in held if s.subject == link.subject]
    async with database.transaction(link.scope) as session:
        result = await _check(session, services, link, code, replaced, origin)
    attempts = services.metrics.attempts
    if isinstance(result, _Locked):
        attempts.labels("locked").inc()
        await _confirm_lockout(database, services, link)
        raise Forbidden("recipient_locked", "Ask the sender to unlock the link.")
    if isinstance(result, _Unusable):
        attempts.labels("unknown_key" if result.unknown_key else "unusable").inc()
        raise Unprocessable(result.code.value, "Request a new code.")
    if isinstance(result, _Missed):
        attempts.labels("mismatch").inc()
        await services.limiter.record(A_FAILED_CODES, ip)
        if result.lockout is not None:
            lockouts = services.metrics.lockouts
            if _uploader(link.subject):
                lockouts = services.metrics.uploader_lockouts
            lockouts.inc()
            await services.archive.confirm([result.lockout])
            raise Forbidden("recipient_locked", "Ask the sender to unlock the link.")
        raise Unprocessable(
            "code_invalid", "The code doesn't match.", attempts_remaining=result.remaining
        )
    attempts.labels("match").inc()
    kept = [s for s in held if s.live and s.subject != link.subject]
    while len(kept) >= link_sessions.MAX_PER_BROWSER:
        oldest = kept.pop(0)
        await _end(database, oldest, Ended.SESSION_LIMIT, origin)
    view = await _session_view(
        database, link.found.tenant_id, link.subject, result.session_id, now=now
    )
    if view is None:  # pragma: no cover - the session was just made
        raise RuntimeError("the new session isn't live")
    return CreatedSession(
        view=_with_csrf(view, services.csrf.token_for(result.token)),
        cookie=(*(s.token for s in kept), result.token),
    )


async def _check(
    session: AsyncSession,
    services: LinkServices,
    link: _Link,
    code: str,
    replaced: Sequence[UUID],
    origin: Origin,
) -> _Matched | _Missed | _Unusable | _Locked:
    subject = link.subject
    actor, target = _actor(subject), link.target

    async def attempt(outcome: Outcome, **details: audit.Detail) -> None:
        await audit.record(
            session,
            action="verification.attempted",
            actor=actor,
            target=target,
            outcome=outcome,
            origin=origin,
            details=details,
        )

    # 1. The lock, unless locked: parallel attempts queue here.
    if not await _lock_unlocked(session, subject):
        await attempt(Outcome.FAILURE, reason=Reason.LOCKED)
        return _Locked()
    # 2. One attempt of the newest code, if it can still be used.
    code_id = await codes.newest_for(session, subject)
    taken = None if code_id is None else await codes.take_attempt(session, code_id)
    if taken is None:
        unusable = await codes.why_unusable(session, code_id)
        await attempt(Outcome.FAILURE, reason=Reason.UNUSABLE, code_id=code_id)
        return _Unusable(unusable)
    if not services.codes.knows(taken.key_id):
        # The key that made the code has left this keyring (a rotation, encryption and keys 6.5):
        # the code can't be checked, so it can't be used, and that is no guess. The recipient asks
        # for a new code; nothing counts against them.
        log.warning(
            "a code made under a key this API doesn't hold", extra={"code_id": str(code_id)}
        )
        await attempt(Outcome.FAILURE, reason=Reason.UNKNOWN_KEY, code_id=taken.code_id)
        return _Unusable(codes.Unusable.EXPIRED, unknown_key=True)
    # 3. The HMAC, in constant time.
    if services.codes.matches(taken.key_id, taken.code_id, code, taken.code_hmac):
        # 4. A match: the code is used up, the session starts, the verification is recorded.
        await codes.consume(session, taken.code_id)
        if not _uploader(subject):
            # A recipient's status records it (FR-7); an uploader's request has no such columns.
            await recipients.mark_verified(session, subject.id)
        for old in replaced:
            if await link_sessions.revoke(session, old):
                await audit.record(
                    session,
                    action="link_session.ended",
                    actor=actor,
                    target=Target(LINK_SESSION, old),
                    origin=origin,
                    details={"reason": Ended.REPLACED},
                )
        new_token, row = await link_sessions.create_for(session, subject, ends_by=link.view.ends_at)
        await attempt(Outcome.SUCCESS, code_id=taken.code_id)
        owner = "upload_request_id" if _uploader(subject) else "recipient_id"
        await audit.record(
            session,
            action="link_session.started",
            actor=actor,
            target=Target(LINK_SESSION, row.id),
            origin=origin,
            details={owner: subject.id},
        )
        return _Matched(new_token, row.id)
    # 5. A mismatch: counted, and the 20th locks the recipient or uploader.
    failure = await _count_failure(session, subject)
    remaining = MAX_ATTEMPTS - taken.attempts
    await attempt(
        Outcome.FAILURE,
        reason=Reason.MISMATCH,
        code_id=taken.code_id,
        attempts_remaining=remaining,
        failed_attempts=failure.failed_attempts,
    )
    if not failure.locked:
        return _Missed(remaining, None)
    event_id = await audit.record(
        session,
        action=_locked_action(subject),
        actor=actor,
        target=target,
        origin=origin,
        security_critical=True,
        details={"failed_attempts": failure.failed_attempts},
    )
    if _uploader(subject):
        await enqueue(session, UPLOAD_REQUEST_UPLOADER_LOCKED, {"upload_request_id": subject.id})
    else:
        await enqueue(session, RECIPIENT_LOCKED, {"recipient_id": subject.id})
    return _Missed(remaining, await audit.archived_event(session, event_id))


def _locked_action(subject: Subject) -> str:
    return "uploader.locked" if _uploader(subject) else "recipient.locked"


async def _lock_unlocked(session: AsyncSession, subject: Subject) -> bool:
    if _uploader(subject):
        return await upload_requests.lock_unlocked(session, subject.id)
    return await recipients.lock_unlocked(session, subject.id)


async def _count_failure(
    session: AsyncSession, subject: Subject
) -> recipients.Failure | upload_requests.Failure:
    if _uploader(subject):
        return await upload_requests.count_failure(session, subject.id)
    return await recipients.count_failure(session, subject.id)


async def _confirm_lockout(database: Database, services: LinkServices, link: _Link) -> None:
    """A refusal because locked also writes the lockout's record if it is still missing, best
    effort: the refusal stands either way."""
    async with database.transaction(link.scope) as session:
        event = await audit.latest_critical_event(
            session, action=_locked_action(link.subject), target=link.target
        )
    # The archive remembers what it has confirmed, so repeated attempts on a locked recipient
    # write nothing more once the record is in both regions.
    if event is not None and await services.archive.write([event]):
        log.warning("the lockout's record is still not in both regions")


async def _end(
    database: Database, found: link_sessions.FoundLinkSession, why: Ended, origin: Origin
) -> None:
    async with database.transaction(Scope.tenant(found.tenant_id)) as session:
        if await link_sessions.revoke(session, found.session_id):
            await audit.record(
                session,
                action="link_session.ended",
                actor=_actor(found.subject),
                target=Target(LINK_SESSION, found.session_id),
                origin=origin,
                details={"reason": why},
            )


def _with_csrf(view: SessionView, csrf_token: str) -> SessionView:
    return replace(view, csrf_token=csrf_token)


async def _session_view(
    database: Database, tenant_id: UUID, subject: Subject, session_id: UUID, *, now: datetime
) -> SessionView | None:
    """The session as its recipient or uploader sees it, read in the session's resource scope."""
    async with database.transaction(Scope.resource(tenant_id, subject)) as session:
        live = await link_sessions.get_live(session, session_id)
        if live is None:
            return None
        view = await _subject_view(session, subject, now)
        sender = await tenants.sender(session)
        if _uploader(subject):
            request = await upload_requests.get_request(session, subject.id)
            owner = await users.get_user(session, request.created_by)
            if sender is None or owner is None:
                return None
            received = (await files.received_counts(session, [request.id])).get(request.id)
            count, size = received or (0, 0)
            part: SessionTransfer | SessionUploadRequest = SessionUploadRequest(
                tenant_name=sender.name,
                requester_email=owner.email,
                message=_message(tenant_id, request.message_ct),
                expires_at=request.expires_at,
                files_received=count,
                bytes_received=size,
            )
        else:
            if view.transfer_id is None:  # pragma: no cover - every recipient has one
                return None
            transfer = await transfer_rows.get_transfer(session, view.transfer_id)
            owner = await users.get_user(session, transfer.created_by)
            if sender is None or owner is None or transfer.expires_at is None:
                return None
            part = SessionTransfer(
                tenant_name=sender.name,
                sender_email=owner.email,
                message=_message(tenant_id, transfer.message_ct),
                expires_at=transfer.expires_at,
                download_limit=transfer.download_limit,
            )
    return SessionView(
        id=session_id,
        csrf_token="",
        email=view.email,
        locale=view.locale,
        expires_at=live.expires_at,
        transfer=part if isinstance(part, SessionTransfer) else None,
        upload_request=part if isinstance(part, SessionUploadRequest) else None,
    )


def _message(tenant_id: UUID, sealed: bytes | None) -> str | None:
    return None if sealed is None else fields.open_sealed(tenant_id, sealed)


# ---- the /session routes ----


@dataclass(frozen=True, slots=True)
class LinkCaller:
    """A `/session` request's caller and the raw token of its session, for its CSRF token."""

    caller: Caller
    token: str


async def session_caller(
    database: Database,
    cookie: Sequence[str],
    session_id: UUID | None,
    *,
    now: datetime,
) -> LinkCaller:
    """The link session `X-Link-Session` names, if this cookie holds it and it is live: 401
    otherwise, and 410 once its transfer or request is revoked or has expired (authn and authz
    4.3). A recipient's session is a `RECIPIENT` caller, an uploader's an `UPLOADER`."""
    if session_id is None or not cookie:
        raise Unauthenticated("authentication_required")
    async with database.transaction(Scope.lookup()) as session:
        held = await link_sessions.lookup(session, cookie)
    found = next((s for s in held if s.session_id == session_id), None)
    if found is None:
        raise Unauthenticated("authentication_required")
    subject = found.subject
    async with database.transaction(Scope.resource(found.tenant_id, subject)) as session:
        try:
            view = await _subject_view(session, subject, now)
        except NotFoundError:
            raise Unauthenticated("session_expired") from None
        if view.status is Status.REVOKED:
            raise Gone("link_revoked")
        if view.status is Status.EXPIRED:
            raise Gone("link_expired")
        live = await link_sessions.get_live(session, found.session_id) if found.live else None
    if live is None or not view.tenant_active or view.status is not Status.LIVE:
        raise Unauthenticated("session_expired")
    caller = Caller(
        CallerKind.UPLOADER if _uploader(subject) else CallerKind.RECIPIENT,
        tenant_id=found.tenant_id,
        subject=subject,
        credential_id=found.session_id,
    )
    return LinkCaller(caller, found.token)


def _resource(caller: Caller) -> Scope:
    if caller.tenant_id is None or caller.subject is None:  # pragma: no cover - session_caller's
        raise Unauthenticated("authentication_required")
    return Scope.resource(caller.tenant_id, caller.subject)


async def get_session(
    database: Database, services: LinkServices, link: LinkCaller, *, now: datetime
) -> SessionView:
    """`getLinkSession`: what the verified recipient or uploader may now see, and the session's
    CSRF token."""
    caller = link.caller
    if caller.tenant_id is None or caller.subject is None or caller.credential_id is None:
        raise Unauthenticated("authentication_required")  # pragma: no cover
    view = await _session_view(
        database, caller.tenant_id, caller.subject, caller.credential_id, now=now
    )
    if view is None:
        raise Unauthenticated("session_expired")
    return _with_csrf(view, services.csrf.token_for(link.token))


async def end_session(database: Database, link: LinkCaller, *, origin: Origin) -> None:
    """`endLinkSession`: the session named by `X-Link-Session` ends."""
    caller = link.caller
    if caller.credential_id is None or caller.subject is None:  # pragma: no cover
        raise Unauthenticated("authentication_required")
    async with database.transaction(_resource(caller)) as session:
        if await link_sessions.revoke(session, caller.credential_id):
            await audit.record(
                session,
                action="link_session.ended",
                actor=caller.actor(),
                target=Target(LINK_SESSION, caller.credential_id),
                origin=origin,
                details={"reason": Ended.SIGNED_OUT},
            )


@dataclass(frozen=True, slots=True)
class SessionFile:
    id: UUID
    display_name: str
    content_type: str
    size: int
    state: FileState
    unscannable: bool
    download_limit: int | None
    downloads_used: int
    uploader: bool = False
    """An uploader's file (#213): no download count or warning, and its upload plan while
    `uploading`."""
    part_size: int = 0
    part_count: int = 0
    blocked: bool = False
    """An uploader's file the company's checks blocked: infected, scan failed, unscannable and not
    allowed, inspection failed, or a DLP rule for received files (FR-12, FR-51, #221). The
    uploader learns that much and no reason."""


def uploader_file(tenant_id: UUID, file: File) -> SessionFile:
    """A file as its uploader sees it (FR-12): its name, its declared size until the upload is
    accepted, its state and, while uploading, its plan, so the web app can resume it. Never a
    finding or a scan detail. An unscannable file the tenant policy allowed carries the
    `unscannable` warning, so the web app words it as accepted, not as a failure (#229). A file
    the company's checks blocked says so (`blocked`, #221), without saying which check."""
    state = FileState(file.state)
    return SessionFile(
        id=file.id,
        display_name=fields.open_sealed(tenant_id, file.display_name_ct),
        content_type=file.content_type,
        size=file.actual_size or file.declared_size,
        state=FileState(file.state),
        unscannable=file.state == FileState.UNSCANNABLE.value and file.unscannable_allowed,
        download_limit=None,
        downloads_used=0,
        uploader=True,
        part_size=file.part_size,
        part_count=file.part_count,
        blocked=file.dlp_blocked
        or is_blocked(state, file.unscannable_allowed, InspectionState(file.inspection_state)),
    )


async def session_files(database: Database, link: LinkCaller) -> list[SessionFile]:
    """`listSessionFiles`. A recipient's: the transfer's shareable files only, each with this
    recipient's download count and limit, and the unscannable warning (FR-6, FR-16, FR-18). An
    uploader's: the files they sent to the request, removed ones left out, with their state, so a
    blocked file is reported to them and an `uploading` one can be resumed (FR-11, FR-12, #213),
    read in their session's resource scope, which reaches their request's files only."""
    caller = link.caller
    if caller.tenant_id is None or caller.subject is None:  # pragma: no cover
        raise Unauthenticated("authentication_required")
    tenant_id = caller.tenant_id
    if _uploader(caller.subject):
        async with database.transaction(_resource(caller)) as session:
            sent = await files.list_request_files(session, caller.subject.id)
        return [uploader_file(tenant_id, file) for file in sent]
    async with database.transaction(_resource(caller)) as session:
        view = await recipients.link_view(session, caller.subject.id)
        found = await files.list_transfer_files(session, view.transfer_id)
        counted = await recipients.counters(session, caller.subject.id)
    out = []
    for file in found:
        state = FileState(file.state)
        shareable = is_shareable(
            state, file.unscannable_allowed, InspectionState(file.inspection_state)
        )
        if not shareable or file.actual_size is None:
            continue
        counter = counted.get(file.id)
        out.append(
            SessionFile(
                id=file.id,
                display_name=fields.open_sealed(tenant_id, file.display_name_ct),
                content_type=file.content_type,
                size=file.actual_size,
                state=state,
                unscannable=state is FileState.UNSCANNABLE,
                download_limit=None if counter is None else counter.download_limit,
                downloads_used=0 if counter is None else counter.count,
            )
        )
    return out
