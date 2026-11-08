"""Upload requests: a member asks an outsider for files (#212; UC-2, FR-3, FR-10, FR-20, FR-33,
NFR-6, NFR-14; data model 2.2, 2.4, 3.3; authn and authz 4.4, 6.3).

Every function checks the caller against the permission registry first (`authorize`, authn and
authz 6.1), then the resource rule (6.4): a request the caller can't see answers 404, one it can
see but may not act on 403, and a state that doesn't allow the change 409, in that order. The
change, its audit event and any outbox message commit in one transaction (architecture 5.2, 5.3).

- **`createUploadRequest`** (`upload_request.create`): any member or admin, an API key with
  `upload_requests:write`; the member, or the key's owner, owns the request. The expiry is a time
  (FR-3): 1 hour to 30 days from now, within the tenant's `max_expiry`, 7 days (or the maximum if
  shorter) when left out. A client computes it from its own clock, so the bounds allow
  `CLOCK_TOLERANCE` (5 minutes) either way: a time up to 5 minutes short of an hour is kept as
  given, and one up to 5 minutes past the maximum is cut to the maximum; anything further is
  `422 expiry_out_of_range`. An address outside the tenant's domain rules (FR-24, #217) is
  `422 recipient_domain_not_allowed`; one this tenant suppresses is `422 recipient_undeliverable`.
  The link email counts against group G's caps, shared with `sendTransfer` (abuse 2.2): the
  caller's and the tenant's recipient emails, and 20 link emails a day to the address within the
  tenant; a `429` charges nothing and creates nothing. The request is `open` from creation, its
  `delivery_state` `queued`, and an outbox message (`upload_request.link_due`) has the
  notification worker email the link in the request's locale (`sft.service.notifications`). It
  takes `Idempotency-Key`: a retry with the same key and body gets the first answer.
- **`listUploadRequests`, `getUploadRequest`** (`upload_request.read`): Own for a member, Tenant
  for an admin acting as one and for a key with `upload_requests:read`. Another member's request
  is 404 to a member.
- **`revokeUploadRequest`** (`upload_request.revoke`): the owner, any tenant admin (a local admin
  without a passkey too, `PASSKEY_EXEMPT`), a key with `upload_requests:write`. One transaction,
  under the request's row lock: `revoked` with `ended_at` and `revoked_by`, every link session of
  the uploader ends, and `upload_request.revoked` is written, security-critical. The next call of
  the uploader's session answers `410 link_revoked`. Then the record goes to both regions'
  archive before the `200`; `503` means done, not confirmed, and a retry finds the request revoked,
  writes the record if it is still missing and answers `200`. An expired request is
  `409 upload_request_expired`. A safety action: never the tenant's budget (abuse 2.2 H).
- **`unlockUploader`** (`uploader.unlock`): the owner, or an admin acting as one; API keys get
  `403`, since a person decides (authn and authz 4.4). It resets the count, clears the lock and
  the whole link and queues a new link email, so the old link is `404 link_not_found`, with
  `uploader.unlocked`, security-critical: `200` once both regions hold it, `503` otherwise with the
  unlock kept. An uploader who isn't locked is returned unchanged and nothing is sent. A revoked
  or expired request can't be unlocked (`409`).

**Expiry is read, not waited for.** A request past `expires_at` shows as `expired` at once, and
its link answers `410 link_expired`, before the lifecycle job records it (data model 3.3).

**Received files** (#213): `file_count` and `total_size` count the request's files that aren't
`rejected` and weren't removed, by their declared sizes (FR-11). A revocation also rejects, in its
transaction and under the request's row lock, every upload still `uploading` or `completing`, so
none of them is ever assembled (NFR-6); files already received keep their own retention and stay
downloadable (FR-13, UC-3). The files themselves are `sft.service.received`'s.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    FieldError,
    Forbidden,
    NotFound,
    ProblemError,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, files, link_sessions, tenants, upload_requests
from sft.data.access import NotFoundError
from sft.data.audit import ArchivedEvent, Origin, Target
from sft.data.database import Database
from sft.data.models import DeliveryState, UploadRequest, UploadRequestState
from sft.data.outbox import UPLOAD_REQUEST_LINK_DUE, enqueue
from sft.data.upload_requests import TARGET
from sft.service import domain_rules, fields
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller, CallerKind
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import Reach, authorize
from sft.service.rate_limits import RateLimiter
from sft.service.sending import _email_charges as email_charges
from sft.service.transfers import (
    DEFAULT_EXPIRY,
    MAX_EXPIRY,
    MAX_PAGE,
    MIN_EXPIRY,
    audit_details,
    decode_cursor,
    describe_duration,
    encode_cursor,
    tenant_scope,
    undeliverable,
)
from sft.service.uploads import reject_request_uploads

CLOCK_TOLERANCE: Final = timedelta(minutes=5)
"""How far a client's clock may be off when it turns a chosen duration into `expires_at`."""

CREATED: Final = "upload_request.created"
REVOKED: Final = "upload_request.revoked"
UNLOCKED: Final = "uploader.unlocked"

AccessState = Literal["invited", "verified", "locked"]


@dataclass(frozen=True, slots=True)
class NewUploadRequest:
    """`createUploadRequest`'s body."""

    email: str
    locale: str | None = None
    expires_at: datetime | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class UploadRequestView:
    """An upload request as the contract's `UploadRequest` shows it."""

    id: UUID
    state: UploadRequestState
    created_by: UUID
    created_at: datetime
    uploader_email: str
    locale: str
    message: str | None
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: UUID | None
    access_state: AccessState
    delivery_state: DeliveryState
    notified_at: datetime | None
    failed_attempts: int
    locked_at: datetime | None
    file_count: int = 0
    """The request's counted files: not `rejected`, not removed (FR-11, #213)."""
    total_size: int = 0
    """Their declared bytes."""


@dataclass(frozen=True, slots=True)
class UploadRequestPage:
    items: tuple[UploadRequestView, ...]
    next_cursor: str | None


def effective_state(
    state: UploadRequestState, expires_at: datetime, now: datetime
) -> UploadRequestState:
    """The state as the API shows it: `expired` once `expires_at` has passed, before the lifecycle
    job records it (data model 3.3)."""
    if state in upload_requests.EXPIRES_FROM and expires_at <= now:
        return UploadRequestState.EXPIRED
    return state


def access_state(locked_at: datetime | None, verified: bool) -> AccessState:
    """Where the uploader stands (data model 3.4): locked, verified (a live link session), or
    invited."""
    if locked_at is not None:
        return "locked"
    return "verified" if verified else "invited"


def request_view(
    tenant_id: UUID,
    row: UploadRequest,
    now: datetime,
    *,
    verified: bool,
    received: tuple[int, int] = (0, 0),
) -> UploadRequestView:
    """The contract's `UploadRequest`; `received` is its counted files and their bytes."""
    state = effective_state(UploadRequestState(row.state), row.expires_at, now)
    return UploadRequestView(
        id=row.id,
        state=state,
        created_by=row.created_by,
        created_at=row.created_at,
        uploader_email=row.uploader_email,
        locale=row.locale,
        message=None if row.message_ct is None else fields.open_sealed(tenant_id, row.message_ct),
        expires_at=row.expires_at,
        revoked_at=row.ended_at if state is UploadRequestState.REVOKED else None,
        revoked_by=row.revoked_by,
        access_state=access_state(row.locked_at, verified),
        delivery_state=DeliveryState(row.delivery_state),
        notified_at=row.notified_at,
        failed_attempts=row.failed_attempts,
        locked_at=row.locked_at,
        file_count=received[0],
        total_size=received[1],
    )


async def _view(
    session: AsyncSession, tenant_id: UUID, request_id: UUID, now: datetime
) -> UploadRequestView:
    row = await upload_requests.get_request(session, request_id)
    verified = row.id in await upload_requests.live_session_ids(session, [row.id])
    counted = await files.received_counts(session, [row.id])
    return request_view(
        tenant_id, row, now, verified=verified, received=counted.get(row.id, (0, 0))
    )


# ---- the resource rule (authn and authz 6.4) ----


def sees_tenant(caller: Caller, now: datetime) -> bool:
    """Whether the caller may read every request of its tenant: `upload_request.read` at Tenant
    reach, so an admin acting as one, or a key with `upload_requests:read`."""
    try:
        return authorize(caller, "getUploadRequest", now=now) is Reach.TENANT
    except ProblemError:
        return False


def require_visible(caller: Caller, reach: Reach, row: UploadRequest) -> None:
    """A read: Own is the creator, for a key its owner; Tenant sees every request. Else 404."""
    if reach is not Reach.TENANT and row.created_by != caller.user_id:
        raise NotFound


def require_reach(caller: Caller, reach: Reach, row: UploadRequest, now: datetime) -> None:
    """A change: Own is the creator, Tenant every request; 404 for a request the caller can't
    see, 403 for one it sees but may not change."""
    if reach is Reach.TENANT or row.created_by == caller.user_id:
        return
    if sees_tenant(caller, now):
        raise Forbidden("permission_denied", "Only the request's owner may change it.")
    raise NotFound


async def _get(session: AsyncSession, request_id: UUID, *, lock: bool = False) -> UploadRequest:
    try:
        return await upload_requests.get_request(session, request_id, lock=lock)
    except NotFoundError:
        raise NotFound from None


# ---- createUploadRequest ----


def _out_of_range(longest: timedelta) -> Unprocessable:
    detail = f"expires_at is between 1 hour and {describe_duration(longest)} from now."
    return Unprocessable(
        "expiry_out_of_range",
        detail,
        errors=[FieldError(detail, pointer=json_pointer("expires_at"))],
    )


def expiry(requested: datetime | None, max_expiry: timedelta, now: datetime) -> datetime:
    """The request's `expires_at` (FR-3, FR-23; module docstring): as asked, within the bounds
    and `CLOCK_TOLERANCE`, or now plus the shorter of 7 days and the tenant's maximum."""
    longest = min(MAX_EXPIRY, max_expiry)
    if requested is None:
        return now + min(DEFAULT_EXPIRY, longest)
    lead = requested - now
    if lead < MIN_EXPIRY - CLOCK_TOLERANCE or lead > longest + CLOCK_TOLERANCE:
        raise _out_of_range(longest)
    return min(requested, now + longest)


def _undeliverable() -> Unprocessable:
    detail = "The uploader's address bounced or complained; a tenant admin can clear it."
    return Unprocessable(
        "recipient_undeliverable",
        detail,
        errors=[FieldError(detail, pointer=json_pointer("uploader_email"))],
    )


async def create_upload_request(
    database: Database,
    caller: Caller,
    request: NewUploadRequest,
    *,
    emails: EmailKeyring,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[UploadRequestView]:
    """`createUploadRequest` (module docstring)."""
    authorize(caller, "createUploadRequest", now=now)
    scope = tenant_scope(caller)
    tenant_id, user_id = scope.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    async with database.transaction(scope) as session:

        async def create() -> UploadRequestView:
            policy = await tenants.get_policy(session)
            expires_at = expiry(request.expires_at, policy.max_expiry, now)
            locale = request.locale or policy.default_locale
            # FR-24's domain rules (#217) first, as for a transfer's recipients, on the policy as
            # it is now: 422 recipient_domain_not_allowed, before the suppression check.
            domain_rules.check(
                domain_rules.DomainRules.of(policy),
                [request.email],
                lambda _: json_pointer("uploader_email"),
            )
            if await undeliverable(session, emails, [request.email]) is not None:
                raise _undeliverable()
            # Group G, as for sendTransfer: one link email, charged only for a request that passes
            # every check above; a 429 rolls the transaction back with nothing created.
            await limiter.check_all(email_charges(caller, emails, [request.email.lower()], now))
            row = await upload_requests.insert_request(
                session,
                request_id=uuid7(),
                created_by=user_id,
                email=request.email,
                locale=locale,
                message_ct=(
                    None if request.message is None else fields.seal(tenant_id, request.message)
                ),
                expires_at=expires_at,
            )
            await audit.record(
                session,
                action=CREATED,
                actor=caller.actor(),
                target=Target(TARGET, row.id),
                origin=origin,
                details=audit_details(
                    caller,
                    expires_in_seconds=int((expires_at - now).total_seconds()),
                    has_message=request.message is not None,
                ),
            )
            await enqueue(session, UPLOAD_REQUEST_LINK_DUE, {"upload_request_id": row.id})
            return request_view(tenant_id, row, now, verified=False)

        async def rebuild(request_id: UUID) -> UploadRequestView | None:
            try:
                return await _view(session, tenant_id, request_id, now)
            except NotFoundError:
                return None

        return await once(
            session,
            caller,
            idempotency,
            status=201,
            resource_type=TARGET,
            create=create,
            rebuild=rebuild,
            resource_id=lambda view: view.id,
        )


# ---- listUploadRequests, getUploadRequest ----


async def list_upload_requests(
    database: Database,
    caller: Caller,
    *,
    tenant_wide: bool = False,
    states: Collection[UploadRequestState] = (),
    cursor: str | None = None,
    limit: int = 25,
    now: datetime,
) -> UploadRequestPage:
    """`listUploadRequests`, newest first. `scope=tenant` (`tenant_wide`) needs Tenant reach: an
    admin acting as one, or an API key; a member gets 403 and a local admin without a passkey
    `403 passkey_required`. `scope=own` is the caller's own, for a key its owner's."""
    reach = authorize(caller, "listUploadRequests", now=now)
    if tenant_wide and reach is not Reach.TENANT:
        if caller.is_admin and caller.kind is CallerKind.MEMBER:
            raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
        raise Forbidden("permission_denied", "scope=tenant needs the admin role or an API key.")
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 upload requests")
    before = None if cursor is None else decode_cursor(cursor)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        found = await upload_requests.list_requests(
            session,
            created_by=None if tenant_wide else caller.user_id,
            states=set(states),
            before=before,
            limit=limit + 1,
            now=now,
        )
        ids = [r.id for r in found]
        verified = await upload_requests.live_session_ids(session, ids)
        counted = await files.received_counts(session, ids)
        items = [
            request_view(
                tenant_id, r, now, verified=r.id in verified, received=counted.get(r.id, (0, 0))
            )
            for r in found
        ]
    more = len(items) > limit
    page = tuple(items[:limit])
    return UploadRequestPage(page, encode_cursor(page[-1].id) if more else None)


async def get_upload_request(
    database: Database, caller: Caller, request_id: UUID, *, now: datetime
) -> UploadRequestView:
    """`getUploadRequest`: the request, with whether the uploader verified or is locked."""
    reach = authorize(caller, "getUploadRequest", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        row = await _get(session, request_id)
        require_visible(caller, reach, row)
        return await _view(session, tenant_id, row.id, now)


# ---- revokeUploadRequest ----


async def revoke_upload_request(
    database: Database,
    archive: AuditArchive,
    caller: Caller,
    request_id: UUID,
    *,
    origin: Origin,
    now: datetime,
) -> UploadRequestView:
    """`revokeUploadRequest` (module docstring), as `revokeTransfer` (`sft.service.revocation`)."""
    reach = authorize(caller, "revokeUploadRequest", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    event: ArchivedEvent | None
    async with database.transaction(scope) as session:
        row = await _get(session, request_id, lock=True)
        require_reach(caller, reach, row, now)
        target = Target(TARGET, row.id)
        stored = UploadRequestState(row.state)
        if stored is UploadRequestState.REVOKED:
            # A retry: the revocation stands; its record is written if it is still missing.
            event = await audit.latest_critical_event(session, action=REVOKED, target=target)
        else:
            state = effective_state(stored, row.expires_at, now)
            if state is UploadRequestState.EXPIRED:
                raise Conflict("upload_request_expired", current_state=state.value)
            await upload_requests.change_state(
                session,
                row.id,
                from_states=(UploadRequestState.OPEN,),
                to=UploadRequestState.REVOKED,
                ended_at=func.now(),
                revoked_by=caller.user_id,
            )
            sessions = await link_sessions.revoke_for_upload_request(session, row.id)
            # Uploads still open are rejected under this lock, as revokeTransfer does: none of
            # their parts is ever assembled (NFR-6). Received files stay, with their retention.
            rejected = await reject_request_uploads(
                session,
                row.id,
                actor=caller.actor(),
                details=audit_details(caller),
                now=now,
                origin=origin,
            )
            event_id = await audit.record(
                session,
                action=REVOKED,
                actor=caller.actor(),
                target=target,
                origin=origin,
                security_critical=True,
                details=audit_details(
                    caller, link_sessions_ended=sessions, uploads_rejected=rejected
                ),
            )
            event = await audit.archived_event(session, event_id)
        view = await _view(session, tenant_id, row.id, now)
    if event is not None:
        await archive.confirm([event])
    return view


# ---- unlockUploader ----


async def unlock_uploader(
    database: Database,
    archive: AuditArchive,
    caller: Caller,
    request_id: UUID,
    *,
    origin: Origin,
    now: datetime,
) -> UploadRequestView:
    """`unlockUploader` (module docstring), as `unlockRecipient` (`sft.service.recipients`)."""
    reach = authorize(caller, "unlockUploader", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        row = await _get(session, request_id, lock=True)
        if reach is not Reach.TENANT and row.created_by != caller.user_id:
            if caller.is_admin:
                raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
            if sees_tenant(caller, now):
                raise Forbidden("permission_denied", "Only the owner or an admin may unlock.")
            raise NotFound
        # 404, then 403, then 409 (authn and authz 6.4).
        state = effective_state(UploadRequestState(row.state), row.expires_at, now)
        if state is UploadRequestState.REVOKED:
            raise Conflict("upload_request_revoked", current_state=state.value)
        if state is UploadRequestState.EXPIRED:
            raise Conflict("upload_request_expired", current_state=state.value)
        target = Target(TARGET, row.id)
        if row.locked_at is not None and caller.user_id is not None:
            await upload_requests.unlock(session, row.id, by=caller.user_id)
            await audit.record(
                session,
                action=UNLOCKED,
                actor=caller.actor(),
                target=target,
                origin=origin,
                security_critical=True,
                details=audit_details(caller, failed_attempts=row.failed_attempts),
            )
            await enqueue(session, UPLOAD_REQUEST_LINK_DUE, {"upload_request_id": row.id})
        # The unlock's record, just written or written by an earlier call (#177).
        event = await audit.latest_critical_event(session, action=UNLOCKED, target=target)
        view = await _view(session, tenant_id, row.id, now)
    await archive.confirm([event] if event else [])
    return view
