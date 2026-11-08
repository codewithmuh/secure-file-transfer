"""Audit search and export: `searchAuditEvents` and `exportAuditEvents` (#216; FR-28, FR-29,
FR-27, UC-4; authn and authz 5.3, 6.3; abuse and rate limits 2.2, I; T-47, T-48).

**Who** (table 6.3): a tenant admin acting as one (a local admin needs a passkey), and an API key
with `audit:read`. Members, link sessions and operators never read the log. Every read is in the
caller's tenant scope (`sft.data.audit_reads`), so another tenant's events are never found, by
filter, guessed ID or address.

**The filter** (`AuditQuery`, the contract's `AuditFilter`) travels in the request body, so an
address or IP never reaches a URL or an access log. An email address is resolved at query time to
the tenant's users and recipients with it, then matched as the actor or target by ID. `actor_email`
is filled at read time for people still known.

**The search**: newest first, 1 to 100 a page, with an opaque cursor that encodes the last event's
`(occurred_at, id)` and is checked (`400 invalid_cursor`). Group I's 60 searches a minute per
tenant are the route's.

**The export**: every matching event, newest first, as CSV or JSON, streamed in pages of
`PAGE` events, each read in a short transaction of its own, up to the time the export began.

- **How much**: an admin's export at most 1,000,000 events, a key's at most 100,000
  (`422 export_too_large`, counted before anything is charged).
- **How often**: a key at most once an hour (`429`), the tenant at most 10 an hour (`429`), and
  one at a time per tenant (`429`), a lease in the counter store renewed while the stream runs and
  released at its end (`ExportLeases`). A store outage counts in the pod instead (group I fails
  open, abuse 4.5).
- **Step-up**: an admin's export needs a sign-in in the last 15 minutes (the registry's).
- **A key's first export** emails the tenant's admins once (`api_key.first_export`), so a leaked
  key's first pull is seen at once (authn and authz 5.3).
- **CSV** (T-48): RFC 4180, every cell quoted, and a cell that starts with `=`, `+`, `-`, `@`, a
  tab or a carriage return is prefixed with `'`, so a spreadsheet never runs it. JSON is unchanged.

**Audited** (FR-27, T-47): every search writes `audit.searched` and every export `audit.exported`,
with which filters were set (never their values: no address or IP in the record), the format and
the row count.

**The 1,000,000-event export** (an open point of #216): one pod streams it page by page, so memory
holds one page; bytes flow at every page, so the load balancer's 60-second idle timeout doesn't
end it. A seeded million-row run hasn't been made yet: if it proves too slow, the admin cap drops
before an asynchronous export (API README 10) is built.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import csv
import io
import json
import logging
import struct
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Final
from uuid import UUID

from sft.core.errors import (
    FieldError,
    InvalidRequest,
    RateLimited,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.data import api_keys, audit, audit_reads
from sft.data.audit import Origin
from sft.data.audit_reads import EventFilter, EventRow
from sft.data.counters import CounterStore, CounterStoreUnavailableError
from sft.data.database import Database
from sft.data.models import ActorType
from sft.data.outbox import API_KEY_FIRST_EXPORT, enqueue
from sft.data.scope import Scope
from sft.service.caller import Caller, CallerKind
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import KEY_EXPORT, TENANT_EXPORT

log = logging.getLogger(__name__)

MAX_PAGE: Final = 100
PAGE: Final = 1000
"""Events an export reads per transaction."""
ADMIN_CAP: Final = 1_000_000
KEY_CAP: Final = 100_000
LEASE_TTL: Final = timedelta(minutes=2)
"""An export's lease lives this long unless a page renews it: a pod that dies frees it soon."""
LEASE_RETRY_AFTER: Final = 30
_FORMULA: Final = ("=", "+", "-", "@", "\t", "\r")
COLUMNS: Final = (
    "id",
    "occurred_at",
    "actor_type",
    "actor_id",
    "actor_email",
    "action",
    "target_type",
    "target_id",
    "source_ip",
    "user_agent",
    "request_id",
    "security_critical",
    "details",
)
"""The CSV's columns: the contract's `AuditEvent`, `details` as one JSON cell."""


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """The contract's `AuditFilter`, as the request sent it. Every field is optional."""

    occurred_after: datetime | None = None
    occurred_before: datetime | None = None
    actor_type: ActorType | None = None
    actor_id: UUID | None = None
    email: str | None = None
    actions: tuple[str, ...] = ()
    target_type: str | None = None
    target_id: UUID | None = None
    source_ip: str | None = None


@dataclass(frozen=True, slots=True)
class EventView:
    """One event as the contract's `AuditEvent` shows it."""

    row: EventRow
    actor_email: str | None


@dataclass(frozen=True, slots=True)
class EventPage:
    items: Sequence[EventView]
    next_cursor: str | None


@dataclass
class Export:
    """A running export: what to send and how much."""

    format: ExportFormat
    rows: int
    filename: str
    chunks: AsyncIterator[bytes] = field(repr=False)

    @property
    def media_type(self) -> str:
        return "text/csv" if self.format is ExportFormat.CSV else "application/json"


def _invalid(pointer: str, detail: str) -> Unprocessable:
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, pointer=pointer)])


def _ip(value: str | None) -> IPv4Address | IPv6Address | None:
    if value is None:
        return None
    try:
        return ip_address(value.strip())
    except ValueError:
        raise _invalid(
            json_pointer("filter", "source_ip"), "source_ip is an IPv4 or IPv6 address."
        ) from None


def _aware(value: datetime | None, name: str) -> datetime | None:
    if value is not None and value.utcoffset() is None:
        raise _invalid(json_pointer("filter", name), f"{name} needs its UTC offset (RFC 3339).")
    return value


def _checked(query: AuditQuery) -> AuditQuery:
    after = _aware(query.occurred_after, "occurred_after")
    before = _aware(query.occurred_before, "occurred_before")
    if after is not None and before is not None and after >= before:
        raise _invalid(
            json_pointer("filter", "occurred_before"), "occurred_before is after occurred_after."
        )
    if len(query.actions) > audit_reads.MAX_ACTIONS:
        raise _invalid(json_pointer("filter", "actions"), "At most 20 actions.")
    return query


async def _event_filter(session: Any, query: AuditQuery) -> EventFilter:
    people = None
    if query.email is not None:
        people = await audit_reads.people_with_email(session, query.email.strip().lower())
    return EventFilter(
        occurred_after=query.occurred_after,
        occurred_before=query.occurred_before,
        actor_type=query.actor_type,
        actor_id=query.actor_id,
        people=people,
        actions=tuple(dict.fromkeys(query.actions)),
        target_type=query.target_type,
        target_id=query.target_id,
        source_ip=_ip(query.source_ip),
    )


def _filter_details(events: EventFilter) -> dict[str, audit.Detail]:
    """Which filters were set: their names, never their values (T-47)."""
    return {f"filter_{name}": True for name in events.fields()}


# ---- the cursor: the last event's (occurred_at, id), opaque and checked ----

_CURSOR: Final = struct.Struct(">q16s")


def encode_cursor(row: EventRow) -> str:
    micros = int(row.occurred_at.timestamp() * 1_000_000)
    raw = _CURSOR.pack(micros, row.id.bytes)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        micros, id_bytes = _CURSOR.unpack(raw)
        at = datetime.fromtimestamp(0, UTC) + timedelta(microseconds=micros)
        return at, UUID(bytes=id_bytes)
    except (binascii.Error, struct.error, ValueError, OverflowError) as exc:
        raise InvalidRequest("invalid_cursor") from exc


# ---- searchAuditEvents ----


async def search_audit_events(
    database: Database,
    caller: Caller,
    query: AuditQuery,
    *,
    cursor: str | None,
    limit: int,
    origin: Origin,
    now: datetime,
) -> EventPage:
    """`searchAuditEvents` (module docstring)."""
    authorize(caller, "searchAuditEvents", now=now)
    tenant_id = _tenant(caller)
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 events")
    query = _checked(query)
    after = None if cursor is None else decode_cursor(cursor)
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        events = await _event_filter(session, query)
        rows = await audit_reads.read_events(
            session, events, after=after, until=now, limit=limit + 1
        )
        page = rows[:limit]
        emails = await audit_reads.actor_emails(session, page)
        await audit.record(
            session,
            action="audit.searched",
            actor=caller.actor(),
            origin=origin,
            details={
                **_filter_details(events),
                "results": len(page),
                "later_page": cursor is not None,
            },
        )
    items = [EventView(row, emails.get(row.actor_id) if row.actor_id else None) for row in page]
    more = len(rows) > limit
    return EventPage(items, encode_cursor(page[-1]) if more and page else None)


# ---- exportAuditEvents ----


class ExportLeases:
    """One export at a time per tenant (abuse 2.2, I): a lease in the counter store, or, during an
    outage or without a store, in this pod (group I fails open)."""

    PREFIX: Final = "lease:I.tenant_exports:tenant:"

    def __init__(self, store: CounterStore | None, clock: Any = time.time) -> None:
        self._store = store
        self._clock = clock
        self._local: dict[str, tuple[str, float]] = {}

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    async def acquire(self, tenant_id: UUID, export_id: UUID) -> bool:
        key, member = f"{self.PREFIX}{tenant_id}", str(export_id)
        ttl_ms = int(LEASE_TTL.total_seconds() * 1000)
        if self._store is not None:
            try:
                return await self._store.acquire_lease(
                    key, member, now_ms=self._now_ms(), ttl_ms=ttl_ms, cap=1
                )
            except CounterStoreUnavailableError:
                log.warning("counter store unavailable: the export lease counts in this pod")
        held = self._local.get(key)
        if held is not None and held[0] != member and held[1] > self._now_ms():
            return False
        self._local[key] = (member, self._now_ms() + ttl_ms)
        return True

    async def renew(self, tenant_id: UUID, export_id: UUID) -> None:
        await self.acquire(tenant_id, export_id)

    async def release(self, tenant_id: UUID, export_id: UUID) -> None:
        key = f"{self.PREFIX}{tenant_id}"
        held = self._local.get(key)
        if held is not None and held[0] == str(export_id):
            del self._local[key]
        if self._store is not None:
            with contextlib.suppress(CounterStoreUnavailableError):  # it ends by itself
                await self._store.release_lease(key, str(export_id))


async def export_audit_events(
    database: Database,
    caller: Caller,
    query: AuditQuery,
    export_format: ExportFormat,
    *,
    limiter: RateLimiter,
    leases: ExportLeases,
    origin: Origin,
    now: datetime,
) -> Export:
    """`exportAuditEvents` (module docstring): checks, charges and records the export, then
    returns its stream, which holds the tenant's lease until it ends."""
    authorize(caller, "exportAuditEvents", now=now)
    tenant_id = _tenant(caller)
    is_key = caller.kind is CallerKind.API_KEY
    cap = KEY_CAP if is_key else ADMIN_CAP
    query = _checked(query)
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        events = await _event_filter(session, query)
        rows = await audit_reads.count_events(session, events, until=now, cap=cap)
    if rows > cap:
        raise Unprocessable(
            "export_too_large",
            f"An export holds at most {cap:,} events: narrow the time range.",
        )
    keys = caller.rate_limit_keys()
    if is_key:
        await limiter.check(KEY_EXPORT, keys)
    await limiter.check(TENANT_EXPORT, keys)
    export_id = uuid7()
    if not await leases.acquire(tenant_id, export_id):
        raise RateLimited(LEASE_RETRY_AFTER, "Another export of this tenant is running.")
    try:
        async with database.transaction(Scope.tenant(tenant_id)) as session:
            first = (
                is_key
                and caller.credential_id is not None
                and await api_keys.mark_first_export(session, caller.credential_id)
            )
            if first and caller.credential_id is not None:
                await enqueue(session, API_KEY_FIRST_EXPORT, {"api_key_id": caller.credential_id})
            await audit.record(
                session,
                action="audit.exported",
                actor=caller.actor(),
                origin=origin,
                details={**_filter_details(events), "format": export_format, "rows": rows},
            )
    except BaseException:
        await leases.release(tenant_id, export_id)
        raise
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Export(
        format=export_format,
        rows=rows,
        filename=f"audit-events-{stamp}.{export_format.value}",
        chunks=_stream(
            database,
            tenant_id,
            events,
            export_format,
            until=now,
            cap=cap,
            leases=leases,
            export_id=export_id,
        ),
    )


async def _stream(
    database: Database,
    tenant_id: UUID,
    events: EventFilter,
    export_format: ExportFormat,
    *,
    until: datetime,
    cap: int,
    leases: ExportLeases,
    export_id: UUID,
) -> AsyncIterator[bytes]:
    """The export's bytes, page by page; the lease is renewed each page and released at the end,
    however the stream ends."""
    sent = 0
    after: tuple[datetime, UUID] | None = None
    try:
        yield _header(export_format)
        while sent < cap:
            async with database.transaction(Scope.tenant(tenant_id)) as session:
                page = await audit_reads.read_events(
                    session, events, after=after, until=until, limit=min(PAGE, cap - sent)
                )
                emails = await audit_reads.actor_emails(session, page)
            if not page:
                break
            views = [EventView(r, emails.get(r.actor_id) if r.actor_id else None) for r in page]
            yield _encode(views, export_format, first=sent == 0)
            sent += len(page)
            after = (page[-1].occurred_at, page[-1].id)
            await leases.renew(tenant_id, export_id)
            if len(page) < PAGE:
                break
        yield _footer(export_format)
    finally:
        await leases.release(tenant_id, export_id)


# ---- the formats ----


def _cell(value: object) -> str:
    """One CSV cell's text, neutralised so a spreadsheet never runs it as a formula (T-48)."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA) else text


def event_json(view: EventView) -> dict[str, Any]:
    """The contract's `AuditEvent` as JSON."""
    row = view.row
    return {
        "id": str(row.id),
        "occurred_at": row.occurred_at.isoformat(),
        "actor_type": row.actor_type,
        "actor_id": None if row.actor_id is None else str(row.actor_id),
        "actor_email": view.actor_email,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": None if row.target_id is None else str(row.target_id),
        "source_ip": None if row.source_ip is None else str(row.source_ip),
        "user_agent": row.user_agent,
        "request_id": row.request_id,
        "security_critical": row.security_critical,
        "details": row.details,
    }


def _header(export_format: ExportFormat) -> bytes:
    if export_format is ExportFormat.JSON:
        return b"["
    out = io.StringIO()
    csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\r\n").writerow(COLUMNS)
    return out.getvalue().encode()


def _footer(export_format: ExportFormat) -> bytes:
    return b"]" if export_format is ExportFormat.JSON else b""


def _encode(views: Sequence[EventView], export_format: ExportFormat, *, first: bool) -> bytes:
    if export_format is ExportFormat.JSON:
        body = ",".join(json.dumps(event_json(v), separators=(",", ":")) for v in views)
        return (body if first else "," + body).encode()
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    for view in views:
        data = event_json(view)
        data["security_critical"] = "true" if view.row.security_critical else "false"
        data["details"] = json.dumps(view.row.details, separators=(",", ":"), sort_keys=True)
        writer.writerow([_cell(data[column]) for column in COLUMNS])
    return out.getvalue().encode()


def _tenant(caller: Caller) -> UUID:
    if caller.tenant_id is None:  # pragma: no cover - authorize admits tenant callers only
        raise ValueError("a tenant caller has a tenant")
    return caller.tenant_id
