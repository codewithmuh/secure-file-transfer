"""The transactional outbox: work for the workers, committed with the change that causes it.

A service function writes the message in its own transaction (architecture 5.3, ADR-0013):

    async with database.transaction(Scope.tenant(tenant_id)) as session:
        ...  # the state change, and its audit event
        await enqueue(session, SCAN_SMALL_FILE, {"file_id": file.id})

Both commit or neither does. The outbox relay (`sft.workers.relay`) later claims the row, sends it
to its topic's queue and marks it published. Delivery is at least once, so every consumer is
idempotent (`sft.data.processed`).

A message is the contract of ADR-0013: its topic, its outbox ID, its tenant, the IDs of the rows to
act on and the trace context, nothing more. The payload accepts only UUIDs, so a link token, a
code, an email address or a file name can't reach a queue (threat model T-49): a worker re-reads
everything else from PostgreSQL in the message's tenant scope.

The trace context is the W3C `traceparent` of the message's own `create` span, a child of the
request's or message's span that wrote it (ADR-0009, architecture 5.3). The relay sends it on in
the body unchanged, and the consumer's span is that span's child, so one trace runs from the API
request through the queue to the worker.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from opentelemetry.trace import SpanKind
from sqlalchemy import ARRAY, Float, Integer, Text, Update, Uuid, func, insert, select, update
from sqlalchemy import cast as sql_cast
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.core.telemetry import current_trace_context, messaging_attributes, traced
from sft.data.access import in_scope, tenant_of
from sft.data.models import Outbox

MAX_DELAY: Final = timedelta(minutes=15)
"""SQS's longest per-message delay (ADR-0013). Work that must wait longer re-sends itself."""

MAX_IDS: Final = 100
"""IDs in one payload value. Messages stay small (capacity 3.1: under 1 KB each)."""

_KEY = re.compile(r"[a-z][a-z0-9_]{0,62}")
_TOPIC = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")

PayloadValue = UUID | Sequence[UUID]
Payload = Mapping[str, PayloadValue]


class Queue(StrEnum):
    """The work queues of ADR-0013. Each environment's queue is `{prefix}{value}`, e.g.
    `sft-dev-notify`; its dead-letter queue is `{prefix}{value}-dlq`."""

    SCAN_SMALL = "scan-small"
    SCAN_LARGE = "scan-large"
    NOTIFY = "notify"
    SES_EVENTS = "ses-events"
    """Not the outbox's: SES's events, through SNS (`sft.service.ses_events`, #185). No topic."""
    GUARDDUTY_RESULTS = "guardduty-results"
    """Not the outbox's: GuardDuty's scan results for files over 2 GB, through EventBridge
    (`sft.service.guardduty`, #234). The large pool's scan workers read it. No topic."""
    SIGNIN_EVENTS = "signin-events"
    """Not the outbox's: the Cognito sign-in triggers send to it directly, in the outbox's
    envelope (`sft.service.signin_triggers`, #238). The notification worker reads it. No topic."""

    @property
    def fair(self) -> bool:
        """A fair queue: the relay sends the tenant as the message group (ADR-0013)."""
        return self in (Queue.SCAN_SMALL, Queue.SCAN_LARGE)


@dataclass(frozen=True, slots=True)
class Topic:
    """A kind of message, and the queue that carries it. Name it `<subject>.<event>`."""

    name: str
    queue: Queue

    def __post_init__(self) -> None:
        if not _TOPIC.fullmatch(self.name):
            raise ValueError(f"a topic is named like 'file.scan', not {self.name!r}")


def topic_registry(*topics: Topic) -> Mapping[str, Topic]:
    """The topics by name, for the relay to route rows by; a name may appear once."""
    registry: dict[str, Topic] = {}
    for topic in topics:
        if topic.name in registry:
            raise ValueError(f"topic {topic.name!r} is defined twice")
        registry[topic.name] = topic
    return registry


MEMBER_INVITED: Final = Topic("member.invited", Queue.NOTIFY)
"""A user was invited (FR-22): the notification worker creates their user in the user pool with a
temporary password, records the identity and emails the invitation (authn and authz 2.5).
Payload `{"user_id": …}`. Locally the pool is Keycloak (#197); where the worker has no pool yet
(dev until Cognito, #193) it records the message and sends nothing, and the user stays `invited`,
which is how #193 finds whom to invite."""

MEMBER_SIGN_IN_RESET: Final = Topic("member.sign_in_reset", Queue.NOTIFY)
"""An admin reset a member's sign-in (`resetUserSignIn`, #197): the API has ended their sessions
and deleted their local identities; the notification worker deletes their user in the pool,
creates it again with a new temporary password, records the new identity and emails a new
invitation (authn and authz 2.5, steps 2 and 3). Payload `{"user_id": …}`."""

TENANT_ADMIN_RECOVERED: Final = Topic("tenant.admin_recovered", Queue.NOTIFY)
"""An operator recovered a tenant admin's sign-in (`recoverTenantAdmin`, #239, #273): the
notification worker emails every active admin of the tenant which admin it was, when, and whether
it is a reset or a temporary local sign-in (authn and authz 2.5). Written with the recovery's
`member.sign_in_reset`. Payload `{"user_id": …, "admin_recovery_id": …}`."""

MEMBER_TEMPORARY_SIGN_IN_ENDED: Final = Topic("member.temporary_sign_in_ended", Queue.NOTIFY)
"""The daily `cleanup` job ended an operator's temporary local sign-in (#239, #273): the
notification worker deletes the admin's user in the pool, if it is still the one made for that
recovery's reset (authn and authz 2.5). Payload `{"user_id": …, "admin_recovery_id": …}`."""

FILE_SCAN: Final = Topic("file.scan", Queue.SCAN_SMALL)
"""A file of up to 100 MB reached `scanning`: a scan worker of the small pool streams it to clamd
and its DLP inspector (architecture 4.1, ADR-0019, #175). Payload `{"file_id": …}`. A scan over
its tenant's cap is sent again under the same topic, delayed 30 seconds."""

FILE_SCAN_LARGE: Final = Topic("file.scan_large", Queue.SCAN_LARGE)
"""A file over 100 MB, up to 2,000,000,000 bytes, reached `scanning`: the same scan, in the large
pool, so large files don't delay small ones (ADR-0019, #175). Payload `{"file_id": …}`.

Files over 2,000,000,000 bytes (`storage_class = large`) get no scan message: ClamAV can't scan
them, and GuardDuty's result on the `guardduty-results` intake queue drives them (#234,
`sft.service.guardduty`); with no result by the scan deadline, the sweep fails them."""

TRANSFER_SENT: Final = Topic("transfer.sent", Queue.NOTIFY)
"""The evaluation moved a transfer to `sent`: the notification worker (#178) writes one
`recipient.link_due` message per recipient, in the transaction that records this one, so each
email is retried on its own (architecture 4.1). Payload `{"transfer_id": …}`."""

TRANSFER_HELD: Final = Topic("transfer.held", Queue.NOTIFY)
"""The evaluation held a transfer: the notification worker (#178) sends the member the
`transfer_held` email. Payload `{"transfer_id": …}`."""

TRANSFER_RETURNED_TO_DRAFT: Final = Topic("transfer.returned_to_draft", Queue.NOTIFY)
"""No counted file was left, so the evaluation moved a transfer back to `draft`: the notification
worker (#178) tells the member (data model 3.2). Payload `{"transfer_id": …}`."""

RECIPIENT_LINK_DUE: Final = Topic("recipient.link_due", Queue.NOTIFY)
"""One recipient's link email is due (#178, data model 2.2): the notification worker derives the
link, emails it and records the delivery. Written by the worker itself for each recipient of a
`transfer.sent` message, so one message is one email, retried on its own; by an unlock (#179),
which issues a new link; and by the worker again, delayed, when the address is over the
cross-tenant cap (abuse 7.2). Payload `{"recipient_id": …}`."""

RECIPIENT_CODE_REQUESTED: Final = Topic("recipient.code_requested", Queue.NOTIFY)
"""A recipient asked for a verification code (`requestVerificationCode`, #179): the notification
worker creates the code, supersedes the older ones and emails it to the stored address only
(data model 2.4). Payload `{"recipient_id": …}`; the code itself never travels."""

RECIPIENT_LOCKED: Final = Topic("recipient.locked", Queue.NOTIFY)
"""A recipient was locked after 20 failed attempts (#179, NFR-14): the notification worker emails
`recipient_locked` to the transfer's owner and every active tenant admin. Payload
`{"recipient_id": …}`."""

TRANSFER_FIRST_DOWNLOAD: Final = Topic("transfer.first_download", Queue.NOTIFY)
"""A transfer whose member asked to be told (FR-8) had its first counted download, by any
recipient of any file (#214): the notification worker emails `first_download` to the member, with
no file name. Written once per transfer, by the download's transaction, under a conditional update
of `transfers.first_download_notified_at` (data model 2.2). Payload `{"transfer_id": …}`."""

UPLOAD_REQUEST_LINK_DUE: Final = Topic("upload_request.link_due", Queue.NOTIFY)
"""An uploader's link email is due (#212, data model 2.2): the notification worker derives the
link, emails `upload_request` in the request's locale and records the delivery. Written by the
request's creation, by an unlock, which issues a new link, and by the worker again, delayed, when
the address is over the cross-tenant cap (abuse 7.2), as `recipient.link_due` is. Payload
`{"upload_request_id": …}`."""

UPLOAD_REQUEST_CODE_REQUESTED: Final = Topic("upload_request.code_requested", Queue.NOTIFY)
"""An uploader asked for a verification code (`requestVerificationCode`, #212): the notification
worker creates the code, supersedes the request's older ones and emails it to the stored address
only (data model 2.4). Payload `{"upload_request_id": …}`; the code itself never travels."""

UPLOAD_REQUEST_UPLOADER_LOCKED: Final = Topic("upload_request.uploader_locked", Queue.NOTIFY)
"""An uploader was locked after 20 failed attempts (#212, NFR-14): the notification worker emails
`recipient_locked`, in its upload-request variant, to the request's owner and every active tenant
admin. Payload `{"upload_request_id": …}`."""

UPLOAD_REQUEST_FILES_SETTLED: Final = Topic("upload_request.files_settled", Queue.NOTIFY)
"""Received files of an upload request settled (#213, architecture 4.3): the notification worker
emails the member `files_arrived` for the shareable ones and `files_blocked_member` for the blocked
ones, and the uploader `files_blocked_uploader`, with no finding or scan detail, counts only.
Written delayed 5 minutes by the scan result that made the request's notice due
(`sft.data.upload_requests.note_settled`), so one notice covers every file of its window; the
request is the dedup key. Payload `{"upload_request_id": …}`."""

API_KEY_EXPIRING: Final = Topic("api_key.expiring", Queue.NOTIFY)
"""An API key expires in 14 or 3 days (#215, authn and authz 5.2): the notification worker emails
`api_key_expiring` to its owner and every active tenant admin, unless it was revoked meanwhile.
Queued by the daily cleanup job. Payload `{"api_key_id": …}`."""

API_KEY_FIRST_EXPORT: Final = Topic("api_key.first_export", Queue.NOTIFY)
"""An API key exported the audit log for the first time (#216, authn and authz 5.3): the
notification worker emails `api_key_first_export` to every active tenant admin. Payload
`{"api_key_id": …}`."""

DLP_POLICY_CHANGES: Final = (
    "rule_added",
    "rule_changed",
    "rule_removed",
    "detector_added",
    "detector_changed",
    "detector_removed",
    "trusted_domains_changed",
    "mode_changed",
    "approvers_changed",
    "approval_timeout_changed",
)
"""The kinds of DLP policy change the admins' notice names (FR-54): the email catalog's
`PolicyChange`, which a test holds this to."""

DLP_POLICY_CHANGED: Final[Mapping[str, Topic]] = {
    change: Topic(f"dlp_policy.changed.{change}", Queue.NOTIFY) for change in DLP_POLICY_CHANGES
}
"""A tenant admin changed the DLP policy, a rule or a detector (#218), or an approver
designation (#220): the notification worker emails `dlp_policy_changed`, naming the kind, to every
active admin of the tenant (FR-54). A payload carries IDs only, so the kind is the topic's last
part: one topic per kind. Payload `{}`. Since #230 the worker coalesces them: the kind waits in the
tenant's notice window, and `dlp_policy.notice_due` sends one email for the window."""

TRANSFER_AWAITING_CONFIRMATION: Final = Topic("transfer.awaiting_confirmation", Queue.NOTIFY)
"""A DLP rule warns or needs approval, so the evaluation moved a transfer to
`awaiting_confirmation` (#219, architecture 4.6): the notification worker sends the member the
`dlp_confirmation_needed` email, which names no file or finding. Payload `{"transfer_id": …}`."""

DLP_APPROVAL_REQUESTED: Final = Topic("dlp_approval.requested", Queue.NOTIFY)
"""A sender requested approval of a transfer (#220, FR-43): the notification worker emails
`dlp_approval_requested` to each eligible approver while the request is pending, with no file name
and no approve link. Payload `{"approval_request_id": …}`."""

DLP_APPROVAL_DECIDED: Final = Topic("dlp_approval.decided", Queue.NOTIFY)
"""An approval request was approved or rejected (#220): `dlp_approval_decided` to the transfer's
sender, saying which; a rejection's comment stays in the web app. Payload
`{"approval_request_id": …}`."""

DLP_APPROVAL_EXPIRED: Final = Topic("dlp_approval.expired", Queue.NOTIFY)
"""The expiry job expired an approval request and returned its transfer to the sender (#220):
`dlp_approval_expired` to the sender. Payload `{"approval_request_id": …}`."""

DLP_NO_ELIGIBLE_APPROVER: Final = Topic("dlp_approval.no_eligible_approver", Queue.NOTIFY)
"""A sender's approval request was refused because the tenant has no eligible approver (#220,
architecture 4.6): `dlp_no_eligible_approver` to every active admin. Payload
`{"transfer_id": …}`."""

DLP_POLICY_NOTICE_DUE: Final = Topic("dlp_policy.notice_due", Queue.NOTIFY)
"""The tenant's coalesced DLP policy notice is due (#230, abuse 7.1): the notification worker
emails `dlp_policy_changed`, listing every kind of change since the last one, to every active
admin. Written delayed 10 minutes by the `dlp_policy.changed.<kind>` message that found no notice
due (`sft.service.notice_windows`), so one email covers every change of its window. Payload `{}`."""

DLP_APPROVAL_DIGEST_DUE: Final = Topic("dlp_approval.digest_due", Queue.NOTIFY)
"""An approver's digest of approval requests is due (#230, abuse 7.1): past 20 request emails in an
hour, the rest of the hour's requests go into one `dlp_approval_requested` email that counts every
request the approver could still decide. Written by the `dlp_approval.requested` message that
first held one back, delayed until the hour ends; a delay longer than SQS's 15 minutes is the
message sent again, delayed. Payload `{"user_id": …}`."""

DLP_APPROVER_DEACTIVATED: Final = Topic("dlp_approval.approver_deactivated", Queue.NOTIFY)
"""A deactivation cleared a member's DLP approver designation (#230): with fewer than two active
approvers left, the notification worker emails `dlp_approver_deactivated` to every active admin at
once; otherwise the change joins the coalesced policy notice as `approvers_changed`. Written by
`deactivateUser` in its transaction. Payload `{"user_id": …}`."""

TOPICS: Final[Mapping[str, Topic]] = topic_registry(
    MEMBER_INVITED,
    MEMBER_SIGN_IN_RESET,
    TENANT_ADMIN_RECOVERED,
    MEMBER_TEMPORARY_SIGN_IN_ENDED,
    FILE_SCAN,
    FILE_SCAN_LARGE,
    TRANSFER_SENT,
    TRANSFER_HELD,
    TRANSFER_RETURNED_TO_DRAFT,
    RECIPIENT_LINK_DUE,
    RECIPIENT_CODE_REQUESTED,
    RECIPIENT_LOCKED,
    TRANSFER_FIRST_DOWNLOAD,
    UPLOAD_REQUEST_LINK_DUE,
    UPLOAD_REQUEST_CODE_REQUESTED,
    UPLOAD_REQUEST_UPLOADER_LOCKED,
    UPLOAD_REQUEST_FILES_SETTLED,
    API_KEY_EXPIRING,
    API_KEY_FIRST_EXPORT,
    *DLP_POLICY_CHANGED.values(),
    TRANSFER_AWAITING_CONFIRMATION,
    DLP_APPROVAL_REQUESTED,
    DLP_APPROVAL_DECIDED,
    DLP_APPROVAL_EXPIRED,
    DLP_NO_ELIGIBLE_APPROVER,
    DLP_POLICY_NOTICE_DUE,
    DLP_APPROVAL_DIGEST_DUE,
    DLP_APPROVER_DEACTIVATED,
)
"""Every topic the service sends. Each feature adds its topics here, with the queue that carries
them: scans (M2) on `Queue.SCAN_SMALL` and `Queue.SCAN_LARGE`, emails (M1, M2) on `Queue.NOTIFY`.
The relay leaves a row whose topic isn't here unpublished and counts it as a failure, which the
outbox age alert then shows, rather than drop it (an older relay during a rolling deploy)."""


class InvalidMessageError(ValueError):
    """A payload or a received message body that breaks the message contract."""


def _payload_json(payload: Payload) -> dict[str, str | list[str]]:
    if not isinstance(payload, Mapping):
        raise InvalidMessageError("the payload maps names to IDs")
    out: dict[str, str | list[str]] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise InvalidMessageError(f"payload names are lower-case identifiers, not {key!r}")
        if isinstance(value, UUID):
            out[key] = str(value)
        elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
            if len(value) > MAX_IDS:
                raise InvalidMessageError(f"{key}: at most {MAX_IDS} IDs")
            if not all(isinstance(item, UUID) for item in value):
                raise InvalidMessageError(f"{key}: the payload carries only IDs (UUIDs)")
            out[key] = [str(item) for item in value]
        else:
            raise InvalidMessageError(f"{key}: the payload carries only IDs (UUIDs)")
    return out


def _payload_from_json(raw: object) -> dict[str, PayloadValue]:
    if not isinstance(raw, dict):
        raise InvalidMessageError("the payload is an object")
    out: dict[str, PayloadValue] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise InvalidMessageError("payload names are lower-case identifiers")
        try:
            if isinstance(value, str):
                out[key] = UUID(value)
            elif (
                isinstance(value, list)
                and len(value) <= MAX_IDS
                and all(isinstance(item, str) for item in value)
            ):
                out[key] = tuple(UUID(item) for item in value)
            else:
                raise InvalidMessageError(f"{key}: the payload carries only IDs")
        except (ValueError, AttributeError) as exc:
            raise InvalidMessageError(f"{key}: not an ID") from exc
    return out


def _trace_from_json(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise InvalidMessageError("the trace context maps names to strings")
    return raw


def _delay_seconds(delay: timedelta) -> int:
    if delay < timedelta(0) or delay > MAX_DELAY:
        raise ValueError("a delay is between 0 and 15 minutes (SQS's limit, ADR-0013)")
    return math.ceil(delay.total_seconds())


async def enqueue(
    session: AsyncSession,
    topic: Topic,
    payload: Payload,
    *,
    delay: timedelta = timedelta(0),
) -> UUID:
    """Write a message in the session's transaction, for the message's tenant; return its ID.

    The tenant is the transaction's own (`tenant_of`, a tenant scope), so a message can't name
    another tenant. `delay` holds the message back: no consumer receives it before the transaction
    started plus `delay`, at most 15 minutes. The ID is what a consumer records in
    `processed_messages`, so a re-sent copy is recognised.

    The message gets a `create` span under the current one, and carries that span's trace context
    (module docstring); outside any span its trace starts here.
    """
    tenant_id = tenant_of(session)  # the scope's tenant; refuses system and platform scopes
    message_id = uuid7()
    attributes = {
        **messaging_attributes("create", topic.queue.value),
        "messaging.message.id": str(message_id),
    }
    with traced(f"create {topic.queue.value}", kind=SpanKind.PRODUCER, attributes=attributes):
        await session.execute(
            insert(Outbox).values(
                id=message_id,
                tenant_id=tenant_id,
                topic=topic.name,
                payload=_payload_json(payload),
                trace_context=current_trace_context(),  # this span's: IDs only
                delay_seconds=_delay_seconds(delay),
            )
        )
    return message_id


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    """A message as it travels through SQS: the body the relay sends and a consumer receives."""

    id: UUID
    topic: str
    tenant_id: UUID
    payload: Mapping[str, PayloadValue]
    trace_context: Mapping[str, str] = field(default_factory=dict)

    def body(self) -> str:
        return json.dumps(
            {
                "id": str(self.id),
                "topic": self.topic,
                "tenant_id": str(self.tenant_id),
                "payload": _payload_json(self.payload),
                "trace_context": dict(self.trace_context),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_body(cls, body: str) -> OutboxMessage:
        """Parse a received body, or raise `InvalidMessageError`; nothing else is trusted."""
        try:
            raw = json.loads(body)
        except (ValueError, RecursionError) as exc:  # deep nesting raises RecursionError
            raise InvalidMessageError("the body is not JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "topic",
            "tenant_id",
            "payload",
            "trace_context",
        }:
            raise InvalidMessageError("the body has exactly the fields of ADR-0013")
        topic, trace = raw["topic"], raw["trace_context"]
        if not isinstance(topic, str) or not _TOPIC.fullmatch(topic):
            raise InvalidMessageError("not a topic")
        try:
            message_id, tenant_id = UUID(raw["id"]), UUID(raw["tenant_id"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise InvalidMessageError("the message and tenant IDs are UUIDs") from exc
        return cls(
            id=message_id,
            topic=topic,
            tenant_id=tenant_id,
            payload=_payload_from_json(raw["payload"]),
            trace_context=_trace_from_json(trace),
        )


# ---- the relay's side, in system scope (authentication and authorization 7.3) ----


@dataclass(frozen=True, slots=True)
class DueRow:
    """An unpublished row the relay has claimed, locked until its transaction ends."""

    message: OutboxMessage
    attempts: int
    remaining_delay: int
    """Seconds of its delay still to run, for SQS's DelaySeconds: the delay counts from when the
    row was written, not from when the relay got to it."""
    error: str | None = None
    """Why the row can't be sent, such as a payload that breaks the contract (written by hand, not
    by `enqueue`). The relay counts it as a failed send, so it can't hold up the rows behind it."""


async def claim_due(session: AsyncSession, limit: int) -> list[DueRow]:
    """Lock up to `limit` unpublished rows that are due, oldest first, skipping locked ones.

    `FOR UPDATE SKIP LOCKED` lets several relays run side by side: each claims rows no other
    transaction holds, and a relay that dies releases its rows when its connection ends.
    """
    elapsed = func.extract("epoch", func.now() - Outbox.created_at)
    remaining = func.greatest(
        0, sql_cast(func.ceil(Outbox.delay_seconds - elapsed), Integer)
    ).label("remaining")
    rows = await session.execute(
        select(
            Outbox.id,
            Outbox.topic,
            Outbox.tenant_id,
            Outbox.payload,
            Outbox.trace_context,
            Outbox.attempts,
            remaining,
        )
        .where(
            Outbox.published_at.is_(None),
            Outbox.next_attempt_at <= func.now(),
            # In system scope the session lets only the relay write tenant rows (check_write).
            in_scope(Outbox, session),
        )
        .order_by(Outbox.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    due = []
    for row in rows:
        error = None
        payload: dict[str, PayloadValue] = {}
        trace: dict[str, str] = {}
        try:
            payload = _payload_from_json(row.payload)
        except InvalidMessageError:
            error = "invalid_payload"
        try:
            trace = _trace_from_json(row.trace_context)
        except InvalidMessageError:
            error = error or "invalid_trace_context"
        message = OutboxMessage(
            id=row.id,
            topic=row.topic,
            tenant_id=row.tenant_id,
            payload=payload,
            trace_context=trace,
        )
        due.append(DueRow(message, row.attempts, int(row.remaining), error))
    return due


def _scoped_update(session: AsyncSession) -> Update:
    """Every UPDATE of the outbox starts here, inside the scope.

    `in_scope` keeps it to the session's scope, and the session itself refuses a system-scope
    write to tenant rows by any role but the relay (`sft.data.access.check_write`).
    """
    return update(Outbox).where(in_scope(Outbox, session))


async def mark_published(session: AsyncSession, ids: Sequence[UUID]) -> None:
    if ids:
        await session.execute(
            _scoped_update(session).where(Outbox.id.in_(ids)).values(published_at=func.now())
        )


async def mark_failed(session: AsyncSession, failed: Mapping[UUID, tuple[str, float]]) -> None:
    """Record failed sends in one UPDATE: each row's error code, and when to try it again.

    `failed` maps a row to (error, seconds until the relay tries it again).
    """
    if not failed:
        return
    ids = list(failed)
    rows = (
        func.unnest(
            sql_cast(ids, ARRAY(Uuid)),
            sql_cast([failed[i][0][:200] for i in ids], ARRAY(Text)),
            sql_cast([float(failed[i][1]) for i in ids], ARRAY(Float)),
        )
        .table_valued("id", "error", "retry_in")
        .render_derived(name="failed")
    )  # AS failed(id, …)
    await session.execute(
        _scoped_update(session)
        .where(Outbox.id == rows.c.id)
        .values(
            attempts=Outbox.attempts + 1,
            next_attempt_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, rows.c.retry_in),
            last_error=rows.c.error,
        )
    )


async def oldest_unpublished_age(session: AsyncSession) -> float:
    """Seconds since the oldest unpublished row was written; 0 when every row is published.

    The alert of ADR-0013 fires above 2 minutes. Delayed rows count from when they were written
    too: the relay sends them at once and SQS holds them, so they don't age in the outbox.
    """
    age: Any = await session.scalar(
        select(func.extract("epoch", func.now() - func.min(Outbox.created_at))).where(
            Outbox.published_at.is_(None), in_scope(Outbox, session)
        )
    )
    return max(0.0, float(age)) if age is not None else 0.0
