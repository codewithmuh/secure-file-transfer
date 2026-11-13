"""What the notification worker does with each message of the notify queue (#178, #179;
architecture 4.1, 4.2; data model 2.2, 2.4; ADR-0013, ADR-0015).

`Notifier.handle` takes one outbox message and does its work in the message's tenant scope, as
the named system actor `notification_worker` (authn and authz 6.1):

- `transfer.sent`: one `recipient.link_due` message per recipient, in the transaction that
  records this one, so one message is one email, retried on its own (the open point of #178).
- `recipient.link_due`: the suppression list, then the cross-tenant cap, then the link (derived,
  its hash stored once), then `transfer_link` in the recipient's locale, then `sent` and
  `notified_at`.
- `recipient.code_requested`: a new 6-digit code, superseding the older ones, its HMAC stored
  under `code-hmac`, then `verification_code` to the stored address only (#179).
- `recipient.locked`: `recipient_locked` to the transfer's owner and every active tenant admin.
- `transfer.held`: `transfer_held` to the owner, while the transfer is still held: once per hold.
- `transfer.returned_to_draft`: `transfer_returned_to_draft` to the owner, while it is a draft.
- `transfer.first_download`: `first_download` to the owner, once per transfer (#214).
- `upload_request.link_due`: as `recipient.link_due`, for an upload request's uploader (#212): the
  suppression list, the cross-tenant cap, the link (derived from the request's ID, its hash
  stored once, `uploader.link_issued`), then `upload_request` in the request's locale, then `sent`
  and `notified_at`. Written by the request's creation and by an unlock.
- `upload_request.code_requested`: a new code for the uploader, as for a recipient.
- `upload_request.uploader_locked`: `recipient_locked`, in its upload-request variant (no
  template of its own), to the request's owner and every active tenant admin.
- `upload_request.files_settled` (#213, architecture 4.3): the request's batched notice, counts
  only. `files_arrived` to the owner for the files that became shareable, `files_blocked_member`
  to the owner and `files_blocked_uploader` to the uploader, in the request's locale, for the
  blocked ones; the uploader's names no finding, scan detail or file. Each email is recorded on
  its own (two go to the owner), and once they are out, the counts sent are taken off with
  `upload_request.notice_sent`; files that settled meanwhile make the next notice due, with a new
  delayed message. The request may have ended since: received files stay, so the notice goes out
  whatever its state.
- `transfer.awaiting_confirmation` (#219): `dlp_confirmation_needed` to the owner, while the
  transfer still waits for them. A DLP block is `transfer.held` (`transfer_held` says a file or a
  rule holds it), and neither email names a file, a rule or a finding.
- `dlp_policy.changed.<kind>` (#218): the kind of change, one topic per kind since a payload
  carries IDs only, joins the tenant's coalesced notice (#230, abuse 7.1;
  `sft.service.notice_windows`): the first change with no notice due makes one due in 10 minutes
  with a delayed `dlp_policy.notice_due`; the rest only add their kind. An approver designation
  changed by `updateUser` is the kind `approvers_changed` (#220).
- `dlp_policy.notice_due` (#230): `dlp_policy_changed`, listing every kind of change of the
  window, to every active admin (FR-54): one email per admin however many changes. A change made
  while it goes out makes the next notice due.
- `dlp_approval.requested` (#220): `dlp_approval_requested` to each eligible approver (active,
  with the designation, not the transfer's sender), while the request is still pending. No file
  name, no approve link: decisions are made signed in (architecture 4.6). Past 20 in an hour, an
  approver's emails wait for their digest (#230, abuse 7.1).
- `dlp_approval.digest_due` (#230): the digest, `dlp_approval_requested` with the count of
  requests the approver could decide now, once the approver's hour has ended.
- `dlp_approval.decided`, `dlp_approval.expired` (#220): `dlp_approval_decided` (approved or
  rejected; the comment stays in the web app) and `dlp_approval_expired` to the transfer's sender.
- `dlp_approval.no_eligible_approver` (#220): `dlp_no_eligible_approver` to every active admin,
  at most 3 times a day per tenant (#230); the rest are counted in `email_caps_hit_total`.
- `dlp_approval.approver_deactivated` (#230): a deactivation cleared an approver designation.
  With fewer than two active approvers left, `dlp_approver_deactivated` to every active admin at
  once; otherwise the kind `approvers_changed` joins the coalesced policy notice.
- `member.invited`: in a tenant with an active SSO connection (#273), when the tenant requires SSO
  or the address is on one of its proven domains linked to that connection, no pool user: a new
  one-time link (256 bits, its SHA-256 and a 7-day expiry on the user,
  `user.invitation_link_issued`), then `member_invitation_sso` with it; the member binds their
  identity provider's subject when they follow it (`startInvitationSignIn`). Otherwise, with a user
  pool (`sft.service.user_pool`; Keycloak locally, #197), the member's pool user with a temporary
  password, its identity, then `member_invitation` with that password; an address that already signs
  in locally for another tenant gets `invitation_address_in_use` instead and no pool user. Cognito's
  admin API in AWS (#193), Keycloak's locally. Without a pool: recorded, and nothing sent;
  `invite_backlog` invites those members once the pool exists.
- `member.sign_in_reset`: the pool user, after deleting the member's earlier one: a new user, a
  new identity, a new invitation (authn and authz 2.5). The API already ended the sessions and
  deleted the old identities.
- `tenant.admin_recovered` (#273): `tenant_admin_recovered` to every active admin of the tenant,
  the recovered one included: which admin an operator recovered, when, and whether it is a reset
  or a temporary local sign-in (`recoverTenantAdmin`, authn and authz 2.5).
- `member.temporary_sign_in_ended` (#273): the daily job ended an operator's temporary local
  sign-in. The admin's pool user is deleted if the recovery's reset is still the admin's latest
  and the pool user was made for it; one made since, for a newer reset, stays. No email.
- `api_key.expiring` (#215): `api_key_expiring` to the key's owner and every active tenant admin,
  unless the key was revoked or has expired meanwhile. Names the key by its prefix only.
- `api_key.first_export` (#216): `api_key_first_export` to every active tenant admin.

**A cleared suppression** (#217, abuse 7.4): before a link or code email goes to an address whose
suppression entry ended since its last release (an admin cleared it, or its 90 days passed), the
worker removes the address from the tenant's SES list (`release`, outside any transaction, before
the send), then records `ses_released_at` and `email_suppression.released` with the email. A
release that fails sends nothing, and the message is delivered again.

**Recorded after the send** (ADR-0013, consumer.py). An email can't share a transaction, so a
message that sends one is handled in three steps: a short transaction checks that the message
wasn't handled before and prepares the email, committing what must survive a retry (the link's
issue time, a code's row); then the send, outside any transaction; then a second short
transaction records the message with the delivery and its audit event. A send that fails leaves
the message unrecorded, so SQS delivers it again; a copy that arrives after the record is skipped,
so a recorded success is never sent twice. A message that sends nothing is recorded in the first
transaction. A notice to several people (the lockout notice) records each email as it goes, under
the message's ID and the addressee's pseudonym, so a redelivery after a failure midway sends only
the ones not sent yet. An email the provider refuses for good isn't retried; a link email then
leaves its recipient `bounced` (`email.rejected` in the audit log).

**The same link on every retry.** The link token is derived from the recipient's ID and
`link_issued_at` under the `link-hmac` key in `link_key_id` (`sft.core.hmac_keyrings`), and the
first transaction sets those only while `link_issued_at` is empty. A retry rebuilds the same
token, so a link that one attempt delivered keeps working. Clearing the link (an unlock) makes the
next message derive a new one. The token never travels through the outbox, SQS, logs or audit
rows: only its SHA-256 is stored.

**The cross-tenant cap** (abuse 7.2): 100 link emails a day to one address across tenants,
counted under the address's pseudonym in the counter store. It is read before the send and
spent only after a successful one, so failed sends and redeliveries cost nothing. Over it, the
email waits: the message
is recorded with a new, delayed `recipient.link_due` message in the same transaction, and the
recipient stays `queued`, the neutral state of every delay. During a counter store outage the cap
counts in this pod (group G fails open).

**A new link on every retry** of an SSO invitation, as a new temporary password is for a local
one: only the link's hash is stored, so a redelivery mints another, which replaces the first.

**A pool user before its email.** The pool user and its identity are made after the first
transaction and before the send (`_Plan.before_send`), so the email names a password the pool
holds. A redelivery makes a new password: it finds the user an earlier delivery created (by its
username, our user ID) and gives it the new one; the identity is recorded once. The password goes
only into the pool and the email, never into the outbox, a log or an audit row.

**Notices to members** go out in the tenant's default language (FR-33); users have no language of
their own yet. A suspended tenant's messages are recorded and send nothing.

Every email sent is audited (`email.sent`, with its type), and counted in
`emails_sent_total{type}`; every email held by a cap in `email_caps_hit_total{cap}`. How long each
took from its message to the provider is `send_latency_seconds{type}` (NFR-7, #260).
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter, Histogram
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import RateLimited
from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.ids import uuid7
from sft.core.pseudonyms import EmailKeyring
from sft.core.tokens import token_hash
from sft.data import (
    admin_recoveries,
    api_keys,
    audit,
    codes,
    dlp_approvals,
    identities,
    recipients,
    sso,
    suppressions,
    tenants,
    transfers,
    upload_requests,
    users,
)
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail
from sft.data.models import (
    ActorType,
    ApprovalState,
    DeliveryState,
    Role,
    TransferState,
    UploadRequestState,
    User,
    UserStatus,
)
from sft.data.models import Outcome as AuditOutcome
from sft.data.outbox import (
    API_KEY_EXPIRING,
    API_KEY_FIRST_EXPORT,
    DLP_APPROVAL_DECIDED,
    DLP_APPROVAL_DIGEST_DUE,
    DLP_APPROVAL_EXPIRED,
    DLP_APPROVAL_REQUESTED,
    DLP_APPROVER_DEACTIVATED,
    DLP_NO_ELIGIBLE_APPROVER,
    DLP_POLICY_CHANGED,
    DLP_POLICY_NOTICE_DUE,
    MAX_DELAY,
    MEMBER_INVITED,
    MEMBER_SIGN_IN_RESET,
    MEMBER_TEMPORARY_SIGN_IN_ENDED,
    RECIPIENT_CODE_REQUESTED,
    RECIPIENT_LINK_DUE,
    RECIPIENT_LOCKED,
    TENANT_ADMIN_RECOVERED,
    TRANSFER_AWAITING_CONFIRMATION,
    TRANSFER_FIRST_DOWNLOAD,
    TRANSFER_HELD,
    TRANSFER_RETURNED_TO_DRAFT,
    TRANSFER_SENT,
    UPLOAD_REQUEST_CODE_REQUESTED,
    UPLOAD_REQUEST_FILES_SETTLED,
    UPLOAD_REQUEST_LINK_DUE,
    UPLOAD_REQUEST_UPLOADER_LOCKED,
    OutboxMessage,
    enqueue,
)
from sft.data.processed import record_processed, recorded_before
from sft.data.scope import Scope, Subject
from sft.service import notice_windows
from sft.service.email import EmailRenderer
from sft.service.email.catalog import (
    ApiKeyExpiring,
    ApiKeyFirstExport,
    DlpApprovalDecided,
    DlpApprovalExpired,
    DlpApprovalRequested,
    DlpApproverDeactivated,
    DlpConfirmationNeeded,
    DlpNoEligibleApprover,
    DlpPolicyChanged,
    Email,
    EmailType,
    FilesArrived,
    FilesBlockedMember,
    FilesBlockedUploader,
    FirstDownload,
    InvitationAddressInUse,
    Locale,
    MemberInvitation,
    MemberInvitationSso,
    PolicyChange,
    RecipientLocked,
    TenantAdminRecovered,
    TransferHeld,
    TransferLink,
    TransferReturnedToDraft,
    UploadRequest,
    VerificationCode,
)
from sft.service.rate_limits import Charge
from sft.service.rate_limits.limits import CROSS_TENANT_LINK_EMAILS, KeyType
from sft.service.transfers import effective_state
from sft.service.upload_requests import effective_state as request_effective_state
from sft.service.user_pool import (
    INVITATION_ENROLMENT,
    TEMPORARY_PASSWORD_DAYS,
    PoolUserExistsError,
    UserPool,
    new_temporary_password,
)

log = logging.getLogger(__name__)

CONSUMER: Final = "notify"
"""The consumer's name in `processed_messages`. Never change it."""
CODE_DIGITS: Final = 6
"""NFR-14: at least 6 digits, from the operating system's generator."""
INVITATION_TOKEN_BYTES: Final = 32
"""An SSO invitation link's token: 256 random bits (authn and authz 2.5)."""
ADMIN_RECOVERY_TARGET: Final = "admin_recovery"
"""The audit target of the admin recovery notice's emails: the recovery (#273)."""

SYSTEM: Final = Actor(ActorType.SYSTEM)


class SystemActor(StrEnum):
    NOTIFICATION_WORKER = "notification_worker"


class Done(StrEnum):
    """What handling one message did."""

    PROCESSED = "processed"
    DUPLICATE = "duplicate"


class Addressed(Protocol):
    """A link or code email's addressee: a recipient's or an uploader's link target."""

    @property
    def email(self) -> str: ...

    @property
    def email_normalized(self) -> str: ...


class Limiter(Protocol):
    """What the worker needs of `sft.service.rate_limits.RateLimiter`."""

    async def peek_all(self, charges: Sequence[Charge]) -> None: ...

    async def check_all(self, charges: Sequence[Charge]) -> None: ...


Send = Callable[[OutgoingEmail], Awaitable[str]]
"""Hands one email to the provider (a `Mailer` in the worker's thread pool); its message ID."""
Release = Callable[[UUID, str], Awaitable[None]]
"""Removes an address from a tenant's suppression list at the provider (`Mailer.release`)."""


@dataclass(frozen=True)
class NotifyMetrics:
    emails: Counter
    caps: Counter
    send_latency: Histogram

    def observe_send(self, message_id: UUID, email_type: EmailType, now: datetime) -> None:
        """NFR-7 (#260): from the outbox message that asked for the email, made when its UUIDv7
        ID was (data model 1), to the provider accepting it."""
        if message_id.version != 7:
            return
        made = datetime.fromtimestamp((message_id.int >> 80) / 1000, UTC)
        self.send_latency.labels(email_type.value).observe(max(0.0, (now - made).total_seconds()))

    @classmethod
    def create(cls, registry: CollectorRegistry) -> NotifyMetrics:
        emails = Counter(
            "emails_sent_total",
            "Emails the provider accepted, by type (abuse 8.1).",
            ["type"],
            registry=registry,
        )
        for email_type in EmailType:
            emails.labels(email_type.value)
        caps = Counter(
            "email_caps_hit_total",
            "Emails held back by a cap, by cap: the email waits and is sent later (abuse 7.2).",
            ["cap"],
            registry=registry,
        )
        caps.labels("address_link_emails_all")
        # #230: an approver's request emails held for their digest, and the tenant's capped
        # "no eligible approver" notices.
        caps.labels("approver_request_emails")
        caps.labels("tenant_no_eligible_approver")
        send_latency = Histogram(
            "send_latency_seconds",
            "NFR-7: from the message that asked for an email to the provider accepting it, by "
            "type; the edge at 10 s is NFR-7's target.",
            ["type"],
            buckets=(1, 2.5, 5, 10, 20, 30, 60, 300, 900),
            registry=registry,
        )
        for email_type in EmailType:
            send_latency.labels(email_type.value)
        return cls(emails, caps, send_latency)


@dataclass
class _Plan:
    """What the first transaction decided: the emails to send, then what to record with them.

    `after` runs in the recording transaction once the email went out (on this delivery or an
    earlier one); `rejected` instead when the provider refused it for good. `charge` runs right
    after a successful send, outside any transaction, so only a sent email spends a cap.
    `per_email` records each email of a plan to several people on its own, so a redelivery after
    a failure midway sends only the ones not sent yet.
    """

    emails: list[tuple[Email, OutgoingEmail]] = field(default_factory=list)
    target: Target | None = None
    after: Callable[[AsyncSession], Awaitable[None]] | None = None
    rejected: Callable[[AsyncSession], Awaitable[None]] | None = None
    charge: Callable[[], Awaitable[None]] | None = None
    per_email: bool = False
    before_send: Callable[[], Awaitable[None]] | None = None
    """Runs after the first transaction and before the first send, outside any transaction: the
    pool user an invitation's email names (#197). Raising there sends nothing."""
    audit_type: EmailType | None = None
    """The email type the tenant's audit log records, when it must not be the email's own: an
    address-in-use email is logged as an invitation, so the tenant learns nothing of another
    tenant (authn and authz 2.5, NFR-12)."""
    part_by_type: bool = False
    """With `per_email`, each email is recorded by its type too: a notice that sends one person
    two emails (#213's to a request's owner) records each."""


def _details(**more: audit.Detail) -> dict[str, audit.Detail]:
    return {"system_actor": SystemActor.NOTIFICATION_WORKER, **more}


def new_code() -> str:
    return f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"


class Notifier:
    def __init__(
        self,
        database: Database,
        *,
        renderer: EmailRenderer,
        send: Send,
        link_keys: LinkKeyring,
        code_keys: CodeKeyring,
        emails: EmailKeyring,
        limiter: Limiter,
        metrics: NotifyMetrics,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        pool: UserPool | None = None,
        release: Release | None = None,
    ) -> None:
        self.database = database
        self.renderer = renderer
        self.send = send
        self.link_keys = link_keys
        self.code_keys = code_keys
        self.emails = emails
        self.limiter = limiter
        self.metrics = metrics
        self.clock = clock
        self.pool = pool
        self.release = release

    async def handle(self, message: OutboxMessage) -> Done:
        """Do the message's work once (module docstring). Raises to have it delivered again."""
        if message.topic == TRANSFER_SENT.name:
            return await self._fan_out(message)
        if self.pool is not None and message.topic in (
            MEMBER_INVITED.name,
            MEMBER_SIGN_IN_RESET.name,
        ):
            return await self._enrol(message, self.pool, reset=message.topic != MEMBER_INVITED.name)
        if message.topic == MEMBER_SIGN_IN_RESET.name:
            # Without a pool there is no user to create again: recorded, and nothing sent.
            return await self._with_emails(message, self._left_for_pool)
        if message.topic == MEMBER_TEMPORARY_SIGN_IN_ENDED.name:
            return await self._temporary_sign_in_ended(message)
        prepare = {
            RECIPIENT_LINK_DUE.name: self._link,
            RECIPIENT_CODE_REQUESTED.name: self._code,
            RECIPIENT_LOCKED.name: self._locked,
            TRANSFER_HELD.name: self._held,
            TRANSFER_RETURNED_TO_DRAFT.name: self._returned_to_draft,
            TRANSFER_AWAITING_CONFIRMATION.name: self._awaiting_confirmation,
            MEMBER_INVITED.name: self._invited,
            TRANSFER_FIRST_DOWNLOAD.name: self._first_download,
            UPLOAD_REQUEST_LINK_DUE.name: self._uploader_link,
            UPLOAD_REQUEST_CODE_REQUESTED.name: self._uploader_code,
            UPLOAD_REQUEST_UPLOADER_LOCKED.name: self._uploader_locked,
            UPLOAD_REQUEST_FILES_SETTLED.name: self._files_settled,
            API_KEY_EXPIRING.name: self._key_expiring,
            API_KEY_FIRST_EXPORT.name: self._key_first_export,
            TENANT_ADMIN_RECOVERED.name: self._admin_recovered,
            **{topic.name: self._policy_changed for topic in DLP_POLICY_CHANGED.values()},
            DLP_APPROVAL_REQUESTED.name: self._approval_requested,
            DLP_APPROVAL_DECIDED.name: self._approval_decided,
            DLP_APPROVAL_EXPIRED.name: self._approval_decided,
            DLP_NO_ELIGIBLE_APPROVER.name: self._no_eligible_approver,
            DLP_POLICY_NOTICE_DUE.name: self._policy_notice_due,
            DLP_APPROVAL_DIGEST_DUE.name: self._approval_digest,
            DLP_APPROVER_DEACTIVATED.name: self._approver_deactivated,
        }.get(message.topic)
        if prepare is None:
            # Never deleted: after 5 receives it lands in the dead-letter queue, which alerts.
            raise ValueError(f"the notification worker handles no {message.topic!r} messages")
        return await self._with_emails(message, prepare)

    # ---- the three steps ----

    async def _with_emails(
        self,
        message: OutboxMessage,
        prepare: Callable[[AsyncSession, OutboxMessage], Awaitable[_Plan]],
    ) -> Done:
        scope = Scope.tenant(message.tenant_id)
        message_id = str(message.id)
        async with self.database.transaction(scope) as session:
            if await recorded_before(session, consumer=CONSUMER, message_id=message_id):
                return Done.DUPLICATE
            plan = await prepare(session, message)
            if not plan.emails:
                await record_processed(session, consumer=CONSUMER, message_id=message_id)
                return Done.PROCESSED
        if plan.before_send is not None:
            await plan.before_send()
        sent: list[Email] = []
        delivered = rejected = False
        for email, outgoing in plan.emails:
            part = None
            if plan.per_email:
                part = f"{message_id}:{self.emails.active(outgoing.to.lower())}"
                if plan.part_by_type:
                    part = f"{part}:{email.TYPE.value}"
            if part is not None:
                async with self.database.transaction(scope) as session:
                    if await recorded_before(session, consumer=CONSUMER, message_id=part):
                        delivered = True
                        continue  # sent on an earlier delivery of this message
            try:
                await self.send(outgoing)
            except MailError as exc:
                if exc.kind is not MailErrorKind.REJECTED:
                    raise
                # This message will never be accepted: don't retry it (data.mail).
                log.error(
                    "email rejected by the provider", extra={"type": email.TYPE, "code": exc.code}
                )
                rejected = True
                if part is not None:
                    await self._record_part(scope, part, plan, email, outcome="rejected")
                continue
            delivered = True
            sent.append(email)
            self.metrics.observe_send(message.id, email.TYPE, self.clock())
            if plan.charge is not None:
                await plan.charge()
            if part is not None:
                await self._record_part(scope, part, plan, email, outcome="sent")
        async with self.database.transaction(scope) as session:
            if not await record_processed(session, consumer=CONSUMER, message_id=message_id):
                return Done.DUPLICATE
            if not plan.per_email:
                for email in sent:
                    await self._audit_sent(session, plan, email)
                if rejected and not delivered:
                    await self._audit_rejected(session, plan, plan.emails[0][0])
            if plan.after is not None and delivered:
                await plan.after(session)
            elif plan.rejected is not None and rejected:
                await plan.rejected(session)
        for email in sent:
            self.metrics.emails.labels(email.TYPE.value).inc()
        return Done.PROCESSED

    async def _record_part(
        self, scope: Scope, part: str, plan: _Plan, email: Email, *, outcome: str
    ) -> None:
        """One email of a plan to several people is done: recorded with its audit event."""
        async with self.database.transaction(scope) as session:
            await record_processed(session, consumer=CONSUMER, message_id=part)
            if outcome == "sent":
                await self._audit_sent(session, plan, email)
            else:
                await self._audit_rejected(session, plan, email)

    async def _audit_sent(self, session: AsyncSession, plan: _Plan, email: Email) -> None:
        await audit.record(
            session,
            action="email.sent",
            actor=SYSTEM,
            target=plan.target,
            details=_details(email_type=plan.audit_type or email.TYPE),
        )

    async def _audit_rejected(self, session: AsyncSession, plan: _Plan, email: Email) -> None:
        await audit.record(
            session,
            action="email.rejected",
            actor=SYSTEM,
            target=plan.target,
            outcome=AuditOutcome.FAILURE,
            details=_details(email_type=plan.audit_type or email.TYPE),
        )

    async def _fan_out(self, message: OutboxMessage) -> Done:
        transfer_id = _id(message, "transfer_id")
        async with self.database.transaction(Scope.tenant(message.tenant_id)) as session:
            if not await record_processed(session, consumer=CONSUMER, message_id=str(message.id)):
                return Done.DUPLICATE
            notice = await transfers.notice(session, transfer_id)
            if notice is None or notice.state is not TransferState.SENT:
                return Done.PROCESSED
            for recipient_id in await transfers.recipient_ids(session, transfer_id):
                await enqueue(session, RECIPIENT_LINK_DUE, {"recipient_id": recipient_id})
        return Done.PROCESSED

    # ---- recipients ----

    async def _live_target(
        self, session: AsyncSession, recipient_id: UUID
    ) -> recipients.LinkTarget | None:
        """The recipient, locked, if their transfer is sent and hasn't expired, they aren't
        locked out and their tenant is active."""
        target = await recipients.link_target(session, recipient_id, lock=True)
        if target is None or target.locked_at is not None:
            return None
        stored = TransferState(target.transfer_state)
        state = effective_state(stored, target.expires_at, self.clock())
        return target if state is TransferState.SENT else None

    async def _suppressed(self, session: AsyncSession, address: str) -> bool:
        found = await suppressions.suppressed(session, self.emails.every_version(address))
        return bool(found)

    async def _link(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        recipient_id = _id(message, "recipient_id")
        target = await self._live_target(session, recipient_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active:
            return _Plan()
        if target.delivery_state is DeliveryState.SENT and target.notified_at is not None:
            return _Plan()  # this link's email went out already (a stale copy)
        subject = Target("recipient", recipient_id)
        if await self._suppressed(session, target.email_normalized):
            await recipients.set_delivery(session, recipient_id, DeliveryState.SUPPRESSED)
            await audit.record(
                session,
                action="recipient.suppressed",
                actor=SYSTEM,
                target=subject,
                details=_details(),
            )
            return _Plan()
        charges = [
            Charge(
                limit,
                {KeyType.EMAIL: self.emails.for_limits(target.email_normalized, self.clock())},
            )
            for limit in CROSS_TENANT_LINK_EMAILS
        ]
        try:
            # Read here, spent only once the email is sent (`charge`), so a failed send, a
            # redelivery or a rejection costs the address nothing.
            await self.limiter.peek_all(charges)
        except RateLimited as held:
            delay = min(timedelta(seconds=held.retry_after), MAX_DELAY)
            await enqueue(session, RECIPIENT_LINK_DUE, {"recipient_id": recipient_id}, delay=delay)
            self.metrics.caps.labels("address_link_emails_all").inc()
            log.info("link email held by the cross-tenant cap", extra={"delay": delay.seconds})
            return _Plan()
        token = await self._token(session, target)
        if token is None:
            return _Plan()
        owner = await users.get_user(session, target.owner_id)
        if owner is None or target.expires_at is None:  # pragma: no cover - a sent transfer's
            return _Plan()
        email = TransferLink(
            tenant_name=sender.name,
            sender_email=owner.email,
            token=token,
            expires_at=target.expires_at,
        )
        outgoing = self.renderer.compose(
            email,
            Locale(target.locale),
            to=target.email,
            tenant_id=message.tenant_id,
            tags={"recipient_id": str(recipient_id)},
        )

        async def delivered(session: AsyncSession) -> None:
            await recipients.set_delivery(session, recipient_id, DeliveryState.SENT, notified=True)

        async def bounced(session: AsyncSession) -> None:
            # The provider will never take this email: `bounced`, the state the contract gives
            # a hard failure, so the member sees it (FR-7).
            await recipients.set_delivery(session, recipient_id, DeliveryState.BOUNCED)

        async def charge() -> None:
            try:
                await self.limiter.check_all(charges)
            except RateLimited:
                # The cap filled meanwhile, from another worker: the email is out already.
                log.info("link email sent as the cross-tenant cap filled")

        plan = _Plan([(email, outgoing)], subject, delivered, bounced, charge)
        return await self._released_first(session, plan, message.tenant_id, target)

    async def _released_first(
        self, session: AsyncSession, plan: _Plan, tenant_id: UUID, target: Addressed
    ) -> _Plan:
        """The plan, removing the address from the tenant's SES list before the send if its
        suppression entry ended since the last release (module docstring)."""
        entry_id = await suppressions.release_due(
            session, self.emails.every_version(target.email_normalized)
        )
        if entry_id is None or self.release is None:
            return plan
        release, address = self.release, target.email

        async def released() -> None:
            await release(tenant_id, address)

        async def recorded(session: AsyncSession) -> None:
            await suppressions.mark_released(session, entry_id)
            await audit.record(
                session,
                action="email_suppression.released",
                actor=SYSTEM,
                target=Target(suppressions.TARGET, entry_id),
                details=_details(),
            )

        plan.before_send = released
        plan.after = _both(recorded, plan.after)
        plan.rejected = _both(recorded, plan.rejected)
        return plan

    async def _token(self, session: AsyncSession, target: recipients.LinkTarget) -> str | None:
        """The recipient's link token: rebuilt from the row, or derived and stored now. None if
        another attempt stored a link first that can't be rebuilt here: never a token whose hash
        isn't stored."""
        if (
            target.link_issued_at is not None
            and target.link_key_id is not None
            and self.link_keys.knows(target.link_key_id)
        ):
            return self.link_keys.token(target.link_key_id, target.id, target.link_issued_at)
        # No link yet, or one whose key has left the keyring (more than 14 days after a rotation,
        # data model 2.2): issue a new one. The old one, if any, stops working.
        replace = target.link_issued_at is not None
        issued_at = self.clock()
        key_id = self.link_keys.active_id
        token = self.link_keys.token(key_id, target.id, issued_at)
        issued = await recipients.issue_link(
            session,
            target.id,
            key_id=key_id,
            issued_at=issued_at,
            hashed=token_hash(token),
            replace=replace,
        )
        if not issued:
            # Another attempt stored a link first: the token to send is the one it stored.
            stored = await recipients.link_target(session, target.id)
            if (
                stored is None
                or stored.link_issued_at is None
                or stored.link_key_id is None
                or not self.link_keys.knows(stored.link_key_id)
            ):
                return None
            return self.link_keys.token(stored.link_key_id, stored.id, stored.link_issued_at)
        await audit.record(
            session,
            action="recipient.link_issued",
            actor=SYSTEM,
            target=Target("recipient", target.id),
            details=_details(replaced=replace),
        )
        return token

    async def _code(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        recipient_id = _id(message, "recipient_id")
        target = await self._live_target(session, recipient_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active or target.link_issued_at is None:
            return _Plan()
        subject = Target("recipient", recipient_id)
        if await self._suppressed(session, target.email_normalized):
            return _Plan()  # requestVerificationCode answered 422; suppressed since: no email
        code = new_code()
        code_id = uuid7()
        key_id = self.code_keys.active_id
        superseded = await codes.create(
            session,
            recipient_id,
            code_id=code_id,
            code_hmac=self.code_keys.code_hmac(key_id, code_id, code),
            key_id=key_id,
        )
        await audit.record(
            session,
            action="verification.code_created",
            actor=SYSTEM,
            target=subject,
            details=_details(code_id=code_id, superseded=superseded),
        )
        email = VerificationCode(tenant_name=sender.name, code=code)
        outgoing = self.renderer.compose(
            email,
            Locale(target.locale),
            to=target.email,
            tenant_id=message.tenant_id,
            tags={"recipient_id": str(recipient_id)},
        )
        plan = _Plan([(email, outgoing)], subject)
        return await self._released_first(session, plan, message.tenant_id, target)

    async def _locked(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        recipient_id = _id(message, "recipient_id")
        target = await recipients.link_target(session, recipient_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active or target.locked_at is None:
            return _Plan()
        email = RecipientLocked(
            tenant_name=sender.name, subject_kind="transfer", subject_id=target.transfer_id
        )
        to = await self._owner_and_admins(session, target.owner_id)
        return _Plan(
            [self._to_member(email, sender, address, message.tenant_id) for address in to],
            Target("recipient", recipient_id),
            per_email=True,
        )

    # ---- uploaders (#212) ----

    async def _live_request(
        self, session: AsyncSession, request_id: UUID
    ) -> upload_requests.LinkTarget | None:
        """The request, locked, if it is open and hasn't expired and its uploader isn't locked
        out."""
        target = await upload_requests.link_target(session, request_id, lock=True)
        if target is None or target.locked_at is not None:
            return None
        state = request_effective_state(target.state, target.expires_at, self.clock())
        return target if state is UploadRequestState.OPEN else None

    async def _uploader_link(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`upload_request` to the uploader, as `_link` sends a recipient theirs."""
        request_id = _id(message, "upload_request_id")
        target = await self._live_request(session, request_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active:
            return _Plan()
        if target.delivery_state is DeliveryState.SENT and target.notified_at is not None:
            return _Plan()  # this link's email went out already (a stale copy)
        subject = Target(upload_requests.TARGET, request_id)
        if await self._suppressed(session, target.email_normalized):
            await upload_requests.set_delivery(session, request_id, DeliveryState.SUPPRESSED)
            await audit.record(
                session,
                action="uploader.suppressed",
                actor=SYSTEM,
                target=subject,
                details=_details(),
            )
            return _Plan()
        charges = [
            Charge(
                limit,
                {KeyType.EMAIL: self.emails.for_limits(target.email_normalized, self.clock())},
            )
            for limit in CROSS_TENANT_LINK_EMAILS
        ]
        try:
            await self.limiter.peek_all(charges)
        except RateLimited as held:
            delay = min(timedelta(seconds=held.retry_after), MAX_DELAY)
            await enqueue(
                session, UPLOAD_REQUEST_LINK_DUE, {"upload_request_id": request_id}, delay=delay
            )
            self.metrics.caps.labels("address_link_emails_all").inc()
            log.info("link email held by the cross-tenant cap", extra={"delay": delay.seconds})
            return _Plan()
        token = await self._uploader_token(session, target)
        if token is None:
            return _Plan()
        owner = await users.get_user(session, target.created_by)
        if owner is None:  # pragma: no cover - a request's owner is a user of its tenant
            return _Plan()
        email = UploadRequest(
            tenant_name=sender.name,
            sender_email=owner.email,
            token=token,
            expires_at=target.expires_at,
        )
        outgoing = self.renderer.compose(
            email,
            Locale(target.locale),
            to=target.email,
            tenant_id=message.tenant_id,
            tags={"upload_request_id": str(request_id)},
        )

        async def delivered(session: AsyncSession) -> None:
            await upload_requests.set_delivery(
                session, request_id, DeliveryState.SENT, notified=True
            )

        async def bounced(session: AsyncSession) -> None:
            await upload_requests.set_delivery(session, request_id, DeliveryState.BOUNCED)

        async def charge() -> None:
            try:
                await self.limiter.check_all(charges)
            except RateLimited:
                log.info("link email sent as the cross-tenant cap filled")

        plan = _Plan([(email, outgoing)], subject, delivered, bounced, charge)
        return await self._released_first(session, plan, message.tenant_id, target)

    async def _uploader_token(
        self, session: AsyncSession, target: upload_requests.LinkTarget
    ) -> str | None:
        """The uploader's link token, derived from the request's ID as `_token` derives a
        recipient's (data model 2.2): rebuilt, or issued now and its hash stored once."""
        if (
            target.link_issued_at is not None
            and target.link_key_id is not None
            and self.link_keys.knows(target.link_key_id)
        ):
            return self.link_keys.token(target.link_key_id, target.id, target.link_issued_at)
        replace = target.link_issued_at is not None
        issued_at = self.clock()
        key_id = self.link_keys.active_id
        token = self.link_keys.token(key_id, target.id, issued_at)
        issued = await upload_requests.issue_link(
            session,
            target.id,
            key_id=key_id,
            issued_at=issued_at,
            hashed=token_hash(token),
            replace=replace,
        )
        if not issued:
            stored = await upload_requests.link_target(session, target.id)
            if (
                stored is None
                or stored.link_issued_at is None
                or stored.link_key_id is None
                or not self.link_keys.knows(stored.link_key_id)
            ):
                return None
            return self.link_keys.token(stored.link_key_id, stored.id, stored.link_issued_at)
        await audit.record(
            session,
            action="uploader.link_issued",
            actor=SYSTEM,
            target=Target(upload_requests.TARGET, target.id),
            details=_details(replaced=replace),
        )
        return token

    async def _uploader_code(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`verification_code` to the uploader's stored address only, as for a recipient."""
        request_id = _id(message, "upload_request_id")
        target = await self._live_request(session, request_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active or target.link_issued_at is None:
            return _Plan()
        subject = Target(upload_requests.TARGET, request_id)
        if await self._suppressed(session, target.email_normalized):
            return _Plan()  # requestVerificationCode answered 422; suppressed since: no email
        code = new_code()
        code_id = uuid7()
        key_id = self.code_keys.active_id
        superseded = await codes.create_for(
            session,
            Subject.upload_request(request_id),
            code_id=code_id,
            code_hmac=self.code_keys.code_hmac(key_id, code_id, code),
            key_id=key_id,
        )
        await audit.record(
            session,
            action="verification.code_created",
            actor=SYSTEM,
            target=subject,
            details=_details(code_id=code_id, superseded=superseded),
        )
        email = VerificationCode(tenant_name=sender.name, code=code)
        outgoing = self.renderer.compose(
            email,
            Locale(target.locale),
            to=target.email,
            tenant_id=message.tenant_id,
            tags={"upload_request_id": str(request_id)},
        )
        plan = _Plan([(email, outgoing)], subject)
        return await self._released_first(session, plan, message.tenant_id, target)

    async def _uploader_locked(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """The lockout notice to the request's owner and every active admin: `recipient_locked`
        in its upload-request variant, which names the request's page and no address."""
        request_id = _id(message, "upload_request_id")
        target = await upload_requests.link_target(session, request_id)
        sender = await tenants.sender(session)
        if target is None or sender is None or not sender.active or target.locked_at is None:
            return _Plan()
        email = RecipientLocked(
            tenant_name=sender.name, subject_kind="upload_request", subject_id=request_id
        )
        to = await self._owner_and_admins(session, target.created_by)
        return _Plan(
            [self._to_member(email, sender, address, message.tenant_id) for address in to],
            Target(upload_requests.TARGET, request_id),
            per_email=True,
        )

    async def _files_settled(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """The request's batched notice of received files (module docstring, #213)."""
        request_id = _id(message, "upload_request_id")
        notice = await upload_requests.notice(session, request_id, lock=True)
        sender = await tenants.sender(session)
        if notice is None or (notice.arrived == 0 and notice.blocked == 0):
            return _Plan()  # a stale copy: an earlier one sent these counts
        if sender is None or not sender.active:
            return _Plan()  # a suspended tenant's: kept, and told with the next notice
        owner = await users.get_user(session, notice.created_by)
        to_owner = owner is not None and owner.status == UserStatus.ACTIVE.value
        emails: list[tuple[Email, OutgoingEmail]] = []
        if to_owner and owner is not None and notice.arrived:
            arrived = FilesArrived(
                tenant_name=sender.name, upload_request_id=request_id, file_count=notice.arrived
            )
            emails.append(self._to_member(arrived, sender, owner.email, message.tenant_id))
        if to_owner and owner is not None and notice.blocked:
            blocked = FilesBlockedMember(
                tenant_name=sender.name, upload_request_id=request_id, file_count=notice.blocked
            )
            emails.append(self._to_member(blocked, sender, owner.email, message.tenant_id))
        if (
            notice.blocked
            and owner is not None
            and not await self._suppressed(session, notice.email_normalized)
        ):
            # The uploader learns only that the company's policy didn't accept a file: no
            # finding, no scan detail, no file name (FR-12, abuse 7.5).
            uploader = FilesBlockedUploader(tenant_name=sender.name, sender_email=owner.email)
            outgoing = self.renderer.compose(
                uploader,
                Locale(notice.locale),
                to=notice.email,
                tenant_id=message.tenant_id,
                tags={"upload_request_id": str(request_id)},
            )
            emails.append((uploader, outgoing))
        counts = (notice.arrived, notice.blocked)

        async def settled(session: AsyncSession) -> None:
            await self._settle(session, request_id, *counts)

        if not emails:
            # Nobody to tell (an owner deactivated, an uploader suppressed): the counts are
            # taken off all the same, so the next notice holds only what follows.
            await self._settle(session, request_id, *counts)
            return _Plan()
        return _Plan(
            emails,
            Target(upload_requests.TARGET, request_id),
            after=settled,
            rejected=settled,
            per_email=True,
            part_by_type=True,
        )

    async def _settle(
        self, session: AsyncSession, request_id: UUID, arrived: int, blocked: int
    ) -> None:
        """Take the notice's counts off the request, with its audit event; files that settled
        meanwhile make the next notice due, with its delayed message."""
        more = await upload_requests.settle_notice(
            session, request_id, arrived=arrived, blocked=blocked
        )
        if more:
            await enqueue(
                session,
                UPLOAD_REQUEST_FILES_SETTLED,
                {"upload_request_id": request_id},
                delay=upload_requests.NOTICE_WINDOW,
            )
        await audit.record(
            session,
            action="upload_request.notice_sent",
            actor=SYSTEM,
            target=Target(upload_requests.TARGET, request_id),
            details=_details(files_arrived=arrived, files_blocked=blocked, next_notice_due=more),
        )

    # ---- API keys (#215, #216) ----

    async def _key_expiring(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        key_id = _id(message, "api_key_id")
        key = await api_keys.notice_key(session, key_id)
        sender = await tenants.sender(session)
        if key is None or key.revoked or key.expires_at <= self.clock():
            return _Plan()  # revoked or expired since the job asked: nothing to warn of
        if sender is None or not sender.active:
            return _Plan()
        email = ApiKeyExpiring(
            tenant_name=sender.name, key_prefix=key.key_prefix, expires_at=key.expires_at
        )
        to = await self._owner_and_admins(session, key.owner_id)
        return _Plan(
            [self._to_member(email, sender, address, message.tenant_id) for address in to],
            Target(api_keys.TARGET, key_id),
            per_email=True,
        )

    async def _key_first_export(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        key_id = _id(message, "api_key_id")
        key = await api_keys.notice_key(session, key_id)
        sender = await tenants.sender(session)
        if key is None or sender is None or not sender.active:
            return _Plan()
        # Even for a key revoked since: the admins learn what it did while it was live.
        email = ApiKeyFirstExport(tenant_name=sender.name, key_prefix=key.key_prefix)
        to = await self._owner_and_admins(session, key.owner_id)
        return _Plan(
            [self._to_member(email, sender, address, message.tenant_id) for address in to],
            Target(api_keys.TARGET, key_id),
            per_email=True,
        )

    # ---- notices to the tenant's admins ----

    async def _policy_changed(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """The kind of change, the topic's last part (#218, FR-54), joins the tenant's coalesced
        notice (#230): no email of its own. Never a keyword, a threshold or a domain."""
        change = PolicyChange(message.topic.rsplit(".", 1)[-1])
        await notice_windows.note_policy_change(session, change.value, now=self.clock())
        return _Plan()

    async def _policy_notice_due(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`dlp_policy_changed` to every active admin, listing every kind of change of the window
        in the catalog's order (#230, abuse 7.1): one email per admin for many changes."""
        notice = await notice_windows.policy_notice(session)
        sender = await tenants.sender(session)
        if notice is None or sender is None or not sender.active:
            return _Plan()  # sent already; or a suspended tenant's, kept for its next change
        now = self.clock()

        async def settled(session: AsyncSession) -> None:
            await notice_windows.settle_policy_notice(session, notice, now=now)

        admins = await users.list_users(
            session, role=Role.ADMIN, status=UserStatus.ACTIVE, limit=users.MAX_PAGE
        )
        if not admins:  # pragma: no cover - a tenant keeps an active admin (409 last_admin)
            await settled(session)
            return _Plan()
        changes = tuple(change for change in PolicyChange if change.value in notice.changes)
        email = DlpPolicyChanged(tenant_name=sender.name, changes=changes)
        return _Plan(
            [self._to_member(email, sender, admin.email, message.tenant_id) for admin in admins],
            Target("dlp_policy", message.tenant_id),
            after=settled,
            rejected=settled,
            per_email=True,
        )

    async def _no_eligible_approver(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`dlp_no_eligible_approver` to every active admin (#220): a sender's request was refused
        because nobody but the sender could approve. Names no file, rule or finding."""
        transfer_id = _id(message, "transfer_id")
        sender = await tenants.sender(session)
        if sender is None or not sender.active:
            return _Plan()
        # At most 3 a day per tenant (#230). Counted once per message: a redelivery after a
        # failed send finds its count recorded and sends without counting again.
        counted = f"{message.id}:counted"
        if not await recorded_before(session, consumer=CONSUMER, message_id=counted):
            if not await notice_windows.reserve_no_approver_email(session, now=self.clock()):
                self.metrics.caps.labels("tenant_no_eligible_approver").inc()
                log.info("no-eligible-approver notice held by the tenant's cap")
                return _Plan()
            await record_processed(session, consumer=CONSUMER, message_id=counted)
        admins = await users.list_users(
            session, role=Role.ADMIN, status=UserStatus.ACTIVE, limit=users.MAX_PAGE
        )
        email = DlpNoEligibleApprover(tenant_name=sender.name)
        return _Plan(
            [self._to_member(email, sender, admin.email, message.tenant_id) for admin in admins],
            Target("transfer", transfer_id),
            per_email=True,
        )

    # ---- DLP approvals (#220) ----

    async def _approval_requested(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`dlp_approval_requested` to each eligible approver while the request is pending."""
        request_id = _id(message, "approval_request_id")
        request = await dlp_approvals.notice(session, request_id)
        sender = await tenants.sender(session)
        if request is None or request.state is not ApprovalState.PENDING:
            return _Plan()  # decided, withdrawn or expired since: nothing to ask
        if sender is None or not sender.active:
            return _Plan()
        transfer = await transfers.notice(session, request.transfer_id)
        if transfer is None:
            return _Plan()
        email = DlpApprovalRequested(tenant_name=sender.name)
        approvers: dict[UUID, str] = {}
        after: UUID | None = None
        while True:
            page = await users.list_users(
                session,
                status=UserStatus.ACTIVE,
                dlp_approver=True,
                after=after,
                limit=users.MAX_PAGE,
            )
            for user in page[: users.MAX_PAGE]:
                if user.id != transfer.created_by:  # the sender never approves (T-100)
                    approvers[user.id] = user.email
            if len(page) <= users.MAX_PAGE:
                break
            after = page[users.MAX_PAGE - 1].id
        # Past 20 this hour, an approver's email waits for their digest (#230, abuse 7.1).
        now = self.clock()
        emailed, held = await notice_windows.split_approvers(session, list(approvers), now=now)
        if held:
            self.metrics.caps.labels("approver_request_emails").inc(len(held))

        async def counted(session: AsyncSession) -> None:
            await notice_windows.count_approver_emails(session, emailed, now=now)

        return _Plan(
            [self._to_member(email, sender, approvers[a], message.tenant_id) for a in emailed],
            Target("dlp_approval_request", request_id),
            after=counted,
            per_email=True,
        )

    async def _approval_digest(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """An approver's digest (#230, abuse 7.1): `dlp_approval_requested` counting every request
        they could decide now, once their hour has ended, if they are still an active approver."""
        user_id = _id(message, "user_id")
        sender = await tenants.sender(session)
        if sender is None or not sender.active:
            return _Plan()
        user = await users.get_user(session, user_id)
        if user is None:  # pragma: no cover - the message names a user of its tenant
            return _Plan()
        if user.status != UserStatus.ACTIVE.value or not user.dlp_approver:
            await notice_windows.clear_digest(session, user_id)
            return _Plan()  # they approve nothing any more
        digest = await notice_windows.digest_due(session, user_id, now=self.clock())
        if not digest.due:
            return _Plan()

        async def cleared(session: AsyncSession) -> None:
            await notice_windows.clear_digest(session, user_id)

        email = DlpApprovalRequested(tenant_name=sender.name, request_count=digest.request_count)
        return _Plan(
            [self._to_member(email, sender, user.email, message.tenant_id)],
            Target(users.TARGET, user_id),
            after=cleared,
            rejected=cleared,
        )

    async def _approver_deactivated(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """A deactivation cleared an approver designation (#230): with fewer than two active
        approvers left, `dlp_approver_deactivated` to every active admin at once, since some
        transfers can't be approved now; otherwise `approvers_changed` joins the coalesced
        policy notice."""
        user_id = _id(message, "user_id")
        sender = await tenants.sender(session)
        if sender is None or not sender.active:
            return _Plan()
        left = await users.list_users(session, status=UserStatus.ACTIVE, dlp_approver=True, limit=2)
        if len(left) >= 2:
            await notice_windows.note_policy_change(
                session, PolicyChange.APPROVERS_CHANGED.value, now=self.clock()
            )
            return _Plan()
        admins = await users.list_users(
            session, role=Role.ADMIN, status=UserStatus.ACTIVE, limit=users.MAX_PAGE
        )
        email = DlpApproverDeactivated(tenant_name=sender.name, none_left=not left)
        return _Plan(
            [self._to_member(email, sender, admin.email, message.tenant_id) for admin in admins],
            Target(users.TARGET, user_id),
            per_email=True,
        )

    async def _approval_decided(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`dlp_approval_decided` or `dlp_approval_expired` to the transfer's sender, by the
        request's state: approved or rejected, or expired."""
        request_id = _id(message, "approval_request_id")
        request = await dlp_approvals.notice(session, request_id)
        sender = await tenants.sender(session)
        if request is None or sender is None or not sender.active:
            return _Plan()
        expected = (
            (ApprovalState.EXPIRED,)
            if message.topic == DLP_APPROVAL_EXPIRED.name
            else (ApprovalState.APPROVED, ApprovalState.REJECTED)
        )
        if request.state not in expected:
            return _Plan()
        transfer = await transfers.notice(session, request.transfer_id)
        if transfer is None:
            return _Plan()
        owner = await users.get_user(session, transfer.created_by)
        if owner is None or owner.status != UserStatus.ACTIVE.value:
            return _Plan()
        email: Email
        if request.state is ApprovalState.EXPIRED:
            email = DlpApprovalExpired(tenant_name=sender.name, transfer_id=transfer.id)
        else:
            email = DlpApprovalDecided(
                tenant_name=sender.name,
                transfer_id=transfer.id,
                decision="approved" if request.state is ApprovalState.APPROVED else "rejected",
            )
        return _Plan(
            [self._to_member(email, sender, owner.email, message.tenant_id)],
            Target("dlp_approval_request", request_id),
        )

    # ---- notices to the member ----

    async def _held(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        return await self._notice(session, message, TransferState.HELD, TransferHeld)

    async def _returned_to_draft(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        return await self._notice(session, message, TransferState.DRAFT, TransferReturnedToDraft)

    async def _awaiting_confirmation(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        # A DLP rule warns or needs approval (#219): the member reviews it in the web app.
        return await self._notice(
            session, message, TransferState.AWAITING_CONFIRMATION, DlpConfirmationNeeded
        )

    async def _notice(
        self,
        session: AsyncSession,
        message: OutboxMessage,
        state: TransferState,
        kind: type[TransferHeld] | type[TransferReturnedToDraft] | type[DlpConfirmationNeeded],
    ) -> _Plan:
        transfer_id = _id(message, "transfer_id")
        notice = await transfers.notice(session, transfer_id)
        sender = await tenants.sender(session)
        if notice is None or notice.state is not state or sender is None or not sender.active:
            return _Plan()  # it has moved on since: the notice would be wrong now
        owner = await users.get_user(session, notice.created_by)
        if owner is None or owner.status != UserStatus.ACTIVE.value:
            return _Plan()
        email = kind(tenant_name=sender.name, transfer_id=transfer_id)
        return _Plan(
            [self._to_member(email, sender, owner.email, message.tenant_id)],
            Target("transfer", transfer_id),
        )

    async def _first_download(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`first_download` to the member (FR-8, #214), with no file name. The download happened
        whatever the transfer's state is now, so a revoked or expired transfer is still told."""
        transfer_id = _id(message, "transfer_id")
        notice = await transfers.notice(session, transfer_id)
        sender = await tenants.sender(session)
        if notice is None or sender is None or not sender.active:
            return _Plan()
        owner = await users.get_user(session, notice.created_by)
        if owner is None or owner.status != UserStatus.ACTIVE.value:
            return _Plan()
        email = FirstDownload(tenant_name=sender.name, transfer_id=transfer_id)
        return _Plan(
            [self._to_member(email, sender, owner.email, message.tenant_id)],
            Target("transfer", transfer_id),
        )

    async def _invited(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """An invitation without a pool: an SSO tenant's link needs none (#273). Otherwise the
        user stays `invited`, and nothing is sent (#178); `invite_backlog` invites them once the
        pool exists (#193)."""
        user = await users.get_user(session, _id(message, "user_id"))
        sender = await tenants.sender(session)
        if user is None or sender is None or not sender.active:
            return _Plan()
        if user.status != UserStatus.INVITED.value:
            return _Plan()  # they joined meanwhile: nothing to send
        plan = await self._sso_invitation(session, message, user, sender)
        return plan if plan is not None else await self._left_for_pool(session, message)

    async def _left_for_pool(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        log.info("invitation left for the user pool", extra={"outbox_id": str(message.id)})
        return _Plan()

    async def _sso_invitation(
        self, session: AsyncSession, message: OutboxMessage, user: User, sender: tenants.Sender
    ) -> _Plan | None:
        """An invited user of a tenant with an active SSO connection, if the tenant requires SSO or
        their address is on one of its proven domains linked to that connection (authn and authz
        2.5, #273): a new one-time link, its hash and expiry on the user, committed before the
        send, then `member_invitation_sso`; no pool user. None otherwise: the invitation takes the
        pool's path, as any local member's. The token goes only into the email; the row, the
        audit event and the logs never hold it."""
        connection_id = await sso.active_connection_id(session)
        if connection_id is None or not await sso.invites_through_sso(
            session, connection_id, user.email_normalized
        ):
            return None
        token = secrets.token_urlsafe(INVITATION_TOKEN_BYTES)
        expires_at = await users.issue_invitation_link(session, user.id, token_hash(token))
        if expires_at is None:  # pragma: no cover - read as invited in this transaction
            return _Plan()
        target = Target(users.TARGET, user.id)
        await audit.record(
            session,
            action="user.invitation_link_issued",
            actor=SYSTEM,
            target=target,
            details=_details(replaced=user.invitation_token_hash is not None),
        )
        email = MemberInvitationSso(tenant_name=sender.name, token=token, expires_at=expires_at)
        return _Plan([self._to_member(email, sender, user.email, message.tenant_id)], target)

    async def _enrol(self, message: OutboxMessage, pool: UserPool, *, reset: bool) -> Done:
        """An invitation or a sign-in reset, with the pool: the pool user before the email names its
        password, then the email and the identity, recorded together; or, for an address another
        tenant's member signs in with, the address-in-use email and nothing in the pool.

        - **A reset superseded** by a newer one (its `reset_id` is no longer the user's
          `sign_in_reset_id`) does nothing: the newer message sends the invitation.
        - **Idempotent per message.** The pool user carries the enrolment it was made for (the
          reset's ID, or `invitation`). A redelivery finds it and gives it a new temporary
          password; a reset deletes only a user made for another enrolment, so a redelivery never
          deletes the user it made. The identity replaces the user's earlier one on the pool.
        - **The tenant's log can't tell** an address in use from an invitation (authn and authz
          2.5, NFR-12): both record `email.sent` as `member_invitation`; the conflict goes to the
          platform audit log only.
        """
        address_in_use = False

        async def prepare(session: AsyncSession, message: OutboxMessage) -> _Plan:
            user = await users.get_user(session, _id(message, "user_id"))
            sender = await tenants.sender(session)
            if user is None or sender is None or not sender.active:
                return _Plan()
            if user.status == UserStatus.DEACTIVATED.value:
                return _Plan()
            if reset:
                enrolment = str(_id(message, "reset_id"))
                if str(user.sign_in_reset_id) != enrolment:
                    return _Plan()  # a newer reset superseded this one: its message invites
            else:
                enrolment = INVITATION_ENROLMENT
                if user.status != UserStatus.INVITED.value:
                    return _Plan()  # they joined meanwhile: nothing to send
                link = await self._sso_invitation(session, message, user, sender)
                if link is not None:
                    return link  # an SSO tenant's member: a link, and no pool user (#273)
            target = Target(users.TARGET, user.id)
            if address_in_use:
                in_use: Email = InvitationAddressInUse(tenant_name=sender.name)
                plan = _Plan(
                    [self._to_member(in_use, sender, user.email, message.tenant_id)], target
                )
                plan.audit_type = EmailType.MEMBER_INVITATION
                user_id, tenant_id = user.id, message.tenant_id

                async def platform_record() -> None:
                    await self._record_address_in_use(tenant_id, user_id, reset=reset)

                plan.before_send = platform_record
                return plan
            connection = await identities.pool_connection(session, pool.provider_name)
            if connection is None or connection.status != "active":
                # Delivered again until the pool's connection is there; then the dead-letter queue.
                raise ValueError("the user pool's connection is missing or inactive")
            password = new_temporary_password()
            email = MemberInvitation(
                tenant_name=sender.name,
                temporary_password=password,
                valid_days=TEMPORARY_PASSWORD_DAYS,
            )
            plan = _Plan([self._to_member(email, sender, user.email, message.tenant_id)], target)
            subject: list[str] = []
            user_id, user_email, connection_id = user.id, user.email, connection.id

            async def pool_user() -> None:
                subject.append(
                    await self._pool_user(
                        pool,
                        tenant_id=message.tenant_id,
                        user_id=user_id,
                        email=user_email,
                        password=password,
                        enrolment=enrolment,
                        reset=reset,
                    )
                )

            async def identity(session: AsyncSession) -> None:
                # In the transaction that records the email and its `email.sent` event.
                await identities.record_identity(
                    session, user_id=user_id, connection_id=connection_id, subject=subject[-1]
                )

            plan.before_send = pool_user
            plan.after = identity
            return plan

        try:
            return await self._with_emails(message, prepare)
        except PoolUserExistsError:
            log.info("invited address signs in for another tenant", extra={"topic": message.topic})
            address_in_use = True
            return await self._with_emails(message, prepare)

    async def _pool_user(
        self,
        pool: UserPool,
        *,
        tenant_id: UUID,
        user_id: UUID,
        email: str,
        password: str,
        enrolment: str,
        reset: bool,
    ) -> str:
        """The member's pool user with `password`, made for `enrolment`; its subject. A reset
        deletes a user made for another enrolment (the old sign-in) first; one made for this
        enrolment is an earlier delivery's, which the pool gives this delivery's password."""
        username = str(user_id)
        if reset:
            existing = await pool.find_user(username=username)
            if existing is not None and existing.enrolment != enrolment:
                await pool.delete_user(username=username)
        return await pool.create_user(
            username=username,
            email=email,
            tenant_id=tenant_id,
            temporary_password=password,
            enrolment=enrolment,
        )

    async def _record_address_in_use(self, tenant_id: UUID, user_id: UUID, *, reset: bool) -> None:
        """The conflict, in the platform audit log only (authn and authz 2.5): the tenant's log
        records an invitation email like any other."""
        async with self.database.transaction(Scope.platform()) as session:
            await audit.record(
                session,
                action="invitation.address_in_use",
                actor=SYSTEM,
                target=Target(users.TARGET, user_id),
                details=_details(tenant_id=tenant_id, sign_in_reset=reset),
            )

    # ---- an operator's admin recovery (#273) ----

    async def _admin_recovered(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        """`tenant_admin_recovered` to every active admin of the tenant, the recovered one
        included (authn and authz 2.5): which admin, when, and the kind. Each email is recorded
        on its own, so a redelivery after a failure midway sends only the ones not sent yet."""
        recovery_id = _id(message, "admin_recovery_id")
        recovery = await admin_recoveries.get_recovery(session, recovery_id)
        sender = await tenants.sender(session)
        if recovery is None or sender is None or not sender.active:
            return _Plan()
        admin = await users.get_user(session, recovery.user_id)
        if admin is None:  # pragma: no cover - a recovery names a user of its tenant
            return _Plan()
        email = TenantAdminRecovered(
            tenant_name=sender.name,
            admin_email=admin.email,
            recovered_at=recovery.created_at,
            temporary_until=recovery.temporary_sign_in_expires_at,
        )
        admins = await users.list_users(
            session, role=Role.ADMIN, status=UserStatus.ACTIVE, limit=users.MAX_PAGE
        )
        return _Plan(
            [self._to_member(email, sender, a.email, message.tenant_id) for a in admins],
            Target(ADMIN_RECOVERY_TARGET, recovery_id),
            per_email=True,
        )

    async def _temporary_sign_in_ended(self, message: OutboxMessage) -> Done:
        """The daily job ended a temporary local sign-in (authn and authz 2.5): delete the
        admin's pool user, outside any transaction, then record the message. Only while the
        recovery's reset is still the admin's latest and the pool user was made for it (its
        enrolment): after a newer reset, the pool user is that reset's, the admin's sign-in now,
        and the newer reset's own message replaces the old one anyway. Without a pool: recorded."""
        scope = Scope.tenant(message.tenant_id)
        message_id = str(message.id)
        recovery_id = _id(message, "admin_recovery_id")
        async with self.database.transaction(scope) as session:
            if await recorded_before(session, consumer=CONSUMER, message_id=message_id):
                return Done.DUPLICATE
            recovery = await admin_recoveries.get_recovery(session, recovery_id)
            admin = None if recovery is None else await users.get_user(session, recovery.user_id)
        if (
            self.pool is not None
            and recovery is not None
            and admin is not None
            and admin.sign_in_reset_id == recovery.sign_in_reset_id
        ):
            username = str(recovery.user_id)
            existing = await self.pool.find_user(username=username)
            if existing is not None and existing.enrolment == str(recovery.sign_in_reset_id):
                await self.pool.delete_user(username=username)
                log.info("temporary sign-in's pool user deleted", extra={"outbox_id": message_id})
        async with self.database.transaction(scope) as session:
            if not await record_processed(session, consumer=CONSUMER, message_id=message_id):
                return Done.DUPLICATE
        return Done.PROCESSED

    async def _owner_and_admins(self, session: AsyncSession, owner_id: UUID) -> list[str]:
        addresses: dict[str, str] = {}
        owner = await users.get_user(session, owner_id)
        if owner is not None and owner.status == UserStatus.ACTIVE.value:
            addresses[owner.email_normalized] = owner.email
        admins = await users.list_users(
            session, role=Role.ADMIN, status=UserStatus.ACTIVE, limit=users.MAX_PAGE
        )
        for admin in admins:
            addresses.setdefault(admin.email_normalized, admin.email)
        return list(addresses.values())

    def _to_member(
        self, email: Email, sender: tenants.Sender, address: str, tenant_id: UUID
    ) -> tuple[Email, OutgoingEmail]:
        return email, self.renderer.compose(
            email, Locale(sender.default_locale), to=address, tenant_id=tenant_id
        )


def _both(
    first: Callable[[AsyncSession], Awaitable[None]],
    then: Callable[[AsyncSession], Awaitable[None]] | None,
) -> Callable[[AsyncSession], Awaitable[None]]:
    async def run(session: AsyncSession) -> None:
        await first(session)
        if then is not None:
            await then(session)

    return run


def _id(message: OutboxMessage, key: str) -> UUID:
    value = message.payload.get(key)
    if not isinstance(value, UUID):
        raise ValueError(f"a {message.topic} message names one {key}")
    return value


async def invite_backlog(database: Database, *, provider_name: str) -> int:
    """Invite, through the pool named `provider_name`, every member left `invited` before it
    existed (#193): a new `member.invited` message each, which the notifier handles as any new
    invitation. Run once, when the environment's pool first exists (`python -m
    sft.workers.notify invite-backlog`). A user who already has an identity on the pool was
    invited through it and is skipped; one whose invitation is still in the queue may get a
    second email, whose password replaces the first's. How many it invited."""
    invited, after = 0, None
    while True:
        async with database.transaction(Scope.system()) as session:
            page = await users.invited_everywhere(session, after=after)
        if not page:
            return invited
        for tenant_id, user_id in page:
            async with database.transaction(Scope.tenant(tenant_id)) as session:
                connection = await identities.pool_connection(session, provider_name)
                if connection is None or connection.status != "active":
                    raise ValueError("the user pool's connection is missing or inactive")
                if await identities.has_identity(
                    session, user_id=user_id, connection_id=connection.id
                ):
                    continue
                await users.invite_again(session, user_id)
                invited += 1
        after = page[-1][1]
