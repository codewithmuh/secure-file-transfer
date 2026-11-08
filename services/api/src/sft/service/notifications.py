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
- `member.invited`: with a user pool (`sft.service.user_pool`; Keycloak locally, #197), the
  member's pool user with a temporary password, its identity, then `member_invitation` with that
  password; an address that already signs in locally for another tenant gets
  `invitation_address_in_use` instead and no pool user. Cognito's admin API in AWS (#193),
  Keycloak's locally. Without a pool: recorded, and nothing sent; `invite_backlog` invites those
  members once the pool exists.
- `member.sign_in_reset`: the same, after deleting the member's pool user: a new user, a new
  identity, a new invitation (authn and authz 2.5). The API already ended the sessions and deleted
  the old identities.

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

**A pool user before its email.** The pool user and its identity are made after the first
transaction and before the send (`_Plan.before_send`), so the email names a password the pool
holds. A redelivery makes a new password: it finds the user an earlier delivery created (by its
username, our user ID) and gives it the new one; the identity is recorded once. The password goes
only into the pool and the email, never into the outbox, a log or an audit row.

**Notices to members** go out in the tenant's default language (FR-33); users have no language of
their own yet. A suspended tenant's messages are recorded and send nothing.

Every email sent is audited (`email.sent`, with its type), and counted in
`emails_sent_total{type}`; every email held by a cap in `email_caps_hit_total{cap}`.
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

from prometheus_client import CollectorRegistry, Counter
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import RateLimited
from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.ids import uuid7
from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, codes, identities, recipients, suppressions, tenants, transfers, users
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail
from sft.data.models import ActorType, DeliveryState, Role, TransferState, UserStatus
from sft.data.models import Outcome as AuditOutcome
from sft.data.outbox import (
    MAX_DELAY,
    MEMBER_INVITED,
    MEMBER_SIGN_IN_RESET,
    RECIPIENT_CODE_REQUESTED,
    RECIPIENT_LINK_DUE,
    RECIPIENT_LOCKED,
    TRANSFER_HELD,
    TRANSFER_RETURNED_TO_DRAFT,
    TRANSFER_SENT,
    OutboxMessage,
    enqueue,
)
from sft.data.processed import record_processed, recorded_before
from sft.data.scope import Scope
from sft.service.email import EmailRenderer
from sft.service.email.catalog import (
    Email,
    EmailType,
    InvitationAddressInUse,
    Locale,
    MemberInvitation,
    RecipientLocked,
    TransferHeld,
    TransferLink,
    TransferReturnedToDraft,
    VerificationCode,
)
from sft.service.rate_limits import Charge
from sft.service.rate_limits.limits import CROSS_TENANT_LINK_EMAILS, KeyType
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

SYSTEM: Final = Actor(ActorType.SYSTEM)


class SystemActor(StrEnum):
    NOTIFICATION_WORKER = "notification_worker"


class Done(StrEnum):
    """What handling one message did."""

    PROCESSED = "processed"
    DUPLICATE = "duplicate"


class Limiter(Protocol):
    """What the worker needs of `sft.service.rate_limits.RateLimiter`."""

    async def peek_all(self, charges: Sequence[Charge]) -> None: ...

    async def check_all(self, charges: Sequence[Charge]) -> None: ...


Send = Callable[[OutgoingEmail], Awaitable[str]]
"""Hands one email to the provider (a `Mailer` in the worker's thread pool); its message ID."""


@dataclass(frozen=True)
class NotifyMetrics:
    emails: Counter
    caps: Counter

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
        return cls(emails, caps)


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
            # Without a pool there is no user to create again: recorded, as an invitation is.
            return await self._with_emails(message, self._invited)
        prepare = {
            RECIPIENT_LINK_DUE.name: self._link,
            RECIPIENT_CODE_REQUESTED.name: self._code,
            RECIPIENT_LOCKED.name: self._locked,
            TRANSFER_HELD.name: self._held,
            TRANSFER_RETURNED_TO_DRAFT.name: self._returned_to_draft,
            MEMBER_INVITED.name: self._invited,
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
        if target is None or target.transfer_state != TransferState.SENT.value:
            return None
        if target.expires_at is not None and target.expires_at <= self.clock():
            return None
        if target.locked_at is not None:
            return None
        return target

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

        return _Plan([(email, outgoing)], subject, delivered, bounced, charge)

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
            hashed=recipients.token_hash(token),
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
        return _Plan([(email, outgoing)], subject)

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

    # ---- notices to the member ----

    async def _held(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        return await self._notice(session, message, TransferState.HELD, TransferHeld)

    async def _returned_to_draft(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        return await self._notice(session, message, TransferState.DRAFT, TransferReturnedToDraft)

    async def _notice(
        self,
        session: AsyncSession,
        message: OutboxMessage,
        state: TransferState,
        kind: type[TransferHeld] | type[TransferReturnedToDraft],
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

    async def _invited(self, session: AsyncSession, message: OutboxMessage) -> _Plan:
        # No pool here: the user stays `invited`, and nothing is sent (#178). `invite_backlog`
        # invites them once the pool exists (#193).
        log.info("invitation left for the user pool", extra={"outbox_id": str(message.id)})
        return _Plan()

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
