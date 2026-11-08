"""SES's events, as the notification worker reads them from the `ses-events` queue (#185;
ADR-0015; abuse and rate limits 7.3, 7.4; data model 2.5).

Each region's configuration set publishes bounce, complaint, delivery, reject and delivery-delay
events through its SNS topic to the queue (infra/modules/ses). A queue message is SNS's envelope,
whose `Message` is SES's event; an envelope-less body (raw delivery) is read too. Every send
carries the tags `tenant_id` and `email_type`, and a link email `recipient_id`
(`sft.data.mail.OutgoingEmail.all_tags`), so each event is handled in its own tenant's scope.

- **A permanent bounce** suppresses the address for the sending tenant: for 90 days the first
  time; with no expiry when an ended entry shows it bounced before. A live entry stays as it is,
  so a complaint is never weakened to a bounce. A link email's recipient becomes `bounced` (FR-7).
- **A complaint** suppresses the address for the tenant until a tenant admin clears it.
- **A reject** (SES refused the email after accepting it) leaves a link email's recipient
  `bounced`.
- **Everything else** (deliveries, delays, transient bounces) and any event without our tenant
  tag, such as one of Cognito's own emails (ADR-0016), changes nothing: the consumer deletes it.

Each change writes its audit event in the same transaction (`audit_required`). An event's ID for
`processed_messages` is derived from SES's message ID, the event type and the event's time, so a
copy SNS or SQS delivers twice is handled once. Addresses are kept only long enough to make their
pseudonyms: never logged, never stored.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, recipients, suppressions, users
from sft.data.audit import Actor, Target
from sft.data.models import ActorType, DeliveryState, SuppressionReason
from sft.data.models import Outcome as AuditOutcome
from sft.data.outbox import InvalidMessageError, OutboxMessage
from sft.service.email.catalog import EmailType

CONSUMER: Final = "ses-events"
"""The consumer's name in `processed_messages`. Never change it."""
BOUNCE_SUPPRESSION: Final = timedelta(days=90)
"""How long a first hard bounce suppresses the address for its tenant (abuse 7.4)."""
_NAMESPACE: Final = uuid.UUID("5b0c3c4e-7a51-4f43-9f0e-3d4b5e6f7a81")
"""Fixed: the namespace of every event's derived ID. Never change it."""

SYSTEM: Final = Actor(ActorType.SYSTEM)


class EventKind(StrEnum):
    BOUNCE = "bounce"
    COMPLAINT = "complaint"
    REJECT = "reject"


_KINDS: Final = {"Bounce": EventKind.BOUNCE, "Complaint": EventKind.COMPLAINT}
_KINDS_REJECT: Final = {"Reject": EventKind.REJECT}


@dataclass(frozen=True, slots=True)
class SesEvent:
    """One SES event we act on: its kind, its tenant, and the addresses it names."""

    id: UUID
    kind: EventKind
    tenant_id: UUID
    email_type: EmailType | None
    recipient_id: UUID | None
    addresses: tuple[str, ...]

    def as_message(self) -> OutboxMessage:
        """The envelope the consumer framework records and scopes by (`sft.workers.consumer`)."""
        payload = {} if self.recipient_id is None else {"recipient_id": self.recipient_id}
        return OutboxMessage(
            id=self.id, topic=f"ses.{self.kind}", tenant_id=self.tenant_id, payload=payload
        )


def _tag(tags: Any, name: str) -> str | None:
    values = tags.get(name) if isinstance(tags, dict) else None
    if isinstance(values, list) and values and isinstance(values[0], str):
        return values[0]
    return None


def _uuid(value: str | None) -> UUID | None:
    try:
        return None if value is None else UUID(value)
    except ValueError:
        return None


def _addresses(part: Any, key: str) -> tuple[str, ...]:
    listed = part.get(key) if isinstance(part, dict) else None
    if not isinstance(listed, list):
        return ()
    found = (r.get("emailAddress") for r in listed if isinstance(r, dict))
    return tuple(a for a in found if isinstance(a, str) and "@" in a)


def parse_event(body: str) -> SesEvent | None:
    """The event in a queue message, or None for one we take no action on.

    Raises `InvalidMessageError` for a body that isn't an SES event at all; it then goes to the
    dead-letter queue, which alerts."""
    try:
        raw = json.loads(body)
        if isinstance(raw, dict) and raw.get("Type") == "Notification":
            raw = json.loads(raw.get("Message", ""))
    except (ValueError, TypeError, RecursionError) as exc:
        raise InvalidMessageError("not an SES event") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("mail"), dict):
        raise InvalidMessageError("not an SES event")
    event_type, mail = raw.get("eventType") or raw.get("notificationType"), raw["mail"]
    kind = {**_KINDS, **_KINDS_REJECT}.get(str(event_type))
    tenant_id = _uuid(_tag(mail.get("tags"), "tenant_id"))
    if kind is None or tenant_id is None:
        return None  # nothing to act on, or not one of our sends (Cognito's own email)
    if kind is EventKind.BOUNCE:
        bounce = raw.get("bounce")
        if not isinstance(bounce, dict) or bounce.get("bounceType") != "Permanent":
            return None  # transient and undetermined bounces suppress nothing
        addresses, at = _addresses(bounce, "bouncedRecipients"), bounce.get("timestamp")
    elif kind is EventKind.COMPLAINT:
        complaint = raw.get("complaint")
        addresses = _addresses(complaint, "complainedRecipients")
        at = complaint.get("timestamp") if isinstance(complaint, dict) else None
    else:
        addresses, at = (), mail.get("timestamp")
    email_type = _tag(mail.get("tags"), "email_type")
    message_id = mail.get("messageId")
    if not isinstance(message_id, str) or not message_id:
        raise InvalidMessageError("the event names no SES message")
    return SesEvent(
        id=uuid.uuid5(_NAMESPACE, f"{tenant_id}/{message_id}/{kind}/{at}"),
        kind=kind,
        tenant_id=tenant_id,
        email_type=EmailType(email_type) if email_type in set(EmailType) else None,
        recipient_id=_uuid(_tag(mail.get("tags"), "recipient_id")),
        addresses=addresses,
    )


class SesEvents:
    """What one event changes, in its tenant's scope and the consumer's transaction."""

    def __init__(self, emails: EmailKeyring) -> None:
        self.emails = emails

    async def handle(self, session: AsyncSession, event: SesEvent) -> None:
        for address in event.addresses:
            await self._suppress(session, event, users.normalize_email(address))
        if event.recipient_id is not None and event.kind in (EventKind.BOUNCE, EventKind.REJECT):
            await recipients.set_delivery(session, event.recipient_id, DeliveryState.BOUNCED)
            await audit.record(
                session,
                action="email.bounced",
                actor=SYSTEM,
                target=Target("recipient", event.recipient_id),
                outcome=AuditOutcome.FAILURE,
                details={"email_type": event.email_type, "event": event.kind},
            )

    async def _suppress(self, session: AsyncSession, event: SesEvent, normalized: str) -> None:
        pseudonym, key_id = self.emails.active(normalized), self.emails.active_key_id
        # The active key's entry first, so an older one is re-keyed only when there is none.
        entry = await suppressions.find_entry(session, [pseudonym])
        if entry is None:
            entry = await suppressions.find_entry(session, self.emails.every_version(normalized))
        now = datetime.now(UTC)
        live = entry is not None and (entry.expires_at is None or entry.expires_at > now)
        if event.kind is EventKind.COMPLAINT:
            reason, expires_at = SuppressionReason.COMPLAINT, None
            if live and entry is not None and entry.reason == SuppressionReason.COMPLAINT:
                return  # suppressed for good already
        else:
            if live:
                return  # a bounce of an email sent before the entry: it already suppresses
            reason = SuppressionReason.HARD_BOUNCE
            # An ended entry is the marker of an earlier bounce: the second one is for good.
            expires_at = None if entry is not None else now + BOUNCE_SUPPRESSION
        if entry is not None and entry.email_hmac != pseudonym:
            await suppressions.rekey(session, entry.id, pseudonym=pseudonym, key_id=key_id)
        entry_id = await suppressions.add_suppression(
            session, pseudonym=pseudonym, key_id=key_id, reason=reason, expires_at=expires_at
        )
        await audit.record(
            session,
            action="email.suppressed",
            actor=SYSTEM,
            target=Target(suppressions.TARGET, entry_id),
            details={
                "reason": reason,
                "email_type": event.email_type,
                "expires_at": expires_at,
            },
        )
