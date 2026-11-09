"""The Cognito sign-in triggers and their audit trail (#238; NFR-14, NFR-15; ADR-0016; authn and
authz 2.4; abuse and rate limits 2.3).

Cognito's own lockout alone allows up to 14 failed passwords in the first 15 minutes, so a
pre-authentication trigger of ours keeps NFR-14's 10. Both triggers run one Lambda function, the
API image with another entry point (`sft.workers.signin_trigger`), in the VPC, reaching only the
counter store and the `signin-events` queue.

**Counting failures.** Cognito tells a trigger nothing about a failed password: the
pre-authentication trigger runs before the check, and the post-authentication trigger only after a
success. So the pre-authentication trigger records every attempt in a sliding log per account,
15 minutes long (`B.account_failures`), and the post-authentication trigger takes the newest entry
out again. What stays in the log is the failed attempts. With 10 of them in the window, the next
attempt, the 11th, is refused. A success takes out only its own attempt: it resets no earlier
failure, which ages out with its window.

**Failing closed.** If the counter store or the queue can't be reached, the trigger raises, and
Cognito refuses the sign-in (architecture section 2). The message Cognito shows names no reason.

**The audit trail** (NFR-15). The triggers send messages in the outbox's envelope, which the
notification worker records in the member's tenant (`SignInEvents`), with the system actor
`signin_trigger` and the member as the target:

- `sign_in.attempted` for every attempt, when it starts;
- `sign_in.refused` (failure) instead, for an attempt the limit refused;
- `sign_in.check`, sent with the attempt and delayed 10 minutes: if the attempt is still in the
  log then, nothing succeeded with it, and the worker records `sign_in.failed`;
- `sign_in.authenticated` for every success.

Every attempt is so in the audit log within seconds, and each failed one marked within about 10
minutes. Attempts for a username that doesn't exist (Cognito calls the trigger for them because the
app client prevents user existence errors) have no tenant: they are counted in the logs only. The
trigger events carry no source IP or user agent; Cognito's user activity log and the sign-in web
ACL's logs hold them for investigations.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data import audit
from sft.data.audit import Actor, Target
from sft.data.counters import CounterMetrics, CounterStore, CounterStoreUnavailableError
from sft.data.models import ActorType
from sft.data.models import Outcome as AuditOutcome
from sft.data.outbox import InvalidMessageError, OutboxMessage
from sft.service.rate_limits.limits import MINUTE, Group, KeyType, Limit, Quota

log = logging.getLogger(__name__)

PRE_AUTHENTICATION: Final = "PreAuthentication_Authentication"
POST_AUTHENTICATION: Final = "PostAuthentication_Authentication"

B_ACCOUNT_FAILURES = Limit(
    Group.SIGN_IN, "account_failures", (KeyType.ACCOUNT,), Quota(10, 15 * MINUTE)
)
"""NFR-14: at most 10 failed sign-ins per account in a sliding 15 minutes (abuse 2.3). The log
holds attempts that no success took out; the 11th attempt meets a full log. Not in `limits.ALL`:
the trigger counts it with its own members, not through the limiter."""

CHECK_DELAY: Final = timedelta(minutes=10)
"""How long an attempt may take to succeed before the worker records it failed (authn-authz 2.4).
Within SQS's 15-minute delay, and inside the log's 15-minute window, so the entry is still there."""
DENIED: Final = "Sign-in isn't possible right now. Try again later."
"""What Cognito shows for any refusal: no reason, so nobody learns of the limit or an outage."""


class Topic(StrEnum):
    """The sign-in events, as the envelope's topic and the audit action."""

    ATTEMPTED = "sign_in.attempted"
    REFUSED = "sign_in.refused"
    CHECK = "sign_in.check"
    AUTHENTICATED = "sign_in.authenticated"


FAILED_ACTION: Final = "sign_in.failed"
USER: Final = "user"


class SystemActor(StrEnum):
    """The named system actor of the sign-in events (authn and authz 6.1)."""

    SIGNIN_TRIGGER = "signin_trigger"


class RefusalReason(StrEnum):
    TOO_MANY_FAILURES = "too_many_failures"


class SignInDenied(Exception):  # noqa: N818 - Cognito shows its message; it isn't an error of ours
    """Raised to Cognito, which refuses the sign-in and shows `DENIED`."""

    def __init__(self) -> None:
        super().__init__(DENIED)


@dataclass(frozen=True, slots=True)
class TriggerEvent:
    """What the triggers read of Cognito's event: which trigger, and whose sign-in."""

    source: str
    user_id: UUID | None
    """The username, which is our user ID (sft.runtime.cognito), or None for an unknown one."""
    tenant_id: UUID | None


def _uuid(value: object) -> UUID | None:
    try:
        return UUID(value) if isinstance(value, str) else None
    except ValueError:
        return None


def parse_trigger(event: Mapping[str, Any]) -> TriggerEvent:
    """Read a Cognito trigger event. Anything unexpected names no member."""
    source = event.get("triggerSource")
    request = event.get("request")
    attributes = request.get("userAttributes") if isinstance(request, dict) else None
    attributes = attributes if isinstance(attributes, dict) else {}
    unknown = isinstance(request, dict) and request.get("userNotFound") is True
    user_id = None if unknown else _uuid(event.get("userName"))
    tenant_id = None if user_id is None else _uuid(attributes.get("custom:tenant_id"))
    return TriggerEvent(str(source), user_id, tenant_id)


def account_key(user_id: UUID) -> str:
    return B_ACCOUNT_FAILURES.store_key(KeyType.ACCOUNT, str(user_id))


Send = Callable[[Sequence[tuple[str, int]]], Awaitable[None]]
"""Sends message bodies, each with its delay in seconds, to the `signin-events` queue; raises if
SQS took any of them not."""


class SignInTriggers:
    """Both triggers' work (module docstring)."""

    def __init__(
        self,
        store: CounterStore,
        metrics: CounterMetrics,
        send: Send,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._metrics = metrics
        self._send = send
        self._clock = clock

    async def handle(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return the event, as Cognito expects, or raise `SignInDenied`."""
        trigger = parse_trigger(event)
        if trigger.source == PRE_AUTHENTICATION:
            await self._pre(trigger)
        elif trigger.source == POST_AUTHENTICATION:
            await self._post(trigger)
        else:
            log.warning("unexpected trigger source", extra={"source": trigger.source[:64]})
            raise SignInDenied
        return event

    async def _pre(self, trigger: TriggerEvent) -> None:
        if trigger.user_id is None or trigger.tenant_id is None:
            log.info("sign-in attempt for no known member")  # Cognito refuses it anyway
            return
        attempt = uuid7()
        rule = B_ACCOUNT_FAILURES.rule
        assert isinstance(rule, Quota)  # noqa: S101 - a constant above
        try:
            verdict = await self._store.log(
                account_key(trigger.user_id),
                now_ms=int(self._clock() * 1000),
                limit=rule.limit,
                window_ms=rule.window_seconds * 1000,
                mode="hit",
                member=str(attempt),
            )
        except CounterStoreUnavailableError:
            log.warning("counter store unavailable: sign-in denied")
            raise SignInDenied from None
        if not verdict.allowed:
            self._metrics.rejections.labels(Group.SIGN_IN.value, KeyType.ACCOUNT.value).inc()
            log.info("rate limited", extra={"limits": [B_ACCOUNT_FAILURES.id]})
            await self._deliver([(self._message(Topic.REFUSED, trigger, attempt), 0)])
            raise SignInDenied
        await self._deliver(
            [
                (self._message(Topic.ATTEMPTED, trigger, attempt), 0),
                (self._message(Topic.CHECK, trigger, attempt), int(CHECK_DELAY.total_seconds())),
            ]
        )

    async def _post(self, trigger: TriggerEvent) -> None:
        if trigger.user_id is None or trigger.tenant_id is None:
            return
        try:
            await self._store.forget_newest(account_key(trigger.user_id))
        except CounterStoreUnavailableError:
            log.warning("counter store unavailable: sign-in denied")
            raise SignInDenied from None
        await self._deliver([(self._message(Topic.AUTHENTICATED, trigger, uuid7()), 0)])

    async def _deliver(self, messages: Sequence[tuple[str, int]]) -> None:
        try:
            await self._send(messages)
        except Exception:
            # No audit record, no sign-in (authn-authz 2.4).
            log.warning("sign-in events queue unavailable: sign-in denied")
            raise SignInDenied from None

    @staticmethod
    def _message(topic: Topic, trigger: TriggerEvent, attempt: UUID) -> str:
        if trigger.user_id is None or trigger.tenant_id is None:  # pragma: no cover - checked
            raise ValueError("a sign-in event names its member and tenant")
        payload = {"user_id": trigger.user_id, "attempt_id": attempt}
        # Each message its own ID; the check's is derived, so a redelivered pair stays one pair.
        message_id = attempt if topic is not Topic.CHECK else uuid.uuid5(attempt, Topic.CHECK.value)
        return OutboxMessage(message_id, topic.value, trigger.tenant_id, payload).body()


# ---- the notification worker's side ----


TOPICS: Final = frozenset(topic.value for topic in Topic)
SYSTEM: Final = Actor(ActorType.SYSTEM)


class SignInEvents:
    """Records one sign-in event in the member's tenant, in the consumer's transaction."""

    def __init__(self, store: CounterStore) -> None:
        self._store = store

    async def handle(self, session: AsyncSession, message: OutboxMessage) -> None:
        user_id, attempt = message.payload.get("user_id"), message.payload.get("attempt_id")
        if not isinstance(user_id, UUID) or not isinstance(attempt, UUID):
            raise ValueError("a sign-in event names its member and attempt")
        topic = Topic(message.topic)
        if topic is Topic.CHECK:
            # Still in the log after 10 minutes: no success took it out. Raises while the
            # store is unavailable, so SQS delivers the check again.
            if not await self._store.holds(account_key(user_id), str(attempt)):
                return
            action, outcome = FAILED_ACTION, AuditOutcome.FAILURE
        elif topic is Topic.REFUSED:
            action, outcome = topic.value, AuditOutcome.FAILURE
        else:
            action, outcome = topic.value, AuditOutcome.SUCCESS
        details: dict[str, audit.Detail] = {
            "system_actor": SystemActor.SIGNIN_TRIGGER,
            "attempt_id": attempt,
        }
        if topic is Topic.REFUSED:
            details["reason"] = RefusalReason.TOO_MANY_FAILURES
        await audit.record(
            session,
            action=action,
            actor=SYSTEM,
            target=Target(USER, user_id),
            outcome=outcome,
            details=details,
        )


def parse_message(body: str) -> OutboxMessage:
    """A sign-in event as the consumer framework records it; anything else is invalid."""
    message = OutboxMessage.from_body(body)
    if message.topic not in TOPICS:
        raise InvalidMessageError("not a sign-in event")
    return message
