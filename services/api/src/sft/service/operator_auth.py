"""Operator authentication: a signed STS request in, a 15-minute operator token out.

Authentication and authorization 8.2.

The operator CLI signs an STS `GetCallerIdentity` request with the operator's IAM Identity Center
credentials, including a signed `X-SFT-Audience: operator-api-<env>` header, and sends the signed
request, never the credentials. `exchange_token` then:

1. accepts only a `GetCallerIdentity` request signed for STS in this Region, whose signed headers
   include this environment's audience;
2. refuses a signature older than 1 minute (or more than 1 minute ahead), or one seen before: the
   signature's SHA-256 is unique in `operator_sessions`;
3. sends the request itself, through `Sts`, to the regional STS endpoint in its configuration,
   never to a host taken from the request;
4. checks STS's answer: the account must be this environment's, and the assumed role exactly this
   account's `Operator` permission set role. Any other account or role, `BreakGlass` included, is
   refused;
5. issues an operator token, 256 random bits, stored only as its SHA-256 with the account and the
   operator's Identity Center user name (the role session name).

Every refusal is the same `401 credentials_invalid`, so the answer never says which check failed;
the platform audit event records why. `authenticate` turns a token back into the operator.

AWS is behind `Sts`, a seam with one method: the operator API's adapter sends the request over
HTTPS (`sft.api.operator.sts`), and tests use a fake.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

from sft.core.errors import ServiceUnavailable, Unauthenticated
from sft.data import audit
from sft.data.audit import Actor, ActorType, OperatorName, Origin, Outcome, Target
from sft.data.database import Database
from sft.data.operator_sessions import (
    create_operator_session,
    find_operator_session,
    signature_seen,
)
from sft.data.scope import Scope
from sft.service.caller import Caller, CallerKind
from sft.service.rate_limits.limits import KeyType, KeyValue

TOKEN_TTL: Final = timedelta(minutes=15)
MAX_SIGNATURE_AGE: Final = timedelta(minutes=1)
GET_CALLER_IDENTITY: Final = "Action=GetCallerIdentity&Version=2011-06-15"
AUDIENCE_HEADER: Final = "x-sft-audience"

_AUTHORIZATION = re.compile(
    r"AWS4-HMAC-SHA256 Credential=(?P<key>[A-Z0-9]{16,128})/(?P<date>[0-9]{8})/"
    r"(?P<region>[a-z0-9-]{1,32})/(?P<service>[a-z0-9-]{1,32})/aws4_request,\s?"
    r"SignedHeaders=(?P<signed>[a-z0-9-]+(?:;[a-z0-9-]+)*),\s?Signature=(?P<signature>[0-9a-f]{64})"
)
_HEADER_VALUE = re.compile(r"[\x20-\x7e]*")
_AMZ_DATE = "%Y%m%dT%H%M%SZ"
# Headers the CLI may send that STS needs; everything else is dropped, never forwarded.
_FORWARDED = frozenset(
    {"authorization", "x-amz-date", "x-amz-security-token", AUDIENCE_HEADER, "content-type"}
)


class Refusal(StrEnum):
    """Why a token exchange was refused, for the audit event only; the caller sees 401."""

    MALFORMED = "malformed"
    WRONG_REGION = "wrong_region"
    WRONG_SERVICE = "wrong_service"
    AUDIENCE = "audience"
    STALE = "stale"
    REPLAYED = "replayed"
    STS_REFUSED = "sts_refused"
    WRONG_ACCOUNT = "wrong_account"
    WRONG_ROLE = "wrong_role"


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """STS's answer to `GetCallerIdentity`."""

    account: str
    arn: str


class StsRefusedError(Exception):
    """STS refused the request: a bad or expired signature, or credentials it doesn't accept."""


class StsUnavailableError(Exception):
    """STS couldn't be reached, or failed on its side. Nothing was decided."""


class Sts(Protocol):
    """Sends a signed `GetCallerIdentity` request to the configured STS endpoint."""

    async def get_caller_identity(self, headers: Mapping[str, str], body: str) -> CallerIdentity:
        """STS's answer; `StsRefusedError` for a 4xx, `StsUnavailableError` otherwise."""
        ...


@dataclass(frozen=True, slots=True)
class OperatorPolicy:
    """Who may get an operator token here, from configuration that Terraform writes."""

    region: str
    audience: str
    account_id: str
    role_name: str


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    session_id: UUID
    expires_at: datetime
    aws_account_id: str
    operator_name: str


@dataclass(frozen=True, slots=True)
class Operator:
    """The operator behind a request: their session and their Identity Center user name."""

    session_id: UUID
    name: OperatorName

    @property
    def caller(self) -> Caller:
        """The request's `Caller`, which `authorize` checks against the permission registry."""
        return Caller(CallerKind.OPERATOR, credential_id=self.session_id)

    @property
    def actor(self) -> Actor:
        """The audit actor: the operator session (`Caller.actor`)."""
        return self.caller.actor()

    def rate_limit_keys(self) -> Mapping[KeyType, KeyValue]:
        """What the operator's limits count per (abuse and rate limits 2.1): the operator.

        The operator's name, not their session, as `Caller` would count: a token lasts 15
        minutes, so a new one must not start a fresh count. Base32, because a key value takes
        neither `@` nor `+`, which a role session name may hold.
        """
        return {KeyType.OPERATOR: base64.b32encode(self.name.encode()).decode()}

    def details(self) -> dict[str, audit.Detail]:
        """What every operator audit event carries besides the actor (authn-authz 8.2)."""
        return {"operator_name": self.name}


class _RefusedError(Exception):
    def __init__(self, reason: Refusal) -> None:
        super().__init__(reason.value)
        self.reason = reason


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _signed_request(
    headers: Mapping[str, str], body: str, policy: OperatorPolicy, now: datetime
) -> tuple[dict[str, str], bytes]:
    """The headers to forward and the signature's hash, or `_RefusedError` (steps 1 and 2)."""
    if body != GET_CALLER_IDENTITY:
        raise _RefusedError(Refusal.MALFORMED)
    lowered: dict[str, str] = {}
    for name, value in headers.items():
        key = name.lower()
        # Visible ASCII and spaces only: anything else can't be a header STS signed.
        if key in lowered or not _HEADER_VALUE.fullmatch(value):
            raise _RefusedError(Refusal.MALFORMED)
        lowered[key] = value
    match = _AUTHORIZATION.fullmatch(lowered.get("authorization", ""))
    if match is None:
        raise _RefusedError(Refusal.MALFORMED)
    if match["region"] != policy.region:
        raise _RefusedError(Refusal.WRONG_REGION)
    if match["service"] != "sts":
        raise _RefusedError(Refusal.WRONG_SERVICE)
    signed = match["signed"].split(";")
    if AUDIENCE_HEADER not in signed or lowered.get(AUDIENCE_HEADER) != policy.audience:
        raise _RefusedError(Refusal.AUDIENCE)
    if "host" not in signed or "x-amz-date" not in signed:
        raise _RefusedError(Refusal.MALFORMED)
    # Every signed header must be one we forward; the host is the configured endpoint's.
    if any(name != "host" and (name not in _FORWARDED or name not in lowered) for name in signed):
        raise _RefusedError(Refusal.MALFORMED)
    try:
        signed_at = datetime.strptime(lowered["x-amz-date"], _AMZ_DATE).replace(tzinfo=UTC)
    except ValueError:
        raise _RefusedError(Refusal.MALFORMED) from None
    if match["date"] != lowered["x-amz-date"][:8]:
        raise _RefusedError(Refusal.MALFORMED)
    if abs(now - signed_at) > MAX_SIGNATURE_AGE:
        raise _RefusedError(Refusal.STALE)
    forwarded = {name: value for name, value in lowered.items() if name in _FORWARDED}
    return forwarded, hashlib.sha256(match["signature"].encode()).digest()


def _operator_name(identity: CallerIdentity, policy: OperatorPolicy) -> OperatorName:
    """Step 4: this account, this role, exactly; the role session name is the operator's."""
    if identity.account != policy.account_id:
        raise _RefusedError(Refusal.WRONG_ACCOUNT)
    prefix = f"arn:aws:sts::{policy.account_id}:assumed-role/"
    if not identity.arn.startswith(prefix):
        raise _RefusedError(Refusal.WRONG_ACCOUNT)
    role, _, session_name = identity.arn[len(prefix) :].partition("/")
    if role != policy.role_name:
        raise _RefusedError(Refusal.WRONG_ROLE)
    try:
        return OperatorName(session_name)
    except ValueError:
        raise _RefusedError(Refusal.WRONG_ROLE) from None


async def exchange_token(
    database: Database,
    sts: Sts,
    policy: OperatorPolicy,
    *,
    headers: Mapping[str, str],
    body: str,
    origin: Origin,
    now: datetime | None = None,
) -> IssuedToken:
    """`createOperatorToken`: a token for the operator who signed the request, or 401."""
    now = now or datetime.now(UTC)
    try:
        forwarded, signature_hash = _signed_request(headers, body, policy, now)
        async with database.transaction(Scope.platform()) as session:
            seen = await signature_seen(session, signature_hash)
        if seen:
            raise _RefusedError(Refusal.REPLAYED)
        # No transaction is open across the call to AWS (data model 2.5).
        try:
            identity = await sts.get_caller_identity(forwarded, body)
        except StsRefusedError:
            raise _RefusedError(Refusal.STS_REFUSED) from None
        name = _operator_name(identity, policy)
        token = secrets.token_urlsafe(32)
        expires_at = now + TOKEN_TTL
        async with database.transaction(Scope.platform()) as session:
            session_id = await create_operator_session(
                session,
                token_hash=token_hash(token),
                signature_hash=signature_hash,
                aws_account_id=identity.account,
                operator_name=name,
                expires_at=expires_at,
            )
            if session_id is None:  # the same request, at the same moment
                raise _RefusedError(Refusal.REPLAYED)
            await audit.record(
                session,
                action="operator.token_created",
                actor=Actor(ActorType.OPERATOR, session_id),
                target=Target("operator_session", session_id),
                origin=origin,
                details={"operator_name": name, "expires_at": expires_at},
            )
    except StsUnavailableError:
        raise ServiceUnavailable(retry_after=5, detail="STS can't be reached.") from None
    except _RefusedError as refused:
        await _record_refusal(database, refused.reason, origin)
        raise Unauthenticated("credentials_invalid") from None
    return IssuedToken(token, session_id, expires_at, identity.account, name)


async def _record_refusal(database: Database, reason: Refusal, origin: Origin) -> None:
    # A transaction of its own: nothing else was written. The caller is unknown, so the actor is
    # the system, and the reason is in the details, never in the answer.
    async with database.transaction(Scope.platform()) as session:
        await audit.record(
            session,
            action="operator.token_refused",
            actor=Actor(ActorType.SYSTEM),
            outcome=Outcome.FAILURE,
            origin=origin,
            details={"reason": reason},
        )


async def authenticate(database: Database, token: str | None) -> Operator:
    """The operator whose token this is, or `401` with the bearer challenge."""
    if not token:
        raise Unauthenticated("authentication_required", bearer=True)
    async with database.transaction(Scope.platform()) as session:
        found = await find_operator_session(session, token_hash(token))
    if found is None:
        raise Unauthenticated("credentials_invalid", bearer=True)
    return Operator(found.id, OperatorName(found.operator_name))
