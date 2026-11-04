"""The application's rate limits as data: the tables of the abuse design, section 2.2.

Each `Limit` is one row: its group, the key it counts per, and its rule. A `Rate` counts requests
with GCRA; a `Quota` keeps a sliding log of events, for small counts (abuse design 4.4). A quota of
`failures` isn't counted per request: a request is refused while the log is full, and the code that
sees the failure records it (`RateLimiter.record`).

The bundles at the end are what one operation applies, narrowest first (abuse design 2.4, 4.4): the
caller's own keys, then IP, then the invited address, then the tenant. A route names its bundle in
one line (`sft.api.rate_limits`). Every number is a starting value, changed only through deploy
config, for every tenant at once.

This page carries the limits of the routes that exist now or arrive in M1 (groups B, G for
`inviteUser`, H and J), and group A, whose per-link and per-address keys and fail-closed mode the
limiter is built around. Groups C to F, I and K join with their routes. Concurrent streams (leases)
and byte budgets are other algorithms and come with the download and upload issues.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, StrEnum

from sft.core.pseudonyms import EmailPseudonyms

MAX_TTL_SECONDS = 25 * 3600
"""No key may live longer (abuse design 4.2)."""


class FailureMode(Enum):
    """What a limit does while the counter store is unavailable (abuse design 4.5)."""

    CLOSED = "closed"
    """Refuse with `503 service_unavailable`, `Retry-After: 5`."""
    LOCAL = "local"
    """Count in this pod instead, at a third of the limit (3 is the minimum pod count)."""


class Group(StrEnum):
    LINK_STEPS = "A"
    SIGN_IN = "B"
    LINK_SESSION = "C"
    DOWNLOAD_GRANTS = "D"
    DOWNLOAD_CONTENT = "E"
    UPLOADS = "F"
    EMAIL = "G"
    TENANT_API = "H"
    AUDIT = "I"
    ADMINISTRATION = "J"
    DLP = "K"

    @property
    def failure_mode(self) -> FailureMode:
        if self in (Group.LINK_STEPS, Group.SIGN_IN):
            return FailureMode.CLOSED
        return FailureMode.LOCAL


class KeyType(StrEnum):
    """What a limit counts per (abuse design 2.1). Values are IDs, HMACs or IP addresses."""

    IP = "ip"
    ACCOUNT = "account"
    API_KEY = "api_key"
    OPERATOR = "operator"
    TENANT = "tenant"
    EMAIL = "email"
    """An invited address's pseudonym, across tenants."""
    TENANT_EMAIL = "tenant_email"
    """An invited address's pseudonym within one tenant: `EmailPseudonyms.within(tenant_id)`."""
    SUBJECT = "subject"
    """A recipient or upload request with its `link_issued_at`, so a new link starts afresh."""
    LINK_SESSION = "link_session"


KeyValue = str | EmailPseudonyms

_VALUE = re.compile(r"[A-Za-z0-9._:/=-]{1,200}")


@dataclass(frozen=True)
class Rate:
    """At most `limit` requests in any `period_seconds`, with an exact wait (GCRA)."""

    limit: int
    period_seconds: int


@dataclass(frozen=True)
class Quota:
    """At most `limit` events in a sliding `window_seconds`.

    `counts="failures"`: the events are failures, recorded after the fact; a request is refused
    while the window holds `limit` of them. With `block_seconds`, reaching the limit also blocks
    the key for that long.
    """

    limit: int
    window_seconds: int
    counts: str = "requests"
    block_seconds: int = 0


@dataclass(frozen=True)
class Limit:
    group: Group
    name: str
    keys: tuple[KeyType, ...]
    """The key it counts per; with several, the first the caller has (a member or an API key)."""
    rule: Rate | Quota

    @property
    def id(self) -> str:
        return f"{self.group.value}.{self.name}"

    @property
    def counts_failures(self) -> bool:
        return isinstance(self.rule, Quota) and self.rule.counts == "failures"

    def key_type(self, values: Mapping[KeyType, KeyValue]) -> KeyType:
        for key_type in self.keys:
            if key_type in values:
                return key_type
        raise LookupError(f"limit {self.id} needs one of {[k.value for k in self.keys]}")

    def store_key(self, key_type: KeyType, value: str) -> str:
        """`rl:{group}.{name}:{key type}:{value}` (abuse design 4.4).

        No braces, so no hash tag: each script touches one key, which cluster mode allows.
        """
        if not _VALUE.fullmatch(value):
            raise ValueError(f"limit {self.id}: a key value is an ID, an HMAC or an IP address")
        return f"rl:{self.id}:{key_type.value}:{value}"


def _limit(
    group: Group, name: str, key: KeyType | tuple[KeyType, ...], rule: Rate | Quota
) -> Limit:
    return Limit(group, name, key if isinstance(key, tuple) else (key,), rule)


MINUTE, HOUR, DAY = 60, 3600, 86400
CALLER = (KeyType.ACCOUNT, KeyType.API_KEY)

# ---- A. Link steps: resolveLink, requestVerificationCode, createLinkSession. Fail closed. ----
A_IP = _limit(Group.LINK_STEPS, "ip_requests", KeyType.IP, Rate(60, MINUTE))  # NFR-14
A_NOT_FOUND = _limit(Group.LINK_STEPS, "not_found", KeyType.IP, Quota(20, HOUR, "failures"))
A_FAILED_CODES = _limit(Group.LINK_STEPS, "failed_codes", KeyType.IP, Quota(30, HOUR, "failures"))
A_SUBJECT_GAP = _limit(Group.LINK_STEPS, "link_code_gap", KeyType.SUBJECT, Rate(1, 30))
A_SUBJECT_DAY = _limit(Group.LINK_STEPS, "link_codes_day", KeyType.SUBJECT, Quota(20, DAY))
A_EMAIL_HOUR = _limit(
    Group.LINK_STEPS, "address_codes_hour", KeyType.EMAIL, Quota(5, HOUR)
)  # NFR-14
A_EMAIL_DAY = _limit(Group.LINK_STEPS, "address_codes_day", KeyType.EMAIL, Quota(50, DAY))
A_TENANT = _limit(Group.LINK_STEPS, "tenant_codes", KeyType.TENANT, Rate(1000, HOUR))

# ---- B. Member sign-in: the API's side; Cognito's trigger counts failures per account. ----
B_START = _limit(Group.SIGN_IN, "start_ip", KeyType.IP, Rate(60, MINUTE))
B_CALLBACK = _limit(Group.SIGN_IN, "callback_ip", KeyType.IP, Rate(60, MINUTE))
B_INVITATION = _limit(Group.SIGN_IN, "invitation_ip", KeyType.IP, Rate(60, MINUTE))

# ---- G. Actions that send email. Recipient emails take a cost: one per address. ----
G_CALLER_EMAILS = _limit(Group.EMAIL, "caller_emails", CALLER, Rate(200, HOUR))
G_TENANT_EMAILS = _limit(Group.EMAIL, "tenant_emails", KeyType.TENANT, Rate(2000, HOUR))
G_ADDRESS_EMAILS = _limit(Group.EMAIL, "address_link_emails", KeyType.TENANT_EMAIL, Quota(20, DAY))
G_INVITES = _limit(Group.EMAIL, "tenant_invites", KeyType.TENANT, Rate(100, HOUR))
G_ADDRESS_INVITES = _limit(Group.EMAIL, "address_invites", KeyType.TENANT_EMAIL, Quota(3, DAY))

# ---- H. Tenant API: every other operation of members and API keys. ----
H_CALLER = _limit(Group.TENANT_API, "caller_requests", CALLER, Rate(300, MINUTE))
H_TENANT = _limit(Group.TENANT_API, "tenant_requests", KeyType.TENANT, Rate(1000, MINUTE))  # NFR-14
H_FAILED_AUTH = _limit(
    Group.TENANT_API, "failed_auth", KeyType.IP, Quota(100, 5 * MINUTE, "failures", 15 * MINUTE)
)

# ---- J. Key and tenant administration. ----
J_API_KEYS = _limit(Group.ADMINISTRATION, "api_keys", KeyType.TENANT, Quota(20, DAY))
J_TENANTS = _limit(Group.ADMINISTRATION, "tenants", KeyType.OPERATOR, Quota(30, HOUR))

ALL = (
    *(A_IP, A_NOT_FOUND, A_FAILED_CODES, A_SUBJECT_GAP, A_SUBJECT_DAY),
    *(A_EMAIL_HOUR, A_EMAIL_DAY, A_TENANT),
    *(B_START, B_CALLBACK, B_INVITATION),
    *(G_CALLER_EMAILS, G_TENANT_EMAILS, G_ADDRESS_EMAILS, G_INVITES, G_ADDRESS_INVITES),
    *(H_CALLER, H_TENANT, H_FAILED_AUTH),
    *(J_API_KEYS, J_TENANTS),
)
"""Every limit above, for the tests that check the whole table."""

# ---- What each operation applies, narrowest first. ----

LINK_STEP = (A_IP, A_NOT_FOUND, A_FAILED_CODES)
"""Before the token lookup, so a `429` reveals nothing about a token (abuse design 2.4)."""
REQUEST_CODE = (A_SUBJECT_GAP, A_SUBJECT_DAY, A_EMAIL_HOUR, A_EMAIL_DAY, A_TENANT)
"""`requestVerificationCode`, after the token lookup and the lockout. The probe mailbox's
addresses on the synthetic tenant's links leave out the two per-address limits (NFR-1)."""

SIGN_IN_START = (B_START,)
SIGN_IN_CALLBACK = (B_CALLBACK,)
INVITATION_SIGN_IN = (B_INVITATION,)

TENANT_OPERATION = (H_CALLER, H_FAILED_AUTH, H_TENANT)
"""Every member and API key operation, `GET /me` and sign-out included."""
SAFETY_ACTION = (H_CALLER, H_FAILED_AUTH)
"""`revokeTransfer`, `revokeUploadRequest`, `revokeApiKey`, `deactivateUser`, `unlockRecipient`,
`unlockUploader`, `rejectTransfer`: never counted against, nor refused by, the tenant's budget."""

INVITE_USER = (G_CALLER_EMAILS, G_ADDRESS_INVITES, G_INVITES)
"""`inviteUser`, after `TENANT_OPERATION`, once the address is known."""
CREATE_TENANT = (J_TENANTS,)
"""`createTenant`, on the operator API."""
CREATE_API_KEY = (J_API_KEYS,)
"""`createApiKey`, after `TENANT_OPERATION`."""
