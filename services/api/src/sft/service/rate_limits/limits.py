"""The application's rate limits as data: the tables of the abuse design, section 2.2.

Each `Limit` is one row: its group, the key it counts per, and its rule. A `Rate` counts requests
with GCRA; a `Quota` keeps a sliding log of events, for small counts (abuse design 4.4). A quota of
`failures` isn't counted per request: a request is refused while the log is full, and the code that
sees the failure records it (`RateLimiter.record`).

The bundles at the end are what one operation applies, narrowest first (abuse design 2.4, 4.4): the
caller's own keys, then IP, then the invited address, then the tenant. A route names its bundle in
one line (`sft.api.rate_limits`); `EVERY_REQUEST` runs before routing, on every request. Every
number is a starting value, changed only through deploy config, for every tenant at once.

This page carries the limits of the routes that exist now (groups A, B, C, D's request rates, F's
request rates, G for `inviteUser` and `sendTransfer`, H, I and J), and group G's cross-tenant cap on
link emails, which the notification worker applies (#178, abuse 7.2). Group K joins with its
routes. Group D's byte caps and group E's concurrent streams are budgets and leases, not
rates: `sft.service.rate_limits.downloads` (#180). Group F's per-file part-URL count and the
tenant's daily upload volume are a PostgreSQL count and a budget: `sft.service.rate_limits.uploads`
(#165).
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
    """At most `limit` requests in any `period_seconds`, with an exact wait (GCRA).

    A fresh key admits a burst of `limit // 2 + 1` at once, then `(limit + 1) // 2` per period,
    evenly spaced, so no window (t - period, t] holds more than `limit` (`gcra_split` in
    `sft.data.counters`). A `cost` above the burst is never admitted.

    `max_cost` is the largest cost one request may carry, such as a send to 50 recipients. The
    store's burst admits it; the per-pod limit of an outage (4.5) is raised to admit it too, so the
    largest valid request never fails only because the store is down (#129).
    """

    limit: int
    period_seconds: int
    max_cost: int = 1

    def __post_init__(self) -> None:
        if not 1 <= self.max_cost <= self.limit // 2 + 1:
            raise ValueError("max_cost is at least 1 and within the store's burst")


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
class Budget:
    """At most `limit` units in each fixed window of `window_seconds`, aligned to the Unix epoch
    (a UTC day for `DAY`), each request spending its cost, such as a grant's megabytes.

    Charged only with `RateLimiter.check_all`, which spends every budget of the batch or none:
    if any limit refuses, the budgets it charged are refunded in the same call.
    """

    limit: int
    window_seconds: int


@dataclass(frozen=True)
class Limit:
    group: Group
    name: str
    keys: tuple[KeyType, ...]
    """The key it counts per; with several, the first the caller has (a member or an API key)."""
    rule: Rate | Quota | Budget

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

# ---- C. Link session reads: getLinkSession, endLinkSession, listSessionFiles. Fail open. ----
C_SESSION = _limit(Group.LINK_SESSION, "session_requests", KeyType.LINK_SESSION, Rate(120, MINUTE))

# ---- D. Download grants: createSessionDownload. Fail open; the count is PostgreSQL's. ----
# The byte caps (25 GB a recipient, 500 GB a tenant, a day) and group E's concurrent streams are
# budgets and leases, not rates: `sft.service.rate_limits.downloads`.
D_SUBJECT = _limit(Group.DOWNLOAD_GRANTS, "subject_grants", KeyType.SUBJECT, Rate(100, HOUR))
D_IP = _limit(Group.DOWNLOAD_GRANTS, "ip_grants", KeyType.IP, Rate(300, HOUR))
D_TENANT = _limit(Group.DOWNLOAD_GRANTS, "tenant_grants", KeyType.TENANT, Rate(2000, HOUR))
D_ACCOUNT = _limit(Group.DOWNLOAD_GRANTS, "account_grants", KeyType.ACCOUNT, Rate(300, HOUR))
"""A member's grant requests of received files, resumes included (#213)."""

# ---- F. Uploads: declaring files, part URLs, listing parts, completing. ----
F_CALLER = _limit(
    Group.UPLOADS, "caller_requests", (*CALLER, KeyType.LINK_SESSION), Rate(600, MINUTE)
)
F_IP = _limit(Group.UPLOADS, "ip_requests", KeyType.IP, Rate(1200, MINUTE))

# ---- G. Actions that send email. Recipient emails take a cost: one per address. ----
MAX_RECIPIENTS = 50
"""A transfer's most recipients (the contract's `TransferCreate`): one send's largest cost."""
G_CALLER_EMAILS = _limit(
    Group.EMAIL, "caller_emails", CALLER, Rate(200, HOUR, max_cost=MAX_RECIPIENTS)
)
G_TENANT_EMAILS = _limit(
    Group.EMAIL, "tenant_emails", KeyType.TENANT, Rate(2000, HOUR, max_cost=MAX_RECIPIENTS)
)
G_ADDRESS_EMAILS = _limit(Group.EMAIL, "address_link_emails", KeyType.TENANT_EMAIL, Quota(20, DAY))
G_ADDRESS_ALL_TENANTS = _limit(
    Group.EMAIL, "address_link_emails_all", KeyType.EMAIL, Quota(100, DAY)
)
"""100 link emails a day to one address across tenants: the notification worker holds the email
until the window allows it, behind the neutral `queued` (abuse 7.2). Never a refusal."""
G_INVITES = _limit(Group.EMAIL, "tenant_invites", KeyType.TENANT, Rate(100, HOUR))
G_ADDRESS_INVITES = _limit(Group.EMAIL, "address_invites", KeyType.TENANT_EMAIL, Quota(3, DAY))

# ---- H. Tenant API: every other operation of members and API keys. ----
H_CALLER = _limit(Group.TENANT_API, "caller_requests", CALLER, Rate(300, MINUTE))
H_TENANT = _limit(Group.TENANT_API, "tenant_requests", KeyType.TENANT, Rate(1000, MINUTE))  # NFR-14
H_FAILED_AUTH = _limit(
    Group.TENANT_API, "failed_auth", KeyType.IP, Quota(100, 5 * MINUTE, "failures", 15 * MINUTE)
)

# ---- I. Audit: searchAuditEvents, exportAuditEvents (#216). Fail open. ----
I_SEARCHES = _limit(Group.AUDIT, "tenant_searches", KeyType.TENANT, Rate(60, MINUTE))
I_TENANT_EXPORTS = _limit(Group.AUDIT, "tenant_exports", KeyType.TENANT, Quota(10, HOUR))
I_KEY_EXPORTS = _limit(Group.AUDIT, "key_exports", KeyType.API_KEY, Quota(1, HOUR))
"""One export an hour per API key (authn and authz 5.3); an admin's exports count only towards
the tenant's 10. One export at a time per tenant is a lease, not a rate
(`sft.service.audit_search.ExportLeases`)."""

# ---- J. Key and tenant administration. ----
J_API_KEYS = _limit(Group.ADMINISTRATION, "api_keys", KeyType.TENANT, Quota(20, DAY))
J_TENANTS = _limit(Group.ADMINISTRATION, "tenants", KeyType.OPERATOR, Quota(30, HOUR))

# K: data loss prevention (#218 onwards).
K_POLICY_CHANGES = _limit(Group.DLP, "policy_changes", KeyType.TENANT, Quota(100, DAY))
K_CONFIRMATIONS = _limit(Group.DLP, "confirmations", CALLER, Rate(30, MINUTE))
K_FINDING_READS = _limit(Group.DLP, "finding_reads", CALLER, Rate(600, HOUR))
K_APPROVAL_DECISIONS = _limit(Group.DLP, "approval_decisions", CALLER, Rate(120, HOUR))
K_DETECTOR_TESTS = _limit(Group.DLP, "detector_tests", CALLER, Rate(30, MINUTE))
K_REPORT_READS = _limit(Group.DLP, "report_reads", KeyType.TENANT, Rate(60, MINUTE))

ALL = (
    *(A_IP, A_NOT_FOUND, A_FAILED_CODES, A_SUBJECT_GAP, A_SUBJECT_DAY),
    *(A_EMAIL_HOUR, A_EMAIL_DAY, A_TENANT),
    *(B_START, B_CALLBACK, B_INVITATION),
    C_SESSION,
    *(D_SUBJECT, D_IP, D_TENANT),
    D_ACCOUNT,
    *(F_CALLER, F_IP),
    *(G_CALLER_EMAILS, G_TENANT_EMAILS, G_ADDRESS_EMAILS, G_ADDRESS_ALL_TENANTS),
    *(G_INVITES, G_ADDRESS_INVITES),
    *(H_CALLER, H_TENANT, H_FAILED_AUTH),
    *(J_API_KEYS, J_TENANTS),
    *(I_SEARCHES, I_TENANT_EXPORTS, I_KEY_EXPORTS),
    K_POLICY_CHANGES,
    K_CONFIRMATIONS,
    K_FINDING_READS,
    K_APPROVAL_DECISIONS,
    K_DETECTOR_TESTS,
    K_REPORT_READS,
)
"""Every limit above, for the tests that check the whole table."""

# ---- What each operation applies, narrowest first. ----

LINK_STEP = (A_IP, A_NOT_FOUND, A_FAILED_CODES)
"""Before the token lookup, so a `429` reveals nothing about a token (abuse design 2.4)."""
REQUEST_CODE = (A_SUBJECT_GAP, A_SUBJECT_DAY, A_EMAIL_HOUR, A_EMAIL_DAY, A_TENANT)
"""`requestVerificationCode`, after the token lookup and the lockout. The probe mailbox's
addresses on the synthetic tenant's links leave out the two per-address limits (NFR-1)."""

CODE_ATTEMPT = LINK_STEP
"""`createLinkSession`: the per-IP link limits before the token lookup. Its code's own attempts
and the recipient's lockout are PostgreSQL's (abuse design 2.2, A); the code-request limits
count requests for codes, not attempts, so they aren't applied again here."""

LINK_SESSION_READ = (C_SESSION,)
"""`getLinkSession`, `endLinkSession`, `listSessionFiles`: per link session (group C)."""

GRANT_REQUEST = (D_SUBJECT, D_IP)
"""`createSessionDownload`, resumes included: per recipient, then per IP (abuse 2.2, D). A grant
that counts a download, not a resume, is also charged the tenant's 2,000 an hour (`D_TENANT`)
with the byte caps, all or none (`sft.service.rate_limits.downloads.grant_charges`)."""

RECEIVED_GRANT_REQUEST = (D_ACCOUNT, D_IP, H_TENANT)
"""`createReceivedFileDownload`, resumes included (#213): per member, then per IP, then the
tenant's group H budget, which counts group D too. A new grant is also charged the tenant's
2,000 an hour and its 500 GB a day (`sft.service.rate_limits.downloads.received_grant_charges`)."""

SIGN_IN_START = (B_START,)
SIGN_IN_CALLBACK = (B_CALLBACK,)
INVITATION_SIGN_IN = (B_INVITATION,)

EVERY_REQUEST = (H_FAILED_AUTH,)
"""Before routing and authentication, on every request of the public API: an IP blocked after 100
failed authentications gets `429` for whatever it sends, so a key guesser is stopped too."""

TENANT_OPERATION = (H_CALLER, H_TENANT)
"""Every member and API key operation, `GET /me` and sign-out included."""
SAFETY_ACTION = (H_CALLER,)
"""`revokeTransfer`, `revokeUploadRequest`, `revokeApiKey`, `deactivateUser`, `unlockRecipient`,
`unlockUploader`, `rejectTransfer`: never counted against, nor refused by, the tenant's budget."""

UPLOAD = (F_CALLER, F_IP, H_TENANT)
"""`addTransferFile`, `requestUploadPartUrls`, `listUploadedParts` and `completeUpload` (and their
link-session twins): group F's own budgets, then the tenant's group H budget, which counts group F
too (abuse and rate limits 2.2)."""

SESSION_UPLOAD = (F_CALLER, F_IP)
"""The uploader's four upload operations (#213): group F per link session and per IP. An uploader
spends none of the tenant's group H budget, as no link session does (2.2, H)."""

LINK_EMAILS = (G_CALLER_EMAILS, G_TENANT_EMAILS)
"""`sendTransfer`, after `TENANT_OPERATION`, once the send passes its checks: the caller's, then
the tenant's recipient emails, each recipient costing one, with `ADDRESS_LINK_EMAILS` between the
two for every address."""
ADDRESS_LINK_EMAILS = (G_ADDRESS_EMAILS,)
"""One address's link emails a day within the tenant (abuse 2.2, G)."""
CROSS_TENANT_LINK_EMAILS = (G_ADDRESS_ALL_TENANTS,)
"""One address's link emails a day across tenants, in the notification worker (abuse 7.2)."""
INVITE_USER = (G_CALLER_EMAILS, G_ADDRESS_INVITES, G_INVITES)
"""`inviteUser`, after `TENANT_OPERATION`, once the address is known."""
CREATE_TENANT = (J_TENANTS,)
"""`createTenant`, on the operator API."""
CREATE_API_KEY = (J_API_KEYS,)
"""`createApiKey`, after `TENANT_OPERATION`."""
AUDIT_SEARCH = (H_CALLER, I_SEARCHES, H_TENANT)
"""`searchAuditEvents`: the caller's group H budget, the tenant's 60 searches a minute, then the
tenant's group H budget, which counts group I too (abuse 2.2, H and I)."""
KEY_EXPORT = (I_KEY_EXPORTS,)
"""`exportAuditEvents` by an API key, in the service once the export may run: one an hour."""
TENANT_EXPORT = (I_TENANT_EXPORTS,)
"""`exportAuditEvents`, in the service after `KEY_EXPORT`: the tenant's 10 an hour."""
DLP_POLICY_CHANGE = (K_POLICY_CHANGES,)
"""`updateDlpPolicy` and the rule and detector writes, after `TENANT_OPERATION`: 100 changes a day
per tenant, counted only for a change that is made, in its transaction (abuse 2.2, K)."""
CONFIRM_TRANSFER = (K_CONFIRMATIONS,)
"""`confirmTransfer`, with `TENANT_OPERATION`: 30 confirmations a minute per account (abuse 2.2,
K). Keys are refused by the service; the API key's key is named only so the check has one."""
TRANSFER_DLP_READ = (K_FINDING_READS,)
"""`getTransferDlp`, with `TENANT_OPERATION`: 600 reads an hour per account or key (abuse 2.2,
K, the cap on responses with finding details, applied to every read until DLP-8 adds details)."""
APPROVAL_DECISION = (K_APPROVAL_DECISIONS,)
"""`approveTransfer` (with `TENANT_OPERATION`) and `rejectTransfer` (with `SAFETY_ACTION` only, a
safety action): 120 approval decisions an hour per approver (abuse 2.2, K), so a compromised
approver session can't release a backlog in seconds (#220)."""
DLP_DETECTOR_TEST = (K_DETECTOR_TESTS,)
"""`testDlpDetectors`, with `TENANT_OPERATION`: 30 tests a minute per account (abuse 2.2, K, #221).
Keys are refused by the service; the API key's key is named only so the check has one."""
DLP_REPORT_READ = (K_REPORT_READS,)
"""`getDlpReport` and `listDlpDecisions`, with `TENANT_OPERATION`: 60 reads a minute per tenant
(abuse 2.2, K, #222)."""
