"""The scope a transaction runs in, as PostgreSQL's row-level security sees it (ADR-0020).

Every transaction starts with `set_config('app.scope', …, true)` and
`set_config('app.tenant_id', …, true)` (`sft.data.database`). The policies read them through
`app_scope()` and `app_tenant_id()`. The scope kinds are those of authentication and authorization
7.1; tenant and resource scopes set a tenant, the others never do, so in them only the policies
written for that scope apply and every tenant policy matches nothing.

A resource scope also names its subject, the one recipient or upload request a verified link
session reaches (authentication and authorization 7.1). PostgreSQL never sees the subject: row-level
security keeps tenants apart, and which rows the subject reaches within its tenant is the
data-access layer's rule (`sft.data.access`), as is which workload role may open which scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class ScopeKind(StrEnum):
    """The value of `app.scope`."""

    TENANT = "tenant"
    """A member session's or an API key's tenant."""
    RESOURCE = "resource"
    """One transfer or upload request, through a verified link session; its tenant is set."""
    SYSTEM = "system"
    """A named job: finds work across tenants, read only, then acts on each item in its tenant."""
    PLATFORM = "platform"
    """An operator, or an event with no tenant: platform tables and platform audit events."""
    LOOKUP = "lookup"
    """The credential lookup functions, before the caller's tenant is known."""
    RECOVERY = "recovery"
    """The restore and failover jobs, as `sft_recovery`, never a running service."""


TENANT_SCOPES = frozenset({ScopeKind.TENANT, ScopeKind.RESOURCE})
"""The scope kinds that set a tenant; every other kind sets none."""


class SubjectKind(StrEnum):
    """What a link session was verified for (data model 2.4)."""

    RECIPIENT = "recipient"
    """A `transfer_recipients` row: its transfer and that transfer's files."""
    UPLOAD_REQUEST = "upload_request"
    """An `upload_requests` row: that request and its files."""


@dataclass(frozen=True, slots=True)
class Subject:
    """The one item a resource scope reaches, from the link session row, never from a request."""

    kind: SubjectKind
    id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SubjectKind):
            raise TypeError("kind must be a SubjectKind")
        if not isinstance(self.id, UUID):
            raise TypeError("id must be a UUID")

    @classmethod
    def recipient(cls, recipient_id: UUID) -> Subject:
        return cls(SubjectKind.RECIPIENT, recipient_id)

    @classmethod
    def upload_request(cls, upload_request_id: UUID) -> Subject:
        return cls(SubjectKind.UPLOAD_REQUEST, upload_request_id)


@dataclass(frozen=True, slots=True)
class Scope:
    """What a transaction may reach. Make one with the class methods, e.g. `Scope.tenant(id)`."""

    kind: ScopeKind
    tenant_id: UUID | None = None
    subject: Subject | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ScopeKind):
            raise TypeError("kind must be a ScopeKind")
        if self.tenant_id is not None and not isinstance(self.tenant_id, UUID):
            # A tenant comes from a credential row, as a UUID, never as text from a request.
            raise TypeError("tenant_id must be a UUID")
        if self.kind in TENANT_SCOPES and self.tenant_id is None:
            raise ValueError(f"a {self.kind} scope needs a tenant")
        if self.kind not in TENANT_SCOPES and self.tenant_id is not None:
            raise ValueError(f"a {self.kind} scope has no tenant")
        if self.subject is not None and not isinstance(self.subject, Subject):
            raise TypeError("subject must be a Subject")
        if self.kind is ScopeKind.RESOURCE and self.subject is None:
            raise ValueError("a resource scope needs a subject")
        if self.kind is not ScopeKind.RESOURCE and self.subject is not None:
            raise ValueError(f"a {self.kind} scope has no subject")

    @classmethod
    def tenant(cls, tenant_id: UUID) -> Scope:
        return cls(ScopeKind.TENANT, tenant_id)

    @classmethod
    def resource(cls, tenant_id: UUID, subject: Subject) -> Scope:
        return cls(ScopeKind.RESOURCE, tenant_id, subject)

    @classmethod
    def system(cls) -> Scope:
        return cls(ScopeKind.SYSTEM)

    @classmethod
    def platform(cls) -> Scope:
        return cls(ScopeKind.PLATFORM)

    @classmethod
    def lookup(cls) -> Scope:
        return cls(ScopeKind.LOOKUP)

    @classmethod
    def recovery(cls) -> Scope:
        return cls(ScopeKind.RECOVERY)

    def settings(self) -> dict[str, str]:
        """The values for `app.scope` and `app.tenant_id`; an empty tenant reads as null.

        The subject isn't among them: PostgreSQL enforces the tenant boundary only (ADR-0020).
        """
        return {
            "scope": self.kind.value,
            "tenant_id": "" if self.tenant_id is None else str(self.tenant_id),
        }
