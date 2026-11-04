"""The scope a transaction runs in, as PostgreSQL's row-level security sees it (ADR-0020).

Every transaction starts with `set_config('app.scope', …, true)` and
`set_config('app.tenant_id', …, true)` (`sft.data.database`). The policies read them through
`app_scope()` and `app_tenant_id()`. The scope kinds are those of authentication and authorization
7.1; tenant and resource scopes set a tenant, the others never do, so in them only the policies
written for that scope apply and every tenant policy matches nothing.

This is the database half of a scope. Which rows a resource scope may reach within its tenant, and
who may open which scope, are the data-access layer's and the service layer's rules (#49).
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


_WITH_TENANT = frozenset({ScopeKind.TENANT, ScopeKind.RESOURCE})


@dataclass(frozen=True, slots=True)
class Scope:
    """What a transaction may reach. Make one with the class methods, e.g. `Scope.tenant(id)`."""

    kind: ScopeKind
    tenant_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ScopeKind):
            raise TypeError("kind must be a ScopeKind")
        if self.tenant_id is not None and not isinstance(self.tenant_id, UUID):
            # A tenant comes from a credential row, as a UUID, never as text from a request.
            raise TypeError("tenant_id must be a UUID")
        if self.kind in _WITH_TENANT and self.tenant_id is None:
            raise ValueError(f"a {self.kind} scope needs a tenant")
        if self.kind not in _WITH_TENANT and self.tenant_id is not None:
            raise ValueError(f"a {self.kind} scope has no tenant")

    @classmethod
    def tenant(cls, tenant_id: UUID) -> Scope:
        return cls(ScopeKind.TENANT, tenant_id)

    @classmethod
    def resource(cls, tenant_id: UUID) -> Scope:
        return cls(ScopeKind.RESOURCE, tenant_id)

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
        """The values for `app.scope` and `app.tenant_id`; an empty tenant reads as null."""
        return {
            "scope": self.kind.value,
            "tenant_id": "" if self.tenant_id is None else str(self.tenant_id),
        }
