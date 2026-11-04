"""Scoped data access: the first isolation layer, before row-level security (ADR-0003, ADR-0020).

`Scope` (`sft.data.scope`) is what PostgreSQL sees. This module holds the rules on top of it:

- **Who may open which scope.** Each workload role opens only the scopes of authentication and
  authorization 7.3 (`SCOPES_BY_ROLE`). `Database` takes the role from its URL and refuses any
  other scope before the transaction reaches the database.
- **Which rows a scope reaches.** Every data-access function filters with `in_scope(Model,
  session)`, never with a tenant of its own making:

      select(Widget).where(Widget.id == widget_id, in_scope(Widget, session))

  - **Tenant:** rows whose tenant key is the scope's tenant.
  - **Resource:** those rows, narrowed to what the subject reaches, `Model.reach(subject)`.
  - **System and recovery:** across tenants, because a named job finds its work there and recovery
    re-applies records; the role's grants and policies decide the tables and rows.
  - **Platform and lookup:** no tenant rows. Platform tables have no `TenantOwned` model, and
    credentials are found only through the lookup functions (data model 4.2).

- **Find across, act within.** In system scope a write reaches no tenant rows,
  `in_scope(Model, session, write=True)`, except for the relay, which marks every tenant's outbox
  rows sent. A lifecycle job finds its work there and changes each item in that item's tenant
  scope. Writes to no tenant's rows, such as the audit partition upkeep, aren't affected.
- **Functions of one scope** check it with `require_scope`: a credential lookup runs only in
  lookup scope, which is also the only scope its `lookup_read` policies match.
- **Where the tenant of a write comes from:** `tenant_of(session)`, the scope's tenant, never an
  argument.

Row-level security checks the tenant boundary only. Within a tenant, the resource rule is this
module's alone, and so is the subject. The isolation suite (`tests/test_isolation.py`) runs every
data-access function with this layer alone, with row-level security alone, and with both.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, Final
from uuid import UUID

from sqlalchemy import ColumnElement, and_, false, true
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import roles
from sft.data.scope import Scope, ScopeKind, Subject

_TENANT, _RESOURCE, _SYSTEM, _PLATFORM, _LOOKUP, _RECOVERY = (
    ScopeKind.TENANT,
    ScopeKind.RESOURCE,
    ScopeKind.SYSTEM,
    ScopeKind.PLATFORM,
    ScopeKind.LOOKUP,
    ScopeKind.RECOVERY,
)
_WITH_TENANT = frozenset({_TENANT, _RESOURCE})
_ACROSS_TENANTS = frozenset({_SYSTEM, _RECOVERY})

SCOPES_BY_ROLE: Final[Mapping[str, frozenset[ScopeKind]]] = {
    # Member sessions and API keys (tenant), link sessions (resource), events with no tenant
    # (platform), and the credential lookup functions (lookup) that come before all of them.
    roles.API: frozenset({_TENANT, _RESOURCE, _PLATFORM, _LOOKUP}),
    # Platform tables; one tenant's rows only in that tenant's scope (authn and authz 8.2).
    roles.OPERATOR: frozenset({_PLATFORM, _TENANT}),
    # The tenant comes from the outbox message, which only our own workloads send.
    roles.SCAN: frozenset({_TENANT}),
    roles.NOTIFY: frozenset({_TENANT}),
    roles.RELAY: frozenset({_SYSTEM}),
    # Find across, act within: one read in system scope, then each item in its tenant's scope.
    roles.JOBS: frozenset({_SYSTEM, _TENANT}),
    roles.ARCHIVE: frozenset({_SYSTEM}),
    roles.RECOVERY: frozenset({_RECOVERY}),
}
"""The scopes each workload role may open (authentication and authorization 7.3)."""


SYSTEM_WRITERS: Final = frozenset({roles.RELAY})
"""Roles whose system-scope writes reach tenant rows: the relay marks every tenant's outbox rows."""


class ScopeNotAllowedError(RuntimeError):
    """A workload asked for a scope its role never opens, or no workload role was named."""


def check_scope(role: str, scope: Scope) -> None:
    """Refuse `scope` unless `role` may open it."""
    allowed = SCOPES_BY_ROLE.get(role)
    if allowed is None:
        raise ScopeNotAllowedError(f"{role!r} is not a workload role; see sft.data.roles")
    if scope.kind not in allowed:
        raise ScopeNotAllowedError(f"{role} never opens a {scope.kind} scope")


def scope_of(session: AsyncSession) -> Scope:
    """The scope the session's transaction runs in, as `Database.transaction` set it."""
    scope = session.info.get("scope")
    if not isinstance(scope, Scope):
        # Unreachable through Database.transaction, which refuses to begin without one.
        raise ScopeNotAllowedError("this session has no scope (ADR-0020)")
    return scope


def require_scope(session: AsyncSession, *kinds: ScopeKind) -> Scope:
    """The session's scope, if it is one of `kinds`; for functions of one scope, e.g. lookups."""
    scope = scope_of(session)
    if scope.kind not in kinds:
        raise ScopeNotAllowedError(f"this runs in a {' or '.join(kinds)} scope, not {scope.kind}")
    return scope


def tenant_of(session: AsyncSession) -> UUID:
    """The tenant of every row this transaction writes: the scope's, never a parameter."""
    tenant_id = scope_of(session).tenant_id
    if tenant_id is None:
        raise ScopeNotAllowedError(f"a {scope_of(session).kind} scope writes no tenant rows")
    return tenant_id


class TenantOwned:
    """A mixin for the model of every tenant-owned table.

    `__tenant_key__` names the column that holds the tenant: `tenant_id`, or `id` for `tenants`.
    `reach` says which rows a resource scope's subject reaches. The default reaches none, so a new
    table is closed to link sessions until its model says otherwise, for example for `files`:

        @classmethod
        def reach(cls, subject: Subject) -> ColumnElement[bool]:
            if subject.kind is SubjectKind.UPLOAD_REQUEST:
                return cls.upload_request_id == subject.id
            return cls.transfer_id == select(TransferRecipient.transfer_id).where(
                TransferRecipient.id == subject.id
            ).scalar_subquery()
    """

    __tenant_key__: ClassVar[str] = "tenant_id"

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        """The rows of this table that `subject`, within its tenant, may reach."""
        return false()


def in_scope(
    model: type[TenantOwned], session: AsyncSession, *, write: bool = False
) -> ColumnElement[bool]:
    """The condition that keeps a query on `model` inside the session's scope.

    Pass `write=True` in an `UPDATE` or `DELETE`: in system scope only the relay writes tenant rows.
    """
    scope = scope_of(session)
    role = session.info.get("role")
    condition = _tenant_condition(model, scope, role if isinstance(role, str) else None, write)
    if scope.subject is not None:
        condition = and_(condition, model.reach(scope.subject))
    return condition


def _tenant_condition(
    model: type[TenantOwned], scope: Scope, role: str | None, write: bool
) -> ColumnElement[bool]:
    # The whole tenant filter, in one place: the isolation suite replaces this function to prove
    # that row-level security alone keeps tenants apart (ADR-0020).
    if scope.kind in _WITH_TENANT:
        column: Any = getattr(model, model.__tenant_key__)
        condition: ColumnElement[bool] = column == scope.tenant_id
        return condition
    if scope.kind is ScopeKind.SYSTEM and write and role not in SYSTEM_WRITERS:
        return false()
    if scope.kind in _ACROSS_TENANTS:
        return true()
    return false()
