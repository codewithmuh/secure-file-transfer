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

- **Find across, act within.** In system scope no write reaches a tenant row: the session refuses
  an `INSERT`, `UPDATE` or `DELETE` on a tenant table, and a flush that adds, changes or deletes
  a tenant-owned object, before it reaches the database (`check_write`, called by `Database`'s
  session). Nothing has to remember a flag. The relay is the one exception (`SYSTEM_WRITERS`): it
  marks every tenant's outbox rows sent. A lifecycle job finds its work in system scope and changes
  each item in that item's tenant scope. Work on no tenant's rows, such as the audit partition
  upkeep, isn't affected.
- **Functions of one scope** check it with `require_scope`: a credential lookup runs only in
  lookup scope, which is also the only scope its `lookup_read` policies match.
- **Where the tenant of a write comes from:** `tenant_of(session)`, the scope's tenant, never an
  argument.
- **Not found** is `NotFoundError`, which a data-access function raises for a row its scope
  doesn't reach; the service answers 404 (authentication and authorization 6.1).

Row-level security checks the tenant boundary only. Within a tenant, the resource rule is this
module's alone, and so is the subject. The isolation suite (`tests/test_isolation.py`) runs every
data-access function with this layer alone, with row-level security alone, and with both.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, ClassVar, Final
from uuid import UUID

from sqlalchemy import ColumnElement, FromClause, and_, false, true
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import roles
from sft.data.scope import TENANT_SCOPES, Scope, ScopeKind, Subject

_TENANT, _RESOURCE, _SYSTEM, _PLATFORM, _LOOKUP, _RECOVERY = (
    ScopeKind.TENANT,
    ScopeKind.RESOURCE,
    ScopeKind.SYSTEM,
    ScopeKind.PLATFORM,
    ScopeKind.LOOKUP,
    ScopeKind.RECOVERY,
)
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
    """A workload asked for a scope its role never opens, or wrote where its scope can't."""


class NotFoundError(Exception):
    """The row isn't there, or the session's scope doesn't reach it: the caller can't tell which.

    Not a `LookupError`, so a `KeyError` or `IndexError` from a bug is never taken for one.
    """


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
        names = [k.value for k in kinds]
        allowed = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} or {names[-1]}"
        raise ScopeNotAllowedError(f"this runs in a {allowed} scope, not {scope.kind}")
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


def in_scope(model: type[TenantOwned], session: AsyncSession) -> ColumnElement[bool]:
    """The condition that keeps a query on `model` inside the session's scope."""
    scope = scope_of(session)
    condition = _tenant_condition(model, scope)
    if scope.subject is not None:
        condition = and_(condition, model.reach(scope.subject))
    return condition


def _tenant_condition(model: type[TenantOwned], scope: Scope) -> ColumnElement[bool]:
    # The whole tenant filter, in one place: the isolation suite replaces this function to prove
    # that row-level security alone keeps tenants apart (ADR-0020).
    if scope.kind in TENANT_SCOPES:
        column: Any = getattr(model, model.__tenant_key__)
        condition: ColumnElement[bool] = column == scope.tenant_id
        return condition
    if scope.kind in _ACROSS_TENANTS:
        return true()
    return false()


def check_write(scope: Scope, role: str | None, tables: Iterable[FromClause | None]) -> None:
    """Refuse a write to tenant tables in system scope, unless `role` writes there by design.

    `Database`'s session calls it for every `INSERT`, `UPDATE` and `DELETE` it executes and for
    every flush, with the tables they touch.
    """
    if scope.kind is not ScopeKind.SYSTEM or _writes_tenant_rows_in_system_scope(role):
        return
    touched = sorted({t.name for t in tables if t is not None and _is_tenant_table(t)})  # type: ignore[attr-defined]
    if touched:
        raise ScopeNotAllowedError(
            f"{role} writes no tenant rows in system scope ({', '.join(touched)}): find across, "
            "then act on each item in its tenant's scope"
        )


def _writes_tenant_rows_in_system_scope(role: str | None) -> bool:
    # The isolation suite replaces this function too, with _tenant_condition.
    return role in SYSTEM_WRITERS


def _is_tenant_table(table: FromClause) -> bool:
    return getattr(table, "name", None) == "tenants" or "tenant_id" in table.c
