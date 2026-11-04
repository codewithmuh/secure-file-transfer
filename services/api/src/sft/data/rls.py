"""Grants and row-level security policies, as migrations write them (ADR-0020, data model 4.2).

A tenant-owned table ships with row-level security and its policies in the migration that creates
it; the catalog test fails otherwise. In that migration:

    op.create_table("widgets", sa.Column("tenant_id", sa.Uuid, nullable=False), ...)
    enable_tenant_rls("widgets", grants={roles.API: "SELECT, INSERT, UPDATE", roles.JOBS: "SELECT"})

That enables row-level security, grants each workload role its privileges, and creates the
`tenant_isolation` policy, `tenant_id = app_tenant_id()` for reads and writes, for exactly those
roles. Row-level security is enabled, not forced: it doesn't apply to the owner, which only
migrations act as (ADR-0020). Policies for other scopes, such as `jobs_find` or the relay's, go in
the same migration with `create_policy`. A later migration that gives one more role the table
calls `grant` and replaces the policy's role list with `ALTER POLICY tenant_isolation ON … TO …`.

Only `SELECT`, `INSERT`, `UPDATE` and `DELETE` can be granted, and only to workload roles: never
`TRUNCATE`, which ignores row-level security, and never to the owner, migration or lookup roles.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from alembic import op

from sft.data.roles import WORKLOAD_ROLES

Command = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]

TENANT_POLICY = "tenant_isolation"

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")


def _identifier(name: str) -> str:
    if not _IDENTIFIER.fullmatch(name):
        raise ValueError(f"not a plain lower-case identifier: {name!r}")
    return name


def _workload_role(role: str) -> str:
    if role not in WORKLOAD_ROLES:
        raise ValueError(f"{role!r} is not a workload role; see sft.data.roles")
    return role


def _privileges(spec: str) -> str:
    privileges = [p.strip().upper() for p in spec.split(",")]
    if not privileges or any(p not in _PRIVILEGES for p in privileges):
        raise ValueError(f"grant only {', '.join(_PRIVILEGES)}, not {spec!r}")
    return ", ".join(p for p in _PRIVILEGES if p in privileges)


def grant_sql(table: str, role: str, privileges: str) -> str:
    """`GRANT` of `privileges` (e.g. "SELECT, INSERT") on `table` to one workload role."""
    return f"GRANT {_privileges(privileges)} ON {_identifier(table)} TO {_workload_role(role)}"


def policy_sql(
    name: str,
    table: str,
    *,
    roles: Sequence[str],
    command: Command = "ALL",
    using: str | None = None,
    with_check: str | None = None,
) -> str:
    """`CREATE POLICY` for workload roles. `using` filters rows read; `with_check`, rows written."""
    if not roles:
        raise ValueError("a policy names the roles it applies to")
    if command in ("SELECT", "DELETE") and with_check is not None:
        raise ValueError(f"a {command} policy has no WITH CHECK")
    if command == "INSERT" and using is not None:
        raise ValueError("an INSERT policy has no USING")
    if using is None and with_check is None:
        raise ValueError("a policy needs USING, WITH CHECK or both")
    sql = (
        f"CREATE POLICY {_identifier(name)} ON {_identifier(table)} FOR {command} "
        f"TO {', '.join(_workload_role(r) for r in roles)}"
    )
    if using is not None:
        sql += f" USING ({using})"
    if with_check is not None:
        sql += f" WITH CHECK ({with_check})"
    return sql


def tenant_rls_sql(table: str, *, grants: Mapping[str, str], key: str = "tenant_id") -> list[str]:
    """The statements `enable_tenant_rls` runs, for review and tests."""
    if not grants:
        raise ValueError("grant the table to at least one workload role")
    condition = f"{_identifier(key)} = app_tenant_id()"
    return [
        f"ALTER TABLE {_identifier(table)} ENABLE ROW LEVEL SECURITY",
        *(grant_sql(table, role, privileges) for role, privileges in grants.items()),
        policy_sql(TENANT_POLICY, table, roles=list(grants), using=condition, with_check=condition),
    ]


def enable_tenant_rls(table: str, *, grants: Mapping[str, str], key: str = "tenant_id") -> None:
    """In a migration: row-level security, grants and the tenant policy for a tenant-owned table.

    `grants` maps each workload role to its privileges. `key` is the column that holds the
    tenant: `tenant_id`, or `id` for `tenants` itself.
    """
    for statement in tenant_rls_sql(table, grants=grants, key=key):
        op.execute(statement)


def create_policy(
    name: str,
    table: str,
    *,
    roles: Sequence[str],
    command: Command = "ALL",
    using: str | None = None,
    with_check: str | None = None,
) -> None:
    """In a migration: a policy for another scope, e.g. `jobs_find` or an audit insert policy."""
    op.execute(
        policy_sql(name, table, roles=roles, command=command, using=using, with_check=with_check)
    )


def grant(table: str, role: str, privileges: str) -> None:
    """In a migration: grant one workload role `privileges` on `table`."""
    op.execute(grant_sql(table, role, privileges))
