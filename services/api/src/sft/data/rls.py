"""Grants and row-level security policies, generated for migrations (ADR-0020, data model 4.2).

A tenant-owned table ships with row-level security and its policies in the migration that creates
it; the catalog test fails otherwise. These functions write that SQL **when you author the
migration**; the revision keeps the literal statements, never a call to this module, so a later
change here can't change what an old revision does to a fresh database (a test checks that no
revision imports `sft`). To write one:

    uv run python -c 'from sft.data.rls import tenant_rls_sql; print(*tenant_rls_sql(
        "widgets", grants={"sft_api": "SELECT, INSERT, UPDATE", "sft_jobs": "SELECT"}), sep="\\n")'

and paste the statements into the revision as a tuple it runs with `op.execute`. That enables
row-level security, grants each workload role its privileges, and creates the `tenant_isolation`
policy, `tenant_id = app_tenant_id()` for reads and writes, for exactly those roles. Row-level
security is enabled, not forced: it doesn't apply to the owner, which only migrations act as
(ADR-0020). Policies for other scopes, such as `jobs_find` or the relay's, come from `policy_sql`.
A later migration that gives one more role the table uses `grant_sql` and replaces the policy's
role list with `ALTER POLICY tenant_isolation ON … TO …`.

Only `SELECT`, `INSERT`, `UPDATE` and `DELETE` can be granted, and only to workload roles: never
`TRUNCATE`, which ignores row-level security, and never to the owner, migration or lookup roles.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from sft.data.roles import WORKLOAD_ROLES

Command = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]

TENANT_POLICY = "tenant_isolation"

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")


def identifier(name: str) -> str:
    """`name` if it is a plain lower-case SQL identifier, needing no quotes; else ValueError."""
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


def grant_sql(table: str, role: str, privileges: str, *, columns: Sequence[str] = ()) -> str:
    """`GRANT` of `privileges` (e.g. "SELECT, INSERT") on `table` to one workload role.

    `columns` limits the grant to those columns, as for `audit_events`, whose writers may not set
    `tx_id` or `occurred_at`. `DELETE` applies to whole rows, so it takes no columns.
    """
    granted = _privileges(privileges)
    if columns:
        if "DELETE" in granted:
            raise ValueError("DELETE applies to whole rows; grant it without columns")
        granted = ", ".join(
            f"{p} ({', '.join(identifier(c) for c in columns)})" for p in granted.split(", ")
        )
    return f"GRANT {granted} ON {identifier(table)} TO {_workload_role(role)}"


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
        f"CREATE POLICY {identifier(name)} ON {identifier(table)} FOR {command} "
        f"TO {', '.join(_workload_role(r) for r in roles)}"
    )
    if using is not None:
        sql += f" USING ({using})"
    if with_check is not None:
        sql += f" WITH CHECK ({with_check})"
    return sql


def tenant_rls_sql(table: str, *, grants: Mapping[str, str], key: str = "tenant_id") -> list[str]:
    """Row-level security, grants and the tenant policy for a tenant-owned table.

    `grants` maps each workload role to its privileges. `key` is the column that holds the
    tenant: `tenant_id`, or `id` for `tenants` itself.
    """
    if not grants:
        raise ValueError("grant the table to at least one workload role")
    condition = f"{identifier(key)} = app_tenant_id()"
    return [
        f"ALTER TABLE {identifier(table)} ENABLE ROW LEVEL SECURITY",
        *(grant_sql(table, role, privileges) for role, privileges in grants.items()),
        policy_sql(TENANT_POLICY, table, roles=list(grants), using=condition, with_check=condition),
    ]
