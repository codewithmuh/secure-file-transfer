"""Grants, policies, tenant keys and lookup functions, generated for migrations (ADR-0020, 4.2).

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
The lookup role gets only column-level `SELECT`, through `lookup_read_sql`.

**Composite foreign keys** (data model 4.2) make the database refuse a row that points at another
tenant's row, which row-level security doesn't check. Every tenant-owned table has
`tenant_id NOT NULL`, a foreign key to `tenants (id)` and a unique key `(tenant_id, id)`
(`tenant_keys_sql`); a child refers to its parent by both columns (`tenant_foreign_key_sql`):

    ALTER TABLE files ADD CONSTRAINT files_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants (id)
    ALTER TABLE files ADD CONSTRAINT files_tenant_id_id_key UNIQUE (tenant_id, id)
    ALTER TABLE files ADD CONSTRAINT files_tenant_id_transfer_id_fkey
        FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE

A catalog test fails the build on any foreign key between tenant tables that leaves `tenant_id`
out, unless the data model names it as an exception.

**Credential lookup functions** (data model 4.2) are the one way to search across tenants. The
migration that creates a credential table also runs `lookup_read_sql(table, columns)`, which gives
`sft_lookup` `SELECT` on just those columns and a policy that matches in lookup scope only, and
`lookup_function_sql(...)`, for example:

    lookup_function_sql(
        "lookup_member_session(p_session_hash bytea)",
        returns="TABLE (session_id uuid, owner_tenant_id uuid, expires_at timestamptz)",
        body="SELECT id, tenant_id, expires_at FROM public.member_sessions "
        "WHERE session_hash = p_session_hash",
    )

The function is `SECURITY DEFINER`, owned by `sft_lookup` (which has no `BYPASSRLS`), with its
`search_path` pinned, and only `sft_api` may execute it. Name tables with their schema in the body.
Return IDs and status columns only, never a hash or a ciphertext.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from sft.data.roles import API, LOOKUP, WORKLOAD_ROLES

Command = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]

OnDelete = Literal["CASCADE", "RESTRICT"]

TENANT_POLICY = "tenant_isolation"
LOOKUP_POLICY = "lookup_read"
LOOKUP_SEARCH_PATH = "pg_catalog, public, pg_temp"
"""Every definer function's `search_path`: the system catalog first, the temporary schema last."""

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_SIGNATURE = re.compile(r"([a-z_][a-z0-9_]{0,62})\(([a-z0-9_ ,\[\]]*)\)")
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


def _policy_role(role: str) -> str:
    # The lookup role reads credential tables through lookup_read policies of its own.
    return role if role == LOOKUP else _workload_role(role)


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
    """`CREATE POLICY` for workload roles, or `sft_lookup` for `lookup_read`. `using` filters rows
    read; `with_check`, rows written."""
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
        f"TO {', '.join(_policy_role(r) for r in roles)}"
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


# ---- composite foreign keys (data model 4.2) ----


def tenant_keys_sql(table: str) -> list[str]:
    """`tenant_id` references `tenants (id)`, and the unique key `(tenant_id, id)` children use."""
    name = identifier(table)
    return [
        f"ALTER TABLE {name} ADD CONSTRAINT {name}_tenant_id_fkey "
        "FOREIGN KEY (tenant_id) REFERENCES tenants (id)",
        f"ALTER TABLE {name} ADD CONSTRAINT {name}_tenant_id_id_key UNIQUE (tenant_id, id)",
    ]


def tenant_foreign_key_sql(
    table: str, column: str, parent: str, *, on_delete: OnDelete | None = None
) -> str:
    """`(tenant_id, column)` references `parent (tenant_id, id)`: a parent of the same tenant.

    A nullable `column` makes the reference optional, as for a file's transfer or upload request:
    PostgreSQL checks a composite key only when every column has a value.
    """
    if on_delete not in (None, "CASCADE", "RESTRICT"):
        raise ValueError(f"ON DELETE {on_delete} would break the tenant key; use CASCADE, RESTRICT")
    name, col = identifier(table), identifier(column)
    sql = (
        f"ALTER TABLE {name} ADD CONSTRAINT {name}_tenant_id_{col}_fkey "
        f"FOREIGN KEY (tenant_id, {col}) REFERENCES {identifier(parent)} (tenant_id, id)"
    )
    return sql if on_delete is None else f"{sql} ON DELETE {on_delete}"


# ---- credential lookup (data model 4.2) ----


def lookup_read_sql(table: str, columns: Sequence[str]) -> list[str]:
    """Let the lookup functions read `columns` of `table`, in lookup scope only."""
    if not columns:
        raise ValueError("name the columns the lookup functions read")
    names = ", ".join(identifier(c) for c in columns)
    return [
        f"GRANT SELECT ({names}) ON {identifier(table)} TO {LOOKUP}",
        policy_sql(
            LOOKUP_POLICY, table, roles=[LOOKUP], command="SELECT", using="app_scope() = 'lookup'"
        ),
    ]


def lookup_function_sql(signature: str, *, returns: str, body: str) -> list[str]:
    """A credential lookup function, as `sft_lookup`, for `sft_api` only.

    `signature` is the name and its arguments, e.g. `lookup_api_key(p_key_hash bytea)`.
    """
    if not _SIGNATURE.fullmatch(signature):
        raise ValueError(f"not a plain function signature: {signature!r}")
    if "$$" in body:
        raise ValueError("the body can't contain $$")
    return [
        f"CREATE FUNCTION {signature} RETURNS {returns} "
        f"LANGUAGE sql STABLE SECURITY DEFINER SET search_path = {LOOKUP_SEARCH_PATH} "
        f"AS $$ {body} $$",
        # Privileges first: once sft_lookup owns it, sft_owner's REVOKE and GRANT would be
        # ignored with only a warning. The new owner keeps them.
        f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC",
        f"GRANT EXECUTE ON FUNCTION {signature} TO {API}",
        # Changing the owner needs the bootstrap's grants: sft_owner may SET ROLE sft_lookup,
        # which may create in public.
        f"ALTER FUNCTION {signature} OWNER TO {LOOKUP}",
    ]
