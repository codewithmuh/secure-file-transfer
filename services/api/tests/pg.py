"""Real PostgreSQL for the tests: scratch databases on the server that TEST_DATABASE_URL names."""

import secrets
from collections.abc import Callable, Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import URL, Connection, text

from sft.data.bootstrap import bootstrap
from sft.data.database import sync_engine
from sft.data.migrate import become_owner
from sft.data.rls import LOOKUP_SEARCH_PATH
from sft.data.roles import API, JOBS, LOGIN_ROLES, LOOKUP, MIGRATE, OWNER, RECOVERY

# A superuser URL for a PostgreSQL 17 server, e.g. postgresql://postgres:…@127.0.0.1:5432/postgres.
# Each test session makes its own databases there and drops them afterwards. The roles are
# cluster-wide, so they stay, with the password below.
ADMIN_URL_VARIABLE = "TEST_DATABASE_URL"
# local/postgres/passwords.sql gives the local stack's roles the same value, so `make test` against
# the stack leaves the API's login working. Change both together.
TEST_PASSWORD = "test-only-password"  # noqa: S105 - local and CI test servers only


class Sql(Protocol):
    """Anything that runs a statement as the superuser: a `ScratchDatabase`, or the harness's
    `Admin`."""

    def sql(self, statement: str, **params: object) -> list[tuple[object, ...]]: ...


@dataclass(frozen=True)
class ScratchDatabase:
    """A database of its own on the test server, with the roles bootstrapped."""

    admin: URL  # the superuser, connected to this database

    @property
    def name(self) -> str:
        return str(self.admin.database)

    def url(self, role: str) -> str:
        """A URL that logs in as `role`, which bootstrap created and the fixture gave a password."""
        return self.admin.set(username=role, password=TEST_PASSWORD).render_as_string(
            hide_password=False
        )

    def admin_url(self) -> str:
        return self.admin.render_as_string(hide_password=False)

    def sql(self, statement: str, **params: object) -> list[tuple[object, ...]]:
        """Run one statement as the superuser, which row-level security doesn't apply to."""
        engine = sync_engine(self.admin)
        try:
            with engine.begin() as connection:
                result = connection.execute(text(statement), params)
                return [tuple(row) for row in result] if result.returns_rows else []
        finally:
            engine.dispose()

    def as_owner(self, work: Callable[[Connection], object]) -> None:
        """Run `work` as a migration does: `sft_migrate`, become `sft_owner`, one transaction."""
        engine = sync_engine(self.url(MIGRATE))
        try:
            with engine.connect() as connection:
                become_owner(connection)
                work(connection)
                connection.commit()
        finally:
            engine.dispose()


@contextmanager
def fresh_database(admin_url: URL) -> Iterator[ScratchDatabase]:
    """An empty database with the roles bootstrapped, dropped afterwards."""
    name = f"sft_test_{secrets.token_hex(4)}"
    server = sync_engine(admin_url, isolation_level="AUTOCOMMIT")
    with server.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    db = ScratchDatabase(admin_url.set(database=name))
    try:
        engine = sync_engine(db.admin)
        try:
            with engine.begin() as connection:
                bootstrap(connection, iam_auth=False)
                for role in LOGIN_ROLES:
                    connection.execute(text(f"ALTER ROLE {role} PASSWORD '{TEST_PASSWORD}'"))
        finally:
            engine.dispose()
        yield db
    finally:
        with server.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        server.dispose()


# ---- catalog checks that later tables are held to (data model 4.2, authn and authz 9.2) ----

TENANT_TABLES = """
    SELECT c.relname FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition
       AND (c.relname = 'tenants' OR EXISTS (
           SELECT FROM pg_attribute a
            WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
"""

FOREIGN_KEYS = """
    SELECT c.conname, src.relname, dst.relname,
           ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY AS k(n, i)
                   JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n
                  ORDER BY k.i),
           ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY AS k(n, i)
                   JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n
                  ORDER BY k.i)
      FROM pg_constraint c
      JOIN pg_class src ON src.oid = c.conrelid
      JOIN pg_class dst ON dst.oid = c.confrelid
     WHERE c.contype = 'f' AND c.conparentid = 0 AND src.relnamespace = 'public'::regnamespace
"""


def tenant_tables(db: ScratchDatabase) -> set[str]:
    """Tables that hold tenant rows: a `tenant_id` column, or `tenants` itself."""
    return {str(name) for (name,) in db.sql(TENANT_TABLES)}


def foreign_keys_without_tenant(db: ScratchDatabase, exempt: Collection[str] = ()) -> list[str]:
    """Foreign keys that could point a tenant's row at another tenant's (data model 4.2).

    From a tenant table, a key must reach `tenants (id)` through `tenant_id` alone, or another
    tenant table through `tenant_id` matched with its `tenant_id`.
    """
    owned = tenant_tables(db)
    problems = []
    for name, source, target, columns, referenced in db.sql(FOREIGN_KEYS):
        if source not in owned or name in exempt:
            continue
        cols, refs = list(columns), list(referenced)  # type: ignore[call-overload]
        if target == "tenants":
            ok = cols == ["tenant_id"] and refs == ["id"]
        elif target in owned:
            ok = "tenant_id" in cols and refs[cols.index("tenant_id")] == "tenant_id"
        else:
            ok = False
        if not ok:
            problems.append(f"{name}: {source} ({', '.join(cols)}) -> {target} ({', '.join(refs)})")
    return problems


DEFINER_FUNCTIONS = """
    SELECT p.oid::regprocedure::text, pg_get_userbyid(p.proowner), p.prosecdef,
           coalesce(p.proconfig, '{}'),
           p.proacl IS NULL,
           ARRAY(SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
                   FROM aclexplode(p.proacl) a
                  WHERE a.grantee <> p.proowner AND a.privilege_type = 'EXECUTE')
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_%'
       AND (p.prosecdef OR p.proowner = CAST(:lookup AS regrole))
"""


def definer_functions(db: ScratchDatabase) -> list[tuple[object, ...]]:
    """Definer functions, and anything `sft_lookup` owns, in every schema but PostgreSQL's own."""
    return db.sql(DEFINER_FUNCTIONS, lookup=LOOKUP)


OWNER_DEFINER_FUNCTIONS: dict[str, tuple[str, ...]] = {
    # The audit partition upkeep (data model 6, #50): the lifecycle job, and the recovery job,
    # which makes the months a restore brings back.
    "audit_create_partitions(integer,date)": (JOBS, RECOVERY),
    "audit_partition_status()": (JOBS,),
    # The fail-closed audit check (#50): a trigger function, which no role calls itself.
    "audit_required()": (),
}
"""`SECURITY DEFINER` functions the owner may have, and the only roles that may execute each.

Every other definer function is a credential lookup. A new owner function is added here, in review.
"""


def definer_function_problems(db: ScratchDatabase) -> list[str]:
    """What is wrong with any `SECURITY DEFINER` function (ADR-0020, authn and authz 7.5).

    Two kinds, each held to its own rule:

    - **Credential lookups** (data model 4.2): owned by `sft_lookup`, `search_path` pinned to
      `pg_catalog, public, pg_temp`, executable by `sft_api` alone. `sft_lookup` owns nothing else.
    - **The owner's functions**, named in `OWNER_DEFINER_FUNCTIONS`: owned by `sft_owner`, the same
      pinned `search_path`, `PUBLIC` revoked, executable by exactly the roles named there.
    """
    problems = []
    for function, owner, definer, config, default_acl, executors in definer_functions(db):
        settings = list(config)  # type: ignore[call-overload]
        granted = "PUBLIC (the default)" if default_acl else sorted(executors)  # type: ignore[call-overload]
        if owner == LOOKUP:
            if not definer:
                problems.append(f"{function}: owned by {LOOKUP} but not SECURITY DEFINER")
            if f"search_path={LOOKUP_SEARCH_PATH}" not in settings:
                problems.append(f"{function}: search_path not pinned to {LOOKUP_SEARCH_PATH}")
            if default_acl or list(executors) != [API]:  # type: ignore[call-overload]
                problems.append(f"{function}: executable by {granted}, not {API} alone")
        elif owner == OWNER and function in OWNER_DEFINER_FUNCTIONS:
            allowed = list(OWNER_DEFINER_FUNCTIONS[function])
            if f"search_path={LOOKUP_SEARCH_PATH}" not in settings:
                problems.append(f"{function}: search_path not pinned to {LOOKUP_SEARCH_PATH}")
            if default_acl or sorted(executors) != sorted(allowed):  # type: ignore[call-overload]
                problems.append(f"{function}: executable by {granted}, not {allowed}")
        else:
            problems.append(
                f"{function}: SECURITY DEFINER owned by {owner}, neither a lookup owned by "
                f"{LOOKUP} nor one of the owner's known functions"
            )
    return problems
