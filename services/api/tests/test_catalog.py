"""The catalog checks of ADR-0020 and authentication and authorization 9.2, after `upgrade head`.

They read PostgreSQL's catalog, so every table a later migration adds is checked the same way:
row-level security on every tenant table, a policy for every grant, no way around either; every
foreign key between tenant tables carries `tenant_id`; every definer function is a pinned
credential lookup or one of the owner's known functions. Each runs on the migrated schema and on
the isolation suite's, which adds the stand-in tables, their composite keys and a lookup function
(`isolation_fixture.py`).
"""

import pytest

from isolation import Mode, World
from pg import (
    EXEMPT_FOREIGN_KEYS,
    ScratchDatabase,
    definer_function_problems,
    foreign_keys_without_tenant,
)
from sft.data.roles import (
    ALL_ROLES,
    LOGIN_ROLES,
    LOOKUP,
    MIGRATE,
    OPERATOR,
    OWNER,
    WORKLOAD_ROLES,
)

# Tables in `public`, with whether they hold tenant rows: a `tenant_id` column, or `tenants` itself.
# Partitions are left out: queries reach them through their parent's policies, and nobody is granted
# a partition (checked below).
TABLES = """
    SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity,
           c.relname = 'tenants' OR EXISTS (
               SELECT FROM pg_attribute a
                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
           ) AS tenant_owned
      FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition
"""

# Every privilege on those tables held by a role other than the owner, on the table or a column.
GRANTS = """
    SELECT c.relname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
           a.privilege_type, 'table'
      FROM pg_class c, aclexplode(c.relacl) a
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
       AND a.grantee <> c.relowner
    UNION
    SELECT c.relname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
           a.privilege_type, 'column'
      FROM pg_class c JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
       AND NOT att.attisdropped AND a.grantee <> c.relowner
"""


@pytest.fixture(params=["migrated", "isolation"])
def catalog_db(
    request: pytest.FixtureRequest, migrated_db: ScratchDatabase, isolation_world: World
) -> ScratchDatabase:
    """The migrated schema, and the isolation suite's with its stand-in tables."""
    return migrated_db if request.param == "migrated" else isolation_world.database(Mode.AS_BUILT)


COMMANDS = {"SELECT": "r", "INSERT": "a", "UPDATE": "w", "DELETE": "d"}


def tables(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql(TABLES)


def test_there_is_at_least_one_tenant_table(catalog_db: ScratchDatabase) -> None:
    # Otherwise the checks below would pass by checking nothing.
    assert any(row[4] for row in tables(catalog_db))


def test_every_tenant_table_has_row_level_security_enabled_not_forced(
    catalog_db: ScratchDatabase,
) -> None:
    for _, name, enabled, forced, tenant_owned in tables(catalog_db):
        if tenant_owned:
            assert enabled, f"{name}: row-level security is off"
            assert not forced, f"{name}: forced, so data migrations would see no rows"


def test_every_grant_on_a_table_with_row_level_security_has_a_policy(
    catalog_db: ScratchDatabase,
) -> None:
    secured = {name for _, name, enabled, *_ in tables(catalog_db) if enabled}
    for table, role, privilege, _ in catalog_db.sql(GRANTS):
        if table not in secured:
            continue
        policies = catalog_db.sql(
            """
            SELECT p.polname FROM pg_policy p
             WHERE p.polrelid = CAST(:table AS regclass)
               AND (p.polroles @> ARRAY[CAST(:role AS regrole)::oid] OR p.polroles = '{0}')
               AND p.polcmd IN ('*', :command)
            """,
            table=table,
            role=role,
            command=COMMANDS[str(privilege)],
        )
        assert policies, f"{role} may {privilege} {table}, but no policy lets it see a row"


def test_tables_without_row_level_security_are_granted_only_to_the_operator(
    catalog_db: ScratchDatabase,
) -> None:
    # Platform tables (data model 2.6); the migration job's own tables are granted to nobody.
    secured = {name for _, name, enabled, *_ in tables(catalog_db) if enabled}
    for table, role, _, _ in catalog_db.sql(GRANTS):
        if table not in secured:
            assert role == OPERATOR, f"{table} has no row-level security but {role} may use it"


def test_only_reads_and_writes_are_granted_and_only_to_workload_roles(
    catalog_db: ScratchDatabase,
) -> None:
    # TRUNCATE ignores row-level security; REFERENCES and TRIGGER aren't needed by any workload.
    # The lookup role reads credential columns, and nothing else (data model 4.2).
    for table, role, privilege, level in catalog_db.sql(GRANTS):
        if role == LOOKUP:
            assert (privilege, level) == ("SELECT", "column"), f"{role} has {privilege} on {table}"
            continue
        assert role in WORKLOAD_ROLES, f"{role} has {privilege} on {table}"
        assert privilege in COMMANDS, f"{role} has {privilege} on {table}"


def test_no_role_is_granted_a_partition(catalog_db: ScratchDatabase) -> None:
    # Queried directly, a partition skips its parent's policies (authn and authz 7.5).
    granted = catalog_db.sql(
        """
        SELECT c.relname FROM pg_class c, aclexplode(c.relacl) a
         WHERE c.relnamespace = 'public'::regnamespace AND c.relispartition
           AND a.grantee <> c.relowner
        """
    )
    assert granted == []


def test_the_owner_owns_everything(catalog_db: ScratchDatabase) -> None:
    owners = catalog_db.sql(
        """
        SELECT DISTINCT pg_get_userbyid(relowner) FROM pg_class
         WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
        UNION
        SELECT DISTINCT pg_get_userbyid(proowner) FROM pg_proc
         WHERE pronamespace = 'public'::regnamespace AND proowner <> 'sft_lookup'::regrole
        """
    )
    assert owners == [(OWNER,)]


def test_no_role_of_ours_can_get_around_row_level_security(catalog_db: ScratchDatabase) -> None:
    risky = catalog_db.sql(
        """
        SELECT rolname FROM pg_roles
         WHERE rolname = ANY(:roles)
           AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
        """,
        roles=list(ALL_ROLES),
    )
    assert risky == []


def test_only_sft_migrate_can_become_the_owner_and_only_on_purpose(
    catalog_db: ScratchDatabase,
) -> None:
    members = catalog_db.sql(
        """
        SELECT pg_get_userbyid(member), inherit_option, set_option, admin_option
          FROM pg_auth_members WHERE roleid = CAST(:owner AS regrole)
        """,
        owner=OWNER,
    )
    assert members == [(MIGRATE, False, True, False)]
    # The owner may become sft_lookup, to hand it a lookup function, and nobody else may.
    lookup_members = catalog_db.sql(
        """
        SELECT pg_get_userbyid(member), inherit_option, set_option, admin_option
          FROM pg_auth_members WHERE roleid = CAST(:lookup AS regrole)
        """,
        lookup=LOOKUP,
    )
    assert lookup_members == [(OWNER, False, True, False)]
    # And no workload role is a member of any of our roles.
    memberships = catalog_db.sql(
        "SELECT pg_get_userbyid(member) FROM pg_auth_members WHERE member = ANY("
        "SELECT oid FROM pg_roles WHERE rolname = ANY(:roles))",
        roles=list(WORKLOAD_ROLES),
    )
    assert memberships == []


def test_only_the_login_roles_can_log_in(catalog_db: ScratchDatabase) -> None:
    rows = catalog_db.sql(
        "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname = ANY(:roles)",
        roles=list(ALL_ROLES),
    )
    assert {name: can for name, can in rows} == {role: role in LOGIN_ROLES for role in ALL_ROLES}


def test_only_the_login_roles_may_connect(catalog_db: ScratchDatabase) -> None:
    rows = catalog_db.sql(
        """
        SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type
          FROM pg_database d, aclexplode(d.datacl) a
         WHERE d.datname = current_database() AND a.grantee <> d.datdba
        """
    )
    assert sorted(rows) == sorted((role, "CONNECT") for role in LOGIN_ROLES)


def test_views_run_with_the_callers_rights(catalog_db: ScratchDatabase) -> None:
    views = catalog_db.sql(
        """
        SELECT relname FROM pg_class
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'v'
           AND NOT coalesce('security_invoker=true' = ANY(reloptions), false)
        """
    )
    assert views == []


def test_sft_migrate_has_no_privileges_until_it_becomes_the_owner(
    catalog_db: ScratchDatabase,
) -> None:
    rows = catalog_db.sql(
        "SELECT has_table_privilege(:role, 'tenants', 'SELECT'), "
        "has_schema_privilege(:role, 'public', 'CREATE')",
        role=MIGRATE,
    )
    assert rows == [(False, False)]


def test_only_the_owner_may_create_in_public(catalog_db: ScratchDatabase) -> None:
    # public is on every pinned search_path, so a role that may create there could plant a table
    # or function a definer function would find (CVE-2018-1058).
    creators = catalog_db.sql(
        """
        SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
          FROM pg_namespace n, aclexplode(n.nspacl) a
         WHERE n.nspname = 'public' AND a.privilege_type = 'CREATE' AND a.grantee <> n.nspowner
        """
    )
    assert creators == [(OWNER,)]


def test_foreign_keys_between_tenant_tables_carry_the_tenant(catalog_db: ScratchDatabase) -> None:
    # Row-level security doesn't check foreign keys; a composite key refuses a reference to another
    # tenant's row (data model 4.2, sft.data.rls.tenant_foreign_key_sql).
    assert foreign_keys_without_tenant(catalog_db, EXEMPT_FOREIGN_KEYS) == []


def test_every_definer_function_is_a_pinned_lookup_or_a_known_owner_function(
    catalog_db: ScratchDatabase,
) -> None:
    assert definer_function_problems(catalog_db) == []
