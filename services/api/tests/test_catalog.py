"""The catalog checks of ADR-0020 and authentication and authorization 9.2, after `upgrade head`.

They read PostgreSQL's catalog, so every table a later migration adds is checked the same way:
row-level security on every tenant table, a policy for every grant, no way around either.
"""

from pg import ScratchDatabase
from sft.data.roles import ALL_ROLES, LOGIN_ROLES, MIGRATE, OPERATOR, OWNER, WORKLOAD_ROLES

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

# Every privilege on those tables held by a role other than the owner.
GRANTS = """
    SELECT c.relname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
           a.privilege_type
      FROM pg_class c, aclexplode(c.relacl) a
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
       AND a.grantee <> c.relowner
"""

COMMANDS = {"SELECT": "r", "INSERT": "a", "UPDATE": "w", "DELETE": "d"}


def tables(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql(TABLES)


def test_there_is_at_least_one_tenant_table(migrated_db: ScratchDatabase) -> None:
    # Otherwise the checks below would pass by checking nothing.
    assert any(row[4] for row in tables(migrated_db))


def test_every_tenant_table_has_row_level_security_enabled_not_forced(
    migrated_db: ScratchDatabase,
) -> None:
    for _, name, enabled, forced, tenant_owned in tables(migrated_db):
        if tenant_owned:
            assert enabled, f"{name}: row-level security is off"
            assert not forced, f"{name}: forced, so data migrations would see no rows"


def test_every_grant_on_a_table_with_row_level_security_has_a_policy(
    migrated_db: ScratchDatabase,
) -> None:
    secured = {name for _, name, enabled, *_ in tables(migrated_db) if enabled}
    for table, role, privilege in migrated_db.sql(GRANTS):
        if table not in secured:
            continue
        policies = migrated_db.sql(
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
    migrated_db: ScratchDatabase,
) -> None:
    # Platform tables (data model 2.6); the migration job's own tables are granted to nobody.
    secured = {name for _, name, enabled, *_ in tables(migrated_db) if enabled}
    for table, role, _ in migrated_db.sql(GRANTS):
        if table not in secured:
            assert role == OPERATOR, f"{table} has no row-level security but {role} may use it"


def test_only_reads_and_writes_are_granted_and_only_to_workload_roles(
    migrated_db: ScratchDatabase,
) -> None:
    # TRUNCATE ignores row-level security; REFERENCES and TRIGGER aren't needed by any workload.
    for table, role, privilege in migrated_db.sql(GRANTS):
        assert role in WORKLOAD_ROLES, f"{role} has {privilege} on {table}"
        assert privilege in COMMANDS, f"{role} has {privilege} on {table}"


def test_no_role_is_granted_a_partition(migrated_db: ScratchDatabase) -> None:
    # Queried directly, a partition skips its parent's policies (authn and authz 7.5).
    granted = migrated_db.sql(
        """
        SELECT c.relname FROM pg_class c, aclexplode(c.relacl) a
         WHERE c.relnamespace = 'public'::regnamespace AND c.relispartition
           AND a.grantee <> c.relowner
        """
    )
    assert granted == []


def test_the_owner_owns_everything(migrated_db: ScratchDatabase) -> None:
    owners = migrated_db.sql(
        """
        SELECT DISTINCT pg_get_userbyid(relowner) FROM pg_class
         WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
        UNION
        SELECT DISTINCT pg_get_userbyid(proowner) FROM pg_proc
         WHERE pronamespace = 'public'::regnamespace AND proowner <> 'sft_lookup'::regrole
        """
    )
    assert owners == [(OWNER,)]


def test_no_role_of_ours_can_get_around_row_level_security(migrated_db: ScratchDatabase) -> None:
    risky = migrated_db.sql(
        """
        SELECT rolname FROM pg_roles
         WHERE rolname = ANY(:roles)
           AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
        """,
        roles=list(ALL_ROLES),
    )
    assert risky == []


def test_only_sft_migrate_can_become_the_owner_and_only_on_purpose(
    migrated_db: ScratchDatabase,
) -> None:
    members = migrated_db.sql(
        """
        SELECT pg_get_userbyid(member), inherit_option, set_option, admin_option
          FROM pg_auth_members WHERE roleid = CAST(:owner AS regrole)
        """,
        owner=OWNER,
    )
    assert members == [(MIGRATE, False, True, False)]
    # And no workload role is a member of any of our roles.
    memberships = migrated_db.sql(
        "SELECT pg_get_userbyid(member) FROM pg_auth_members WHERE member = ANY("
        "SELECT oid FROM pg_roles WHERE rolname = ANY(:roles))",
        roles=list(WORKLOAD_ROLES),
    )
    assert memberships == []


def test_only_the_login_roles_can_log_in(migrated_db: ScratchDatabase) -> None:
    rows = migrated_db.sql(
        "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname = ANY(:roles)",
        roles=list(ALL_ROLES),
    )
    assert {name: can for name, can in rows} == {role: role in LOGIN_ROLES for role in ALL_ROLES}


def test_only_the_login_roles_may_connect(migrated_db: ScratchDatabase) -> None:
    rows = migrated_db.sql(
        """
        SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type
          FROM pg_database d, aclexplode(d.datacl) a
         WHERE d.datname = current_database() AND a.grantee <> d.datdba
        """
    )
    assert sorted(rows) == sorted((role, "CONNECT") for role in LOGIN_ROLES)


def test_views_run_with_the_callers_rights(migrated_db: ScratchDatabase) -> None:
    views = migrated_db.sql(
        """
        SELECT relname FROM pg_class
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'v'
           AND NOT coalesce('security_invoker=true' = ANY(reloptions), false)
        """
    )
    assert views == []


def test_sft_migrate_has_no_privileges_until_it_becomes_the_owner(
    migrated_db: ScratchDatabase,
) -> None:
    rows = migrated_db.sql(
        "SELECT has_table_privilege(:role, 'tenants', 'SELECT'), "
        "has_schema_privilege(:role, 'public', 'CREATE')",
        role=MIGRATE,
    )
    assert rows == [(False, False)]
