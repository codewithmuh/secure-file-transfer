"""Catalog checks for the audit trail after `upgrade head`, so every later table meets them too."""

from alembic.script import ScriptDirectory

from pg import ScratchDatabase
from sft.data.audit_required import NOT_AUDITED, TRIGGER, require_audit_sql
from sft.data.migrate import alembic_config
from sft.data.rls import grant_sql, policy_sql

# Tenant-owned tables in `public`, partitions left out, with whether each has the audit trigger
# as a deferred constraint trigger.
TENANT_TABLES = """
    SELECT c.relname, EXISTS (
               SELECT FROM pg_trigger t
                WHERE t.tgrelid = c.oid AND t.tgname = :trigger AND t.tgconstraint <> 0
                  AND t.tgdeferrable AND t.tginitdeferred AND t.tgenabled = 'O'
                  AND t.tgfoid = 'audit_required()'::regprocedure
           )
      FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition AND c.relname <> 'audit_events'
       AND (c.relname = 'tenants' OR EXISTS (
               SELECT FROM pg_attribute a
                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
"""


def test_every_tenant_table_is_audited_or_says_why_not(migrated_db: ScratchDatabase) -> None:
    tables = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    assert tables, "no tenant tables: the check below would pass by checking nothing"
    for table, audited in tables.items():
        assert audited or table in NOT_AUDITED, (
            f"{table}: give it the require_audit_sql() trigger in its migration, or a reason in "
            "sft.data.audit_required.NOT_AUDITED"
        )
    for table, reason in NOT_AUDITED.items():
        assert table in tables, f"NOT_AUDITED names {table}, which isn't a tenant table"
        assert not tables[table], f"{table} is audited, so it doesn't belong in NOT_AUDITED"
        assert reason.strip(), f"{table}: say why its changes need no audit event"


def test_tenants_are_audited(migrated_db: ScratchDatabase) -> None:
    assert dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))["tenants"]


def test_no_role_may_change_or_delete_audit_events(migrated_db: ScratchDatabase) -> None:
    # T-43: the app roles only insert; retention arrives with a role and a review of its own.
    rows = migrated_db.sql(
        """
        SELECT pg_get_userbyid(a.grantee), a.privilege_type
          FROM pg_class c, aclexplode(c.relacl) a
         WHERE c.oid = 'audit_events'::regclass AND a.grantee <> c.relowner
           AND a.privilege_type NOT IN ('INSERT', 'SELECT')
        """
    )
    assert rows == []


def test_the_audit_table_is_partitioned_with_a_default(migrated_db: ScratchDatabase) -> None:
    assert migrated_db.sql(
        """
        SELECT p.partstrat, pg_get_partkeydef(p.partrelid),
               p.partdefid::regclass::text
          FROM pg_partitioned_table p WHERE p.partrelid = 'audit_events'::regclass
        """
    ) == [("r", "RANGE (occurred_at)", "audit_events_default")]


def test_definer_functions_pin_their_path_and_are_not_public(migrated_db: ScratchDatabase) -> None:
    # A SECURITY DEFINER function runs with its owner's rights: it must not resolve names
    # through the caller's search_path, nor be callable by every role (authn and authz 7.5).
    rows = migrated_db.sql(
        """
        SELECT p.proname,
               coalesce(EXISTS (SELECT FROM unnest(p.proconfig) s WHERE s LIKE 'search_path=%'),
                        false),
               p.proacl IS NULL OR EXISTS (
                   SELECT FROM aclexplode(p.proacl) a WHERE a.grantee = 0)
          FROM pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace AND p.prosecdef
        """
    )
    assert rows, "no definer functions: the check would pass by checking nothing"
    for name, pinned, public in rows:
        assert pinned, f"{name} doesn't pin search_path"
        assert not public, f"every role may execute {name}"


def test_0002_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # 0002 was written by pasting this output. If a helper changes on purpose, 0002 must not:
    # replace the calls below with the old output, as literals, and keep the test.
    revision = ScriptDirectory.from_config(alembic_config()).get_revision("0002").module
    writers = ["sft_api", "sft_scan", "sft_notify", "sft_jobs", "sft_operator"]
    assert list(revision.AUDIT_EVENTS_RLS) == [
        "ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY",
        *(grant_sql("audit_events", role, "INSERT") for role in writers),
        grant_sql("audit_events", "sft_api", "SELECT"),
        grant_sql("audit_events", "sft_archive", "SELECT"),
        grant_sql("audit_events", "sft_recovery", "INSERT"),
        policy_sql(
            "audit_tenant_insert",
            "audit_events",
            roles=writers,
            command="INSERT",
            with_check="tenant_id = app_tenant_id()",
        ),
        policy_sql(
            "audit_platform_insert",
            "audit_events",
            roles=["sft_api", "sft_operator"],
            command="INSERT",
            with_check="tenant_id IS NULL AND app_tenant_id() IS NULL AND app_scope() = 'platform'",
        ),
        policy_sql(
            "audit_tenant_read",
            "audit_events",
            roles=["sft_api"],
            command="SELECT",
            using="tenant_id = app_tenant_id()",
        ),
        policy_sql(
            "audit_archive_read",
            "audit_events",
            roles=["sft_archive"],
            command="SELECT",
            using="app_scope() = 'system'",
        ),
        policy_sql(
            "audit_recovery_insert",
            "audit_events",
            roles=["sft_recovery"],
            command="INSERT",
            with_check="app_scope() = 'recovery'",
        ),
    ]
    trigger = require_audit_sql("tenants", commands=("INSERT", "UPDATE"), update_of=("status",))
    assert trigger == revision.TENANTS_AUDIT_REQUIRED
