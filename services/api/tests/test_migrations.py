"""The real revisions: numbered in a line, honest about what they serve, in step with the models."""

import ast
import re
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from pg import ScratchDatabase
from sft.data.audit_required import require_audit_sql
from sft.data.database import sync_engine
from sft.data.migrate import alembic_config, compatible_with, include_name
from sft.data.models import Base, Role, UserStatus, sql_values
from sft.data.rls import (
    grant_sql,
    lookup_function_sql,
    lookup_read_sql,
    policy_sql,
    tenant_keys_sql,
    tenant_rls_sql,
)

SCRIPTS = ScriptDirectory.from_config(alembic_config())


def test_revisions_form_one_numbered_line() -> None:
    # Linear history keeps "older" and "newer" unambiguous for the migration job.
    revisions = list(reversed(list(SCRIPTS.walk_revisions())))
    assert SCRIPTS.get_heads() == [revisions[-1].revision]
    for number, script in enumerate(revisions, start=1):
        assert script.revision == f"{number:04d}"
        assert script.down_revision == (None if number == 1 else f"{number - 1:04d}")
        assert re.fullmatch(rf"{script.revision}_[a-z0-9_]+\.py", Path(script.path).name)


def test_compatible_with_names_only_earlier_revisions() -> None:
    for script in SCRIPTS.walk_revisions():
        earlier = (
            {s.revision for s in SCRIPTS.iterate_revisions(script.down_revision, "base")}
            if script.down_revision
            else set()
        )
        assert set(compatible_with(script)) <= earlier, script.revision


def test_revisions_keep_literal_sql_and_import_nothing_of_ours() -> None:
    # A revision that called sft.data.rls would change what it does whenever the helpers change.
    for script in SCRIPTS.walk_revisions():
        tree = ast.parse(Path(str(script.path)).read_text())
        modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        modules += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        ours = [m for m in modules if m == "sft" or m.startswith("sft.")]
        assert ours == [], f"{script.revision} imports {ours}"


def test_0001_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # 0001 was written by pasting this output. If a helper changes on purpose, 0001 must not:
    # replace the call below with the old output, as a literal, and keep the test.
    frozen = SCRIPTS.get_revision("0001").module.TENANTS_RLS
    assert list(frozen) == tenant_rls_sql(
        "tenants", key="id", grants={"sft_api": "SELECT", "sft_operator": "SELECT, INSERT, UPDATE"}
    )


def test_the_outbox_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001: if a helper changes on purpose, replace the calls with the old output. Found by
    # its contents, so renumbering the revision doesn't touch this test.
    [module] = [s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "OUTBOX_RLS")]
    system = "app_scope() = 'system'"
    assert list(module.OUTBOX_RLS) == [
        *tenant_rls_sql(
            "outbox",
            grants={
                "sft_api": "INSERT",
                "sft_operator": "INSERT",
                "sft_scan": "INSERT",
                "sft_jobs": "INSERT",
            },
        ),
        grant_sql("outbox", "sft_relay", "SELECT, UPDATE"),
        policy_sql("relay_read", "outbox", roles=["sft_relay"], command="SELECT", using=system),
        policy_sql(
            "relay_mark",
            "outbox",
            roles=["sft_relay"],
            command="UPDATE",
            using=system,
            with_check=system,
        ),
    ]
    assert list(module.PROCESSED_MESSAGES_RLS) == tenant_rls_sql(
        "processed_messages", grants={"sft_scan": "INSERT", "sft_notify": "INSERT"}
    )


def test_the_users_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001. Found by its contents, so renumbering the revision doesn't touch this test.
    [module] = [s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "USERS_RLS")]
    assert list(module.USERS_KEYS) == tenant_keys_sql("users")
    assert list(module.USERS_RLS) == tenant_rls_sql(
        "users",
        grants={
            "sft_api": "SELECT, INSERT, UPDATE",
            "sft_operator": "SELECT, INSERT",
            "sft_notify": "SELECT",
        },
    )
    assert list(module.LOOKUP_INVITATION) == [
        *lookup_read_sql(
            "users", ["id", "tenant_id", "status", "invitation_token_hash", "invitation_expires_at"]
        ),
        *lookup_function_sql(
            "lookup_invitation(p_token_hash bytea)",
            returns="TABLE (user_id uuid, owner_tenant_id uuid)",
            body=module.LOOKUP_INVITATION_BODY,
        ),
    ]
    assert require_audit_sql("users") == module.USERS_AUDIT_REQUIRED


def test_the_users_checks_list_the_roles_and_statuses_of_the_code() -> None:
    [script] = [s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "USERS_RLS")]
    source = Path(str(script.path)).read_text()
    assert f"role IN {sql_values(Role)}" in source
    assert f"status IN {sql_values(UserStatus)}" in source


def test_the_models_match_the_migrations(migrated_db: ScratchDatabase) -> None:
    engine = sync_engine(migrated_db.admin)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True, "include_name": include_name}
            )
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_the_job_recorded_what_head_serves(migrated_db: ScratchDatabase) -> None:
    head = SCRIPTS.get_current_head()
    assert migrated_db.sql("SELECT version_num FROM alembic_version") == [(head,)]
    rows = migrated_db.sql(
        "SELECT compatible_with FROM schema_compatibility WHERE revision = :head", head=head
    )
    assert rows == [(list(compatible_with(SCRIPTS.get_revision(head))),)]
