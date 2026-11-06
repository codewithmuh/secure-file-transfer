"""The real revisions: numbered in a line, honest about what they serve, in step with the models."""

import ast
import re
from pathlib import Path
from typing import Any

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from pg import ScratchDatabase
from sft.data.audit_required import require_audit_sql
from sft.data.database import sync_engine
from sft.data.migrate import alembic_config, compatible_with, include_name
from sft.data.models import (
    Base,
    FileState,
    InspectionReason,
    InspectionState,
    Role,
    ScanDetail,
    ScanEngine,
    SessionRevokedReason,
    TransferState,
    UserStatus,
    sql_values,
)
from sft.data.rls import (
    grant_sql,
    lookup_function_sql,
    lookup_read_sql,
    policy_sql,
    tenant_foreign_key_sql,
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


def test_the_operator_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001: if a helper changes on purpose, replace the calls with the old output. Found by
    # its contents, so renumbering the revision doesn't touch this test.
    [module] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "TENANTS_DIRECTORY")
    ]
    assert list(module.TENANTS_DIRECTORY) == [
        policy_sql(
            "operator_directory",
            "tenants",
            roles=["sft_operator"],
            command="SELECT",
            using="app_scope() = 'platform'",
        )
    ]
    assert list(module.TENANT_POLICIES_RLS) == [
        tenant_keys_sql("tenant_policies")[0],
        *tenant_rls_sql("tenant_policies", grants={"sft_operator": "INSERT"}),
        require_audit_sql("tenant_policies"),
    ]
    assert list(module.OPERATOR_SESSIONS_GRANTS) == [
        grant_sql("operator_sessions", "sft_operator", "SELECT, INSERT")
    ]


def test_the_sign_in_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001. Found by its contents, so renumbering the revision doesn't touch this test.
    [module] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "MEMBER_SESSIONS_RLS")
    ]
    assert list(module.IDP_CONNECTIONS_KEYS) == tenant_keys_sql("idp_connections")
    assert list(module.IDP_CONNECTIONS_RLS) == [
        "ALTER TABLE idp_connections ENABLE ROW LEVEL SECURITY",
        *lookup_read_sql("idp_connections", ["id", "tenant_id", "kind", "provider_name", "status"]),
        *lookup_function_sql(
            "lookup_idp_connection(p_provider_name text)",
            returns="TABLE (connection_id uuid, owner_tenant_id uuid, kind text, status text)",
            body=module.LOOKUP_IDP_CONNECTION_BODY,
        ),
    ]
    assert require_audit_sql("idp_connections") == module.IDP_CONNECTIONS_AUDIT_REQUIRED
    assert list(module.USER_IDENTITIES_KEYS) == [
        *tenant_keys_sql("user_identities"),
        tenant_foreign_key_sql("user_identities", "user_id", "users"),
    ]
    assert list(module.USER_IDENTITIES_RLS) == [
        "ALTER TABLE user_identities ENABLE ROW LEVEL SECURITY",
        *lookup_read_sql(
            "user_identities",
            ["id", "tenant_id", "user_id", "idp_connection_id", "subject", "expires_at"],
        ),
        *lookup_function_sql(
            "lookup_user_identity(p_idp_connection_id uuid, p_subject text)",
            returns="TABLE (identity_id uuid, owner_tenant_id uuid, user_id uuid, "
            "expires_at timestamptz)",
            body=module.LOOKUP_USER_IDENTITY_BODY,
        ),
    ]
    assert require_audit_sql("user_identities") == module.USER_IDENTITIES_AUDIT_REQUIRED
    assert list(module.MEMBER_SESSIONS_KEYS) == [
        *tenant_keys_sql("member_sessions"),
        tenant_foreign_key_sql("member_sessions", "user_id", "users"),
    ]
    enable, api, _, policy = tenant_rls_sql(
        "member_sessions",
        grants={"sft_api": "SELECT, INSERT, UPDATE", "sft_operator": "SELECT, UPDATE"},
    )
    assert list(module.MEMBER_SESSIONS_RLS) == [
        enable,
        api,
        grant_sql("member_sessions", "sft_operator", "SELECT", columns=["tenant_id", "revoked_at"]),
        grant_sql(
            "member_sessions", "sft_operator", "UPDATE", columns=["revoked_at", "revoked_reason"]
        ),
        policy,
    ]
    assert list(module.LOOKUP_MEMBER_SESSION) == [
        *lookup_read_sql(
            "member_sessions", ["id", "tenant_id", "session_hash", "expires_at", "revoked_at"]
        ),
        *lookup_function_sql(
            "lookup_member_session(p_session_hash bytea)",
            returns="TABLE (session_id uuid, owner_tenant_id uuid, live boolean)",
            body=module.LOOKUP_MEMBER_SESSION_BODY,
        ),
    ]
    assert (
        require_audit_sql(
            "member_sessions", commands=("INSERT", "UPDATE"), update_of=("revoked_at",)
        )
        == module.MEMBER_SESSIONS_AUDIT_REQUIRED
    )


def test_the_session_checks_list_the_reasons_of_the_code() -> None:
    [script] = [s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "MEMBER_SESSIONS_RLS")]
    tree = ast.parse(Path(str(script.path)).read_text())
    texts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)]
    assert f"revoked_reason IN {sql_values(SessionRevokedReason)}" in texts


def test_the_idempotency_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001. Found by its contents, so renumbering the revision doesn't touch this test.
    [module] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "IDEMPOTENCY_KEYS_RLS")
    ]
    enable, api, _, policy = tenant_rls_sql(
        "idempotency_keys",
        grants={"sft_api": "SELECT, INSERT, UPDATE", "sft_jobs": "SELECT, DELETE"},
    )
    job_columns = ["tenant_id", "caller_type", "caller_id", "key", "expires_at"]
    assert list(module.IDEMPOTENCY_KEYS_RLS) == [
        tenant_keys_sql("idempotency_keys")[0],
        enable,
        api,
        grant_sql("idempotency_keys", "sft_jobs", "SELECT", columns=job_columns),
        grant_sql("idempotency_keys", "sft_jobs", "DELETE"),
        policy,
        policy_sql(
            "jobs_find",
            "idempotency_keys",
            roles=["sft_jobs"],
            command="SELECT",
            using="app_scope() = 'system'",
        ),
    ]


def test_the_transfers_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # As for 0001. Found by its contents, so renumbering the revision doesn't touch this test.
    [script] = [
        s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "KEYS") and "files" in s.path
    ]
    module = script.module
    tables = ("transfers", "transfer_recipients", "files", "tenant_usage")
    assert list(module.KEYS) == [
        *tenant_keys_sql("transfers"),
        tenant_foreign_key_sql("transfers", "created_by", "users"),
        tenant_foreign_key_sql("transfers", "revoked_by", "users"),
        *tenant_keys_sql("transfer_recipients"),
        tenant_foreign_key_sql(
            "transfer_recipients", "transfer_id", "transfers", on_delete="CASCADE"
        ),
        *tenant_keys_sql("files"),
        tenant_foreign_key_sql("files", "transfer_id", "transfers", on_delete="CASCADE"),
        tenant_keys_sql("tenant_usage")[0],
    ]
    assert list(module.RLS) == [
        statement
        for table in tables
        for statement in tenant_rls_sql(table, grants={"sft_api": "SELECT, INSERT, UPDATE"})
    ]
    assert list(module.AUDIT) == [require_audit_sql(table) for table in tables[:3]]


def test_the_transfers_checks_list_the_states_of_the_code() -> None:
    [script] = [
        s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "KEYS") and "files" in s.path
    ]
    assert f"({script.module.TRANSFER_STATES})" == sql_values(TransferState)
    assert f"({script.module.FILE_STATES})" == sql_values(FileState)


def _module(attribute: str, revision: str) -> object:
    [script] = [
        s
        for s in SCRIPTS.walk_revisions()
        if hasattr(s.module, attribute) and s.revision == revision
    ]
    return script.module


def _columns(listed: str) -> list[str]:
    return [c.strip() for c in listed.split(",")]


def test_the_send_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("TRANSFER_WRITE", "0009")
    assert list(module.KEYS) == [
        tenant_keys_sql("download_counters")[0],
        tenant_foreign_key_sql(
            "download_counters", "recipient_id", "transfer_recipients", on_delete="CASCADE"
        ),
        tenant_foreign_key_sql("download_counters", "file_id", "files", on_delete="CASCADE"),
        *tenant_keys_sql("email_suppressions"),
    ]
    evaluators = ("sft_scan", "sft_jobs")
    grants = [
        *tenant_rls_sql(
            "download_counters",
            grants={"sft_api": "SELECT, INSERT", "sft_scan": "INSERT", "sft_jobs": "INSERT"},
        ),
        *tenant_rls_sql(
            "email_suppressions",
            grants={"sft_api": "SELECT", "sft_notify": "SELECT, INSERT, UPDATE"},
        ),
        grant_sql("tenant_policies", "sft_api", "SELECT, INSERT, UPDATE"),
        grant_sql(
            "tenant_policies", "sft_scan", "SELECT", columns=["tenant_id", "unscannable_policy"]
        ),
        "ALTER POLICY tenant_isolation ON tenant_policies TO sft_operator, sft_api, sft_scan",
    ]
    for table, read, write in (
        ("transfers", module.TRANSFER_READ, module.TRANSFER_WRITE),
        ("transfer_recipients", module.RECIPIENT_READ, module.RECIPIENT_WRITE),
        ("files", module.FILE_READ, None),
    ):
        for role in evaluators:
            grants.append(grant_sql(table, role, "SELECT", columns=_columns(read)))
            if write is not None:
                grants.append(grant_sql(table, role, "UPDATE", columns=_columns(write)))
        grants.append(f"ALTER POLICY tenant_isolation ON {table} TO sft_api, sft_scan, sft_jobs")
    assert list(module.RLS) == grants
    assert list(module.AUDIT) == [
        require_audit_sql("download_counters"),
        require_audit_sql("email_suppressions"),
    ]
    # The evaluation's roles never read a ciphertext column or an address (data model 4.2).
    for listed in (module.TRANSFER_READ, module.RECIPIENT_READ, module.FILE_READ):
        assert not {"message_ct", "display_name_ct", "email", "email_normalized"} & set(
            _columns(listed)
        )


def test_the_scan_revisions_keep_the_sql_the_helpers_wrote_for_them() -> None:
    scans: Any = _module("SCAN_COLUMNS", "0010")
    columns = _columns(scans.SCAN_COLUMNS)
    assert list(scans.RLS) == [
        grant_sql("files", "sft_scan", "SELECT", columns=columns),
        grant_sql("files", "sft_scan", "UPDATE", columns=["state", *columns, "updated_at"]),
        grant_sql("files", "sft_jobs", "SELECT", columns=columns),
        grant_sql(
            "files",
            "sft_jobs",
            "UPDATE",
            columns=["state", "scan_detail", "scanned_at", "updated_at"],
        ),
        policy_sql(
            "jobs_find",
            "files",
            roles=["sft_jobs"],
            command="SELECT",
            using="app_scope() = 'system'",
        ),
    ]
    inspections: Any = _module("INSPECTION_COLUMNS", "0011")
    inspected = _columns(inspections.INSPECTION_COLUMNS)
    assert list(inspections.KEYS) == [
        *tenant_keys_sql("dlp_findings"),
        tenant_foreign_key_sql("dlp_findings", "file_id", "files", on_delete="CASCADE"),
    ]
    assert list(inspections.RLS) == [
        grant_sql("files", "sft_scan", "SELECT", columns=inspected),
        grant_sql("files", "sft_scan", "UPDATE", columns=inspected),
        grant_sql("files", "sft_jobs", "SELECT", columns=inspected),
        grant_sql("files", "sft_jobs", "UPDATE", columns=["inspection_state"]),
        *tenant_rls_sql("dlp_findings", grants={"sft_api": "SELECT", "sft_scan": "INSERT"}),
    ]
    assert list(inspections.AUDIT) == [require_audit_sql("dlp_findings")]


def test_the_scan_checks_list_the_values_of_the_code() -> None:
    scans: Any = _module("SCAN_COLUMNS", "0010")
    checks = dict(scans.CHECKS)
    assert f"scan_engine IN {sql_values(ScanEngine)}" == checks["files_scan_engine_check"]
    assert f"scan_detail IN {sql_values(ScanDetail)}" == checks["files_scan_detail_check"]
    inspections: Any = _module("INSPECTION_COLUMNS", "0011")
    checks = dict(inspections.CHECKS)
    assert checks["files_inspection_state_check"] == (
        f"inspection_state IN {sql_values(InspectionState)}"
    )
    reasons = sql_values(InspectionReason)[1:-1]
    assert checks["files_inspection_reasons_check"] == (
        f"inspection_reasons <@ ARRAY[{reasons}]::text[]"
    )


def test_the_sweep_finds_overdue_scans_by_an_index(migrated_db: ScratchDatabase) -> None:
    [(definition,)] = migrated_db.sql(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'files_scan_deadline_idx'"
    )
    assert "WHERE (state = 'scanning'::text)" in str(definition)
