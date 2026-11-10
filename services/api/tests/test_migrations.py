"""The real revisions: numbered in a line, honest about what they serve, in step with the models."""

import ast
import re
from pathlib import Path
from typing import Any

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from pg import ScratchDatabase
from sft.data.audit_required import require_audit_sql
from sft.data.database import sync_engine
from sft.data.migrate import alembic_config, become_owner, compatible_with, include_name
from sft.data.models import (
    AdminRecoveryKind,
    ApiKeyRevokedReason,
    ApiKeyScope,
    ApprovalDecisionKind,
    ApprovalState,
    Base,
    BreakGlassState,
    DeliveryState,
    DlpAction,
    DlpCondition,
    DlpConfidence,
    DlpDetectorKind,
    DlpDirection,
    DlpMode,
    DlpOutcome,
    DlpRecipientScope,
    FileState,
    InspectionReason,
    InspectionState,
    Role,
    ScanDetail,
    ScanEngine,
    SessionRevokedReason,
    TransferState,
    UploadRequestState,
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
from sft.data.roles import MIGRATE

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


def test_the_link_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("RECIPIENT_WRITE", "0012")
    written: str = module.UNLOCKED_BY_KEY
    assert written == tenant_foreign_key_sql("transfer_recipients", "unlocked_by", "users")
    notify = "sft_notify"
    assert list(module.RLS) == [
        grant_sql("tenants", notify, "SELECT", columns=_columns(module.TENANT_READ)),
        "ALTER POLICY tenant_isolation ON tenants TO sft_api, sft_operator, sft_notify",
        grant_sql("tenant_policies", notify, "SELECT", columns=_columns(module.POLICY_READ)),
        "ALTER POLICY tenant_isolation ON tenant_policies TO sft_operator, sft_api, sft_scan, "
        "sft_notify",
        grant_sql("transfers", notify, "SELECT", columns=_columns(module.TRANSFER_READ)),
        "ALTER POLICY tenant_isolation ON transfers TO sft_api, sft_scan, sft_jobs, sft_notify",
        grant_sql("transfer_recipients", notify, "SELECT", columns=_columns(module.RECIPIENT_READ)),
        grant_sql(
            "transfer_recipients", notify, "UPDATE", columns=_columns(module.RECIPIENT_WRITE)
        ),
        "ALTER POLICY tenant_isolation ON transfer_recipients TO sft_api, sft_scan, sft_jobs, "
        "sft_notify",
        grant_sql("outbox", notify, "INSERT"),
        "ALTER POLICY tenant_isolation ON outbox TO sft_api, sft_operator, sft_scan, sft_jobs, "
        "sft_notify",
    ]
    # The notification worker never reads a ciphertext column (data model 4.2).
    for listed in (module.TRANSFER_READ, module.RECIPIENT_READ):
        assert not {"message_ct", "display_name_ct"} & set(_columns(listed))


def test_the_verification_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("LOOKUP_LINK_SESSIONS", "0013")
    assert list(module.KEYS) == [
        *tenant_keys_sql("verification_codes"),
        tenant_foreign_key_sql(
            "verification_codes", "recipient_id", "transfer_recipients", on_delete="CASCADE"
        ),
        *tenant_keys_sql("link_sessions"),
        tenant_foreign_key_sql(
            "link_sessions", "recipient_id", "transfer_recipients", on_delete="CASCADE"
        ),
    ]
    assert list(module.RLS) == [
        *tenant_rls_sql(
            "verification_codes", grants={"sft_api": "SELECT, UPDATE", "sft_notify": "INSERT"}
        ),
        grant_sql("verification_codes", "sft_notify", "SELECT", columns=_columns(module.CODE_READ)),
        grant_sql("verification_codes", "sft_notify", "UPDATE", columns=["superseded_at"]),
        *tenant_rls_sql("link_sessions", grants={"sft_api": "SELECT, INSERT, UPDATE"}),
    ]
    assert "code_hmac" not in _columns(module.CODE_READ)
    assert list(module.LOOKUP_LINK_TOKEN) == [
        *lookup_read_sql("transfer_recipients", ["id", "tenant_id", "link_token_hash"]),
        *lookup_function_sql(
            "lookup_link_token(p_token_hash bytea)",
            returns="TABLE (recipient_id uuid, owner_tenant_id uuid)",
            body=module.LOOKUP_LINK_TOKEN_BODY,
        ),
    ]
    assert list(module.LOOKUP_LINK_SESSIONS) == [
        *lookup_read_sql(
            "link_sessions",
            [
                "id",
                "tenant_id",
                "recipient_id",
                "session_hash",
                "expires_at",
                "last_seen_at",
                "revoked_at",
            ],
        ),
        *lookup_function_sql(
            "lookup_link_sessions(p_session_hashes bytea[])",
            returns="TABLE (session_id uuid, owner_tenant_id uuid, recipient_id uuid, "
            "live boolean)",
            body=module.LOOKUP_LINK_SESSIONS_BODY,
        ),
    ]
    assert list(module.AUDIT) == [
        require_audit_sql("verification_codes"),
        require_audit_sql(
            "link_sessions", commands=("INSERT", "UPDATE"), update_of=("revoked_at",)
        ),
    ]


def test_the_link_token_hash_is_unique(migrated_db: ScratchDatabase) -> None:
    [(definition,)] = migrated_db.sql(
        "SELECT indexdef FROM pg_indexes "
        "WHERE indexname = 'transfer_recipients_link_token_hash_key'"
    )
    assert "CREATE UNIQUE INDEX" in str(definition)


def test_the_download_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("COUNTER_WRITE", "0014")
    assert list(module.KEYS) == [
        *tenant_keys_sql("download_grants"),
        *(
            tenant_foreign_key_sql("download_grants", column, parent, on_delete="CASCADE")
            for column, parent in (
                ("file_id", "files"),
                ("recipient_id", "transfer_recipients"),
                ("link_session_id", "link_sessions"),
            )
        ),
    ]
    assert list(module.RLS) == [
        *tenant_rls_sql("download_grants", grants={"sft_api": "SELECT, INSERT, UPDATE"}),
        grant_sql("download_counters", "sft_api", "UPDATE", columns=_columns(module.COUNTER_WRITE)),
        grant_sql("files", "sft_scan", "UPDATE", columns=["sha256"]),
    ]
    assert list(module.AUDIT) == [require_audit_sql("download_grants", commands=("INSERT",))]


def test_the_lifecycle_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("FILE_WRITE", "0015")
    find = "app_scope() = 'system'"
    isolation = "ALTER POLICY tenant_isolation ON {} TO {}"
    assert list(module.RLS) == [
        grant_sql("transfers", "sft_jobs", "UPDATE", columns=["ended_at"]),
        policy_sql("jobs_find", "transfers", roles=["sft_jobs"], command="SELECT", using=find),
        grant_sql("files", "sft_jobs", "SELECT", columns=["deleted_at"]),
        grant_sql("files", "sft_jobs", "UPDATE", columns=_columns(module.FILE_WRITE)),
        grant_sql("tenant_usage", "sft_jobs", "SELECT, UPDATE"),
        isolation.format("tenant_usage", "sft_api, sft_jobs"),
        grant_sql("verification_codes", "sft_jobs", "SELECT", columns=_columns(module.CODE_READ)),
        grant_sql("verification_codes", "sft_jobs", "DELETE"),
        policy_sql(
            "jobs_find", "verification_codes", roles=["sft_jobs"], command="SELECT", using=find
        ),
        isolation.format("verification_codes", "sft_api, sft_notify, sft_jobs"),
        grant_sql("link_sessions", "sft_jobs", "SELECT", columns=_columns(module.SESSION_READ)),
        grant_sql("link_sessions", "sft_jobs", "DELETE"),
        policy_sql("jobs_find", "link_sessions", roles=["sft_jobs"], command="SELECT", using=find),
        isolation.format("link_sessions", "sft_api, sft_jobs"),
        grant_sql("download_grants", "sft_jobs", "SELECT", columns=_columns(module.GRANT_READ)),
        grant_sql("download_grants", "sft_jobs", "UPDATE", columns=["archived_at"]),
        grant_sql("download_grants", "sft_jobs", "DELETE"),
        policy_sql(
            "jobs_find", "download_grants", roles=["sft_jobs"], command="SELECT", using=find
        ),
        isolation.format("download_grants", "sft_api, sft_jobs"),
    ]
    # The jobs never read a name, a message or a byte count of a grant.
    for listed in (module.FILE_WRITE, module.GRANT_READ, module.SESSION_READ):
        assert "display_name_ct" not in _columns(listed)
        assert "bytes_served" not in _columns(listed)


def test_the_pool_identities_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("POOL_ROWS", "0016")
    # 0006 already enabled row-level security on user_identities: the rest of tenant_rls_sql.
    assert list(module.RLS) == [
        *tenant_rls_sql(
            "user_identities",
            grants={"sft_api": "SELECT, DELETE", "sft_notify": "SELECT, INSERT, DELETE"},
        )[1:],
        grant_sql(
            "idp_connections", "sft_notify", "SELECT", columns=_columns(module.CONNECTION_READ)
        ),
        policy_sql(
            "pool_read",
            "idp_connections",
            roles=["sft_notify"],
            command="SELECT",
            using=module.POOL_ROWS,
        ),
        "ALTER POLICY audit_platform_insert ON audit_events TO sft_api, sft_operator, sft_notify",
    ]
    # The worker reads the pool's rows only: never a tenant's own provider.
    assert "tenant_id IS NULL" in module.POOL_ROWS


def test_the_jobs_find_their_work_by_indexes(migrated_db: ScratchDatabase) -> None:
    indexes = {
        str(name)
        for (name,) in migrated_db.sql(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname IN "
            "('transfers_expires_at_idx', 'transfers_last_activity_at_idx', "
            "'files_last_part_at_idx', 'files_completion_started_at_idx', "
            "'files_delete_after_idx', 'download_grants_unarchived_idx')"
        )
    }
    assert len(indexes) == 6
    [(valid,)] = migrated_db.sql(
        "SELECT convalidated FROM pg_constraint WHERE conname = 'files_deleted_check'"
    )
    assert valid is True


def test_the_invitation_backlog_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("FIND", "0017")
    assert list(module.RLS) == [
        policy_sql(
            "notify_find", "users", roles=["sft_notify"], command="SELECT", using=module.FIND
        )
    ]
    # Read only: the worker writes nothing in the system scope.
    assert "INSERT" not in module.RLS[0]
    assert "UPDATE" not in module.RLS[0]


def test_the_upload_requests_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("LOOKUP_LINK_SUBJECT_BODY", "0019")
    assert list(module.KEYS) == [
        *tenant_keys_sql("upload_requests"),
        *(
            tenant_foreign_key_sql("upload_requests", column, "users")
            for column in ("created_by", "revoked_by", "unlocked_by")
        ),
    ]
    assert [statement for _, _, statement in module.OWNER_KEYS] == [
        tenant_foreign_key_sql(table, "upload_request_id", "upload_requests", on_delete="CASCADE")
        for table in ("verification_codes", "link_sessions")
    ]
    enable, api, _, _, policy = tenant_rls_sql(
        "upload_requests",
        grants={"sft_api": "SELECT, INSERT, UPDATE", "sft_notify": "SELECT", "sft_jobs": "SELECT"},
    )
    assert list(module.RLS) == [
        enable,
        api,
        grant_sql("upload_requests", "sft_notify", "SELECT", columns=_columns(module.NOTIFY_READ)),
        grant_sql("upload_requests", "sft_notify", "UPDATE", columns=_columns(module.NOTIFY_WRITE)),
        grant_sql("upload_requests", "sft_jobs", "SELECT", columns=_columns(module.JOBS_READ)),
        grant_sql("upload_requests", "sft_jobs", "UPDATE", columns=_columns(module.JOBS_WRITE)),
        policy,
        policy_sql(
            "jobs_find",
            "upload_requests",
            roles=["sft_jobs"],
            command="SELECT",
            using="app_scope() = 'system'",
        ),
        grant_sql("verification_codes", "sft_notify", "SELECT", columns=["upload_request_id"]),
        grant_sql("link_sessions", "sft_jobs", "SELECT", columns=["upload_request_id"]),
        grant_sql("link_sessions", "sft_jobs", "UPDATE", columns=["revoked_at"]),
    ]
    # The worker never reads the message; the jobs never read an address or the message.
    assert "message_ct" not in _columns(module.NOTIFY_READ)
    assert not {"message_ct", "uploader_email", "email_normalized"} & set(
        _columns(module.JOBS_READ)
    )
    assert list(module.LOOKUPS) == [
        *lookup_read_sql("upload_requests", ["id", "tenant_id", "link_token_hash"]),
        lookup_read_sql("link_sessions", ["upload_request_id"])[0],
        *lookup_function_sql(
            "lookup_link_subject(p_token_hash bytea)",
            returns="TABLE (recipient_id uuid, upload_request_id uuid, owner_tenant_id uuid)",
            body=module.LOOKUP_LINK_SUBJECT_BODY,
        ),
        *lookup_function_sql(
            "lookup_link_subject_sessions(p_session_hashes bytea[])",
            returns="TABLE (session_id uuid, owner_tenant_id uuid, recipient_id uuid, "
            "upload_request_id uuid, live boolean)",
            body=module.LOOKUP_LINK_SUBJECT_SESSIONS_BODY,
        ),
    ]
    # 0013's function, the same but for recipients only, replaced as its owner.
    old: Any = _module("LOOKUP_LINK_SESSIONS", "0013")
    [create] = [s for s in module.RECIPIENTS_ONLY if s.startswith("CREATE OR REPLACE")]
    assert create == lookup_function_sql(
        "lookup_link_sessions(p_session_hashes bytea[])",
        returns="TABLE (session_id uuid, owner_tenant_id uuid, recipient_id uuid, live boolean)",
        body=f"{old.LOOKUP_LINK_SESSIONS_BODY} AND recipient_id IS NOT NULL",
    )[0].replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION")
    assert module.RECIPIENTS_ONLY[-1] == "REVOKE CREATE ON SCHEMA public FROM sft_lookup"
    assert list(module.AUDIT) == [require_audit_sql("upload_requests")]


def test_the_upload_request_checks_list_the_states_of_the_code() -> None:
    module: Any = _module("LOOKUP_LINK_SUBJECT_BODY", "0019")
    assert f"({module.STATES})" == sql_values(UploadRequestState)
    assert f"({module.DELIVERY_STATES})" == sql_values(DeliveryState)


def test_an_upload_request_owns_codes_and_sessions_with_valid_checks_and_indexes(
    migrated_db: ScratchDatabase,
) -> None:
    rows = migrated_db.sql(
        "SELECT conname, convalidated FROM pg_constraint WHERE conname IN "
        "('verification_codes_owner_check', 'link_sessions_owner_check', "
        "'verification_codes_tenant_id_upload_request_id_fkey', "
        "'link_sessions_tenant_id_upload_request_id_fkey')"
    )
    assert len(rows) == 4
    assert all(valid is True for _, valid in rows)
    [(definition,)] = migrated_db.sql(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'upload_requests_expires_at_idx'"
    )
    assert "WHERE (state = 'open'::text)" in str(definition)
    [(unique,)] = migrated_db.sql(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'upload_requests_link_token_hash_key'"
    )
    assert "CREATE UNIQUE INDEX" in str(unique)
    # The revision handed CREATE back: only the owner keeps it on public (CVE-2018-1058).
    [(can_create,)] = migrated_db.sql(
        "SELECT has_schema_privilege('sft_lookup', 'public', 'CREATE')"
    )
    assert can_create is False


def test_the_received_files_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("JOBS_FINDING_WRITE", "0020")
    assert [statement for _, _, statement in module.OWNER_KEYS] == [
        tenant_foreign_key_sql(
            "files", "upload_request_id", "upload_requests", on_delete="CASCADE"
        ),
        tenant_foreign_key_sql("download_grants", "user_id", "users", on_delete="CASCADE"),
        tenant_foreign_key_sql(
            "download_grants", "member_session_id", "member_sessions", on_delete="CASCADE"
        ),
    ]
    isolation = "ALTER POLICY tenant_isolation ON {} TO {}"
    assert list(module.RLS) == [
        grant_sql("files", "sft_scan", "SELECT", columns=["upload_request_id"]),
        grant_sql("upload_requests", "sft_scan", "SELECT", columns=_columns(module.SCAN_READ)),
        grant_sql("upload_requests", "sft_scan", "UPDATE", columns=_columns(module.SCAN_WRITE)),
        isolation.format("upload_requests", "sft_api, sft_notify, sft_jobs, sft_scan"),
        grant_sql("upload_requests", "sft_notify", "SELECT", columns=_columns(module.NOTICE)),
        grant_sql("upload_requests", "sft_notify", "UPDATE", columns=_columns(module.NOTICE)),
        grant_sql("upload_requests", "sft_jobs", "SELECT", columns=_columns(module.NOTICE)),
        grant_sql("upload_requests", "sft_jobs", "UPDATE", columns=_columns(module.NOTICE)),
        grant_sql("files", "sft_jobs", "SELECT", columns=_columns(module.JOBS_FILE_READ)),
        grant_sql("files", "sft_jobs", "UPDATE", columns=_columns(module.JOBS_FILE_WRITE)),
        grant_sql(
            "tenant_policies", "sft_jobs", "SELECT", columns=_columns(module.JOBS_POLICY_READ)
        ),
        isolation.format(
            "tenant_policies", "sft_operator, sft_api, sft_scan, sft_notify, sft_jobs"
        ),
        grant_sql(
            "download_grants", "sft_jobs", "SELECT", columns=_columns(module.JOBS_GRANT_READ)
        ),
        grant_sql("dlp_findings", "sft_jobs", "SELECT", columns=_columns(module.JOBS_FINDING_READ)),
        grant_sql(
            "dlp_findings", "sft_jobs", "UPDATE", columns=_columns(module.JOBS_FINDING_WRITE)
        ),
        isolation.format("dlp_findings", "sft_api, sft_scan, sft_jobs"),
    ]
    # The scan worker and the jobs read no name, message, address or finding detail; the
    # notification worker reads no message here either.
    for listed in (module.SCAN_READ, module.JOBS_FILE_READ, module.JOBS_FINDING_READ):
        assert not {"display_name_ct", "message_ct", "uploader_email", "detail_ct"} & set(
            _columns(listed)
        )


def test_received_files_have_one_owner_with_valid_checks_keys_and_indexes(
    migrated_db: ScratchDatabase,
) -> None:
    names = (
        "files_owner_check",
        "files_retention_until_check",
        "files_dlp_blocked_check",
        "files_tenant_id_upload_request_id_fkey",
        "download_grants_owner_check",
        "download_grants_tenant_id_user_id_fkey",
        "download_grants_tenant_id_member_session_id_fkey",
        "upload_requests_notice_counts_check",
    )
    rows = dict(
        migrated_db.sql(
            "SELECT conname, convalidated FROM pg_constraint WHERE conname = ANY(:names)",
            names=list(names),
        )
    )
    assert set(rows) == set(names)
    assert all(valid is True for valid in rows.values())
    indexes = {
        name
        for (name,) in migrated_db.sql(
            "SELECT indexname FROM pg_indexes WHERE indexname IN "
            "('files_tenant_id_upload_request_id_idx', 'download_grants_user_id_idx', "
            "'download_grants_member_session_id_idx')"
        )
    }
    assert len(indexes) == 3
    nullable = dict(
        migrated_db.sql(
            "SELECT table_name || '.' || column_name, is_nullable FROM information_schema.columns "
            "WHERE (table_name, column_name) IN (('files', 'transfer_id'), "
            "('download_grants', 'recipient_id'), ('download_grants', 'link_session_id'))"
        )
    )
    assert set(nullable.values()) == {"YES"}


def test_the_api_keys_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("LOOKUP_API_KEY", "0021")
    assert list(module.KEYS) == [
        *tenant_keys_sql("api_keys"),
        tenant_foreign_key_sql("api_keys", "created_by", "users"),
    ]
    find = "app_scope() = 'system'"
    assert list(module.RLS) == [
        *tenant_rls_sql("api_keys", grants={"sft_api": "SELECT, INSERT, UPDATE"}),
        grant_sql("api_keys", "sft_jobs", "SELECT", columns=_columns(module.JOBS_READ)),
        grant_sql("api_keys", "sft_jobs", "UPDATE", columns=["expiry_notice"]),
        policy_sql("jobs_find", "api_keys", roles=["sft_jobs"], command="SELECT", using=find),
        grant_sql("api_keys", "sft_notify", "SELECT", columns=_columns(module.NOTIFY_READ)),
        "ALTER POLICY tenant_isolation ON api_keys TO sft_api, sft_jobs, sft_notify",
    ]
    assert list(module.LOOKUP_API_KEY) == [
        *lookup_read_sql("api_keys", ["id", "tenant_id", "key_hash"]),
        *lookup_function_sql(
            "lookup_api_key(p_key_hash bytea)",
            returns="TABLE (api_key_id uuid, owner_tenant_id uuid)",
            body=module.LOOKUP_API_KEY_BODY,
        ),
    ]
    assert (
        require_audit_sql("api_keys", commands=("INSERT", "UPDATE"), update_of=("revoked_at",))
        == module.AUDIT
    )
    # The jobs and the notification worker never read a key's hash or its name.
    for listed in (module.JOBS_READ, module.NOTIFY_READ):
        assert "key_hash" not in _columns(listed)
        assert "name" not in _columns(listed)


def test_the_api_key_checks_list_the_scopes_and_reasons_of_the_code() -> None:
    module: Any = _module("LOOKUP_API_KEY", "0021")
    assert sql_values(ApiKeyScope)[1:-1] == module.SCOPES
    source = Path(str(SCRIPTS.get_revision("0021").path)).read_text()
    assert f"revoked_reason IN {sql_values(ApiKeyRevokedReason)}" in source


def test_the_domain_rules_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("RLS", "0023")
    assert list(module.RLS) == [
        grant_sql("email_suppressions", "sft_api", "UPDATE", columns=["expires_at", "updated_at"])
    ]


def test_the_email_search_finds_recipients_by_an_index(migrated_db: ScratchDatabase) -> None:
    [(valid,)] = migrated_db.sql(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "WHERE c.relname = 'transfer_recipients_tenant_id_email_normalized_idx'"
    )
    assert valid is True


def test_the_dlp_policy_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("DEFAULT_RULES", "0024")
    assert list(module.KEYS) == [
        tenant_keys_sql("dlp_policies")[0],
        tenant_foreign_key_sql("dlp_policies", "updated_by", "users"),
        tenant_keys_sql("dlp_rules")[0],
        tenant_foreign_key_sql("dlp_rules", "created_by", "users"),
        tenant_keys_sql("dlp_detectors")[0],
        tenant_foreign_key_sql("dlp_detectors", "created_by", "users"),
    ]

    def jobs_find(table: str) -> str:
        return policy_sql(
            "jobs_find", table, roles=["sft_jobs"], command="SELECT", using="app_scope() = 'system'"
        )

    readers = {"sft_scan": "SELECT"}
    assert list(module.RLS) == [
        *tenant_rls_sql(
            "dlp_policies",
            grants={
                "sft_api": "SELECT, INSERT, UPDATE",
                "sft_operator": "INSERT",
                **readers,
                "sft_jobs": "SELECT",
            },
        ),
        grant_sql("dlp_policies", "sft_operator", "SELECT", columns=["tenant_id"]),
        *tenant_rls_sql(
            "dlp_rules",
            grants={
                "sft_api": "SELECT, INSERT",
                "sft_operator": "INSERT",
                **readers,
                "sft_jobs": "SELECT, DELETE",
            },
        ),
        grant_sql("dlp_rules", "sft_api", "UPDATE", columns=["retired_at"]),
        jobs_find("dlp_rules"),
        *tenant_rls_sql(
            "dlp_detectors",
            grants={"sft_api": "SELECT, INSERT", **readers, "sft_jobs": "SELECT, DELETE"},
        ),
        grant_sql("dlp_detectors", "sft_api", "UPDATE", columns=["retired_at"]),
        jobs_find("dlp_detectors"),
        grant_sql("dlp_findings", "sft_jobs", "SELECT", columns=["tenant_id", "detector"]),
        jobs_find("dlp_findings"),
        "ALTER POLICY tenant_isolation ON dlp_findings TO sft_api, sft_scan, sft_jobs",
    ]
    assert list(module.AUDIT) == [
        require_audit_sql(table) for table in ("dlp_policies", "dlp_rules", "dlp_detectors")
    ]
    # The API changes a revision's `retired_at` only: rules and detectors are never edited.
    assert "UPDATE ON dlp_rules" not in " ".join(module.RLS)
    # The checks list the values of the code.
    for listed, values in (
        (module.MODES, DlpMode),
        (module.DIRECTIONS, DlpDirection),
        (module.CONDITIONS, DlpCondition),
        (module.CONFIDENCES, DlpConfidence),
        (module.SCOPES, DlpRecipientScope),
        (module.ACTIONS, DlpAction),
        (module.REASONS, InspectionReason),
        (module.KINDS, DlpDetectorKind),
    ):
        assert f"({listed})" == sql_values(values)


def _upgrade(db: ScratchDatabase, revision: str) -> None:
    engine = sync_engine(db.url(MIGRATE))
    try:
        with engine.connect() as connection:
            become_owner(connection)
            command.upgrade(alembic_config(connection), revision)
    finally:
        engine.dispose()


def test_the_dlp_policy_revision_gives_every_tenant_the_default_policy(
    empty_db: ScratchDatabase,
) -> None:
    _upgrade(empty_db, "0017")
    japanese, empty = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    for tenant in (japanese, empty):
        empty_db.sql(
            "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant
        )
    empty_db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja')", t=japanese
    )
    member, admin = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
    for user, role in ((member, "member"), (admin, "admin")):
        empty_db.sql(
            "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
            "VALUES (:id, :t, :email, :email, :role, 'active')",
            id=user,
            t=japanese,
            email=f"{role}@example.test",
            role=role,
        )
    _upgrade(empty_db, "head")
    policies = empty_db.sql(
        "SELECT tenant_id::text, version, mode, approval_timeout = interval '72 hours' "
        "FROM dlp_policies ORDER BY 1"
    )
    assert policies == [(japanese, 1, "enforce", True), (empty, 1, "enforce", True)]
    rules = empty_db.sql(
        "SELECT tenant_id::text, name, created_by::text, revision FROM dlp_rules "
        "ORDER BY tenant_id, id"
    )
    assert len(rules) == 16
    by_tenant = {t: [r for r in rules if r[0] == t] for t in (japanese, empty)}
    assert [r[1] for r in by_tenant[japanese]][:2] == ["認証情報と秘密鍵", "マイナンバー"]
    assert [r[1] for r in by_tenant[empty]][-1] == "New recipient domain"
    # The earliest admin, else the earliest user, else no one, made the rules.
    assert {r[2] for r in by_tenant[japanese]} == {admin}
    assert {r[2] for r in by_tenant[empty]} == {None}
    assert {r[3] for r in rules} == {1}


def test_the_dlp_decision_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("DECISION_KEY", "0025")
    assert list(module.KEYS) == [
        *tenant_keys_sql("dlp_decisions"),
        tenant_foreign_key_sql("dlp_decisions", "transfer_id", "transfers", on_delete="CASCADE"),
        tenant_foreign_key_sql("dlp_decisions", "file_id", "files", on_delete="CASCADE"),
        tenant_keys_sql("dlp_decision_rules")[0],
        tenant_foreign_key_sql(
            "dlp_decision_rules", "decision_id", "dlp_decisions", on_delete="CASCADE"
        ),
        # By hand: the revision's key is (tenant_id, id, revision), and no ON DELETE, so a rule
        # revision a decision applied stays.
        "ALTER TABLE dlp_decision_rules ADD CONSTRAINT "
        "dlp_decision_rules_tenant_id_rule_id_rule_revision_fkey "
        "FOREIGN KEY (tenant_id, rule_id, rule_revision) "
        "REFERENCES dlp_rules (tenant_id, id, revision)",
        *tenant_keys_sql("dlp_confirmations"),
        tenant_foreign_key_sql(
            "dlp_confirmations", "transfer_id", "transfers", on_delete="CASCADE"
        ),
        tenant_foreign_key_sql(
            "dlp_confirmations", "decision_id", "dlp_decisions", on_delete="CASCADE"
        ),
        tenant_foreign_key_sql("dlp_confirmations", "confirmed_by", "users"),
        tenant_keys_sql("dlp_known_domains")[0],
    ]
    assert (
        tenant_foreign_key_sql("transfers", "dlp_decision_id", "dlp_decisions")
        == module.DECISION_KEY
    )

    def jobs_find(table: str) -> str:
        return policy_sql(
            "jobs_find", table, roles=["sft_jobs"], command="SELECT", using="app_scope() = 'system'"
        )

    deciders = {"sft_api": "SELECT, INSERT", "sft_scan": "INSERT", "sft_jobs": "INSERT"}
    assert list(module.RLS) == [
        *tenant_rls_sql("dlp_decisions", grants=deciders),
        *tenant_rls_sql("dlp_decision_rules", grants=deciders),
        grant_sql(
            "dlp_decision_rules",
            "sft_jobs",
            "SELECT",
            columns=["tenant_id", "rule_id", "rule_revision"],
        ),
        jobs_find("dlp_decision_rules"),
        *tenant_rls_sql("dlp_confirmations", grants={"sft_api": "SELECT, INSERT"}),
        *tenant_rls_sql(
            "dlp_known_domains",
            grants={
                "sft_api": "SELECT, INSERT, UPDATE",
                "sft_scan": "SELECT, INSERT, UPDATE",
                "sft_jobs": "SELECT, INSERT, UPDATE, DELETE",
            },
        ),
        jobs_find("dlp_known_domains"),
        grant_sql("transfers", "sft_scan", "SELECT, UPDATE", columns=["dlp_decision_id"]),
        grant_sql("transfer_recipients", "sft_scan", "SELECT", columns=["domain"]),
        grant_sql("transfers", "sft_jobs", "SELECT, UPDATE", columns=["dlp_decision_id"]),
        grant_sql("transfer_recipients", "sft_jobs", "SELECT", columns=["domain"]),
        grant_sql(
            "dlp_findings",
            "sft_scan",
            "SELECT",
            columns=["tenant_id", "file_id", "detector", "count_low", "count_medium", "count_high"],
        ),
        grant_sql(
            "dlp_findings",
            "sft_jobs",
            "SELECT",
            columns=["file_id", "count_low", "count_medium", "count_high"],
        ),
    ]
    assert list(module.AUDIT) == [
        require_audit_sql(table)
        for table in (
            "dlp_decisions",
            "dlp_decision_rules",
            "dlp_confirmations",
            "dlp_known_domains",
        )
    ]
    # The evaluation's roles never read a finding's details, nor an address.
    assert "detail_ct" not in " ".join(module.RLS)
    assert "email" not in " ".join(module.RLS)
    for listed, values in (
        (module.MODES, DlpMode),
        (module.OUTCOMES, DlpOutcome),
        (module.ACTIONS, DlpAction),
    ):
        assert f"({listed})" == sql_values(values)


def test_the_dlp_approval_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("REQUEST_JOBS_COLUMNS", "0026")
    requests, decisions = "dlp_approval_requests", "dlp_approval_decisions"
    assert list(module.KEYS) == [
        *tenant_keys_sql(requests),
        tenant_foreign_key_sql(requests, "transfer_id", "transfers", on_delete="CASCADE"),
        tenant_foreign_key_sql(requests, "decision_id", "dlp_decisions", on_delete="CASCADE"),
        tenant_foreign_key_sql(
            requests, "confirmation_id", "dlp_confirmations", on_delete="CASCADE"
        ),
        tenant_foreign_key_sql(requests, "requested_by", "users"),
        tenant_keys_sql(decisions)[0],
        tenant_foreign_key_sql(decisions, "approval_request_id", requests, on_delete="CASCADE"),
        tenant_foreign_key_sql(decisions, "approver_id", "users"),
    ]
    assert list(module.RLS) == [
        *tenant_rls_sql(requests, grants={"sft_api": "SELECT, INSERT"}),
        grant_sql(requests, "sft_api", "UPDATE", columns=["state", "ended_at"]),
        grant_sql(requests, "sft_jobs", "SELECT", columns=_columns(module.REQUEST_JOBS_COLUMNS)),
        grant_sql(requests, "sft_jobs", "UPDATE", columns=["state", "ended_at"]),
        grant_sql(
            requests, "sft_notify", "SELECT", columns=_columns(module.REQUEST_NOTIFY_COLUMNS)
        ),
        f"ALTER POLICY tenant_isolation ON {requests} TO sft_api, sft_jobs, sft_notify",
        policy_sql(
            "jobs_find",
            requests,
            roles=["sft_jobs"],
            command="SELECT",
            using="app_scope() = 'system'",
        ),
        *tenant_rls_sql(decisions, grants={"sft_api": "SELECT, INSERT"}),
    ]
    assert list(module.AUDIT) == [require_audit_sql(requests), require_audit_sql(decisions)]
    # The system roles read no justification, comment or decision, and sft_jobs never the sender.
    assert _columns(module.REQUEST_JOBS_COLUMNS) == [
        "id",
        "tenant_id",
        "transfer_id",
        "state",
        "expires_at",
    ]
    assert _columns(module.REQUEST_NOTIFY_COLUMNS) == ["id", "tenant_id", "transfer_id", "state"]
    assert "comment" not in " ".join(module.RLS)
    assert f"({module.STATES})" == sql_values(ApprovalState)
    assert f"({module.DECISIONS})" == sql_values(ApprovalDecisionKind)


def test_the_notice_windows_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    from sft.data.audit_required import NOT_AUDITED
    from sft.data.models import NoticeKind
    from sft.data.outbox import DLP_POLICY_CHANGES

    module: Any = _module("NOTICES", "0028")
    table = "notice_windows"
    assert list(module.KEYS) == [
        tenant_keys_sql(table)[0],
        tenant_foreign_key_sql(table, "user_id", "users"),
    ]
    assert list(module.RLS) == tenant_rls_sql(
        table, grants={"sft_notify": "SELECT, INSERT, UPDATE"}
    )
    assert f"({module.NOTICES})" == sql_values(NoticeKind)
    assert ", ".join(f"'{change}'" for change in DLP_POLICY_CHANGES) == module.CHANGES
    # Only the notification worker keeps it, and its changes need no audit event (#230).
    assert table in NOT_AUDITED
    assert "sft_api" not in " ".join(module.RLS)


def test_a_notice_window_is_one_per_tenant_kind_and_approver(migrated_db: ScratchDatabase) -> None:
    tenant = "88888888-8888-4888-8888-888888888888"
    migrated_db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant)
    insert = (
        "INSERT INTO notice_windows (id, tenant_id, notice) "
        "VALUES (gen_random_uuid(), :t, 'dlp_policy_changed') ON CONFLICT DO NOTHING"
    )
    migrated_db.sql(insert, t=tenant)
    migrated_db.sql(insert, t=tenant)
    assert migrated_db.sql(
        "SELECT count(*) FROM notice_windows WHERE tenant_id = :t", t=tenant
    ) == [(1,)]


def test_a_recipients_domain_is_set_on_insert(migrated_db: ScratchDatabase) -> None:
    # Revision 0025's trigger: the evaluation's roles read the domain, never the address.
    tenant = "55555555-5555-4555-8555-555555555555"
    user = "66666666-6666-4666-8666-666666666666"
    transfer = "77777777-7777-4777-8777-777777777777"
    migrated_db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant)
    migrated_db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :t, 'a@example.test', 'a@example.test', 'member', 'active')",
        id=user,
        t=tenant,
    )
    migrated_db.sql(
        "INSERT INTO transfers (id, tenant_id, created_by, state, expires_in) "
        "VALUES (:id, :t, :u, 'draft', interval '1 day')",
        id=transfer,
        t=tenant,
        u=user,
    )
    migrated_db.sql(
        "INSERT INTO transfer_recipients (id, tenant_id, transfer_id, email, email_normalized, "
        "locale) VALUES (gen_random_uuid(), :t, :x, 'Bo@Sub.Partner.Example', "
        "'bo@sub.partner.example', 'en')",
        t=tenant,
        x=transfer,
    )
    assert migrated_db.sql(
        "SELECT domain FROM transfer_recipients WHERE transfer_id = :x", x=transfer
    ) == [("sub.partner.example",)]


def test_the_dlp_should_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module: Any = _module("MESSAGE_KEY", "0027")
    stops = "dlp_pattern_stops"
    assert list(module.KEYS) == [tenant_keys_sql(stops)[0]]
    assert (
        tenant_foreign_key_sql("dlp_findings", "transfer_id", "transfers", on_delete="CASCADE")
        == module.MESSAGE_KEY
    )
    assert list(module.RLS) == [
        *tenant_rls_sql(stops, grants={"sft_api": "SELECT", "sft_scan": "SELECT, INSERT, UPDATE"}),
        grant_sql("dlp_findings", "sft_api", "INSERT"),
        grant_sql("dlp_findings", "sft_scan", "SELECT", columns=["transfer_id"]),
        grant_sql("dlp_findings", "sft_jobs", "SELECT", columns=["transfer_id"]),
        grant_sql("files", "sft_scan", "SELECT, UPDATE", columns=["dlp_blocked"]),
    ]
    assert list(module.AUDIT) == [require_audit_sql(stops)]
    # Nobody new reads a finding's details.
    assert "detail_ct" not in " ".join(module.RLS)


def test_the_tenant_sso_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # #231. Found by its contents, not its number.
    [module] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "LOOKUP_SSO_DOMAIN_BODY")
    ]
    domains, roles_table = "sso_domains", "sso_group_roles"
    assert list(module.KEYS) == [
        *tenant_keys_sql(domains),
        tenant_foreign_key_sql(domains, "idp_connection_id", "idp_connections"),
        tenant_foreign_key_sql(domains, "created_by", "users"),
        *tenant_keys_sql(roles_table),
    ]
    dlp_read = _columns(module.DLP_READ_COLUMNS)
    assert list(module.RLS) == [
        *tenant_rls_sql(
            domains, grants={"sft_api": "SELECT, INSERT, UPDATE, DELETE", "sft_operator": "SELECT"}
        ),
        grant_sql(domains, "sft_operator", "UPDATE", columns=["idp_connection_id", "updated_at"]),
        grant_sql(domains, "sft_scan", "SELECT", columns=dlp_read),
        grant_sql(domains, "sft_jobs", "SELECT", columns=dlp_read),
        f"ALTER POLICY tenant_isolation ON {domains} TO sft_api, sft_operator, sft_scan, sft_jobs",
        *lookup_read_sql(domains, _columns(module.LOOKUP_COLUMNS)),
        *lookup_function_sql(
            "lookup_sso_domain(p_domain text)",
            returns="TABLE (connection_id uuid, owner_tenant_id uuid, provider_name text, "
            "status text)",
            body=module.LOOKUP_SSO_DOMAIN_BODY,
        ),
        *tenant_rls_sql(roles_table, grants={"sft_api": "SELECT, INSERT, DELETE"}),
        grant_sql("idp_connections", "sft_operator", "SELECT, INSERT, UPDATE"),
        grant_sql("idp_connections", "sft_api", "SELECT"),
        policy_sql(
            "tenant_isolation",
            "idp_connections",
            roles=["sft_api", "sft_operator"],
            using="tenant_id = app_tenant_id()",
            with_check="tenant_id = app_tenant_id()",
        ),
        grant_sql("user_identities", "sft_api", "INSERT"),
        grant_sql("tenants", "sft_api", "UPDATE", columns=_columns(module.TENANT_SSO_COLUMNS)),
    ]
    assert list(module.AUDIT) == [require_audit_sql(domains), require_audit_sql(roles_table)]
    # The DLP roles read a proven domain's name, never its token; the lookup returns no token.
    assert "verification_token" not in module.DLP_READ_COLUMNS + module.LOOKUP_COLUMNS
    assert f"{module.ROLES}" == sql_values(Role)


def test_the_break_glass_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # #232: the operator's platform table, and the person's read-only role, policy by policy.
    [module] = [s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "READ_TABLES")]
    assert list(module.GRANTS) == [
        grant_sql("break_glass_grants", "sft_operator", "SELECT, INSERT, UPDATE")
    ]
    expected = []
    for table in module.READ_TABLES:
        key = "id" if table == "tenants" else "tenant_id"
        expected += [
            grant_sql(table, "sft_breakglass", "SELECT"),
            policy_sql(
                "break_glass_read",
                table,
                roles=["sft_breakglass"],
                command="SELECT",
                using=f"{key} = ANY (break_glass_tenants())",
            ),
        ]
    assert list(module.RLS) == expected
    assert (
        f"({', '.join(repr(s.value) for s in BreakGlassState)})".replace('"', "'") == module.STATES
    )


def test_break_glass_reaches_nothing_without_an_active_grant(migrated_db: ScratchDatabase) -> None:
    # The function the policies call: with no grant named it reaches no tenant
    # (tests/test_break_glass.py tries an unknown grant, an ended one and an expired one).
    rows = migrated_db.sql("SELECT cardinality(break_glass_tenants())")
    assert rows == [(0,)]


def test_the_break_glass_records_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # #239: the drift check's platform read of tenants' connections, and a break-glass function
    # that a grant recorded from Identity Center never satisfies. Found by its contents.
    [module] = [s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "SSO_DRIFT_READ")]
    assert list(module.SSO_DRIFT_READ) == [
        policy_sql(
            "sso_drift_read",
            "idp_connections",
            roles=["sft_operator"],
            command="SELECT",
            using="app_scope() = 'platform' AND tenant_id IS NOT NULL",
        )
    ]
    [revision_0030] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "READ_TABLES")
    ]
    # Revision 0030's body with one more condition, nothing else.
    expected = revision_0030.BREAK_GLASS_TENANTS_BODY.replace(
        "AND g.state = 'active' ", "AND g.state = 'active' AND g.recorded_by = 'service' "
    )
    assert expected == module.BREAK_GLASS_TENANTS_BODY


def test_a_recorded_grant_is_not_a_service_grant(migrated_db: ScratchDatabase) -> None:
    [(body,)] = migrated_db.sql("SELECT prosrc FROM pg_proc WHERE proname = 'break_glass_tenants'")
    assert "recorded_by = 'service'" in str(body)


def test_the_operator_keys_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # #160: the operator's own idempotency keys, in a tenant's scope and found in platform scope.
    [module] = [s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "OPERATOR_KEYS")]
    assert list(module.OPERATOR_KEYS) == [
        grant_sql("idempotency_keys", "sft_operator", "SELECT, INSERT, UPDATE"),
        policy_sql(
            "operator_keys",
            "idempotency_keys",
            roles=["sft_operator"],
            using=module.OPERATOR_TENANT,
            with_check=module.OPERATOR_TENANT,
        ),
        policy_sql(
            "operator_find",
            "idempotency_keys",
            roles=["sft_operator"],
            command="SELECT",
            using="app_scope() = 'platform' AND caller_type = 'operator'",
        ),
    ]


def test_the_admin_recovery_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # #239: the recoveries, and what the operator, the worker and the job need for them.
    [module] = [
        s.module for s in SCRIPTS.walk_revisions() if hasattr(s.module, "ADMIN_RECOVERIES_RLS")
    ]
    table = "admin_recoveries"
    enable, operator, notify, jobs, policy = tenant_rls_sql(
        table,
        grants={"sft_operator": "SELECT, INSERT", "sft_notify": "SELECT", "sft_jobs": "SELECT"},
    )
    assert list(module.ADMIN_RECOVERIES_RLS) == [
        *tenant_keys_sql(table),
        tenant_foreign_key_sql(table, "user_id", "users"),
        enable,
        operator,
        notify,
        jobs,
        policy,
        grant_sql(table, "sft_jobs", "UPDATE", columns=["ended_at"]),
        policy_sql(
            "jobs_find", table, roles=["sft_jobs"], command="SELECT", using="app_scope() = 'system'"
        ),
        require_audit_sql(table),
    ]
    tenant_rows = "tenant_id = app_tenant_id()"
    assert list(module.OPERATOR_RECOVERY) == [
        grant_sql("users", "sft_operator", "UPDATE", columns=["sign_in_reset_id", "updated_at"]),
        grant_sql("member_sessions", "sft_operator", "SELECT", columns=["user_id"]),
        grant_sql(
            "user_identities",
            "sft_operator",
            "SELECT",
            columns=["id", "tenant_id", "user_id", "idp_connection_id"],
        ),
        grant_sql("user_identities", "sft_operator", "DELETE"),
        policy_sql(
            "operator_recovery", "user_identities", roles=["sft_operator"], using=tenant_rows
        ),
        grant_sql(
            "audit_events", "sft_operator", "SELECT", columns=list(module.OPERATOR_AUDIT_COLUMNS)
        ),
        policy_sql(
            "operator_read_own_critical",
            "audit_events",
            roles=["sft_operator"],
            command="SELECT",
            using=f"{tenant_rows} AND actor_type = 'operator' AND security_critical",
        ),
    ]
    assert list(module.JOBS_TEMPORARY) == [
        grant_sql(
            "user_identities",
            "sft_jobs",
            "SELECT",
            columns=["id", "tenant_id", "user_id", "idp_connection_id", "expires_at"],
        ),
        grant_sql("user_identities", "sft_jobs", "DELETE"),
        policy_sql("jobs_temporary", "user_identities", roles=["sft_jobs"], using=tenant_rows),
    ]
    assert f"({', '.join(repr(k.value) for k in AdminRecoveryKind)})" == module.KINDS
