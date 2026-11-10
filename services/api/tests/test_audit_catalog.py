"""Catalog checks for the audit trail after `upgrade head`, so every later table meets them too."""

import re
from pathlib import Path

from alembic.script import ScriptDirectory

import sft
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
    # pg_temp goes last, explicitly: left out, it is searched first, so a caller's temporary
    # table could stand in for one of ours.
    rows = migrated_db.sql(
        """
        SELECT p.proname,
               coalesce('search_path=pg_catalog, public, pg_temp' = ANY(p.proconfig), false),
               p.proacl IS NULL OR EXISTS (
                   SELECT FROM aclexplode(p.proacl) a WHERE a.grantee = 0)
          FROM pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace AND p.prosecdef
        """
    )
    assert rows, "no definer functions: the check would pass by checking nothing"
    for name, pinned, public in rows:
        assert pinned, f"{name} doesn't pin search_path to pg_catalog, public, pg_temp"
        assert not public, f"every role may execute {name}"


# Every column but tx_id and occurred_at, which only the database sets (and sft_recovery, which
# re-imports archived events with their own values).
WRITER_COLUMNS = [
    "id",
    "tenant_id",
    "actor_type",
    "actor_id",
    "action",
    "target_type",
    "target_id",
    "outcome",
    "source_ip",
    "user_agent",
    "request_id",
    "trace_id",
    "security_critical",
    "details",
]


def test_0002_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # 0002 was written by pasting this output. If a helper changes on purpose, 0002 must not:
    # replace the calls below with the old output, as literals, and keep the test.
    revision = ScriptDirectory.from_config(alembic_config()).get_revision("0002").module
    writers = ["sft_api", "sft_scan", "sft_notify", "sft_jobs", "sft_operator"]
    assert list(revision.AUDIT_EVENTS_RLS) == [
        "ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY",
        *(grant_sql("audit_events", role, "INSERT", columns=WRITER_COLUMNS) for role in writers),
        grant_sql("audit_events", "sft_api", "SELECT"),
        grant_sql("audit_events", "sft_archive", "SELECT"),
        grant_sql("audit_events", "sft_recovery", "INSERT"),
        policy_sql(
            "audit_tenant_insert",
            "audit_events",
            roles=writers,
            command="INSERT",
            with_check="tenant_id = app_tenant_id() AND app_scope() IN ('tenant', 'resource')",
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
            using="tenant_id = app_tenant_id() AND app_scope() = 'tenant'",
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


# The audit actions sending and scanning add (#174 to #176), each with the audited tables whose
# changes its event covers in the same transaction (FR-27, NFR-15).
SEND_AND_SCAN_ACTIONS = {
    "transfer.submitted": ("transfers",),
    "transfer.sent": ("transfers", "transfer_recipients", "download_counters"),
    "transfer.held": ("transfers",),
    "transfer.returned_to_draft": ("transfers",),
    "transfer.cancelled": ("transfers", "files"),
    "tenant_policy.updated": ("tenant_policies",),
    "file.scanned": ("files", "dlp_findings"),
}


def test_the_send_and_scan_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in SEND_AND_SCAN_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions downloads and the lifecycle jobs add (#180, #181), with the audited tables
# whose changes each covers in its transaction.
DOWNLOAD_AND_LIFECYCLE_ACTIONS = {
    "download.granted": ("download_grants", "download_counters"),
    "download.resumed": (),
    "download.refused": (),
    "download.completed": (),
    "download.stopped": (),
    "transfer.revoked": ("transfers", "link_sessions", "files"),
    "transfer.expired": ("transfers", "files"),
    "file.deleted": ("files",),
    "retention.rows_deleted": ("verification_codes",),
}


def test_the_download_and_lifecycle_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in DOWNLOAD_AND_LIFECYCLE_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source or f'ACTION: Final = "{action}"' in source, action
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of extending a transfer's expiry and the first-download notice (#214), with the
# audited tables whose changes each covers in its transaction. `download.granted` also covers the
# transfer's `first_download_notified_at`, set in the grant's transaction; the worker's notice is
# `email.sent`.
EXTENSION_AND_NOTICE_ACTIONS = {
    "transfer.expiry_extended": ("transfers", "link_sessions", "download_grants"),
    "download.granted": ("transfers",),
    "email.sent": (),
}


def test_the_extension_and_notice_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in EXTENSION_AND_NOTICE_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source or f'ACTION: Final = "{action}"' in source, action
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of upload requests and their uploaders (#212), with the audited tables whose
# changes each covers in its transaction. The link steps' existing actions (`verification.*`,
# `link_session.*`) and `email.sent` cover an uploader's codes, sessions and link email too.
UPLOAD_REQUEST_ACTIONS = {
    "upload_request.created": ("upload_requests",),
    "upload_request.revoked": ("upload_requests", "link_sessions"),
    "upload_request.expired": ("upload_requests", "link_sessions"),
    "uploader.link_issued": ("upload_requests",),
    "uploader.locked": ("upload_requests",),
    "uploader.unlocked": ("upload_requests",),
    "uploader.suppressed": ("upload_requests",),
    "verification.code_created": ("verification_codes",),
    "verification.attempted": ("verification_codes", "upload_requests"),
    "link_session.started": ("link_sessions",),
    "link_session.ended": ("link_sessions",),
    "email.sent": ("upload_requests",),
}


def test_the_upload_request_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    assert audited["upload_requests"], "upload_requests changes without the audit trigger"
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in UPLOAD_REQUEST_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of received files (#213), with the audited tables whose changes each covers in
# its transaction. The uploader's file events are the member's (`file.*`, actor type `uploader`);
# a scan result also adds to its request's notice counts, a revocation or an expiry rejects the
# request's open uploads, and the deletion job clears a deleted file's finding details.
RECEIVED_FILE_ACTIONS = {
    "file.added": ("files",),
    "file.part_urls_issued": ("files",),
    "file.completion_started": ("files",),
    "file.upload_incomplete": ("files",),
    "file.uploaded": ("files",),
    "file.scanned": ("files", "dlp_findings", "upload_requests"),
    "file.rejected": ("files",),
    "file.removed": ("files",),
    "file.deleted": ("files", "dlp_findings"),
    "upload_request.revoked": ("upload_requests", "link_sessions", "files"),
    "upload_request.expired": ("upload_requests", "link_sessions", "files"),
    "upload_request.notice_sent": ("upload_requests",),
    "download.granted": ("download_grants",),
    "download.resumed": (),
    "download.refused": (),
}


def test_the_received_file_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in RECEIVED_FILE_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of API keys, audit reads and the domain rules (#215, #216, #217), with the
# audited tables whose changes each covers in its transaction.
ADMINISTRATION_ACTIONS = {
    "api_key.created": ("api_keys",),
    "api_key.revoked": ("api_keys",),
    "api_key.used": (),
    "api_key.expiry_notice_queued": (),
    "audit.searched": (),
    "audit.exported": (),
    "tenant_policy.updated": ("tenant_policies",),
    "email_suppression.cleared": ("email_suppressions",),
    "email_suppression.released": ("email_suppressions",),
    "email.sent": (),
}


def test_the_administration_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in ADMINISTRATION_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source or f'ACTION: Final = "{action}"' in source, action
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of the DLP policy (#218), with the audited tables whose changes each covers in
# its transaction; `retention.rows_deleted` covers the cleanup's deletions of retired revisions.
DLP_POLICY_ACTIONS = {
    "dlp_policy.updated": ("dlp_policies",),
    "dlp_rule.created": ("dlp_rules", "dlp_policies"),
    "dlp_rule.changed": ("dlp_rules", "dlp_policies"),
    "dlp_rule.deleted": ("dlp_rules", "dlp_policies"),
    "dlp_detector.created": ("dlp_detectors", "dlp_policies"),
    "dlp_detector.changed": ("dlp_detectors", "dlp_policies"),
    "dlp_detector.deleted": ("dlp_detectors", "dlp_policies"),
    "tenant.created": ("dlp_policies", "dlp_rules"),
    "retention.rows_deleted": ("dlp_rules", "dlp_detectors"),
}


def test_the_dlp_policy_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in DLP_POLICY_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of the DLP decision (#219), with the audited tables whose changes each covers
# in its transaction: the decision and its rules with the transfer's state, the confirmation, the
# known domains a send records, and the cleanup's deletions of known domains.
DLP_DECISION_ACTIONS = {
    "dlp.decided": ("dlp_decisions", "dlp_decision_rules", "transfers"),
    "dlp.rule_matched": ("dlp_decision_rules",),
    "transfer.awaiting_confirmation": ("transfers",),
    "transfer.held": ("transfers",),
    "transfer.confirmed": ("dlp_confirmations",),
    "transfer.sent": ("transfers", "dlp_known_domains"),
    "retention.rows_deleted": ("dlp_known_domains",),
}


def test_the_dlp_decision_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in DLP_DECISION_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of DLP approvals (#220), with the audited tables whose changes each covers in
# its transaction: the request with its confirmation and the transfer's state; each approver's
# decision with the request's end and the transfer's; the withdrawals and expiries; the approver
# designation.
DLP_APPROVAL_ACTIONS = {
    "dlp_approval.requested": ("dlp_approval_requests", "dlp_confirmations", "transfers"),
    "dlp_approval.approved": ("dlp_approval_decisions", "dlp_approval_requests"),
    "dlp_approval.rejected": ("dlp_approval_decisions", "dlp_approval_requests", "transfers"),
    "dlp_approval.expired": ("dlp_approval_requests", "transfers"),
    "dlp_approval.withdrawn": ("dlp_approval_requests",),
    "transfer.held": ("transfers",),
    "transfer.sent": ("transfers", "dlp_known_domains"),
    "transfer.awaiting_confirmation": ("transfers",),
    "user.dlp_approver_changed": ("users",),
}


def test_the_dlp_approval_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in DLP_APPROVAL_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of #228 to #230, with the audited tables whose changes each covers in its
# transaction: an uploader's bounced email marks the request and suppresses the address; the
# uploader's removal takes a file off and off its request's notice; a deactivation clears the
# approver designation and writes its notice message. The notice windows are `NOT_AUDITED`.
M5_REST_ACTIONS = {
    "email.bounced": ("upload_requests", "transfer_recipients"),
    "email.suppressed": ("email_suppressions",),
    "file.removed": ("files", "upload_requests"),
    "user.deactivated": ("users",),
    "email.sent": (),
}


def test_the_m5_rest_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    assert not audited["notice_windows"]
    assert "notice_windows" in NOT_AUDITED
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in M5_REST_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of DLP-6 and DLP-7 (#221, #222), with the audited tables whose changes each
# covers in its transaction: a received file's decision and its block (with `file.scanned`), the
# message's findings (with `transfer.created`), a pattern's budget stops, and the reads that are
# audited though they change nothing.
DLP_SHOULD_ACTIONS = {
    "dlp.decided": ("dlp_decisions", "dlp_decision_rules"),
    "dlp.rule_matched": ("dlp_decision_rules",),
    "file.scanned": ("files", "dlp_findings"),
    "transfer.created": ("transfers", "dlp_findings"),
    "dlp.pattern_budget_exceeded": ("dlp_pattern_stops",),
    "dlp.detector_tested": (),
    "dlp.report_viewed": (),
}


def test_the_dlp_should_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in DLP_SHOULD_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"


# The audit actions of tenant SSO and break-glass (#231, #232), with the audited tables whose
# changes each covers in its transaction. Break-glass grants are a platform table, which has no
# audit trigger: each step writes its own security-critical platform event, and the approval, the
# end and the expiry one in each named tenant's log too.
SSO_AND_BREAK_GLASS_ACTIONS = {
    "sso_domain.claimed": ("sso_domains",),
    "sso_domain.verified": ("sso_domains",),
    "sso_domain.deleted": ("sso_domains",),
    "tenant_sso.updated": ("tenants", "sso_group_roles"),
    "tenant_sso.configured": ("idp_connections", "sso_domains", "tenants"),
    "user.provisioned": ("users", "user_identities"),
    "user.identity_bound": ("user_identities",),
    "member.signed_in": ("member_sessions",),
    "member.sign_in_refused": (),
    "break_glass.requested": (),
    "break_glass.approved": (),
    "break_glass.ended": (),
    "break_glass.expired": (),
    "break_glass.lapsed": (),
    # #239: Identity Center grants recorded by the tool or the reconciliation, and the daily SSO
    # drift check's findings and runs, all platform events (break-glass records also in the
    # tenants' logs).
    "break_glass.recorded": (),
    "sso_provider.drift_found": (),
    "sso_provider.drift_checked": (),
    # #239: an operator's recovery of a tenant admin writes the reset's own event (with its
    # recovery, which `admin_recoveries` changes cover), then a platform event; the daily job
    # ends the temporary sign-in with an event of its own.
    "user.sign_in_reset": ("users", "user_identities", "admin_recoveries"),
    "tenant.admin_recovered": (),
    "user.temporary_sign_in_ended": ("user_identities", "admin_recoveries"),
}


def test_the_sso_and_break_glass_actions_are_catalogued(migrated_db: ScratchDatabase) -> None:
    audited = dict(migrated_db.sql(TENANT_TABLES, trigger=TRIGGER))
    source = "".join(path.read_text() for path in Path(sft.__file__).parent.rglob("*.py"))
    for action, tables in SSO_AND_BREAK_GLASS_ACTIONS.items():
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+", action), action
        assert f'"{action}"' in source, f"{action} is catalogued but nothing writes it"
        for table in tables:
            assert audited[table], f"{action}: {table} changes without the audit trigger"
