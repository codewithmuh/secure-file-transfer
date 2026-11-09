"""What the recovery job needs (#253, #252; data model 4.2): sft_recovery's grants and policies.

Revision 0035, after 0034 (the audit archive cursor and the purge). Expand only (data model 7):
grants and policies, so the code of the revisions in `compatible_with` still runs on this schema.

The restore and failover runbooks run `sft.service.recovery_replay` as `sft_recovery`, in recovery
scope (`app.scope = 'recovery'`), across tenants by design (data model 4.2): it re-imports the
archived security-critical events the restored database lacks and re-applies the changes they
record, the ones that take access away (docs/operations/disaster-recovery.md 4). Revision 0002
gave it `INSERT` on `audit_events` and `audit_create_partitions`; revision 0034 the archive cursor.
This one gives it, column by column, what the re-apply reads and writes:

- revocations of transfers and upload requests, with their link sessions and, for NFR-8, the
  transfer's files' `delete_after`;
- recipient and uploader lockouts, API key revocations, member deactivations and demotions with
  their sessions, forced sign-outs, sign-in resets (sessions and pool identities only);
- a committed download grant's count whose row is gone (`download_grants` read, the counters);
- `audit_events (tx_id, occurred_at)` read, to rewind the archive cursor, with a `SELECT` policy of
  its own beside revision 0002's insert policy;
- the outbox's publish columns, for the re-publish step (architecture 7).

Each table gets one policy, `recovery_reapply`, for `sft_recovery` in recovery scope only; a
pool's connection (`idp_connections`) has no tenant. The isolation suite never names recovery
scope: it reaches across tenants by design, which the policies make explicit.

Like every revision, it keeps the literal SQL it runs. The statements were generated with
`sft.data.rls` (`grant_sql`, `policy_sql`) when it was written.
"""

from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

# Grants and policies only: no earlier code is affected. Back to 0017, as 0034 does.
compatible_with: tuple[str, ...] = (
    down_revision,
    "0033",
    "0032",
    "0031",
    "0030",
    "0029",
    "0028",
    "0027",
    "0026",
    "0025",
    "0024",
    "0023",
    "0022",
    "0021",
    "0020",
    "0019",
    "0018",
    "0017",
)

GRANTS = (
    "GRANT SELECT (id, tenant_id, state, ended_at, revoked_by) ON transfers TO sft_recovery",
    "GRANT UPDATE (state, hold_reason, ended_at, revoked_by, updated_at) ON transfers TO "
    "sft_recovery",
    "GRANT SELECT (id, tenant_id, transfer_id, delete_after) ON files TO sft_recovery",
    "GRANT UPDATE (delete_after) ON files TO sft_recovery",
    "GRANT SELECT (id, tenant_id, state, ended_at, revoked_by, locked_at, failed_attempts) ON "
    "upload_requests TO sft_recovery",
    "GRANT UPDATE (state, ended_at, revoked_by, locked_at, failed_attempts, updated_at) ON "
    "upload_requests TO sft_recovery",
    "GRANT SELECT (id, tenant_id, transfer_id, locked_at, failed_attempts) ON "
    "transfer_recipients TO sft_recovery",
    "GRANT UPDATE (locked_at, failed_attempts, updated_at) ON transfer_recipients TO sft_recovery",
    "GRANT SELECT (id, tenant_id, recipient_id, upload_request_id, revoked_at) ON "
    "link_sessions TO sft_recovery",
    "GRANT UPDATE (revoked_at) ON link_sessions TO sft_recovery",
    "GRANT SELECT (id, tenant_id, role, status) ON users TO sft_recovery",
    "GRANT UPDATE (role, status, sso_fallback, dlp_approver, invitation_token_hash, "
    "invitation_expires_at, updated_at) ON users TO sft_recovery",
    "GRANT SELECT (id, tenant_id, revoked_at) ON api_keys TO sft_recovery",
    "GRANT UPDATE (revoked_at, revoked_reason) ON api_keys TO sft_recovery",
    "GRANT SELECT (id, tenant_id, user_id, created_at, revoked_at) ON member_sessions TO "
    "sft_recovery",
    "GRANT UPDATE (revoked_at, revoked_reason) ON member_sessions TO sft_recovery",
    "GRANT SELECT (id, tenant_id, user_id, idp_connection_id, created_at) ON user_identities "
    "TO sft_recovery",
    "GRANT DELETE ON user_identities TO sft_recovery",
    "GRANT SELECT (id, tenant_id) ON idp_connections TO sft_recovery",
    "GRANT SELECT (id) ON download_grants TO sft_recovery",
    "GRANT SELECT (tenant_id, recipient_id, file_id, count, first_downloaded_at, "
    "last_downloaded_at) ON download_counters TO sft_recovery",
    "GRANT UPDATE (count, first_downloaded_at, last_downloaded_at, updated_at) ON "
    "download_counters TO sft_recovery",
    "GRANT SELECT (tx_id, occurred_at) ON audit_events TO sft_recovery",
    "GRANT SELECT (published_at) ON outbox TO sft_recovery",
    "GRANT UPDATE (published_at, attempts, next_attempt_at, last_error) ON outbox TO sft_recovery",
)

POLICIES = (
    "CREATE POLICY recovery_reapply ON transfers FOR ALL TO sft_recovery USING (app_scope() = "
    "'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON files FOR ALL TO sft_recovery USING (app_scope() = "
    "'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON upload_requests FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON transfer_recipients FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON link_sessions FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON users FOR ALL TO sft_recovery USING (app_scope() = "
    "'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON api_keys FOR ALL TO sft_recovery USING (app_scope() = "
    "'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON member_sessions FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON user_identities FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON download_counters FOR ALL TO sft_recovery USING "
    "(app_scope() = 'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON outbox FOR ALL TO sft_recovery USING (app_scope() = "
    "'recovery') WITH CHECK (app_scope() = 'recovery')",
    "CREATE POLICY recovery_reapply ON idp_connections FOR SELECT TO sft_recovery USING "
    "(app_scope() = 'recovery' AND tenant_id IS NULL)",
    "CREATE POLICY recovery_reapply ON download_grants FOR SELECT TO sft_recovery USING "
    "(app_scope() = 'recovery')",
    "CREATE POLICY audit_recovery_select ON audit_events FOR SELECT TO sft_recovery USING "
    "(app_scope() = 'recovery')",
)


def upgrade() -> None:
    for statement in (*GRANTS, *POLICIES):
        op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
