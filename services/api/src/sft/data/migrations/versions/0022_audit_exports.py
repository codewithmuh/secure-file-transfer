"""Audit search and export (#216; data model 2.1, 5; authn and authz 5.3).

Revision 0022, after 0021 (API keys, #215). Expand only (data model 7): one nullable column and
an index, so the code of the revisions in `compatible_with` still runs on this schema. Renumbering
it (when another revision lands first) changes only `revision`, `down_revision` and the file name.

- `api_keys.first_exported_at`: when the key first exported the audit log. The export that sets it
  (a conditional update, so two at once can't both) also queues the email that tells the tenant's
  admins (`api_key_first_export`), so a leaked key's first pull is seen at once (authn and authz
  5.3). `sft_api` already may update the table (revision 0021), and the audit trigger watches
  `revoked_at` only: the export's own `audit.exported` event records the export.
- Searches filter `audit_events` by tenant and time, actor or target, which the per-partition
  indexes of revision 0002 already serve (data model 5), and `sft_api` already reads the log in
  tenant scope. A search by email address first finds the people with that address (users, by
  their unique `(tenant_id, email_normalized)`, and recipients), so recipients get an index on
  `(tenant_id, email_normalized)`, built concurrently because the table already holds rows.

Like every revision, it keeps the literal SQL it runs.
"""

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

# A nullable column and an index: the previous head's code runs unchanged.
# Every revision back to 0017 is listed too: M5 (0018 to 0026) ships as one batch, so a rollback
# past several of them still finds its revision here.
compatible_with: tuple[str, ...] = (down_revision, "0020", "0019", "0018", "0017")


# The email search's recipients (data model 5), built concurrently on a table that holds rows.
INDEXES = (
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS transfer_recipients_tenant_id_email_normalized_idx "
    "ON transfer_recipients (tenant_id, email_normalized)",
)


def upgrade() -> None:
    op.add_column(
        "api_keys", sa.Column("first_exported_at", sa.DateTime(timezone=True), nullable=True)
    )
    # Outside the migration's transaction: an index built concurrently doesn't block writes.
    with op.get_context().autocommit_block():
        for statement in INDEXES:
            op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
