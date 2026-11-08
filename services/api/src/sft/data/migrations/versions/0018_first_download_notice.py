"""The first-download notice: a transfer's member is emailed once, on its first counted download
(#214; FR-8; data model 2.2).

Revision 0018, after 0017 (the invitation backlog, #193). Expand only (data model 7): the new
column is nullable, so the code of the revisions in `compatible_with` still runs on this schema.
Renumbering it (when another revision lands first) changes only `revision`, `down_revision` and
the file name.

- `transfers.first_download_notified_at`: when the transaction that counted the transfer's first
  download (any recipient, any file) wrote the `transfer.first_download` outbox message. It is set
  by one conditional update (`... WHERE first_download_notified_at IS NULL`), so the message is
  written once per transfer however many recipients and files follow, and a retried or resumed
  download writes nothing more. It stays null on a transfer without `notify_on_first_download`.
- **No new grant.** The API's role already may read and update every column of `transfers`
  (revision 0008, a table grant); no other role reads or writes the column. The notification
  worker reads only the message and the transfer's owner, not this column.

Like every revision, it keeps the literal SQL it runs.
"""

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

# The earlier revisions whose code still runs on this schema: the new column is nullable, and the
# previous head's code reads none of it.
compatible_with: tuple[str, ...] = (down_revision,)


def upgrade() -> None:
    op.add_column(
        "transfers",
        sa.Column("first_download_notified_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
