"""The per-file part-URL count (#165, #235; abuse and rate limits 2.2 F, 6.1; data model 3.1).

Revision 0033, after 0032 (DLP data keys, #233), the last of M6. Expand only (data model 7): the
new column has a constant default, so the code of the revisions in `compatible_with` still runs on
this schema, and adding it rewrites nothing.

- `files.part_urls_issued`: how many part URLs the API has issued for the file over its life. A
  file may have at most 10 times its `part_count` (abuse 6.1): `requestUploadPartUrls` and
  `requestSessionUploadPartUrls` add the call's parts with one conditional update, the one that
  already records `last_part_at`, so parallel calls can't pass the cap together. It lives with
  the file rather than in the counter store because a file may keep uploading for longer than the
  store's 25-hour keys (abuse 4.2): its unfinished upload is rejected only 24 hours after its
  last part. The check is added `NOT VALID`, then validated outside the transaction.
- **No new grant.** The API's role may read and update every column of `files` (revision 0008, a
  table grant); no other role reads or writes the column.

Like every revision, it keeps the literal SQL it runs.
"""

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

# The earlier revisions whose code still runs on this schema: the column has a default, and the
# earlier heads' code reads none of it. Back to 0017, as M5's revisions do, because M5 and M6 ship
# in batches.
compatible_with: tuple[str, ...] = (
    down_revision,
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

CHECK = ("files_part_urls_issued_check", "part_urls_issued >= 0")


def upgrade() -> None:
    op.add_column(
        "files",
        sa.Column("part_urls_issued", sa.Integer, server_default=sa.text("0"), nullable=False),
    )
    name, check = CHECK
    op.execute(f"ALTER TABLE files ADD CONSTRAINT {name} CHECK ({check}) NOT VALID")
    with op.get_context().autocommit_block():
        op.execute(f"ALTER TABLE files VALIDATE CONSTRAINT {name}")


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
