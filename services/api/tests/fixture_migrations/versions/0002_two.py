"""The second fixture revision: it needs a lock on `one`, which a test can hold."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
compatible_with: tuple[str, ...] = ("0001",)


def upgrade() -> None:
    op.execute("ALTER TABLE one ADD COLUMN two integer")
    op.execute("GRANT SELECT ON one TO sft_jobs")
    op.execute("CREATE POLICY jobs_find ON one FOR SELECT TO sft_jobs USING (true)")
