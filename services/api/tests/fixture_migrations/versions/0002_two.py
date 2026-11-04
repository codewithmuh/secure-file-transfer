"""The second fixture revision: it needs a lock on `one`, which a test can hold."""

from alembic import op

from sft.data.rls import create_policy, grant

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
compatible_with: tuple[str, ...] = ("0001",)


def upgrade() -> None:
    op.execute("ALTER TABLE one ADD COLUMN two integer")
    grant("one", "sft_jobs", "SELECT")
    create_policy("jobs_find", "one", roles=["sft_jobs"], command="SELECT", using="true")
