"""The first fixture revision: the compatibility table and a tenant table."""

from alembic import op

from sft.data.rls import enable_tenant_rls

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None
compatible_with: tuple[str, ...] = ()


def upgrade() -> None:
    op.execute(
        "CREATE TABLE schema_compatibility (revision text PRIMARY KEY, "
        "compatible_with text[] NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now())"
    )
    op.execute(
        "CREATE FUNCTION app_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
        "AS $$ SELECT NULL::uuid $$"
    )
    op.execute("CREATE TABLE one (id integer PRIMARY KEY, tenant_id uuid NOT NULL)")
    enable_tenant_rls("one", grants={"sft_api": "SELECT"})
