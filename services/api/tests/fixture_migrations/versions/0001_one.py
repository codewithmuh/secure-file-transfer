"""The first fixture revision: the compatibility table and a tenant table."""

from alembic import op

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
    # Literal SQL, as every revision keeps it (sft.data.rls wrote it).
    op.execute("ALTER TABLE one ENABLE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT ON one TO sft_api")
    op.execute(
        "CREATE POLICY tenant_isolation ON one FOR ALL TO sft_api "
        "USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id())"
    )
