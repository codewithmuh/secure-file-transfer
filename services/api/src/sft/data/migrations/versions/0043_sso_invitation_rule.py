"""Which invitations are SSO links (#273; authn and authz 2.5, 7.3; data model 2.1, 4.2).

Revision 0043, after 0042 (the worker's SSO invitation links). Expand only (data model 7): column
grants and a read policy, so the code of the revisions in `compatible_with` still runs on this
schema. Renumbering it changes only `revision`, `down_revision` and the file name.

An invitation in a tenant with an active SSO connection is an SSO link only when the tenant
requires SSO or the invitee's address is on one of its proven domains linked to that connection:
anyone else may sign in locally, and has no identity at the tenant's provider. To tell, the
notification worker reads, in its tenant's scope only and read only:

- `tenants.sso_required`, under the `tenant_isolation` policy it already has on `tenants`
  (revision 0012), which it may read only `id`, `name` and `status` of so far;
- the tenant's `sso_domains`: tenant, domain, linked connection and proof time, never the
  verification token or who claimed it, under `notify_domains` (`tenant_id = app_tenant_id()`).

Like every revision, it keeps the literal SQL it runs. Generated with `grant_sql("tenants",
"sft_notify", "SELECT", columns=["sso_required"])`, `grant_sql("sso_domains", "sft_notify",
"SELECT", columns=["tenant_id", "domain", "idp_connection_id", "verified_at"])` and
`policy_sql("notify_domains", "sso_domains", roles=["sft_notify"], command="SELECT",
using="tenant_id = app_tenant_id()")`.
"""

from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

# Column grants and a read policy: no earlier code is affected. Back to 0017, as 0042 does.
compatible_with: tuple[str, ...] = (
    down_revision,
    "0041",
    "0040",
    "0039",
    "0038",
    "0037",
    "0036",
    "0035",
    "0034",
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

NOTIFY_SSO_INVITATION_RULE = (
    "GRANT SELECT (sso_required) ON tenants TO sft_notify",
    "GRANT SELECT (tenant_id, domain, idp_connection_id, verified_at) ON sso_domains TO sft_notify",
    "CREATE POLICY notify_domains ON sso_domains FOR SELECT TO sft_notify "
    "USING (tenant_id = app_tenant_id())",
)


def upgrade() -> None:
    for statement in NOTIFY_SSO_INVITATION_RULE:
        op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
