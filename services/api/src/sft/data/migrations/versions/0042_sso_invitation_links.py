"""The notification worker mints an SSO tenant's invitation links (#273; authn and authz 2.5, 7.3;
data model 2.1, 4.2).

Revision 0042, after 0041 (the approval backlog's age). Expand only (data model 7): a column grant
and a read policy, so the code of the revisions in `compatible_with` still runs on this schema.
Renumbering it changes only `revision`, `down_revision` and the file name.

- **The link on the user's row.** For `member.invited` in a tenant with an active SSO connection,
  the worker makes no pool user: it mints a one-time link and stores its SHA-256 and when it stops
  working on the invited user (`invitation_token_hash`, `invitation_expires_at`), then emails it.
  It may update those two columns and `updated_at`, under `users`' existing `tenant_isolation`
  policy (revision 0004), so in the tenant's scope only. The table's check keeps a hash on an
  invited user only, and its audit trigger requires the worker's event in the same transaction.
- **Whether the tenant uses SSO.** The worker read only the pool rows of `idp_connections`
  (revision 0016's `pool_read`, with its column grant: ID, tenant, kind, provider name, status).
  `notify_connection` lets it read the scope's tenant's own row with the same columns, never its
  issuer: the tenant's connection is active or not.

Like every revision, it keeps the literal SQL it runs. Generated with
`grant_sql("users", "sft_notify", "UPDATE", columns=["invitation_token_hash",
"invitation_expires_at", "updated_at"])` and `policy_sql("notify_connection", "idp_connections",
roles=["sft_notify"], command="SELECT", using="tenant_id = app_tenant_id()")`.
"""

from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None

# A column grant and a read policy: no earlier code is affected. Back to 0017, as 0041 does.
compatible_with: tuple[str, ...] = (
    down_revision,
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

NOTIFY_INVITATION_LINKS = (
    "GRANT UPDATE (invitation_token_hash, invitation_expires_at, updated_at) ON users "
    "TO sft_notify",
    "CREATE POLICY notify_connection ON idp_connections FOR SELECT TO sft_notify "
    "USING (tenant_id = app_tenant_id())",
)


def upgrade() -> None:
    for statement in NOTIFY_INVITATION_LINKS:
        op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
