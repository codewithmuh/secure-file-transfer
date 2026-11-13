"""The age of the oldest pending DLP approval request, for its alert (#260; abuse and rate limits
8.2, `DlpApprovalBacklog`; architecture 6, "Approvals not decided").

Revision 0041, after 0040 (the audit partition drop). Expand only (data model 7): one column
grant, so the code of the revisions in `compatible_with` still runs on this schema. Renumbering it
changes only `revision`, `down_revision` and the file name.

The expiry job (`sft_jobs`) already finds pending requests past `expires_at` across tenants, in
system scope (revision 0026's `jobs_find` policy, read only). To measure how long the oldest has
waited, and how much of its own timeout the nearest to it has used, it also reads `created_at`. A
time, nothing a sender or an approver wrote.

Like every revision, it keeps the literal SQL it runs. Generated with
`grant_sql("dlp_approval_requests", "sft_jobs", "SELECT", columns=["created_at"])`.
"""

from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

# One column grant: no earlier code is affected. Back to 0017, as 0040 does.
compatible_with: tuple[str, ...] = (
    down_revision,
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

GRANTS = ("GRANT SELECT (created_at) ON dlp_approval_requests TO sft_jobs",)


def upgrade() -> None:
    for statement in GRANTS:
        op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
