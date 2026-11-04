"""${message}

Revision ${up_revision}, after ${down_revision | comma,n}. Expand only (data model 7): the code of
the revisions in `compatible_with` must still run on this schema.
"""

import sqlalchemy as sa
from alembic import op

${imports if imports else ""}
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None

# The earlier revisions whose code still runs on this schema: usually the previous release's head.
compatible_with: tuple[str, ...] = ()


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError
