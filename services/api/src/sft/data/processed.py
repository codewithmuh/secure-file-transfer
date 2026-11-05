"""Processed-message records: what makes a consumer idempotent (ADR-0013, data model 2.5).

SQS delivers at least once, the relay may send a row twice, and after a failover the last day's
messages are sent again. So a consumer records `(consumer, message_id)` in the same transaction as
the work the message asks for, and skips a message it has recorded before.
`sft.workers.consumer.Consumer` does this for every work-queue consumer.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import tenant_of

# No conflict target: naming one needs SELECT on its columns, which the consumers don't have. The
# primary key is the table's only unique constraint, so it is the arbiter. Plain SQL, because
# SQLAlchemy's compiled INSERT reports no row count through psycopg's async cursor. An INSERT needs
# no `in_scope`: the tenant is `tenant_of(session)`, and the tenant policy's WITH CHECK refuses any
# other, so row-level security binds it as it binds the ORM's inserts.
_RECORD = text(
    "INSERT INTO processed_messages (consumer, message_id, tenant_id) "
    "VALUES (:consumer, :message_id, :tenant_id) ON CONFLICT DO NOTHING"
)


async def record_processed(session: AsyncSession, *, consumer: str, message_id: str) -> bool:
    """Record the message for `consumer` in this transaction; False if it was recorded before.

    Call it first in the transaction. A second copy handled at the same time waits on the first
    one's row: if the first commits, this returns False; if it rolls back, this one goes ahead.
    The record commits only with the handler's effects, so a failed attempt leaves none and the
    message is tried again.
    """
    tenant_id = tenant_of(session)  # the scope's tenant, never a parameter
    connection = await session.connection()
    result = await connection.execute(
        _RECORD, {"consumer": consumer, "message_id": message_id, "tenant_id": tenant_id}
    )
    # 1 if the row is new, 0 if it was there already.
    return result.rowcount == 1
