"""Fail-closed audit: a change to an audited table can't commit without its audit event (NFR-15).

Architecture 5.2 says the audit record is written in the same transaction as the change it
describes, so a change can't happen without its record. The database enforces that, not just the
code that is supposed to remember it:

- Each audited table has `audit_required`, a constraint trigger that is `DEFERRABLE INITIALLY
  DEFERRED`, so it runs at `COMMIT`, after every statement of the transaction. For each row the
  transaction inserted, updated or deleted, it checks that `audit_events` holds a row with this
  transaction's ID (`tx_id = pg_current_xact_id()`). If none does, the commit fails with
  SQLSTATE 23000 and the constraint name `audit_required`, and the whole transaction, the
  change included, rolls back. An audit row inserted in a savepoint that was rolled back doesn't
  count; nor does any row of another transaction.
- Workload roles may only insert audit rows (`sft.data.audit`), so a row that satisfied the check
  stays there.
- The check applies to the workload roles. Roles that can act as the table owner are exempt,
  like row-level security, which isn't forced: migrations, which are reviewed (data model 7), and
  the master user, whose break-glass sessions pgaudit records (threat model T-65).
- A new table decides in the migration that creates it: the trigger from `require_audit_sql(...)`
  for a table whose changes are security-relevant (FR-27), or an entry in `NOT_AUDITED` below with
  the reason. The catalog test fails for a tenant-owned table that has neither.

What it can't catch, so tests and review still must:

- whether the audit event describes the change: any one audit row in the transaction satisfies
  every audited change in it;
- changes the trigger doesn't watch: tables in `NOT_AUDITED`, commands or columns left out of
  the trigger, and work outside PostgreSQL (S3, SES);
- an action that changes no audited row, such as a refused request whose transaction rolls back:
  its failure record needs a transaction of its own;
- the security-critical copy in the archive of both regions (architecture 5.2), which the API
  writes after the commit.

Like `sft.data.rls`, this writes the SQL **when you author the migration**; the revision keeps the
literal statement, never a call to this module (a test checks that no revision imports `sft`):

    uv run python -c 'from sft.data.audit_required import require_audit_sql;
        print(require_audit_sql("transfers"))'                    # every insert, update, delete
    require_audit_sql("tenants", commands=("INSERT", "UPDATE"), update_of=("status",))

and add a test that the revision's text still equals the helper's output, as
tests/test_audit_catalog.py does for revision 0002.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Literal

from sft.data.rls import identifier

TRIGGER: Final = "audit_required"
"""The constraint trigger's name on every audited table, and the constraint named in its error."""

AuditedCommand = Literal["INSERT", "UPDATE", "DELETE"]

NOT_AUDITED: Final[dict[str, str]] = {
    # Tenant-owned tables whose changes need no audit event, each with the reason. Add a table here
    # in the migration's PR, or give it `require_audit` there; the catalog test checks one or the
    # other.
    "outbox": "Enqueueing a message isn't an action of its own: the change that enqueues it is "
    "audited in the same transaction, and the relay only marks rows sent (ADR-0013).",
    "processed_messages": "Recording a delivery isn't an action of its own: the handler's change "
    "in the same transaction is audited where it is security-relevant (ADR-0013).",
    "idempotency_keys": "Remembering a request isn't an action of its own: the change it records "
    "is audited in the same transaction, and the daily job only deletes expired rows "
    "(architecture 5.4).",
    "tenant_usage": "A storage reservation changes only with the file it is for: declaring, "
    "rejecting or removing the file is audited in the same transaction (#114, data model 2.5).",
}


def require_audit_sql(
    table: str,
    *,
    commands: Sequence[AuditedCommand] = ("INSERT", "UPDATE", "DELETE"),
    update_of: Sequence[str] = (),
) -> str:
    """The `CREATE CONSTRAINT TRIGGER` that makes `table` fail closed, for a migration to paste in.

    `update_of` narrows `UPDATE` to changes of those columns, for a table with columns that change
    without an audited action, such as `last_used_at`.
    """
    if not commands or len(set(commands)) != len(commands):
        raise ValueError("name each audited command once")
    if any(c not in ("INSERT", "UPDATE", "DELETE") for c in commands):
        raise ValueError(f"audit only INSERT, UPDATE or DELETE, not {list(commands)}")
    if update_of and "UPDATE" not in commands:
        raise ValueError("update_of narrows UPDATE, which isn't audited here")
    events = [
        f"UPDATE OF {', '.join(identifier(c) for c in update_of)}"
        if command == "UPDATE" and update_of
        else command
        for command in ("INSERT", "UPDATE", "DELETE")
        if command in commands
    ]
    return (
        f"CREATE CONSTRAINT TRIGGER {TRIGGER} AFTER {' OR '.join(events)} ON {identifier(table)} "
        f"DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"
    )
