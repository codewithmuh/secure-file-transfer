"""Audit events in real PostgreSQL: fail-closed commits, insert-only roles, what a row holds."""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.core.logs import bind_context
from sft.data import audit
from sft.data.access import ScopeNotAllowedError
from sft.data.audit import Actor, ActorType, Origin, Outcome, Target
from sft.data.database import Database
from sft.data.models import Tenant
from sft.data.roles import API, ARCHIVE, JOBS, RECOVERY, SCAN
from sft.data.scope import Scope, Subject

pytestmark = pytest.mark.anyio

INSUFFICIENT_PRIVILEGE = "42501"
INTEGRITY_CONSTRAINT_VIOLATION = "23000"

OPERATOR = Actor(ActorType.OPERATOR, uuid.uuid4())


def sqlstate(error: pytest.ExceptionInfo[DBAPIError]) -> object:
    return getattr(error.value.orig, "sqlstate", None)


def refused_for_missing_audit(error: pytest.ExceptionInfo[DBAPIError]) -> bool:
    diag = getattr(error.value.orig, "diag", None)
    return (
        sqlstate(error) == INTEGRITY_CONSTRAINT_VIOLATION
        and getattr(diag, "constraint_name", None) == "audit_required"
    )


def tenant_exists(db: ScratchDatabase, tenant_id: uuid.UUID) -> bool:
    return db.sql("SELECT count(*) FROM tenants WHERE id = :id", id=tenant_id) == [(1,)]


def events_for(db: ScratchDatabase, target_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT action, tenant_id FROM audit_events WHERE target_id = :id ORDER BY occurred_at",
        id=target_id,
    )


async def record_created(session: object, tenant_id: uuid.UUID) -> uuid.UUID:
    return await audit.record(
        session,  # type: ignore[arg-type]
        action="tenant.created",
        actor=OPERATOR,
        target=Target("tenant", tenant_id),
    )


@pytest.fixture
async def scan_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(SCAN), pool_size=1)
    yield database
    await database.dispose()


@pytest.fixture
async def archive_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(ARCHIVE), pool_size=1)
    yield database
    await database.dispose()


async def new_tenant(operator: Database) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with operator.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name="Example", status="active"))
        await record_created(session, tenant_id)
    return tenant_id


# ---- fail closed (acceptance criterion 1) ----


async def test_a_state_change_without_its_audit_event_cannot_commit(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = uuid.uuid4()
    with pytest.raises(DBAPIError) as refused:
        async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
            session.add(Tenant(id=tenant_id, name="Unaudited", status="active"))
    assert refused_for_missing_audit(refused)
    assert "tenants has no audit event" in str(refused.value)
    assert not tenant_exists(migrated_db, tenant_id)


async def test_a_state_change_with_its_audit_event_commits_with_it(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = uuid.uuid4()
    async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name="Audited", status="active"))
        event_id = await record_created(session, tenant_id)
        tx_id = await session.scalar(text("SELECT pg_current_xact_id()::text"))
    assert tenant_exists(migrated_db, tenant_id)
    rows = migrated_db.sql(
        "SELECT tx_id::text, tenant_id FROM audit_events WHERE id = :id", id=event_id
    )
    assert rows == [(tx_id, tenant_id)]


async def test_an_audit_event_rolled_back_with_its_savepoint_does_not_count(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = uuid.uuid4()

    async def create_with_the_event_rolled_back() -> None:
        async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
            session.add(Tenant(id=tenant_id, name="Example", status="active"))
            savepoint = await session.begin_nested()
            await record_created(session, tenant_id)
            await savepoint.rollback()

    with pytest.raises(DBAPIError) as refused:
        await create_with_the_event_rolled_back()
    assert refused_for_missing_audit(refused)
    assert not tenant_exists(migrated_db, tenant_id)
    assert events_for(migrated_db, tenant_id) == []


async def test_an_audit_event_of_another_transaction_does_not_count(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    with pytest.raises(DBAPIError) as refused:
        async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
            await session.execute(
                update(Tenant).where(Tenant.id == tenant_id).values(status="suspended")
            )
    assert refused_for_missing_audit(refused)
    assert migrated_db.sql("SELECT status FROM tenants WHERE id = :id", id=tenant_id) == [
        ("active",)
    ]


async def test_suspending_a_tenant_commits_with_its_audit_event(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
        await session.execute(
            update(Tenant).where(Tenant.id == tenant_id).values(status="suspended")
        )
        await audit.record(
            session,
            action="tenant.suspended",
            actor=OPERATOR,
            target=Target("tenant", tenant_id),
        )
    assert [action for action, _ in events_for(migrated_db, tenant_id)] == [
        "tenant.created",
        "tenant.suspended",
    ]


async def test_changes_outside_the_watched_columns_need_no_audit_event(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    # The limit of the check: `tenants` is watched on insert and on status changes only.
    tenant_id = await new_tenant(operator_db)
    async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
        await session.execute(update(Tenant).where(Tenant.id == tenant_id).values(name="Renamed"))
    assert migrated_db.sql("SELECT name FROM tenants WHERE id = :id", id=tenant_id) == [
        ("Renamed",)
    ]


async def test_the_owner_and_the_master_user_are_exempt(migrated_db: ScratchDatabase) -> None:
    # Like row-level security, which isn't forced: migrations and break-glass (ADR-0020).
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'Seeded', 'active')", id=tenant_id
    )
    assert tenant_exists(migrated_db, tenant_id)


# ---- insert only, in scope ----


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'tenant.hidden'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "SELECT count(*) FROM audit_events_default",
        "INSERT INTO audit_events_default (id, actor_type, action, outcome) "
        "VALUES (gen_random_uuid(), 'system', 'x.y', 'success')",
    ],
)
async def test_workload_roles_cannot_change_audit_events_or_reach_partitions(
    api_db: Database, operator_db: Database, statement: str
) -> None:
    tenant_id = await new_tenant(operator_db)
    with pytest.raises(DBAPIError) as refused:
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await session.execute(text(statement))
    assert sqlstate(refused) == INSUFFICIENT_PRIVILEGE


async def test_an_event_takes_its_tenant_from_the_scope(
    api_db: Database, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    target = Target("transfer", uuid.uuid4())
    link = Subject.recipient(uuid.uuid4())
    async with api_db.transaction(Scope.resource(tenant_id, link)) as session:
        await audit.record(
            session,
            action="transfer.downloaded",
            actor=Actor(ActorType.RECIPIENT, uuid.uuid4()),
            target=target,
        )
    assert events_for(migrated_db, target.id) == [("transfer.downloaded", tenant_id)]


async def test_a_tenant_scope_cannot_write_another_tenants_event(
    api_db: Database, operator_db: Database
) -> None:
    mine = await new_tenant(operator_db)
    theirs = await new_tenant(operator_db)
    with pytest.raises(DBAPIError) as refused:
        async with api_db.transaction(Scope.tenant(mine)) as session:
            await session.execute(
                text(
                    "INSERT INTO audit_events (id, tenant_id, actor_type, action, outcome) "
                    "VALUES (gen_random_uuid(), :theirs, 'system', 'x.y', 'success')"
                ),
                {"theirs": theirs},
            )
    assert sqlstate(refused) == INSUFFICIENT_PRIVILEGE


async def test_platform_events_have_no_tenant_and_need_platform_scope(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    target = Target("identity", uuid.uuid4())
    async with api_db.transaction(Scope.platform()) as session:
        await audit.record(
            session,
            action="sign_in.refused",
            actor=Actor(ActorType.SYSTEM),
            target=target,
            outcome=Outcome.FAILURE,
        )
    assert events_for(migrated_db, target.id) == [("sign_in.refused", None)]

    # A transaction that forgot its tenant can't pass one off as a platform event (ADR-0020):
    # not the API's lookup scope, nor a lifecycle job's system scope (sft_api never opens one).
    jobs_db = Database.connect(migrated_db.url(JOBS), pool_size=1)
    try:
        for database, scope in ((api_db, Scope.lookup()), (jobs_db, Scope.system())):
            with pytest.raises(DBAPIError) as refused:
                async with database.transaction(scope) as session:
                    await session.execute(
                        text(
                            "INSERT INTO audit_events (id, actor_type, action, outcome) "
                            "VALUES (gen_random_uuid(), 'system', 'x.y', 'success')"
                        )
                    )
            assert sqlstate(refused) == INSUFFICIENT_PRIVILEGE
    finally:
        await jobs_db.dispose()


@pytest.mark.parametrize(
    ("role", "scope"),
    [(JOBS, Scope.system()), (API, Scope.lookup()), (RECOVERY, Scope.recovery())],
)
async def test_record_refuses_scopes_that_write_no_events(
    migrated_db: ScratchDatabase, role: str, scope: Scope
) -> None:
    # Each scope opened by a role that may open it (sft.data.access.SCOPES_BY_ROLE).
    database = Database.connect(migrated_db.url(role), pool_size=1)
    try:
        async with database.transaction(scope) as session:
            with pytest.raises(ValueError, match="tenant, resource or platform scope"):
                await audit.record(session, action="x.y", actor=Actor(ActorType.SYSTEM))
    finally:
        await database.dispose()


async def test_record_takes_an_actor(api_db: Database) -> None:
    async with api_db.transaction(Scope.platform()) as session:
        with pytest.raises(TypeError, match="actor must be an Actor"):
            await audit.record(session, action="x.y", actor="operator")  # type: ignore[arg-type]


async def test_who_reads_audit_events(
    api_db: Database,
    operator_db: Database,
    scan_db: Database,
    archive_db: Database,
) -> None:
    mine = await new_tenant(operator_db)
    theirs = await new_tenant(operator_db)

    async with api_db.transaction(Scope.tenant(mine)) as session:
        tenants = set(await session.scalars(text("SELECT DISTINCT tenant_id FROM audit_events")))
    assert tenants == {mine}

    # The archive job reads every tenant's events, in system scope only (data model 2.5).
    async with archive_db.transaction(Scope.system()) as session:
        everyone = set(await session.scalars(text("SELECT tenant_id FROM audit_events")))
    assert {mine, theirs} <= everyone
    # It never opens another scope, and outside system scope its policy matches nothing.
    with pytest.raises(ScopeNotAllowedError, match="sft_archive never opens a tenant scope"):
        async with archive_db.transaction(Scope.tenant(mine)):
            pass  # pragma: no cover
    async with archive_db.raw_connection_for_tests() as connection, connection.begin():
        await connection.execute(
            text(
                "SELECT set_config('app.scope', 'tenant', true), "
                "set_config('app.tenant_id', :t, true)"
            ),
            {"t": str(mine)},
        )
        assert await connection.scalar(text("SELECT count(*) FROM audit_events")) == 0

    # Workers write events but never read them.
    with pytest.raises(DBAPIError) as refused:
        async with scan_db.transaction(Scope.tenant(mine)) as session:
            await session.execute(text("SELECT count(*) FROM audit_events"))
    assert sqlstate(refused) == INSUFFICIENT_PRIVILEGE


async def test_a_worker_writes_its_tenants_events(
    scan_db: Database, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    target = Target("file", uuid.uuid4())
    async with scan_db.transaction(Scope.tenant(tenant_id)) as session:
        await audit.record(
            session, action="file.scanned", actor=Actor(ActorType.SYSTEM), target=target
        )
    assert events_for(migrated_db, target.id) == [("file.scanned", tenant_id)]


# ---- what a row holds ----


class Reason(StrEnum):
    HARD_BOUNCE = "hard_bounce"


async def test_a_row_holds_the_event_and_the_request_context(
    api_db: Database, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    actor = Actor(ActorType.MEMBER, uuid.uuid4())
    target = Target("transfer", uuid.uuid4())
    grant_id = uuid.uuid4()
    when = datetime(2026, 11, 4, 9, 30, tzinfo=UTC)
    bind_context(request_id="req_" + "a" * 32, trace_id="b" * 32)
    try:
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            event_id = await audit.record(
                session,
                action="transfer.revoked",
                actor=actor,
                target=target,
                origin=Origin(source_ip=ip_address("2001:db8::7"), user_agent="x" * 600),
                security_critical=True,
                details={
                    "grant_id": grant_id,
                    "files": 3,
                    "notify": False,
                    "expires_at": when,
                    "reason": Reason.HARD_BOUNCE,
                    "previous": None,
                },
            )
            now = await session.scalar(text("SELECT now()"))
    finally:
        bind_context(request_id=None, trace_id=None)

    (row,) = migrated_db.sql(
        "SELECT tenant_id, occurred_at, actor_type, actor_id, action, target_type, target_id, "
        "outcome, host(source_ip), length(user_agent), request_id, trace_id, security_critical, "
        "details FROM audit_events WHERE id = :id",
        id=event_id,
    )
    assert row == (
        tenant_id,
        now,
        "member",
        actor.id,
        "transfer.revoked",
        "transfer",
        target.id,
        "success",
        "2001:db8::7",
        audit.USER_AGENT_MAX,
        "req_" + "a" * 32,
        "b" * 32,
        True,
        {
            "grant_id": str(grant_id),
            "files": 3,
            "notify": False,
            "expires_at": "2026-11-04T09:30:00+00:00",
            "reason": "hard_bounce",
            "previous": None,
        },
    )
    assert event_id.version == 7
