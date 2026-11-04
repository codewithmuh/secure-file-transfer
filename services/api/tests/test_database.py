"""The transaction helper and row-level security, against real PostgreSQL as the workload roles."""

import uuid

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError, InvalidRequestError

from pg import ScratchDatabase
from sft.data.database import Database, ScopeMissingError, psycopg_url
from sft.data.models import Tenant
from sft.data.scope import Scope

pytestmark = pytest.mark.anyio

INSUFFICIENT_PRIVILEGE = "42501"


async def create_tenant(operator: Database, name: str = "Example") -> uuid.UUID:
    """As the operator API does: in the new tenant's own scope."""
    tenant_id = uuid.uuid4()
    async with operator.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name=name, status="active"))
    return tenant_id


async def visible_tenants(database: Database, scope: Scope) -> set[uuid.UUID]:
    async with database.transaction(scope) as session:
        return set((await session.scalars(select(Tenant.id))).all())


async def test_without_a_tenant_a_workload_role_reads_nothing(
    api_db: Database, operator_db: Database
) -> None:
    # The acceptance test of #48: no app.tenant_id, no rows, though the role may read the table.
    await create_tenant(operator_db)
    await create_tenant(operator_db)
    async with api_db.engine.connect() as connection:
        assert await connection.scalar(text("SELECT current_user")) == "sft_api"
        assert await connection.scalar(text("SELECT app_tenant_id()")) is None
        assert await connection.scalar(text("SELECT count(*) FROM tenants")) == 0


@pytest.mark.parametrize("scope", [Scope.system(), Scope.platform(), Scope.lookup()])
async def test_scopes_without_a_tenant_read_no_tenant_rows(
    api_db: Database, operator_db: Database, scope: Scope
) -> None:
    await create_tenant(operator_db)
    assert await visible_tenants(api_db, scope) == set()


async def test_a_tenant_scope_reads_only_its_own_tenant(
    api_db: Database, operator_db: Database
) -> None:
    mine = await create_tenant(operator_db)
    theirs = await create_tenant(operator_db)
    assert await visible_tenants(api_db, Scope.tenant(mine)) == {mine}
    assert await visible_tenants(api_db, Scope.resource(theirs)) == {theirs}


async def test_a_tenant_scope_cannot_write_another_tenants_rows(operator_db: Database) -> None:
    mine = await create_tenant(operator_db)
    theirs = await create_tenant(operator_db, name="Theirs")

    with pytest.raises(DBAPIError) as refused:
        async with operator_db.transaction(Scope.tenant(mine)) as session:
            session.add(Tenant(id=uuid.uuid4(), name="Smuggled", status="active"))
    assert getattr(refused.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE

    async with operator_db.transaction(Scope.tenant(mine)) as session:
        changed = await session.execute(
            update(Tenant).where(Tenant.id == theirs).values(name="Renamed")
        )
        assert changed.rowcount == 0  # type: ignore[attr-defined]
    async with operator_db.transaction(Scope.tenant(theirs)) as session:
        assert await session.scalar(select(Tenant.name).where(Tenant.id == theirs)) == "Theirs"


async def test_the_api_role_cannot_create_tenants(api_db: Database) -> None:
    tenant_id = uuid.uuid4()
    with pytest.raises(DBAPIError) as refused:
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            session.add(Tenant(id=tenant_id, name="Example", status="active"))
    assert getattr(refused.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize(
    "scope",
    [Scope.tenant(uuid.uuid4()), Scope.resource(uuid.uuid4()), Scope.system(), Scope.recovery()],
)
async def test_the_transaction_runs_in_its_scope(api_db: Database, scope: Scope) -> None:
    async with api_db.transaction(scope) as session:
        row = (await session.execute(text("SELECT app_scope(), app_tenant_id()"))).one()
    assert tuple(row) == (scope.kind.value, scope.tenant_id)


async def test_a_pooled_connection_carries_no_scope_after_commit(api_db: Database) -> None:
    async with api_db.transaction(Scope.tenant(uuid.uuid4())) as session:
        backend = await session.scalar(text("SELECT pg_backend_pid()"))
    await assert_next_user_has_no_scope(api_db, backend)


async def test_a_pooled_connection_carries_no_scope_after_rollback(api_db: Database) -> None:
    backends = []

    async def fail_in_a_tenant_scope() -> None:
        async with api_db.transaction(Scope.tenant(uuid.uuid4())) as session:
            backends.append(await session.scalar(text("SELECT pg_backend_pid()")))
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await fail_in_a_tenant_scope()
    await assert_next_user_has_no_scope(api_db, backends[0])


async def assert_next_user_has_no_scope(database: Database, backend: object) -> None:
    async with database.engine.connect() as connection:
        row = await connection.execute(
            text(
                "SELECT pg_backend_pid(), current_setting('app.scope', true), "
                "current_setting('app.tenant_id', true), app_scope(), app_tenant_id()"
            )
        )
        pid, scope, tenant, app_scope, app_tenant = row.one()
    assert pid == backend  # the same connection, back from the pool
    assert scope in ("", None)
    assert tenant in ("", None)
    assert (app_scope, app_tenant) == (None, None)


async def test_a_transaction_without_a_scope_is_refused(api_db: Database) -> None:
    with pytest.raises(ScopeMissingError):
        async with api_db.transaction(None):  # type: ignore[arg-type]
            pass  # pragma: no cover


async def test_a_session_without_a_scope_never_reaches_the_database(api_db: Database) -> None:
    # Even the session factory behind transaction() refuses to begin without a scope.
    async with api_db._sessions() as session:
        with pytest.raises(ScopeMissingError):
            await session.execute(text("SELECT 1"))


async def test_a_commit_inside_the_block_ends_it(api_db: Database) -> None:
    # No second transaction can start in the block, so none can run without the scope.
    async with api_db.transaction(Scope.system()) as session:
        await session.commit()
        with pytest.raises(InvalidRequestError):
            await session.execute(text("SELECT 1"))


async def test_the_workload_role_settings_apply(api_db: Database) -> None:
    names = ("statement_timeout", "idle_in_transaction_session_timeout", "transaction_timeout")
    async with api_db.transaction(Scope.system()) as session:
        settings = {name: await session.scalar(text(f"SHOW {name}")) for name in names}
    assert settings == {
        "statement_timeout": "10s",
        "idle_in_transaction_session_timeout": "10s",
        "transaction_timeout": "30s",
    }


def test_urls_use_psycopg_3() -> None:
    assert psycopg_url("postgresql://u@h/db").drivername == "postgresql+psycopg"
    assert psycopg_url("postgresql+psycopg://u@h/db").drivername == "postgresql+psycopg"
    with pytest.raises(ValueError, match="only postgresql"):
        psycopg_url("postgresql+asyncpg://u@h/db")


def test_connect_opens_no_connection() -> None:
    # Nothing listens on port 1: the pool is made, and no connection is tried until a transaction.
    database = Database.connect("postgresql://sft_api@127.0.0.1:1/sft", pool_size=3)
    assert database.engine.pool.size() == 3  # type: ignore[attr-defined]
    assert database.engine.pool.checkedout() == 0  # type: ignore[attr-defined]


def test_scratch_databases_are_bootstrapped(migrated_db: ScratchDatabase) -> None:
    assert migrated_db.sql("SELECT current_database()") == [(migrated_db.name,)]
