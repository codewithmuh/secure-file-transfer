"""The transaction helper and row-level security, against real PostgreSQL as the workload roles."""

import re
import uuid
from pathlib import Path

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError, InvalidRequestError
from sqlalchemy.ext.asyncio import create_async_engine

from pg import ScratchDatabase
from sft.data import audit
from sft.data.access import ScopeNotAllowedError
from sft.data.database import Database, LoginRoleError, ScopeMissingError, psycopg_url
from sft.data.models import Tenant
from sft.data.roles import API, MIGRATE, RECOVERY, RELAY
from sft.data.scope import Scope, Subject

pytestmark = pytest.mark.anyio

INSUFFICIENT_PRIVILEGE = "42501"


async def create_tenant(operator: Database, name: str = "Example") -> uuid.UUID:
    """As the operator API does: in the new tenant's own scope, with its audit event (#50)."""
    tenant_id = uuid.uuid4()
    async with operator.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name=name, status="active"))
        await audit.record(
            session,
            action="tenant.created",
            actor=audit.Actor(audit.ActorType.OPERATOR, uuid.uuid4()),
            target=audit.Target("tenant", tenant_id),
        )
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
    async with api_db.raw_connection_for_tests() as connection:
        assert await connection.scalar(text("SELECT current_user")) == "sft_api"
        assert await connection.scalar(text("SELECT app_tenant_id()")) is None
        assert await connection.scalar(text("SELECT count(*) FROM tenants")) == 0


# sft_api never opens a system scope; the isolation suite covers every role's scopes.
@pytest.mark.parametrize("scope", [Scope.platform(), Scope.lookup()])
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
    link = Subject.recipient(uuid.uuid4())
    assert await visible_tenants(api_db, Scope.resource(theirs, link)) == {theirs}


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
    ("role", "scope"),
    [
        (API, Scope.tenant(uuid.uuid4())),
        (API, Scope.resource(uuid.uuid4(), Subject.upload_request(uuid.uuid4()))),
        (RELAY, Scope.system()),
        (RECOVERY, Scope.recovery()),
    ],
)
async def test_the_transaction_runs_in_its_scope(
    migrated_db: ScratchDatabase, role: str, scope: Scope
) -> None:
    database = Database.connect(migrated_db.url(role), pool_size=1)
    try:
        async with database.transaction(scope) as session:
            row = (await session.execute(text("SELECT app_scope(), app_tenant_id()"))).one()
    finally:
        await database.dispose()
    assert tuple(row) == (scope.kind.value, scope.tenant_id)


@pytest.mark.parametrize("scope", [Scope.system(), Scope.recovery()])
async def test_a_role_opens_only_its_own_scopes(scope: Scope) -> None:
    # Refused before any connection: nothing listens on port 1 (sft.data.access.SCOPES_BY_ROLE).
    database = Database.connect("postgresql://sft_api@127.0.0.1:1/sft")
    with pytest.raises(ScopeNotAllowedError, match=f"sft_api never opens a {scope.kind} scope"):
        async with database.transaction(scope):
            pass  # pragma: no cover


@pytest.mark.parametrize(
    "query",
    [
        "user=postgres",
        "options=-c%20role%3Dpostgres",
        "service=admin",
        "password=x",
        "sslmode=require&user=postgres",
    ],
)
def test_a_pool_url_may_not_change_who_logs_in(query: str) -> None:
    # psycopg applies the query after the user name: ?user=postgres would log in as postgres.
    with pytest.raises(ValueError, match="may not set"):
        Database.connect(f"postgresql://sft_api@127.0.0.1:1/sft?{query}")


def test_a_pool_url_may_carry_tls_and_timeouts() -> None:
    query = "sslmode=verify-full&sslrootcert=/ca.pem&connect_timeout=5&application_name=sft-api"
    Database.connect(f"postgresql://sft_api@127.0.0.1:1/sft?{query}")


async def first_statement(database: Database) -> None:
    # A transaction connects at its first statement, not when the block starts.
    async with database.transaction(Scope.platform()) as session:
        await session.execute(text("SELECT 1"))


async def test_every_new_connection_checks_who_logged_in(migrated_db: ScratchDatabase) -> None:
    # Whatever the driver does with its arguments, PostgreSQL has the last word on current_user.
    engine = create_async_engine(
        psycopg_url(migrated_db.url(API)),
        pool_size=1,
        connect_args={"user": "sft_scan"},
    )
    database = Database(engine)
    try:
        with pytest.raises(
            LoginRoleError, match=r"logged in as \('sft_scan', 'sft_scan'\), not sft_api"
        ):
            await first_statement(database)
    finally:
        await database.dispose()


class FakeConnection:
    """A DB-API connection that says who it logged in as, for the check itself."""

    def __init__(self, row: tuple[str, str] | None) -> None:
        self.row, self.rolled_back = row, False

    def cursor(self) -> "FakeConnection":
        return self

    def execute(self, statement: str) -> None:
        assert statement == "SELECT current_user, session_user"

    def fetchone(self) -> tuple[str, str] | None:
        return self.row

    def close(self) -> None:
        pass

    def rollback(self) -> None:
        self.rolled_back = True


@pytest.mark.parametrize("row", [("sft_scan", "sft_scan"), ("postgres", "sft_api"), None])
def test_the_login_check_refuses_anyone_but_the_urls_role(row: tuple[str, str] | None) -> None:
    database = Database.connect("postgresql://sft_api@127.0.0.1:1/sft")
    connection = FakeConnection(row)
    with pytest.raises(LoginRoleError):
        database._check_login(connection, None)
    assert connection.rolled_back  # it leaves no transaction open on the pooled connection
    database._check_login(FakeConnection(("sft_api", "sft_api")), None)


@pytest.mark.parametrize("user", ["postgres", MIGRATE, "sft_owner", "sft_lookup", None])
def test_a_pool_logs_in_only_as_a_workload_role(user: str | None) -> None:
    # The master user bypasses row-level security, and the others have no policies of their own.
    url = "postgresql://127.0.0.1:1/sft" if user is None else f"postgresql://{user}@127.0.0.1:1/sft"
    with pytest.raises(ValueError, match="must name a workload login role"):
        Database.connect(url)


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
    async with database.raw_connection_for_tests() as connection:
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
    async with api_db.transaction(Scope.platform()) as session:
        await session.commit()
        with pytest.raises(InvalidRequestError):
            await session.execute(text("SELECT 1"))


async def test_the_workload_role_settings_apply(api_db: Database) -> None:
    names = ("statement_timeout", "idle_in_transaction_session_timeout", "transaction_timeout")
    async with api_db.transaction(Scope.platform()) as session:
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
    pool = database._engine.pool  # the private engine, read here only to count connections
    assert pool.size() == 3  # type: ignore[attr-defined]
    assert pool.checkedout() == 0  # type: ignore[attr-defined]


def test_scratch_databases_are_bootstrapped(migrated_db: ScratchDatabase) -> None:
    assert migrated_db.sql("SELECT current_database()") == [(migrated_db.name,)]


SOURCE = Path(__file__).resolve().parents[1] / "src"


def test_only_tests_reach_the_pool_without_a_scope() -> None:
    # Database's engine is private, and its test-only connection is for tests alone.
    offenders = [
        str(path.relative_to(SOURCE))
        for path in SOURCE.rglob("*.py")
        if path.name != "database.py"
        and re.search(r"\._engine\b|raw_connection_for_tests", path.read_text())
    ]
    assert offenders == []


# ---- statement spans ----


async def test_each_statement_is_a_span_under_the_current_one(
    api_db: Database, spans: InMemorySpanExporter
) -> None:
    with trace.get_tracer(__name__).start_as_current_span("request") as request:
        async with api_db.transaction(Scope.platform()) as session:
            await session.execute(text("SELECT :secret_value AS v"), {"secret_value": "hunter2"})
    statements = [s for s in spans.get_finished_spans() if s.kind == SpanKind.CLIENT]
    set_scope, query = statements
    assert set_scope.attributes is not None
    assert str(set_scope.attributes["db.query.text"]).startswith("SELECT set_config(")
    assert query.attributes is not None
    database = query.attributes["db.namespace"]
    assert query.name == f"SELECT {database}"
    assert query.attributes["db.system.name"] == "postgresql"
    assert query.attributes["db.operation.name"] == "SELECT"
    assert query.attributes["server.address"] == "127.0.0.1"
    assert "secret_value" in str(query.attributes["db.query.text"])  # the placeholder …
    assert "hunter2" not in str(spans.get_finished_spans())  # … never the value
    for span in statements:
        assert span.parent is not None
        assert span.parent.span_id == request.get_span_context().span_id


async def test_a_failed_statement_is_an_error_span_without_the_message(
    api_db: Database, spans: InMemorySpanExporter
) -> None:
    tenant_id = uuid.uuid4()
    with pytest.raises(DBAPIError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            session.add(Tenant(id=tenant_id, name="Secret Corp", status="active"))
    [failed] = [s for s in spans.get_finished_spans() if s.status.status_code == StatusCode.ERROR]
    assert failed.name.startswith("INSERT ")
    assert failed.attributes is not None
    assert failed.attributes["error.type"] == "InsufficientPrivilege"
    assert failed.status.description is None
    assert "Secret Corp" not in str(spans.get_finished_spans())
