"""The connection pool, and the one way to open a transaction: in a scope (ADR-0020).

    database = Database.connect(settings.database_url.get_secret_value())
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        ...  # commits at the end of the block, rolls back on an exception

Every transaction the session begins starts with
`SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tenant_id, true)`.
`true` makes both settings transaction-local: they end at commit or rollback, so a connection
back in the pool carries no tenant to its next user. Nothing here sets them for the session. A
session without a scope is refused before its first statement reaches the database.

The URL names one workload login role, and the pool opens only the scopes that role may open
(`sft.data.access.SCOPES_BY_ROLE`). Any other user, the master user or the migration role
included, is refused at `connect`: a pool that bypassed row-level security, or had no policies of
its own, would leave the first layer alone. So is a URL whose query could change who logs in or
how (`user`, `options`, `service`, …): only `SAFE_QUERY_PARAMETERS` pass. And every new connection
checks that PostgreSQL agrees on `current_user`, whatever the driver did with the URL.

In system scope the session refuses any write to a tenant table, unless the role is the relay
(`sft.data.access.check_write`): find across, act within.

Every statement through `Database` gets a CLIENT span, a child of the request's or message's span,
named like `SELECT sft`, with the SQL text: its bound parameters, never their values. A failed
statement's span carries the error's type, never its message, which can quote a value.

In AWS the URL names the workload's login role with no password; M4 adds a `do_connect` hook that
signs a 15-minute IAM token for each new connection, and `sslmode=verify-full` in the URL
(encryption and keys 2.2, 6.3).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Span, SpanKind, StatusCode
from sqlalchemy import Connection, Engine, create_engine, event, inspect, text
from sqlalchemy.engine import URL, ExceptionContext, ExecutionContext, make_url
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import ORMExecuteState, Session, SessionTransaction
from sqlalchemy.pool import NullPool

from sft.data.access import SCOPES_BY_ROLE, check_scope, check_write
from sft.data.scope import Scope

_SET_SCOPE = text(
    "SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tenant_id, true)"
)


SAFE_QUERY_PARAMETERS = frozenset(
    {"sslmode", "sslrootcert", "sslcrl", "sslnegotiation", "connect_timeout", "application_name"}
)
"""URL query parameters that change neither who logs in nor the session's settings."""


class ScopeMissingError(RuntimeError):
    """A transaction was about to run without a scope."""


class LoginRoleError(RuntimeError):
    """A pooled connection logged in as someone other than the URL's workload role."""


def psycopg_url(url: str | URL) -> URL:
    """The URL with the psycopg 3 driver, which serves both the async app and the sync jobs."""
    parsed = make_url(url)
    if parsed.drivername not in ("postgresql", "postgresql+psycopg"):
        raise ValueError("only postgresql:// and postgresql+psycopg:// URLs are supported")
    return parsed.set(drivername="postgresql+psycopg")


def sync_engine(url: str | URL, **options: Any) -> Engine:
    """A synchronous engine without a pool, for one-shot jobs (bootstrap, migrations) and tests.

    It has no scope: it is never used for the application's queries, which go through `Database`.
    """
    return create_engine(psycopg_url(url), poolclass=NullPool, **options)


_tracer = trace.get_tracer(__name__)
_SPAN = "_sft_span"  # where a statement's span waits on its execution context


def _trace_statements(engine: Engine) -> None:
    """Give every statement on `engine` a span (module docstring)."""
    url = engine.url
    base: dict[str, str | int] = {"db.system.name": "postgresql"}
    if url.database:
        base["db.namespace"] = url.database
    if url.host:
        base["server.address"] = url.host
    if url.port:
        base["server.port"] = url.port

    @event.listens_for(engine, "before_cursor_execute")
    def start(
        conn: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: ExecutionContext | None,
        executemany: bool,
    ) -> None:
        if context is None:
            return
        operation = statement.split(maxsplit=1)[0].upper() if statement.strip() else "SQL"
        span = _tracer.start_span(
            f"{operation} {url.database}" if url.database else operation,
            kind=SpanKind.CLIENT,
            attributes={**base, "db.operation.name": operation, "db.query.text": statement},
        )
        setattr(context, _SPAN, span)

    @event.listens_for(engine, "after_cursor_execute")
    def end(
        conn: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: ExecutionContext | None,
        executemany: bool,
    ) -> None:
        span: Span | None = getattr(context, _SPAN, None)
        if span is not None:
            delattr(context, _SPAN)
            span.end()

    @event.listens_for(engine, "handle_error")
    def fail(exception_context: ExceptionContext) -> None:
        context = exception_context.execution_context
        span: Span | None = getattr(context, _SPAN, None)
        if span is not None:
            delattr(context, _SPAN)
            span.set_attribute("error.type", type(exception_context.original_exception).__name__)
            span.set_status(StatusCode.ERROR)
            span.end()


class _ScopedSession(Session):
    """A session that sets its scope at the start of every transaction it begins."""


@event.listens_for(_ScopedSession, "after_begin")
def _set_scope(session: Session, transaction: SessionTransaction, connection: Connection) -> None:
    scope = session.info.get("scope")
    if not isinstance(scope, Scope):
        raise ScopeMissingError("every transaction runs in a scope (ADR-0020)")
    connection.execute(_SET_SCOPE, scope.settings())


@event.listens_for(_ScopedSession, "do_orm_execute")
def _check_statement(state: ORMExecuteState) -> None:
    if state.is_insert or state.is_update or state.is_delete:
        info = state.session.info
        check_write(info["scope"], info.get("role"), [getattr(state.statement, "table", None)])


@event.listens_for(_ScopedSession, "before_flush")
def _check_flush(session: Session, flush_context: object, instances: object) -> None:
    objects = [*session.new, *session.dirty, *session.deleted]
    tables = [inspect(o).mapper.local_table for o in objects]
    check_write(session.info["scope"], session.info.get("role"), tables)


class Database:
    """The engine and its pool, shared by the whole process. Create one at startup.

    Its only ways in are `transaction()` and `dispose()`; the engine stays private, so no code
    can reach the pool without a scope. The pool logs in as one workload role, from its URL, and
    opens only that role's scopes.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        role = engine.url.username
        if role is None or role not in SCOPES_BY_ROLE:
            raise ValueError(
                f"the database URL must name a workload login role, not {role!r} (ADR-0020)"
            )
        unsafe = sorted(set(engine.url.query) - SAFE_QUERY_PARAMETERS)
        if unsafe:
            # psycopg applies the query after the user name, so `?user=postgres` would win.
            raise ValueError(f"the database URL may not set {', '.join(unsafe)} (ADR-0020)")
        self._engine = engine
        self._role: str = role
        event.listen(engine.sync_engine, "connect", self._check_login)
        self._sessions = async_sessionmaker(
            engine,
            sync_session_class=_ScopedSession,
            # Objects stay readable after commit; async code can't load expired attributes lazily.
            expire_on_commit=False,
        )

    def _check_login(self, dbapi_connection: Any, connection_record: object) -> None:
        """On every new connection: PostgreSQL agrees it is the URL's role, with no SET ROLE."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SELECT current_user, session_user")
            row = cursor.fetchone()
        finally:
            cursor.close()
        dbapi_connection.rollback()
        if row is None or tuple(row) != (self._role, self._role):
            raise LoginRoleError(f"logged in as {row!r}, not {self._role} (ADR-0020)")

    @classmethod
    def connect(cls, url: str, *, pool_size: int = 5) -> Database:
        """A pool for `url`. It opens no connection until the first transaction needs one."""
        engine = create_async_engine(
            psycopg_url(url),
            pool_size=pool_size,
            max_overflow=0,
            # A connection that died while idle, after a failover say, is replaced, not handed out.
            pool_pre_ping=True,
        )
        _trace_statements(engine.sync_engine)
        return cls(engine)

    @asynccontextmanager
    async def transaction(self, scope: Scope) -> AsyncIterator[AsyncSession]:
        """A session whose transaction runs in `scope`, committed when the block ends."""
        if not isinstance(scope, Scope):
            raise ScopeMissingError("every transaction runs in a scope (ADR-0020)")
        check_scope(self._role, scope)
        # The role lets in_scope apply its write rule in system scope (sft.data.access).
        info = {"scope": scope, "role": self._role}
        async with self._sessions(info=info) as session, session.begin():
            yield session

    async def dispose(self) -> None:
        """Close every pooled connection. Call it once, at shutdown."""
        await self._engine.dispose()

    def raw_connection_for_tests(self) -> AsyncConnection:
        """Tests only: a connection from this pool with no scope, to check what it leaves behind.

        A test fails if any code under src/ calls it.
        """
        return self._engine.connect()
