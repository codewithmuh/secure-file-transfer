"""The connection pool, and the one way to open a transaction: in a scope (ADR-0020).

    database = Database.connect(settings.database_url.get_secret_value())
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        ...  # commits at the end of the block, rolls back on an exception

Every transaction the session begins starts with
`SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tenant_id, true)`.
`true` makes both settings transaction-local: they end at commit or rollback, so a connection
back in the pool carries no tenant to its next user. Nothing here sets them for the session. A
session without a scope is refused before its first statement reaches the database.

In AWS the URL names the workload's login role with no password; M4 adds a `do_connect` hook that
signs a 15-minute IAM token for each new connection, and `sslmode=verify-full` in the URL
(encryption and keys 2.2, 6.3).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, SessionTransaction
from sqlalchemy.pool import NullPool

from sft.data.scope import Scope

_SET_SCOPE = text(
    "SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tenant_id, true)"
)


class ScopeMissingError(RuntimeError):
    """A transaction was about to run without a scope."""


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


class _ScopedSession(Session):
    """A session that sets its scope at the start of every transaction it begins."""


@event.listens_for(_ScopedSession, "after_begin")
def _set_scope(session: Session, transaction: SessionTransaction, connection: Connection) -> None:
    scope = session.info.get("scope")
    if not isinstance(scope, Scope):
        raise ScopeMissingError("every transaction runs in a scope (ADR-0020)")
    connection.execute(_SET_SCOPE, scope.settings())


class Database:
    """The engine and its pool, shared by the whole process. Create one at startup.

    Its only ways in are `transaction()` and `dispose()`; the engine stays private, so no code
    can reach the pool without a scope.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessions = async_sessionmaker(
            engine,
            sync_session_class=_ScopedSession,
            # Objects stay readable after commit; async code can't load expired attributes lazily.
            expire_on_commit=False,
        )

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
        return cls(engine)

    @asynccontextmanager
    async def transaction(self, scope: Scope) -> AsyncIterator[AsyncSession]:
        """A session whose transaction runs in `scope`, committed when the block ends."""
        if not isinstance(scope, Scope):
            raise ScopeMissingError("every transaction runs in a scope (ADR-0020)")
        async with self._sessions(info={"scope": scope}) as session, session.begin():
            yield session

    async def dispose(self) -> None:
        """Close every pooled connection. Call it once, at shutdown."""
        await self._engine.dispose()

    def raw_connection_for_tests(self) -> AsyncConnection:
        """Tests only: a connection from this pool with no scope, to check what it leaves behind.

        A test fails if any code under src/ calls it.
        """
        return self._engine.connect()
