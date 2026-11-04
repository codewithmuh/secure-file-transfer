"""Real PostgreSQL for the tests: scratch databases on the server that TEST_DATABASE_URL names."""

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy import URL, create_engine, text
from sqlalchemy.pool import NullPool

from sft.data.bootstrap import bootstrap
from sft.data.roles import LOGIN_ROLES

# A superuser URL for a PostgreSQL 17 server, e.g. postgresql://postgres:…@127.0.0.1:5432/postgres.
# Each test session makes its own databases there and drops them afterwards. The roles are
# cluster-wide, so they stay, with the password below.
ADMIN_URL_VARIABLE = "TEST_DATABASE_URL"
TEST_PASSWORD = "test-only-password"  # noqa: S105 - local and CI test servers only


@dataclass(frozen=True)
class ScratchDatabase:
    """A database of its own on the test server, with the roles bootstrapped."""

    admin: URL  # the superuser, connected to this database

    @property
    def name(self) -> str:
        return str(self.admin.database)

    def url(self, role: str) -> str:
        """A URL that logs in as `role`, which bootstrap created and the fixture gave a password."""
        return self.admin.set(username=role, password=TEST_PASSWORD).render_as_string(
            hide_password=False
        )

    def admin_url(self) -> str:
        return self.admin.render_as_string(hide_password=False)

    def sql(self, statement: str, **params: object) -> list[tuple[object, ...]]:
        """Run one statement as the superuser, which row-level security doesn't apply to."""
        engine = create_engine(self.admin, poolclass=NullPool)
        try:
            with engine.begin() as connection:
                result = connection.execute(text(statement), params)
                return [tuple(row) for row in result] if result.returns_rows else []
        finally:
            engine.dispose()


@contextmanager
def fresh_database(admin_url: URL) -> Iterator[ScratchDatabase]:
    """An empty database with the roles bootstrapped, dropped afterwards."""
    name = f"sft_test_{secrets.token_hex(4)}"
    server = create_engine(admin_url, poolclass=NullPool, isolation_level="AUTOCOMMIT")
    with server.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    db = ScratchDatabase(admin_url.set(database=name))
    try:
        engine = create_engine(db.admin, poolclass=NullPool)
        try:
            with engine.begin() as connection:
                bootstrap(connection, iam_auth=False)
                for role in LOGIN_ROLES:
                    connection.execute(text(f"ALTER ROLE {role} PASSWORD '{TEST_PASSWORD}'"))
        finally:
            engine.dispose()
        yield db
    finally:
        with server.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        server.dispose()
