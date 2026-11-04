"""The database bootstrap job: `python -m sft.data.bootstrap`. It creates the roles.

It runs as the master user, once per environment and again whenever the role list changes; every
statement can run again safely. In AWS that is the `sft-{env}-db-bootstrap` job, the only reader
of the master password in Secrets Manager outside break-glass (encryption and keys 6.3). Locally
and in CI it runs as a superuser. It needs `BOOTSTRAP_DATABASE_URL` and `BOOTSTRAP_IAM_AUTH`.

What it sets up (authentication and authorization 7.3):

- `sft_owner` and `sft_lookup`, which can't log in. `sft_owner` may create tables in `public`.
  `sft_owner` may also become `sft_lookup` with `SET ROLE`, without inheriting from it, and
  `sft_lookup` may create in `public`: together they let a migration hand a credential lookup
  function to `sft_lookup` (`sft.data.rls.lookup_function_sql`).
- One login role per workload, and `sft_migrate`, with no attributes beyond `LOGIN`: no
  superuser, `CREATEROLE`, `CREATEDB`, replication or `BYPASSRLS`. `sft_migrate` may become
  `sft_owner` with `SET ROLE`, but doesn't inherit its privileges.
- A role that already exists with other attributes is put back: a re-run repairs drift. Only an
  attribute that differs is altered, because on Aurora the master user may not name some
  attributes at all; drift it can't repair fails the job instead of passing silently.
- `CONNECT` on this database for the login roles only, and the workload roles' timeouts.
- With `BOOTSTRAP_IAM_AUTH=true`, `rds_iam` for every login role, so each signs in with a 15-minute
  IAM token and has no password at all. Locally (`false`) the roles get no password from here: the
  test suite or the local stack sets an obviously fake one.

It grants no table: each migration grants its own tables (`sft.data.rls`).
"""

from __future__ import annotations

import logging
import sys

from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, BootstrapSettings, load_settings
from sft.data.database import sync_engine
from sft.data.roles import (
    LOGIN_ROLES,
    LOOKUP,
    MIGRATE,
    OWNER,
    WORKLOAD_ROLE_SETTINGS,
    WORKLOAD_ROLES,
)

log = logging.getLogger("sft.data.bootstrap")  # not __main__ under python -m

EXIT_FAILED = 1

# (pg_roles column, the value every role of ours has, the ALTER ROLE keyword that restores it)
_ATTRIBUTES = (
    ("rolsuper", False, "NOSUPERUSER"),
    ("rolcreatedb", False, "NOCREATEDB"),
    ("rolcreaterole", False, "NOCREATEROLE"),
    ("rolreplication", False, "NOREPLICATION"),
    ("rolbypassrls", False, "NOBYPASSRLS"),
    # Membership options decide inheritance (sft_migrate's of sft_owner is INHERIT FALSE); the
    # role attribute stays at PostgreSQL's default.
    ("rolinherit", True, "INHERIT"),
)


def _create_role(role: str, *, login: bool) -> str:
    """Create `role`, or put back any attribute that has drifted from what the design says."""
    expected = (("rolcanlogin", login, "LOGIN" if login else "NOLOGIN"), *_ATTRIBUTES)
    repairs = " ".join(
        f"IF r.{column} IS DISTINCT FROM {str(value).lower()} THEN ALTER ROLE {role} {keyword}; "
        "END IF;"
        for column, value, keyword in expected
    )
    # Role names are the constants of sft.data.roles, never input.
    return (
        f"DO $$ DECLARE r pg_roles%ROWTYPE; BEGIN "  # noqa: S608
        f"SELECT * INTO r FROM pg_roles WHERE rolname = '{role}'; "
        f"IF NOT FOUND THEN CREATE ROLE {role} {expected[0][2]}; RETURN; END IF; "
        f"{repairs} END $$"
    )


def bootstrap_sql(*, iam_auth: bool) -> list[str]:
    """Every statement the bootstrap runs, in order. Role names are constants, never input."""
    logins = ", ".join(LOGIN_ROLES)
    statements = [
        _create_role(OWNER, login=False),
        _create_role(LOOKUP, login=False),
        *(_create_role(role, login=True) for role in LOGIN_ROLES),
        # Migrations act as the owner only after an explicit SET ROLE.
        f"GRANT {OWNER} TO {MIGRATE} WITH INHERIT FALSE, SET TRUE",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        f"GRANT USAGE, CREATE ON SCHEMA public TO {OWNER}",
        # ALTER FUNCTION … OWNER TO sft_lookup needs both (data model 4.2).
        f"GRANT {LOOKUP} TO {OWNER} WITH INHERIT FALSE, SET TRUE",
        f"GRANT USAGE, CREATE ON SCHEMA public TO {LOOKUP}",
        "DO $$ BEGIN "
        "EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()); "
        f"EXECUTE format('GRANT CONNECT ON DATABASE %I TO {logins}', current_database()); "
        "END $$",
        *(
            f"ALTER ROLE {role} SET {name} = '{value}'"
            for role in WORKLOAD_ROLES
            for name, value in WORKLOAD_ROLE_SETTINGS.items()
        ),
    ]
    if iam_auth:
        statements.append(f"GRANT rds_iam TO {logins}")
    return statements


def bootstrap(connection: Connection, *, iam_auth: bool) -> None:
    """Create or update the roles, in the caller's transaction."""
    for statement in bootstrap_sql(iam_auth=iam_auth):
        connection.execute(text(statement))


def main() -> int:
    settings = load_settings(BootstrapSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    engine = sync_engine(settings.bootstrap_database_url.get_secret_value())
    try:
        with engine.begin() as connection:
            bootstrap(connection, iam_auth=settings.bootstrap_iam_auth)
    except SQLAlchemyError as exc:
        # The driver's message, not SQLAlchemy's, which appends the statement.
        reason = str(exc.orig) if isinstance(exc, DBAPIError) else str(exc)
        log.critical("bootstrap failed", extra={"reason": reason, "error": type(exc).__name__})
        return EXIT_FAILED
    finally:
        engine.dispose()
    log.info("roles ready", extra={"iam_auth": settings.bootstrap_iam_auth})
    return 0


if __name__ == "__main__":
    sys.exit(main())
