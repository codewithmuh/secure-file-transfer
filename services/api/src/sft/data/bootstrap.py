"""The database bootstrap job: `python -m sft.data.bootstrap`. It creates the roles.

It runs as the master user, once per environment and again whenever the role list changes; every
statement can run again safely. In AWS that is the `sft-{env}-db-bootstrap` job, the only reader
of the master password in Secrets Manager outside break-glass (encryption and keys 6.3). Locally
and in CI it runs as a superuser. It needs `BOOTSTRAP_DATABASE_URL` and `BOOTSTRAP_IAM_AUTH`.

What it sets up (authentication and authorization 7.3):

- `sft_owner` and `sft_lookup`, which can't log in. `sft_owner` may create tables in `public`.
- One login role per workload, and `sft_migrate`, with no attributes beyond `LOGIN`: no
  superuser, `CREATEROLE`, `CREATEDB`, replication or `BYPASSRLS`. `sft_migrate` may become
  `sft_owner` with `SET ROLE`, but doesn't inherit its privileges.
- `CONNECT` on this database for the login roles only, and the workload roles' timeouts.
- With `BOOTSTRAP_IAM_AUTH=true`, `rds_iam` for every login role, so each signs in with a 15-minute
  IAM token and has no password at all. Locally (`false`) the roles get no password from here: the
  test suite or the local stack sets an obviously fake one.

It grants no table: each migration grants its own tables (`sft.data.rls`).
"""

from __future__ import annotations

import logging
import sys

from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from sft.core.logs import configure_logging
from sft.core.settings import BootstrapSettings, load_settings
from sft.data.database import psycopg_url
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
EXIT_BAD_SETTINGS = 2


def _create_role(role: str, *, login: bool) -> list[str]:
    attribute = "LOGIN" if login else "NOLOGIN"
    return [
        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') "
        f"THEN CREATE ROLE {role} {attribute}; END IF; END $$",
        f"ALTER ROLE {role} {attribute}",
    ]


def bootstrap_sql(*, iam_auth: bool) -> list[str]:
    """Every statement the bootstrap runs, in order. Role names are constants, never input."""
    logins = ", ".join(LOGIN_ROLES)
    statements = [
        *_create_role(OWNER, login=False),
        *_create_role(LOOKUP, login=False),
        *(s for role in LOGIN_ROLES for s in _create_role(role, login=True)),
        # Migrations act as the owner only after an explicit SET ROLE.
        f"GRANT {OWNER} TO {MIGRATE} WITH INHERIT FALSE, SET TRUE",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        f"GRANT USAGE, CREATE ON SCHEMA public TO {OWNER}",
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
    url = psycopg_url(settings.bootstrap_database_url.get_secret_value())
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            bootstrap(connection, iam_auth=settings.bootstrap_iam_auth)
    except SQLAlchemyError:
        log.exception("bootstrap failed")
        return EXIT_FAILED
    finally:
        engine.dispose()
    log.info("roles ready", extra={"iam_auth": settings.bootstrap_iam_auth})
    return 0


if __name__ == "__main__":
    sys.exit(main())
