"""The database bootstrap job: `python -m sft.data.bootstrap`. It creates the roles.

It runs as the master user, once per environment and again whenever the role list changes; every
statement can run again safely. In AWS that is the `sft-{env}-db-bootstrap` job, the only reader
of the master password in Secrets Manager outside break-glass (encryption and keys 6.3). Locally
and in CI it runs as a superuser. It needs `BOOTSTRAP_DATABASE_URL` and `BOOTSTRAP_IAM_AUTH`.

**The master password** (#278). In AWS, `BOOTSTRAP_MASTER_SECRET` names the master user's secret
(`secretsmanager:sft/<env>/db/master`, the JSON `{"username": …, "password": …}` the aurora
module writes) and `BOOTSTRAP_DATABASE_URL` names the user and no password. The job reads the
secret once, as its own role, in `AWS_REGION`, checks that it is the URL's user, and puts the
password into the connection in memory only: never into a log, an environment variable or a
Kubernetes Secret. A read that fails exits 1 naming the secret ID and the error code, never a
value. Locally the URL holds the superuser's password and no secret is named.

What it sets up (authentication and authorization 7.3):

- `sft_owner` and `sft_lookup`, which can't log in. `sft_owner` may create tables in `public`.
  `sft_owner` may also become `sft_lookup` with `SET ROLE`, without inheriting from it, and may
  grant `CREATE` on `public`: a migration gives it to `sft_lookup` only while it hands over a
  credential lookup function (`sft.data.rls.lookup_function_sql`).
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

import json
import logging
import sys
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import URL, Connection, make_url, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from sft.core.keyrings import SECRET_REFERENCE
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
        # ALTER FUNCTION … OWNER TO sft_lookup: the owner may become sft_lookup, and may give it
        # CREATE on public for that one statement (sft.data.rls.lookup_function_sql). sft_owner
        # stays the only role that keeps CREATE there (CVE-2018-1058).
        f"GRANT {LOOKUP} TO {OWNER} WITH INHERIT FALSE, SET TRUE",
        f"GRANT CREATE ON SCHEMA public TO {OWNER} WITH GRANT OPTION",
        f"GRANT USAGE ON SCHEMA public TO {LOOKUP}",
        f"REVOKE CREATE ON SCHEMA public FROM {LOOKUP}",
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


class SecretsClient(Protocol):
    """The one Secrets Manager call the job makes (boto3's client, or a fake in the tests)."""

    def get_secret_value(self, *, SecretId: str) -> Mapping[str, Any]: ...  # noqa: N803


class MasterSecretError(Exception):
    """The master user's secret couldn't be used. The message names no value."""


def _secrets_client(region: str) -> SecretsClient:
    client: SecretsClient = boto3.client(
        "secretsmanager",
        region_name=region,
        config=Config(retries={"mode": "standard", "max_attempts": 3}),
    )
    return client


def with_master_password(url: str, secret_id: str, client: SecretsClient) -> URL:
    """`url` with the password of the master user's secret `secret_id`, which must be the URL's
    user. In memory only; `MasterSecretError` names what is wrong, never a value."""
    try:
        answer = client.get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", "ClientError"))
        raise MasterSecretError(f"Secrets Manager refused the read ({code})") from None
    except BotoCoreError as exc:
        reason = type(exc).__name__
        raise MasterSecretError(f"Secrets Manager can't be reached ({reason})") from None
    raw = answer.get("SecretString")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        raise MasterSecretError("the secret isn't a JSON object")
    username, password = parsed.get("username"), parsed.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not password:
        raise MasterSecretError("the secret needs a username and a password")
    parsed_url = make_url(url)
    if parsed_url.username != username:
        raise MasterSecretError("the secret's user isn't BOOTSTRAP_DATABASE_URL's")
    return parsed_url.set(password=password)


def main(secrets_client: Callable[[str], SecretsClient] = _secrets_client) -> int:
    settings = load_settings(BootstrapSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    url: str | URL = settings.bootstrap_database_url.get_secret_value()
    if settings.bootstrap_master_secret is not None:
        secret_id = settings.bootstrap_master_secret.removeprefix(SECRET_REFERENCE)
        try:
            url = with_master_password(str(url), secret_id, secrets_client(settings.aws_region))
        except MasterSecretError as exc:
            log.critical(
                "the master user's secret can't be used",
                extra={"secret_id": secret_id, "reason": str(exc)},
            )
            return EXIT_FAILED
    engine = sync_engine(url)
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
