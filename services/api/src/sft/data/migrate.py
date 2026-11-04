"""The migration job: `python -m sft.data.migrate`, an Argo CD PreSync job from M4 (ADR-0005).

It connects as `sft_migrate` (`MIGRATION_DATABASE_URL`), becomes `sft_owner` with `SET ROLE`, and
compares the image's head revision with the database's (data model 7):

- **The database is empty or behind:** `alembic upgrade head`. Each revision runs in its own
  transaction, and records in `schema_compatibility` the earlier revisions whose code its schema
  still serves: the `compatible_with` list in its migration file.
- **The database is at the image's head:** nothing to do.
- **The database is ahead,** as after a rollback, at a revision this image doesn't know: if the
  image's head is in the list recorded for the database's revision, skip; otherwise fail, so the
  sync stops before any pod changes.

It never runs a down-migration. It exits 0 when the database is ready for this image, 1 when it
refuses or a migration fails, and 2 when its settings are wrong.

Every statement runs with a 2-second `lock_timeout`, so a migration gives up instead of making the
application's queries queue behind it; a run that gives up is retried a few times. An advisory lock
keeps two jobs from migrating at once.
"""

from __future__ import annotations

import logging
import re
import sys
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import psycopg.errors
from alembic import command, context
from alembic.config import Config
from alembic.runtime.migration import MigrationContext, MigrationInfo
from alembic.script import Script, ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError, OperationalError, SQLAlchemyError

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, MigrationSettings, load_settings
from sft.data.database import sync_engine
from sft.data.models import Base
from sft.data.roles import OWNER

log = logging.getLogger("sft.data.migrate")  # not __main__ under python -m

SCRIPT_LOCATION = "sft.data:migrations"
LOCK_TIMEOUT = "2s"
ATTEMPTS = 5
LOCK_WAIT_SECONDS = 300.0
# The advisory lock only migration jobs take: any fixed number, since such locks are per database.
_ADVISORY_LOCK = 48_000_001

EXIT_REFUSED = 1


class Action(StrEnum):
    UPGRADE = "upgrade"
    CURRENT = "current"
    SKIP = "skip"


@dataclass(frozen=True)
class Plan:
    action: Action
    database_revision: str | None
    image_revision: str


class MigrationRefusedError(Exception):
    """The database isn't one this image can run against, or another job holds the lock."""


class InvalidMigrationError(Exception):
    """A migration file in the image breaks a rule the job relies on."""


def alembic_config(
    connection: Connection | None = None, script_location: str = SCRIPT_LOCATION
) -> Config:
    """Alembic's configuration, from code: the image has no alembic.ini."""
    config = Config()
    config.set_main_option("script_location", script_location)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def become_owner(connection: Connection, *, lock_timeout: str = LOCK_TIMEOUT) -> None:
    """Act as `sft_owner`, and give up on any lock not granted within `lock_timeout`.

    Session settings are right here and nowhere else: the migration connection isn't pooled and
    closes when the job ends.
    """
    connection.execute(text(f"SET ROLE {OWNER}"))
    connection.execute(
        text("SELECT set_config('lock_timeout', :value, false)"), {"value": lock_timeout}
    )
    connection.commit()


def plan(connection: Connection, script: ScriptDirectory) -> Plan:
    """What to do for the database on `connection`, which acts as the owner."""
    head = script.get_current_head()
    if head is None:
        raise MigrationRefusedError("the image has no migrations")
    current = MigrationContext.configure(connection).get_current_heads()
    if len(current) > 1:
        raise MigrationRefusedError(f"the database has several heads: {sorted(current)}")
    database = current[0] if current else None
    if database is None:
        return Plan(Action.UPGRADE, None, head)
    if database == head:
        return Plan(Action.CURRENT, database, head)
    if database in {s.revision for s in script.iterate_revisions(head, "base")}:
        return Plan(Action.UPGRADE, database, head)
    compatible = _recorded_compatibility(connection, database)
    if compatible is not None and head in compatible:
        return Plan(Action.SKIP, database, head)
    raise MigrationRefusedError(
        f"the database is at {database}, which this image doesn't know, and its schema "
        f"doesn't list {head} as compatible ({'no record' if compatible is None else compatible})"
    )


def _recorded_compatibility(connection: Connection, revision: str) -> list[str] | None:
    if connection.execute(text("SELECT to_regclass('schema_compatibility')")).scalar() is None:
        return None
    row = connection.execute(
        text("SELECT compatible_with FROM schema_compatibility WHERE revision = :revision"),
        {"revision": revision},
    ).scalar()
    return None if row is None else list(row)


def _lock(connection: Connection, wait_seconds: float, sleep: Callable[[float], None]) -> None:
    deadline = time.monotonic() + wait_seconds
    while True:
        got = connection.execute(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": _ADVISORY_LOCK}
        ).scalar()
        connection.commit()
        if got:
            return
        if time.monotonic() >= deadline:
            raise MigrationRefusedError("another migration job holds the lock")
        sleep(1.0)


def _lock_not_available(exc: OperationalError) -> bool:
    return isinstance(exc.orig, psycopg.errors.LockNotAvailable)


def run(
    url: str,
    *,
    script_location: str = SCRIPT_LOCATION,
    lock_timeout: str = LOCK_TIMEOUT,
    attempts: int = ATTEMPTS,
    lock_wait_seconds: float = LOCK_WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> Plan:
    """Bring the database at `url` up to this image's head, or check it may run as it is."""
    script = ScriptDirectory.from_config(alembic_config(script_location=script_location))
    engine = sync_engine(url)
    try:
        with engine.connect() as connection:
            become_owner(connection, lock_timeout=lock_timeout)
            _lock(connection, lock_wait_seconds, sleep)
            attempt = 1
            while True:
                decided = plan(connection, script)
                connection.rollback()
                if decided.action is not Action.UPGRADE:
                    return decided
                try:
                    command.upgrade(alembic_config(connection, script_location), "head")
                except OperationalError as exc:
                    if not _lock_not_available(exc) or attempt >= attempts:
                        raise
                else:
                    return decided
                connection.rollback()
                log.warning(
                    "a migration couldn't get its lock in time; trying again",
                    extra={"attempt": attempt, "attempts": attempts},
                )
                sleep(2.0**attempt)
                attempt += 1
    finally:
        engine.dispose()


# ---- what env.py runs, inside Alembic ----

# The monthly partitions of audit_events and its default partition: made by the migration and the
# lifecycle job (data model 6), not by the models, so autogenerate must not see them as strays.
_AUDIT_PARTITION = re.compile(r"audit_events_(default|y\d{4}m\d{2})")


def include_name(name: str | None, type_: str, parent_names: object) -> bool:
    """Alembic's `include_name` hook: compare everything but the audit partitions."""
    return not (type_ == "table" and name is not None and _AUDIT_PARTITION.fullmatch(name))


def record_compatibility(
    ctx: MigrationContext,
    step: MigrationInfo,
    heads: Collection[Any],
    run_args: Mapping[str, Any],
) -> None:
    """After each upgrade step, in its transaction: record the revision's `compatible_with`."""
    if not step.is_upgrade:
        return
    script = step.up_revision
    if not isinstance(script, Script) or ctx.connection is None:  # pragma: no cover
        raise TypeError("Alembic passed an unexpected step")
    ctx.connection.execute(
        text(
            "INSERT INTO schema_compatibility (revision, compatible_with) "
            "VALUES (:revision, :compatible) ON CONFLICT (revision) DO UPDATE "
            "SET compatible_with = EXCLUDED.compatible_with, recorded_at = now()"
        ),
        {"revision": script.revision, "compatible": list(compatible_with(script))},
    )


def compatible_with(script: Script) -> Sequence[str]:
    """The earlier revisions a migration says its schema still serves. Every migration says."""
    value = getattr(script.module, "compatible_with", None)
    if not isinstance(value, tuple) or not all(isinstance(v, str) for v in value):
        raise InvalidMigrationError(
            f"migration {script.revision} must set compatible_with to a tuple of str"
        )
    return value


def run_env() -> None:
    """The body of env.py: run the migrations Alembic has chosen, as the owner."""
    if context.is_offline_mode():
        raise RuntimeError("offline (--sql) migrations aren't supported")
    connection = context.config.attributes.get("connection")
    if connection is not None:
        _run_in(connection)
        return
    # The alembic command line, for developers: MIGRATION_DATABASE_URL, as for the job, and the
    # same one log line naming bad settings, never their values.
    settings = load_settings(MigrationSettings)
    if settings is None:
        raise SystemExit(EXIT_BAD_SETTINGS)
    engine = sync_engine(settings.migration_database_url.get_secret_value())
    try:
        with engine.connect() as connection:
            become_owner(connection)
            _run_in(connection)
    finally:
        engine.dispose()


def _run_in(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        include_name=include_name,
        transaction_per_migration=True,
        on_version_apply=record_compatibility,
    )
    with context.begin_transaction():
        context.run_migrations()


def main() -> int:
    settings = load_settings(MigrationSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    try:
        decided = run(settings.migration_database_url.get_secret_value())
    except MigrationRefusedError as exc:
        log.critical("migration refused", extra={"reason": str(exc)})
        return EXIT_REFUSED
    except (CommandError, InvalidMigrationError) as exc:
        # The image's migrations themselves are wrong: several heads, a broken file, and so on.
        log.critical("migration failed", extra={"reason": str(exc), "error": type(exc).__name__})
        return EXIT_REFUSED
    except SQLAlchemyError as exc:
        # The driver's message, not SQLAlchemy's, which appends the statement and its parameters.
        reason = str(exc.orig) if isinstance(exc, DBAPIError) else str(exc)
        log.critical("migration failed", extra={"reason": reason, "error": type(exc).__name__})
        return EXIT_REFUSED
    log.info(
        "database ready",
        extra={
            "action": decided.action.value,
            "database_revision": decided.database_revision,
            "image_revision": decided.image_revision,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
