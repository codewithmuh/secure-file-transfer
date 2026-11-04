"""The migration job's rules (data model 7, ADR-0005), on real PostgreSQL with fixture revisions."""

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

from pg import ScratchDatabase
from sft.core import settings as settings_module
from sft.data import migrate
from sft.data.database import psycopg_url
from sft.data.migrate import (
    Action,
    MigrationRefusedError,
    Plan,
    alembic_config,
    become_owner,
    compatible_with,
    run,
)
from sft.data.roles import MIGRATE

FIXTURE = str(Path(__file__).parent / "fixture_migrations")

Logs = Callable[[], list[dict[str, object]]]


def run_fixture(db: ScratchDatabase, **options: object) -> Plan:
    return run(db.url(MIGRATE), script_location=FIXTURE, **options)  # type: ignore[arg-type]


def upgrade_to(db: ScratchDatabase, revision: str) -> None:
    engine = create_engine(psycopg_url(db.url(MIGRATE)), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            become_owner(connection)
            command.upgrade(alembic_config(connection, FIXTURE), revision)
    finally:
        engine.dispose()


def version(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql("SELECT version_num FROM alembic_version")


def recorded(db: ScratchDatabase) -> dict[object, object]:
    rows = db.sql("SELECT revision, compatible_with FROM schema_compatibility")
    return {revision: compatible for revision, compatible in rows}


def database_ahead(db: ScratchDatabase, compatible: list[str] | None) -> None:
    """As after a rollback: the database is at 0003, which the fixture image doesn't have."""
    run_fixture(db)
    db.sql("UPDATE alembic_version SET version_num = '0003'")
    if compatible is not None:
        db.sql(
            "INSERT INTO schema_compatibility (revision, compatible_with) VALUES ('0003', :c)",
            c=compatible,
        )


def test_an_empty_database_is_upgraded_to_head(empty_db: ScratchDatabase) -> None:
    assert run_fixture(empty_db) == Plan(Action.UPGRADE, None, "0002")
    assert version(empty_db) == [("0002",)]
    # Each revision recorded, in its own transaction, the earlier revisions it serves.
    assert recorded(empty_db) == {"0001": [], "0002": ["0001"]}
    owners = empty_db.sql("SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = 'public'")
    assert owners == [("sft_owner",)]
    # The revisions' grants and policies (sft.data.rls), made inside Alembic as the owner.
    assert empty_db.sql("SELECT polname FROM pg_policy ORDER BY 1") == [
        ("jobs_find",),
        ("tenant_isolation",),
    ]
    assert empty_db.sql(
        "SELECT has_table_privilege('sft_jobs', 'one', 'SELECT'), "
        "has_table_privilege('sft_jobs', 'one', 'INSERT')"
    ) == [(True, False)]


def test_an_older_database_is_upgraded(empty_db: ScratchDatabase) -> None:
    upgrade_to(empty_db, "0001")
    assert run_fixture(empty_db) == Plan(Action.UPGRADE, "0001", "0002")
    assert version(empty_db) == [("0002",)]


def test_stamping_down_records_nothing(empty_db: ScratchDatabase) -> None:
    # Only developers move a database back, by hand; the job never does (ADR-0005).
    run_fixture(empty_db)
    engine = create_engine(psycopg_url(empty_db.url(MIGRATE)), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            become_owner(connection)
            command.stamp(alembic_config(connection, FIXTURE), "0001")
    finally:
        engine.dispose()
    assert version(empty_db) == [("0001",)]
    assert recorded(empty_db) == {"0001": [], "0002": ["0001"]}


def test_a_database_at_head_is_left_alone(empty_db: ScratchDatabase) -> None:
    run_fixture(empty_db)
    assert run_fixture(empty_db) == Plan(Action.CURRENT, "0002", "0002")


def test_a_newer_database_that_serves_this_image_is_skipped(empty_db: ScratchDatabase) -> None:
    database_ahead(empty_db, ["0001", "0002"])
    assert run_fixture(empty_db) == Plan(Action.SKIP, "0003", "0002")
    assert version(empty_db) == [("0003",)]  # never a down-migration


@pytest.mark.parametrize("compatible", [["0001"], [], None])
def test_a_newer_database_that_does_not_serve_this_image_is_refused(
    empty_db: ScratchDatabase, compatible: list[str] | None
) -> None:
    database_ahead(empty_db, compatible)
    with pytest.raises(MigrationRefusedError, match="at 0003, which this image doesn't know"):
        run_fixture(empty_db)
    assert version(empty_db) == [("0003",)]


def test_a_database_without_the_compatibility_table_is_refused(empty_db: ScratchDatabase) -> None:
    empty_db.sql("CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY)")
    empty_db.sql("ALTER TABLE alembic_version OWNER TO sft_owner")
    empty_db.sql("INSERT INTO alembic_version VALUES ('0042')")
    with pytest.raises(MigrationRefusedError, match="no record"):
        run_fixture(empty_db)


def test_a_database_with_several_heads_is_refused(empty_db: ScratchDatabase) -> None:
    run_fixture(empty_db)
    empty_db.sql("INSERT INTO alembic_version VALUES ('0003')")
    with pytest.raises(MigrationRefusedError, match="several heads"):
        run_fixture(empty_db)


def test_an_image_without_migrations_is_refused(empty_db: ScratchDatabase, tmp_path: Path) -> None:
    shutil.copy(Path(FIXTURE) / "env.py", tmp_path / "env.py")
    (tmp_path / "versions").mkdir()
    with pytest.raises(MigrationRefusedError, match="no migrations"):
        run(empty_db.url(MIGRATE), script_location=str(tmp_path))


def test_a_migration_that_cannot_get_its_lock_is_retried(empty_db: ScratchDatabase) -> None:
    upgrade_to(empty_db, "0001")
    holder = create_engine(empty_db.admin, poolclass=NullPool)
    with holder.connect() as connection:
        connection.execute(text("LOCK TABLE one IN ACCESS EXCLUSIVE MODE"))
        waits: list[float] = []

        def release_and_wait(seconds: float) -> None:
            waits.append(seconds)
            connection.rollback()  # the application's transaction ends

        plan = run_fixture(empty_db, lock_timeout="50ms", sleep=release_and_wait)
    holder.dispose()
    assert plan == Plan(Action.UPGRADE, "0001", "0002")
    assert waits == [2.0]
    assert version(empty_db) == [("0002",)]


def test_a_migration_gives_up_after_the_last_attempt(empty_db: ScratchDatabase) -> None:
    upgrade_to(empty_db, "0001")
    holder = create_engine(empty_db.admin, poolclass=NullPool)
    waits: list[float] = []
    with holder.connect() as connection:
        connection.execute(text("LOCK TABLE one IN ACCESS EXCLUSIVE MODE"))
        with pytest.raises(OperationalError, match="lock timeout"):
            run_fixture(empty_db, lock_timeout="50ms", attempts=2, sleep=waits.append)
        connection.rollback()
    holder.dispose()
    assert waits == [2.0]
    assert version(empty_db) == [("0001",)]


def hold_advisory_lock(db: ScratchDatabase) -> tuple[Engine, Connection]:
    engine = create_engine(db.admin, poolclass=NullPool)
    connection = engine.connect()
    connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": migrate._ADVISORY_LOCK})
    connection.commit()
    return engine, connection


def test_only_one_job_migrates_at_a_time(empty_db: ScratchDatabase) -> None:
    engine, connection = hold_advisory_lock(empty_db)
    try:
        with pytest.raises(MigrationRefusedError, match="holds the lock"):
            run_fixture(empty_db, lock_wait_seconds=0)
    finally:
        connection.close()
        engine.dispose()
    assert empty_db.sql("SELECT to_regclass('alembic_version')") == [(None,)]


def test_a_job_waits_for_the_other_to_finish(empty_db: ScratchDatabase) -> None:
    engine, connection = hold_advisory_lock(empty_db)
    waits: list[float] = []

    def other_job_finishes(seconds: float) -> None:
        waits.append(seconds)
        connection.close()

    try:
        assert run_fixture(empty_db, sleep=other_job_finishes).action is Action.UPGRADE
    finally:
        engine.dispose()
    assert waits == [1.0]


def test_the_alembic_command_line_runs_the_same_way(
    empty_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No connection given: env.py connects with MIGRATION_DATABASE_URL and becomes the owner.
    monkeypatch.setenv("MIGRATION_DATABASE_URL", empty_db.url(MIGRATE))
    command.upgrade(alembic_config(script_location=FIXTURE), "head")
    assert version(empty_db) == [("0002",)]
    assert recorded(empty_db) == {"0001": [], "0002": ["0001"]}


def test_offline_migrations_are_refused() -> None:
    with pytest.raises(RuntimeError, match="offline"):
        command.upgrade(alembic_config(script_location=FIXTURE), "head", sql=True)


@pytest.mark.parametrize("value", [None, ["0001"], ("0001", 2)])
def test_every_migration_says_what_it_serves(value: object) -> None:
    module = SimpleNamespace() if value is None else SimpleNamespace(compatible_with=value)
    script = SimpleNamespace(revision="0009", module=module)
    with pytest.raises(TypeError, match="0009 must set compatible_with"):
        compatible_with(script)  # type: ignore[arg-type]


# ---- the entry point, with the real migrations ----


@pytest.fixture
def quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    # main() configures logging for the process; keep the test runner's handlers.
    monkeypatch.setattr(migrate, "configure_logging", lambda level: None)
    monkeypatch.setattr(settings_module, "configure_logging", lambda level: None)


@pytest.mark.usefixtures("quiet_logging")
def test_main_migrates_and_exits_0(
    empty_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch, json_logs: Logs
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", empty_db.url(MIGRATE))
    assert migrate.main() == 0
    assert migrate.main() == 0
    ready = [line for line in json_logs() if line["msg"] == "database ready"]
    assert [line["action"] for line in ready] == ["upgrade", "current"]


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_1_when_it_refuses(
    empty_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch, json_logs: Logs
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", empty_db.url(MIGRATE))
    assert migrate.main() == 0
    empty_db.sql("UPDATE alembic_version SET version_num = '9999'")
    assert migrate.main() == 1
    [refused] = [line for line in json_logs() if line["msg"] == "migration refused"]
    assert "9999" in str(refused["reason"])


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_1_when_the_database_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql://sft_migrate@127.0.0.1:1/sft")
    assert migrate.main() == 1


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_2_on_bad_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    assert migrate.main() == 2


@pytest.mark.parametrize("module", ["sft.data.migrate", "sft.data.bootstrap"])
def test_the_jobs_run_as_modules(module: str) -> None:
    # As the image runs them: python -m …; without settings each exits 2 and says which are missing.
    env = {k: v for k, v in os.environ.items() if not k.endswith("DATABASE_URL")}
    done = subprocess.run(  # noqa: S603 - a fixed command
        [sys.executable, "-m", module], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 2
    [line] = [json.loads(line) for line in done.stdout.splitlines()]
    assert line["msg"] == "invalid settings"
