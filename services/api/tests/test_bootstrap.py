import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from pg import ScratchDatabase
from sft.core import settings as settings_module
from sft.data import bootstrap as bootstrap_module
from sft.data.bootstrap import bootstrap, bootstrap_sql
from sft.data.database import psycopg_url
from sft.data.roles import LOGIN_ROLES, MIGRATE, OWNER


def test_on_aurora_every_login_role_signs_in_with_iam() -> None:
    statements = bootstrap_sql(iam_auth=True)
    assert statements[-1] == f"GRANT rds_iam TO {', '.join(LOGIN_ROLES)}"


def test_locally_there_is_no_rds_iam_and_never_a_password() -> None:
    statements = " ".join(bootstrap_sql(iam_auth=False))
    assert "rds_iam" not in statements
    assert "PASSWORD" not in statements.upper()


def test_bootstrap_can_run_again(empty_db: ScratchDatabase) -> None:
    # The fixture ran it once; an environment runs it again whenever the role list changes.
    engine = create_engine(empty_db.admin, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            bootstrap(connection, iam_auth=False)
    finally:
        engine.dispose()
    members = empty_db.sql(
        "SELECT pg_get_userbyid(member) FROM pg_auth_members WHERE roleid = CAST(:r AS regrole)",
        r=OWNER,
    )
    assert members == [(MIGRATE,)]


def test_sft_migrate_must_become_the_owner_to_create_anything(empty_db: ScratchDatabase) -> None:
    engine = create_engine(psycopg_url(empty_db.url(MIGRATE)), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            with pytest.raises(DBAPIError, match="permission denied for schema public"):
                connection.execute(text("CREATE TABLE nope (id integer)"))
            connection.rollback()
            connection.execute(text(f"SET ROLE {OWNER}"))
            connection.execute(text("CREATE TABLE fine (id integer)"))
            connection.commit()
    finally:
        engine.dispose()
    assert empty_db.sql("SELECT tableowner FROM pg_tables WHERE tablename = 'fine'") == [(OWNER,)]


@pytest.fixture
def quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap_module, "configure_logging", lambda level: None)
    monkeypatch.setattr(settings_module, "configure_logging", lambda level: None)


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_0_when_the_roles_are_ready(
    empty_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", empty_db.admin_url())
    monkeypatch.setenv("BOOTSTRAP_IAM_AUTH", "false")
    assert bootstrap_module.main() == 0


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_1_when_it_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", "postgresql://postgres@127.0.0.1:1/sft")
    monkeypatch.setenv("BOOTSTRAP_IAM_AUTH", "false")
    assert bootstrap_module.main() == 1


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_2_without_a_choice_of_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", "postgresql://postgres@127.0.0.1:1/sft")
    monkeypatch.delenv("BOOTSTRAP_IAM_AUTH", raising=False)
    assert bootstrap_module.main() == 2
