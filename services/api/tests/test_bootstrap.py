import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.core import settings as settings_module
from sft.data import bootstrap as bootstrap_module
from sft.data.bootstrap import bootstrap, bootstrap_sql
from sft.data.database import sync_engine
from sft.data.roles import LOGIN_ROLES, LOOKUP, MIGRATE, OWNER


def test_on_aurora_every_login_role_signs_in_with_iam() -> None:
    statements = bootstrap_sql(iam_auth=True)
    assert statements[-1] == f"GRANT rds_iam TO {', '.join(LOGIN_ROLES)}"


def test_locally_there_is_no_rds_iam_and_never_a_password() -> None:
    statements = " ".join(bootstrap_sql(iam_auth=False))
    assert "rds_iam" not in statements
    assert "PASSWORD" not in statements.upper()


def test_the_owner_can_hand_a_lookup_function_to_sft_lookup() -> None:
    # ALTER FUNCTION … OWNER TO sft_lookup: the owner may become it, and it may create in public.
    statements = bootstrap_sql(iam_auth=False)
    assert f"GRANT {LOOKUP} TO {OWNER} WITH INHERIT FALSE, SET TRUE" in statements
    assert f"GRANT CREATE ON SCHEMA public TO {OWNER} WITH GRANT OPTION" in statements
    # sft_lookup never keeps CREATE on public: each lookup revision lends it for one statement.
    assert f"REVOKE CREATE ON SCHEMA public FROM {LOOKUP}" in statements
    assert not [s for s in statements if "CREATE ON SCHEMA public TO sft_lookup" in s]


def test_bootstrap_can_run_again(empty_db: ScratchDatabase) -> None:
    # The fixture ran it once; an environment runs it again whenever the role list changes.
    engine = sync_engine(empty_db.admin)
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


ATTRIBUTES = (
    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, "
    "rolinherit FROM pg_roles WHERE rolname = :role"
)
DESIGNED = {"sft_api": (True, False, False, False, False, False, True)}
DESIGNED["sft_owner"] = (False, *DESIGNED["sft_api"][1:])
RESTORE = {
    "sft_api": "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT",
    "sft_owner": "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT",
}


def test_every_role_statement_repairs_every_attribute() -> None:
    for statement in bootstrap_sql(iam_auth=False)[: len(LOGIN_ROLES) + 2]:
        for keyword in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION"):
            assert f" {keyword};" in statement
        assert " NOBYPASSRLS;" in statement
        assert " INHERIT;" in statement


def test_a_rerun_repairs_roles_that_have_drifted(empty_db: ScratchDatabase) -> None:
    # Roles are cluster-wide, so both exist already: give them every attribute they must not have.
    try:
        empty_db.sql(
            "ALTER ROLE sft_api BYPASSRLS SUPERUSER CREATEDB CREATEROLE REPLICATION "
            "NOINHERIT NOLOGIN"
        )
        empty_db.sql("ALTER ROLE sft_owner LOGIN BYPASSRLS")
        engine = sync_engine(empty_db.admin)
        try:
            with engine.begin() as connection:
                bootstrap(connection, iam_auth=False)
        finally:
            engine.dispose()
        for role, designed in DESIGNED.items():
            assert empty_db.sql(ATTRIBUTES, role=role) == [designed], role
    finally:
        for role, attributes in RESTORE.items():  # never leave a superuser on the shared server
            empty_db.sql(f"ALTER ROLE {role} {attributes}")


def test_sft_migrate_must_become_the_owner_to_create_anything(empty_db: ScratchDatabase) -> None:
    engine = sync_engine(empty_db.url(MIGRATE))
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
