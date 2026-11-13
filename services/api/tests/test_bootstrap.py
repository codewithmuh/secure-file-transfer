import json

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from sqlalchemy import URL, make_url, text
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.core import settings as settings_module
from sft.data import bootstrap as bootstrap_module
from sft.data.bootstrap import MasterSecretError, bootstrap, bootstrap_sql, with_master_password
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


# ---- the master password from Secrets Manager (#278) ----

MASTER_SECRET = "secretsmanager:sft/dev/db/master"  # noqa: S105 - a secret's ID, not a secret
SECRET_ID = MASTER_SECRET.removeprefix("secretsmanager:")
VALUE = "test-only"  # what a wrong secret holds: never in a message or a log


class FakeSecrets:
    """Secrets Manager's one call, answering `secret` (or raising `error`) and keeping each ID."""

    def __init__(self, secret: object = None, error: Exception | None = None) -> None:
        self.secret, self.error = secret, error
        self.read: list[str] = []

    def get_secret_value(self, *, SecretId: str) -> dict[str, object]:  # noqa: N803
        self.read.append(SecretId)
        if self.error is not None:
            raise self.error
        return {
            "SecretString": self.secret if isinstance(self.secret, str) else json.dumps(self.secret)
        }


def without_password(db: ScratchDatabase) -> tuple[str, str, str]:
    """The test server's URL with no password, its user, and the password it needs."""
    url = make_url(db.admin_url())
    assert url.username is not None
    assert url.password is not None
    bare = URL.create(url.drivername, url.username, None, url.host, url.port, url.database)
    return (
        bare.render_as_string(hide_password=False),
        url.username,
        str(url.password),
    )


@pytest.mark.usefixtures("quiet_logging")
def test_in_aws_the_job_reads_the_master_password_from_its_secret(
    empty_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, user, password = without_password(empty_db)
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", url)
    monkeypatch.setenv("BOOTSTRAP_IAM_AUTH", "false")
    monkeypatch.setenv("BOOTSTRAP_MASTER_SECRET", MASTER_SECRET)
    monkeypatch.setenv("AWS_REGION", "ap-northeast-3")
    secrets = FakeSecrets({"username": user, "password": password})
    regions: list[str] = []

    def client(region: str) -> FakeSecrets:
        regions.append(region)
        return secrets

    assert bootstrap_module.main(secrets_client=client) == 0
    assert (secrets.read, regions) == ([SECRET_ID], ["ap-northeast-3"])
    assert empty_db.sql("SELECT count(*) FROM pg_roles WHERE rolname = :r", r=OWNER) == [(1,)]


@pytest.mark.usefixtures("quiet_logging")
def test_with_a_secret_the_url_carries_no_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOOTSTRAP_IAM_AUTH", "true")
    monkeypatch.setenv("BOOTSTRAP_MASTER_SECRET", MASTER_SECRET)
    for url in (
        "postgresql://sft_master:x@db.example.test/sft",
        "postgresql://db.example.test/sft",
    ):
        monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", url)
        assert bootstrap_module.main(secrets_client=lambda region: FakeSecrets()) == 2
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", "postgresql://sft_master@db.example.test/sft")
    monkeypatch.setenv("BOOTSTRAP_MASTER_SECRET", "sft/dev/db/master")  # not a reference
    assert bootstrap_module.main(secrets_client=lambda region: FakeSecrets()) == 2


@pytest.mark.parametrize(
    ("secrets", "reason"),
    [
        (
            FakeSecrets(
                error=ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetSecretValue"
                )
            ),
            r"refused the read \(AccessDeniedException\)",
        ),
        (FakeSecrets(error=EndpointConnectionError(endpoint_url="x")), "can't be reached"),
        (FakeSecrets(f"{VALUE}-not-json"), "isn't a JSON object"),
        (FakeSecrets({"username": "sft_master"}), "needs a username and a password"),
        (FakeSecrets({"username": "someone", "password": VALUE}), "isn't BOOTSTRAP"),
    ],
)
def test_a_secret_that_cant_be_used_names_no_value(secrets: FakeSecrets, reason: str) -> None:
    with pytest.raises(MasterSecretError, match=reason) as refused:
        with_master_password("postgresql://sft_master@db.example.test/sft", SECRET_ID, secrets)
    assert VALUE not in str(refused.value)


@pytest.mark.usefixtures("quiet_logging")
def test_main_exits_1_on_a_secret_it_cant_use_and_logs_its_id_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("BOOTSTRAP_DATABASE_URL", "postgresql://sft_master@127.0.0.1:1/sft")
    monkeypatch.setenv("BOOTSTRAP_IAM_AUTH", "true")
    monkeypatch.setenv("BOOTSTRAP_MASTER_SECRET", MASTER_SECRET)
    wrong_user = FakeSecrets({"username": "someone", "password": VALUE})
    assert bootstrap_module.main(secrets_client=lambda region: wrong_user) == 1
    [record] = [r for r in caplog.records if r.name == "sft.data.bootstrap"]
    assert record.secret_id == SECRET_ID  # type: ignore[attr-defined]
    assert VALUE not in caplog.text
