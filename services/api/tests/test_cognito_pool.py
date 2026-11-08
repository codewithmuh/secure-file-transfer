"""The Cognito user pool adapter (#193, `sft.runtime.cognito`) against botocore's Stubber: what
it sends, what it reads back, and how a conflict is told by its error code. Then the notify
worker's settings for it, and the one-off pass that invites members left `invited` (#193)."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator, Iterator

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from pydantic import ValidationError

from member_fixtures import seed_tenant, seed_user
from pg import ScratchDatabase
from sft.core.settings import NotifySettings
from sft.data.database import Database
from sft.data.roles import NOTIFY
from sft.runtime.cognito import CognitoUserPool
from sft.service.notifications import invite_backlog
from sft.service.user_pool import PoolUser, PoolUserExistsError, UserPoolError
from sft.workers.notify import user_pool
from test_notify_settings import REQUIRED

pytestmark = pytest.mark.anyio

POOL = "ap-northeast-1_Example1"
SUBJECT = "0b5c6f1e-2c1a-4bb0-9d1e-5f3f9f1a2b3c"
TENANT = uuid.UUID("018f0000-0000-7000-8000-000000000001")
PASSWORD = "p" * 24


@pytest.fixture
def stubbed() -> Iterator[tuple[CognitoUserPool, Stubber]]:
    client = boto3.session.Session().client(
        "cognito-idp",
        config=Config(region_name="ap-northeast-1"),
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106
    )
    with Stubber(client) as stubber:
        yield CognitoUserPool(client, user_pool_id=POOL, provider_name=POOL), stubber
        stubber.assert_no_pending_responses()


def user(enrolment: str | None = "invitation") -> dict[str, object]:
    attributes = [{"Name": "sub", "Value": SUBJECT}, {"Name": "email", "Value": "a@example.test"}]
    if enrolment is not None:
        attributes.append({"Name": "custom:enrolment_id", "Value": enrolment})
    return {"Username": "user-1", "UserAttributes": attributes}


async def create(pool: CognitoUserPool) -> str:
    return await pool.create_user(
        username="user-1",
        email="a@example.test",
        tenant_id=TENANT,
        temporary_password=PASSWORD,
        enrolment="invitation",
    )


async def test_a_new_user_is_made_with_our_email_suppressed(
    stubbed: tuple[CognitoUserPool, Stubber],
) -> None:
    pool, stub = stubbed
    stub.add_response(
        "admin_create_user",
        {"User": {"Username": "user-1", "Attributes": [{"Name": "sub", "Value": SUBJECT}]}},
        {
            "UserPoolId": POOL,
            "Username": "user-1",
            "UserAttributes": [
                {"Name": "email", "Value": "a@example.test"},
                {"Name": "email_verified", "Value": "true"},
                {"Name": "custom:tenant_id", "Value": str(TENANT)},
                {"Name": "custom:enrolment_id", "Value": "invitation"},
            ],
            "TemporaryPassword": PASSWORD,
            "MessageAction": "SUPPRESS",
            "ForceAliasCreation": False,
        },
    )
    assert await create(pool) == SUBJECT
    await pool.aclose()


async def test_our_own_user_from_an_earlier_delivery_gets_the_new_password(
    stubbed: tuple[CognitoUserPool, Stubber],
) -> None:
    pool, stub = stubbed
    stub.add_client_error("admin_create_user", "UsernameExistsException")
    stub.add_response("admin_get_user", user(), {"UserPoolId": POOL, "Username": "user-1"})
    stub.add_response(
        "admin_update_user_attributes",
        {},
        {
            "UserPoolId": POOL,
            "Username": "user-1",
            "UserAttributes": [{"Name": "custom:enrolment_id", "Value": "invitation"}],
        },
    )
    stub.add_response(
        "admin_set_user_password",
        {},
        {"UserPoolId": POOL, "Username": "user-1", "Password": PASSWORD, "Permanent": False},
    )
    assert await create(pool) == SUBJECT


async def test_another_user_with_the_address_is_a_conflict(
    stubbed: tuple[CognitoUserPool, Stubber],
) -> None:
    pool, stub = stubbed
    stub.add_client_error("admin_create_user", "AliasExistsException")
    with pytest.raises(PoolUserExistsError):
        await create(pool)


async def test_any_other_refusal_is_retried_and_names_only_the_code(
    stubbed: tuple[CognitoUserPool, Stubber],
) -> None:
    pool, stub = stubbed
    stub.add_client_error("admin_create_user", "TooManyRequestsException", "a@example.test")
    with pytest.raises(UserPoolError) as raised:
        await create(pool)
    assert "TooManyRequestsException" in str(raised.value)
    assert "a@example.test" not in str(raised.value)


async def test_find_and_delete(stubbed: tuple[CognitoUserPool, Stubber]) -> None:
    pool, stub = stubbed
    stub.add_response("admin_get_user", user("reset-1"), {"UserPoolId": POOL, "Username": "u"})
    stub.add_client_error("admin_get_user", "UserNotFoundException")
    stub.add_response("admin_delete_user", {}, {"UserPoolId": POOL, "Username": "u"})
    stub.add_client_error("admin_delete_user", "UserNotFoundException")
    assert await pool.find_user(username="u") == PoolUser(SUBJECT, "reset-1")
    assert await pool.find_user(username="u") is None
    assert await pool.delete_user(username="u") is True
    assert await pool.delete_user(username="u") is False


async def test_a_lookup_that_fails_is_retried(stubbed: tuple[CognitoUserPool, Stubber]) -> None:
    pool, stub = stubbed
    stub.add_client_error("admin_get_user", "InternalErrorException", http_status_code=500)
    with pytest.raises(UserPoolError):
        await pool.find_user(username="u")


def test_the_settings_name_the_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in NotifySettings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("USER_POOL_BACKEND", "cognito")
    with pytest.raises(ValidationError, match="COGNITO_USER_POOL_ID"):
        NotifySettings()
    monkeypatch.setenv("COGNITO_USER_POOL_ID", POOL)
    monkeypatch.setenv("USER_POOL_PROVIDER_NAME", "something-else")
    with pytest.raises(ValidationError, match="must be COGNITO_USER_POOL_ID"):
        NotifySettings()
    monkeypatch.setenv("USER_POOL_PROVIDER_NAME", POOL)
    pool = user_pool(NotifySettings())
    assert isinstance(pool, CognitoUserPool)
    assert pool.provider_name == POOL


@pytest.fixture
async def database(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield database
    await database.dispose()


async def test_the_backlog_invites_members_left_invited_once(
    migrated_db: ScratchDatabase, database: Database
) -> None:
    name, connection = f"pool-{secrets.token_hex(6)}", uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, 'https://pool.example.test', 'active')",
        id=connection,
        name=name,
    )
    one, two = seed_tenant(migrated_db), seed_tenant(migrated_db)
    left = [
        seed_user(migrated_db, one.id, status="invited"),
        seed_user(migrated_db, two.id, status="invited"),
    ]
    invited_already = seed_user(migrated_db, two.id, status="invited")
    migrated_db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :t, :u, :c, 'sub-1')",
        id=uuid.uuid4(),
        t=two.id,
        u=invited_already,
        c=connection,
    )
    # The session's database holds other tests' invited members too, and the pass reaches every
    # tenant: it invites each one without an identity on this pool, this test's two among them.
    [(expected,)] = migrated_db.sql(
        "SELECT count(*) FROM users u WHERE u.status = 'invited' AND NOT EXISTS ("
        "SELECT 1 FROM user_identities i WHERE i.user_id = u.id AND i.idp_connection_id = :c)",
        c=connection,
    )
    assert await invite_backlog(database, provider_name=name) == expected
    queued = migrated_db.sql(
        "SELECT payload->>'user_id' FROM outbox WHERE topic = 'member.invited' "
        "AND tenant_id IN (:a, :b) ORDER BY payload->>'user_id'",
        a=one.id,
        b=two.id,
    )
    assert sorted(str(u) for u in left) == [row[0] for row in queued]
