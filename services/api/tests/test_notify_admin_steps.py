"""The notification worker's steps for SSO invitations and admin recovery (#273; authn and authz
2.5), on the real database as `sft_notify`:

- `member.invited` in a tenant with an active SSO connection mints a one-time link (its hash and a
  7-day expiry on the user) and sends `member_invitation_sso`, with no pool user;
- `tenant.admin_recovered` emails every active admin of the tenant which admin an operator
  recovered, when, and the kind;
- `member.temporary_sign_in_ended` deletes the admin's pool user made for the recovery's reset,
  and no other.

Each runs with the in-memory pool of test_notify_pool.py, and with the Keycloak and Cognito
adapters on their fakes (an `httpx.MockTransport` and botocore's `Stubber`), so what each step asks
of a real pool is checked call by call.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import boto3
import httpx2 as httpx
import pytest
from botocore.config import Config
from botocore.stub import Stubber

from member_fixtures import Tenant, seed_tenant, seed_user
from notify_fixtures import WEB_APP_URL, Sent, message, notifier
from pg import ScratchDatabase
from sft.data import users
from sft.data.database import Database
from sft.data.mail import MailErrorKind
from sft.data.outbox import OutboxMessage
from sft.data.roles import API, NOTIFY
from sft.data.scope import Scope
from sft.data.users import InvitationMatch
from sft.runtime.cognito import CognitoUserPool
from sft.runtime.keycloak import KeycloakUserPool
from sft.service.notifications import Done, Notifier
from sft.service.user_pool import UserPool
from test_notify_pool import FakePool

pytestmark = pytest.mark.anyio

_INVITATION = re.compile(re.escape(WEB_APP_URL) + r"/invite#([A-Za-z0-9_-]+)")
COGNITO_POOL = "ap-northeast-1_Example1"


@dataclass
class World:
    db: ScratchDatabase
    database: Database
    tenant: Tenant
    pool: FakePool


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    name = f"pool-{secrets.token_hex(6)}"
    migrated_db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (gen_random_uuid(), NULL, 'local', :name, 'https://pool.example.test', 'active')",
        name=name,
    )
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield World(migrated_db, database, seed_tenant(migrated_db), FakePool(name))
    await database.dispose()


def with_pool(w: World, sent: Sent, pool: UserPool | None) -> Notifier:
    worker = notifier(w.database, sent)
    worker.pool = pool
    return worker


def use_sso(w: World, status: str = "active") -> str:
    """The tenant's own connection, as `configureTenantSso` records it, with one proven domain
    linked to it; the domain."""
    connection, domain = uuid.uuid4(), f"corp-{w.tenant.id.hex}.example.test"
    w.db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :tenant, 'oidc', :name, 'https://idp.example.test', :status)",
        id=connection,
        tenant=w.tenant.id,
        name=w.tenant.id.hex,
        status=status,
    )
    w.db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, verified_at, "
        "idp_connection_id, created_by) VALUES (gen_random_uuid(), :tenant, :domain, "
        "repeat('v', 32), now(), :connection, :admin)",
        tenant=w.tenant.id,
        domain=domain,
        connection=connection,
        admin=w.tenant.admin,
    )
    return domain


def invite_on(w: World, domain: str, status: str = "invited") -> uuid.UUID:
    """A user of the tenant at an address on `domain`."""
    return seed_user(w.db, w.tenant.id, status=status, email=f"{uuid.uuid4().hex}@{domain}")


def tenant_log(w: World, target: uuid.UUID) -> list[tuple[str, dict[str, object]]]:
    return [
        (str(row[0]), row[1])  # type: ignore[misc]
        for row in w.db.sql(
            "SELECT action, details FROM audit_events WHERE tenant_id = :t AND target_id = :id "
            "ORDER BY occurred_at, id",
            t=w.tenant.id,
            id=target,
        )
    ]


def invitation(w: World, user_id: uuid.UUID) -> tuple[bytes | None, datetime | None]:
    [(hashed, expires_at)] = w.db.sql(
        "SELECT invitation_token_hash, invitation_expires_at FROM users WHERE id = :u", u=user_id
    )
    return hashed, expires_at  # type: ignore[return-value]


async def signs_in_with(w: World, hashed: bytes | None) -> InvitationMatch | None:
    """What `startInvitationSignIn` finds for the link: the API's lookup (lookup scope)."""
    assert hashed is not None
    api = Database.connect(w.db.url(API), pool_size=1)
    try:
        async with api.transaction(Scope.lookup()) as session:
            return await users.find_invitation(session, hashed)
    finally:
        await api.dispose()


def token_in(text: str) -> str:
    match = _INVITATION.search(text)
    assert match, "no invitation link in the email"
    return match.group(1)


# ---- the pool fakes: the Keycloak and Cognito adapters ----


class KeycloakFake:
    """Keycloak's admin API, answering in turn; `calls` is every request but the token."""

    def __init__(self, answers: list[httpx.Response]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-only", "expires_in": 300})
        self.calls.append((request.method, request.url.path))
        return self.answers.pop(0)

    def pool(self, provider_name: str) -> KeycloakUserPool:
        return KeycloakUserPool(
            base_url="http://oidc:8080",
            realm="sft",
            client_id="sft-notify-local",
            client_secret="test-only",  # noqa: S106 - a fake
            provider_name=provider_name,
            http=httpx.AsyncClient(transport=httpx.MockTransport(self)),
        )


@pytest.fixture
def cognito() -> Iterator[tuple[object, Stubber]]:
    client = boto3.session.Session().client(
        "cognito-idp",
        config=Config(region_name="ap-northeast-1"),
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106
    )
    with Stubber(client) as stubber:
        yield client, stubber
        stubber.assert_no_pending_responses()


def cognito_pool(client: object, provider_name: str) -> CognitoUserPool:
    return CognitoUserPool(client, user_pool_id=COGNITO_POOL, provider_name=provider_name)  # type: ignore[arg-type]


# ---- (1) an SSO tenant's invitation: a link, no pool user ----


async def test_an_sso_tenants_invitation_is_a_one_time_link_and_no_pool_user(w: World) -> None:
    domain = use_sso(w)
    invited = invite_on(w, domain)
    sent = Sent()
    worker = with_pool(w, sent, w.pool)
    before = datetime.now(UTC)
    done = await worker.handle(message(w.tenant.id, "member.invited", user_id=invited))
    assert done is Done.PROCESSED

    assert w.pool.calls == []  # no pool user, no identity
    assert w.db.sql("SELECT count(*) FROM user_identities WHERE user_id = :u", u=invited) == [(0,)]
    [email] = sent.emails
    assert email.email_type == "member_invitation_sso"
    token = token_in(email.text)
    assert len(token) >= 43  # 256 bits, base64url
    # The row holds the token's SHA-256 only, for 7 days; the lookup finds the user by it.
    hashed, expires_at = invitation(w, invited)
    assert hashed == hashlib.sha256(token.encode()).digest()
    assert expires_at is not None
    assert timedelta(days=7) <= expires_at - before < timedelta(days=7, minutes=5)
    assert await signs_in_with(w, hashed) == InvitationMatch(invited, w.tenant.id)
    # Audited, and the token is in no event.
    log = tenant_log(w, invited)
    assert [action for action, _ in log] == ["user.invitation_link_issued", "email.sent"]
    assert log[0][1] == {"replaced": False, "system_actor": "notification_worker"}
    assert log[1][1]["email_type"] == "member_invitation_sso"
    assert token not in json.dumps(log)
    assert await worker.handle(message(w.tenant.id, "member.invited", user_id=invited)) in (
        Done.PROCESSED,
        Done.DUPLICATE,
    )


async def test_an_sso_invitation_asks_nothing_of_keycloak_or_cognito(
    w: World, cognito: tuple[object, Stubber]
) -> None:
    domain = use_sso(w)
    keycloak = KeycloakFake([])  # any request would find no answer and fail
    client, _ = cognito  # the stubber has no response queued: any call would fail
    for pool in (keycloak.pool(w.pool.provider_name), cognito_pool(client, w.pool.provider_name)):
        invited = invite_on(w, domain)
        sent = Sent()
        done = await with_pool(w, sent, pool).handle(
            message(w.tenant.id, "member.invited", user_id=invited)
        )
        assert done is Done.PROCESSED
        assert [e.email_type for e in sent.emails] == ["member_invitation_sso"]
    assert keycloak.calls == []


async def test_an_sso_invitation_needs_no_pool(w: World) -> None:
    domain = use_sso(w)
    invited = invite_on(w, domain)
    sent = Sent()
    done = await with_pool(w, sent, None).handle(
        message(w.tenant.id, "member.invited", user_id=invited)
    )
    assert done is Done.PROCESSED
    assert [e.email_type for e in sent.emails] == ["member_invitation_sso"]


async def test_a_tenant_whose_connection_is_inactive_invites_through_the_pool(w: World) -> None:
    domain = use_sso(w, status="inactive")
    invited = invite_on(w, domain)
    sent = Sent()
    await with_pool(w, sent, w.pool).handle(message(w.tenant.id, "member.invited", user_id=invited))
    assert [e.email_type for e in sent.emails] == ["member_invitation"]
    assert str(invited) in w.pool.users
    assert invitation(w, invited) == (None, None)


@pytest.mark.parametrize("where", ["elsewhere", "an unproven claim", "proven but not linked"])
async def test_an_address_off_the_proven_linked_domains_gets_a_local_invitation(
    w: World, where: str
) -> None:
    # The tenant allows local members unless it requires SSO, and a link would be no use to
    # someone with no identity at its provider (authn and authz 2.5).
    use_sso(w)
    domain = "example.test"
    if where != "elsewhere":
        domain = f"{where.split()[0]}-{uuid.uuid4().hex}.example.test"
        w.db.sql(
            "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, verified_at, "
            "created_by) VALUES (gen_random_uuid(), :tenant, :domain, repeat('c', 32), "
            "CASE WHEN :proven THEN now() END, :admin)",
            tenant=w.tenant.id,
            domain=domain,
            proven=where == "proven but not linked",
            admin=w.tenant.admin,
        )
    invited = invite_on(w, domain)
    sent = Sent()
    done = await with_pool(w, sent, w.pool).handle(
        message(w.tenant.id, "member.invited", user_id=invited)
    )
    assert done is Done.PROCESSED
    [email] = sent.emails
    assert email.email_type == "member_invitation"
    assert re.search(r"Your temporary password: (\S+)", email.text)
    assert str(invited) in w.pool.users
    assert invitation(w, invited) == (None, None)


async def test_without_a_pool_an_address_off_the_domains_is_left_for_the_pool(w: World) -> None:
    use_sso(w)
    invited = invite_on(w, "example.test")
    sent = Sent()
    done = await with_pool(w, sent, None).handle(
        message(w.tenant.id, "member.invited", user_id=invited)
    )
    assert done is Done.PROCESSED
    assert sent.emails == []
    assert invitation(w, invited) == (None, None)


async def test_a_tenant_that_requires_sso_sends_a_link_whatever_the_domain(w: World) -> None:
    use_sso(w)
    w.db.sql("UPDATE tenants SET sso_required = true WHERE id = :t", t=w.tenant.id)
    for pool in (w.pool, None):
        invited = invite_on(w, "example.test")
        sent = Sent()
        done = await with_pool(w, sent, pool).handle(
            message(w.tenant.id, "member.invited", user_id=invited)
        )
        assert done is Done.PROCESSED
        assert [e.email_type for e in sent.emails] == ["member_invitation_sso"]
        assert invitation(w, invited)[0] is not None
    assert w.pool.calls == []


async def test_a_redelivery_after_a_failed_send_mints_a_link_that_replaces_the_first(
    w: World,
) -> None:
    domain = use_sso(w)
    invited = invite_on(w, domain)
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE])
    worker = with_pool(w, sent, w.pool)
    invite = message(w.tenant.id, "member.invited", user_id=invited)
    with pytest.raises(Exception, match="TestFailure"):
        await worker.handle(invite)
    first, _ = invitation(w, invited)
    assert first is not None  # committed before the send, so a link that goes out works

    assert await worker.handle(invite) is Done.PROCESSED
    assert await worker.handle(invite) is Done.DUPLICATE
    [email] = sent.emails
    second, _ = invitation(w, invited)
    assert second == hashlib.sha256(token_in(email.text).encode()).digest() != first
    assert await signs_in_with(w, first) is None
    assert await signs_in_with(w, second) == InvitationMatch(invited, w.tenant.id)
    log = tenant_log(w, invited)
    assert [action for action, _ in log] == [
        "user.invitation_link_issued",
        "user.invitation_link_issued",
        "email.sent",
    ]
    assert log[1][1]["replaced"] is True


@pytest.mark.parametrize("status", ["active", "deactivated"])
async def test_a_member_no_longer_invited_gets_no_link(w: World, status: str) -> None:
    user_id = invite_on(w, use_sso(w), status=status)
    sent = Sent()
    for pool in (w.pool, None):
        done = await with_pool(w, sent, pool).handle(
            message(w.tenant.id, "member.invited", user_id=user_id)
        )
        assert done is Done.PROCESSED
    assert sent.emails == []
    assert invitation(w, user_id) == (None, None)


async def test_a_suspended_tenants_invitation_sends_nothing(w: World) -> None:
    domain = use_sso(w)
    invited = invite_on(w, domain)
    w.db.sql("UPDATE tenants SET status = 'suspended' WHERE id = :t", t=w.tenant.id)
    sent = Sent()
    await with_pool(w, sent, None).handle(message(w.tenant.id, "member.invited", user_id=invited))
    assert sent.emails == []
    assert invitation(w, invited) == (None, None)


async def test_a_reset_in_an_sso_tenant_still_makes_a_pool_user(w: World) -> None:
    # An operator's temporary local sign-in is a reset (authn and authz 2.5): never a link.
    use_sso(w)
    reset_id = uuid.uuid4()
    w.db.sql("UPDATE users SET sign_in_reset_id = :r WHERE id = :u", r=reset_id, u=w.tenant.admin)
    sent = Sent()
    await with_pool(w, sent, w.pool).handle(
        message(w.tenant.id, "member.sign_in_reset", user_id=w.tenant.admin, reset_id=reset_id)
    )
    assert [e.email_type for e in sent.emails] == ["member_invitation"]
    assert w.pool.users[str(w.tenant.admin)]["enrolment"] == str(reset_id)


# ---- (2) every admin is told of an admin recovery ----


def seed_recovery(
    w: World, user_id: uuid.UUID, *, temporary: bool, reset_id: uuid.UUID | None = None
) -> uuid.UUID:
    # A temporary one is marked ended, as the job leaves it, so no other test's run of the daily
    # job on the shared database ends it again.
    recovery_id, reset = uuid.uuid4(), reset_id or uuid.uuid4()
    w.db.sql(
        "INSERT INTO admin_recoveries (id, tenant_id, user_id, kind, confirmed_via, "
        "operator_name, sign_in_reset_id, temporary_sign_in_expires_at, ended_at) VALUES (:id, "
        ":tenant, :user, :kind, 'Called the recovery contact', 'operator-1', :reset, "
        "CASE WHEN :temporary THEN now() + interval '72 hours' END, "
        "CASE WHEN :temporary THEN now() END)",
        id=recovery_id,
        tenant=w.tenant.id,
        user=user_id,
        kind="temporary_local_sign_in" if temporary else "sign_in_reset",
        reset=reset,
        temporary=temporary,
    )
    # The recovery's reset is the admin's latest, as recoverTenantAdmin leaves it.
    w.db.sql("UPDATE users SET sign_in_reset_id = :r WHERE id = :u", r=reset, u=user_id)
    return recovery_id


def address(w: World, user_id: uuid.UUID) -> str:
    [(email,)] = w.db.sql("SELECT email FROM users WHERE id = :u", u=user_id)
    return str(email)


@pytest.mark.parametrize("temporary", [False, True])
async def test_every_active_admin_is_told_which_admin_was_recovered(
    w: World, temporary: bool
) -> None:
    other_admin = seed_user(w.db, w.tenant.id, role="admin")
    seed_user(w.db, w.tenant.id, role="admin", status="deactivated")
    recovered = w.tenant.admin
    recovery_id = seed_recovery(w, recovered, temporary=temporary)
    sent = Sent()
    notice = message(
        w.tenant.id, "tenant.admin_recovered", user_id=recovered, admin_recovery_id=recovery_id
    )
    assert await with_pool(w, sent, None).handle(notice) is Done.PROCESSED
    assert await with_pool(w, sent, None).handle(notice) is Done.DUPLICATE

    # The active admins, the recovered one included; no member and no deactivated admin.
    assert sorted(e.to for e in sent.emails) == sorted(
        [address(w, recovered), address(w, other_admin)]
    )
    for email in sent.emails:
        assert email.email_type == "tenant_admin_recovered"
        assert address(w, recovered) in email.text
        assert ("temporary sign-in" in email.text) is temporary
        assert "Called the recovery contact" not in email.text  # confirmed_via stays in the row
        assert "operator-1" not in email.text
    log = tenant_log(w, recovery_id)
    assert [action for action, _ in log] == ["email.sent", "email.sent"]
    assert {d["email_type"] for _, d in log} == {"tenant_admin_recovered"}


async def test_a_redelivery_after_a_failure_midway_tells_only_the_admins_not_told(
    w: World,
) -> None:
    seed_user(w.db, w.tenant.id, role="admin")
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=False)
    sent = Sent(fail_on={2: MailErrorKind.UNAVAILABLE})
    worker = with_pool(w, sent, None)
    notice = message(
        w.tenant.id, "tenant.admin_recovered", user_id=w.tenant.admin, admin_recovery_id=recovery_id
    )
    with pytest.raises(Exception, match="TestFailure"):
        await worker.handle(notice)
    assert await worker.handle(notice) is Done.PROCESSED
    assert len({e.to for e in sent.emails}) == len(sent.emails) == 2


async def test_a_suspended_tenants_recovery_notice_sends_nothing(w: World) -> None:
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=False)
    w.db.sql("UPDATE tenants SET status = 'suspended' WHERE id = :t", t=w.tenant.id)
    sent = Sent()
    notice = message(
        w.tenant.id, "tenant.admin_recovered", user_id=w.tenant.admin, admin_recovery_id=recovery_id
    )
    assert await with_pool(w, sent, None).handle(notice) is Done.PROCESSED
    assert sent.emails == []


# ---- (3) the end of a temporary sign-in deletes its pool user ----


def ended(w: World, recovery_id: uuid.UUID) -> OutboxMessage:
    return message(
        w.tenant.id,
        "member.temporary_sign_in_ended",
        user_id=w.tenant.admin,
        admin_recovery_id=recovery_id,
    )


async def make_pool_user(w: World, enrolment: str) -> None:
    await w.pool.create_user(
        username=str(w.tenant.admin),
        email=address(w, w.tenant.admin),
        tenant_id=w.tenant.id,
        temporary_password=secrets.token_urlsafe(18),
        enrolment=enrolment,
    )


async def test_the_end_deletes_the_pool_user_made_for_the_recovery(w: World) -> None:
    reset_id = uuid.uuid4()
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True, reset_id=reset_id)
    await make_pool_user(w, str(reset_id))
    sent = Sent()
    worker = with_pool(w, sent, w.pool)
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    assert str(w.tenant.admin) not in w.pool.users
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    assert sent.emails == []


async def test_a_pool_user_made_since_for_a_newer_enrolment_stays(w: World) -> None:
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True)
    await make_pool_user(w, str(uuid.uuid4()))  # a newer reset's: the admin's sign-in now
    worker = with_pool(w, Sent(), w.pool)
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    assert str(w.tenant.admin) in w.pool.users
    assert "delete" not in w.pool.calls


async def test_after_a_newer_reset_the_end_leaves_the_pool_to_that_reset(w: World) -> None:
    # The newer reset's own message replaces the recovery's pool user; the end never races it.
    reset_id = uuid.uuid4()
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True, reset_id=reset_id)
    await make_pool_user(w, str(reset_id))
    w.db.sql(
        "UPDATE users SET sign_in_reset_id = :r WHERE id = :u", r=uuid.uuid4(), u=w.tenant.admin
    )
    worker = with_pool(w, Sent(), w.pool)
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    assert str(w.tenant.admin) in w.pool.users
    assert "delete" not in w.pool.calls


async def test_the_end_is_recorded_once_and_without_a_pool_does_nothing(w: World) -> None:
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True)
    worker = with_pool(w, Sent(), None)
    notice = ended(w, recovery_id)
    assert await worker.handle(notice) is Done.PROCESSED
    assert await worker.handle(notice) is Done.DUPLICATE


async def test_the_end_deletes_the_keycloak_user_of_the_recovery_only(w: World) -> None:
    reset_id = uuid.uuid4()
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True, reset_id=reset_id)
    username = str(w.tenant.admin)
    made_for = {"id": "kc-1", "username": username, "attributes": {"enrolment_id": [str(reset_id)]}}
    newer = {"id": "kc-2", "username": username, "attributes": {"enrolment_id": ["invitation"]}}
    keycloak = KeycloakFake(
        [
            httpx.Response(200, json=[made_for]),  # find
            httpx.Response(200, json=[made_for]),  # delete: find its ID
            httpx.Response(204),  # delete
            httpx.Response(200, json=[newer]),  # the second recovery's find
        ]
    )
    worker = with_pool(w, Sent(), keycloak.pool(w.pool.provider_name))
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    assert [method for method, _ in keycloak.calls] == ["GET", "GET", "DELETE"]
    assert keycloak.calls[-1][1].endswith("/users/kc-1")

    other = seed_recovery(w, w.tenant.admin, temporary=True)
    assert await worker.handle(ended(w, other)) is Done.PROCESSED
    assert [method for method, _ in keycloak.calls] == ["GET", "GET", "DELETE", "GET"]


async def test_the_end_deletes_the_cognito_user_of_the_recovery_only(
    w: World, cognito: tuple[object, Stubber]
) -> None:
    client, stub = cognito
    reset_id = uuid.uuid4()
    recovery_id = seed_recovery(w, w.tenant.admin, temporary=True, reset_id=reset_id)
    username = str(w.tenant.admin)

    def user(enrolment: str) -> dict[str, object]:
        return {
            "Username": username,
            "UserAttributes": [
                {"Name": "sub", "Value": str(uuid.uuid4())},
                {"Name": "custom:enrolment_id", "Value": enrolment},
            ],
        }

    expected = {"UserPoolId": COGNITO_POOL, "Username": username}
    stub.add_response("admin_get_user", user(str(reset_id)), expected)
    stub.add_response("admin_delete_user", {}, expected)
    stub.add_response("admin_get_user", user("invitation"), expected)  # no delete follows
    worker = with_pool(w, Sent(), cognito_pool(client, w.pool.provider_name))
    assert await worker.handle(ended(w, recovery_id)) is Done.PROCESSED
    other = seed_recovery(w, w.tenant.admin, temporary=True)
    assert await worker.handle(ended(w, other)) is Done.PROCESSED
