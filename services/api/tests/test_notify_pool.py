"""The notification worker with a user pool (#197; authn and authz 2.5): an invitation creates the
member's pool user with a temporary password before the email names it, then records the email and
the identity together; a sign-in reset deletes the old pool user and makes a new one; an address
another tenant's member signs in with gets the address-in-use email, which the tenant's log can't
tell from an invitation. The pool is a fake here; the Keycloak adapter has its own tests
(test_keycloak_pool.py), and `make web-e2e` runs it against Keycloak."""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest

from member_fixtures import Tenant, seed_tenant, seed_user
from notify_fixtures import Sent, message, notifier
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.mail import MailErrorKind
from sft.data.roles import NOTIFY
from sft.service.notifications import Done, Notifier
from sft.service.user_pool import PoolUser, PoolUserExistsError

pytestmark = pytest.mark.anyio

_PASSWORD = re.compile(r"Your temporary password: (\S+)")


@dataclass
class FakePool:
    """The pool in memory, as Keycloak behaves: users by username, each with an email, a
    subject, a password and the enrolment it was made for."""

    provider_name: str
    users: dict[str, dict[str, str]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    taken_emails: set[str] = field(default_factory=set)
    """Addresses another tenant's members sign in with."""

    async def find_user(self, *, username: str) -> PoolUser | None:
        found = self.users.get(username)
        return None if found is None else PoolUser(found["subject"], found["enrolment"])

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        tenant_id: uuid.UUID,
        temporary_password: str,
        enrolment: str,
    ) -> str:
        self.calls.append("create")
        if username in self.users:  # ours, from an earlier delivery: taken over
            self.users[username].update(password=temporary_password, enrolment=enrolment)
            return self.users[username]["subject"]
        if email in self.taken_emails or any(u["email"] == email for u in self.users.values()):
            raise PoolUserExistsError("email")
        subject = str(uuid.uuid4())
        self.users[username] = {
            "email": email,
            "subject": subject,
            "password": temporary_password,
            "tenant": str(tenant_id),
            "enrolment": enrolment,
        }
        return subject

    async def delete_user(self, *, username: str) -> bool:
        self.calls.append("delete")
        return self.users.pop(username, None) is not None


@dataclass
class World:
    db: ScratchDatabase
    database: Database
    tenant: Tenant
    pool: FakePool
    connection: uuid.UUID


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    name = f"pool-{secrets.token_hex(6)}"
    connection = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, 'https://pool.example.test', 'active')",
        id=connection,
        name=name,
    )
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield World(migrated_db, database, seed_tenant(migrated_db), FakePool(name), connection)
    await database.dispose()


def with_pool(w: World, sent: Sent) -> Notifier:
    worker = notifier(w.database, sent)
    worker.pool = w.pool
    return worker


def identities(w: World, user_id: uuid.UUID) -> list[tuple[object, ...]]:
    return w.db.sql(
        "SELECT idp_connection_id, subject FROM user_identities WHERE user_id = :u "
        "ORDER BY subject",
        u=user_id,
    )


def tenant_log(w: World, user_id: uuid.UUID) -> list[tuple[str, dict[str, object]]]:
    """What the tenant's admins could read of the user: every event of the tenant on them."""
    return [
        (str(row[0]), row[1])  # type: ignore[misc]
        for row in w.db.sql(
            "SELECT action, details FROM audit_events WHERE tenant_id = :t AND target_id = :u "
            "ORDER BY occurred_at, id",
            t=w.tenant.id,
            u=user_id,
        )
    ]


def platform_log(w: World, user_id: uuid.UUID) -> list[tuple[str, dict[str, object]]]:
    return [
        (str(row[0]), row[1])  # type: ignore[misc]
        for row in w.db.sql(
            "SELECT action, details FROM audit_events WHERE tenant_id IS NULL AND target_id = :u",
            u=user_id,
        )
    ]


def address(w: World, user_id: uuid.UUID) -> str:
    [(email,)] = w.db.sql("SELECT email FROM users WHERE id = :u", u=user_id)
    return str(email)


def start_reset(w: World, user_id: uuid.UUID) -> uuid.UUID:
    """What `resetUserSignIn` leaves for the worker: a new pending reset on the user."""
    reset_id = uuid.uuid4()
    w.db.sql("UPDATE users SET sign_in_reset_id = :r WHERE id = :u", r=reset_id, u=user_id)
    return reset_id


def password_in(text: str) -> str:
    match = _PASSWORD.search(text)
    assert match, "no temporary password in the email"
    return match.group(1)


async def test_an_invitation_creates_the_pool_user_then_records_the_email_and_identity(
    w: World,
) -> None:
    invited = seed_user(w.db, w.tenant.id, status="invited")
    sent = Sent()
    worker = with_pool(w, sent)
    done = await worker.handle(message(w.tenant.id, "member.invited", user_id=invited))
    assert done is Done.PROCESSED

    pool_user = w.pool.users[str(invited)]
    assert (pool_user["email"], pool_user["tenant"]) == (address(w, invited), str(w.tenant.id))
    assert pool_user["enrolment"] == "invitation"
    assert identities(w, invited) == [(w.connection, pool_user["subject"])]
    [email] = sent.emails
    assert (email.to, email.email_type) == (address(w, invited), "member_invitation")
    # The email names the password the pool holds; the audit log doesn't.
    assert password_in(email.text) == pool_user["password"]
    log = tenant_log(w, invited)
    assert [action for action, _ in log] == ["email.sent"]
    assert pool_user["password"] not in json.dumps(log)


async def test_the_tenant_log_cant_tell_an_address_in_use_from_an_invitation(w: World) -> None:
    """authn and authz 2.5, NFR-12: the inviting tenant sees an invitation email sent, as for anyone
    else; that the address signs in for another tenant is in the platform audit log only."""
    ordinary = seed_user(w.db, w.tenant.id, status="invited")
    taken = seed_user(w.db, w.tenant.id, status="invited")
    w.pool.taken_emails.add(address(w, taken))
    sent = Sent()
    worker = with_pool(w, sent)
    for user_id in (ordinary, taken):
        done = await worker.handle(message(w.tenant.id, "member.invited", user_id=user_id))
        assert done is Done.PROCESSED

    [_, in_use] = sent.emails
    assert in_use.email_type == "invitation_address_in_use"
    assert "temporary password" not in in_use.text.lower()
    assert identities(w, taken) == []
    assert str(taken) not in w.pool.users
    # Tenant A's log reads the same for both.
    assert tenant_log(w, taken) == tenant_log(w, ordinary)
    assert tenant_log(w, taken) == [
        ("email.sent", {"email_type": "member_invitation", "system_actor": "notification_worker"})
    ]
    [(action, details)] = platform_log(w, taken)
    assert action == "invitation.address_in_use"
    assert details["tenant_id"] == str(w.tenant.id)
    assert platform_log(w, ordinary) == []


async def test_an_invitation_redelivered_after_a_failed_send_reuses_its_pool_user(
    w: World,
) -> None:
    invited = seed_user(w.db, w.tenant.id, status="invited")
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE])
    worker = with_pool(w, sent)
    invitation = message(w.tenant.id, "member.invited", user_id=invited)
    with pytest.raises(Exception, match="TestFailure"):
        await worker.handle(invitation)
    first = dict(w.pool.users[str(invited)])
    assert identities(w, invited) == []  # recorded with the email, which didn't go

    assert await worker.handle(invitation) is Done.PROCESSED
    assert await worker.handle(invitation) is Done.DUPLICATE
    second = w.pool.users[str(invited)]
    assert second["subject"] == first["subject"]
    assert second["password"] != first["password"]
    assert "delete" not in w.pool.calls
    [email] = sent.emails
    assert password_in(email.text) == second["password"]
    assert identities(w, invited) == [(w.connection, first["subject"])]


async def test_a_reset_replaces_the_pool_user_and_its_identity(w: World) -> None:
    member = w.tenant.target
    old = await w.pool.create_user(
        username=str(member),
        email=address(w, member),
        tenant_id=w.tenant.id,
        temporary_password=secrets.token_urlsafe(18),
        enrolment="invitation",
    )
    # An identity left behind on the pool (the API deletes them; the worker replaces, never adds).
    w.db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :t, :u, :c, :s)",
        id=uuid.uuid4(),
        t=w.tenant.id,
        u=member,
        c=w.connection,
        s=old,
    )
    w.pool.calls.clear()
    reset_id = start_reset(w, member)
    sent = Sent()
    worker = with_pool(w, sent)
    reset = message(w.tenant.id, "member.sign_in_reset", user_id=member, reset_id=reset_id)
    assert await worker.handle(reset) is Done.PROCESSED
    assert w.pool.calls == ["delete", "create"]
    new = w.pool.users[str(member)]
    assert (new["subject"] != old, new["enrolment"]) == (True, str(reset_id))
    assert identities(w, member) == [(w.connection, new["subject"])]
    [email] = sent.emails
    assert email.email_type == "member_invitation"


async def test_a_reset_redelivered_after_a_failed_send_never_deletes_its_own_user(
    w: World,
) -> None:
    """#197 review: one pool user and one identity, and no second delete, however often the
    message is delivered."""
    member = w.tenant.target
    reset_id = start_reset(w, member)
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE])
    worker = with_pool(w, sent)
    reset = message(w.tenant.id, "member.sign_in_reset", user_id=member, reset_id=reset_id)
    with pytest.raises(Exception, match="TestFailure"):
        await worker.handle(reset)
    subject = w.pool.users[str(member)]["subject"]
    assert await worker.handle(reset) is Done.PROCESSED
    assert w.pool.calls == ["create", "create"]  # no delete: the user is this reset's own
    assert w.pool.users[str(member)]["subject"] == subject
    assert identities(w, member) == [(w.connection, subject)]
    assert len(sent.emails) == 1


async def test_a_superseded_reset_sends_nothing(w: World) -> None:
    """A newer reset replaced this one before it was handled: only the newer one invites."""
    member = w.tenant.target
    first = start_reset(w, member)
    second = start_reset(w, member)
    sent = Sent()
    worker = with_pool(w, sent)
    old = message(w.tenant.id, "member.sign_in_reset", user_id=member, reset_id=first)
    assert await worker.handle(old) is Done.PROCESSED
    assert (sent.emails, w.pool.calls) == ([], [])
    new = message(w.tenant.id, "member.sign_in_reset", user_id=member, reset_id=second)
    assert await worker.handle(new) is Done.PROCESSED
    assert len(sent.emails) == 1


async def test_a_member_who_joined_meanwhile_gets_no_invitation(w: World) -> None:
    sent = Sent()
    worker = with_pool(w, sent)
    done = await worker.handle(message(w.tenant.id, "member.invited", user_id=w.tenant.member))
    assert done is Done.PROCESSED
    assert (sent.emails, w.pool.calls) == ([], [])


async def test_a_deactivated_user_gets_nothing(w: World) -> None:
    gone = seed_user(w.db, w.tenant.id, status="deactivated")
    reset_id = start_reset(w, gone)
    sent = Sent()
    worker = with_pool(w, sent)
    for topic in ("member.invited", "member.sign_in_reset"):
        done = await worker.handle(message(w.tenant.id, topic, user_id=gone, reset_id=reset_id))
        assert done is Done.PROCESSED
    assert (sent.emails, w.pool.calls) == ([], [])


async def test_without_the_pools_connection_the_message_waits(w: World) -> None:
    invited = seed_user(w.db, w.tenant.id, status="invited")
    worker = with_pool(w, Sent())
    worker.pool = FakePool("no-such-pool")
    with pytest.raises(ValueError, match="connection is missing"):
        await worker.handle(message(w.tenant.id, "member.invited", user_id=invited))


async def test_without_a_pool_a_reset_is_recorded_and_sends_nothing(w: World) -> None:
    sent = Sent()
    worker = notifier(w.database, sent)
    reset = message(
        w.tenant.id, "member.sign_in_reset", user_id=w.tenant.member, reset_id=uuid.uuid4()
    )
    assert await worker.handle(reset) is Done.PROCESSED
    assert await worker.handle(reset) is Done.DUPLICATE
    assert sent.emails == []
