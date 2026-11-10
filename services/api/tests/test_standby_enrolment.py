"""The standby enrolment after a regional failover (#258; authn and authz 2.6;
`sft.service.standby_enrolment`, `sft.workers.standby_enrolment`).

Against PostgreSQL as `sft_notify`, on a migrated database of the test's own (the job reads every
tenant's members), with the pool a fake that behaves as Cognito and Keycloak do (test_notify_pool's)
and the mail adapter a list.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass

import pytest
from sqlalchemy import URL

from member_fixtures import seed_tenant, seed_user
from pg import ScratchDatabase, fresh_database
from sft.core.settings import NotifySettings
from sft.data.database import Database
from sft.data.mail import OutgoingEmail
from sft.data.migrate import run
from sft.data.roles import MIGRATE, NOTIFY
from sft.service.email import EmailRenderer
from sft.service.standby_enrolment import (
    ENROLMENT,
    PoolConnectionMissingError,
    Result,
    enrol_standby,
)
from sft.workers import standby_enrolment as command
from test_notify_pool import FakePool
from test_notify_settings import REQUIRED

pytestmark = pytest.mark.anyio

RENDERER = EmailRenderer("https://app.example.test")
_PASSWORD = re.compile(r"Your temporary password: (\S+)")


@pytest.fixture
def own_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def notify(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(NOTIFY), pool_size=1)
    yield database
    await database.dispose()


def connection(db: ScratchDatabase, *, tenant: uuid.UUID | None = None) -> tuple[uuid.UUID, str]:
    """A user pool's connection (no tenant), or a tenant's SSO provider."""
    connection_id, name = uuid.uuid4(), f"conn-{uuid.uuid4().hex[:8]}"
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :tenant, :kind, :name, 'https://idp.example.test', 'active')",
        id=connection_id,
        tenant=tenant,
        kind="local" if tenant is None else "oidc",
        name=name,
    )
    return connection_id, name


def identity(db: ScratchDatabase, tenant: uuid.UUID, user: uuid.UUID, conn: uuid.UUID) -> None:
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :tenant, :user, :conn, :subject)",
        id=uuid.uuid4(),
        tenant=tenant,
        user=user,
        conn=conn,
        subject=uuid.uuid4().hex,
    )


@dataclass
class Mailbox:
    sent: list[OutgoingEmail]

    async def send(self, email: OutgoingEmail) -> str:
        self.sent.append(email)
        return f"message-{len(self.sent)}"


async def test_every_active_local_member_is_enrolled_once_and_nobody_else(
    notify: Database, own_db: ScratchDatabase
) -> None:
    tokyo, _ = connection(own_db)
    osaka, osaka_name = connection(own_db)
    tenant = seed_tenant(own_db)
    sso, _ = connection(own_db, tenant=tenant.id)
    local = seed_user(own_db, tenant.id)
    identity(own_db, tenant.id, local, tokyo)
    sso_member = seed_user(own_db, tenant.id)
    identity(own_db, tenant.id, sso_member, sso)
    gone = seed_user(own_db, tenant.id, status="deactivated")
    identity(own_db, tenant.id, gone, tokyo)
    done = seed_user(own_db, tenant.id)
    identity(own_db, tenant.id, done, tokyo)
    identity(own_db, tenant.id, done, osaka)
    suspended = seed_tenant(own_db)
    own_db.sql("UPDATE tenants SET status = 'suspended' WHERE id = :id", id=suspended.id)
    identity(own_db, suspended.id, suspended.member, tokyo)

    pool, mail = FakePool(osaka_name), Mailbox([])
    results = await enrol_standby(notify, pool=pool, send=mail.send, renderer=RENDERER)

    # The seeded tenants' admins and other members have no identity at all: not local.
    assert results[Result.ENROLLED] == 1
    assert results[Result.ALREADY] == 1
    assert results[Result.INACTIVE] >= 1  # the suspended tenant's members
    assert set(pool.users) == {str(local)}
    made = pool.users[str(local)]
    assert made["enrolment"] == ENROLMENT
    [email] = mail.sent
    password = _PASSWORD.search(email.text)
    assert password is not None
    assert password.group(1) == made["password"]
    # The identity and the email's audit event, together, in the member's tenant.
    [(subject,)] = own_db.sql(
        "SELECT subject FROM user_identities WHERE user_id = :u AND idp_connection_id = :c",
        u=local,
        c=osaka,
    )
    assert subject == made["subject"]
    assert own_db.sql(
        "SELECT tenant_id, details->>'email_type' FROM audit_events "
        "WHERE action = 'email.sent' AND target_id = :u",
        u=local,
    ) == [(tenant.id, "member_reenrolment")]

    # A second run sends nothing more.
    again = await enrol_standby(notify, pool=pool, send=mail.send, renderer=RENDERER)
    assert again[Result.ENROLLED] == 0
    assert again[Result.ALREADY] == 2
    assert len(mail.sent) == 1


async def test_an_address_another_tenants_member_holds_here_is_counted_and_left(
    notify: Database, own_db: ScratchDatabase
) -> None:
    tokyo, _ = connection(own_db)
    _, osaka_name = connection(own_db)
    tenant = seed_tenant(own_db)
    local = seed_user(own_db, tenant.id, email="taken@example.test")
    identity(own_db, tenant.id, local, tokyo)
    pool, mail = FakePool(osaka_name, taken_emails={"taken@example.test"}), Mailbox([])
    results = await enrol_standby(notify, pool=pool, send=mail.send, renderer=RENDERER)
    assert results[Result.ADDRESS_IN_USE] == 1
    assert mail.sent == []


async def test_a_pool_without_its_connection_creates_nobody(
    notify: Database, own_db: ScratchDatabase
) -> None:
    tokyo, _ = connection(own_db)
    tenant = seed_tenant(own_db)
    local = seed_user(own_db, tenant.id)
    identity(own_db, tenant.id, local, tokyo)
    pool, mail = FakePool("no-such-pool"), Mailbox([])
    with pytest.raises(PoolConnectionMissingError):
        await enrol_standby(notify, pool=pool, send=mail.send, renderer=RENDERER)
    assert (pool.users, mail.sent) == ({}, [])


def test_the_command_needs_a_user_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in NotifySettings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("USER_POOL_BACKEND", "none")
    assert command.main() == 2
