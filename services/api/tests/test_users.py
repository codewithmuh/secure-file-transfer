"""`sft.data.users` against PostgreSQL: invitations, the lookup, changes, and their audit events."""

from __future__ import annotations

import hashlib
import secrets
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from pg import ScratchDatabase
from sft.data.access import NotFoundError, ScopeNotAllowedError
from sft.data.audit import Actor
from sft.data.database import Database
from sft.data.models import ActorType, Role, UserStatus
from sft.data.scope import Scope
from sft.data.users import (
    InvitationMatch,
    UserExistsError,
    accept_invitation,
    change_role,
    create_invitation,
    deactivate_user,
    find_invitation,
    get_user,
    get_user_by_email,
    list_users,
    lock_active_admins,
    normalize_email,
    set_dlp_approver,
    set_sso_fallback,
)

pytestmark = pytest.mark.anyio

OPERATOR = Actor(ActorType.OPERATOR, uuid.uuid4())
OPERATOR_AS_ADMIN = Actor(ActorType.ADMIN, uuid.uuid4())


def new_tenant(db: ScratchDatabase) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id)
    return tenant_id


def token() -> tuple[str, bytes]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).digest()


def events(db: ScratchDatabase, user_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT action, actor_type, security_critical, details FROM audit_events "
        "WHERE target_id = :id ORDER BY occurred_at, id",
        id=user_id,
    )


def outbox(db: ScratchDatabase, user_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT topic, tenant_id FROM outbox WHERE payload ->> 'user_id' = :id", id=str(user_id)
    )


async def test_an_invitation_writes_the_user_its_audit_event_and_its_email(
    operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    async with operator_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="First.Admin@Example.com", role=Role.ADMIN, actor=OPERATOR
        )
    assert (user.tenant_id, user.email, user.email_normalized) == (
        tenant_id,
        "First.Admin@Example.com",
        "first.admin@example.com",
    )
    assert (user.role, user.status, user.sso_fallback, user.dlp_approver) == (
        "admin",
        "invited",
        False,
        False,
    )
    assert user.invitation_token_hash is None
    assert user.invitation_expires_at is None
    assert events(migrated_db, user.id) == [("user.invited", "operator", False, {"role": "admin"})]
    assert outbox(migrated_db, user.id) == [("member.invited", tenant_id)]


async def test_an_address_is_invited_once_per_tenant_and_other_tenants_are_not_checked(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    first, second = new_tenant(migrated_db), new_tenant(migrated_db)
    actor = Actor(ActorType.ADMIN, uuid.uuid4())
    async with api_db.transaction(Scope.tenant(first)) as session:
        await create_invitation(session, email="a@example.com", role=Role.MEMBER, actor=actor)
    with pytest.raises(UserExistsError):
        async with api_db.transaction(Scope.tenant(first)) as session:
            await create_invitation(session, email="A@EXAMPLE.COM", role=Role.ADMIN, actor=actor)
    async with api_db.transaction(Scope.tenant(second)) as session:
        other = await create_invitation(
            session, email="a@example.com", role=Role.MEMBER, actor=actor
        )
    assert other.tenant_id == second


async def test_an_sso_invitation_is_found_by_its_hash_and_accepted_once(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    raw, digest = token()
    actor = Actor(ActorType.ADMIN, uuid.uuid4())
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="sso@example.com", role=Role.MEMBER, actor=actor, token_hash=digest
        )
    assert user.invitation_token_hash == digest
    assert user.invitation_expires_at is not None

    async with api_db.transaction(Scope.lookup()) as session:
        assert await find_invitation(session, digest) == InvitationMatch(user.id, tenant_id)
        assert await find_invitation(session, token()[1]) is None
    # Only in lookup scope: inside a tenant's transaction the lookup isn't available at all.
    with pytest.raises(ScopeNotAllowedError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await find_invitation(session, digest)

    member = Actor(ActorType.MEMBER, user.id)
    with pytest.raises(NotFoundError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await accept_invitation(session, user.id, actor=member, token_hash=token()[1])
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        active = await accept_invitation(session, user.id, actor=member, token_hash=digest)
    assert (active.status, active.invitation_token_hash, active.invitation_expires_at) == (
        "active",
        None,
        None,
    )
    async with api_db.transaction(Scope.lookup()) as session:
        assert await find_invitation(session, digest) is None
    with pytest.raises(NotFoundError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await accept_invitation(session, user.id, actor=member, token_hash=digest)
    assert [e[0] for e in events(migrated_db, user.id)] == ["user.invited", "user.activated"]
    assert raw not in str(events(migrated_db, user.id))


async def test_an_expired_invitation_is_neither_found_nor_accepted(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    _, digest = token()
    actor = Actor(ActorType.ADMIN, uuid.uuid4())
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="late@example.com", role=Role.MEMBER, actor=actor, token_hash=digest
        )
    migrated_db.sql(
        # As the superuser, whom the audit trigger exempts, like the owner.
        "UPDATE users SET invitation_expires_at = now() - interval '1 second' WHERE id = :id",
        id=user.id,
    )
    async with api_db.transaction(Scope.lookup()) as session:
        assert await find_invitation(session, digest) is None
    with pytest.raises(NotFoundError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await accept_invitation(
                session, user.id, actor=Actor(ActorType.MEMBER, user.id), token_hash=digest
            )


async def test_a_local_member_is_activated_without_a_link(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="local@example.com", role=Role.MEMBER, actor=OPERATOR_AS_ADMIN
        )
        active = await accept_invitation(session, user.id, actor=Actor(ActorType.MEMBER, user.id))
    assert active.status == UserStatus.ACTIVE


async def test_reads_list_filter_and_page(api_db: Database, migrated_db: ScratchDatabase) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        made = [
            await create_invitation(
                session, email=f"u{i}@example.com", role=role, actor=OPERATOR_AS_ADMIN
            )
            for i, role in enumerate([Role.ADMIN, Role.MEMBER, Role.MEMBER])
        ]
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        assert [u.id for u in await list_users(session)] == [u.id for u in made]
        members = await list_users(session, role=Role.MEMBER)
        assert [u.id for u in members] == [made[1].id, made[2].id]
        page = await list_users(session, after=made[0].id, limit=1)
        assert [u.id for u in page] == [made[1].id]
        assert await list_users(session, status=UserStatus.ACTIVE) == []
        assert await list_users(session, dlp_approver=True) == []
        assert (await get_user(session, made[1].id)) is not None
        assert (await get_user(session, uuid.uuid4())) is None
        found = await get_user_by_email(session, "U2@Example.com")
        assert found is not None
        assert found.id == made[2].id
        with pytest.raises(ValueError, match="page"):
            await list_users(session, limit=0)


async def test_changes_write_their_events(api_db: Database, migrated_db: ScratchDatabase) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="c@example.com", role=Role.MEMBER, actor=OPERATOR_AS_ADMIN
        )
        await accept_invitation(session, user.id, actor=Actor(ActorType.MEMBER, user.id))
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        promoted = await change_role(session, user.id, Role.ADMIN, actor=OPERATOR_AS_ADMIN)
        assert promoted.role == "admin"
        assert await lock_active_admins(session) == [user.id]
        fallback = await set_sso_fallback(session, user.id, True, actor=OPERATOR_AS_ADMIN)
        assert fallback.sso_fallback
        approver = await set_dlp_approver(session, user.id, True, actor=OPERATOR_AS_ADMIN)
        assert approver.dlp_approver
        demoted = await change_role(session, user.id, Role.MEMBER, actor=OPERATOR_AS_ADMIN)
        assert (demoted.role, demoted.sso_fallback) == ("member", False)
        gone = await deactivate_user(session, user.id, actor=OPERATOR_AS_ADMIN)
        assert gone.status == "deactivated"
    assert [(e[0], e[2]) for e in events(migrated_db, user.id)] == [
        ("user.invited", False),
        ("user.activated", False),
        ("user.role_changed", False),
        ("user.sso_fallback_changed", False),
        ("user.dlp_approver_changed", False),
        ("user.role_changed", True),
        ("user.deactivated", True),
    ]
    with pytest.raises(NotFoundError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await deactivate_user(session, uuid.uuid4(), actor=OPERATOR_AS_ADMIN)


async def test_a_member_is_never_a_fallback_admin(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="m@example.com", role=Role.MEMBER, actor=OPERATOR_AS_ADMIN
        )
    with pytest.raises(IntegrityError):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await set_sso_fallback(session, user.id, True, actor=OPERATOR_AS_ADMIN)


async def test_no_workload_role_deletes_a_user(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="d@example.com", role=Role.MEMBER, actor=OPERATOR_AS_ADMIN
        )
    with pytest.raises(DBAPIError, match="permission denied"):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user.id})


async def test_a_user_change_without_its_audit_event_cannot_commit(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        user = await create_invitation(
            session, email="e@example.com", role=Role.MEMBER, actor=OPERATOR_AS_ADMIN
        )
    with pytest.raises(IntegrityError, match="audit_required"):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await session.execute(
                text("UPDATE users SET role = 'admin' WHERE id = :id"), {"id": user.id}
            )


def test_addresses_are_compared_in_lowercase() -> None:
    assert normalize_email("A@B.C") == "a@b.c"


async def test_a_token_hash_of_the_wrong_size_is_refused(
    api_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = new_tenant(migrated_db)
    with pytest.raises(ValueError, match="32-byte"):
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await create_invitation(
                session,
                email="f@example.com",
                role=Role.MEMBER,
                actor=OPERATOR_AS_ADMIN,
                token_hash=b"short",
            )
