"""Tenants, users and callers for the member and transfer routes' tests and the authorization
matrix.

Rows are seeded as the superuser, which neither row-level security nor the audit trigger applies
to, so seeding is never mistaken for the code under test. Requests go through the real app over
ASGI, with the caller dependency (#113's session resolution) replaced by the caller under test, the
rate limiter by `RecordingLimiter`, which admits every request and keeps what it was asked, and the
files buckets by `FakeObjects` (object_fixtures.py).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx2 as httpx
from fastapi import FastAPI

from api_settings import EMAIL_HMAC_KEYRING
from object_fixtures import FakeObjects
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.caller import get_caller
from sft.api.rate_limits import get_rate_limiter
from sft.core.errors import RateLimited, Unauthenticated
from sft.core.ids import uuid7
from sft.core.pseudonyms import EmailKeyring
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import API
from sft.service.caller import AuthMethod, Caller
from sft.service.rate_limits import Charge
from sft.service.rate_limits.limits import KeyType, KeyValue, Limit
from sft.service.uploads import UploadPolicy

EMAIL_KEYRING = EmailKeyring.from_json(EMAIL_HMAC_KEYRING)
"""The `email-hmac` keyring of the apps these tests build, from api_settings."""


@dataclass(frozen=True)
class Tenant:
    id: uuid.UUID
    admin: uuid.UUID
    member: uuid.UUID
    target: uuid.UUID
    """An active member the admin acts on."""


def seed_user(
    db: ScratchDatabase,
    tenant_id: uuid.UUID,
    *,
    role: str = "member",
    status: str = "active",
    email: str | None = None,
) -> uuid.UUID:
    user_id = uuid7()
    address = email or f"{user_id.hex}@example.test"
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :tenant, :email, lower(:email), :role, :status)",
        id=user_id,
        tenant=tenant_id,
        email=address,
        role=role,
        status=status,
    )
    return user_id


def seed_tenant(db: ScratchDatabase) -> Tenant:
    tenant_id = uuid.uuid4()
    db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id)
    return Tenant(
        id=tenant_id,
        admin=seed_user(db, tenant_id, role="admin"),
        member=seed_user(db, tenant_id),
        target=seed_user(db, tenant_id),
    )


def session_caller(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    role: Role,
    method: AuthMethod = AuthMethod.PASSKEY,
    *,
    signed_in: timedelta = timedelta(minutes=1),
) -> Caller:
    return Caller.member(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        auth_method=method,
        auth_time=datetime.now(UTC) - signed_in,
        session_id=uuid.uuid4(),
    )


@dataclass
class RecordingLimiter:
    """A stand-in for `RateLimiter`: each check's limit IDs, keys and cost (`check_all` records
    each of its charges as a check), each `peek_all`; `refuse` makes it a 429."""

    checks: list[tuple[tuple[str, ...], dict[KeyType, KeyValue]]] = field(default_factory=list)
    costs: list[int] = field(default_factory=list)
    peeks: list[list[tuple[str, int]]] = field(default_factory=list)
    refuse: bool = False

    async def check(
        self, limits: Sequence[Limit], keys: Mapping[KeyType, KeyValue], *, cost: int = 1
    ) -> None:
        self.checks.append((tuple(limit.id for limit in limits), dict(keys)))
        self.costs.append(cost)
        if self.refuse:
            raise RateLimited(retry_after=30)

    async def peek_all(self, charges: Sequence[Charge]) -> None:
        self.peeks.append([(c.limit.id, c.cost) for c in charges])
        if self.refuse:
            raise RateLimited(retry_after=30)

    async def check_all(self, charges: Sequence[Charge]) -> None:
        for charge in charges:
            await self.check([charge.limit], charge.keys, cost=charge.cost)


def app_for(
    database: Database,
    caller: Callable[[], Caller | None],
    limiter: RecordingLimiter | None = None,
    objects: FakeObjects | None = None,
    policy: UploadPolicy | None = None,
) -> FastAPI:
    app = create_app()
    app.state.database = database
    app.state.email_keyring = EMAIL_KEYRING
    app.state.objects = objects or FakeObjects()
    app.state.upload_policy = policy or UploadPolicy()
    recording = limiter or RecordingLimiter()

    def resolve() -> Caller:
        found = caller()
        if found is None:
            raise Unauthenticated("authentication_required")
        return found

    app.dependency_overrides[get_caller] = resolve
    app.dependency_overrides[get_rate_limiter] = lambda: recording
    return app


@asynccontextmanager
async def client(
    db: ScratchDatabase,
    caller: Callable[[], Caller | None],
    limiter: RecordingLimiter | None = None,
    objects: FakeObjects | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    database = Database.connect(db.url(API), pool_size=2)
    try:
        transport = httpx.ASGITransport(app=app_for(database, caller, limiter, objects))
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
            yield http
    finally:
        await database.dispose()


def events(db: ScratchDatabase, user_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT action, actor_type, actor_id, security_critical FROM audit_events "
        "WHERE target_id = :id ORDER BY occurred_at, id",
        id=user_id,
    )
