"""The two-tenant isolation harness (NFR-12; data model 4.2, point 5; authn and authz 9.2).

Every data-access function, and later every endpoint, gets a case. A case calls the function in
one tenant's scope ("mine") with the other tenant's IDs ("theirs"). The harness runs it in every
scope the case names and in the tenant-less scopes its role may open, three ways:

- `AS_BUILT`: the data-access layer and row-level security together;
- `DATA_LAYER_ALONE`: row-level security disabled on every table, so `in_scope` must hold;
- `RLS_ALONE`: `in_scope`'s tenant filter removed, so the policies must hold.

After each attempt it fails the build if the result carries anything of theirs (an ID or the
marker written into their rows), if any of their rows changed, or if any row of another tenant
now refers to one of their IDs. Refusals are fine: no row, a policy or privilege error, a
foreign key violation, or the data layer's own `NotFoundError` or `ScopeNotAllowedError`. Any
other exception, a `KeyError` included, fails the case.

Adding a case (README, "The isolation suite"):

    cases = Cases()

    @cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
    async def get_another_tenants_tenant(session: AsyncSession, tenants: Tenants) -> object:
        return await get_tenant(session, tenants.theirs.tenant_id)

    test_isolation = cases.test()

A new table also gets its rows in `seed_tenant`, so every case has something of theirs to miss.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager, nullcontext
from dataclasses import dataclass, field
from enum import StrEnum
from unittest import mock

import pytest
from sqlalchemy import URL, create_engine, inspect, text, true
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

import isolation_fixture
from pg import TENANT_TABLES, ScratchDatabase, Sql, fresh_database
from sft.data import access
from sft.data.access import SCOPES_BY_ROLE, NotFoundError, ScopeNotAllowedError
from sft.data.database import Database, psycopg_url
from sft.data.migrate import run
from sft.data.roles import MIGRATE, OPERATOR
from sft.data.scope import Scope, ScopeKind, Subject


class Mode(StrEnum):
    AS_BUILT = "as_built"
    DATA_LAYER_ALONE = "data_layer_alone"
    RLS_ALONE = "rls_alone"


MODES = tuple(Mode)

# What a refusal looks like from PostgreSQL: a policy or a grant (42501), a foreign key (23503).
# Anything else is a bug, and the case fails with it.
REFUSED = frozenset({"42501", "23503"})

# Scopes that read across tenants by design, when a case names them: a job's find step in system
# scope, a credential lookup in lookup scope. There the harness checks that nothing changed, not
# what was read; the lookup's own tests check it returns IDs and status only. Recovery re-applies
# records across tenants and has its own policy tests, so no case runs in it.
_ACROSS = frozenset({ScopeKind.SYSTEM, ScopeKind.LOOKUP})
# The operator API's tenant directory (#111): `sft_operator` reads tenant rows in platform scope, by
# design, when a case says so with `across=`. No other role or scope may be named there.
_ACROSS_ON_REQUEST = {ScopeKind.PLATFORM: frozenset({OPERATOR})}
_TENANTLESS = (ScopeKind.PLATFORM, ScopeKind.LOOKUP)


@dataclass(frozen=True)
class Seeded:
    """One tenant's rows: its ID, the marker in its text columns, and its other rows by name."""

    tenant_id: uuid.UUID
    marker: str
    rows: Mapping[str, uuid.UUID] = field(default_factory=dict)

    def ids(self) -> set[uuid.UUID]:
        return {self.tenant_id, *self.rows.values()}


@dataclass(frozen=True)
class Tenants:
    mine: Seeded
    theirs: Seeded


Call = Callable[[AsyncSession, Tenants], Awaitable[object]]


@dataclass(frozen=True)
class Case:
    name: str
    call: Call
    scopes: Mapping[str, Sequence[ScopeKind]]
    """For each workload role, the scopes the function is used in."""
    subject: Callable[[Seeded], Subject] | None = None
    """Mine's subject in resource scope; by default one that reaches nothing below the tenant."""
    across: frozenset[ScopeKind] = frozenset()
    """Named scopes this case reads across tenants in by design: the operator's directory."""

    def __str__(self) -> str:
        return self.name

    def attempts(self) -> list[tuple[str, ScopeKind, bool]]:
        """Each (role, scope, named): the scopes named, then the tenant-less ones the role opens."""
        tried = []
        for kind in self.across:
            allowed_roles = _ACROSS_ON_REQUEST.get(kind, frozenset())
            naming = {role for role, kinds in self.scopes.items() if kind in kinds}
            if not naming <= allowed_roles:
                raise ValueError(f"{self.name}: only {sorted(allowed_roles)} read across in {kind}")
        for role, kinds in self.scopes.items():
            allowed = SCOPES_BY_ROLE[role]
            for kind in kinds:
                if kind not in allowed:
                    raise ValueError(f"{self.name}: {role} never opens a {kind} scope")
                if kind is ScopeKind.RECOVERY:
                    raise ValueError(f"{self.name}: recovery reaches across tenants by design")
            tried += [(role, kind, True) for kind in kinds]
            tried += [(role, k, False) for k in _TENANTLESS if k in allowed and k not in kinds]
        return tried


class Cases:
    """A module's isolation cases, and the test that runs them."""

    def __init__(self) -> None:
        self._cases: list[Case] = []

    def add(
        self,
        *,
        scopes: Mapping[str, Sequence[ScopeKind]],
        subject: Callable[[Seeded], Subject] | None = None,
        across: Sequence[ScopeKind] = (),
    ) -> Callable[[Call], Call]:
        def register(call: Call) -> Call:
            self._cases.append(Case(call.__name__, call, scopes, subject, frozenset(across)))
            return call

        return register

    def __iter__(self) -> Iterator[Case]:
        return iter(self._cases)

    def test(self) -> Callable[..., Awaitable[None]]:
        """The test function: every case, in every mode. Assign it to a `test_…` name."""

        @pytest.mark.anyio
        @pytest.mark.parametrize("mode", MODES)
        @pytest.mark.parametrize("case", list(self._cases), ids=str)
        async def test_no_tenant_reaches_another(
            case: Case, mode: Mode, isolation_world: World
        ) -> None:
            await isolation_world.check(case, mode)

        return test_no_tenant_reaches_another


# ---- the databases ----


@contextmanager
def world_database(admin_url: URL, *, rls: bool) -> Iterator[ScratchDatabase]:
    """A migrated database with the stand-in tables; with `rls=False`, row-level security off."""
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        db.as_owner(isolation_fixture.create)
        if not rls:
            for (table,) in db.sql(
                "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                "AND relrowsecurity"
            ):
                db.sql(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        yield db


class Admin:
    """The superuser on one database, over one pooled connection the checks share."""

    def __init__(self, db: ScratchDatabase) -> None:
        self._engine = create_engine(psycopg_url(db.admin), pool_size=1, max_overflow=0)
        self._tables: list[str] | None = None
        self._uuid_columns: list[tuple[str, str]] | None = None

    def sql(self, statement: str, **params: object) -> list[tuple[object, ...]]:
        with self._engine.begin() as connection:
            result = connection.execute(text(statement), params)
            return [tuple(row) for row in result] if result.returns_rows else []

    def dispose(self) -> None:
        self._engine.dispose()

    def tenant_tables(self) -> list[str]:
        """Read from the catalog once per world: its schema doesn't change while it runs."""
        if self._tables is None:
            self._tables = sorted(str(name) for (name,) in self.sql(TENANT_TABLES))
        return self._tables

    def uuid_columns(self) -> list[tuple[str, str]]:
        """The uuid columns of tenant tables, other than their own ID and tenant."""
        if self._uuid_columns is None:
            owned = set(self.tenant_tables()) - {"tenants"}
            rows = self.sql(
                """
                SELECT c.relname, a.attname FROM pg_class c
                  JOIN pg_attribute a ON a.attrelid = c.oid
                 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
                   AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped
                   AND a.atttypid = 'uuid'::regtype AND a.attname NOT IN ('id', 'tenant_id')
                 ORDER BY 1, 2
                """
            )
            self._uuid_columns = [(str(t), str(c)) for t, c in rows if t in owned]
        return self._uuid_columns


def seed_tenant(db: Sql, label: str) -> Seeded:
    """One tenant and a row in every tenant table, as the superuser.

    The superuser path skips the policies and the audit trigger of #50, so seeding is never
    mistaken for the code under test. A migration that adds a tenant table adds its rows here.
    """
    tenant_id = uuid.uuid4()
    marker = f"isolation-{label}-{secrets.token_hex(4)}"
    db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, :name, 'active')",
        id=tenant_id,
        name=marker,
    )
    rows = isolation_fixture.seed(db, tenant_id, marker)
    # The outbox (#51): one unpublished message, and one message a consumer has recorded.
    rows["outbox"], rows["processed_message"] = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload, last_error) VALUES (:id, :tenant, "
        "'isolation.seed', jsonb_build_object('file_id', CAST(:file AS text)), :marker)",
        id=rows["outbox"],
        tenant=tenant_id,
        file=str(rows["outbox"]),
        marker=marker,
    )
    db.sql(
        "INSERT INTO processed_messages (consumer, message_id, tenant_id) "
        "VALUES ('isolation', :message, :tenant)",
        message=str(rows["processed_message"]),
        tenant=tenant_id,
    )
    # Users (#112): an invited member with a live invitation link, whose address holds the marker.
    rows["user"], rows["invitation"] = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status, "
        "invitation_token_hash, invitation_expires_at) VALUES (:id, :tenant, :email, :email, "
        "'member', 'invited', sha256(convert_to(:token, 'UTF8')), now() + interval '7 days')",
        id=rows["user"],
        tenant=tenant_id,
        email=f"{marker}@example.test",
        token=str(rows["invitation"]),
    )
    # The tenant's policy and recovery contact (#111), the contact holding the marker.
    db.sql(
        "UPDATE tenants SET recovery_contact = :marker WHERE id = :tenant",
        marker=marker,
        tenant=tenant_id,
    )
    db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:tenant, 'ja')",
        tenant=tenant_id,
    )
    # Member sign-in (#113): the tenant's own SSO connection, named with the marker, the user's
    # identity there, and a live session, whose token is the SHA-256 of the session's row name.
    rows["connection"], rows["identity"], rows["session"] = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rows["session_token"] = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :tenant, 'oidc', :marker, :marker, 'active')",
        id=rows["connection"],
        tenant=tenant_id,
        marker=marker,
    )
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :tenant, :user, :connection, :marker)",
        id=rows["identity"],
        tenant=tenant_id,
        user=rows["user"],
        connection=rows["connection"],
        marker=marker,
    )
    db.sql(
        "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
        "auth_time, auth_method, expires_at, user_agent) VALUES (:id, :tenant, :user, :identity, "
        "sha256(convert_to(:token, 'UTF8')), now(), 'sso', now() + interval '12 hours', :marker)",
        id=rows["session"],
        tenant=tenant_id,
        user=rows["user"],
        identity=rows["identity"],
        token=str(rows["session_token"]),
        marker=marker,
    )
    # Idempotency keys (#144): the user's live key, named with the marker, and an expired one.
    for key, expires in ((marker, "1 day"), (f"{marker}-old", "-1 day")):
        db.sql(
            "INSERT INTO idempotency_keys (tenant_id, caller_type, caller_id, key, "
            "request_fingerprint, response_status, resource_type, resource_id, created_at, "
            "expires_at) VALUES (:tenant, 'member', :user, :key, sha256(convert_to(:key, 'UTF8')), "
            "201, 'user', :user, now() - interval '2 days', now() + CAST(:expires AS interval))",
            tenant=tenant_id,
            user=rows["user"],
            key=key,
            expires=expires,
        )
    seed_transfers(db, tenant_id, marker, rows)
    return Seeded(tenant_id, marker, rows)


def seed_transfers(db: Sql, tenant_id: uuid.UUID, marker: str, rows: dict[str, uuid.UUID]) -> None:
    """Transfers (#114): a draft of the seeded user, its recipient, an uploading file, a file that
    is completing, and the tenant's storage reservation. The marker is in the address, the sealed
    name and the upload ID."""
    for key in ("transfer", "recipient", "file", "completing_file"):
        rows[key] = uuid.uuid4()
    db.sql(
        "INSERT INTO transfers (id, tenant_id, created_by, state, expires_in, message_ct) "
        "VALUES (:id, :tenant, :user, 'draft', interval '7 days', convert_to(:marker, 'UTF8'))",
        id=rows["transfer"],
        tenant=tenant_id,
        user=rows["user"],
        marker=marker,
    )
    db.sql(
        "INSERT INTO transfer_recipients (id, tenant_id, transfer_id, email, email_normalized, "
        "locale) VALUES (:id, :tenant, :transfer, :email, :email, 'en')",
        id=rows["recipient"],
        tenant=tenant_id,
        transfer=rows["transfer"],
        email=f"{marker}@recipient.test",
    )
    for key, state in (("file", "uploading"), ("completing_file", "completing")):
        db.sql(
            "INSERT INTO files (id, tenant_id, transfer_id, display_name_ct, content_type, "
            "declared_size, storage_class, storage_key, s3_upload_id, part_size, part_count, "
            "state, completion_started_at) VALUES (:id, :tenant, :transfer, "
            "convert_to(:marker, 'UTF8'), 'text/plain', 10, 'standard', "
            "'tenants/' || :tenant || '/files/' || :id, :marker, 5242880, 1, :state, "
            "CASE WHEN :state = 'completing' THEN now() END)",
            id=rows[key],
            tenant=tenant_id,
            transfer=rows["transfer"],
            marker=marker,
            state=state,
        )
    db.sql(
        "INSERT INTO tenant_usage (tenant_id, bytes_reserved) VALUES (:tenant, 20)",
        tenant=tenant_id,
    )


def snapshot(admin: Admin, tenants: Sequence[Seeded]) -> list[tuple[object, ...]]:
    """Every row of `tenants`, as the superuser sees it, in one query."""
    parts = [
        # Names from the catalog, not input.
        f"SELECT '{table}' AS t, to_jsonb(x)::text AS r FROM \"{table}\" x "  # noqa: S608
        f"WHERE {'id' if table == 'tenants' else 'tenant_id'} = ANY(:tenants)"
        for table in admin.tenant_tables()
    ]
    return admin.sql(
        " UNION ALL ".join(parts) + " ORDER BY 1, 2", tenants=[t.tenant_id for t in tenants]
    )


def references_to(admin: Admin, tenant: Seeded) -> list[str]:
    """Rows of other tenants that hold one of `tenant`'s IDs in a uuid column, in one query."""
    parts = [
        f"(SELECT '{table}.{column}' FROM \"{table}\" "  # noqa: S608 - names from the catalog
        f'WHERE tenant_id <> :tenant AND "{column}" = ANY(:ids) LIMIT 1)'
        for table, column in admin.uuid_columns()
    ]
    if not parts:
        return []
    rows = admin.sql(" UNION ALL ".join(parts), tenant=tenant.tenant_id, ids=list(tenant.ids()))
    return sorted(str(name) for (name,) in rows)


# ---- running a case ----


def render(value: object) -> str:
    """Everything a result holds, ORM objects' columns included, as text to search."""
    if isinstance(value, DeclarativeBase):
        state = inspect(value)
        return render({a.key: getattr(value, a.key) for a in state.mapper.column_attrs})
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{render(k)}: {render(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple, set, frozenset)) or hasattr(value, "_mapping"):
        return "[" + ", ".join(render(v) for v in value) + "]"  # type: ignore[attr-defined]
    return str(value)


def leaks(result: object, tenant: Seeded) -> list[str]:
    text = render(result)
    return [str(i) for i in tenant.ids() if str(i) in text] + (
        [tenant.marker] if tenant.marker in text else []
    )


def scope_for(kind: ScopeKind, case: Case, mine: Seeded) -> Scope:
    if kind is ScopeKind.TENANT:
        return Scope.tenant(mine.tenant_id)
    if kind is ScopeKind.RESOURCE:
        subject = case.subject(mine) if case.subject else Subject.recipient(uuid.uuid4())
        return Scope.resource(mine.tenant_id, subject)
    return Scope(kind)


@asynccontextmanager
async def pool(db: ScratchDatabase, role: str) -> AsyncIterator[Database]:
    database = Database.connect(db.url(role), pool_size=1)
    try:
        yield database
    finally:
        await database.dispose()


@contextmanager
def _without_the_data_layer() -> Iterator[None]:
    """The test hook of ADR-0020: `in_scope` adds no tenant condition at all, and system scope
    may write tenant rows, so the policies alone must hold."""
    with (
        mock.patch.object(access, "_tenant_condition", return_value=true()),
        mock.patch.object(access, "_writes_tenant_rows_in_system_scope", return_value=True),
    ):
        yield


async def _attempt(database: Database, scope: Scope, case: Case, tenants: Tenants) -> object:
    try:
        async with database.transaction(scope) as session:
            return await case.call(session, tenants)
    except DBAPIError as exc:
        state = getattr(exc.orig, "sqlstate", None)
        if state not in REFUSED:
            raise
        return f"refused ({state})"
    except (NotFoundError, ScopeNotAllowedError) as exc:
        # Only the data layer's own refusals: a KeyError or IndexError is a bug, and fails.
        return f"refused ({type(exc).__name__})"


@dataclass
class World:
    """The isolation suite's databases, by mode. `RLS_ALONE` uses the `AS_BUILT` one."""

    databases: Mapping[Mode, ScratchDatabase]
    _admins: dict[str, Admin] = field(default_factory=dict)

    def database(self, mode: Mode) -> ScratchDatabase:
        return self.databases[Mode.AS_BUILT if mode is Mode.RLS_ALONE else mode]

    def admin(self, mode: Mode) -> Admin:
        db = self.database(mode)
        if db.name not in self._admins:
            self._admins[db.name] = Admin(db)
        return self._admins[db.name]

    def close(self) -> None:
        for admin in self._admins.values():
            admin.dispose()

    async def check(self, case: Case, mode: Mode) -> None:
        db, admin = self.database(mode), self.admin(mode)
        tenants = Tenants(seed_tenant(admin, "mine"), seed_tenant(admin, "theirs"))
        async with AsyncExitStack() as stack:
            pools: dict[str, Database] = {}
            for role, kind, named in case.attempts():
                if role not in pools:  # one pool per role for the whole check
                    pools[role] = await stack.enter_async_context(pool(db, role))
                await self._try(case, mode, admin, pools[role], role, kind, named, tenants)

    async def _try(
        self,
        case: Case,
        mode: Mode,
        admin: Admin,
        database: Database,
        role: str,
        kind: ScopeKind,
        named: bool,
        tenants: Tenants,
    ) -> None:
        where = f"{case.name} as {role} in {kind} scope, {mode}"
        across = named and (kind in _ACROSS or kind in case.across)
        # A scope that reads across tenants must change neither.
        watched = [tenants.theirs, tenants.mine] if across else [tenants.theirs]
        before = snapshot(admin, watched)
        scope = scope_for(kind, case, tenants.mine)
        with _without_the_data_layer() if mode is Mode.RLS_ALONE else nullcontext():
            result = await _attempt(database, scope, case, tenants)
        if not across:
            exposed = [tenants.theirs] + ([tenants.mine] if kind in _TENANTLESS else [])
            for tenant in exposed:
                assert not leaks(result, tenant), f"{where}: read {leaks(result, tenant)}"
        assert snapshot(admin, watched) == before, f"{where}: changed rows"
        referring = references_to(admin, tenants.theirs)
        assert not referring, f"{where}: refers to theirs from {referring}"
