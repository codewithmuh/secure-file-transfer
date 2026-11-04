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
foreign key violation, a read-only transaction, or a `LookupError` from the code.

Adding a case (README, "The isolation suite"):

    cases = Cases()

    @cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
    async def get_another_tenants_tenant(session: AsyncSession, tenants: Tenants) -> object:
        return await get_tenant(session, tenants.theirs.tenant_id)

    test_isolation = cases.test()

A new table also gets its rows in `seed_tenant`, so every case has something of theirs to miss.
"""

from __future__ import annotations

import json
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager, nullcontext
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from unittest import mock

import pytest
from sqlalchemy import URL, inspect, true
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

import isolation_fixture
from pg import ScratchDatabase, fresh_database, tenant_tables
from sft.data import access
from sft.data.access import SCOPES_BY_ROLE, ScopeNotAllowedError
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.roles import MIGRATE
from sft.data.scope import Scope, ScopeKind, Subject


class Mode(StrEnum):
    AS_BUILT = "as_built"
    DATA_LAYER_ALONE = "data_layer_alone"
    RLS_ALONE = "rls_alone"


MODES = tuple(Mode)

# What a refusal looks like from PostgreSQL: a policy or a grant (42501), a foreign key (23503),
# a read-only transaction (25006). Anything else is a bug, and the case fails with it.
REFUSED = frozenset({"42501", "23503", "25006"})

# Scopes that read across tenants by design, when a case names them: a job's find step in system
# scope, a credential lookup in lookup scope. There the harness checks that nothing changed, not
# what was read; the lookup's own tests check it returns IDs and status only. Recovery re-applies
# records across tenants and has its own policy tests, so no case runs in it.
_ACROSS = frozenset({ScopeKind.SYSTEM, ScopeKind.LOOKUP})
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

    def __str__(self) -> str:
        return self.name

    def attempts(self) -> list[tuple[str, ScopeKind, bool]]:
        """Each (role, scope, named): the scopes named, then the tenant-less ones the role opens."""
        tried = []
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
    ) -> Callable[[Call], Call]:
        def register(call: Call) -> Call:
            self._cases.append(Case(call.__name__, call, scopes, subject))
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


def seed_tenant(db: ScratchDatabase, label: str) -> Seeded:
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
    return Seeded(tenant_id, marker, rows)


def snapshot(db: ScratchDatabase, tenant: Seeded) -> dict[str, list[str]]:
    """Every row of `tenant`, as the superuser sees it."""
    rows = {}
    for table in sorted(tenant_tables(db)):
        key = "id" if table == "tenants" else "tenant_id"
        rows[table] = [
            json.dumps(row, sort_keys=True, default=str)
            for (row,) in db.sql(
                # Names from the catalog, not input.
                f'SELECT to_jsonb(t) FROM "{table}" t WHERE {key} = :tenant ORDER BY 1::text',  # noqa: S608
                tenant=tenant.tenant_id,
            )
        ]
    return rows


def references_to(db: ScratchDatabase, tenant: Seeded) -> list[str]:
    """Rows of other tenants that hold one of `tenant`'s IDs in a uuid column."""
    found = []
    columns = db.sql(
        """
        SELECT c.relname, a.attname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
         WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
           AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped
           AND a.atttypid = 'uuid'::regtype AND a.attname NOT IN ('id', 'tenant_id')
        """
    )
    owned = tenant_tables(db)
    for table, column in columns:
        if table not in owned or table == "tenants":
            continue
        count = db.sql(
            f'SELECT count(*) FROM "{table}" '  # noqa: S608 - names from the catalog
            f'WHERE tenant_id <> :tenant AND "{column}" = ANY(:ids)',
            tenant=tenant.tenant_id,
            ids=list(tenant.ids()),
        )[0][0]
        if count:
            found.append(f"{table}.{column}")
    return found


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


def _without_tenant_filter() -> Any:
    """The test hook of ADR-0020: `in_scope` adds no tenant condition at all."""
    return mock.patch.object(access, "_tenant_condition", return_value=true())


async def _attempt(database: Database, scope: Scope, case: Case, tenants: Tenants) -> object:
    try:
        async with database.transaction(scope) as session:
            return await case.call(session, tenants)
    except DBAPIError as exc:
        state = getattr(exc.orig, "sqlstate", None)
        if state not in REFUSED:
            raise
        return f"refused ({state})"
    except (LookupError, ScopeNotAllowedError) as exc:
        return f"refused ({type(exc).__name__})"


@dataclass
class World:
    """The isolation suite's databases, by mode. `RLS_ALONE` uses the `AS_BUILT` one."""

    databases: Mapping[Mode, ScratchDatabase]

    def database(self, mode: Mode) -> ScratchDatabase:
        return self.databases[Mode.AS_BUILT if mode is Mode.RLS_ALONE else mode]

    async def check(self, case: Case, mode: Mode) -> None:
        db = self.database(mode)
        tenants = Tenants(seed_tenant(db, "mine"), seed_tenant(db, "theirs"))
        for role, kind, named in case.attempts():
            where = f"{case.name} as {role} in {kind} scope, {mode}"
            across = named and kind in _ACROSS
            # A scope that reads across tenants must change neither.
            watched = [tenants.theirs, tenants.mine] if across else [tenants.theirs]
            before = {t.tenant_id: snapshot(db, t) for t in watched}
            scope = scope_for(kind, case, tenants.mine)
            hook = _without_tenant_filter() if mode is Mode.RLS_ALONE else nullcontext()
            async with pool(db, role) as database:
                with hook:
                    result = await _attempt(database, scope, case, tenants)
            if not across:
                exposed = [tenants.theirs] + ([tenants.mine] if kind in _TENANTLESS else [])
                for tenant in exposed:
                    assert not leaks(result, tenant), f"{where}: read {leaks(result, tenant)}"
            for tenant in watched:
                assert snapshot(db, tenant) == before[tenant.tenant_id], f"{where}: changed rows"
            assert not references_to(db, tenants.theirs), (
                f"{where}: refers to theirs from {references_to(db, tenants.theirs)}"
            )
