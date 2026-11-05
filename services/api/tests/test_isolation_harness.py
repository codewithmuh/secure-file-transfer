"""The isolation harness tested on its stand-in tables, and shown to catch what it is for.

The cases here are the shapes later tables will have: a child under a composite foreign key, a
credential found by a lookup function, a resource scope, a lifecycle job's find step. The tests
after them break one layer at a time and check that the suite fails the build.
"""

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import URL, Connection, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

import isolation_fixture as fx
from isolation import Case, Cases, Mode, Tenants, World, pool, seed_tenant, world_database
from pg import (
    EXEMPT_FOREIGN_KEYS,
    ScratchDatabase,
    definer_function_problems,
    definer_functions,
    foreign_keys_without_tenant,
)
from sft.data.access import NotFoundError, ScopeNotAllowedError, in_scope
from sft.data.rls import policy_sql, tenant_rls_sql
from sft.data.roles import API, JOBS, SCAN
from sft.data.scope import Scope, ScopeKind, Subject

TENANT, RESOURCE, SYSTEM, LOOKUP = (
    ScopeKind.TENANT,
    ScopeKind.RESOURCE,
    ScopeKind.SYSTEM,
    ScopeKind.LOOKUP,
)


def my_widget(mine: object) -> Subject:
    """A link session for mine's widget, as an upload request's session would be."""
    return Subject.upload_request(mine.rows["widget"])  # type: ignore[attr-defined]


cases = Cases()
API_SCOPES = {API: [TENANT, RESOURCE]}


@cases.add(scopes=API_SCOPES, subject=my_widget)
async def get_their_widget(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.get_widget(session, tenants.theirs.rows["widget"])


@cases.add(scopes=API_SCOPES, subject=my_widget)
async def list_widgets(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.list_widgets(session)


@cases.add(scopes=API_SCOPES, subject=my_widget)
async def list_their_parts(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.list_parts(session, tenants.theirs.rows["widget"])


@cases.add(scopes={API: [TENANT], JOBS: [TENANT, SYSTEM]})
async def rename_their_widget(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.rename_widget(session, tenants.theirs.rows["widget"], "renamed")


@cases.add(scopes={API: [TENANT]})
async def delete_their_widget(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.delete_widget(session, tenants.theirs.rows["widget"])


@cases.add(scopes=API_SCOPES, subject=my_widget)
async def add_a_part_to_their_widget(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.add_part(session, tenants.theirs.rows["widget"], "smuggled")


@cases.add(scopes={JOBS: [SYSTEM, TENANT]})
async def find_widgets(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.find_widgets(session)


# In lookup scope it finds their widget, by design; in the others it must not.
@cases.add(scopes={API: [LOOKUP, TENANT, RESOURCE]}, subject=my_widget)
async def look_up_their_token(session: AsyncSession, tenants: Tenants) -> object:
    return await fx.lookup_widget(session, str(tenants.theirs.rows["token"]))


test_stand_in_tables = cases.test()


# ---- within a tenant: the resource rule is the data layer's alone ----

pytestmark = pytest.mark.anyio


async def test_a_resource_scope_reaches_only_its_subject(isolation_world: World) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    mine = seed_tenant(db, "mine")
    other = uuid.uuid4()
    db.sql(
        "INSERT INTO widgets (id, tenant_id, name, token_hash) VALUES (:id, :t, 'other', :h)",
        id=other,
        t=mine.tenant_id,
        h=fx.token_hash(str(other)),
    )
    async with pool(db, API) as database:
        scope = Scope.resource(mine.tenant_id, my_widget(mine))
        async with database.transaction(scope) as session:
            assert [w.id for w in await fx.list_widgets(session)] == [mine.rows["widget"]]
            assert await fx.get_widget(session, other) is None
            assert [p.id for p in await fx.list_parts(session, mine.rows["widget"])] == [
                mine.rows["part"]
            ]
        # A recipient's session reaches no widget at all: the model says so.
        recipient = Scope.resource(mine.tenant_id, Subject.recipient(mine.rows["widget"]))
        async with database.transaction(recipient) as session:
            assert await fx.list_widgets(session) == []


async def test_a_tenant_scope_reaches_its_own_rows(isolation_world: World) -> None:
    # The cases above would pass on code that found nothing at all; this one wouldn't.
    db = isolation_world.database(Mode.AS_BUILT)
    mine = seed_tenant(db, "mine")
    async with pool(db, API) as database, database.transaction(Scope.tenant(mine.tenant_id)) as s:
        assert (await fx.get_widget(s, mine.rows["widget"])).name == mine.marker  # type: ignore[union-attr]
        part = await fx.add_part(s, mine.rows["widget"], "mine")
    assert db.sql("SELECT tenant_id FROM widget_parts WHERE id = :id", id=part) == [
        (mine.tenant_id,)
    ]


# ---- the credential lookup mechanism (data model 4.2) ----


async def test_a_lookup_finds_any_tenants_credential_without_bypassrls(
    isolation_world: World,
) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    theirs = seed_tenant(db, "theirs")
    async with pool(db, API) as database, database.transaction(Scope.lookup()) as session:
        found = await fx.lookup_widget(session, str(theirs.rows["token"]))
        assert found == (theirs.rows["widget"], theirs.tenant_id)
        assert await fx.lookup_widget(session, "no such token") is None


async def test_lookup_read_matches_only_in_lookup_scope(isolation_world: World) -> None:
    # Even called directly, past require_scope, the function finds nothing in a tenant scope.
    db = isolation_world.database(Mode.AS_BUILT)
    theirs = seed_tenant(db, "theirs")
    mine = seed_tenant(db, "mine")
    async with pool(db, API) as database, database.transaction(Scope.tenant(mine.tenant_id)) as s:
        rows = await s.execute(
            text("SELECT * FROM lookup_widget(:h)"), {"h": fx.token_hash(str(theirs.rows["token"]))}
        )
        assert rows.all() == []


async def test_only_sft_api_may_call_a_lookup_function(isolation_world: World) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    mine = seed_tenant(db, "mine")
    async with pool(db, SCAN) as database:
        with pytest.raises(DBAPIError, match="permission denied for function lookup_widget"):
            async with database.transaction(Scope.tenant(mine.tenant_id)) as session:
                await session.execute(text("SELECT * FROM lookup_widget('\\x00')"))


def test_sft_lookup_reads_only_the_columns_it_was_granted(isolation_world: World) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    with pytest.raises(DBAPIError, match="permission denied for table widgets"):
        db.sql("SET LOCAL ROLE sft_lookup; SELECT name FROM widgets")


async def test_a_lookup_is_refused_by_the_data_layer_outside_lookup_scope(
    isolation_world: World,
) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    mine = seed_tenant(db, "mine")
    async with pool(db, API) as database, database.transaction(Scope.tenant(mine.tenant_id)) as s:
        with pytest.raises(ScopeNotAllowedError, match="runs in a lookup scope, not tenant"):
            await fx.lookup_widget(s, "token")


def test_the_stand_in_schema_passes_the_catalog_checks(isolation_world: World) -> None:
    db = isolation_world.database(Mode.AS_BUILT)
    assert foreign_keys_without_tenant(db, EXEMPT_FOREIGN_KEYS) == []
    assert "lookup_widget(bytea)" in [f for f, *_ in definer_functions(db)]
    assert definer_function_problems(db) == []


# ---- the suite fails the build when a layer leaks ----


async def leaky_get_widget(session: AsyncSession, tenants: Tenants) -> object:
    # The bug the suite is for: a query that forgot in_scope.
    return await session.scalar(
        select(fx.Widget).where(fx.Widget.id == tenants.theirs.rows["widget"])
    )


async def leaky_rename(session: AsyncSession, tenants: Tenants) -> object:
    statement = fx.widgets.update().where(fx.widgets.c.id == tenants.theirs.rows["widget"])
    return (await session.execute(statement.values(name="renamed"))).rowcount  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("call", "found"), [(leaky_get_widget, "read"), (leaky_rename, "changed rows")]
)
async def test_a_query_without_its_scope_fails_when_the_data_layer_stands_alone(
    isolation_world: World, call: object, found: str
) -> None:
    case = Case("leaky", call, {API: [TENANT]})  # type: ignore[arg-type]
    await isolation_world.check(case, Mode.AS_BUILT)  # row-level security still holds
    with pytest.raises(AssertionError, match=found):
        await isolation_world.check(case, Mode.DATA_LAYER_ALONE)


def break_the_schema(connection: Connection) -> None:
    """A permissive policy that leaks, a child with a plain foreign key instead of
    `tenant_foreign_key_sql`, and a definer function nobody pinned."""
    statements = [
        policy_sql("leak", "widgets", roles=[API], command="SELECT", using="true"),
        "CREATE TABLE widget_notes (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, "
        "widget_id uuid NOT NULL REFERENCES widgets (id), body text NOT NULL)",
        *tenant_rls_sql("widget_notes", grants={API: "SELECT, INSERT"}),
        "CREATE FUNCTION peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER "
        "AS $$ SELECT count(*) FROM public.widgets $$",
    ]
    for statement in statements:
        connection.execute(text(statement))


@pytest.fixture(scope="module")
def broken(admin_url: URL) -> Iterator[ScratchDatabase]:
    with world_database(admin_url, rls=True) as db:
        db.as_owner(break_the_schema)
        yield db


@pytest.fixture(scope="module")
def broken_world(broken: ScratchDatabase) -> Iterator[World]:
    world = World({Mode.AS_BUILT: broken})
    yield world
    world.close()


async def test_a_leaking_policy_fails_when_row_level_security_stands_alone(
    broken_world: World,
) -> None:
    world = broken_world
    case = Case("get", get_their_widget, {API: [TENANT]})
    await world.check(case, Mode.AS_BUILT)  # the data layer still holds
    with pytest.raises(AssertionError, match="read"):
        await world.check(case, Mode.RLS_ALONE)


async def add_a_note_to_their_widget(session: AsyncSession, tenants: Tenants) -> object:
    note = {"id": uuid.uuid4(), "tenant_id": tenants.mine.tenant_id, "body": "smuggled"}
    table = fx.sa.table("widget_notes", *(fx.sa.column(c) for c in [*note, "widget_id"]))
    await session.execute(insert(table).values(**note, widget_id=tenants.theirs.rows["widget"]))
    return note["id"]


async def test_a_reference_across_tenants_fails_without_a_composite_key(
    broken: ScratchDatabase, broken_world: World
) -> None:
    # Row-level security doesn't check foreign keys: only the composite key would refuse this.
    world = broken_world
    with pytest.raises(AssertionError, match=r"refers to theirs from \['widget_notes.widget_id'\]"):
        await world.check(Case("note", add_a_note_to_their_widget, {API: [TENANT]}), Mode.AS_BUILT)
    # And the catalog check fails the build before any test has to try it.
    assert foreign_keys_without_tenant(broken, EXEMPT_FOREIGN_KEYS) == [
        "widget_notes_widget_id_fkey: widget_notes (widget_id) -> widgets (id)"
    ]


def test_the_catalog_check_finds_an_unsafe_definer_function(broken: ScratchDatabase) -> None:
    assert definer_function_problems(broken) == [
        "peek(): SECURITY DEFINER owned by sft_owner, neither a lookup owned by sft_lookup "
        "nor one of the owner's known functions",
    ]


def test_the_catalog_check_holds_each_kind_to_its_own_rule(admin_url: URL) -> None:
    # A lookup another role may call too, and an owner's function that PUBLIC may call.
    def loosen(connection: Connection) -> None:
        connection.execute(text("GRANT EXECUTE ON FUNCTION audit_partition_status() TO PUBLIC"))
        connection.execute(text("SET LOCAL ROLE sft_lookup"))  # only its owner may grant it
        connection.execute(text("GRANT EXECUTE ON FUNCTION lookup_widget(bytea) TO sft_scan"))

    with world_database(admin_url, rls=True) as db:
        db.as_owner(loosen)
        # Outside public too: no schema but PostgreSQL's own is skipped.
        db.sql("CREATE SCHEMA elsewhere")
        db.sql(
            "CREATE FUNCTION elsewhere.peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER "
            "SET search_path = pg_catalog, public, pg_temp AS $$ SELECT 1::bigint $$"
        )
        assert sorted(definer_function_problems(db)) == [
            "audit_partition_status(): executable by ['PUBLIC', 'sft_jobs'], not ['sft_jobs']",
            "elsewhere.peek(): SECURITY DEFINER owned by postgres, neither a lookup owned by "
            "sft_lookup nor one of the owner's known functions",
            "lookup_widget(bytea): executable by ['sft_api', 'sft_scan'], not sft_api alone",
        ]


# ---- in system scope no write reaches a tenant row, whatever the code forgets ----


async def rename_all_widgets(session: AsyncSession, tenants: Tenants) -> object:
    # A job that forgot it is in system scope: in_scope reaches every tenant there.
    statement = update(fx.Widget).where(in_scope(fx.Widget, session)).values(name="renamed")
    return (await session.execute(statement)).rowcount  # type: ignore[attr-defined]


async def rename_through_the_table(session: AsyncSession, tenants: Tenants) -> object:
    statement = fx.widgets.update().where(fx.widgets.c.id == tenants.theirs.rows["widget"])
    return (await session.execute(statement.values(name="renamed"))).rowcount  # type: ignore[attr-defined]


async def rename_a_loaded_widget(session: AsyncSession, tenants: Tenants) -> object:
    widget = await session.get(fx.Widget, tenants.theirs.rows["widget"])
    assert widget is not None  # system scope reads across tenants
    widget.name = "renamed"
    await session.flush()
    return None


@pytest.mark.parametrize(
    "call", [rename_all_widgets, rename_through_the_table, rename_a_loaded_widget]
)
async def test_a_system_scope_write_is_refused_before_the_database(
    isolation_world: World, call: object
) -> None:
    # With row-level security off, nothing but the data layer stands in the way.
    db = isolation_world.database(Mode.DATA_LAYER_ALONE)
    theirs = seed_tenant(db, "theirs")
    tenants = Tenants(seed_tenant(db, "mine"), theirs)
    async with pool(db, JOBS) as database:
        with pytest.raises(ScopeNotAllowedError, match="sft_jobs writes no tenant rows"):
            async with database.transaction(Scope.system()) as session:
                await call(session, tenants)  # type: ignore[operator]
    assert db.sql("SELECT name FROM widgets WHERE id = :id", id=theirs.rows["widget"]) == [
        (theirs.marker,)
    ]


# ---- the harness's own rules ----


async def test_a_bug_is_not_taken_for_a_refusal(isolation_world: World) -> None:
    async def look_up_a_missing_key(session: AsyncSession, tenants: Tenants) -> object:
        return {}["widget"]

    with pytest.raises(KeyError):
        await isolation_world.check(
            Case("bug", look_up_a_missing_key, {API: [TENANT]}), Mode.AS_BUILT
        )


async def test_not_found_is_a_refusal(isolation_world: World) -> None:
    async def not_found(session: AsyncSession, tenants: Tenants) -> object:
        raise NotFoundError

    await isolation_world.check(Case("not_found", not_found, {API: [TENANT]}), Mode.AS_BUILT)


def test_a_case_names_only_scopes_its_role_opens() -> None:
    async def call(session: AsyncSession, tenants: Tenants) -> object:
        return None  # pragma: no cover

    with pytest.raises(ValueError, match="sft_scan never opens a system scope"):
        Case("c", call, {SCAN: [SYSTEM]}).attempts()
    with pytest.raises(ValueError, match="recovery reaches across tenants"):
        Case("c", call, {"sft_recovery": [ScopeKind.RECOVERY]}).attempts()
    # The tenant-less scopes a role may open are always tried too.
    assert Case("c", call, {API: [TENANT]}).attempts() == [
        (API, TENANT, True),
        (API, ScopeKind.PLATFORM, False),
        (API, LOOKUP, False),
    ]
