"""Audit events after the #50 review: no backdating, no audit reads in resource scope, and what
the helper cleans or refuses before it reaches the database."""

import re
import uuid
from collections.abc import AsyncIterator
from enum import Enum, IntEnum

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.data import audit
from sft.data.access import ScopeNotAllowedError
from sft.data.audit import Actor, ActorType, Origin, Outcome, Target
from sft.data.database import Database
from sft.data.models import Tenant
from sft.data.roles import RECOVERY
from sft.data.scope import Scope, Subject

pytestmark = pytest.mark.anyio

INSUFFICIENT_PRIVILEGE = "42501"

INSERT_WITH = (
    "INSERT INTO audit_events (id, tenant_id, actor_type, action, outcome, {column}) "
    "VALUES (gen_random_uuid(), :tenant, 'system', 'x.y', 'success', {value})"
)


async def new_tenant(operator: Database) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with operator.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name="Example", status="active"))
        await audit.record(
            session,
            action="tenant.created",
            actor=Actor(ActorType.OPERATOR, uuid.uuid4()),
            target=Target("tenant", tenant_id),
        )
    return tenant_id


@pytest.fixture
async def recovery_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(RECOVERY), pool_size=1)
    yield database
    await database.dispose()


# ---- 1: the database's own tx_id and occurred_at ----


@pytest.mark.parametrize(
    ("column", "value"),
    [("occurred_at", "now() - interval '1 year'"), ("tx_id", "'1'::xid8")],
)
async def test_workload_roles_cannot_set_tx_id_or_occurred_at(
    api_db: Database, operator_db: Database, column: str, value: str
) -> None:
    tenant_id = await new_tenant(operator_db)
    with pytest.raises(DBAPIError) as refused:
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await session.execute(
                text(INSERT_WITH.format(column=column, value=value)), {"tenant": tenant_id}
            )
    assert getattr(refused.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


async def test_recovery_reimports_events_with_their_own_values(
    recovery_db: Database, migrated_db: ScratchDatabase
) -> None:
    event_id = uuid.uuid4()
    async with recovery_db.transaction(Scope.recovery()) as session:
        await session.execute(
            text(
                "INSERT INTO audit_events (id, tenant_id, tx_id, occurred_at, actor_type, action, "
                "outcome) VALUES (:id, :tenant, '12345'::xid8, date_trunc('month', now()), "
                "'system', 'transfer.revoked', 'success')"
            ),
            {"id": event_id, "tenant": uuid.uuid4()},
        )
    assert migrated_db.sql(
        "SELECT tx_id::text, occurred_at = date_trunc('month', now()) FROM audit_events "
        "WHERE id = :id",
        id=event_id,
    ) == [("12345", True)]


def test_only_recovery_may_set_tx_id_or_occurred_at(migrated_db: ScratchDatabase) -> None:
    rows = migrated_db.sql(
        """
        SELECT r.rolname, a.attname FROM pg_roles r, pg_attribute a
         WHERE a.attrelid = 'audit_events'::regclass AND a.attname IN ('tx_id', 'occurred_at')
           AND r.rolname LIKE 'sft\\_%'
           AND has_column_privilege(r.oid, 'audit_events', a.attname, 'INSERT')
        """
    )
    assert {role for role, _ in rows} == {"sft_owner", RECOVERY}


# The columns each credential lookup reads, as sft_lookup (data model 4.2), and nothing else.
LOOKUP_COLUMNS = {
    *(
        ("users", column, "SELECT")
        for column in (
            "id",
            "tenant_id",
            "status",
            "invitation_token_hash",
            "invitation_expires_at",
        )
    ),
    *(
        ("idp_connections", column, "SELECT")
        for column in ("id", "tenant_id", "kind", "provider_name", "status")
    ),
    *(
        ("user_identities", column, "SELECT")
        for column in ("id", "tenant_id", "user_id", "idp_connection_id", "subject", "expires_at")
    ),
    *(
        ("member_sessions", column, "SELECT")
        for column in ("id", "tenant_id", "session_hash", "expires_at", "revoked_at")
    ),
}
LOOKUP_GRANTS = {(table, privilege) for table, _, privilege in LOOKUP_COLUMNS}


def test_sft_lookup_reads_only_the_columns_of_its_lookups(migrated_db: ScratchDatabase) -> None:
    rows = migrated_db.sql(
        """
        SELECT c.relname, a.attname, g.privilege_type
          FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid,
               aclexplode(a.attacl) g
         WHERE c.relnamespace = 'public'::regnamespace AND g.grantee = 'sft_lookup'::regrole
        """
    )
    assert set(rows) == LOOKUP_COLUMNS
    tables = migrated_db.sql(
        """
        SELECT c.relname, g.privilege_type
          FROM pg_class c, aclexplode(c.relacl) g
         WHERE c.relnamespace = 'public'::regnamespace AND g.grantee = 'sft_lookup'::regrole
        """
    )
    assert tables == [], "sft_lookup has a table grant; it reads columns only"


def test_column_grants_follow_the_table_rules(migrated_db: ScratchDatabase) -> None:
    # Column grants live in pg_attribute, beside the table grants #48's catalog test reads.
    grants = migrated_db.sql(
        """
        SELECT c.relname, pg_get_userbyid(g.grantee), g.privilege_type
          FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid,
               aclexplode(a.attacl) g
         WHERE c.relnamespace = 'public'::regnamespace AND g.grantee <> c.relowner
         GROUP BY 1, 2, 3
        """
    )
    assert grants, "no column grants: the checks below would pass by checking nothing"
    for table, role, privilege in grants:
        assert privilege in ("SELECT", "INSERT", "UPDATE"), f"{role} has {privilege} on {table}"
        assert role.startswith("sft_")
        assert role not in ("sft_owner", "sft_migrate")
        if role == "sft_lookup":
            # The credential lookups read their columns through lookup_read (data model 4.2).
            assert (table, privilege) in LOOKUP_GRANTS, f"sft_lookup may {privilege} {table}"
        if table == "audit_events":
            assert privilege == "INSERT", f"{role} may {privilege} columns of audit_events"
        policies = migrated_db.sql(
            """
            SELECT p.polname FROM pg_policy p
             WHERE p.polrelid = CAST(:table AS regclass)
               AND p.polroles @> ARRAY[CAST(:role AS regrole)::oid]
               AND p.polcmd IN ('*', :command)
            """,
            table=table,
            role=role,
            command={"SELECT": "r", "INSERT": "a", "UPDATE": "w"}[str(privilege)],
        )
        assert policies, f"{role} may {privilege} columns of {table}, but no policy covers it"


# ---- 5: a link session never reads the audit log ----


async def test_resource_scope_writes_events_but_reads_none(
    api_db: Database, operator_db: Database
) -> None:
    tenant_id = await new_tenant(operator_db)
    link = Subject.recipient(uuid.uuid4())
    async with api_db.transaction(Scope.resource(tenant_id, link)) as session:
        await audit.record(
            session,
            action="transfer.downloaded",
            actor=Actor(ActorType.RECIPIENT, uuid.uuid4()),
            target=Target("file", uuid.uuid4()),
        )
        assert await session.scalar(text("SELECT count(*) FROM audit_events")) == 0
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        assert await session.scalar(text("SELECT count(*) FROM audit_events")) == 2


async def test_scopes_with_no_tenant_insert_no_tenant_events(
    api_db: Database, operator_db: Database
) -> None:
    tenant_id = await new_tenant(operator_db)
    insert = text(INSERT_WITH.format(column="details", value="'{}'"))
    with pytest.raises(DBAPIError) as refused:
        async with api_db.transaction(Scope.lookup()) as session:
            await session.execute(insert, {"tenant": tenant_id})
    assert getattr(refused.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE

    # sft_api never opens recovery scope (sft.data.access.SCOPES_BY_ROLE), and if a connection
    # claimed it anyway, the recovery insert policy is sft_recovery's alone.
    with pytest.raises(ScopeNotAllowedError, match="sft_api never opens a recovery scope"):
        async with api_db.transaction(Scope.recovery()):
            pass  # pragma: no cover

    async def insert_claiming_recovery() -> None:
        async with api_db.raw_connection_for_tests() as connection, connection.begin():
            await connection.execute(text("SELECT set_config('app.scope', 'recovery', true)"))
            await connection.execute(insert, {"tenant": tenant_id})

    with pytest.raises(DBAPIError) as refused:
        await insert_claiming_recovery()
    assert getattr(refused.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


# ---- 7, 8: what the helper accepts ----


class Plain(Enum):
    NAME = "contract.pdf"


class Attempts(IntEnum):
    THIRD = 3


def test_details_take_str_and_int_enums_only() -> None:
    assert audit._details({"attempt": Attempts.THIRD}) == {"attempt": 3}
    with pytest.raises(TypeError, match="StrEnum or IntEnum"):
        audit._details({"name": Plain.NAME})  # type: ignore[dict-item]


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        ("Mozilla/5.0\x00 (X11)", "Mozilla/5.0 (X11)"),
        ("curl/8\r\nX-Injected: 1", "curl/8X-Injected: 1"),
        ("tab\there\x7f\x85", "tabhere"),
        ("\x00\x01", None),
        ("é" * 600, "é" * audit.USER_AGENT_MAX),
    ],
)
def test_user_agents_lose_control_characters(raw: str, stored: str | None) -> None:
    assert audit._user_agent(raw) == stored


async def test_a_user_agent_with_nul_does_not_fail_the_audited_change(
    api_db: Database, operator_db: Database, migrated_db: ScratchDatabase
) -> None:
    tenant_id = await new_tenant(operator_db)
    async with api_db.transaction(Scope.tenant(tenant_id)) as session:
        event_id = await audit.record(
            session,
            action="transfer.revoked",
            actor=Actor(ActorType.MEMBER, uuid.uuid4()),
            origin=Origin(user_agent="evil\x00agent\n"),
            outcome=Outcome.SUCCESS,
        )
    assert migrated_db.sql("SELECT user_agent FROM audit_events WHERE id = :id", id=event_id) == [
        ("evilagent",)
    ]


# ---- 9: one list of values ----


@pytest.mark.parametrize(
    ("constraint", "values"),
    [("audit_events_actor_type_check", ActorType), ("audit_events_outcome_check", Outcome)],
)
def test_the_migrations_checks_match_the_enums(
    migrated_db: ScratchDatabase, constraint: str, values: type[Enum]
) -> None:
    ((definition,),) = migrated_db.sql(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'audit_events'::regclass AND conname = :name",
        name=constraint,
    )
    assert re.findall(r"'([a-z_]+)'::text", str(definition)) == [m.value for m in values]
