"""Stand-in tables for the isolation harness, until M1 and M2 bring the real ones.

M0 has one tenant table, `tenants`, with no children and no credentials. These two tables have the
shapes the later ones will have, and their keys, policies and lookup function are the SQL that
`sft.data.rls` generates for a revision, so the harness, the composite foreign keys and the
credential lookup mechanism are proven now:

- `widgets`: a tenant-owned parent, like `transfers`, with a credential, like `link_token_hash`;
  a resource scope whose subject is an upload request reaches the widget with that ID;
- `widget_parts`: its child, like `files`, by the composite foreign key `(tenant_id, widget_id)`.

They exist only in the isolation suite's databases, never in `migrated_db` or a migration. Not
being revisions, they call the generators directly instead of keeping literal SQL.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import ColumnElement, Connection, delete, false, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped

from pg import Sql
from sft.data.access import TenantOwned, in_scope, require_scope, tenant_of
from sft.data.rls import (
    lookup_function_sql,
    lookup_read_sql,
    policy_sql,
    tenant_foreign_key_sql,
    tenant_keys_sql,
    tenant_rls_sql,
)
from sft.data.roles import API, JOBS
from sft.data.scope import ScopeKind, Subject, SubjectKind

metadata = sa.MetaData()

widgets = sa.Table(
    "widgets",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("tenant_id", sa.Uuid, nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
)
widget_parts = sa.Table(
    "widget_parts",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("tenant_id", sa.Uuid, nullable=False),
    sa.Column("widget_id", sa.Uuid, nullable=False),
    sa.Column("label", sa.Text, nullable=False),
)

LOOKUP_WIDGET = "lookup_widget(p_token_hash bytea)"

STATEMENTS = [
    *tenant_keys_sql("widgets"),
    *tenant_keys_sql("widget_parts"),
    tenant_foreign_key_sql("widget_parts", "widget_id", "widgets", on_delete="CASCADE"),
    *tenant_rls_sql(
        "widgets", grants={API: "SELECT, INSERT, UPDATE, DELETE", JOBS: "SELECT, UPDATE"}
    ),
    policy_sql(
        "jobs_find", "widgets", roles=[JOBS], command="SELECT", using="app_scope() = 'system'"
    ),
    *lookup_read_sql("widgets", ["id", "tenant_id", "token_hash"]),
    *lookup_function_sql(
        LOOKUP_WIDGET,
        returns="TABLE (widget_id uuid, owner_tenant_id uuid)",
        body="SELECT id, tenant_id FROM public.widgets WHERE token_hash = p_token_hash",
    ),
    *tenant_rls_sql("widget_parts", grants={API: "SELECT, INSERT, UPDATE, DELETE"}),
]


def create(connection: Connection) -> None:
    """As the owner, the way a migration would."""
    metadata.create_all(connection)
    for statement in STATEMENTS:
        connection.execute(text(statement))


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def seed(db: Sql, tenant_id: uuid.UUID, marker: str) -> dict[str, uuid.UUID]:
    rows = {"widget": uuid.uuid4(), "part": uuid.uuid4(), "token": uuid.uuid4()}
    db.sql(
        "INSERT INTO widgets (id, tenant_id, name, token_hash) VALUES (:id, :tenant, :name, :hash)",
        id=rows["widget"],
        tenant=tenant_id,
        name=marker,
        hash=token_hash(str(rows["token"])),
    )
    db.sql(
        "INSERT INTO widget_parts (id, tenant_id, widget_id, label) "
        "VALUES (:id, :tenant, :widget, :label)",
        id=rows["part"],
        tenant=tenant_id,
        widget=rows["widget"],
        label=marker,
    )
    return rows


# ---- models and data-access functions, written as the real ones will be ----


class FixtureBase(DeclarativeBase):
    metadata = metadata


class Widget(TenantOwned, FixtureBase):
    __table__ = widgets
    id: Mapped[uuid.UUID]
    tenant_id: Mapped[uuid.UUID]
    name: Mapped[str]

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        if subject.kind is SubjectKind.UPLOAD_REQUEST:
            return cls.id == subject.id
        return false()


class WidgetPart(TenantOwned, FixtureBase):
    __table__ = widget_parts
    id: Mapped[uuid.UUID]
    tenant_id: Mapped[uuid.UUID]
    widget_id: Mapped[uuid.UUID]
    label: Mapped[str]

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        if subject.kind is SubjectKind.UPLOAD_REQUEST:
            return cls.widget_id == subject.id
        return false()


async def get_widget(session: AsyncSession, widget_id: uuid.UUID) -> Widget | None:
    widget: Widget | None = await session.scalar(
        select(Widget).where(Widget.id == widget_id, in_scope(Widget, session))
    )
    return widget


async def list_widgets(session: AsyncSession) -> Sequence[Widget]:
    return (await session.scalars(select(Widget).where(in_scope(Widget, session)))).all()


async def list_parts(session: AsyncSession, widget_id: uuid.UUID) -> Sequence[WidgetPart]:
    statement = select(WidgetPart).where(
        WidgetPart.widget_id == widget_id, in_scope(WidgetPart, session)
    )
    return (await session.scalars(statement)).all()


async def rename_widget(session: AsyncSession, widget_id: uuid.UUID, name: str) -> int:
    result = await session.execute(
        update(Widget).where(Widget.id == widget_id, in_scope(Widget, session)).values(name=name)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]


async def delete_widget(session: AsyncSession, widget_id: uuid.UUID) -> int:
    result = await session.execute(
        delete(Widget).where(Widget.id == widget_id, in_scope(Widget, session))
    )
    return int(result.rowcount)  # type: ignore[attr-defined]


async def add_part(session: AsyncSession, widget_id: uuid.UUID, label: str) -> uuid.UUID:
    """A child of the caller's widget. The tenant is the scope's; only the database checks the
    widget, through the composite foreign key."""
    part = WidgetPart(
        id=uuid.uuid4(), tenant_id=tenant_of(session), widget_id=widget_id, label=label
    )
    session.add(part)
    await session.flush()
    return part.id


async def find_widgets(session: AsyncSession) -> Sequence[uuid.UUID]:
    """A lifecycle job's find step: across tenants, IDs only, in system scope."""
    return (await session.scalars(select(Widget.id).where(in_scope(Widget, session)))).all()


async def lookup_widget(session: AsyncSession, token: str) -> tuple[uuid.UUID, uuid.UUID] | None:
    """The credential lookup: the widget a token belongs to, and its tenant."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text("SELECT widget_id, owner_tenant_id FROM lookup_widget(:hash)"),
            {"hash": token_hash(token)},
        )
    ).first()
    return None if row is None else (row[0], row[1])
