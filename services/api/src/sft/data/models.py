"""Table definitions for queries, in step with the migrations (data model section 2).

The migrations create the tables; these classes describe them for SQLAlchemy. A test compares the
two after `upgrade head`, so a column added to one and not the other fails the build. Migrations
never import this module: each migration keeps the schema of its own time.

Conventions (data model 1): IDs are UUIDv7 made by the application, times are `timestamptz`,
states are `text` with a `CHECK` constraint. Constraint and index names follow PostgreSQL's own
pattern, so names in migrations, errors and the catalog agree.

Every tenant-owned model mixes in `TenantOwned` (`sft.data.access`), which names its tenant column
and what a link session's subject reaches, so `in_scope` can filter it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    ColumnElement,
    DateTime,
    Index,
    MetaData,
    PrimaryKeyConstraint,
    Text,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql.base import ischema_names
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType

from sft.data.access import TenantOwned
from sft.data.scope import Subject

NAMING_CONVENTION = {
    "pk": "%(table_name)s_pkey",
    "uq": "%(table_name)s_%(column_0_N_name)s_key",
    "fk": "%(table_name)s_%(column_0_N_name)s_fkey",
    "ix": "%(table_name)s_%(column_0_N_name)s_idx",
    "ck": "%(table_name)s_%(constraint_name)s_check",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {datetime: DateTime(timezone=True)}  # noqa: RUF012


class Tenant(TenantOwned, Base):
    """A customer company (data model 2.1). Every tenant-owned row refers to one.

    The columns for recovery and SSO arrive with their features (M1, M6), each in its own migration.
    """

    __tablename__ = "tenants"
    __tenant_key__ = "id"
    __table_args__ = (CheckConstraint("status IN ('active', 'suspended')", name="status"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A link session reads its own tenant's row: the sender's company name, and its status,
        # so a suspended tenant's links stop working. The tenant condition in_scope adds is enough.
        return true()


class SchemaCompatibility(Base):
    """Which earlier revisions' code each revision's schema still serves (data model 7).

    Only the migration job reads and writes it, as `sft_owner`; no workload role is granted it.
    """

    __tablename__ = "schema_compatibility"

    revision: Mapped[str] = mapped_column(Text, primary_key=True)
    compatible_with: Mapped[list[str]] = mapped_column(ARRAY(Text))
    recorded_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Xid8(UserDefinedType[int]):
    """PostgreSQL's 64-bit transaction ID, which `pg_current_xact_id()` returns."""

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "xid8"


# So reflection, and with it the models test, knows the type too.
ischema_names["xid8"] = Xid8


class ActorType(StrEnum):
    """Who acted (data model 2.5). The one list of actor types: the CHECK below is built from it,
    and a test checks the migration's literal CHECK against it."""

    MEMBER = "member"
    ADMIN = "admin"
    RECIPIENT = "recipient"
    UPLOADER = "uploader"
    API_KEY = "api_key"
    OPERATOR = "operator"
    SYSTEM = "system"


class Outcome(StrEnum):
    """Whether the action succeeded, e.g. a verification attempt (FR-27). One list, as above."""

    SUCCESS = "success"
    FAILURE = "failure"


def sql_values(values: type[StrEnum]) -> str:
    """An enum's values as an SQL list, `('a', 'b')`, for a CHECK."""
    return "(" + ", ".join(f"'{member.value}'" for member in values) + ")"


class AuditEvent(Base):
    """One audit record (data model 2.5, FR-27). Written only through `sft.data.audit.record`.

    Partitioned by month on `occurred_at`, with a `DEFAULT` partition for any month that has no
    partition yet (data model 6). The partitions aren't models: queries go through this table, so
    its row-level security applies, and no role is granted a partition. Workload roles may insert
    rows, never update or delete them. `tx_id` and `occurred_at` are always the database's own
    values, which the fail-closed check (`audit_required`) relies on.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        PrimaryKeyConstraint("id", "occurred_at"),
        CheckConstraint(f"actor_type IN {sql_values(ActorType)}", name="actor_type"),
        CheckConstraint(f"outcome IN {sql_values(Outcome)}", name="outcome"),
        CheckConstraint("(target_type IS NULL) = (target_id IS NULL)", name="target"),
        CheckConstraint("jsonb_typeof(details) = 'object'", name="details"),
        Index("audit_events_tenant_id_occurred_at_idx", "tenant_id", text("occurred_at DESC")),
        Index(
            "audit_events_tenant_id_target_type_target_id_idx",
            "tenant_id",
            "target_type",
            "target_id",
        ),
        Index(
            "audit_events_tenant_id_actor_id_occurred_at_idx",
            "tenant_id",
            "actor_id",
            text("occurred_at DESC"),
        ),
        Index("audit_events_tx_id_id_idx", "tx_id", "id"),
        {"postgresql_partition_by": "RANGE (occurred_at)", "implicit_returning": False},
    )

    id: Mapped[uuid.UUID]
    tenant_id: Mapped[uuid.UUID | None]
    tx_id: Mapped[int] = mapped_column(Xid8, server_default=func.pg_current_xact_id())
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())
    actor_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[uuid.UUID | None]
    action: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[uuid.UUID | None]
    outcome: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[str | None] = mapped_column(Text)
    security_critical: Mapped[bool] = mapped_column(server_default=text("false"))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'"))
