"""Table definitions for queries, in step with the migrations (data model section 2).

The migrations create the tables; these classes describe them for SQLAlchemy. A test compares the
two after `upgrade head`, so a column added to one and not the other fails the build. Migrations
never import this module: each migration keeps the schema of its own time.

Conventions (data model 1): IDs are UUIDv7 made by the application, times are `timestamptz`,
states are `text` with a `CHECK` constraint. Constraint and index names follow PostgreSQL's own
pattern, so names in migrations, errors and the catalog agree.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, CheckConstraint, DateTime, MetaData, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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


class Tenant(Base):
    """A customer company (data model 2.1). Every tenant-owned row refers to one.

    The columns for recovery and SSO arrive with their features (M1, M6), each in its own migration.
    """

    __tablename__ = "tenants"
    __table_args__ = (CheckConstraint("status IN ('active', 'suspended')", name="status"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class SchemaCompatibility(Base):
    """Which earlier revisions' code each revision's schema still serves (data model 7).

    Only the migration job reads and writes it, as `sft_owner`; no workload role is granted it.
    """

    __tablename__ = "schema_compatibility"

    revision: Mapped[str] = mapped_column(Text, primary_key=True)
    compatible_with: Mapped[list[str]] = mapped_column(ARRAY(Text))
    recorded_at: Mapped[datetime] = mapped_column(server_default=func.now())
