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
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    Text,
    UniqueConstraint,
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

    Created by a platform operator (FR-34) with `recovery_contact`, the second contact an operator
    confirms an admin recovery through; empty only for rows from before revision 0005. The SSO
    columns arrive with their feature (M6).
    """

    __tablename__ = "tenants"
    __tenant_key__ = "id"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'suspended')", name="status"),
        CheckConstraint("char_length(recovery_contact) BETWEEN 1 AND 320", name="recovery_contact"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    recovery_contact: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A link session reads its own tenant's row: the sender's company name, and its status,
        # so a suspended tenant's links stop working. The tenant condition in_scope adds is enough.
        return true()


class TenantPolicy(TenantOwned, Base):
    """A tenant's policy, one row per tenant, made with the tenant (data model 2.1, FR-33).

    Revision 0005 brings `default_locale`; the expiry, domain and scanning columns arrive with the
    policy features (FR-23, FR-24), each with its default, in their own migrations.
    """

    __tablename__ = "tenant_policies"
    __table_args__ = (CheckConstraint("default_locale IN ('en', 'ja')", name="default_locale"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    default_locale: Mapped[str] = mapped_column(Text)
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


class Outbox(TenantOwned, Base):
    """A message to hand to a worker, written with the change that causes it (data model 2.5).

    `sft.data.outbox` writes and reads it; the relay publishes each row to SQS (ADR-0013).
    """

    __tablename__ = "outbox"
    __table_args__ = (
        CheckConstraint("delay_seconds BETWEEN 0 AND 900", name="delay_seconds"),
        CheckConstraint("attempts >= 0", name="attempts"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload"),
        CheckConstraint("jsonb_typeof(trace_context) = 'object'", name="trace_context"),
        Index(
            "outbox_unpublished_idx",
            "created_at",
            postgresql_where=text("published_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    topic: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    trace_context: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    delay_seconds: Mapped[int] = mapped_column(server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    published_at: Mapped[datetime | None]
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    next_attempt_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_error: Mapped[str | None] = mapped_column(Text)


class ProcessedMessage(TenantOwned, Base):
    """A message a consumer has handled, so a second delivery is skipped (data model 2.5)."""

    __tablename__ = "processed_messages"

    consumer: Mapped[str] = mapped_column(Text, primary_key=True)
    message_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    processed_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Role(StrEnum):
    """A user's role in their tenant (data model 2.1, authn and authz 6.2). One list: the CHECK
    below is built from it, and a test checks the migration's literal CHECK against it."""

    ADMIN = "admin"
    MEMBER = "member"


class UserStatus(StrEnum):
    """Where a user is: invited until their first sign-in, then active, or deactivated."""

    INVITED = "invited"
    ACTIVE = "active"
    DEACTIVATED = "deactivated"


class User(TenantOwned, Base):
    """A member or admin of one tenant, with their role and invitation (data model 2.1, FR-22).

    `sft.data.users` writes and reads it; every change commits only with its audit event. Link
    sessions reach no user (the default `reach`).
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(f"role IN {sql_values(Role)}", name="role"),
        CheckConstraint(f"status IN {sql_values(UserStatus)}", name="status"),
        CheckConstraint("char_length(email) BETWEEN 3 AND 254", name="email"),
        CheckConstraint("NOT sso_fallback OR role = 'admin'", name="sso_fallback"),
        CheckConstraint(
            "(invitation_token_hash IS NULL) = (invitation_expires_at IS NULL)", name="invitation"
        ),
        CheckConstraint(
            "invitation_token_hash IS NULL "
            "OR (octet_length(invitation_token_hash) = 32 AND status = 'invited')",
            name="invitation_token_hash",
        ),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "email_normalized"),
        UniqueConstraint("invitation_token_hash"),
        Index(
            "users_invitation_expires_at_idx",
            "invitation_expires_at",
            postgresql_where=text("invitation_token_hash IS NOT NULL"),
        ),
        Index(
            "users_dlp_approver_idx",
            "tenant_id",
            postgresql_where=text("dlp_approver AND status = 'active'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    email: Mapped[str] = mapped_column(Text)
    email_normalized: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    sso_fallback: Mapped[bool] = mapped_column(server_default=text("false"))
    dlp_approver: Mapped[bool] = mapped_column(server_default=text("false"))
    invitation_token_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    invitation_expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class OperatorSession(Base):
    """An operator token, made from a signed STS request (data model 2.6, authn and authz 8.2).

    A platform table: no tenant, no row-level security, granted to `sft_operator` alone. Both
    hashes are SHA-256 and unique: of the token, and of the request's signature, so a signed
    request works once.
    """

    __tablename__ = "operator_sessions"
    __table_args__ = (
        CheckConstraint("aws_account_id ~ '^[0-9]{12}$'", name="aws_account_id"),
        CheckConstraint("octet_length(token_hash) = 32", name="token_hash"),
        CheckConstraint("octet_length(signature_hash) = 32", name="signature_hash"),
        Index("operator_sessions_expires_at_idx", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    signature_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    aws_account_id: Mapped[str] = mapped_column(Text)
    operator_name: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class IdpConnection(TenantOwned, Base):
    """A way in: one of the platform's user pools (no tenant), or a tenant's SSO provider (M6).

    Found only through the connection lookup, by `provider_name`, never by `issuer` (data model
    2.1). Link sessions reach none (the default `reach`).
    """

    __tablename__ = "idp_connections"
    __table_args__ = (
        CheckConstraint("kind IN ('local', 'oidc', 'saml')", name="kind"),
        CheckConstraint("status IN ('active', 'inactive')", name="status"),
        CheckConstraint("(kind = 'local') = (tenant_id IS NULL)", name="tenant"),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("provider_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id"))
    kind: Mapped[str] = mapped_column(Text)
    provider_name: Mapped[str] = mapped_column(Text)
    issuer: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class UserIdentity(TenantOwned, Base):
    """A subject at a connection, mapped to one user (data model 2.1). Found only through the
    identity lookup, by `(idp_connection_id, subject)`; an email claim never finds one."""

    __tablename__ = "user_identities"
    __table_args__ = (
        CheckConstraint("char_length(subject) BETWEEN 1 AND 255", name="subject"),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("idp_connection_id", "subject"),
        ForeignKeyConstraint(["tenant_id", "user_id"], ["users.tenant_id", "users.id"]),
        Index("user_identities_tenant_id_user_id_idx", "tenant_id", "user_id"),
        Index(
            "user_identities_expires_at_idx",
            "expires_at",
            postgresql_where=text("expires_at IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID]
    # By ID alone: a pool's connection has no tenant (data model 2).
    idp_connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("idp_connections.id"))
    subject: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class SessionRevokedReason(StrEnum):
    """Why a member session ended early (data model 2.4). One list: the migration's CHECK."""

    SIGNED_OUT = "signed_out"
    SIGN_IN_REPLACED = "sign_in_replaced"
    """The browser signed in again, so the session cookie it sent before is revoked (3.3)."""
    SESSION_LIMIT = "session_limit"
    """An 11th session ended the oldest."""
    ROLE_CHANGED = "role_changed"
    DEACTIVATED = "deactivated"
    SIGNED_OUT_BY_ADMIN = "signed_out_by_admin"
    SIGN_IN_RESET = "sign_in_reset"
    TENANT_SUSPENDED = "tenant_suspended"


class MemberSession(TenantOwned, Base):
    """A member's web session (authn and authz 3.2): only the token's SHA-256 is stored.

    `sft.data.member_sessions` reads and writes it. Creating and revoking one commits only with
    its audit event; `last_seen_at` moves without one. Link sessions reach none.
    """

    __tablename__ = "member_sessions"
    __table_args__ = (
        CheckConstraint(
            "auth_method IN ('passkey', 'password_totp', 'local', 'sso')", name="auth_method"
        ),
        CheckConstraint("octet_length(session_hash) = 32", name="session_hash"),
        CheckConstraint("(revoked_at IS NULL) = (revoked_reason IS NULL)", name="revoked"),
        CheckConstraint(
            f"revoked_reason IN {sql_values(SessionRevokedReason)}", name="revoked_reason"
        ),
        CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '12 hours'",
            name="expires_at",
        ),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("session_hash"),
        ForeignKeyConstraint(["tenant_id", "user_id"], ["users.tenant_id", "users.id"]),
        Index(
            "member_sessions_tenant_id_user_id_created_at_idx", "tenant_id", "user_id", "created_at"
        ),
        Index("member_sessions_expires_at_idx", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID]
    identity_id: Mapped[uuid.UUID]
    session_hash: Mapped[bytes] = mapped_column(LargeBinary)
    auth_time: Mapped[datetime]
    auth_method: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    created_ip: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)


class IdempotencyKey(TenantOwned, Base):
    """What a creating `POST` did, for a retry with the same key (architecture 5.4, data model 2.5).

    `sft.data.idempotency` reads and writes it, in the tenant's scope; the daily job deletes
    expired rows. It keeps the status and the ID of what was created, never a response body. Link
    sessions reach none yet (the default `reach`); their operations add it when they land.
    """

    __tablename__ = "idempotency_keys"
    __table_args__ = (
        PrimaryKeyConstraint("caller_type", "caller_id", "key"),
        CheckConstraint(
            "caller_type IN ('member', 'api_key', 'recipient', 'uploader')", name="caller_type"
        ),
        CheckConstraint("key ~ '^[\\x21-\\x7e]{1,255}$'", name="key"),
        CheckConstraint("octet_length(request_fingerprint) = 32", name="request_fingerprint"),
        CheckConstraint("response_status BETWEEN 200 AND 299", name="response_status"),
        CheckConstraint("expires_at > created_at", name="expires_at"),
        Index("idempotency_keys_expires_at_idx", "expires_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    caller_type: Mapped[str] = mapped_column(Text)
    caller_id: Mapped[uuid.UUID]
    key: Mapped[str] = mapped_column(Text)
    request_fingerprint: Mapped[bytes] = mapped_column(LargeBinary)
    response_status: Mapped[int] = mapped_column(SmallInteger)
    resource_type: Mapped[str] = mapped_column(Text)
    resource_id: Mapped[uuid.UUID]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
