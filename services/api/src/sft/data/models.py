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
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    CheckConstraint,
    ColumnElement,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Interval,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    Text,
    UniqueConstraint,
    false,
    func,
    select,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql.base import ischema_names
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType

from sft.data.access import TenantOwned
from sft.data.scope import Subject, SubjectKind

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


def sql_values(values: type[StrEnum]) -> str:
    """An enum's values as an SQL list, `('a', 'b')`, for a CHECK."""
    return "(" + ", ".join(f"'{member.value}'" for member in values) + ")"


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


class UnscannablePolicy(StrEnum):
    """What the tenant does with files the scanner can't inspect (FR-18)."""

    BLOCK = "block"
    ALLOW_WITH_WARNING = "allow_with_warning"


class TenantPolicy(TenantOwned, Base):
    """A tenant's policy, one row per tenant, made with the tenant (data model 2.1, FR-33).

    Revision 0005 brings `default_locale`, revision 0009 the transfer and scanning fields of FR-23
    with their defaults: the longest expiry, what happens to unscannable files and how long
    received files are kept. The domain rules (FR-24) arrive with their feature (M5).
    """

    __tablename__ = "tenant_policies"
    __table_args__ = (
        CheckConstraint("default_locale IN ('en', 'ja')", name="default_locale"),
        CheckConstraint(
            "max_expiry BETWEEN interval '1 hour' AND interval '30 days'", name="max_expiry"
        ),
        CheckConstraint(
            f"unscannable_policy IN {sql_values(UnscannablePolicy)}", name="unscannable_policy"
        ),
        CheckConstraint(
            "received_file_retention_days BETWEEN 1 AND 90", name="received_file_retention_days"
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    default_locale: Mapped[str] = mapped_column(Text)
    max_expiry: Mapped[timedelta] = mapped_column(Interval, server_default=text("'30 days'"))
    unscannable_policy: Mapped[str] = mapped_column(Text, server_default="block")
    received_file_retention_days: Mapped[int] = mapped_column(server_default=text("30"))
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

    `sft.data.users` writes and reads it; every change commits only with its audit event. A
    recipient's link session reaches one user: the sender of its transfer, whose address the
    recipient sees (`getLinkSession`).
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

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # The sender of the recipient's transfer, and no one else.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.id.in_(
            select(Transfer.created_by).where(
                Transfer.id.in_(
                    select(TransferRecipient.transfer_id).where(TransferRecipient.id == subject.id)
                )
            )
        )


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


class TransferState(StrEnum):
    """The states of a transfer (data model 3.2). Revision 0008's CHECK lists the same values."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    PENDING_APPROVAL = "pending_approval"
    SENT = "sent"
    HELD = "held"
    REVOKED = "revoked"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class FileState(StrEnum):
    """The states of a file (data model 3.1). Revision 0008's CHECK lists the same values."""

    UPLOADING = "uploading"
    COMPLETING = "completing"
    SCANNING = "scanning"
    CLEAN = "clean"
    INFECTED = "infected"
    UNSCANNABLE = "unscannable"
    SCAN_FAILED = "scan_failed"
    REJECTED = "rejected"
    DELETED = "deleted"


class StorageClass(StrEnum):
    """Which files bucket pair holds a file, chosen from its declared size (ADR-0012)."""

    STANDARD = "standard"
    LARGE = "large"


class ScanEngine(StrEnum):
    """Which engine scanned a file (ADR-0019)."""

    CLAMAV = "clamav"
    GUARDDUTY = "guardduty"


class ScanDetail(StrEnum):
    """Why a file is `unscannable` or `scan_failed`, shown to the member (revision 0010)."""

    ENCRYPTED = "encrypted"
    LIMIT_EXCEEDED = "limit_exceeded"
    ENGINE_ERROR = "engine_error"
    DEADLINE_PASSED = "deadline_passed"
    LARGE_FILE_SCANNING_UNAVAILABLE = "large_file_scanning_unavailable"
    """A file over 2 GB, which only GuardDuty scans (M6): recorded at completion until then."""


class InspectionState(StrEnum):
    """A file's DLP inspection (data model 3.5). Revision 0011's CHECK lists the same values."""

    PENDING = "pending"
    INSPECTED = "inspected"
    PARTIAL = "partial"
    NOT_INSPECTED = "not_inspected"
    FAILED = "failed"
    SKIPPED = "skipped"


class InspectionReason(StrEnum):
    """Why content wasn't inspected (FR-47, detectors 1)."""

    ENCRYPTED = "encrypted"
    NO_TEXT = "no_text"
    UNSUPPORTED_TYPE = "unsupported_type"
    TOO_LARGE = "too_large"
    LIMIT_EXCEEDED = "limit_exceeded"
    PARSE_ERROR = "parse_error"


class DeliveryState(StrEnum):
    """Where a recipient's latest link email stands (data model 2.2)."""

    PENDING = "pending"
    QUEUED = "queued"
    SENT = "sent"
    BOUNCED = "bounced"
    SUPPRESSED = "suppressed"


class Transfer(TenantOwned, Base):
    """A transfer to external recipients (data model 2.2). Written through `sft.data.transfers`.

    `message_ct` holds the message as `sft.service.fields` seals it, never as plain text.
    """

    __tablename__ = "transfers"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(["tenant_id", "created_by"], ["users.tenant_id", "users.id"]),
        ForeignKeyConstraint(["tenant_id", "revoked_by"], ["users.tenant_id", "users.id"]),
        CheckConstraint(f"state IN {sql_values(TransferState)}", name="state"),
        CheckConstraint(
            "hold_reason IN ('file_blocked', 'dlp_blocked', 'approval_rejected')",
            name="hold_reason",
        ),
        CheckConstraint("(state = 'held') = (hold_reason IS NOT NULL)", name="held"),
        CheckConstraint(
            "expires_in BETWEEN interval '1 hour' AND interval '30 days'", name="expires_in"
        ),
        CheckConstraint("state <> 'draft' OR expires_at IS NULL", name="draft_expiry"),
        CheckConstraint("download_limit BETWEEN 1 AND 100", name="download_limit"),
        CheckConstraint(
            "(message_ct IS NULL) OR (octet_length(message_ct) > 0)", name="message_ct"
        ),
        # The lifecycle jobs' finds (data model 5, revision 0015).
        Index(
            "transfers_expires_at_idx",
            "expires_at",
            postgresql_where=text(
                "state IN ('submitted', 'awaiting_confirmation', 'pending_approval', 'sent', "
                "'held')"
            ),
        ),
        Index(
            "transfers_last_activity_at_idx",
            "last_activity_at",
            postgresql_where=text("state = 'draft'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    created_by: Mapped[uuid.UUID]
    state: Mapped[str] = mapped_column(Text)
    hold_reason: Mapped[str | None] = mapped_column(Text)
    message_ct: Mapped[bytes | None] = mapped_column(LargeBinary)
    data_key_version: Mapped[int | None]
    expires_in: Mapped[timedelta] = mapped_column(Interval)
    expires_at: Mapped[datetime | None]
    download_limit: Mapped[int | None]
    notify_on_first_download: Mapped[bool] = mapped_column(server_default=false())
    last_activity_at: Mapped[datetime] = mapped_column(server_default=func.now())
    submitted_at: Mapped[datetime | None]
    sent_at: Mapped[datetime | None]
    ended_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches its own transfer; an uploader's none.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.id.in_(
            select(TransferRecipient.transfer_id).where(TransferRecipient.id == subject.id)
        )


class TransferRecipient(TenantOwned, Base):
    """One recipient of one transfer (data model 2.2), with their link and status (revision 0012).

    `link_token_hash` is the SHA-256 of the token the notification worker derives from
    `link_issued_at` under the `link-hmac` key `link_key_id`; the three are set together or not
    at all. `failed_attempts` and `locked_at` are the lockout of data model 2.4."""

    __tablename__ = "transfer_recipients"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "transfer_id"],
            ["transfers.tenant_id", "transfers.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(["tenant_id", "unlocked_by"], ["users.tenant_id", "users.id"]),
        UniqueConstraint("tenant_id", "transfer_id", "email_normalized"),
        Index("transfer_recipients_link_token_hash_key", "link_token_hash", unique=True),
        CheckConstraint("locale IN ('en', 'ja')", name="locale"),
        CheckConstraint(f"delivery_state IN {sql_values(DeliveryState)}", name="delivery_state"),
        CheckConstraint("email_normalized = lower(email)", name="email_normalized"),
        CheckConstraint("octet_length(link_token_hash) = 32", name="link_token_hash"),
        CheckConstraint(
            "(link_issued_at IS NULL) = (link_key_id IS NULL) "
            "AND (link_issued_at IS NULL) = (link_token_hash IS NULL)",
            name="link",
        ),
        CheckConstraint("link_key_id ~ '^[A-Za-z0-9-]{1,32}$'", name="link_key_id"),
        CheckConstraint("failed_attempts BETWEEN 0 AND 20", name="failed_attempts"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    transfer_id: Mapped[uuid.UUID]
    email: Mapped[str] = mapped_column(Text)
    email_normalized: Mapped[str] = mapped_column(Text)
    locale: Mapped[str] = mapped_column(Text)
    delivery_state: Mapped[str] = mapped_column(Text, server_default="pending")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    link_token_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    link_key_id: Mapped[str | None] = mapped_column(Text)
    link_issued_at: Mapped[datetime | None]
    notified_at: Mapped[datetime | None]
    first_verified_at: Mapped[datetime | None]
    last_verified_at: Mapped[datetime | None]
    failed_attempts: Mapped[int] = mapped_column(server_default=text("0"))
    locked_at: Mapped[datetime | None]
    unlocked_by: Mapped[uuid.UUID | None]

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches its own row only.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.id == subject.id


class File(TenantOwned, Base):
    """A file of a transfer (data model 2.3, states in 3.1). Written through `sft.data.files`.

    `storage_key` is `tenants/{tenant_id}/files/{id}`; the bucket pair follows `storage_class`.
    `display_name_ct` holds the name as `sft.service.fields` seals it, never as plain text.
    """

    __tablename__ = "files"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "transfer_id"],
            ["transfers.tenant_id", "transfers.id"],
            ondelete="CASCADE",
        ),
        Index("files_tenant_id_transfer_id_idx", "tenant_id", "transfer_id"),
        CheckConstraint(f"state IN {sql_values(FileState)}", name="state"),
        CheckConstraint("declared_size BETWEEN 1 AND 5000000000", name="declared_size"),
        CheckConstraint("actual_size >= 1", name="actual_size"),
        CheckConstraint(f"storage_class IN {sql_values(StorageClass)}", name="storage_class"),
        CheckConstraint(
            "(storage_class = 'large') = (declared_size > 2000000000)", name="storage_class_size"
        ),
        CheckConstraint(
            "storage_key = 'tenants/' || tenant_id || '/files/' || id", name="storage_key"
        ),
        CheckConstraint("part_size >= 5242880", name="part_size"),
        CheckConstraint("part_count BETWEEN 1 AND 1000", name="part_count"),
        CheckConstraint(
            "state NOT IN ('scanning', 'clean', 'infected', 'unscannable', 'scan_failed') OR "
            "(actual_size IS NOT NULL AND s3_version_id IS NOT NULL AND scan_deadline IS NOT NULL)",
            name="scanned",
        ),
        CheckConstraint(
            "state <> 'completing' OR completion_started_at IS NOT NULL", name="completing"
        ),
        CheckConstraint(
            "(state <> 'rejected' AND removed_at IS NULL) OR delete_after IS NOT NULL",
            name="delete_after",
        ),
        CheckConstraint("octet_length(display_name_ct) > 0", name="display_name_ct"),
        CheckConstraint(f"scan_engine IN {sql_values(ScanEngine)}", name="scan_engine"),
        CheckConstraint(f"scan_detail IN {sql_values(ScanDetail)}", name="scan_detail"),
        CheckConstraint("scan_attempts >= 0", name="scan_attempts"),
        CheckConstraint(
            "NOT unscannable_allowed OR state IN ('unscannable', 'deleted')",
            name="unscannable_allowed",
        ),
        CheckConstraint(
            f"inspection_state IN {sql_values(InspectionState)}", name="inspection_state"
        ),
        CheckConstraint(
            f"inspection_reasons <@ ARRAY[{sql_values(InspectionReason)[1:-1]}]::text[]",
            name="inspection_reasons",
        ),
        Index(
            "files_scan_deadline_idx",
            "scan_deadline",
            postgresql_where=text("state = 'scanning'"),
        ),
        CheckConstraint("octet_length(sha256) = 32", name="sha256"),
        CheckConstraint("state <> 'deleted' OR deleted_at IS NOT NULL", name="deleted"),
        # The lifecycle jobs' finds (data model 5, revision 0015).
        Index(
            "files_delete_after_idx", "delete_after", postgresql_where=text("deleted_at IS NULL")
        ),
        Index(
            "files_last_part_at_idx", "last_part_at", postgresql_where=text("state = 'uploading'")
        ),
        Index(
            "files_completion_started_at_idx",
            "completion_started_at",
            postgresql_where=text("state = 'completing'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    transfer_id: Mapped[uuid.UUID]
    display_name_ct: Mapped[bytes] = mapped_column(LargeBinary)
    data_key_version: Mapped[int | None]
    content_type: Mapped[str] = mapped_column(Text)
    declared_size: Mapped[int] = mapped_column(BigInteger)
    actual_size: Mapped[int | None] = mapped_column(BigInteger)
    storage_class: Mapped[str] = mapped_column(Text)
    storage_key: Mapped[str] = mapped_column(Text, unique=True)
    s3_upload_id: Mapped[str] = mapped_column(Text)
    s3_version_id: Mapped[str | None] = mapped_column(Text)
    part_size: Mapped[int]
    part_count: Mapped[int]
    state: Mapped[str] = mapped_column(Text)
    last_part_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completion_started_at: Mapped[datetime | None]
    removed_at: Mapped[datetime | None]
    scan_deadline: Mapped[datetime | None]
    delete_after: Mapped[datetime | None]
    scan_attempts: Mapped[int] = mapped_column(server_default=text("0"))
    scan_engine: Mapped[str | None] = mapped_column(Text)
    scan_detail: Mapped[str | None] = mapped_column(Text)
    scanned_at: Mapped[datetime | None]
    unscannable_allowed: Mapped[bool] = mapped_column(server_default=false())
    inspection_state: Mapped[str] = mapped_column(Text, server_default="pending")
    inspection_reasons: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]")
    )
    inspection_engine_version: Mapped[str | None] = mapped_column(Text)
    inspection_policy_version: Mapped[int | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    sha256: Mapped[bytes | None] = mapped_column(LargeBinary)
    """The SHA-256 of the scanned version, which the scan worker reads in full (revision 0014)."""
    deleted_at: Mapped[datetime | None]
    """When the deletion job removed every object version (revision 0015)."""

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches the files of its own transfer; the files of upload
        # requests arrive with them.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.transfer_id.in_(
            select(TransferRecipient.transfer_id).where(TransferRecipient.id == subject.id)
        )


class TenantUsage(TenantOwned, Base):
    """The bytes a tenant has reserved against its storage quota (data model 2.5).

    Changed only by `sft.data.usage`, with one conditional statement each.
    """

    __tablename__ = "tenant_usage"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        CheckConstraint("bytes_reserved >= 0", name="bytes_reserved"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    bytes_reserved: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class DownloadCounter(TenantOwned, Base):
    """How often one recipient downloaded one file (data model 2.3). The rows of a transfer are
    made in the transaction that moves it to `sent`, with its limit copied (revision 0009)."""

    __tablename__ = "download_counters"
    __table_args__ = (
        PrimaryKeyConstraint("recipient_id", "file_id"),
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        ForeignKeyConstraint(
            ["tenant_id", "recipient_id"],
            ["transfer_recipients.tenant_id", "transfer_recipients.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "file_id"], ["files.tenant_id", "files.id"], ondelete="CASCADE"
        ),
        Index("download_counters_tenant_id_file_id_idx", "tenant_id", "file_id"),
        CheckConstraint("download_limit BETWEEN 1 AND 100", name="download_limit"),
        CheckConstraint("count >= 0", name="count"),
    )

    tenant_id: Mapped[uuid.UUID]
    recipient_id: Mapped[uuid.UUID]
    file_id: Mapped[uuid.UUID]
    download_limit: Mapped[int | None]
    count: Mapped[int] = mapped_column(server_default=text("0"))
    first_downloaded_at: Mapped[datetime | None]
    last_downloaded_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches its own counters: its download count and limit.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.recipient_id == subject.id


class SuppressionReason(StrEnum):
    HARD_BOUNCE = "hard_bounce"
    COMPLAINT = "complaint"


class EmailSuppression(TenantOwned, Base):
    """An address this tenant doesn't email (data model 2.5, abuse 7.4), by its pseudonym under
    the `email-hmac` keyring, never the address (revision 0009)."""

    __tablename__ = "email_suppressions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "email_hmac"),
        CheckConstraint(f"reason IN {sql_values(SuppressionReason)}", name="reason"),
        CheckConstraint("bounce_count >= 1", name="bounce_count"),
        CheckConstraint("email_hmac LIKE 'e' || hmac_key_id || ':%'", name="email_hmac"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    email_hmac: Mapped[str] = mapped_column(Text)
    hmac_key_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    bounce_count: Mapped[int] = mapped_column(server_default=text("1"))
    expires_at: Mapped[datetime | None]
    ses_released_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class DlpFinding(TenantOwned, Base):
    """What one detector found in one file: counts at each confidence, never a value (data model
    2.7, FR-53). Written by the scan worker, which may not read `detail_ct` back (revision 0011).
    A transfer's message gets `transfer_id` with FR-50; until then `file_id` is always set."""

    __tablename__ = "dlp_findings"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "file_id"], ["files.tenant_id", "files.id"], ondelete="CASCADE"
        ),
        UniqueConstraint("tenant_id", "file_id", "detector"),
        CheckConstraint("char_length(detector) BETWEEN 1 AND 72", name="detector"),
        CheckConstraint(
            "count_low >= 0 AND count_medium >= 0 AND count_high >= 0 "
            "AND count_low + count_medium + count_high > 0",
            name="counts",
        ),
        CheckConstraint("detail_ct IS NULL OR octet_length(detail_ct) > 0", name="detail_ct"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    file_id: Mapped[uuid.UUID]
    detector: Mapped[str] = mapped_column(Text)
    count_low: Mapped[int]
    count_medium: Mapped[int]
    count_high: Mapped[int]
    detail_ct: Mapped[bytes | None] = mapped_column(LargeBinary)
    dlp_key_version: Mapped[int | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class VerificationCode(TenantOwned, Base):
    """A one-time code of a recipient, by its HMAC under the `code-hmac` keyring (data model 2.4,
    revision 0013). The notification worker creates one and supersedes the older ones; the API
    counts each attempt with one conditional update. Only the newest live code can match."""

    __tablename__ = "verification_codes"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "recipient_id"],
            ["transfer_recipients.tenant_id", "transfer_recipients.id"],
            ondelete="CASCADE",
        ),
        Index(
            "verification_codes_recipient_id_created_at_idx",
            "recipient_id",
            text("created_at DESC"),
        ),
        Index("verification_codes_expires_at_idx", "expires_at"),
        CheckConstraint("octet_length(code_hmac) = 32", name="code_hmac"),
        CheckConstraint("hmac_key_id ~ '^[A-Za-z0-9-]{1,32}$'", name="hmac_key_id"),
        CheckConstraint("attempts BETWEEN 0 AND 5", name="attempts"),
        CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '10 minutes'",
            name="expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    recipient_id: Mapped[uuid.UUID]
    code_hmac: Mapped[bytes] = mapped_column(LargeBinary)
    hmac_key_id: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime]
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    superseded_at: Mapped[datetime | None]
    consumed_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class LinkSession(TenantOwned, Base):
    """A verified browser's session for one recipient (data model 2.4, authn and authz 4.3): the
    SHA-256 of its token, 24 hours at most and 1 hour idle. Revision 0013."""

    __tablename__ = "link_sessions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("session_hash"),
        ForeignKeyConstraint(
            ["tenant_id", "recipient_id"],
            ["transfer_recipients.tenant_id", "transfer_recipients.id"],
            ondelete="CASCADE",
        ),
        Index("link_sessions_recipient_id_idx", "recipient_id"),
        Index("link_sessions_expires_at_idx", "expires_at"),
        CheckConstraint("octet_length(session_hash) = 32", name="session_hash"),
        CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '24 hours'",
            name="expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    recipient_id: Mapped[uuid.UUID]
    session_hash: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches the sessions of its own recipient.
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.recipient_id == subject.id


class DownloadGrant(TenantOwned, Base):
    """One counted download of one file by one link session (data model 2.3, abuse 5.4; revision
    0014): a byte, request and time budget, and the lease of its one active stream. The member's
    pair (`user_id`, `member_session_id`) arrives with received files (M5)."""

    __tablename__ = "download_grants"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "file_id"], ["files.tenant_id", "files.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "recipient_id"],
            ["transfer_recipients.tenant_id", "transfer_recipients.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "link_session_id"],
            ["link_sessions.tenant_id", "link_sessions.id"],
            ondelete="CASCADE",
        ),
        Index("download_grants_file_id_idx", "file_id"),
        Index("download_grants_recipient_id_idx", "recipient_id"),
        Index("download_grants_link_session_id_idx", "link_session_id"),
        Index("download_grants_expires_at_idx", "expires_at"),
        Index(
            "download_grants_unarchived_idx",
            "created_at",
            postgresql_where=text("archived_at IS NULL"),
        ),
        CheckConstraint("byte_budget >= 1", name="byte_budget"),
        CheckConstraint("bytes_served >= 0", name="bytes_served"),
        CheckConstraint("request_count BETWEEN 0 AND 20", name="request_count"),
        CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '24 hours'",
            name="expires_at",
        ),
        CheckConstraint(
            "(active_stream_id IS NULL) = (active_stream_until IS NULL)", name="active_stream"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID]
    file_id: Mapped[uuid.UUID]
    s3_version_id: Mapped[str] = mapped_column(Text)
    recipient_id: Mapped[uuid.UUID]
    link_session_id: Mapped[uuid.UUID]
    byte_budget: Mapped[int] = mapped_column(BigInteger)
    bytes_served: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    request_count: Mapped[int] = mapped_column(server_default=text("0"))
    expires_at: Mapped[datetime]
    active_stream_id: Mapped[uuid.UUID | None]
    active_stream_until: Mapped[datetime | None]
    archived_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    @classmethod
    def reach(cls, subject: Subject) -> ColumnElement[bool]:
        # A recipient's link session reaches its own recipient's grants; which of them the session
        # may use is the service's rule (the grant's session).
        if subject.kind is not SubjectKind.RECIPIENT:
            return false()
        return cls.recipient_id == subject.id
