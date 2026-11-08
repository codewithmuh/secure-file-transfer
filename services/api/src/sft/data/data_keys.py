"""Data access for the tenants' wrapped data keys: `tenant_data_keys` (field data keys, #236) and
`tenant_dlp_keys` (DLP data keys, #233); encryption and keys 3.2, 3.3, 7.2; data model 2.1, 2.7.

Rows hold a key only as KMS returned it, wrapped under the fields key; `sft.service.fields`
unwraps them. Every function works in the scope's tenant: the keys a transaction opens values with
are always its own tenant's, never the tenant on a row (the third isolation layer). The API reads
and writes both tables; the scan worker reads and inserts DLP keys only (revision 0032).

The field key job (`sft.service.field_keys`) also reseals stored values here, column by column,
in the scope's tenant; it finds its tenants through the `field_key_tenants` lookup function,
which returns IDs only (revision 0031).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sqlalchemy import and_, bindparam, delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.sealed import AEAD_FORMAT, PLAINTEXT_FORMAT, Column, key_version
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    DlpApprovalDecision,
    DlpConfirmation,
    DlpDetector,
    DlpFinding,
    File,
    TenantDataKey,
    TenantDlpKey,
    Transfer,
    UploadRequest,
)
from sft.data.scope import ScopeKind

# A link session (resource scope) opens names and messages, and an uploader seals a file name.
_SCOPES: Final = (ScopeKind.TENANT, ScopeKind.RESOURCE)


class KeyPurpose(StrEnum):
    """What a data key protects: the `purpose` of its KMS encryption context (3.3)."""

    FIELD = "field-dek"
    DLP = "dlp-dek"


_MODELS: Final[dict[KeyPurpose, Any]] = {
    KeyPurpose.FIELD: TenantDataKey,
    KeyPurpose.DLP: TenantDlpKey,
}


@dataclass(frozen=True, slots=True)
class WrappedKey:
    version: int
    wrapped: bytes = field(repr=False)
    created_at: datetime
    retired_at: datetime | None

    @property
    def live(self) -> bool:
        return self.retired_at is None


async def list_keys(session: AsyncSession, purpose: KeyPurpose) -> list[WrappedKey]:
    """The scope's tenant's key versions of `purpose`, oldest first."""
    require_scope(session, *_SCOPES)
    model = _MODELS[purpose]
    rows = await session.execute(
        select(model.key_version, model.wrapped_key, model.created_at, model.retired_at)
        .where(in_scope(model, session))
        .order_by(model.key_version)
    )
    return [WrappedKey(r[0], r[1], r[2], r[3]) for r in rows.tuples()]


async def insert_key(
    session: AsyncSession, purpose: KeyPurpose, *, version: int, wrapped: bytes
) -> bool:
    """A new live version for the scope's tenant; False if another transaction made one first
    (the primary key, or the one live version per tenant, settles the race)."""
    require_scope(session, *_SCOPES)
    model = _MODELS[purpose]
    inserted = await session.scalar(
        pg_insert(model)
        .values(tenant_id=tenant_of(session), key_version=version, wrapped_key=wrapped)
        .on_conflict_do_nothing()
        .returning(model.key_version)
    )
    return inserted is not None


async def retire_live(session: AsyncSession, purpose: KeyPurpose, *, now: datetime) -> int | None:
    """Retire the scope's tenant's live version, so a new one can take over; its number."""
    require_scope(session, ScopeKind.TENANT)
    model = _MODELS[purpose]
    found: int | None = await session.scalar(
        update(model)
        .where(in_scope(model, session), model.retired_at.is_(None))
        .values(retired_at=now)
        .returning(model.key_version)
    )
    return found


async def rewrap(
    session: AsyncSession, purpose: KeyPurpose, *, version: int, before: bytes, wrapped: bytes
) -> bool:
    """Replace a version's wrapped key with the same key wrapped again (KMS `ReEncrypt`), only if
    it is still the one that was read."""
    require_scope(session, ScopeKind.TENANT)
    model = _MODELS[purpose]
    result: Any = await session.execute(
        update(model)
        .where(in_scope(model, session), model.key_version == version, model.wrapped_key == before)
        .values(wrapped_key=wrapped)
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount)


async def delete_retired(
    session: AsyncSession, purpose: KeyPurpose, versions: Sequence[int]
) -> list[int]:
    """Delete these retired versions of the scope's tenant; the versions gone. The foreign keys
    refuse a version a row still names, so a race can't lose a key in use."""
    require_scope(session, ScopeKind.TENANT)
    if not versions:
        return []
    model = _MODELS[purpose]
    rows = await session.scalars(
        delete(model)
        .where(
            in_scope(model, session),
            model.retired_at.is_not(None),
            model.key_version.in_(list(versions)),
        )
        .returning(model.key_version)
    )
    return sorted(int(v) for v in rows)


# ---- the sealed columns ----


@dataclass(frozen=True, slots=True)
class Sealed:
    """A column whose values are sealed, and the column that names their key version."""

    column: Column
    purpose: KeyPurpose
    model: Any
    value_name: str
    version_name: str

    @property
    def value(self) -> Any:
        return getattr(self.model, self.value_name)

    @property
    def version(self) -> Any:
        return getattr(self.model, self.version_name)

    @property
    def revisioned(self) -> bool:
        """Detector rows are keyed by ID and revision; every other table by ID."""
        return self.model is DlpDetector


def _sealed(model: Any, value: str, version: str, purpose: KeyPurpose) -> Sealed:
    return Sealed(Column(model.__tablename__, value), purpose, model, value, version)


SEALED_COLUMNS: Final = (
    _sealed(File, "display_name_ct", "data_key_version", KeyPurpose.FIELD),
    _sealed(Transfer, "message_ct", "data_key_version", KeyPurpose.FIELD),
    _sealed(UploadRequest, "message_ct", "data_key_version", KeyPurpose.FIELD),
    _sealed(DlpConfirmation, "justification_ct", "data_key_version", KeyPurpose.FIELD),
    _sealed(DlpApprovalDecision, "comment_ct", "data_key_version", KeyPurpose.FIELD),
    _sealed(DlpDetector, "definition_ct", "dlp_key_version", KeyPurpose.DLP),
)
"""Every column the field key job reseals. `dlp_findings.detail_ct` isn't one: details live only
until their file's contents are deleted, so old versions empty out on their own (7.2)."""

FINDING_DETAILS: Final = _sealed(DlpFinding, "detail_ct", "dlp_key_version", KeyPurpose.DLP)


@dataclass(frozen=True, slots=True)
class StoredValue:
    row_id: UUID
    revision: int | None
    value: bytes = field(repr=False)


def _stale(sealed: Sealed, current: int) -> Any:
    # Format 0 (M2's stand-in), or format 1 under a version other than the live one.
    first = func.get_byte(sealed.value, 0)
    return and_(
        sealed.value.is_not(None),
        or_(
            first == PLAINTEXT_FORMAT,
            and_(first == AEAD_FORMAT, sealed.version.is_distinct_from(current)),
        ),
    )


async def stale_values(
    session: AsyncSession, sealed: Sealed, *, current: int, limit: int
) -> list[StoredValue]:
    """Up to `limit` values of the column, in the scope's tenant, not sealed under the live
    version `current`: what the backfill and the re-encryption reseal. Locked, skipping rows
    another transaction holds."""
    require_scope(session, ScopeKind.TENANT)
    model = sealed.model
    columns = [model.id, sealed.value, model.revision if sealed.revisioned else model.id]
    rows = await session.execute(
        select(*columns)
        .where(in_scope(model, session), _stale(sealed, current))
        .order_by(model.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return [StoredValue(r[0], r[2] if sealed.revisioned else None, r[1]) for r in rows.tuples()]


async def reseal(session: AsyncSession, sealed: Sealed, row: StoredValue, value: bytes) -> bool:
    """Write a resealed value over the one that was read, with its key version, only if it is
    still that one."""
    require_scope(session, ScopeKind.TENANT)
    model = sealed.model
    conditions = [in_scope(model, session), model.id == row.row_id, sealed.value == row.value]
    if row.revision is not None:
        conditions.append(model.revision == row.revision)
    result: Any = await session.execute(
        update(model)
        .where(*conditions)
        .values({sealed.value_name: value, sealed.version_name: key_version(value)})
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount)


async def versions_in_use(session: AsyncSession, purpose: KeyPurpose) -> set[int]:
    """The key versions of `purpose` that some row of the scope's tenant still names."""
    require_scope(session, ScopeKind.TENANT)
    columns = [s for s in SEALED_COLUMNS if s.purpose is purpose]
    if purpose is KeyPurpose.DLP:
        columns.append(FINDING_DETAILS)
    used: set[int] = set()
    for sealed in columns:
        rows = await session.scalars(
            select(sealed.version)
            .where(in_scope(sealed.model, session), sealed.version.is_not(None))
            .distinct()
        )
        used.update(int(v) for v in rows)
    return used


# ---- the job's find (revision 0031) ----

_TENANTS: Final = text("SELECT tenant_id FROM field_key_tenants(:after)").bindparams(
    bindparam("after", required=False)
)


async def tenants_after(session: AsyncSession, after: UUID | None) -> list[UUID]:
    """Up to 500 tenant IDs after `after`, in order: the field key job's find, IDs only, through
    the lookup function (lookup scope)."""
    require_scope(session, ScopeKind.LOOKUP)
    rows = await session.scalars(_TENANTS, {"after": after})
    return list(rows)
