"""Download grants and the download count (data model 2.3; abuse and rate limits 5.4; #180).

A grant is one counted download of one file by one link session. Each limit is one conditional
statement, never read-check-write (data model 1):

- `count_download`: the counter's `count + 1 WHERE count < limit`, in the transaction that inserts
  the grant and writes `download.granted` (FR-4). Parallel requests serialise on the row.
- `admit`: one content request takes a request and the grant's stream lease, while the grant has
  time, requests and bytes left. A newer request takes the lease over.
- `record_progress`: a running stream adds the bytes it sent, by grant ID alone, so a stream that
  was taken over still records them; only the lease depends on the stream's ID.

Times are the database's. The API reads and writes grants in the recipient's resource scope, which
reaches that recipient's grants (`DownloadGrant.reach`); which session may use one is the
service's rule. A member's grant of a received file (#213, `insert_member_grant`) has the member's
pair instead, `user_id` and `member_session_id`, and is read and written in the tenant's scope;
it counts no download, since received files have no limit. The lifecycle jobs (`sft_jobs`,
revision 0015) find grants across tenants in system scope and delete or mark them in each tenant's
scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import ColumnElement, case, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.models import DownloadCounter, DownloadGrant, LinkSession, TransferRecipient
from sft.data.scope import ScopeKind

LIFETIME: Final = timedelta(hours=24)
REQUEST_LIMIT: Final = 20
BUDGET_FACTOR: Final = 3
LEASE: Final = timedelta(seconds=60)
"""A stream's lease, renewed at every re-check (every 30 s), so two streams overlap 30 s at most."""

_WRITE_SCOPES = (ScopeKind.TENANT, ScopeKind.RESOURCE)


@dataclass(frozen=True, slots=True)
class Grant:
    id: UUID
    tenant_id: UUID
    file_id: UUID
    s3_version_id: str
    recipient_id: UUID | None
    link_session_id: UUID | None
    byte_budget: int
    bytes_served: int
    request_count: int
    expires_at: datetime
    archived_at: datetime | None
    created_at: datetime
    user_id: UUID | None = None
    """A member's grant of a received file (#213): exactly one pair is set."""
    member_session_id: UUID | None = None

    def usable(self, now: datetime) -> bool:
        """Time, requests and bytes left: what a resume needs (FR-6)."""
        return (
            self.expires_at > now
            and self.request_count < REQUEST_LIMIT
            and self.bytes_served < self.byte_budget
        )


_COLUMNS = (
    DownloadGrant.id,
    DownloadGrant.tenant_id,
    DownloadGrant.file_id,
    DownloadGrant.s3_version_id,
    DownloadGrant.recipient_id,
    DownloadGrant.link_session_id,
    DownloadGrant.byte_budget,
    DownloadGrant.bytes_served,
    DownloadGrant.request_count,
    DownloadGrant.expires_at,
    DownloadGrant.archived_at,
    DownloadGrant.created_at,
    DownloadGrant.user_id,
    DownloadGrant.member_session_id,
)


async def count_download(session: AsyncSession, recipient_id: UUID, file_id: UUID) -> int | None:
    """Count one download of the file by the recipient, if its limit allows; the new count, or
    None when the limit is reached (data model 2.3)."""
    require_scope(session, *_WRITE_SCOPES)
    now = func.now()
    count: int | None = await session.scalar(
        update(DownloadCounter)
        .where(
            DownloadCounter.recipient_id == recipient_id,
            DownloadCounter.file_id == file_id,
            in_scope(DownloadCounter, session),
            (DownloadCounter.download_limit.is_(None))
            | (DownloadCounter.count < DownloadCounter.download_limit),
        )
        .values(
            count=DownloadCounter.count + 1,
            first_downloaded_at=func.coalesce(DownloadCounter.first_downloaded_at, now),
            last_downloaded_at=now,
            updated_at=now,
        )
        .returning(DownloadCounter.count)
        .execution_options(synchronize_session=False)
    )
    return count


@dataclass(frozen=True, slots=True)
class Counted:
    count: int
    download_limit: int | None


async def counter(session: AsyncSession, recipient_id: UUID, file_id: UUID) -> Counted | None:
    """The recipient's counter for the file: none until the transfer is sent."""
    row = (
        await session.execute(
            select(DownloadCounter.count, DownloadCounter.download_limit).where(
                DownloadCounter.recipient_id == recipient_id,
                DownloadCounter.file_id == file_id,
                in_scope(DownloadCounter, session),
            )
        )
    ).first()
    return None if row is None else Counted(row[0], row[1])


async def insert_grant(
    session: AsyncSession,
    *,
    grant_id: UUID,
    file_id: UUID,
    s3_version_id: str,
    recipient_id: UUID,
    link_session_id: UUID,
    size: int,
    ends_by: datetime,
) -> Grant:
    """A grant for 3 times `size` bytes and 20 requests, for 24 hours or until `ends_by` (the
    session's end), whichever is sooner. The caller writes `download.granted`."""
    require_scope(session, *_WRITE_SCOPES)
    await session.execute(
        insert(DownloadGrant).values(
            id=grant_id,
            tenant_id=tenant_of(session),
            file_id=file_id,
            s3_version_id=s3_version_id,
            recipient_id=recipient_id,
            link_session_id=link_session_id,
            byte_budget=BUDGET_FACTOR * size,
            expires_at=func.least(func.now() + LIFETIME, ends_by),
        )
    )
    return await get_grant(session, grant_id)


async def insert_member_grant(
    session: AsyncSession,
    *,
    grant_id: UUID,
    file_id: UUID,
    s3_version_id: str,
    user_id: UUID,
    member_session_id: UUID,
    size: int,
    ends_by: datetime,
) -> Grant:
    """A member's grant of a received file (#213): the same budget as a recipient's, 3 times
    `size` bytes and 20 requests, for 24 hours or until `ends_by` (the member session's end). No
    download is counted. In the tenant's scope; the caller writes `download.granted`."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        insert(DownloadGrant).values(
            id=grant_id,
            tenant_id=tenant_of(session),
            file_id=file_id,
            s3_version_id=s3_version_id,
            user_id=user_id,
            member_session_id=member_session_id,
            byte_budget=BUDGET_FACTOR * size,
            expires_at=func.least(func.now() + LIFETIME, ends_by),
        )
    )
    return await get_grant(session, grant_id)


async def get_grant(session: AsyncSession, grant_id: UUID) -> Grant:
    row = (
        await session.execute(
            select(*_COLUMNS).where(DownloadGrant.id == grant_id, in_scope(DownloadGrant, session))
        )
    ).first()
    if row is None:
        raise NotFoundError("download grant")
    return Grant(*row)


@dataclass(frozen=True, slots=True)
class Admitted:
    bytes_served: int
    byte_budget: int


async def admit(
    session: AsyncSession, grant_id: UUID, stream_id: UUID, *, need: int = 1
) -> Admitted | None:
    """One content request (data model 2.3): a request of the 20, and the grant's only stream
    lease. None when the grant has no time or requests left, or fewer bytes left than the `need`
    of the span asked for, so a response never declares more than it may send (#180 review)."""
    require_scope(session, *_WRITE_SCOPES)
    now = func.now()
    row = (
        await session.execute(
            update(DownloadGrant)
            .where(
                DownloadGrant.id == grant_id,
                in_scope(DownloadGrant, session),
                DownloadGrant.expires_at > now,
                DownloadGrant.request_count < REQUEST_LIMIT,
                DownloadGrant.bytes_served + need <= DownloadGrant.byte_budget,
            )
            .values(
                request_count=DownloadGrant.request_count + 1,
                active_stream_id=stream_id,
                active_stream_until=now + LEASE,
            )
            .returning(DownloadGrant.bytes_served, DownloadGrant.byte_budget)
            .execution_options(synchronize_session=False)
        )
    ).first()
    return None if row is None else Admitted(int(row[0]), int(row[1]))


async def record_progress(
    session: AsyncSession, grant_id: UUID, stream_id: UUID, sent: int, *, ending: bool = False
) -> bool:
    """Add `sent` bytes to the grant; renew the lease if this stream still holds it, or give it
    up when `ending`. Whether it held the lease (data model 2.3)."""
    require_scope(session, *_WRITE_SCOPES)
    holds = DownloadGrant.active_stream_id == stream_id
    renewed = None if ending else func.now() + LEASE
    held: bool | None = await session.scalar(
        update(DownloadGrant)
        .where(DownloadGrant.id == grant_id, in_scope(DownloadGrant, session))
        .values(
            bytes_served=DownloadGrant.bytes_served + sent,
            active_stream_until=case((holds, renewed), else_=DownloadGrant.active_stream_until),
            active_stream_id=case(
                (holds, None if ending else stream_id), else_=DownloadGrant.active_stream_id
            ),
        )
        .returning(holds)
        .execution_options(synchronize_session=False)
    )
    return bool(held)


async def extend_for_transfer(session: AsyncSession, transfer_id: UUID) -> int:
    """Let the live grants of the transfer's recipients run on with their sessions, after
    `link_sessions.extend_for_transfer` moved those (#214): each to 24 hours after it was made or
    its session's end, whichever is sooner, as `insert_grant` caps a new one. A grant that has
    ended stays ended, none is shortened, and nothing else of the grant changes, so its committed
    record (which holds no expiry) stays as written. How many moved."""
    require_scope(session, ScopeKind.TENANT)
    longest = func.least(DownloadGrant.created_at + LIFETIME, LinkSession.expires_at)
    result = await session.execute(
        update(DownloadGrant)
        .where(
            DownloadGrant.link_session_id == LinkSession.id,
            LinkSession.recipient_id.in_(
                select(TransferRecipient.id).where(
                    TransferRecipient.transfer_id == transfer_id,
                    in_scope(TransferRecipient, session),
                )
            ),
            LinkSession.revoked_at.is_(None),
            DownloadGrant.expires_at > func.now(),
            DownloadGrant.expires_at < longest,
            in_scope(LinkSession, session),
            in_scope(DownloadGrant, session),
        )
        .values(expires_at=longest)
        .returning(DownloadGrant.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


async def mark_archived(session: AsyncSession, grant_id: UUID) -> None:
    """Both regions confirmed the grant's committed record (data model 2.3)."""
    require_scope(session, *_WRITE_SCOPES)
    await session.execute(
        update(DownloadGrant)
        .where(
            DownloadGrant.id == grant_id,
            DownloadGrant.archived_at.is_(None),
            in_scope(DownloadGrant, session),
        )
        .values(archived_at=func.now())
        .execution_options(synchronize_session=False)
    )


# ---- the lifecycle jobs (sft_jobs) ----


@dataclass(frozen=True, slots=True)
class Unarchived:
    """What a grant's committed record holds (`sft.service.downloads.committed_record`)."""

    id: UUID
    tenant_id: UUID
    file_id: UUID
    s3_version_id: str
    recipient_id: UUID | None
    link_session_id: UUID | None
    byte_budget: int
    expires_at: datetime
    created_at: datetime
    user_id: UUID | None = None
    member_session_id: UUID | None = None


async def unarchived(
    session: AsyncSession, *, created_before: datetime, limit: int
) -> list[Unarchived]:
    """Grants whose committed record isn't confirmed a minute after creation, across tenants:
    reconciliation's find step, in system scope (data model 2.3, 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(
            DownloadGrant.id,
            DownloadGrant.tenant_id,
            DownloadGrant.file_id,
            DownloadGrant.s3_version_id,
            DownloadGrant.recipient_id,
            DownloadGrant.link_session_id,
            DownloadGrant.byte_budget,
            DownloadGrant.expires_at,
            DownloadGrant.created_at,
            DownloadGrant.user_id,
            DownloadGrant.member_session_id,
        )
        .where(
            DownloadGrant.archived_at.is_(None),
            DownloadGrant.created_at < created_before,
            in_scope(DownloadGrant, session),
        )
        .order_by(DownloadGrant.created_at)
        .limit(limit)
    )
    return [Unarchived(*row) for row in rows]


def archived() -> ColumnElement[bool]:
    """A grant the cleanup may delete: its committed record is confirmed in both regions. One
    that isn't stays for reconciliation, however old (NFR-15, #181 review)."""
    return DownloadGrant.archived_at.is_not(None)


async def count_unarchived(session: AsyncSession, *, created_before: datetime) -> int:
    """Grants still waiting for their committed record, across tenants: what the cleanup keeps
    and reconciliation retries (`lifecycle_unarchived_grants`)."""
    require_scope(session, ScopeKind.SYSTEM)
    count = await session.scalar(
        select(func.count())
        .select_from(DownloadGrant)
        .where(
            DownloadGrant.archived_at.is_(None),
            DownloadGrant.created_at < created_before,
            in_scope(DownloadGrant, session),
        )
    )
    return int(count or 0)


async def tenants_with_expired(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with grants past their expiry and archived, across tenants, in system scope (data
    model 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(DownloadGrant.tenant_id)
        .where(DownloadGrant.expires_at <= before, archived(), in_scope(DownloadGrant, session))
        .group_by(DownloadGrant.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_expired(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's expired grants whose committed record is
    confirmed (`archived`). The count and the audit record stay (data model 6)."""
    require_scope(session, ScopeKind.TENANT)
    found = select(DownloadGrant.id).where(
        DownloadGrant.expires_at <= before, archived(), in_scope(DownloadGrant, session)
    )
    result = await session.execute(
        delete(DownloadGrant)
        .where(
            DownloadGrant.id.in_(found.limit(limit).scalar_subquery()),
            in_scope(DownloadGrant, session),
        )
        .returning(DownloadGrant.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


__all__ = [
    "BUDGET_FACTOR",
    "LEASE",
    "LIFETIME",
    "REQUEST_LIMIT",
    "Admitted",
    "Counted",
    "Grant",
    "Unarchived",
    "admit",
    "archived",
    "count_download",
    "count_unarchived",
    "counter",
    "delete_expired",
    "extend_for_transfer",
    "get_grant",
    "insert_grant",
    "insert_member_grant",
    "mark_archived",
    "record_progress",
    "tenants_with_expired",
    "unarchived",
]
