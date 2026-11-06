"""Transfers and files in any state, seeded as the superuser with time-ordered IDs as the
application makes them, for the send, evaluation and scan tests (#174 to #176).

The superuser skips row-level security and the audit trigger, so seeding is never mistaken for the
code under test. Every file gets the columns its state's checks ask for (data model 3.1): a version
and a deadline once it is past `completing`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import timedelta

from pg import ScratchDatabase
from sft.core.ids import uuid7

FILE_SIZE = 10
DONE = ("clean", "infected", "unscannable", "scan_failed")


def seed_transfer(
    db: ScratchDatabase,
    tenant_id: uuid.UUID,
    owner: uuid.UUID,
    *,
    state: str = "draft",
    recipients: Sequence[str] = ("partner@example.test",),
    expires_in: timedelta = timedelta(days=7),
    expires_at_offset: timedelta | None = timedelta(days=7),
    download_limit: int | None = None,
    hold_reason: str | None = None,
) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """A transfer and its recipients. Past draft it has `submitted_at` and `expires_at`."""
    transfer_id = uuid7()
    submitted = state != "draft"
    db.sql(
        "INSERT INTO transfers (id, tenant_id, created_by, state, expires_in, download_limit, "
        "hold_reason, submitted_at, expires_at) VALUES (:id, :tenant, :owner, :state, "
        ":expires_in, :limit, :hold, CASE WHEN :submitted THEN now() END, "
        "CASE WHEN :submitted THEN now() + CAST(:offset AS interval) END)",
        id=transfer_id,
        tenant=tenant_id,
        owner=owner,
        state=state,
        expires_in=expires_in,
        limit=download_limit,
        hold=hold_reason if hold_reason or state != "held" else "file_blocked",
        submitted=submitted,
        offset=expires_at_offset if expires_at_offset is not None else timedelta(days=7),
    )
    recipient_ids = []
    for email in recipients:
        recipient_id = uuid7()
        db.sql(
            "INSERT INTO transfer_recipients (id, tenant_id, transfer_id, email, "
            "email_normalized, locale) VALUES (:id, :tenant, :transfer, :email, lower(:email), "
            "'en')",
            id=recipient_id,
            tenant=tenant_id,
            transfer=transfer_id,
            email=email,
        )
        recipient_ids.append(recipient_id)
    return transfer_id, recipient_ids


def seed_file(
    db: ScratchDatabase,
    tenant_id: uuid.UUID,
    transfer_id: uuid.UUID,
    *,
    state: str = "scanning",
    unscannable_allowed: bool = False,
    inspection_state: str | None = None,
    removed: bool = False,
    size: int = FILE_SIZE,
    storage_class: str = "standard",
    deadline: timedelta = timedelta(hours=2),
    version: str = "version-1",
) -> uuid.UUID:
    """A file of the transfer. A finished file's inspection is `inspected` unless given."""
    file_id = uuid7()
    scanned = state not in ("uploading", "completing", "rejected")
    if inspection_state is None:
        inspection_state = "inspected" if state in DONE else "pending"
        if state in ("infected", "scan_failed"):
            inspection_state = "skipped"
    db.sql(
        "INSERT INTO files (id, tenant_id, transfer_id, display_name_ct, content_type, "
        "declared_size, actual_size, storage_class, storage_key, s3_upload_id, s3_version_id, "
        "part_size, part_count, state, completion_started_at, removed_at, scan_deadline, "
        "delete_after, unscannable_allowed, inspection_state, scan_engine, scanned_at) VALUES "
        "(:id, :tenant, :transfer, '\\x0061', 'text/plain', :size, "
        "CASE WHEN :scanned THEN :size END, :class, 'tenants/' || :tenant || '/files/' || :id, "
        "'upload-' || :id, CASE WHEN :scanned THEN :version END, 5242880, "
        "greatest(1, ceil(:size / 5242880.0))::int, :state, "
        "CASE WHEN :state = 'completing' THEN now() END, CASE WHEN :removed THEN now() END, "
        "CASE WHEN :scanned THEN now() + CAST(:deadline AS interval) END, "
        "CASE WHEN :removed OR :state = 'rejected' THEN now() END, :allowed, :inspection, "
        "CASE WHEN :state IN ('clean', 'infected', 'unscannable') THEN 'clamav' END, "
        "CASE WHEN :state IN ('clean', 'infected', 'unscannable', 'scan_failed') THEN now() END)",
        id=file_id,
        tenant=tenant_id,
        transfer=transfer_id,
        size=size,
        scanned=scanned,
        **{"class": storage_class},
        version=version,
        state=state,
        removed=removed,
        deadline=deadline,
        allowed=unscannable_allowed,
        inspection=inspection_state,
    )
    db.sql(
        "INSERT INTO tenant_usage (tenant_id, bytes_reserved) VALUES (:tenant, :size) "
        "ON CONFLICT (tenant_id) DO UPDATE "
        "SET bytes_reserved = tenant_usage.bytes_reserved + :size",
        tenant=tenant_id,
        size=size,
    )
    return file_id


def seed_finding(
    db: ScratchDatabase, tenant_id: uuid.UUID, file_id: uuid.UUID, detector: str, high: int = 1
) -> None:
    db.sql(
        "INSERT INTO dlp_findings (id, tenant_id, file_id, detector, count_low, count_medium, "
        "count_high) VALUES (:id, :tenant, :file, :detector, 0, 0, :high)",
        id=uuid.uuid4(),
        tenant=tenant_id,
        file=file_id,
        detector=detector,
        high=high,
    )


def transfer_row(db: ScratchDatabase, transfer_id: uuid.UUID) -> dict[str, object]:
    [row] = db.sql(
        "SELECT state, hold_reason, submitted_at, expires_at, sent_at, ended_at, expires_in "
        "FROM transfers WHERE id = :id",
        id=transfer_id,
    )
    keys = ("state", "hold_reason", "submitted_at", "expires_at", "sent_at", "ended_at")
    return dict(zip((*keys, "expires_in"), row, strict=True))


def outbox_topics(db: ScratchDatabase, key: str, value: uuid.UUID) -> list[object]:
    return [
        topic
        for (topic,) in db.sql(
            "SELECT topic FROM outbox WHERE payload->>CAST(:key AS text) = :id "
            "ORDER BY created_at, id",
            key=key,
            id=str(value),
        )
    ]


def actions(db: ScratchDatabase, target: uuid.UUID) -> list[object]:
    return [
        action
        for (action,) in db.sql(
            "SELECT action FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
            id=target,
        )
    ]
