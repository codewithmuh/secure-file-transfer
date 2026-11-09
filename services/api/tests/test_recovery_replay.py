"""The restore and failover runbooks' re-import and re-apply (#253, #252), against a real database
as `sft_recovery` in recovery scope (`sft.service.recovery_replay`)."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, date, datetime, timedelta
from importlib import import_module

import pytest

import isolation_fixture
from isolation import Seeded, seed_tenant
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.rls import grant_sql, policy_sql
from sft.data.roles import MIGRATE, RECOVERY
from sft.service.recovery_replay import (
    Outcome,
    Record,
    day_prefixes,
    merge,
    parse_record,
    prepare_partitions,
    replay,
    republish_outbox,
    start_generation,
)

pytestmark = pytest.mark.anyio

# Revision 0035's statements, rebuilt with the helpers that wrote them (sft.data.rls): what the
# re-apply reads and writes, column by column, and one policy per table in recovery scope only.
_COLUMNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("transfers", "SELECT", ("id", "tenant_id", "state", "ended_at", "revoked_by")),
    ("transfers", "UPDATE", ("state", "hold_reason", "ended_at", "revoked_by", "updated_at")),
    ("files", "SELECT", ("id", "tenant_id", "transfer_id", "delete_after")),
    ("files", "UPDATE", ("delete_after",)),
    (
        "upload_requests",
        "SELECT",
        ("id", "tenant_id", "state", "ended_at", "revoked_by", "locked_at", "failed_attempts"),
    ),
    (
        "upload_requests",
        "UPDATE",
        ("state", "ended_at", "revoked_by", "locked_at", "failed_attempts", "updated_at"),
    ),
    (
        "transfer_recipients",
        "SELECT",
        ("id", "tenant_id", "transfer_id", "locked_at", "failed_attempts"),
    ),
    ("transfer_recipients", "UPDATE", ("locked_at", "failed_attempts", "updated_at")),
    (
        "link_sessions",
        "SELECT",
        ("id", "tenant_id", "recipient_id", "upload_request_id", "revoked_at"),
    ),
    ("link_sessions", "UPDATE", ("revoked_at",)),
    ("users", "SELECT", ("id", "tenant_id", "role", "status")),
    (
        "users",
        "UPDATE",
        (
            "role",
            "status",
            "sso_fallback",
            "dlp_approver",
            "invitation_token_hash",
            "invitation_expires_at",
            "updated_at",
        ),
    ),
    ("api_keys", "SELECT", ("id", "tenant_id", "revoked_at")),
    ("api_keys", "UPDATE", ("revoked_at", "revoked_reason")),
    ("member_sessions", "SELECT", ("id", "tenant_id", "user_id", "created_at", "revoked_at")),
    ("member_sessions", "UPDATE", ("revoked_at", "revoked_reason")),
    (
        "user_identities",
        "SELECT",
        ("id", "tenant_id", "user_id", "idp_connection_id", "created_at"),
    ),
    ("user_identities", "DELETE", ()),
    ("idp_connections", "SELECT", ("id", "tenant_id")),
    ("download_grants", "SELECT", ("id",)),
    (
        "download_counters",
        "SELECT",
        (
            "tenant_id",
            "recipient_id",
            "file_id",
            "count",
            "first_downloaded_at",
            "last_downloaded_at",
        ),
    ),
    (
        "download_counters",
        "UPDATE",
        ("count", "first_downloaded_at", "last_downloaded_at", "updated_at"),
    ),
    ("audit_events", "SELECT", ("tx_id", "occurred_at")),
    ("outbox", "SELECT", ("published_at",)),
    ("outbox", "UPDATE", ("published_at", "attempts", "next_attempt_at", "last_error")),
)
_IN_RECOVERY = "app_scope() = 'recovery'"
_REAPPLIED = (
    "transfers",
    "files",
    "upload_requests",
    "transfer_recipients",
    "link_sessions",
    "users",
    "api_keys",
    "member_sessions",
    "user_identities",
    "download_counters",
    "outbox",
)


def test_revision_0035_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    revision = import_module("sft.data.migrations.versions.0035_recovery_grants")
    assert (
        tuple(
            grant_sql(table, RECOVERY, privilege, columns=columns)
            for table, privilege, columns in _COLUMNS
        )
        == revision.GRANTS
    )
    assert (
        *(
            policy_sql(
                "recovery_reapply",
                table,
                roles=[RECOVERY],
                using=_IN_RECOVERY,
                with_check=_IN_RECOVERY,
            )
            for table in _REAPPLIED
        ),
        # A pool's connection has no tenant.
        policy_sql(
            "recovery_reapply",
            "idp_connections",
            roles=[RECOVERY],
            command="SELECT",
            using=f"{_IN_RECOVERY} AND tenant_id IS NULL",
        ),
        policy_sql(
            "recovery_reapply",
            "download_grants",
            roles=[RECOVERY],
            command="SELECT",
            using=_IN_RECOVERY,
        ),
        # Beside revision 0002's insert policy: the cursor's rewind reads tx_id and occurred_at.
        policy_sql(
            "audit_recovery_select",
            "audit_events",
            roles=[RECOVERY],
            command="SELECT",
            using=_IN_RECOVERY,
        ),
    ) == revision.POLICIES


@pytest.fixture
def own_db(empty_db: ScratchDatabase) -> ScratchDatabase:
    """A migrated database of the test's own: the archive cursor is global, so its moves must not
    reach other tests."""
    run(empty_db.url(MIGRATE))
    empty_db.as_owner(isolation_fixture.create)  # seed_tenant fills its stand-in tables too
    return empty_db


@pytest.fixture
async def recovery(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(RECOVERY), pool_size=1)
    yield database
    await database.dispose()


RESTORE_POINT = datetime.now(UTC) - timedelta(hours=1)


def record(
    action: str,
    *,
    tenant: uuid.UUID | None,
    target: tuple[str, uuid.UUID] | None,
    actor: tuple[str, uuid.UUID | None] = ("admin", None),
    critical: bool = True,
    details: Mapping[str, object] | None = None,
    minutes: int = 10,
    event_id: uuid.UUID | None = None,
) -> Record:
    """A record as the archive holds it, `minutes` after the restore point, through its JSON."""
    body = {
        "id": str(event_id or uuid.uuid4()),
        "tenant_id": None if tenant is None else str(tenant),
        "occurred_at": (RESTORE_POINT + timedelta(minutes=minutes)).isoformat(),
        "action": action,
        "actor_type": actor[0],
        "actor_id": None if actor[1] is None else str(actor[1]),
        "target_type": None if target is None else target[0],
        "target_id": None if target is None else str(target[1]),
        "outcome": "success",
        "security_critical": critical,
        "details": dict(details or {}),
        # The archive job's copy carries more; what is re-applied needs none of it.
        "request_id": "ignored",
    }
    return parse_record(json.dumps(body).encode())


def one(db: ScratchDatabase, statement: str, **params: object) -> tuple[object, ...]:
    [row] = db.sql(statement, **params)
    return row


def seed_pool_member(db: ScratchDatabase, tenant_id: uuid.UUID) -> dict[str, uuid.UUID]:
    """A member who signs in through the user pool, with an identity there and a live session."""
    ids = {k: uuid.uuid4() for k in ("pool", "user", "identity", "session")}
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, 'https://pool.example.test', 'active')",
        id=ids["pool"],
        name=f"pool-{ids['pool'].hex[:8]}",
    )
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :tenant, :email, :email, 'admin', 'active')",
        id=ids["user"],
        tenant=tenant_id,
        email=f"{ids['user'].hex}@example.test",
    )
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject, "
        "created_at) VALUES (:id, :tenant, :user, :pool, :subject, :created)",
        id=ids["identity"],
        tenant=tenant_id,
        user=ids["user"],
        pool=ids["pool"],
        subject=ids["identity"].hex,
        created=RESTORE_POINT - timedelta(days=1),
    )
    db.sql(
        "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
        "auth_time, auth_method, expires_at, created_at) VALUES (:id, :tenant, :user, "
        ":identity, sha256(convert_to(CAST(:id AS text), 'UTF8')), now(), 'password', "
        "now() + interval '12 hours', :created)",
        id=ids["session"],
        tenant=tenant_id,
        user=ids["user"],
        identity=ids["identity"],
        created=RESTORE_POINT,
    )
    return ids


def counted(db: ScratchDatabase, seeded: Seeded) -> object:
    return one(
        db,
        "SELECT count FROM download_counters WHERE recipient_id = :r AND file_id = :f",
        r=seeded.rows["recipient"],
        f=seeded.rows["scanning_file"],
    )[0]


async def test_replay_reimports_events_and_reapplies_what_takes_access_away(
    own_db: ScratchDatabase, recovery: Database
) -> None:
    db = own_db
    seeded = seed_tenant(db, "recovery")
    rows, tenant = seeded.rows, seeded.tenant_id
    # The restored state: the transfer was sent before the restore point, and its link session,
    # the uploader's session, the API key and the member's session are all live.
    db.sql(
        "UPDATE transfers SET state = 'sent', expires_at = now() + interval '7 days', "
        "submitted_at = now(), sent_at = now() WHERE id = :id",
        id=rows["transfer"],
    )
    pool = seed_pool_member(db, tenant)
    before = counted(db, seeded)
    present = uuid.uuid4()
    db.sql(
        "INSERT INTO audit_events (id, tenant_id, occurred_at, actor_type, action, outcome, "
        "security_critical) VALUES (:id, :tenant, :at, 'system', 'transfer.expired', "
        "'success', false)",
        id=present,
        tenant=tenant,
        at=RESTORE_POINT + timedelta(minutes=1),
    )
    admin = ("admin", rows["user"])
    new_grant = uuid.uuid4()
    records = [
        record(
            "transfer.revoked", tenant=tenant, target=("transfer", rows["transfer"]), actor=admin
        ),
        record(
            "upload_request.revoked",
            tenant=tenant,
            target=("upload_request", rows["upload_request"]),
            actor=admin,
        ),
        record(
            "recipient.locked",
            tenant=tenant,
            target=("recipient", rows["recipient"]),
            actor=("recipient", rows["recipient"]),
            details={"failed_attempts": 20},
        ),
        record(
            "api_key.revoked",
            tenant=tenant,
            target=("api_key", rows["api_key"]),
            details={"reason": "owner_deactivated", "owner_id": str(rows["user"])},
        ),
        record("user.deactivated", tenant=tenant, target=("user", rows["user"]), actor=admin),
        record("user.sign_in_reset", tenant=tenant, target=("user", pool["user"]), actor=admin),
        # A grant committed after the restore point, whose row the restore lost: counted again.
        record(
            "download.grant_committed",
            tenant=tenant,
            target=("file", rows["scanning_file"]),
            actor=("recipient", rows["recipient"]),
            details={"grant_id": str(new_grant), "byte_budget": 30},
            event_id=new_grant,
        ),
        # A grant the restored database still has: already counted, so not again.
        record(
            "download.grant_committed",
            tenant=tenant,
            target=("file", rows["scanning_file"]),
            actor=("recipient", rows["recipient"]),
            details={"grant_id": str(rows["download_grant"]), "byte_budget": 30},
            event_id=rows["download_grant"],
        ),
        record(
            "download.grant_intent",
            tenant=tenant,
            target=("file", rows["scanning_file"]),
            actor=("recipient", rows["recipient"]),
            details={"grant_id": str(uuid.uuid4())},
        ),
        record(
            "uploader.unlocked",
            tenant=tenant,
            target=("upload_request", rows["upload_request"]),
            actor=admin,
            minutes=20,
        ),
        record(
            "transfer.created", tenant=tenant, target=("transfer", uuid.uuid4()), critical=False
        ),
        record(
            "transfer.expired",
            tenant=tenant,
            target=None,
            actor=("system", None),
            critical=False,
            minutes=1,
            event_id=present,
        ),
        # Older than the restore point: the database has it already.
        record("transfer.revoked", tenant=tenant, target=("transfer", uuid.uuid4()), minutes=-5),
    ]
    # The same record twice, as a direct record and as the archive job's copy: once.
    records.append(records[0])

    created = await prepare_partitions(recovery, merge(records, since=RESTORE_POINT))
    assert created
    report = await replay(recovery, records, since=RESTORE_POINT)

    assert report.total(Outcome.REAPPLIED) == 7
    assert report.counts[("download.grant_committed", Outcome.REAPPLIED)] == 1
    # The grant the database still has: re-imported, already counted.
    assert report.counts[("download.grant_committed", Outcome.REIMPORTED)] == 1
    assert report.counts[("uploader.unlocked", Outcome.NOT_REAPPLIED)] == 1
    assert report.counts[("transfer.created", Outcome.REIMPORTED)] == 1
    assert report.counts[("transfer.expired", Outcome.PRESENT)] == 1
    assert report.counts[("download.grant_intent", Outcome.IGNORED)] == 1
    assert sum(report.counts.values()) == 12

    # Revocations: the transfer and request end, and so do their link sessions; the transfer's
    # files go to the deletion job.
    assert one(
        db, "SELECT state, revoked_by FROM transfers WHERE id = :id", id=rows["transfer"]
    ) == (
        "revoked",
        rows["user"],
    )
    assert one(
        db,
        "SELECT revoked_at IS NOT NULL FROM link_sessions WHERE id = :id",
        id=rows["link_session"],
    ) == (True,)
    assert db.sql(
        "SELECT count(*) FROM files WHERE transfer_id = :id AND delete_after IS NULL",
        id=rows["transfer"],
    ) == [(0,)]
    assert one(
        db, "SELECT state FROM upload_requests WHERE id = :id", id=rows["upload_request"]
    ) == ("revoked",)
    assert one(
        db,
        "SELECT revoked_at IS NOT NULL FROM link_sessions WHERE id = :id",
        id=rows["upload_session"],
    ) == (True,)
    # The lockout stands; the unlock isn't re-applied.
    assert one(
        db,
        "SELECT locked_at IS NOT NULL, failed_attempts FROM transfer_recipients WHERE id = :id",
        id=rows["recipient"],
    ) == (True, 20)
    # The key, the deactivated user and their session, the reset user's session and pool identity.
    assert one(db, "SELECT revoked_reason FROM api_keys WHERE id = :id", id=rows["api_key"]) == (
        "owner_deactivated",
    )
    assert one(db, "SELECT status FROM users WHERE id = :id", id=rows["user"]) == ("deactivated",)
    assert one(
        db, "SELECT revoked_reason FROM member_sessions WHERE id = :id", id=rows["session"]
    ) == ("deactivated",)
    assert one(
        db, "SELECT revoked_reason FROM member_sessions WHERE id = :id", id=pool["session"]
    ) == ("sign_in_reset",)
    assert db.sql("SELECT 1 FROM user_identities WHERE id = :id", id=pool["identity"]) == []
    # The tenant's SSO identity isn't the pool's: a sign-in reset leaves it.
    assert db.sql("SELECT 1 FROM user_identities WHERE id = :id", id=rows["identity"]) == [(1,)]
    # One download counted again, for the lost grant only.
    assert counted(db, seeded) == int(str(before)) + 1
    # Re-imported with their own IDs and times, intents left out.
    assert one(db, "SELECT occurred_at FROM audit_events WHERE id = :id", id=new_grant) == (
        RESTORE_POINT + timedelta(minutes=10),
    )
    assert db.sql("SELECT count(*) FROM audit_events WHERE action = 'download.grant_intent'") == [
        (0,)
    ]
    assert db.sql("SELECT count(*) FROM audit_events_default") == [(0,)]
    # Each change made again has the recovery's own event, naming the record.
    assert one(
        db,
        "SELECT actor_type, target_id, details->>'record_action' FROM audit_events "
        "WHERE action = 'recovery.reapplied' AND details->>'record_id' = :record",
        record=str(records[0].id),
    ) == ("system", rows["transfer"], "transfer.revoked")
    assert db.sql("SELECT count(*) FROM audit_events WHERE action = 'recovery.reapplied'") == [(7,)]

    # A second run finds every record present and changes nothing.
    again = await replay(recovery, records, since=RESTORE_POINT)
    assert again.total(Outcome.REAPPLIED) == 0
    assert again.total(Outcome.PRESENT) == 11
    assert counted(db, seeded) == int(str(before)) + 1


async def test_a_new_generation_rewinds_the_cursor_once(
    own_db: ScratchDatabase, recovery: Database
) -> None:
    db = own_db
    seeded = seed_tenant(db, "generation")
    rewind_to = datetime.now(UTC) - timedelta(minutes=30)
    for minutes in (-60, -20, -10):
        db.sql(
            "INSERT INTO audit_events (id, tenant_id, occurred_at, actor_type, action, outcome, "
            "security_critical) VALUES (:id, :tenant, now() + make_interval(mins => :m), "
            "'system', 'transfer.expired', 'success', false)",
            id=uuid.uuid4(),
            tenant=seeded.tenant_id,
            m=minutes,
        )
    # The restored cursor is past every event, as if their batches were archived in Tokyo.
    db.sql(
        "UPDATE audit_archive_cursor SET generation = 2, archived_up_to_tx = pg_current_xact_id()"
    )
    # And a run of the archive job had claimed the next range when the region went: the claim goes.
    db.sql("UPDATE audit_archive_cursor SET claimed_up_to_tx = pg_current_xact_id()")
    [(oldest_since,)] = db.sql(
        "SELECT tx_id::text FROM audit_events WHERE occurred_at >= :at ORDER BY tx_id LIMIT 1",
        at=rewind_to,
    )

    assert await start_generation(recovery, highest_in_archive=3, rewind_to=rewind_to) == 4
    assert one(
        db,
        "SELECT generation, archived_up_to_tx::text, claimed_up_to_tx FROM audit_archive_cursor",
    ) == (4, oldest_since, None)
    # Run again: the generation and the position stay.
    assert await start_generation(recovery, highest_in_archive=3, rewind_to=rewind_to) == 4
    assert one(db, "SELECT archived_up_to_tx::text FROM audit_archive_cursor") == (oldest_since,)


async def test_outbox_messages_sent_since_go_back_to_the_relay(
    own_db: ScratchDatabase, recovery: Database
) -> None:
    db = own_db
    tenant = seed_tenant(db, "outbox").tenant_id
    since = datetime.now(UTC) - timedelta(hours=24)
    ids = {}
    now = datetime.now(UTC)
    for name, published in (
        ("recent", now - timedelta(hours=1)),
        ("old", now - timedelta(hours=25)),
        ("unsent", None),
    ):
        ids[name] = uuid.uuid4()
        db.sql(
            "INSERT INTO outbox (id, tenant_id, topic, payload, published_at, attempts) "
            "VALUES (:id, :tenant, 'scan.small', '{}'::jsonb, :published, 1)",
            id=ids[name],
            tenant=tenant,
            published=published,
        )

    assert await republish_outbox(recovery, since=since) == 1

    state = dict(
        db.sql(
            "SELECT id, published_at IS NULL AND attempts = 0 FROM outbox WHERE id = ANY(:ids)",
            ids=list(ids.values()),
        )
    )
    assert state == {ids["recent"]: True, ids["old"]: False, ids["unsent"]: False}


def test_merge_keeps_each_event_once_newest_last() -> None:
    tenant = uuid.uuid4()
    late = record("transfer.created", tenant=tenant, target=None, critical=False, minutes=30)
    early = record("transfer.created", tenant=tenant, target=None, critical=False, minutes=5)
    copy = record(
        "user.deactivated", tenant=tenant, target=("user", tenant), critical=False, minutes=7
    )
    direct = record(
        "user.deactivated", tenant=tenant, target=("user", tenant), minutes=7, event_id=copy.id
    )
    old = record("transfer.created", tenant=tenant, target=None, critical=False, minutes=-1)

    merged = merge([late, copy, early, direct, old], since=RESTORE_POINT)

    assert [r.id for r in merged] == [early.id, copy.id, late.id]
    assert merged[1].security_critical  # the direct record wins over the copy


def test_parse_record_refuses_what_isnt_one() -> None:
    with pytest.raises(ValueError, match="offset"):
        parse_record(
            json.dumps(
                {
                    "id": str(uuid.uuid4()),
                    "occurred_at": "2026-11-09T00:00:00",
                    "action": "transfer.revoked",
                    "actor_type": "admin",
                    "outcome": "success",
                }
            ).encode()
        )
    with pytest.raises(ValueError, match="object"):
        parse_record(b"[]")
    with pytest.raises(ValueError, match="aware"):
        merge([], since=datetime(2026, 11, 9))  # naive on purpose


def test_day_prefixes_cover_each_day() -> None:
    assert day_prefixes(
        "security-critical/v1", "platform", date(2026, 10, 31), date(2026, 11, 1)
    ) == [
        "security-critical/v1/platform/2026/10/31/",
        "security-critical/v1/platform/2026/11/01/",
    ]
    assert day_prefixes("p", "o", date(2026, 11, 2), date(2026, 11, 1)) == []
