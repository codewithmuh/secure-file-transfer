"""The audit archive's surviving-region mode for a regional loss, and the failback's back-fill
(#257; architecture 5.2, 7; data model 2.5; revision 0039).

Tokyo's archive is a failing stand-in throughout (archive_fixtures.FakeArchiveStore with Tokyo in
`fail`). With the toggle on, a download grant and the archive job succeed against Osaka alone;
once Tokyo answers again and the toggle is off, the archive job writes Tokyo exactly the objects
Osaka holds, and the records of the window's security-critical events: no gap, no duplicate.

The archive job's tests get a migrated database of their own, since the cursor is one row for the
whole database. The grant runs through the API against the shared world of test_downloads.py.
"""

from __future__ import annotations

import gzip
import json
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic.script import ScriptDirectory
from prometheus_client import CollectorRegistry
from sqlalchemy import URL

from archive_fixtures import FakeArchiveStore, fake_archive
from link_fixtures import World, unique, w
from pg import ScratchDatabase, fresh_database
from sft.core.settings import ArchiveJobSettings, JobSettings, OperatorSettings
from sft.data import archive_cursor
from sft.data.audit import ArchivedEvent
from sft.data.database import Database
from sft.data.migrate import alembic_config, run
from sft.data.rls import grant_sql, policy_sql
from sft.data.roles import ARCHIVE, MIGRATE
from sft.data.scope import Scope
from sft.runtime.archive import open_audit_archive
from sft.service import archive_job
from sft.service.archive_job import (
    ArchiveIncompleteError,
    ArchiveJobMetrics,
    records,
    run_archive,
)
from sft.service.audit_archive import (
    ArchiveWriteError,
    RecordNotConfirmed,
    Region,
    SurvivingRegion,
    intent_first,
    record_key,
)
from test_downloads import grant, shared

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests

SCRIPTS = ScriptDirectory.from_config(alembic_config())
OSAKA_ALONE = {Region.TOKYO}


# ---- the revision, without a database ----


def test_the_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    [script] = [s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "SINGLE_REGION")]
    system = "app_scope() = 'system'"
    expected = (
        "ALTER TABLE audit_archive_single_region ENABLE ROW LEVEL SECURITY",
        grant_sql("audit_archive_single_region", "sft_archive", "SELECT, INSERT, DELETE"),
        grant_sql(
            "audit_archive_cursor",
            "sft_archive",
            "UPDATE",
            columns=["single_region_since", "both_regions_since"],
        ),
        policy_sql(
            "archive_single_region",
            "audit_archive_single_region",
            roles=["sft_archive"],
            using=system,
            with_check=system,
        ),
    )
    assert expected == script.module.RLS


# ---- the toggle: settings and the store ----


def _settings(cls: type, **more: object) -> object:
    values: dict[str, object] = {
        "database_url": "postgresql://sft_archive@db.example/sft",
        "audit_archive_tokyo_bucket": "sft-prod-apne1-audit-archive-000000000000",
        "audit_archive_osaka_bucket": "sft-prod-apne3-audit-archive-000000000000",
    }
    if cls is JobSettings:
        values |= {
            "database_url": "postgresql://sft_jobs@db.example/sft",
            "s3_files_bucket": "sft-prod-apne3-files-000000000000",
            "s3_large_files_bucket": "sft-prod-apne3-large-files-000000000000",
        }
    if cls is OperatorSettings:
        # The operator API's records of recoverTenantAdmin follow the toggle too (#239, #257).
        values |= {
            "database_url": "postgresql://sft_operator@db.example/sft",
            "valkey_url": "redis://u:p@127.0.0.1:1/0",
            "operator_environment": "prod",
            "operator_aws_account_id": "000000000000",
            "operator_role_name": "AWSReservedSSO_Operator_0123456789abcdef",
        }
    return cls(**(values | more))


@pytest.mark.parametrize("cls", [ArchiveJobSettings, JobSettings, OperatorSettings])
def test_the_toggle_names_a_region_of_an_environment_that_has_both(cls: type) -> None:
    settings = _settings(cls, audit_archive_surviving_region="ap-northeast-3")
    assert settings.audit_archive_surviving_region == "ap-northeast-3"  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="AUDIT_ARCHIVE_OSAKA_BUCKET"):
        _settings(
            cls, audit_archive_osaka_bucket=None, audit_archive_surviving_region="ap-northeast-3"
        )
    with pytest.raises(ValueError, match="ap-northeast-1"):
        _settings(cls, audit_archive_surviving_region="us-east-1")


async def test_the_store_writes_the_surviving_region_alone() -> None:
    both = open_audit_archive(tokyo_bucket="sft-a-tokyo", osaka_bucket="sft-a-osaka")
    alone = open_audit_archive(
        tokyo_bucket="sft-a-tokyo", osaka_bucket="sft-a-osaka", surviving_region="ap-northeast-3"
    )
    try:
        assert both.regions == (Region.TOKYO, Region.OSAKA)
        assert alone.regions == (Region.OSAKA,)
        # Nothing reaches the lost region by mistake.
        with pytest.raises(ArchiveWriteError, match="NotTheSurvivingRegion"):
            await alone.put_once(Region.TOKYO, "k", b"{}")
    finally:
        await both.close()
        await alone.close()
    with pytest.raises(ValueError, match="no archive in ap-northeast-3"):
        SurvivingRegion(FakeArchiveStore(regions=(Region.TOKYO,)), Region.OSAKA)


def _event(**more: object) -> ArchivedEvent:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "occurred_at": datetime(2026, 11, 9, tzinfo=UTC),
        "action": "download.grant_intent",
        "actor_type": "recipient",
        "actor_id": uuid.uuid4(),
        "target_type": "file",
        "target_id": uuid.uuid4(),
        "outcome": "success",
    }
    return ArchivedEvent(**(values | more))  # type: ignore[arg-type]


async def test_intent_first_succeeds_in_osaka_with_tokyo_failing_only_with_the_toggle() -> None:
    store = FakeArchiveStore(fail=OSAKA_ALONE)
    committed = _event(action="download.grant_committed")

    async def commit() -> tuple[str, ArchivedEvent]:
        return "granted", committed

    # Without the toggle, Tokyo's failure is a 503 and nothing is committed.
    with pytest.raises(RecordNotConfirmed):
        await intent_first(fake_archive(store), _event(), commit)
    # With it, Osaka alone confirms.
    archive = fake_archive(SurvivingRegion(store, Region.OSAKA))  # type: ignore[arg-type]
    intent = _event()
    assert await intent_first(archive, intent, commit) == "granted"
    await archive.drain()
    assert {record_key(intent), record_key(committed)} <= set(store.objects[Region.OSAKA])
    assert store.objects.get(Region.TOKYO, {}) == {}


async def test_a_grant_through_the_api_succeeds_in_osaka_with_tokyo_lost(w: World) -> None:
    # Acceptance criterion 1, end to end: a recipient's grant with the toggle on.
    address = unique()
    _, [recipient], [file_id], _ = shared(w, address, limit=1)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    w.store.fail = set(OSAKA_ALONE)
    archive = w.downloads.archive
    lost = archive.store
    archive.store = SurvivingRegion(w.store, Region.OSAKA)
    try:
        answer = await grant(browser, session, file_id)
        await archive.drain()
    finally:
        archive.store = lost
        w.store.fail = set()
    assert answer.status_code == 200, answer.text
    osaka = [json.loads(b) for b in w.store.objects[Region.OSAKA].values()]
    actions = {r["action"] for r in osaka if r.get("target_id") == str(file_id)}
    assert {"download.grant_intent", "download.grant_committed"} <= actions
    assert w.db.sql(
        "SELECT count FROM download_counters WHERE recipient_id = :r AND file_id = :f",
        r=recipient,
        f=file_id,
    ) == [(1,)]


# ---- the archive job, against the database as sft_archive ----


@pytest.fixture
def archive_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def archive(archive_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(archive_db.url(ARCHIVE), pool_size=2)
    yield database
    await database.dispose()


def add_event(db: ScratchDatabase, *, critical: bool = False) -> str:
    """One event in a transaction of its own; a revocation when `critical`."""
    event_id = uuid.uuid4()
    db.sql(
        "INSERT INTO audit_events (id, tenant_id, actor_type, action, target_type, target_id, "
        "outcome, security_critical, details) VALUES (:id, :tenant, 'system', :action, "
        "'transfer', :target, 'success', :critical, '{\"system_actor\": \"expiry_job\"}')",
        id=event_id,
        tenant=uuid.uuid4(),
        action="transfer.revoked" if critical else "transfer.expired",
        target=uuid.uuid4(),
        critical=critical,
    )
    return str(event_id)


def batches(store: FakeArchiveStore, region: Region) -> dict[str, bytes]:
    return {k: v for k, v in store.objects.get(region, {}).items() if k.startswith("g")}


def recorded(store: FakeArchiveStore, region: Region) -> dict[str, bytes]:
    return {k: v for k, v in store.objects.get(region, {}).items() if not k.startswith("g")}


def waiting(db: ScratchDatabase) -> int:
    [(n,)] = db.sql("SELECT count(*) FROM audit_archive_single_region")
    return int(str(n))


def window(db: ScratchDatabase) -> tuple[bool, bool]:
    [(single, both)] = db.sql(
        "SELECT single_region_since IS NOT NULL, both_regions_since IS NOT NULL "
        "FROM audit_archive_cursor"
    )
    return bool(single), bool(both)


async def test_the_job_keeps_up_in_osaka_and_failback_back_fills_tokyo_exactly(
    archive: Database, archive_db: ScratchDatabase
) -> None:
    store = FakeArchiveStore()
    metrics = ArchiveJobMetrics.create(CollectorRegistry())
    before = add_event(archive_db)
    await run_archive(archive, store, metrics, max_rows=2)
    assert batches(store, Region.TOKYO) == batches(store, Region.OSAKA) != {}

    # Tokyo is lost. Without the toggle the job stops and lags; with it, Osaka alone keeps up.
    store.fail = set(OSAKA_ALONE)
    during = [add_event(archive_db), add_event(archive_db, critical=True), add_event(archive_db)]
    with pytest.raises(ArchiveIncompleteError):
        await run_archive(archive, store, metrics, max_rows=2)
    report = await run_archive(archive, store, metrics, max_rows=2, surviving=Region.OSAKA)
    assert report.lag_seconds == 0
    assert report.single_region == waiting(archive_db) >= 2  # ranges of up to 2 events
    assert metrics.single_region.collect()[0].samples[0].value == report.single_region
    assert window(archive_db) == (True, False)
    # The intent of a grant made meanwhile, which only the API ever wrote.
    intent = _event()
    await store.put_once(Region.OSAKA, record_key(intent), b"{}")
    osaka_ids = {
        json.loads(line)["id"]
        for body in batches(store, Region.OSAKA).values()
        for line in gzip.decompress(body).decode().splitlines()
    }
    assert {before, *during} <= osaka_ids

    # Failback: Tokyo answers, the toggle is off. One run back-fills, with the window's records.
    store.fail = set()
    report = await run_archive(archive, store, metrics, max_rows=2)
    assert report.backfilled >= 2
    assert waiting(archive_db) == 0
    assert batches(store, Region.TOKYO) == batches(store, Region.OSAKA)  # same keys, same bytes
    tokyo_records = recorded(store, Region.TOKYO)
    critical_key = [k for k in tokyo_records if during[1] in k]
    assert len(critical_key) == 1
    assert record_key(intent) not in tokyo_records  # an intent is never in the database

    # Nothing is written twice: a second run writes no batch, in either region.
    writes = store.writes
    after = await run_archive(archive, store, metrics, max_rows=2)
    assert after.backfilled == 0
    assert after.objects_written == {}
    assert store.writes == writes

    # A new event goes to both regions as before, with its record while the window is open.
    late = add_event(archive_db, critical=True)
    await run_archive(archive, store, metrics, max_rows=2)
    assert batches(store, Region.TOKYO) == batches(store, Region.OSAKA)
    assert [k for k in recorded(store, Region.TOKYO) if late in k]

    # The window closes once both regions have been written for the grace.
    assert window(archive_db) == (True, True)
    archive_db.sql(
        "UPDATE audit_archive_cursor SET both_regions_since = now() - interval '16 minutes'"
    )
    await run_archive(archive, store, metrics, max_rows=2)
    assert window(archive_db) == (False, False)
    quiet = add_event(archive_db, critical=True)
    await run_archive(archive, store, metrics, max_rows=2)
    assert not [k for k in recorded(store, Region.TOKYO) if quiet in k]


async def test_a_back_fill_tokyo_refuses_stays_recorded_and_completes_later(
    archive: Database, archive_db: ScratchDatabase
) -> None:
    store = FakeArchiveStore(fail=set(OSAKA_ALONE))
    metrics = ArchiveJobMetrics.create(CollectorRegistry())
    add_event(archive_db, critical=True)
    await run_archive(archive, store, metrics, surviving=Region.OSAKA)
    assert waiting(archive_db) == 1
    # The toggle is off before Tokyo answers: the back-fill fails, the range stays, the lag is
    # measured, and the run fails.
    with pytest.raises(ArchiveIncompleteError):
        await run_archive(archive, store, metrics)
    assert waiting(archive_db) == 1
    store.fail = set()
    report = await run_archive(archive, store, metrics)
    assert (report.backfilled, waiting(archive_db)) == (1, 0)
    assert batches(store, Region.TOKYO) == batches(store, Region.OSAKA)


async def test_a_long_back_fill_leaves_time_for_new_events(
    archive: Database, archive_db: ScratchDatabase
) -> None:
    store = FakeArchiveStore(fail=set(OSAKA_ALONE))
    metrics = ArchiveJobMetrics.create(CollectorRegistry())
    for _ in range(3):
        add_event(archive_db)
    await run_archive(archive, store, metrics, max_rows=1, surviving=Region.OSAKA)
    assert waiting(archive_db) == 3
    store.fail = set()
    new = add_event(archive_db)
    ticks = iter(range(1000))

    def clock() -> float:
        return next(ticks) * 50.0  # each look at the clock is 50 s later

    # The back-fill may take half of the run's 240 s: two ranges here. Then the new event goes to
    # both regions in the same run, so the lag doesn't page while a long back-fill catches up.
    report = await run_archive(archive, store, metrics, max_rows=1, monotonic=clock)
    assert (report.backfilled, waiting(archive_db)) == (2, 1)
    for region in Region:
        ids = {
            json.loads(line)["id"]
            for body in batches(store, region).values()
            for line in gzip.decompress(body).decode().splitlines()
        }
        assert new in ids


async def test_the_records_of_a_range_are_the_apis_keys(
    archive: Database, archive_db: ScratchDatabase
) -> None:
    critical = add_event(archive_db, critical=True)
    add_event(archive_db)
    async with archive.transaction(Scope.system()) as session:
        claimed = await archive_cursor.claim(session, max_rows=10)
        assert claimed is not None
        rows = await archive_cursor.events(session, claimed)
    made = records(rows)
    assert [key.rsplit("/", 1)[-1] for key, _ in made] == [f"{critical}.json"]
    body = json.loads(made[0][1])
    assert body["security_critical"] is True
    assert "source_ip" not in body
    assert "user_agent" not in body


def test_the_grace_covers_an_api_rollout() -> None:
    assert timedelta(seconds=archive_job.GRACE_SECONDS) >= timedelta(minutes=10)
