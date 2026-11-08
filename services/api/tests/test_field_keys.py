"""Field encryption against PostgreSQL (#236, #233; encryption and keys 3.2, 3.3, 7.2): the key
tables and their grants, values sealed by the API, the caller's tenant as the third isolation
layer, and the field key job's backfill, rotation, re-wrap and purge. Real KMS is pending the AWS
run; these use the in-process stand-in, which binds the same encryption context."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import Tenant, client, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.data.data_keys import KeyPurpose
from sft.data.database import Database
from sft.data.migrate import alembic_config
from sft.data.models import Role
from sft.data.rls import grant_sql, lookup_function_sql, lookup_read_sql, tenant_rls_sql
from sft.data.scope import Scope
from sft.runtime.kms import LocalKms
from sft.service import fields
from sft.service.field_keys import FieldKeyJob, Step
from sft.service.fields import FieldDecryptError, FieldKeys, FieldKeysUnavailableError, FieldMetrics
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio


def _module(attribute: str) -> Any:
    # Found by contents, so the combine's renumbering doesn't touch these tests.
    from alembic.script import ScriptDirectory

    scripts = ScriptDirectory.from_config(alembic_config())
    [module] = [s.module for s in scripts.walk_revisions() if hasattr(s.module, attribute)]
    return module


def test_the_field_key_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module = _module("SEALED")
    assert list(module.RLS) == [
        *tenant_rls_sql("tenant_data_keys", grants={"sft_api": "SELECT, INSERT, DELETE"}),
        grant_sql("tenant_data_keys", "sft_api", "UPDATE", columns=["wrapped_key", "retired_at"]),
        grant_sql(
            "dlp_confirmations",
            "sft_api",
            "UPDATE",
            columns=["justification_ct", "data_key_version"],
        ),
        grant_sql(
            "dlp_approval_decisions",
            "sft_api",
            "UPDATE",
            columns=["comment_ct", "data_key_version"],
        ),
    ]
    assert list(module.LOOKUP) == [
        *lookup_read_sql("tenants", ["id"]),
        *lookup_function_sql(
            "field_key_tenants(p_after uuid)",
            returns="TABLE (tenant_id uuid)",
            body="SELECT id FROM public.tenants WHERE p_after IS NULL OR id > p_after "
            "ORDER BY id LIMIT 500",
        ),
    ]


def test_the_dlp_key_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    module = _module("DLP_RLS")
    assert list(module.DLP_RLS) == [
        *tenant_rls_sql(
            "tenant_dlp_keys",
            grants={"sft_api": "SELECT, INSERT, DELETE", "sft_scan": "SELECT, INSERT"},
        ),
        grant_sql("tenant_dlp_keys", "sft_api", "UPDATE", columns=["wrapped_key", "retired_at"]),
        grant_sql(
            "dlp_detectors", "sft_api", "UPDATE", columns=["definition_ct", "dlp_key_version"]
        ),
    ]


def can(db: ScratchDatabase, role: str, table: str, column: str, privilege: str = "SELECT") -> bool:
    [(allowed,)] = db.sql(
        "SELECT has_column_privilege(:role, :table, :column, :privilege)",
        role=role,
        table=table,
        column=column,
        privilege=privilege,
    )
    return bool(allowed)


def test_only_the_api_reads_the_fields_and_the_scan_role_writes_details_it_cant_read(
    migrated_db: ScratchDatabase,
) -> None:
    # Workloads whose role lacks the decrypt grant can't even select the ciphertext (4.2).
    for role in ("sft_scan", "sft_notify", "sft_jobs", "sft_operator", "sft_relay"):
        for table, column in (
            ("files", "display_name_ct"),
            ("transfers", "message_ct"),
            ("upload_requests", "message_ct"),
            ("tenant_data_keys", "wrapped_key"),
        ):
            assert not can(migrated_db, role, table, column), (role, table)
    assert can(migrated_db, "sft_api", "tenant_data_keys", "wrapped_key")
    # #233: the scan worker inserts details and reads and makes DLP keys, never reads details.
    assert can(migrated_db, "sft_scan", "dlp_findings", "detail_ct", "INSERT")
    assert not can(migrated_db, "sft_scan", "dlp_findings", "detail_ct")
    assert can(migrated_db, "sft_scan", "tenant_dlp_keys", "wrapped_key")
    assert can(migrated_db, "sft_scan", "tenant_dlp_keys", "wrapped_key", "INSERT")
    assert not can(migrated_db, "sft_jobs", "dlp_findings", "detail_ct")
    assert can(migrated_db, "sft_api", "dlp_findings", "detail_ct")


# ---- the API seals; the caller's tenant opens ----


@pytest.fixture
async def http(migrated_db: ScratchDatabase) -> AsyncIterator[tuple[httpx.AsyncClient, Tenant]]:
    tenant = seed_tenant(migrated_db)
    caller = session_caller(tenant.id, tenant.member, Role.MEMBER)
    async with client(migrated_db, lambda: caller) as session:
        yield session, tenant


async def test_a_message_is_stored_sealed_and_the_api_answers_with_it(
    migrated_db: ScratchDatabase, http: tuple[httpx.AsyncClient, Tenant]
) -> None:
    session, tenant = http
    response = await session.post(
        "/v1/transfers",
        json={"recipients": [{"email": "partner@example.test"}], "message": "Q3 layoffs plan"},
    )
    assert response.status_code == 201, response.text
    transfer_id = response.json()["id"]
    [(value, version)] = migrated_db.sql(
        "SELECT message_ct, data_key_version FROM transfers WHERE id = :id", id=transfer_id
    )
    assert (value[0], version) == (1, 1)  # type: ignore[index]
    assert b"layoffs" not in value  # type: ignore[operator]
    assert migrated_db.sql(
        "SELECT count(*) FROM tenant_data_keys WHERE tenant_id = :t", t=tenant.id
    ) == [(1,)]
    got = await session.get(f"/v1/transfers/{transfer_id}")
    assert got.json()["message"] == "Q3 layoffs plan"
    # The database refuses to delete a version a row still uses.
    with pytest.raises(Exception, match="tenant_data_key"):
        migrated_db.sql("DELETE FROM tenant_data_keys WHERE tenant_id = :t", t=tenant.id)


async def test_a_row_of_another_tenant_fails_to_open_and_counts(
    migrated_db: ScratchDatabase, api_db: Database, field_keys: FieldKeys
) -> None:
    mine, theirs = seed_tenant(migrated_db), seed_tenant(migrated_db)
    row = uuid.uuid4()
    async with api_db.transaction(Scope.tenant(theirs.id)) as session:
        keys = await fields.tenant_keys(session, theirs.id, write=True)
        value = keys.seal(fields.FILE_NAME, row, "their file")
    async with api_db.transaction(Scope.tenant(mine.id)) as session:
        keys = await fields.tenant_keys(session, mine.id, write=True)
        with pytest.raises(FieldDecryptError):
            keys.open(fields.FILE_NAME, row, value)
        # And a transaction can't borrow another tenant's keys.
        with pytest.raises(ValueError, match="own tenant"):
            await fields.tenant_keys(session, theirs.id)
    assert field_keys.metrics.scope_mismatches.labels("field-dek")._value.get() == 1


async def test_the_scan_workers_keys_never_unwrap_a_field_data_key(
    migrated_db: ScratchDatabase, api_db: Database
) -> None:
    tenant = seed_tenant(migrated_db)
    scan = FieldKeys(
        LocalKms(purposes=frozenset({"dlp-dek"})),
        FieldMetrics.create(CollectorRegistry()),
        purposes=frozenset({KeyPurpose.DLP}),
    )
    async with api_db.transaction(Scope.tenant(tenant.id)) as session:
        with pytest.raises(FieldKeysUnavailableError):
            await scan.tenant(session, tenant.id, KeyPurpose.FIELD)
        dlp = await scan.tenant(session, tenant.id, KeyPurpose.DLP, write=True)
        assert dlp.live == 1


# ---- the field key job ----


def dump(db: ScratchDatabase, tenant_id: uuid.UUID) -> str:
    """Every row of the tenant's tables with sealed columns, as text: what a dump would show."""
    rows = db.sql(
        "SELECT to_jsonb(f)::text FROM files f WHERE tenant_id = :t UNION ALL "
        "SELECT to_jsonb(x)::text FROM transfers x WHERE tenant_id = :t UNION ALL "
        "SELECT to_jsonb(d)::text FROM dlp_detectors d WHERE tenant_id = :t",
        t=tenant_id,
    )
    hexed = " ".join(str(r) for (r,) in rows)
    # bytea comes out as \x… hex: decode what looks like it, so plain text would show.
    found = []
    for part in hexed.split("\\\\x")[1:]:
        digits = part.split('"')[0]
        try:
            found.append(bytes.fromhex(digits).decode("utf-8", "replace"))
        except ValueError:
            continue
    return hexed + " ".join(found)


def job(database: Database, keys: FieldKeys, **options: Any) -> FieldKeyJob:
    return FieldKeyJob(database, keys, now=lambda: datetime.now(UTC), batch_size=2, **options)


async def test_the_backfill_reseals_plain_rows_and_the_api_answers_unchanged(
    migrated_db: ScratchDatabase,
    api_db: Database,
    field_keys: FieldKeys,
    http: tuple[httpx.AsyncClient, Tenant],
) -> None:
    session, tenant = http
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.member)
    migrated_db.sql(
        "UPDATE transfers SET message_ct = '\\x00' || convert_to('Merger memo', 'UTF8') "
        "WHERE id = :id",
        id=transfer_id,
    )
    names = [f"board-{n}.pdf" for n in range(5)]  # more than one batch of 2
    for name in names:
        file_id = seed_file(migrated_db, tenant.id, transfer_id, state="uploading")
        migrated_db.sql(
            "UPDATE files SET display_name_ct = '\\x00' || convert_to(:n, 'UTF8') WHERE id = :id",
            n=name,
            id=file_id,
        )
    before = (await session.get(f"/v1/transfers/{transfer_id}")).json()
    assert "Merger memo" in dump(migrated_db, tenant.id)

    report = await job(api_db, field_keys).run(Step.BACKFILL)
    assert report.resealed >= 6
    after = (await session.get(f"/v1/transfers/{transfer_id}")).json()
    assert after == before  # the API answers unchanged
    text = dump(migrated_db, tenant.id)
    for plain in ("Merger memo", *names):
        assert plain not in text  # a dump shows no name or message in plain text
    assert migrated_db.sql(
        "SELECT count(*) FROM files WHERE tenant_id = :t AND get_byte(display_name_ct, 0) = 0",
        t=tenant.id,
    ) == [(0,)]
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE tenant_id = :t AND action = 'fields.resealed' "
        "ORDER BY occurred_at LIMIT 1",
        t=tenant.id,
    )
    assert details["system_actor"] == "field_key_job"
    assert "Merger" not in json.dumps(details)
    # Running it again changes nothing.
    assert (await job(api_db, field_keys).run(Step.BACKFILL)).resealed == 0


async def test_rotate_then_backfill_then_purge_moves_every_row_to_the_new_version(
    migrated_db: ScratchDatabase,
    api_db: Database,
    field_keys: FieldKeys,
    http: tuple[httpx.AsyncClient, Tenant],
) -> None:
    session, tenant = http
    response = await session.post(
        "/v1/transfers",
        json={"recipients": [{"email": "partner@example.test"}], "message": "Old key"},
    )
    transfer_id = response.json()["id"]

    def versions() -> list[tuple[object, ...]]:
        return migrated_db.sql(
            "SELECT key_version, retired_at IS NOT NULL FROM tenant_data_keys "
            "WHERE tenant_id = :t ORDER BY 1",
            t=tenant.id,
        )

    assert (await job(api_db, field_keys).run(Step.ROTATE)).rotated == 0  # not due yet
    rotated = await job(api_db, field_keys, max_age=timedelta(0)).run(Step.ROTATE)
    assert rotated.rotated >= 1
    assert versions() == [(1, True), (2, False)]
    # The retired version still opens; a purge keeps it while a row uses it.
    assert (await session.get(f"/v1/transfers/{transfer_id}")).json()["message"] == "Old key"
    await job(api_db, field_keys).run(Step.PURGE)
    assert versions() == [(1, True), (2, False)]

    await job(api_db, field_keys).run(Step.BACKFILL)  # the re-encryption
    assert migrated_db.sql(
        "SELECT data_key_version FROM transfers WHERE id = :id", id=transfer_id
    ) == [(2,)]
    await job(api_db, field_keys).run(Step.PURGE)
    assert versions() == [(2, False)]

    [(wrapped,)] = migrated_db.sql(
        "SELECT wrapped_key FROM tenant_data_keys WHERE tenant_id = :t", t=tenant.id
    )
    assert (await job(api_db, field_keys).run(Step.REWRAP)).rewrapped >= 1
    [(rewrapped,)] = migrated_db.sql(
        "SELECT wrapped_key FROM tenant_data_keys WHERE tenant_id = :t", t=tenant.id
    )
    assert rewrapped != wrapped
    field_keys.forget()  # the next read unwraps the re-wrapped key
    assert (await session.get(f"/v1/transfers/{transfer_id}")).json()["message"] == "Old key"
    actions = {
        a
        for (a,) in migrated_db.sql(
            "SELECT action FROM audit_events WHERE tenant_id = :t", t=tenant.id
        )
    }
    assert {"data_key.rotated", "data_key.deleted", "data_key.rewrapped"} <= actions


async def test_the_job_finds_every_tenant_through_the_lookup(
    migrated_db: ScratchDatabase, api_db: Database, field_keys: FieldKeys
) -> None:
    made = {seed_tenant(migrated_db).id for _ in range(3)}
    found = {t async for t in job(api_db, field_keys).tenants()}
    assert made <= found


def test_the_entry_point_refuses_an_unknown_step(capsys: pytest.CaptureFixture[str]) -> None:
    from sft.workers.field_keys import main

    assert main(["shred"]) == 2
    assert "backfill|rotate|rewrap|purge" in capsys.readouterr().err
