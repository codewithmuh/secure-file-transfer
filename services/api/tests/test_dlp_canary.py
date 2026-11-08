"""The NFR-26 canary (#233, DLP-8): synthetic identifiers through every DLP flow, failing if a value
appears in the database, the logs, the traces, the metrics, a queue message, an audit record or an
email.

One transfer carries a spreadsheet of synthetic My Numbers and payment card numbers, and a term of
the tenant's own keyword list, to a new domain. It goes through the tenant's detector (sealed with
the DLP data key), the scan worker with the real detectors (`detect`, in process) and only the
`dlp-dek` key, the decision and its notices, the owner's reads of the findings with their hints
and masked previews (audited), an admin's read (counts only), the sender's confirmation with a
justification, and the notification worker's emails. Then every store is searched for every value.
Only a masked preview may hold part of one, and only in an API response to the owner.
"""

from __future__ import annotations

import json
import random
import re
from collections.abc import Callable

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry, generate_latest

from dlp_corpus.generate import card_number, my_number
from dlp_fixtures import xlsx
from member_fixtures import client, seed_tenant, session_caller
from notify_fixtures import Sent, drain, notifier
from pg import ScratchDatabase
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects
from sft.core.ids import uuid7
from sft.data.database import Database
from sft.data.models import Role
from sft.data.outbox import OutboxMessage, Queue
from sft.data.roles import NOTIFY, SCAN
from sft.runtime.kms import open_field_keys
from sft.service import fields
from sft.service.fields import KeyPurpose
from sft.workers.consumer import Delivery
from sft.workers.consumer import Outcome as Processed
from sft.workers.scan import Engines, Leases, ScanMetrics, SmallScanConsumer
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

NEW = "kenji@canary-partner.example"
TERM = "CANARY計画"


def database_text(db: ScratchDatabase) -> str:
    """Every row of every table, as text, with each bytea decoded too: what a dump shows."""
    tables = [
        str(t)
        for (t,) in db.sql(
            "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
            "AND relkind IN ('r', 'p') AND NOT relispartition"
        )
    ]
    rows = []
    for table in tables:
        rows += [str(r) for (r,) in db.sql(f'SELECT to_jsonb(x)::text FROM "{table}" x')]  # noqa: S608
    text = "\n".join(rows)
    decoded = []
    for digits in re.findall(r"\\\\x([0-9a-f]+)", text):
        decoded.append(bytes.fromhex(digits).decode("utf-8", "replace"))
    return text + "\n" + "\n".join(decoded)


async def test_no_synthetic_value_leaves_the_dlp_flows(
    migrated_db: ScratchDatabase,
    json_logs: Callable[[], list[dict[str, object]]],
    spans: InMemorySpanExporter,
) -> None:
    rng = random.Random(233)  # noqa: S311 - synthetic test data, not a secret
    numbers = [my_number(rng) for _ in range(3)]
    cards = [card_number(rng, "Visa", length=16), card_number(rng, "Mastercard")]
    values = [*numbers, *cards]
    sheet = xlsx(
        {
            "社員": [["氏名", "マイナンバー", "カード", "件名"]]
            + [["山田", n, c, TERM] for n, c in zip(numbers, [*cards, cards[0]], strict=True)]
        }
    )
    db = migrated_db
    tenant = seed_tenant(db)
    current = [session_caller(tenant.id, tenant.admin, Role.ADMIN)]
    async with client(db, lambda: current[0]) as http:
        # The tenant's own keyword list: its definition is sealed with the DLP data key.
        made = await http.post(
            "/v1/dlp/detectors", json={"name": "Canary", "kind": "keywords", "keywords": [TERM]}
        )
        assert made.status_code == 201, made.text

        transfer_id, _ = seed_transfer(db, tenant.id, tenant.member, recipients=(NEW,))
        file_id = seed_file(db, tenant.id, transfer_id, state="scanning", size=len(sheet))
        current[0] = session_caller(tenant.id, tenant.member, Role.MEMBER)
        sent_now = await http.post(f"/v1/transfers/{transfer_id}/send")
        assert sent_now.status_code == 200, sent_now.text

        # The scan worker, with the dlp-dek key only, as its role has (encryption and keys 3.3).
        registry = CollectorRegistry()
        scan_keys = open_field_keys(
            key_id="local",
            region="ap-northeast-1",
            registry=registry,
            purposes=frozenset({KeyPurpose.DLP}),
        )
        api_keys = fields.install(scan_keys)
        objects, clamd, inspector = FakeScanObjects(), FakeClamd(), FakeInspector(mode="detect")
        objects.put(f"tenants/{tenant.id}/files/{file_id}", "version-1", sheet)
        await clamd.start()
        await inspector.start()
        scan_db = Database.connect(db.url(SCAN), pool_size=2)
        try:
            engines = Engines(
                "127.0.0.1", clamd.port, "127.0.0.1", inspector.port, connect_timeout=2
            )
            consumer = SmallScanConsumer(
                scan_db,
                objects,
                engines,
                ScanMetrics.create(registry),
                Leases(None, Queue.SCAN_SMALL, 4, lambda: 0.0),
            )
            message = OutboxMessage(uuid7(), "file.scan", tenant.id, {"file_id": file_id})
            assert await consumer.process(Delivery(message)) is Processed.PROCESSED
        finally:
            fields.install(api_keys)
            await scan_keys.close()
            await scan_db.dispose()
            await clamd.stop()
            await inspector.stop()
        [(details,)] = db.sql(
            "SELECT count(*) FROM dlp_findings WHERE file_id = :id AND detail_ct IS NOT NULL",
            id=file_id,
        )
        assert details >= 3  # My Numbers, cards and the keyword, each with sealed details

        # The owner sees hints and masked previews; never a value.
        shown = await http.get(f"/v1/transfers/{transfer_id}/dlp")
        assert shown.status_code == 200, shown.text
        inspection = await http.get(f"/v1/files/{file_id}/inspection")
        owner_view = shown.text + inspection.text
        found = {f["detector"]: f for f in inspection.json()["findings"]}
        assert found["jp_my_number"]["details_visible"] is True
        assert found["jp_my_number"]["locations"]
        assert found["payment_card"]["previews"]
        # An admin acting on another member's transfer sees counts only (FR-53).
        current[0] = session_caller(tenant.id, tenant.admin, Role.ADMIN)
        admin_view = (await http.get(f"/v1/files/{file_id}/inspection")).json()
        assert {f["details_visible"] for f in admin_view["findings"]} == {False}
        assert all("previews" not in f for f in admin_view["findings"])

        current[0] = session_caller(tenant.id, tenant.member, Role.MEMBER)
        decision = shown.json()["decision"]
        confirmed = await http.post(
            f"/v1/transfers/{transfer_id}/confirm",
            json={"decision_id": decision["id"], "justification": "Canary audit run"},
        )
        assert confirmed.status_code == 200, confirmed.text

    sent = Sent()
    notify_db = Database.connect(db.url(NOTIFY), pool_size=1)
    try:
        await drain(notifier(notify_db, sent), db, tenant.id)
    finally:
        await notify_db.dispose()
    assert sent.emails, "the decision's notices and the link email were sent"

    reads = db.sql(
        "SELECT details FROM audit_events WHERE tenant_id = :t "
        "AND action = 'dlp_findings.details_read'",
        t=tenant.id,
    )
    assert len(reads) == 2  # the owner's two reads with details; the admin's had none

    stores = {
        "database (rows, audit records, queue messages)": database_text(db),
        "logs": json.dumps(json_logs(), ensure_ascii=False, default=str),
        "traces": json.dumps(
            [dict(s.attributes or {}) | {"name": s.name} for s in spans.get_finished_spans()],
            ensure_ascii=False,
            default=str,
        ),
        "metrics": generate_latest(registry).decode(),
        "emails": json.dumps(
            [[e.subject, e.text, e.html] for e in sent.emails], ensure_ascii=False, default=str
        ),
    }
    for store, text in stores.items():
        for value in values:
            assert value not in text, f"a synthetic identifier reached the {store}"
        assert TERM not in text, f"the tenant's keyword reached the {store}"
    for value in values:
        assert value not in owner_view
        assert value not in json.dumps(admin_view)
