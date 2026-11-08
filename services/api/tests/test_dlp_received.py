"""Received files and the DLP block rule (#221; FR-51, FR-52, FR-12): the scan worker decides on
a received file with the tenant's rules for received files, and a block keeps it from the member
while both sides are told, the uploader without any finding.

Through the routes and the scan worker as `sft_scan`, with the fake inspector running the real
detectors on the file (scan_fixtures.py `detect`), and the notification worker as `sft_notify`.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any

import pytest
from prometheus_client import CollectorRegistry

from link_fixtures import World, w
from object_fixtures import FakeObjects
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects
from sft.api.caller import get_caller
from sft.data.database import Database
from sft.data.models import Role
from sft.data.outbox import Queue
from sft.data.roles import SCAN
from sft.service.uploads import UploadPolicy
from sft.workers.scan import Engines, Leases, ScanMetrics, SmallScanConsumer
from test_received_files import (
    SIZE,
    Rig,
    file_row,
    owner_email,
    send_notices,
    session_files,
    upload,
    uploader,
)

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests

LABELLED = "社外秘 quarterly figures\n".encode()
"""A confidentiality label, which `confidentiality_label` finds (at low confidence here)."""


def text_file(head: bytes) -> bytes:
    return head + b"plain words\n" * ((SIZE - len(head)) // 12) + b"\n" * ((SIZE - len(head)) % 12)


@pytest.fixture
async def rig(w: World) -> AsyncIterator[Rig]:
    """test_received_files.py's rig, with an inspector that runs the real detectors."""
    objects = FakeObjects()
    w.app.state.objects = objects
    w.app.state.upload_policy = UploadPolicy()
    clamd, inspector = FakeClamd(), FakeInspector(mode="detect")
    await clamd.start()
    await inspector.start()
    scanned = FakeScanObjects()
    database = Database.connect(w.db.url(SCAN), pool_size=2)
    consumer = SmallScanConsumer(
        database,
        scanned,
        Engines("127.0.0.1", clamd.port, "127.0.0.1", inspector.port, connect_timeout=2),
        ScanMetrics.create(CollectorRegistry()),
        Leases(None, Queue.SCAN_SMALL, 4, time.time),
    )
    try:
        yield Rig(w, objects, scanned, consumer, clamd)
    finally:
        w.app.dependency_overrides.pop(get_caller, None)
        await clamd.stop()
        await inspector.stop()
        await database.dispose()


async def as_admin(rig: Rig, method: str, path: str, body: object = None) -> Any:
    admin = rig.member(rig.tenant.admin, role=Role.ADMIN)
    return await rig.as_member(admin, method, path, json=body)


async def received_rule(rig: Rig, action: str) -> None:
    made = await as_admin(
        rig,
        "POST",
        "/v1/dlp/rules",
        {
            "name": "Labelled files from outside",
            "direction": "received",
            "condition": "content",
            "detectors": ["confidentiality_label"],
            "min_confidence": "low",
            "action": action,
        },
    )
    assert made.status_code == 201, made.text


def decisions(rig: Rig, file_id: object) -> list[tuple[object, ...]]:
    return rig.w.db.sql(
        "SELECT outcome, mode, enforced FROM dlp_decisions WHERE file_id = :id", id=file_id
    )


async def test_a_blocked_received_file_never_reaches_the_member_and_both_sides_are_told(
    rig: Rig,
) -> None:
    await received_rule(rig, "block")
    up = await uploader(rig)
    data = text_file(LABELLED)
    file_id = await upload(rig, up, "figures.txt", data)
    await rig.scan(file_id, data)

    # Recorded clean, then blocked by the rule: the tag the API's read condition refuses.
    assert file_row(rig, file_id)["state"] == "clean"
    [(blocked,)] = rig.w.db.sql("SELECT dlp_blocked FROM files WHERE id = :id", id=file_id)
    assert blocked is True
    assert decisions(rig, file_id) == [("block", "enforce", True)]
    key = f"tenants/{rig.tenant.id}/files/{file_id}"
    assert rig.scanned.tags[(key, "version-1")]["scan"] == "dlp_blocked"
    [(details,)] = rig.w.db.sql(
        "SELECT details FROM audit_events WHERE action = 'dlp.decided' AND target_id = :id",
        id=file_id,
    )
    assert (details["outcome"], details["dlp_blocked"]) == ("block", True)  # type: ignore[index]

    # The member: listed, not shareable, no grant.
    owner = rig.member()
    [item] = (
        await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}/files")
    ).json()["items"]
    assert (item["shareable"], item["inspection"]["dlp_blocked"]) == (False, True)
    refused = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "file_not_shareable"
    assert rig.w.db.sql("SELECT id FROM download_grants WHERE file_id = :id", id=file_id) == []

    # Both sides are told; the uploader learns only that the company's policy blocked it.
    await send_notices(rig)
    assert [e.email_type for e in rig.w.sent.to(owner_email(rig))] == ["files_blocked_member"]
    [told] = [e for e in rig.w.sent.to(up.address) if e.email_type.startswith("files_")]
    assert told.email_type == "files_blocked_uploader"
    words = (told.subject + told.text + told.html).lower()
    for detail in ("社外秘", "confidential", "label", "figures", "finding", "rule", "detector"):
        assert detail not in words, detail
    [listed] = (await session_files(up)).json()["items"]
    assert (listed["state"], listed["blocked"]) == ("clean", True)
    assert "dlp" not in " ".join(listed)


async def test_allow_and_record_and_monitor_mode_never_block_a_received_file(rig: Rig) -> None:
    await received_rule(rig, "allow_and_record")
    up = await uploader(rig)
    data = text_file(LABELLED)
    recorded = await upload(rig, up, "a.txt", data)
    await rig.scan(recorded, data)
    assert decisions(rig, recorded) == [("allow_and_record", "enforce", True)]

    rules = await as_admin(rig, "GET", "/v1/dlp/rules")
    [rule] = [r for r in rules.json()["items"] if r["direction"] == "received"]
    changed = await as_admin(rig, "PATCH", f"/v1/dlp/rules/{rule['id']}", {"action": "block"})
    assert changed.status_code == 200, changed.text
    moved = await as_admin(rig, "PATCH", "/v1/dlp/policy", {"mode": "monitor"})
    assert moved.status_code == 200, moved.text
    watched = await upload(rig, up, "b.txt", data)
    await rig.scan(watched, data)
    assert decisions(rig, watched) == [("block", "monitor", False)]

    owner = rig.member()
    items = (
        await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}/files")
    ).json()["items"]
    assert {(i["id"], i["shareable"], i["inspection"]["dlp_blocked"]) for i in items} == {
        (str(recorded), True, False),
        (str(watched), True, False),
    }
    granted = await rig.as_member(owner, "POST", f"/v1/files/{watched}/downloads", json={})
    assert granted.status_code == 200, granted.text


async def test_a_file_without_a_rule_for_received_files_has_no_decision(rig: Rig) -> None:
    up = await uploader(rig)
    data = text_file(LABELLED)
    file_id = await upload(rig, up, "c.txt", data)
    await rig.scan(file_id, data)
    assert decisions(rig, file_id) == []
    key = f"tenants/{rig.tenant.id}/files/{file_id}"
    assert rig.scanned.tags[(key, "version-1")]["scan"] == "clean"
