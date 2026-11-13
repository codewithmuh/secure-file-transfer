"""The M5 journey (#223; delivery plan 3, M5's exit criterion): one test, steps 1 to 9.

It runs against the local stack, after `make up`, `make seed` and the M2 journey, with `make e2e`
(docs/local-development.md 7), and in CI's Local stack job. Like the M2 journey
(`test_journey.py`, whose browsers and helpers it reuses), it talks to the service only through
its public HTTP API, and to the stand-ins only through their own APIs: Keycloak's login form,
Mailpit's API, S3's API, the lifecycle job commands and the clock's test hook. So once M4's dev
environment exists, the same test can point at dev with the probe mailbox (the M4 follow-up of
#223). The one local shortcut is the M2 journey's: part URLs name `localhost:9090`.

What it proves, in the order of M5's exit criterion:

1. **The upload-request journey**: the member asks an outsider for files; the uploader verifies
   with Mailpit's code and uploads two files in parts, one resumed, one EICAR; the member sees one
   available and one blocked and downloads the clean one; both sides get the blocked notice; the
   clock passes the retention and the deletion job removes the file.
2. **Audit search and export**: the admin finds transfer 2's approval by the approver; an API key
   exports the log as CSV, which holds every decision and the upload-request events.
3. **API keys**: a key with `transfers:write` and `audit:read` sends a transfer with no findings.
   The authorization matrix (#215) runs in the same CI run.
4. **Three transfers with sensitive data**: warned and confirmed, approved and sent, blocked and
   held, each asserted on its state, its audit records and Mailpit (who was emailed, who wasn't).

The seed (local/seed.py) trusts `partner.example` and makes the admin and `dev.approver` DLP
approvers, so a rule that requires one approval can be made, and the member's request has an
approver who isn't the sender. The rules the admin adds are deleted at the end, so the browser
flows that run next see the default policy. Every step is a `step(...)` block, so a failure names
its step. It is skipped unless SFT_E2E=1.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import random
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest

from dlp_corpus.generate import my_number, private_key_lines
from dlp_fixtures import xlsx
from scan_fixtures import eicar
from test_journey import (
    MIB,
    Member,
    Recipient,
    cfg,
    code_for,
    copies_left,
    link_token,
    mailpit,
    messages_to,
    run_job,
    s3,
    step,
    text_of,
    text_of_words,
    wait_for,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("SFT_E2E") != "1", reason="the journey runs with `make e2e`"),
]

USERS = {
    "member": ("dev.member@example.com", "local-only-member-password"),
    "admin": ("dev.admin@example.com", "local-only-admin-password"),
    "approver": ("dev.approver@example.com", "local-only-approver-password"),
}
"""The seed's users (docs/local-development.md 3); E2E_<ROLE>_EMAIL and _PASSWORD replace them."""

TRUSTED = "partner.example"
"""The seed's trusted domain."""

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
# The notices of a request's files go out 5 minutes after the first file settles (#213), so the
# test waits for them last, after the transfers, and allows them more than the usual wait.
NOTICE_SECONDS = 600


def person(http: httpx.Client, role: str) -> Member:
    email, password = USERS[role]
    signed_in = Member(http)
    signed_in.sign_in(
        os.environ.get(f"E2E_{role.upper()}_EMAIL", email),
        os.environ.get(f"E2E_{role.upper()}_PASSWORD", password),
    )
    return signed_in


def address(kind: str, domain: str = TRUSTED) -> str:
    return f"m5-{kind}-{uuid.uuid4().hex[:10]}@{domain}"


def message_ids(inbox: httpx.Client, to: str) -> set[str]:
    return {m["ID"] for m in messages_to(inbox, to)}


def new_texts(inbox: httpx.Client, to: str, before: set[str]) -> list[str]:
    """The text of every message to `to` that arrived after `before` was taken."""
    return [text_of(inbox, m["ID"]) for m in messages_to(inbox, to) if m["ID"] not in before]


def wait_for_mail(
    inbox: httpx.Client,
    to: str,
    before: set[str],
    contains: str,
    seconds: float | None = None,
) -> str:
    def probe() -> str | None:
        # Plain-text emails wrap their lines, so the words are compared with the breaks undone.
        return next(
            (t for t in new_texts(inbox, to, before) if contains in " ".join(t.split())), None
        )

    return wait_for(f"an email to {to} with {contains!r}", probe, seconds)


def api_key_client(secret: str) -> httpx.Client:
    return httpx.Client(
        base_url=cfg["API_URL"], timeout=60, headers={"authorization": f"Bearer {secret}"}
    )


def put_parts(
    caller: Member | Recipient | httpx.Client,
    path: str,
    data: bytes,
    part_size: int,
    numbers: list[int],
) -> None:
    """Ask for the parts' URLs at `path` and PUT each part straight to the S3 stand-in."""
    if isinstance(caller, httpx.Client):
        urls = caller.post(path, json={"part_numbers": numbers})
    else:
        urls = caller.request("POST", path, json={"part_numbers": numbers})
    assert urls.status_code == 200, urls.text
    for part in urls.json()["parts"]:
        n = part["part_number"]
        body = data[(n - 1) * part_size : n * part_size]
        url = part["url"].replace(cfg["S3_PART_HOST"], cfg["S3_ENDPOINT_URL"], 1)
        put = httpx.put(url, content=body, headers=part.get("headers") or {}, timeout=60)
        assert put.status_code == 200, put.text


def upload_as_uploader(
    uploader: Recipient, name: str, data: bytes, content_type: str, *, interrupt: bool
) -> str:
    """The uploader's `/u` page, in calls: declare, upload in parts and complete one file. With
    `interrupt`, the last part goes only after `listSessionUploadedParts` shows what arrived."""
    declared = uploader.request(
        "POST",
        "/v1/session/files",
        json={"display_name": name, "size": len(data), "content_type": content_type},
    )
    assert declared.status_code == 201, declared.text
    file = declared.json()
    part_size, part_count = file["upload"]["part_size"], file["upload"]["part_count"]
    numbers = list(range(1, part_count + 1))
    first = numbers[:-1] if interrupt else numbers
    put_parts(uploader, f"/v1/session/files/{file['id']}/parts", data, part_size, first)
    if interrupt:
        arrived = uploader.request("GET", f"/v1/session/files/{file['id']}/parts")
        assert arrived.status_code == 200, arrived.text
        got = sorted(p["part_number"] for p in arrived.json()["parts"])
        assert got == first, got
        put_parts(uploader, f"/v1/session/files/{file['id']}/parts", data, part_size, [part_count])
    completed = uploader.request("POST", f"/v1/session/files/{file['id']}/complete")
    assert completed.status_code == 200, completed.text
    return str(file["id"])


def upload_to_transfer(
    caller: Member | httpx.Client, transfer_id: str, name: str, data: bytes, content_type: str
) -> str:
    """A member's or an API key's file on a draft transfer, uploaded in parts and completed. Both
    take `request(method, path, ...)`: the member's adds its cookie and CSRF token."""
    call = caller.request
    declared = call(
        "POST",
        f"/v1/transfers/{transfer_id}/files",
        json={"display_name": name, "size": len(data), "content_type": content_type},
    )
    assert declared.status_code == 201, declared.text
    file = declared.json()
    plan = file["upload"]
    numbers = list(range(1, plan["part_count"] + 1))
    put_parts(caller, f"/v1/files/{file['id']}/parts", data, plan["part_size"], numbers)
    completed = call("POST", f"/v1/files/{file['id']}/complete")
    assert completed.status_code == 200, completed.text
    return str(file["id"])


def new_transfer(
    member: Member, recipient: str, name: str, data: bytes, content_type: str
) -> tuple[str, str]:
    """A transfer of one file to one recipient, sent: its ID and its file's."""
    created = member.request(
        "POST", "/v1/transfers", json={"recipients": [{"email": recipient}], "expires_in": "P2D"}
    )
    assert created.status_code == 201, created.text
    transfer_id = str(created.json()["id"])
    file_id = upload_to_transfer(member, transfer_id, name, data, content_type)
    sent = member.request("POST", f"/v1/transfers/{transfer_id}/send")
    assert sent.status_code == 200, sent.text
    return transfer_id, file_id


def settled(member: Member, transfer_id: str, *waiting_in: str) -> dict[str, Any]:
    """The transfer's DLP view once the scan and the decision moved it out of `scanning`."""

    def probe() -> dict[str, Any] | None:
        dlp = member.request("GET", f"/v1/transfers/{transfer_id}/dlp")
        assert dlp.status_code == 200, dlp.text
        view: dict[str, Any] = dlp.json()
        return view if view["state"] not in ("draft", "submitted", *waiting_in) else None

    return wait_for(f"transfer {transfer_id}'s DLP decision", probe)


def state_of(caller: Member, transfer_id: str) -> str:
    response = caller.request("GET", f"/v1/transfers/{transfer_id}")
    assert response.status_code == 200, response.text
    return str(response.json()["state"])


def rule_names(view: dict[str, Any]) -> set[str]:
    return {r["name"] for r in view["decision"]["matched_rules"]}


def search(admin: Member, **filter_: Any) -> list[dict[str, Any]]:
    """Every event the admin's audit search finds for the filter, following the cursor."""
    events: list[dict[str, Any]] = []
    cursor = None
    while True:
        body: dict[str, Any] = {"filter": filter_, "limit": 100}
        if cursor:
            body["cursor"] = cursor
        found = admin.request("POST", "/v1/audit/events/search", json=body)
        assert found.status_code == 200, found.text
        page = found.json()
        events += page["items"]
        cursor = page["next_cursor"]
        if not cursor:
            return events


def add_rule(admin: Member, body: dict[str, Any]) -> str:
    created = admin.request(
        "POST", "/v1/dlp/rules", json={"direction": "sent", "condition": "content", **body}
    )
    assert created.status_code == 201, created.text
    return str(created.json()["id"])


def private_key_text(rng: random.Random) -> str:
    """A synthetic private key in a note, built when the test runs: never a key in the repo."""
    lines, _ = private_key_lines(rng, "")
    return "Deploy notes\n" + "\n".join(lines) + "\n" + text_of_words(rng, 2048).decode()


def test_the_m5_journey() -> None:
    started = datetime.now(UTC)
    rng = random.Random(223)  # noqa: S311 - test data, not a secret
    http = httpx.Client(base_url=cfg["API_URL"], timeout=60)
    inbox = mailpit()
    storage = s3()
    member, admin, approver = (person(http, role) for role in ("member", "admin", "approver"))
    tenant_id = member.me["tenant"]["id"]
    assert member.me["user"]["id"] != approver.me["user"]["id"]
    secrets_seen: list[str] = []
    rules: list[str] = []

    try:
        with step(1, "the admin adds the M5 rules: approval for untrusted, block for keys"):
            rules.append(
                add_rule(
                    admin,
                    {
                        "name": f"M5 My Numbers to untrusted {uuid.uuid4().hex[:6]}",
                        "detectors": ["jp_my_number"],
                        "min_confidence": "high",
                        "recipient_scope": "untrusted",
                        "action": "require_approval",
                    },
                )
            )
            rules.append(
                add_rule(
                    admin,
                    {
                        "name": f"M5 Credentials and private keys {uuid.uuid4().hex[:6]}",
                        "detectors": ["cloud_credential", "private_key"],
                        "min_confidence": "medium",
                        "action": "block",
                    },
                )
            )
            names = {
                rule_id: admin.request("GET", f"/v1/dlp/rules/{rule_id}").json()["name"]
                for rule_id in rules
            }
            approval_rule, block_rule = (names[rule_id] for rule_id in rules)

        uploader_address = address("uploader")
        clean_name = f"delivery-{uuid.uuid4().hex[:6]}.txt"
        clean = text_of_words(rng, 6 * MIB)  # two parts: one resumed
        with step(2, "an upload request: the uploader verifies and uploads, one file EICAR"):
            created = member.request(
                "POST",
                "/v1/upload-requests",
                json={
                    "uploader_email": uploader_address,
                    "locale": "en",
                    "message": "The signed delivery notes, please.",
                },
            )
            assert created.status_code == 201, created.text
            request_id = created.json()["id"]
            member_mail = message_ids(inbox, member.me["user"]["email"])
            uploader = Recipient(http)
            token = upload_link_token(inbox, uploader_address)
            secrets_seen.append(token)
            resolved = uploader.request("POST", "/v1/links/resolve", json={"token": token})
            assert resolved.status_code == 200, resolved.text
            assert resolved.json()["kind"] == "upload_request", resolved.text
            assert resolved.json()["access_state"] == "verification_required"
            asked = uploader.request("POST", "/v1/links/codes", json={"token": token})
            assert asked.status_code == 202, asked.text
            code = code_for(inbox, uploader_address, 0)
            secrets_seen.append(code)
            session = uploader.request(
                "POST", "/v1/links/sessions", json={"token": token, "code": code}
            )
            assert session.status_code == 201, session.text
            uploader.session = session.json()
            assert uploader.session["kind"] == "upload_request"
            clean_id = upload_as_uploader(uploader, clean_name, clean, "text/plain", interrupt=True)
            infected_id = upload_as_uploader(
                uploader,
                f"setup-{uuid.uuid4().hex[:6]}.exe",
                eicar(),
                "text/plain",
                interrupt=False,
            )

        with step(3, "the member sees one file available, one blocked, and downloads the clean"):

            def both_scanned() -> dict[str, dict[str, Any]] | None:
                listed = member.request("GET", f"/v1/upload-requests/{request_id}/files")
                assert listed.status_code == 200, listed.text
                files = {f["id"]: f for f in listed.json()["items"]}
                done = {"clean", "infected", "unscannable", "scan_failed", "rejected"}
                return files if all(files[i]["state"] in done for i in files) else None

            files = wait_for("the uploaded files to be scanned", both_scanned)
            assert set(files) == {clean_id, infected_id}, files
            assert (files[clean_id]["state"], files[clean_id]["shareable"]) == ("clean", True)
            assert (files[infected_id]["state"], files[infected_id]["shareable"]) == (
                "infected",
                False,
            )
            retention_until = datetime.fromisoformat(files[clean_id]["retention_until"])
            assert retention_until > datetime.now(UTC) + timedelta(days=1)
            grant = member.request("POST", f"/v1/files/{clean_id}/downloads", json={})
            assert grant.status_code == 200, grant.text
            got = member.request("GET", grant.json()["url"])
            assert got.status_code == 200, got.text
            assert hashlib.sha256(got.content).hexdigest() == hashlib.sha256(clean).hexdigest()
            refused = member.request("POST", f"/v1/files/{infected_id}/downloads", json={})
            assert (refused.status_code, refused.json()["code"]) == (409, "file_not_shareable")

        staff = xlsx(
            {"Staff": [["Name", "個人番号"], ["Yamada Taro", f"個人番号: {my_number(rng)}"]]}
        )
        sheet = f"staff-{uuid.uuid4().hex[:6]}.xlsx"
        approver_mail = message_ids(inbox, approver.me["user"]["email"])

        with step(4, "transfer 1, trusted: warned, the member confirms, the recipient downloads"):
            first = address("warned")
            transfer_1, sheet_1 = new_transfer(member, first, sheet, staff, XLSX)
            view = settled(member, transfer_1)
            assert view["state"] == "awaiting_confirmation", view["state"]
            decision = view["decision"]
            assert decision["outcome"] == "warn", decision
            assert "jp_my_number" in detectors_found(member, sheet_1)
            assert approval_rule not in rule_names(view)  # a trusted recipient
            assert messages_to(inbox, first) == [], "no link before the member confirms"
            confirmed = member.request(
                "POST",
                f"/v1/transfers/{transfer_1}/confirm",
                json={"decision_id": decision["id"], "justification": "The partner's payroll."},
            )
            assert confirmed.status_code == 200, confirmed.text
            wait_for(
                "transfer 1 to be sent", lambda: state_of(member, transfer_1) == "sent" or None
            )
            recipient, first_token = verify_recipient(http, inbox, first)
            secrets_seen.append(first_token)
            [shared] = recipient.request("GET", "/v1/session/files").json()["items"]
            access = recipient.request(
                "POST", f"/v1/session/files/{shared['id']}/downloads", json={}
            )
            assert access.status_code == 200, access.text
            body = recipient.request("GET", access.json()["url"], session=False)
            assert body.status_code == 200, body.text
            assert hashlib.sha256(body.content).hexdigest() == hashlib.sha256(staff).hexdigest()

        with step(
            5, "transfer 2, untrusted: approval requested, the approver approves after step-up"
        ):
            second = address("approved", f"untrusted-{uuid.uuid4().hex[:8]}.example")
            transfer_2, _ = new_transfer(member, second, sheet, staff, XLSX)
            view = settled(member, transfer_2)
            assert view["state"] == "awaiting_confirmation", view["state"]
            decision = view["decision"]
            assert decision["outcome"] == "require_approval", decision
            assert approval_rule in rule_names(view)
            missing = member.request(
                "POST", f"/v1/transfers/{transfer_2}/confirm", json={"decision_id": decision["id"]}
            )
            assert (missing.status_code, missing.json()["code"]) == (422, "justification_required")
            requested = member.request(
                "POST",
                f"/v1/transfers/{transfer_2}/confirm",
                json={"decision_id": decision["id"], "justification": "Their auditor needs it."},
            )
            assert requested.status_code == 200, requested.text
            assert state_of(member, transfer_2) == "pending_approval"
            approval_id = member.request("GET", f"/v1/transfers/{transfer_2}/dlp").json()[
                "approval_request"
            ]["id"]
            wait_for_mail(inbox, approver.me["user"]["email"], approver_mail, "/approvals")
            assert messages_to(inbox, second) == [], "no link before the approval"
            own = member.request(
                "POST", f"/v1/dlp/approval-requests/{approval_id}/approve", json={}
            )
            assert own.status_code == 403, own.text  # the sender is no approver, and never self
            # The step-up (authn and authz 3.3): the approver signs in again, as the web app's
            # "Confirm it's you" does, and approves within the 15 minutes it allows.
            before = approver.me["session"]["auth_time"]
            approver = person(http, "approver")
            assert approver.me["session"]["auth_time"] >= before
            approved = approver.request(
                "POST", f"/v1/dlp/approval-requests/{approval_id}/approve", json={}
            )
            assert approved.status_code == 200, approved.text
            assert approved.json()["state"] == "approved"
            wait_for(
                "transfer 2 to be sent", lambda: state_of(member, transfer_2) == "sent" or None
            )
            secrets_seen.append(link_token(inbox, second))

        with step(6, "transfer 3: a private key is blocked and held; no recipient is emailed"):
            third = address("blocked")
            transfer_3, key_file = new_transfer(
                member,
                third,
                f"deploy-{uuid.uuid4().hex[:6]}.txt",
                private_key_text(rng).encode(),
                "text/plain",
            )
            view = settled(member, transfer_3)
            assert view["state"] == "held", view["state"]
            assert view["decision"]["outcome"] == "block"
            assert "private_key" in detectors_found(member, key_file)
            assert block_rule in rule_names(view)  # the member sees the rule
            held = member.request("GET", f"/v1/transfers/{transfer_3}").json()
            assert held["hold_reason"] == "dlp_blocked", held

        key_name = f"M5 journey {uuid.uuid4().hex[:6]}"
        with step(7, "an API key sends a transfer with no findings"):
            created = admin.request(
                "POST",
                "/v1/api-keys",
                json={"name": key_name, "scopes": ["transfers:write", "audit:read"]},
            )
            assert created.status_code == 201, created.text
            key = created.json()
            key_client = api_key_client(key["secret"])
            fourth = address("api-key")
            draft = key_client.post(
                "/v1/transfers", json={"recipients": [{"email": fourth}], "expires_in": "P1D"}
            )
            assert draft.status_code == 201, draft.text
            transfer_4 = draft.json()["id"]
            upload_to_transfer(
                key_client, transfer_4, "plain.txt", text_of_words(rng, 4096), "text/plain"
            )
            sent = key_client.post(f"/v1/transfers/{transfer_4}/send")
            assert sent.status_code == 200, sent.text
            wait_for(
                "the key's transfer to be sent",
                lambda: state_of(admin, transfer_4) == "sent" or None,
            )
            dlp = admin.request("GET", f"/v1/transfers/{transfer_4}/dlp").json()
            assert dlp["decision"]["outcome"] == "none", dlp["decision"]
            secrets_seen.append(link_token(inbox, fourth))

        with step(8, "the admin finds the approval; the key exports the log as CSV"):
            approvals = search(
                admin, actions=["dlp_approval.approved"], occurred_after=started.isoformat()
            )
            [found] = [
                e for e in approvals if transfer_2 in (e["target_id"], *e["details"].values())
            ]
            assert (found["actor_type"], found["actor_id"]) == (
                "member",
                approver.me["user"]["id"],
            ), found
            admin_mail = message_ids(inbox, admin.me["user"]["email"])
            exported = key_client.post(
                "/v1/audit/exports",
                json={"format": "csv", "filter": {"occurred_after": started.isoformat()}},
            )
            assert exported.status_code == 200, exported.text
            assert exported.headers["content-type"].startswith("text/csv")
            rows = list(csv.DictReader(io.StringIO(exported.text)))
            by_action: dict[str, list[dict[str, str]]] = {}
            for row in rows:
                by_action.setdefault(row["action"], []).append(row)

            def about(action: str) -> set[str]:
                """The transfers and requests the export's `action` rows are about: the target,
                or the transfer an approval request's row names in its details."""
                rows = by_action.get(action, [])
                return {r["target_id"] for r in rows} | {
                    str(json.loads(r["details"] or "{}").get("transfer_id")) for r in rows
                }

            assert {transfer_1, transfer_2, transfer_3, transfer_4} <= about("dlp.decided")
            assert {transfer_1, transfer_2} <= about("transfer.confirmed")
            assert transfer_2 in about("dlp_approval.requested")
            assert transfer_2 in about("dlp_approval.approved")
            assert transfer_3 in about("transfer.held")
            assert request_id in about("upload_request.created")
            assert {"file.uploaded", "file.scanned"} <= set(by_action)
            wait_for_mail(inbox, admin.me["user"]["email"], admin_mail, key["key_prefix"])
            for secret in secrets_seen:
                assert secret not in exported.text, "a link token or a code is in the export"

        with step(
            9, "both sides were told of the blocked file; retention deletes the received file"
        ):
            texts = wait_for(
                "the member's arrived and blocked notices",
                lambda: notices_for(inbox, member.me["user"]["email"], member_mail, request_id),
                NOTICE_SECONDS,
            )
            assert any("blocked" in t for t in texts), texts
            assert any("ready" in t for t in texts), texts
            told = wait_for_mail(inbox, uploader_address, set(), "weren't accepted", NOTICE_SECONDS)
            assert clean_name not in told, "the uploader's notice names no file"
            # The clock's test hook moves the deletion job one day past the file's retention.
            past = int((retention_until - datetime.now(UTC)).total_seconds()) + 86_400
            run_job("deletion", past)
            gone = member.request("GET", f"/v1/files/{clean_id}")
            assert gone.status_code == 200, gone.text
            assert gone.json()["state"] == "deleted"
            assert copies_left(storage, f"tenants/{tenant_id}/files/{clean_id}") == 0
            deleted = search(
                admin,
                actions=["file.deleted"],
                target_id=clean_id,
                occurred_after=started.isoformat(),
            )
            assert deleted, "file.deleted for the received file"
    finally:
        # The rules go, so the browser flows that run next see the default policy. Deleting one is
        # a step-up operation, so the admin signs in again: the journey may take over 15 minutes.
        if rules:
            again = person(http, "admin")
            for rule_id in rules:
                gone = again.request("DELETE", f"/v1/dlp/rules/{rule_id}")
                assert gone.status_code in (200, 204), f"rule {rule_id} is left: {gone.text}"


def upload_link_token(inbox: httpx.Client, address: str) -> str:
    """The `/u#` link of the upload request email to `address`."""

    def probe() -> str | None:
        for message in messages_to(inbox, address):
            found = re.search(r"/u#([A-Za-z0-9_-]{22,128})", text_of(inbox, message["ID"]))
            if found:
                return found.group(1)
        return None

    return wait_for(f"the upload request email to {address}", probe)


def verify_recipient(
    http: httpx.Client, inbox: httpx.Client, address: str
) -> tuple[Recipient, str]:
    recipient = Recipient(http)
    token = link_token(inbox, address)
    resolved = recipient.request("POST", "/v1/links/resolve", json={"token": token})
    assert resolved.status_code == 200, resolved.text
    asked = recipient.request("POST", "/v1/links/codes", json={"token": token})
    assert asked.status_code == 202, asked.text
    code = code_for(inbox, address, 0)
    session = recipient.request("POST", "/v1/links/sessions", json={"token": token, "code": code})
    assert session.status_code == 201, session.text
    recipient.session = session.json()
    return recipient, token


def detectors_found(member: Member, file_id: str) -> set[str]:
    """The detectors the inspection of the file found, as the member's findings list shows."""
    inspection = member.request("GET", f"/v1/files/{file_id}/inspection")
    assert inspection.status_code == 200, inspection.text
    return {f["detector"] for f in inspection.json()["findings"]}


def notices_for(
    inbox: httpx.Client, to: str, before: set[str], request_id: str
) -> list[str] | None:
    """The member's notices for the request: the arrived and the blocked one, once both came."""
    texts = [t for t in new_texts(inbox, to, before) if f"/upload-requests/{request_id}" in t]
    return texts if len(texts) >= 2 else None
