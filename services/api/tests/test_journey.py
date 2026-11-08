"""The M2 end-to-end journey (#182; delivery plan 3, M2's exit criterion): one test, steps 1 to 9.

It runs against the local stack, `make up` then `make seed`, with `make e2e` (docs/local-development
.md 6), and in CI's Local stack job. It talks to the service only through its public HTTP API, and
to the stand-ins only through their own APIs: Keycloak's login form (the browser's part of member
sign-in), Mailpit's HTTP API (the inbox), S3's API (what is left in the buckets), the lifecycle job
commands and the clock's test hook. So in M4 the same test can point at dev, with the seed and the
clock replaced there (delivery plan 5). Two things it reads from the local stack directly, each
named where it does it: the stand-ins' in-network S3 host in part URLs, and the audit log, until an
audit search operation exists (step 9).

Every step is a `step(...)` block, so a failure names the step it happened in. It is skipped unless
SFT_E2E=1, so the ordinary test run, which has no stack, never starts it.
"""

from __future__ import annotations

import hashlib
import html
import os
import random
import re
import shlex
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import boto3
import httpx2 as httpx
import psycopg
import pytest

from dlp_corpus.generate import my_number

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("SFT_E2E") != "1", reason="the journey runs with `make e2e`"),
]

ENV = {
    "API_URL": "http://localhost:8000",
    "WEB_ORIGIN": "http://localhost:3000",
    "MAILPIT_URL": "http://127.0.0.1:8025",
    "S3_ENDPOINT_URL": "http://127.0.0.1:9090",
    # Part URLs name the stand-in as a browser on the host reaches it (S3_PRESIGN_ENDPOINT_URL,
    # #195); the test sends them to the published port by its IPv4 address, as it does every call.
    "S3_PART_HOST": "http://localhost:9090",
    "S3_FILES_BUCKET": "sft-local-files",
    "S3_LARGE_FILES_BUCKET": "sft-local-large-files",
    "LOCAL_POSTGRES_URL": "postgresql://sft:sft-local-only@127.0.0.1:5432/sft",
    "MEMBER_EMAIL": "dev.member@example.com",
    "MEMBER_PASSWORD": "local-only-member-password",
    "JOB_COMMAND": "docker compose --profile jobs run --build --rm --no-deps -T "
    "-e CLOCK_OFFSET_SECONDS={offset} jobs {job}",
    "WAIT_SECONDS": "240",
}
cfg = {name: os.environ.get(f"E2E_{name}", default) for name, default in ENV.items()}
ROOT = Path(__file__).resolve().parents[3]
MIB = 1024 * 1024


@contextmanager
def step(number: int, name: str) -> Iterator[None]:
    """A failure inside names the step of the exit criterion it broke."""
    try:
        yield
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise AssertionError(f"journey step {number} ({name}) failed: {exc!r}") from exc


def wait_for[T](what: str, probe: Callable[[], T | None], seconds: float | None = None) -> T:
    deadline = time.monotonic() + (seconds or float(cfg["WAIT_SECONDS"]))
    while True:
        found = probe()
        if found is not None:
            return found
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(1)


def cookies_of(response: httpx.Response) -> dict[str, str]:
    """The cookies a response sets, as a browser keeps them: `Secure` ones too, which a browser
    keeps for http://localhost and httpx doesn't."""
    jar: dict[str, str] = {}
    for raw in response.headers.get_list("set-cookie"):
        parsed: SimpleCookie = SimpleCookie()
        parsed.load(raw)
        for name, morsel in parsed.items():
            jar[name] = morsel.value
    return jar


def cookie_header(jar: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in jar.items() if value)


class Member:
    """A member's browser: the session cookie and the CSRF token of authn and authz 3.4."""

    def __init__(self, http: httpx.Client) -> None:
        self.http = http
        self.jar: dict[str, str] = {}
        self.csrf = ""
        self.me: dict[str, Any] = {}

    def sign_in(self, email: str, password: str) -> None:
        start = self.http.get(
            "/v1/auth/sign-in", params={"method": "local"}, follow_redirects=False
        )
        assert start.status_code == 302, start.text
        self.jar.update(cookies_of(start))
        login_page = httpx.get(start.headers["location"], follow_redirects=False, timeout=15)
        login_page.raise_for_status()
        form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', login_page.text)
        assert form, "Keycloak's login form"
        keycloak = cookies_of(login_page)
        login = httpx.post(
            html.unescape(form.group(1)),
            data={"username": email, "password": password},
            headers={"cookie": cookie_header(keycloak)},
            follow_redirects=False,
            timeout=15,
        )
        callback = urlsplit(login.headers.get("location", ""))
        assert "code" in parse_qs(callback.query), (
            f"Keycloak refused the sign-in ({login.status_code})"
        )
        done = self.http.get(
            f"{callback.path}?{callback.query}",
            headers={"cookie": cookie_header(self.jar)},
            follow_redirects=False,
        )
        assert done.status_code == 302, done.text
        self.jar.update(cookies_of(done))
        assert self.jar.get("__Host-sft_session"), "no member session"
        me = self.request("GET", "/v1/me")
        assert me.status_code == 200, me.text
        self.me = me.json()
        self.csrf = self.me["csrf_token"]

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"cookie": cookie_header(self.jar), **kwargs.pop("headers", {})}
        if method not in ("GET", "HEAD"):
            headers.update({"origin": cfg["WEB_ORIGIN"], "x-csrf-token": self.csrf})
        return self.http.request(method, path, headers=headers, **kwargs)


class Recipient:
    """A recipient's browser: the link cookie, and the session `X-Link-Session` names."""

    def __init__(self, http: httpx.Client) -> None:
        self.http = http
        self.jar: dict[str, str] = {}
        self.session: dict[str, Any] = {}

    def request(
        self, method: str, path: str, *, session: bool = True, **kwargs: Any
    ) -> httpx.Response:
        headers = {"cookie": cookie_header(self.jar), **kwargs.pop("headers", {})}
        if session and self.session:
            headers["x-link-session"] = self.session["id"]
        if method not in ("GET", "HEAD"):
            headers["origin"] = cfg["WEB_ORIGIN"]
            if self.session:
                headers["x-csrf-token"] = self.session["csrf_token"]
        response = self.http.request(method, path, headers=headers, **kwargs)
        self.jar.update(cookies_of(response))
        return response


# ---- Mailpit (the inbox) ----


def mailpit() -> httpx.Client:
    return httpx.Client(base_url=cfg["MAILPIT_URL"], timeout=15)


def messages_to(inbox: httpx.Client, address: str) -> list[dict[str, Any]]:
    found = inbox.get("/api/v1/search", params={"query": f'to:"{address}"', "limit": 50})
    found.raise_for_status()
    return list(found.json().get("messages") or [])


def text_of(inbox: httpx.Client, message_id: str) -> str:
    message = inbox.get(f"/api/v1/message/{message_id}")
    message.raise_for_status()
    return str(message.json().get("Text") or "")


def link_token(inbox: httpx.Client, address: str) -> str:
    def probe() -> list[str] | None:
        tokens = []
        for message in messages_to(inbox, address):
            found = re.search(r"/t#([A-Za-z0-9_-]{22,128})", text_of(inbox, message["ID"]))
            if found:
                tokens.append(found.group(1))
        return tokens or None

    tokens = wait_for(f"the link email to {address}", probe)
    assert len(tokens) == 1, f"one transfer_link email per recipient, got {len(tokens)}"
    return tokens[0]


def code_for(inbox: httpx.Client, address: str, seen: int) -> str:
    def probe() -> str | None:
        codes = []
        for message in messages_to(inbox, address):
            text = text_of(inbox, message["ID"])
            if "/t#" in text:
                continue
            codes += re.findall(r"(?<![0-9])([0-9]{6,10})(?![0-9])", text)
        return codes[0] if len(codes) > seen else None

    return wait_for(f"the code email to {address}", probe)


# ---- S3, the jobs and the database ----


def s3() -> Any:
    return boto3.client(
        "s3",
        endpoint_url=cfg["S3_ENDPOINT_URL"],
        region_name="ap-northeast-1",
        aws_access_key_id="local-fake",
        aws_secret_access_key="local-fake",  # noqa: S106 - S3Mock checks none
    )


def copies_left(client: Any, key: str) -> int:
    left = 0
    for bucket in (cfg["S3_FILES_BUCKET"], cfg["S3_LARGE_FILES_BUCKET"]):
        versions = client.list_object_versions(Bucket=bucket, Prefix=key)
        left += sum(
            1
            for v in [*versions.get("Versions", []), *versions.get("DeleteMarkers", [])]
            if v["Key"] == key
        )
        uploads = client.list_multipart_uploads(Bucket=bucket, Prefix=key).get("Uploads", [])
        left += sum(1 for u in uploads if u["Key"] == key)
    return left


def run_job(job: str, offset_seconds: int) -> None:
    command = cfg["JOB_COMMAND"].format(offset=offset_seconds, job=job)
    done = subprocess.run(  # noqa: S603 - the configured job command, no shell
        shlex.split(command), cwd=ROOT, capture_output=True, text=True, timeout=300, check=False
    )
    assert done.returncode == 0, f"{job}: {done.stdout[-2000:]}{done.stderr[-2000:]}"


# ---- the member's side ----


def upload(member: Member, transfer_id: str, name: str, data: bytes, *, interrupt: bool) -> str:
    """Declare, upload in parts and complete one file; with `interrupt`, the last part is sent only
    after `listUploadedParts` shows what arrived."""
    declared = member.request(
        "POST",
        f"/v1/transfers/{transfer_id}/files",
        json={"display_name": name, "size": len(data), "content_type": "text/plain"},
    )
    assert declared.status_code == 201, declared.text
    file = declared.json()
    plan = file["upload"]
    part_size, part_count = plan["part_size"], plan["part_count"]
    numbers = list(range(1, part_count + 1))
    first = numbers[:-1] if interrupt else numbers

    def send(parts: list[int]) -> None:
        urls = member.request("POST", f"/v1/files/{file['id']}/parts", json={"part_numbers": parts})
        assert urls.status_code == 200, urls.text
        for part in urls.json()["parts"]:
            n = part["part_number"]
            body = data[(n - 1) * part_size : n * part_size]
            url = part["url"].replace(cfg["S3_PART_HOST"], cfg["S3_ENDPOINT_URL"], 1)
            put = httpx.put(url, content=body, headers=part.get("headers") or {}, timeout=60)
            assert put.status_code == 200, put.text

    send(first)
    if interrupt:
        arrived = member.request("GET", f"/v1/files/{file['id']}/parts")
        assert arrived.status_code == 200, arrived.text
        got = sorted(p["part_number"] for p in arrived.json()["parts"])
        assert got == first, got
        missing = [n for n in numbers if n not in got]
        assert missing == [part_count]
        send(missing)
    completed = member.request("POST", f"/v1/files/{file['id']}/complete")
    assert completed.status_code == 200, completed.text
    return str(file["id"])


def file_state(member: Member, file_id: str) -> dict[str, Any]:
    response = member.request("GET", f"/v1/files/{file_id}")
    assert response.status_code == 200, response.text
    return dict(response.json())


def confirm_warning(member: Member, transfer_id: str) -> None:
    """The DLP decision (#219): the default policy warns on a My Number and on a new recipient
    domain, so the member reviews the decision and confirms it, as the web app does."""

    def probe() -> bool | None:
        state = member.request("GET", f"/v1/transfers/{transfer_id}").json()["state"]
        assert state not in ("held", "draft", "sent"), state
        return True if state == "awaiting_confirmation" else None

    wait_for(f"transfer {transfer_id} to await confirmation", probe)
    dlp = member.request("GET", f"/v1/transfers/{transfer_id}/dlp")
    assert dlp.status_code == 200, dlp.text
    decision = dlp.json()["decision"]
    assert decision["outcome"] == "warn"
    assert {r["condition"] for r in decision["matched_rules"]} >= {"content", "new_domain"}
    confirmed = member.request(
        "POST", f"/v1/transfers/{transfer_id}/confirm", json={"decision_id": decision["id"]}
    )
    assert confirmed.status_code == 200, confirmed.text


def sent_transfer(member: Member, transfer_id: str) -> None:
    def probe() -> bool | None:
        state = member.request("GET", f"/v1/transfers/{transfer_id}").json()["state"]
        assert state not in ("held", "draft"), state
        return True if state == "sent" else None

    wait_for(f"transfer {transfer_id} to be sent", probe)


def verify(http: httpx.Client, inbox: httpx.Client, address: str) -> tuple[Recipient, str]:
    recipient = Recipient(http)
    token = link_token(inbox, address)
    resolved = recipient.request("POST", "/v1/links/resolve", json={"token": token})
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["access_state"] == "verification_required"
    seen = len([m for m in messages_to(inbox, address) if "/t#" not in text_of(inbox, m["ID"])])
    asked = recipient.request("POST", "/v1/links/codes", json={"token": token})
    assert asked.status_code == 202, asked.text
    code = code_for(inbox, address, seen)
    session = recipient.request("POST", "/v1/links/sessions", json={"token": token, "code": code})
    assert session.status_code == 201, session.text
    recipient.session = session.json()
    assert recipient.jar.get("__Host-sft_link"), "no link cookie"
    return recipient, token


WORDS = (
    "report",
    "review",
    "quarterly",
    "budget",
    "meeting",
    "draft",
    "final",
    "schedule",
    "project",
    "summary",
    "contract",
    "invoice",
    "delivery",
    "partner",
    "team",
    "update",
    "notes",
    "agenda",
    "plan",
    "record",
)


def text_of_words(rng: random.Random, size: int) -> bytes:
    """`size` bytes of plain words, different on every run, that no detector matches."""
    lines = []
    total = 0
    while total < size:
        line = " ".join(rng.choice(WORDS) for _ in range(12)) + "\n"
        lines.append(line)
        total += len(line)
    return "".join(lines).encode()[:size]


def new_address() -> str:
    return f"journey-{uuid.uuid4().hex[:10]}@partner.example"


def test_the_m2_journey() -> None:
    started = datetime.now(UTC)
    rng = random.Random(182)  # noqa: S311 - test data, not a secret
    canary = my_number(rng)
    plain = text_of_words(rng, 6 * MIB)  # text, so the inspector reads all of it: `inspected`
    with_number = (f"個人番号: {canary}\n").encode() + text_of_words(rng, 6 * MIB)
    names = (f"plain-{uuid.uuid4().hex[:6]}.txt", f"staff-{uuid.uuid4().hex[:6]}.txt")
    first, second = new_address(), new_address()
    http = httpx.Client(base_url=cfg["API_URL"], timeout=60)
    inbox = mailpit()
    storage = s3()
    member = Member(http)
    secrets_seen: list[str] = [canary, first, second, *names]

    with step(1, "sends a transfer"):
        member.sign_in(cfg["MEMBER_EMAIL"], cfg["MEMBER_PASSWORD"])
        tenant_id = member.me["tenant"]["id"]
        created = member.request(
            "POST",
            "/v1/transfers",
            json={
                "recipients": [{"email": first}, {"email": second}],
                "download_limit": 2,
                "expires_in": "P2D",
            },
        )
        assert created.status_code == 201, created.text
        transfer_id = created.json()["id"]

    with step(2, "uploads in parts, resumes an interrupted upload, sends"):
        file_ids = [
            upload(member, transfer_id, names[0], plain, interrupt=True),
            upload(member, transfer_id, names[1], with_number, interrupt=False),
        ]
        sent = member.request("POST", f"/v1/transfers/{transfer_id}/send")
        assert sent.status_code == 200, sent.text

    with step(3, "scans with ClamAV and inspects every file"):
        for file_id in file_ids:
            wait_for(
                f"file {file_id} to be scanned",
                lambda f=file_id: True if file_state(member, f)["state"] == "clean" else None,
            )
            inspection = member.request("GET", f"/v1/files/{file_id}/inspection")
            assert inspection.status_code == 200, inspection.text
            assert inspection.json()["state"] == "inspected"
        findings = {
            f["detector"]: f
            for f in member.request("GET", f"/v1/files/{file_ids[1]}/inspection").json()["findings"]
        }
        found = findings["jp_my_number"]
        assert found["count_low"] + found["count_medium"] + found["count_high"] >= 1
        assert "jp_my_number" not in {
            f["detector"]
            for f in member.request("GET", f"/v1/files/{file_ids[0]}/inspection").json()["findings"]
        }
        confirm_warning(member, transfer_id)  # the DLP decision warns (#219)
        sent_transfer(member, transfer_id)

    with step(4, "emails a link to each recipient"):
        tokens = {address: link_token(inbox, address) for address in (first, second)}
        assert len(set(tokens.values())) == 2
        secrets_seen += list(tokens.values())

    with step(5, "verifies the recipient"):
        recipient, token = verify(http, inbox, first)
        listed = recipient.request("GET", "/v1/session/files")
        assert listed.status_code == 200, listed.text
        assert {f["id"] for f in listed.json()["items"]} == set(file_ids)

    with step(6, "streams a download and resumes it"):
        grant = recipient.request("POST", f"/v1/session/files/{file_ids[0]}/downloads", json={})
        assert grant.status_code == 200, grant.text
        url = grant.json()["url"]
        half = len(plain) // 2
        head = recipient.request(
            "GET", url, session=False, headers={"range": f"bytes=0-{half - 1}"}
        )
        assert head.status_code == 206, head.text
        tail = recipient.request(
            "GET",
            url,
            session=False,
            headers={"range": f"bytes={half}-", "if-range": head.headers["etag"]},
        )
        assert tail.status_code == 206, tail.text
        joined = head.content + tail.content
        assert hashlib.sha256(joined).hexdigest() == hashlib.sha256(plain).hexdigest()
        assert head.headers["etag"] == f'"{hashlib.sha256(plain).hexdigest()}"'
        statuses = member.request("GET", f"/v1/transfers/{transfer_id}/recipients").json()
        [mine] = [r for r in statuses["items"] if r["email"] == first]
        assert [(d["file_id"], d["count"]) for d in mine["downloads"]] == [(file_ids[0], 1)]

    with step(7, "revokes the transfer"):
        revoked = member.request("POST", f"/v1/transfers/{transfer_id}/revoke")
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["state"] == "revoked"
        for response in (
            recipient.request("POST", f"/v1/session/files/{file_ids[0]}/downloads", json={}),
            recipient.request("GET", url, session=False),
            recipient.request("POST", "/v1/links/resolve", session=False, json={"token": token}),
        ):
            assert (response.status_code, response.json()["code"]) == (410, "link_revoked")

    with step(8, "expiry deletes every copy"):
        later = new_address()
        secrets_seen.append(later)
        created = member.request(
            "POST", "/v1/transfers", json={"recipients": [{"email": later}], "expires_in": "PT1H"}
        )
        assert created.status_code == 201, created.text
        expiring = created.json()["id"]
        expiring_file = upload(member, expiring, names[0], plain, interrupt=False)
        assert member.request("POST", f"/v1/transfers/{expiring}/send").status_code == 200
        wait_for(
            "the second transfer's file to be scanned",
            lambda: True if file_state(member, expiring_file)["state"] == "clean" else None,
        )
        sent_transfer(member, expiring)
        _, later_token = verify(http, inbox, later)
        secrets_seen.append(later_token)
        # The clock's test hook moves the jobs two hours on, past the one-hour expiry.
        two_hours = 2 * 3600
        run_job("expiry", two_hours)
        run_job("deletion", two_hours)
        expired = Recipient(http).request(
            "POST", "/v1/links/resolve", session=False, json={"token": later_token}
        )
        assert (expired.status_code, expired.json()["code"]) == (410, "link_expired")
        for file_id in (expiring_file, *file_ids):
            key = f"tenants/{tenant_id}/files/{file_id}"
            assert copies_left(storage, key) == 0, key
            assert file_state(member, file_id)["state"] == "deleted", file_id
        # Osaka's copies are checked when this test runs against AWS in M4 (delivery plan 5).

    with step(9, "audits every security-relevant step, and nothing secret"):
        # The audit log through the local database, read only: no operation searches it yet.
        with psycopg.connect(cfg["LOCAL_POSTGRES_URL"]) as connection:
            rows = connection.execute(
                "SELECT action, coalesce(details::text, ''), coalesce(user_agent, '') "
                "FROM audit_events WHERE tenant_id = %(t)s AND occurred_at >= %(since)s",
                {"t": tenant_id, "since": started},
            ).fetchall()
        actions = {row[0] for row in rows}
        expected = {
            "member.signed_in",
            "transfer.created",
            "file.added",
            "file.uploaded",
            "transfer.submitted",
            "file.scanned",
            "transfer.sent",
            "recipient.link_issued",
            "verification.code_requested",
            "verification.code_created",
            "verification.attempted",
            "link_session.started",
            "download.granted",
            "transfer.revoked",
            "transfer.expired",
            "file.deleted",
        }
        assert expected <= actions, sorted(expected - actions)
        text = "\n".join(f"{details} {agent}" for _, details, agent in rows)
        for secret in secrets_seen:
            assert secret not in text, "a token, code, address, name or My Number is in the log"
