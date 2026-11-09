"""The synthetic probe (#248): each step against a fake service, its failures named, and its report.

The fake answers as the contract does, through httpx's mock transport, so these run with no stack.
`test_probe_local.py` runs the real probe against the local stack.
"""

from __future__ import annotations

import io
import json
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

import httpx2 as httpx
import pytest
from botocore.exceptions import ClientError
from prometheus_client import CollectorRegistry
from pydantic import ValidationError

from sft.probe import __main__ as entry
from sft.probe import report
from sft.probe.journey import STEPS, Probe, words
from sft.probe.mailbox import Mail, MailpitMailbox, S3Mailbox, code, link_token, parse_raw
from sft.probe.settings import ProbeSettings

API = "http://api.test"
WEB = "http://web.test"
TOKEN = "T" * 43
CODE = "48213977"
KEY = "sft_dev_" + "a" * 43 + "_" + "b" * 6  # the format only: no check digits, never a real key


def settings(**changes: Any) -> ProbeSettings:
    values: dict[str, Any] = {
        "environment": "test",
        "probe_api_url": API,
        "probe_web_origin": WEB,
        "probe_api_key": KEY,
        "probe_mailbox": "mailpit",
        "probe_mailpit_url": "http://mail.test",
        "probe_mailbox_domain": "probe.sft.localhost",
        "probe_file_bytes": 4096,
        "probe_timeout_seconds": 60,
    }
    values.update(changes)
    return ProbeSettings(**values)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeMailbox:
    """Mail appears when the fake service sends it."""

    mails: dict[str, list[Mail]] = field(default_factory=dict)
    deleted: list[str] = field(default_factory=list)
    closed: bool = False

    def deliver(self, address: str, text: str) -> None:
        box = self.mails.setdefault(address, [])
        box.append(Mail(f"m{len(box)}", text))

    def messages_to(self, address: str) -> list[Mail]:
        return list(self.mails.get(address, []))

    def delete(self, ids: list[str]) -> None:
        self.deleted += ids

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeService:
    """The API's answers on the probe's path, and the S3 stand-in's part PUT."""

    mailbox: FakeMailbox
    states: list[str] = field(default_factory=lambda: ["submitted", "sent"])
    status: dict[str, int] = field(default_factory=dict)
    corrupt: bool = False
    send_link: bool = True
    internal_open: bool = False
    calls: list[str] = field(default_factory=list)
    stored: bytes = b""
    recipient: str = ""
    headers_seen: dict[str, dict[str, str]] = field(default_factory=dict)

    def answer(self, name: str, ok: int, body: Any = None, **kwargs: Any) -> httpx.Response:
        status = self.status.get(name, ok)
        if status != ok:
            problem = {"code": "service_unavailable"} if status == 503 else {"title": "refused"}
            return httpx.Response(status, json=problem)
        return httpx.Response(status, json=body if body is not None else {}, **kwargs)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content and method != "PUT" else {}
        self.headers_seen[path] = dict(request.headers)
        if method == "PUT" and request.url.host == "s3.test":
            self.calls.append("putPart")
            self.stored += request.content
            return httpx.Response(200)
        route: dict[tuple[str, str], Callable[[], httpx.Response]] = {
            ("POST", "/v1/transfers"): lambda: self.create(body),
            ("POST", "/v1/transfers/t1/files"): lambda: self.answer(
                "addTransferFile",
                201,
                {"id": "f1", "upload": {"part_size": 5 * 1024 * 1024, "part_count": 1}},
            ),
            ("POST", "/v1/files/f1/parts"): lambda: self.answer(
                "requestUploadPartUrls",
                200,
                {"parts": [{"part_number": 1, "url": "http://s3.test/b/k?partNumber=1"}]},
            ),
            ("POST", "/v1/files/f1/complete"): lambda: self.answer("completeUpload", 200),
            ("POST", "/v1/transfers/t1/send"): lambda: self.answer("sendTransfer", 200),
            ("GET", "/v1/transfers/t1"): self.transfer,
            ("POST", "/v1/links/resolve"): lambda: self.answer(
                "resolveLink", 200, {"access_state": "verification_required"}
            ),
            ("POST", "/v1/links/codes"): self.codes,
            ("POST", "/v1/links/sessions"): lambda: self.answer(
                "createLinkSession",
                201,
                {"id": "s1", "csrf_token": "c1"},
                headers=[("set-cookie", "__Host-sft_link=L1; Path=/; Secure; HttpOnly")],
            ),
            ("GET", "/v1/session/files"): lambda: self.answer(
                "listSessionFiles", 200, {"items": [{"id": "f1"}]}
            ),
            ("POST", "/v1/session/files/f1/downloads"): lambda: self.answer(
                "createSessionDownload", 200, {"url": "/v1/session/downloads/g1/content"}
            ),
            ("GET", "/v1/session/downloads/g1/content"): self.content,
            ("POST", "/v1/transfers/t1/revoke"): lambda: self.answer(
                "revokeTransfer", 200, {"state": "revoked"}
            ),
        }
        if (method, path) in route:
            self.calls.append(f"{method} {path}")
            return route[(method, path)]()
        if self.internal_open and path == "/metrics":
            return httpx.Response(200, text="# metrics")
        return httpx.Response(404, json={"code": "not_found"})

    def create(self, body: dict[str, Any]) -> httpx.Response:
        self.recipient = body["recipients"][0]["email"]
        return self.answer("createTransfer", 201, {"id": "t1", "state": "draft"})

    def transfer(self) -> httpx.Response:
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if state == "sent" and self.send_link and not self.mailbox.messages_to(self.recipient):
            self.mailbox.deliver(
                self.recipient, f"Open http://web.test/t#{TOKEN} by Friday 20261109"
            )
        return self.answer("getTransfer", 200, {"id": "t1", "state": state})

    def codes(self) -> httpx.Response:
        self.mailbox.deliver(self.recipient, f"Your code is {CODE}. It lasts 10 minutes.")
        return self.answer("requestVerificationCode", 202)

    def content(self) -> httpx.Response:
        data = self.stored[::-1] if self.corrupt else self.stored
        return httpx.Response(self.status.get("content", 200), content=data)


def make(
    service_changes: dict[str, Any] | None = None, web: httpx.Client | None = None, **changes: Any
) -> tuple[Probe, FakeService, FakeMailbox, Clock]:
    box = FakeMailbox()
    service = FakeService(box, **(service_changes or {}))
    clock = Clock()
    transport = httpx.MockTransport(service)
    probe = Probe(
        settings(**changes),
        box,
        api=httpx.Client(base_url=API, transport=transport),
        storage=httpx.Client(transport=transport),
        web=web,
        clock=clock,
        sleep=clock.sleep,
        run_id="run1",
    )
    return probe, service, box, clock


def test_the_whole_journey_passes_and_cleans_up() -> None:
    probe, service, box, _ = make()
    result = probe.run()
    assert result.passed, result
    assert (result.failed_step, result.reason) == (None, None)
    assert set(result.step_seconds) == set(STEPS)
    assert result.first_byte_seconds is not None
    assert service.recipient == "probe+run1@probe.sft.localhost"  # a fresh address each run
    assert service.calls[-1] == "POST /v1/transfers/t1/revoke"
    assert box.deleted == ["m0", "m1"]
    assert service.stored == words(4096, random.Random("run1"))  # noqa: S311 - test data
    # The key on the member side; the cookie, Origin and CSRF token on the recipient's, no key.
    assert service.headers_seen["/v1/transfers"]["authorization"] == f"Bearer {KEY}"
    session = service.headers_seen["/v1/session/files/f1/downloads"]
    assert "authorization" not in session
    assert (session["origin"], session["x-csrf-token"], session["x-link-session"]) == (
        WEB,
        "c1",
        "s1",
    )
    assert (
        "__Host-sft_link=L1" in service.headers_seen["/v1/session/downloads/g1/content"]["cookie"]
    )
    probe.close()
    assert box.closed


@pytest.mark.parametrize(
    ("changes", "step", "reason"),
    [
        (
            {"status": {"sendTransfer": 503}},
            "send",
            "sendTransfer answered 503 service_unavailable",
        ),
        ({"status": {"addTransferFile": 429}}, "upload", "addTransferFile answered 429"),
        (
            {"states": ["awaiting_confirmation"]},
            "shareable",
            "the transfer became awaiting_confirmation",
        ),
        ({"send_link": False}, "link_email", "timed out waiting for the link email"),
        ({"status": {"createLinkSession": 422}}, "verify", "createLinkSession answered 422"),
        ({"corrupt": True}, "download", "the downloaded bytes differ from the uploaded ones"),
        ({"status": {"content": 410}}, "download", "getSessionDownloadContent answered 410"),
        (
            {"status": {"revokeTransfer": 503}},
            "revoke",
            "revokeTransfer answered 503 service_unavailable",
        ),
    ],
)
def test_a_failing_step_names_itself_and_the_transfer_is_still_revoked(
    changes: dict[str, Any], step: str, reason: str
) -> None:
    probe, service, _, _ = make(changes)
    result = probe.run()
    assert not result.passed
    assert (result.failed_step, result.reason) == (step, reason)
    assert "POST /v1/transfers/t1/revoke" in service.calls
    assert TOKEN not in reason
    assert CODE not in reason


def test_a_slow_transfer_times_out_inside_the_run() -> None:
    probe, _, _, clock = make({"states": ["submitted"]})
    result = probe.run()
    assert (result.failed_step, result.reason) == (
        "shareable",
        "timed out waiting for the transfer to be sent",
    )
    assert clock.now - 1000.0 <= 60 + 2


def test_an_internal_path_on_the_public_host_fails_the_edge_and_creates_nothing() -> None:
    probe, service, _, _ = make({"internal_open": True})
    result = probe.run()
    assert (result.failed_step, result.reason) == (
        "edge",
        "the public API serves an internal path (/metrics)",
    )
    assert not [c for c in service.calls if "/v1/" in c]


def web_answering(headers: dict[str, str]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, headers=headers))
    )


GOOD_WEB = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
}


@pytest.mark.parametrize(
    ("drop", "reason"),
    [
        ("strict-transport-security", "the web app sends no Strict-Transport-Security"),
        ("content-security-policy", "the web app's CSP has no frame-ancestors"),
        ("referrer-policy", "the web app sends no Referrer-Policy"),
    ],
)
def test_over_https_the_web_app_headers_are_checked(drop: str, reason: str) -> None:
    headers = {k: v for k, v in GOOD_WEB.items() if k != drop}
    probe, _, _, _ = make(web=web_answering(headers), probe_web_origin="https://app.test")
    result = probe.run()
    assert (result.failed_step, result.reason) == ("edge", reason)


def test_over_https_good_headers_pass_the_edge() -> None:
    probe, _, _, _ = make(web=web_answering(GOOD_WEB), probe_web_origin="https://app.test")
    assert probe.run().passed


def test_a_transport_error_names_its_step() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    box = FakeMailbox()
    clock = Clock()
    probe = Probe(
        settings(),
        box,
        api=httpx.Client(base_url=API, transport=httpx.MockTransport(down)),
        clock=clock,
        sleep=clock.sleep,
    )
    result = probe.run()
    assert (result.failed_step, result.reason) == ("edge", "transport: ConnectError")


def test_part_urls_go_to_the_local_host_when_asked() -> None:
    probe, _, _, _ = make(probe_part_url_host="http://s3.test")
    assert probe._part_url("http://localhost:9090/b/k?partNumber=1") == (
        "http://s3.test/b/k?partNumber=1"
    )
    assert probe._part_url("http://localhost:9090/b/k") == "http://s3.test/b/k"


# ---- settings ----


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"environment": "prod"}, "for the local stack only"),
        ({"probe_mailbox": "s3"}, "PROBE_MAILBOX_BUCKET is required"),
        ({"probe_mailpit_url": None}, "PROBE_MAILPIT_URL is required"),
        (
            {"environment": "staging", "probe_mailbox": "s3", "probe_mailbox_bucket": "b"},
            "must be https://",
        ),
        (
            {
                "environment": "dev",
                "probe_mailbox": "s3",
                "probe_mailbox_bucket": "b",
                "probe_part_url_host": "http://s3.test",
            },
            "for the local stack only",
        ),
        ({"probe_api_url": "http://api.test/v1"}, "must be an origin"),
        ({"probe_mailbox_local_part": "pro.be"}, "letters and digits"),
        ({"probe_mailbox_domain": "a@b"}, "a domain name"),
    ],
)
def test_settings_refuse_what_doesnt_belong(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        settings(**changes)


def test_settings_for_aws() -> None:
    ok = settings(
        environment="prod",
        probe_api_url="https://api.sft.example.com/",
        probe_web_origin="https://app.sft.example.com",
        probe_mailbox="s3",
        probe_mailbox_bucket="sft-prod-apne1-mailbox-000000000000",
        probe_mailpit_url=None,
        probe_mailbox_domain="Probe.SFT.example.com",
    )
    assert ok.probe_api_url == "https://api.sft.example.com"
    assert ok.probe_mailbox_domain == "probe.sft.example.com"
    assert KEY not in repr(ok)


# ---- the mailbox ----


def raw_mail(to: str, text: str) -> bytes:
    message = EmailMessage()
    message["From"] = "no-reply@mail.sft.example.com"
    message["To"] = to
    message["Subject"] = "Files for you"
    message.set_content(text)
    message.add_alternative(f"<p>{text}</p>", subtype="html")
    return bytes(message)


def test_the_token_and_the_code_come_from_the_right_emails() -> None:
    assert link_token(f"Open https://app.test/t#{TOKEN} now") == TOKEN
    assert link_token("no link") is None
    assert code(f"Your code is {CODE}.") == CODE
    assert code(f"https://app.test/t#{TOKEN} 20261109") is None  # a link email's digits
    assert code("expires in 10 minutes") is None
    recipients, text = parse_raw(raw_mail("Probe+Run1@probe.test", f"Your code is {CODE}."))
    assert recipients == {"probe+run1@probe.test"}
    assert CODE in text
    assert "<p>" not in text


class FakeS3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects
        self.gets = 0
        self.deleted: list[str] = []

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        keys = sorted(k for k in self.objects if k.startswith(kwargs["Prefix"]))
        if "ContinuationToken" not in kwargs:
            first = [
                {"Key": k, "LastModified": datetime(2026, 11, 9, tzinfo=UTC)} for k in keys[:1]
            ]
            return {"Contents": first, "NextContinuationToken": "next"}
        return {"Contents": [{"Key": k} for k in keys[1:]]}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.gets += 1
        return {"Body": io.BytesIO(self.objects[kwargs["Key"]])}

    def delete_objects(self, **kwargs: Any) -> dict[str, Any]:
        self.deleted += [o["Key"] for o in kwargs["Delete"]["Objects"]]
        return {}


def test_the_s3_mailbox_reads_each_object_once_and_keeps_this_runs_mail() -> None:
    s3 = FakeS3(
        {
            "probe/a": raw_mail("probe+run1@probe.test", f"https://app.test/t#{TOKEN}"),
            "probe/b": raw_mail("probe+other@probe.test", "Your code is 11111111."),
            "probe/c": raw_mail("probe+run1@probe.test", f"Your code is {CODE}."),
            "elsewhere/d": raw_mail("probe+run1@probe.test", "not mine"),
        }
    )
    box = S3Mailbox(s3, "bucket", "probe/")
    found = box.messages_to("probe+run1@probe.test")
    assert [m.id for m in found] == ["probe/a", "probe/c"]
    assert box.messages_to("probe+run1@probe.test") == found
    assert s3.gets == 3
    box.delete([m.id for m in found])
    box.delete([])
    assert s3.deleted == ["probe/a", "probe/c"]
    box.close()


def test_the_mailpit_mailbox_searches_by_recipient() -> None:
    asked: list[str] = []

    def mailpit(request: httpx.Request) -> httpx.Response:
        asked.append(f"{request.method} {request.url.path}")
        if request.url.path == "/api/v1/search":
            assert request.url.params["query"] == 'to:"probe+run1@probe.test"'
            return httpx.Response(200, json={"messages": [{"ID": "new"}, {"ID": "old"}]})
        if request.method == "DELETE":
            return httpx.Response(200)
        return httpx.Response(200, json={"Text": request.url.path.rsplit("/", 1)[-1]})

    box = MailpitMailbox("http://mail.test", transport=httpx.MockTransport(mailpit))
    assert box.messages_to("probe+run1@probe.test") == [Mail("old", "old"), Mail("new", "new")]
    box.delete(["old"])
    box.delete([])
    assert asked[-1] == "DELETE /api/v1/messages"
    box.close()


# ---- the report ----


def sample(registry: CollectorRegistry, name: str, **labels: str) -> float | None:
    return registry.get_sample_value(name, labels)


def test_a_failed_run_marks_its_step_and_keeps_the_last_success() -> None:
    registry = report.registry_for(
        passed=False,
        failed_step="verify",
        steps=STEPS,
        seconds=12.5,
        step_seconds={"edge": 0.1, "verify": 9.0},
        first_byte_seconds=None,
        finished_at=1_700_000_000.0,
    )
    assert sample(registry, "synthetic_probe_success") == 0
    assert sample(registry, "synthetic_probe_step_failures_total", step="verify") == 1
    assert sample(registry, "synthetic_probe_step_failures_total", step="download") == 0
    assert sample(registry, "synthetic_probe_duration_seconds") == 12.5
    assert sample(registry, "synthetic_probe_step_duration_seconds", step="verify") == 9.0
    assert sample(registry, "synthetic_probe_last_success_timestamp_seconds") is None
    assert sample(registry, "synthetic_probe_download_first_byte_seconds") is None


def test_a_passed_run_sets_the_last_success() -> None:
    registry = report.registry_for(
        passed=True,
        failed_step=None,
        steps=STEPS,
        seconds=20.0,
        step_seconds={},
        first_byte_seconds=0.2,
        finished_at=1_700_000_000.0,
    )
    assert sample(registry, "synthetic_probe_success") == 1
    assert sample(registry, "synthetic_probe_last_success_timestamp_seconds") == 1_700_000_000.0
    assert sample(registry, "synthetic_probe_download_first_byte_seconds") == 0.2


class FakeCloudWatch:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.put: list[dict[str, Any]] = []

    def put_metric_data(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutMetricData")
        self.put.append(kwargs)
        return {}


def test_cloudwatch_gets_the_environment_series_and_the_digest_series() -> None:
    client = FakeCloudWatch()
    digest = "sha256:" + "0" * 64
    assert report.publish(client, environment="staging", passed=True, image_digest=digest)
    [call] = client.put
    assert call["Namespace"] == "SecureFileTransfer/Probe"
    dims = [d["Dimensions"] for d in call["MetricData"]]
    assert dims == [
        [{"Name": "Environment", "Value": "staging"}],
        [{"Name": "Environment", "Value": "staging"}, {"Name": "ImageDigest", "Value": digest}],
    ]
    assert {d["MetricName"] for d in call["MetricData"]} == {"ProbeSuccess"}
    assert {d["Value"] for d in call["MetricData"]} == {1.0}
    assert report.publish(client, environment="dev", passed=False, image_digest=None)
    assert [d["Value"] for d in client.put[1]["MetricData"]] == [0.0]
    assert not report.publish(
        FakeCloudWatch(fail=True), environment="dev", passed=True, image_digest=None
    )


def test_a_push_to_an_unreachable_gateway_is_only_a_warning() -> None:
    registry = report.registry_for(
        passed=True,
        failed_step=None,
        steps=STEPS,
        seconds=1.0,
        step_seconds={},
        first_byte_seconds=None,
        finished_at=1.0,
    )
    report.push("http://127.0.0.1:9", registry)  # nothing listens on the discard port


# ---- the entry point ----


def test_main_exits_2_on_bad_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROBE_API_KEY", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")
    assert entry.main() == 2


@pytest.mark.parametrize("passed", [True, False])
def test_main_reports_and_exits_with_the_result(
    monkeypatch: pytest.MonkeyPatch, passed: bool
) -> None:
    env = {
        "ENVIRONMENT": "test",
        "PROBE_API_URL": API,
        "PROBE_WEB_ORIGIN": WEB,
        "PROBE_API_KEY": KEY,
        "PROBE_MAILBOX": "mailpit",
        "PROBE_MAILPIT_URL": "http://mail.test",
        "PROBE_MAILBOX_DOMAIN": "probe.test",
        "PROBE_CLOUDWATCH": "true",
        "METRICS_PUSHGATEWAY_URL": "http://gateway.test",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    seen: dict[str, Any] = {}

    def run(self: Probe) -> Any:
        self.result.passed = passed
        self.result.failed_step = None if passed else "send"
        return self.result

    monkeypatch.setattr(Probe, "run", run)
    monkeypatch.setattr(report, "push", lambda gateway, registry: seen.update(gateway=gateway))
    monkeypatch.setattr(report, "cloudwatch_client", lambda region: FakeCloudWatch())
    monkeypatch.setattr(report, "publish", lambda client, **kw: seen.update(kw))
    assert entry.main() == (0 if passed else 1)
    assert seen["gateway"] == "http://gateway.test"
    assert (seen["environment"], seen["passed"]) == ("test", passed)


def test_the_mailbox_follows_the_settings() -> None:
    assert isinstance(entry.open_mailbox(settings()), MailpitMailbox)
    s3 = entry.open_mailbox(
        settings(probe_mailbox="s3", probe_mailbox_bucket="b", probe_mailpit_url=None)
    )
    assert isinstance(s3, S3Mailbox)
