"""One probe run: the steps of the package docstring, each timed, the first failure named.

Everything goes through the public API with plain HTTP, as a customer's integration and a
recipient's browser would: the API key in `Authorization`, the recipient's link cookie and
`X-Link-Session`, the web app's `Origin` and the link session's CSRF token on unsafe calls. A
failure's reason is the operation and its status, or the problem's `code`: never a body, a URL, a
token, a code or an address.
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

import httpx2 as httpx

from sft.probe import mailbox as mail
from sft.probe.mailbox import Mailbox
from sft.probe.settings import ProbeSettings

log = logging.getLogger(__name__)

STEPS: Final = (
    "edge",
    "create",
    "upload",
    "send",
    "shareable",
    "link_email",
    "verify",
    "download",
    "revoke",
)
INTERNAL_PATHS: Final = ("/metrics", "/healthz", "/readyz", "/docs", "/redoc", "/openapi.json")
"""Served only on the internal port, or not at all: never on the public host (T-05)."""
WAIT: Final = {
    "shareable": (150.0, "the transfer to be sent"),
    "link_email": (90.0, "the link email"),
    "code_email": (90.0, "the code email"),
}
"""The longest each wait may take, inside the run's own deadline, and what it waits for."""
POLL_SECONDS: Final = 2.0
REVOKE_TIMEOUT: Final = 20.0
STOPPED: Final = frozenset(
    {"held", "cancelled", "revoked", "expired", "awaiting_confirmation", "pending_approval"}
)
"""Transfer states the probe's transfer must never reach on its way to `sent`."""
WORDS: Final = (
    *("report", "review", "quarterly", "budget", "meeting", "draft", "final", "schedule"),
    *("project", "summary", "contract", "invoice", "delivery", "partner", "team", "update"),
    *("notes", "agenda", "plan", "record"),
)


class StepFailedError(Exception):
    def __init__(self, step: str, reason: str) -> None:
        super().__init__(f"{step}: {reason}")
        self.step = step
        self.reason = reason


@dataclass
class RunResult:
    run: str
    passed: bool
    failed_step: str | None = None
    reason: str | None = None
    seconds: float = 0.0
    step_seconds: dict[str, float] = field(default_factory=dict)
    first_byte_seconds: float | None = None


def words(size: int, rng: random.Random) -> bytes:
    """`size` bytes of plain words, different every run, that no DLP detector matches."""
    out = bytearray()
    while len(out) < size:
        out += (" ".join(rng.choice(WORDS) for _ in range(12)) + "\n").encode()
    return bytes(out[:size])


def _problem(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return str(response.status_code)
    code = body.get("code") if isinstance(body, dict) else None
    return f"{response.status_code} {code}" if isinstance(code, str) else str(response.status_code)


def _cookies(response: httpx.Response) -> dict[str, str]:
    """The cookies a response sets, as a browser keeps them, `Secure` ones over http://localhost
    included (httpx's own jar would drop those)."""
    jar: dict[str, str] = {}
    for raw in response.headers.get_list("set-cookie"):
        parsed: SimpleCookie = SimpleCookie()
        parsed.load(raw)
        for name, morsel in parsed.items():
            jar[name] = morsel.value
    return jar


class Probe:
    """One run against the environment `settings` names."""

    def __init__(
        self,
        settings: ProbeSettings,
        mailbox: Mailbox,
        *,
        api: httpx.Client | None = None,
        storage: httpx.Client | None = None,
        web: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        run_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.mailbox = mailbox
        self.api = api or httpx.Client(base_url=settings.probe_api_url, timeout=30)
        self.storage = storage or httpx.Client(timeout=60)
        self.web = web or httpx.Client(timeout=15)
        self.clock = clock
        self.sleep = sleep
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.address = (
            f"{settings.probe_mailbox_local_part}+{self.run_id}@{settings.probe_mailbox_domain}"
        )
        self.result = RunResult(self.run_id, passed=False)
        self._deadline = 0.0
        self._key = {"authorization": f"Bearer {settings.probe_api_key.get_secret_value()}"}
        self._jar: dict[str, str] = {}
        self._session: dict[str, Any] = {}

    # ---- the run ----

    def run(self) -> RunResult:
        started = self.clock()
        self._deadline = started + self.settings.probe_timeout_seconds
        data = words(self.settings.probe_file_bytes, random.Random(self.run_id))  # noqa: S311 - test data
        transfer_id: str | None = None
        try:
            with self._step("edge"):
                self._edge()
            with self._step("create"):
                transfer_id = self._create()
            with self._step("upload"):
                file_id = self._upload(transfer_id, data)
            with self._step("send"):
                self._call("sendTransfer", "POST", f"/v1/transfers/{transfer_id}/send", 200)
            with self._step("shareable"):
                self._until_sent(transfer_id)
            with self._step("link_email"):
                token = self._wait("link_email", self._token)
            with self._step("verify"):
                self._verify(token)
            with self._step("download"):
                self._download(file_id, data)
        except StepFailedError as failed:
            self.result.failed_step, self.result.reason = failed.step, failed.reason
        finally:
            if transfer_id is not None:
                self._revoke(transfer_id)
            self._tidy_mailbox()
        self.result.passed = self.result.failed_step is None
        self.result.seconds = round(self.clock() - started, 3)
        return self.result

    def close(self) -> None:
        for client in (self.api, self.storage, self.web):
            client.close()
        self.mailbox.close()

    @contextmanager
    def _step(self, name: str) -> Iterator[None]:
        start = self.clock()
        try:
            yield
        except httpx.TransportError as exc:
            raise StepFailedError(name, f"transport: {type(exc).__name__}") from exc
        except StepFailedError as failed:
            if failed.step:
                raise
            raise StepFailedError(name, failed.reason) from failed
        except Exception as exc:
            # Anything unexpected still names its step; the type only, never the message,
            # which might quote a body.
            raise StepFailedError(name, f"error: {type(exc).__name__}") from exc
        finally:
            self.result.step_seconds[name] = round(self.clock() - start, 3)

    def _revoke(self, transfer_id: str) -> None:
        """Always, once a transfer exists, so a failed run leaves nothing shared."""
        try:
            with self._step("revoke"):
                self._call(
                    "revokeTransfer",
                    "POST",
                    f"/v1/transfers/{transfer_id}/revoke",
                    200,
                    timeout=REVOKE_TIMEOUT,
                )
        except StepFailedError as failed:
            if self.result.failed_step is None:
                self.result.failed_step, self.result.reason = failed.step, failed.reason

    def _tidy_mailbox(self) -> None:
        try:
            self.mailbox.delete([m.id for m in self.mailbox.messages_to(self.address)])
        except Exception as exc:  # the lifecycle rule removes what this leaves
            log.warning("probe mailbox not tidied", extra={"error": type(exc).__name__})

    # ---- HTTP ----

    def _call(
        self,
        operation: str,
        method: str,
        path: str,
        expected: int,
        *,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        if method != "GET":
            kwargs.setdefault("json", {})
        headers = {**self._key, **kwargs.pop("headers", {})}
        response = self.api.request(
            method, path, headers=headers, timeout=timeout or httpx.USE_CLIENT_DEFAULT, **kwargs
        )
        if response.status_code != expected:
            raise StepFailedError("", f"{operation} answered {_problem(response)}")
        return response

    def _as_recipient(
        self, operation: str, method: str, path: str, expected: int, **kwargs: Any
    ) -> httpx.Response:
        """A recipient's browser: the link cookie, and on unsafe calls the web app's Origin and the
        link session's CSRF token; never the API key."""
        headers: dict[str, str] = {}
        if self._jar:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in self._jar.items() if v)
        if kwargs.pop("session", True) and self._session:
            headers["x-link-session"] = str(self._session["id"])
        if method != "GET":
            kwargs.setdefault("json", {})
            headers["origin"] = self.settings.probe_web_origin
            if self._session:
                headers["x-csrf-token"] = str(self._session["csrf_token"])
        response = self.api.request(method, path, headers=headers, **kwargs)
        self._jar.update(_cookies(response))
        if response.status_code != expected:
            raise StepFailedError("", f"{operation} answered {_problem(response)}")
        return response

    # ---- the steps ----

    def _edge(self) -> None:
        for path in INTERNAL_PATHS:
            response = self.api.get(path)
            if response.is_success:
                raise StepFailedError("", f"the public API serves an internal path ({path})")
        origin = self.settings.probe_web_origin
        if not origin.startswith("https://"):
            return  # the local stack: plain HTTP, no HSTS to check
        page = self.web.get(f"{origin}/")
        headers = page.headers
        if "strict-transport-security" not in headers:
            raise StepFailedError("", "the web app sends no Strict-Transport-Security")
        if "frame-ancestors" not in headers.get("content-security-policy", ""):
            raise StepFailedError("", "the web app's CSP has no frame-ancestors")
        if "referrer-policy" not in headers:
            raise StepFailedError("", "the web app sends no Referrer-Policy")

    def _create(self) -> str:
        created = self._call(
            "createTransfer",
            "POST",
            "/v1/transfers",
            201,
            json={
                "recipients": [{"email": self.address}],
                "expires_in": "PT1H",
                "download_limit": 1,
            },
        )
        return str(created.json()["id"])

    def _upload(self, transfer_id: str, data: bytes) -> str:
        declared = self._call(
            "addTransferFile",
            "POST",
            f"/v1/transfers/{transfer_id}/files",
            201,
            json={
                "display_name": f"probe-{self.run_id}.txt",
                "size": len(data),
                "content_type": "text/plain",
            },
        ).json()
        file_id = str(declared["id"])
        plan = declared["upload"]
        part_size, count = int(plan["part_size"]), int(plan["part_count"])
        urls = self._call(
            "requestUploadPartUrls",
            "POST",
            f"/v1/files/{file_id}/parts",
            200,
            json={"part_numbers": list(range(1, count + 1))},
        ).json()["parts"]
        for part in urls:
            n = int(part["part_number"])
            put = self.storage.put(
                self._part_url(str(part["url"])),
                content=data[(n - 1) * part_size : n * part_size],
                headers=part.get("headers") or {},
            )
            if put.status_code != 200:
                raise StepFailedError("", f"part {n} PUT answered {put.status_code}")
        self._call("completeUpload", "POST", f"/v1/files/{file_id}/complete", 200)
        return file_id

    def _part_url(self, url: str) -> str:
        host = self.settings.probe_part_url_host
        if host is None:
            return url
        parts = urlsplit(url)
        return f"{host}{parts.path}?{parts.query}" if parts.query else f"{host}{parts.path}"

    def _until_sent(self, transfer_id: str) -> None:
        def sent() -> bool | None:
            state = self._call("getTransfer", "GET", f"/v1/transfers/{transfer_id}", 200).json()[
                "state"
            ]
            if state in STOPPED:
                raise StepFailedError("", f"the transfer became {state}")
            return True if state == "sent" else None

        self._wait("shareable", sent)

    def _token(self) -> str | None:
        for message in self.mailbox.messages_to(self.address):
            token = mail.link_token(message.text)
            if token:
                return token
        return None

    def _codes(self) -> list[str]:
        found = (mail.code(m.text) for m in self.mailbox.messages_to(self.address))
        return [c for c in found if c]

    def _verify(self, token: str) -> None:
        resolved = self._as_recipient(
            "resolveLink", "POST", "/v1/links/resolve", 200, json={"token": token}
        )
        if resolved.json().get("access_state") != "verification_required":
            raise StepFailedError("", "resolveLink: the link didn't ask for verification")
        seen = len(self._codes())
        self._as_recipient(
            "requestVerificationCode", "POST", "/v1/links/codes", 202, json={"token": token}
        )

        def new_code() -> str | None:
            codes = self._codes()
            return codes[-1] if len(codes) > seen else None

        code = self._wait("code_email", new_code)
        session = self._as_recipient(
            "createLinkSession",
            "POST",
            "/v1/links/sessions",
            201,
            json={"token": token, "code": code},
        )
        self._session = dict(session.json())

    def _download(self, file_id: str, data: bytes) -> None:
        listed = self._as_recipient("listSessionFiles", "GET", "/v1/session/files", 200).json()
        if file_id not in {str(f["id"]) for f in listed.get("items", [])}:
            raise StepFailedError("", "listSessionFiles: the file isn't listed")
        grant = self._as_recipient(
            "createSessionDownload", "POST", f"/v1/session/files/{file_id}/downloads", 200
        ).json()
        url = urljoin(self.settings.probe_api_url, str(grant["url"]))
        cookie = "; ".join(f"{k}={v}" for k, v in self._jar.items() if v)
        digest = hashlib.sha256()
        asked = self.clock()
        with self.api.stream("GET", url, headers={"cookie": cookie}) as response:
            if response.status_code != 200:
                raise StepFailedError(
                    "", f"getSessionDownloadContent answered {response.status_code}"
                )
            for chunk in response.iter_bytes():
                if self.result.first_byte_seconds is None:
                    self.result.first_byte_seconds = round(self.clock() - asked, 3)
                digest.update(chunk)
        if digest.digest() != hashlib.sha256(data).digest():
            raise StepFailedError("", "the downloaded bytes differ from the uploaded ones")

    # ---- waiting ----

    def _wait[T](self, what: str, probe: Callable[[], T | None]) -> T:
        budget, waiting_for = WAIT[what]
        deadline = min(self._deadline, self.clock() + budget)
        while True:
            found = probe()
            if found is not None:
                return found
            if self.clock() + POLL_SECONDS > deadline:
                raise StepFailedError("", f"timed out waiting for {waiting_for}")
            self.sleep(POLL_SECONDS)
