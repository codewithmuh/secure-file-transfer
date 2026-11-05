"""The SMTP adapter delivers to a real Mailpit, the local stack's mail catcher (#100).

Runs when TEST_MAIL_CATCHER_URL (Mailpit's API) and TEST_SMTP_PORT are set, as in CI's mail job,
or after `make up`: TEST_MAIL_CATCHER_URL=http://127.0.0.1:8025 TEST_SMTP_PORT=1025. Each test sends
to an address of its own, so a shared Mailpit with other messages in it is fine.
"""

import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from typing import Any
from uuid import UUID

import pytest

from email_samples import CODE, LINK_TOKEN, ORIGIN, SAMPLES, SENDER, TENANT
from sft.core.settings import MailSettings
from sft.data.mail import MailError, MailErrorKind, mailer_from_settings
from sft.service.email import EmailRenderer
from sft.service.email.catalog import EmailType, Locale

TENANT_ID = UUID("0d6f2a51-6c7e-4b1e-8f55-0a1b2c3d4e5f")


@pytest.fixture(scope="module")
def catcher() -> tuple[str, str, int]:
    api = os.environ.get("TEST_MAIL_CATCHER_URL")
    port = os.environ.get("TEST_SMTP_PORT")
    if not api or not port:
        if os.environ.get("MAIL_TESTS_REQUIRED") == "1":  # CI's mail job: never skip silently
            pytest.fail("TEST_MAIL_CATCHER_URL and TEST_SMTP_PORT must be set")
        pytest.skip("set TEST_MAIL_CATCHER_URL and TEST_SMTP_PORT to a Mailpit (make up)")
    return api.rstrip("/"), os.environ.get("TEST_SMTP_HOST", "127.0.0.1"), int(port)


def get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - a local test URL
        return json.load(response)


def wait_for(api: str, address: str) -> dict[str, Any]:
    """The one message Mailpit holds for `address`, with its text, HTML and headers."""
    query = urllib.parse.urlencode({"query": f'to:"{address}"'})
    for _ in range(50):
        found = get(f"{api}/api/v1/search?{query}")["messages"]
        if found:
            [summary] = found
            message: dict[str, Any] = get(f"{api}/api/v1/message/{summary['ID']}")
            message["headers"] = get(f"{api}/api/v1/message/{summary['ID']}/headers")
            return message
        time.sleep(0.1)
    raise AssertionError("Mailpit never got the message")


def mailer_for(host: str, port: int) -> Any:
    settings = MailSettings(
        mail_backend="smtp",
        mail_from_address="no-reply@mail.sft.localhost",
        web_app_url=ORIGIN,
        smtp_host=host,
        smtp_port=port,
    )
    return mailer_from_settings(settings)


@pytest.mark.parametrize(
    ("email_type", "locale", "secret"),
    [
        (EmailType.TRANSFER_LINK, Locale.JA, LINK_TOKEN),
        (EmailType.VERIFICATION_CODE, Locale.EN, CODE),
    ],
)
def test_smtp_delivers_to_mailpit(
    catcher: tuple[str, str, int], email_type: EmailType, locale: Locale, secret: str
) -> None:
    api, host, port = catcher
    to = f"recipient-{secrets.token_hex(6)}@partner.example"
    renderer = EmailRenderer(ORIGIN)
    outgoing = renderer.compose(SAMPLES[email_type], locale, to=to, tenant_id=TENANT_ID)
    rendered = renderer.render(SAMPLES[email_type], locale)

    message_id = mailer_for(host, port).send(outgoing)

    got = wait_for(api, to)
    assert f"<{got['MessageID']}>" == message_id
    assert got["Subject"] == rendered.subject  # UTF-8 subjects survive the encoding
    assert got["From"] == {"Name": "Secure File Transfer", "Address": "no-reply@mail.sft.localhost"}
    assert [r["Address"] for r in got["To"]] == [to]
    assert got["Text"].replace("\r\n", "\n").strip() == rendered.text.strip()  # SMTP sends CRLF
    assert secret in got["Text"]
    assert secret in got["HTML"]
    assert TENANT in got["Text"]
    assert got["Attachments"] == []
    headers = got["headers"]
    assert headers["Auto-Submitted"] == ["auto-generated"]
    # Mailpit shows header names in canonical case; header names don't depend on case.
    tags = {name.lower(): value for name, value in headers.items()}
    assert tags["x-sft-tag-tenant_id"] == [str(TENANT_ID)]
    assert tags["x-sft-tag-email_type"] == [email_type.value]
    if email_type is EmailType.TRANSFER_LINK:
        assert [r["Address"] for r in got["ReplyTo"]] == [SENDER]
    else:
        assert got["ReplyTo"] == []


def test_smtp_reports_a_closed_port_as_unavailable(catcher: tuple[str, str, int]) -> None:
    _, host, _ = catcher
    outgoing = EmailRenderer(ORIGIN).compose(
        SAMPLES[EmailType.TRANSFER_HELD], Locale.EN, to="m@customer.example", tenant_id=TENANT_ID
    )
    with pytest.raises(MailError) as caught:
        mailer_for(host, 1).send(outgoing)  # nothing listens on port 1
    assert caught.value.kind is MailErrorKind.UNAVAILABLE
