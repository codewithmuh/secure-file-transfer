"""The mail adapter: SES API v2 against botocore's Stubber, SMTP against a fake. No network."""

import smtplib
from collections.abc import Callable, Iterator
from email.message import EmailMessage
from typing import Any
from uuid import UUID

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import EndpointConnectionError, ReadTimeoutError
from botocore.stub import Stubber

from sft.core.settings import MailSettings
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail, mailer_from_settings
from sft.data.mail.ses import SesMailer
from sft.data.mail.smtp import SmtpMailer

Logs = Callable[[], list[dict[str, object]]]

TENANT_ID = UUID("0d6f2a51-6c7e-4b1e-8f55-0a1b2c3d4e5f")
TO = "recipient@partner.example"
REPLY_TO = "sender@customer.example"
SECRET = "LINKtokenLINKtokenLINKtokenLINKtokenLINKtok"  # noqa: S105 - a fake link token
FROM = "Secure File Transfer <no-reply@mail.sft.example>"


def email(**changes: Any) -> OutgoingEmail:
    values: dict[str, Any] = {
        "tenant_id": TENANT_ID,
        "email_type": "transfer_link",
        "to": TO,
        "subject": "ファイルが届いています",
        "text": f"Open https://app.sft.example/t#{SECRET}\n",
        "html": f'<p><a href="https://app.sft.example/t#{SECRET}">Open</a></p>',
        "reply_to": REPLY_TO,
        "tags": {"recipient_id": "8b1d"},
    }
    values.update(changes)
    return OutgoingEmail(**values)


def settings(**env: Any) -> MailSettings:
    values: dict[str, Any] = {
        "mail_backend": "ses",
        "mail_from_address": "no-reply@mail.sft.example",
        "web_app_url": "https://app.sft.example",
        "ses_configuration_set": "sft-dev-ap-northeast-1",
    }
    values.update(env)
    return MailSettings(**values)


def assert_nothing_personal(text: str) -> None:
    for value in (TO, REPLY_TO, SECRET, "ファイル"):
        assert value not in text


# ---- the message ----


def test_outgoing_email_keeps_its_content_out_of_the_repr() -> None:
    shown = repr(email())
    assert_nothing_personal(shown)
    assert "transfer_link" in shown


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"to": "two@a.example, three@b.example"}, "to must be"),
        ({"to": "Name <x@y.example>"}, "to must be"),
        ({"reply_to": "not-an-address"}, "reply_to must be"),
        ({"subject": "one\r\nBcc: x@y.example"}, "subject must be"),
        ({"subject": ""}, "subject must be"),
        ({"email_type": "transfer link"}, "email_type must be"),
        ({"tags": {"tenant_id": "other"}}, "reserved"),
        ({"tags": {"recipient": "a b"}}, "reserved or not a valid"),
    ],
)
def test_outgoing_email_refuses_bad_values_without_echoing_them(
    changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message) as caught:
        email(**changes)
    assert "x@y.example" not in str(caught.value)
    assert "two@a.example" not in str(caught.value)


def test_mail_errors_say_whether_to_retry() -> None:
    assert MailError(MailErrorKind.THROTTLED, "x").retryable
    assert MailError(MailErrorKind.UNAVAILABLE, "x").retryable
    assert not MailError(MailErrorKind.PAUSED, "x").retryable
    assert not MailError(MailErrorKind.REJECTED, "x").retryable
    assert str(MailError(MailErrorKind.REJECTED, "MessageRejected")) == "rejected: MessageRejected"


# ---- SES API v2 ----


@pytest.fixture
def ses() -> Iterator[tuple[SesMailer, Stubber]]:
    # Fake credentials and no network: the Stubber answers every call.
    client = boto3.client(
        "sesv2",
        region_name="ap-northeast-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a fake key for the Stubber
        config=Config(retries={"max_attempts": 1}),
    )
    mailer = SesMailer(
        client, from_header=FROM, configuration_set="sft-dev-ap-northeast-1", name_tenants=True
    )
    with Stubber(client) as stubber:
        yield mailer, stubber
        stubber.assert_no_pending_responses()


def expected_request(**changes: Any) -> dict[str, Any]:
    out = email()
    request: dict[str, Any] = {
        "FromEmailAddress": FROM,
        "Destination": {"ToAddresses": [TO]},
        "ReplyToAddresses": [REPLY_TO],
        "Content": {
            "Simple": {
                "Subject": {"Data": out.subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": out.text, "Charset": "UTF-8"},
                    "Html": {"Data": out.html, "Charset": "UTF-8"},
                },
                "Headers": [{"Name": "Auto-Submitted", "Value": "auto-generated"}],
            }
        },
        "ConfigurationSetName": "sft-dev-ap-northeast-1",
        "EmailTags": [
            {"Name": "tenant_id", "Value": str(TENANT_ID)},
            {"Name": "email_type", "Value": "transfer_link"},
            {"Name": "recipient_id", "Value": "8b1d"},
        ],
        "TenantName": str(TENANT_ID),
    }
    request.update(changes)
    return request


def test_ses_sends_one_email_with_tags_and_the_tenant(
    ses: tuple[SesMailer, Stubber], json_logs: Logs
) -> None:
    mailer, stubber = ses
    stubber.add_response("send_email", {"MessageId": "0106-abc"}, expected_request())
    assert mailer.send(email()) == "0106-abc"
    [line] = json_logs()
    assert line["msg"] == "email handed to the provider"
    assert line["message_id"] == "0106-abc"
    assert_nothing_personal(str(line))


def test_ses_without_tenant_management_or_reply_to(ses: tuple[SesMailer, Stubber]) -> None:
    mailer, stubber = ses
    mailer._name_tenants = False
    request = expected_request()
    del request["TenantName"], request["ReplyToAddresses"]
    stubber.add_response("send_email", {"MessageId": "0106-def"}, request)
    assert mailer.send(email(reply_to=None)) == "0106-def"


@pytest.mark.parametrize(
    ("code", "status", "kind"),
    [
        ("TooManyRequestsException", 429, MailErrorKind.THROTTLED),
        ("LimitExceededException", 400, MailErrorKind.THROTTLED),
        ("SendingPausedException", 400, MailErrorKind.PAUSED),
        ("AccountSuspendedException", 400, MailErrorKind.PAUSED),
        ("MessageRejected", 400, MailErrorKind.REJECTED),
        ("MailFromDomainNotVerifiedException", 400, MailErrorKind.REJECTED),
        ("NotFoundException", 404, MailErrorKind.REJECTED),
        ("BadRequestException", 400, MailErrorKind.REJECTED),
        ("InternalFailure", 500, MailErrorKind.UNAVAILABLE),
        ("SomethingNew", 400, MailErrorKind.REJECTED),
    ],
)
def test_ses_errors_name_a_kind_and_never_the_address(
    ses: tuple[SesMailer, Stubber], json_logs: Logs, code: str, status: int, kind: MailErrorKind
) -> None:
    mailer, stubber = ses
    # SES messages can quote the address; none of it may reach the error or the logs.
    stubber.add_client_error(
        "send_email",
        service_error_code=code,
        service_message=f"Email address is not verified: {TO}",
        http_status_code=status,
    )
    with pytest.raises(MailError) as caught:
        mailer.send(email())
    assert caught.value.kind is kind
    assert caught.value.code == code
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    assert_nothing_personal(str(caught.value))
    [line] = json_logs()
    assert line["error"] == code
    assert_nothing_personal(str(line))


@pytest.mark.parametrize(
    "error",
    [
        EndpointConnectionError(endpoint_url="https://email.ap-northeast-1.amazonaws.com"),
        ReadTimeoutError(endpoint_url="https://email.ap-northeast-1.amazonaws.com"),
    ],
)
def test_ses_connection_errors_are_retryable(
    ses: tuple[SesMailer, Stubber], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    mailer, _ = ses

    def fail(**_: object) -> None:
        raise error

    monkeypatch.setattr(mailer._client, "send_email", fail)
    with pytest.raises(MailError) as caught:
        mailer.send(email())
    assert caught.value.kind is MailErrorKind.UNAVAILABLE
    assert caught.value.retryable
    assert caught.value.code == type(error).__name__


def test_ses_from_settings() -> None:
    mailer = mailer_from_settings(settings(ses_region="ap-northeast-3", mail_from_name="SFT"))
    assert isinstance(mailer, SesMailer)
    assert mailer._client.meta.region_name == "ap-northeast-3"
    assert mailer._from == "SFT <no-reply@mail.sft.example>"
    assert mailer._configuration_set == "sft-dev-ap-northeast-1"
    assert mailer._name_tenants is True


def test_ses_needs_a_configuration_set() -> None:
    with pytest.raises(ValueError, match="SES_CONFIGURATION_SET"):
        SesMailer.from_settings(settings(mail_backend="smtp", ses_configuration_set=None))


# ---- SMTP (Mailpit) ----


class FakeSmtp:
    sent: list[EmailMessage]
    error: Exception | None = None
    opened: list[tuple[str, int, float]]

    def __init__(self, host: str, port: int, timeout: float) -> None:
        type(self).opened.append((host, port, timeout))

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def send_message(self, message: EmailMessage) -> None:
        if self.error is not None:
            raise self.error
        type(self).sent.append(message)


@pytest.fixture
def fake_smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSmtp]:
    FakeSmtp.sent = []
    FakeSmtp.opened = []
    FakeSmtp.error = None
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    return FakeSmtp


def smtp_mailer() -> SmtpMailer:
    mailer = mailer_from_settings(settings(mail_backend="smtp", smtp_host="mail", smtp_port=2525))
    assert isinstance(mailer, SmtpMailer)
    return mailer


def test_smtp_sends_a_multipart_message(fake_smtp: type[FakeSmtp], json_logs: Logs) -> None:
    message_id = smtp_mailer().send(email())
    assert fake_smtp.opened == [("mail", 2525, 5)]
    [message] = fake_smtp.sent
    assert message["From"] == FROM
    assert message["To"] == TO
    assert message["Reply-To"] == REPLY_TO
    assert message["Subject"] == "ファイルが届いています"
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["X-Sft-Tag-tenant_id"] == str(TENANT_ID)
    assert message["X-Sft-Tag-email_type"] == "transfer_link"
    assert message["Message-ID"] == message_id
    assert message_id.endswith("@mail.sft.example>")
    assert message.get_content_type() == "multipart/alternative"
    text, html = message.iter_parts()
    assert text.get_content_type() == "text/plain"
    assert html.get_content_type() == "text/html"
    assert SECRET in text.get_content()  # type: ignore[attr-defined]
    [line] = json_logs()
    assert line["provider"] == "smtp"
    assert_nothing_personal(str(line))


def test_smtp_without_reply_to(fake_smtp: type[FakeSmtp]) -> None:
    smtp_mailer().send(email(reply_to=None))
    assert "Reply-To" not in fake_smtp.sent[0]


@pytest.mark.parametrize(
    ("error", "kind", "code"),
    [
        (
            smtplib.SMTPRecipientsRefused({TO: (550, b"no such user " + TO.encode())}),
            MailErrorKind.REJECTED,
            "SMTPRecipientsRefused",
        ),
        (smtplib.SMTPDataError(554, b"rejected"), MailErrorKind.REJECTED, "SMTPDataError:554"),
        (smtplib.SMTPDataError(451, b"try later"), MailErrorKind.UNAVAILABLE, "SMTPDataError:451"),
        (
            smtplib.SMTPSenderRefused(553, b"no", "x@y.example"),
            MailErrorKind.REJECTED,
            "SMTPSenderRefused:553",
        ),
        (
            smtplib.SMTPServerDisconnected("gone"),
            MailErrorKind.UNAVAILABLE,
            "SMTPServerDisconnected",
        ),
        (
            ConnectionRefusedError(61, "refused"),
            MailErrorKind.UNAVAILABLE,
            "ConnectionRefusedError",
        ),
        (TimeoutError("timed out"), MailErrorKind.UNAVAILABLE, "TimeoutError"),
    ],
)
def test_smtp_errors_name_a_kind_and_never_the_address(
    fake_smtp: type[FakeSmtp], json_logs: Logs, error: Exception, kind: MailErrorKind, code: str
) -> None:
    fake_smtp.error = error
    with pytest.raises(MailError) as caught:
        smtp_mailer().send(email())
    assert (caught.value.kind, caught.value.code) == (kind, code)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    assert_nothing_personal(str(caught.value))
    [line] = json_logs()
    assert_nothing_personal(str(line))
