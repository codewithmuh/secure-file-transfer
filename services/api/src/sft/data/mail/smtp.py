"""SMTP for the local stack's Mailpit, which catches every message (local development, Email).

Plain SMTP with no TLS and no sign-in, because Mailpit listens only on the laptop or the CI
runner. It is never used in AWS: there `MAIL_BACKEND` is `ses` (ADR-0015).
"""

from __future__ import annotations

import logging
import smtplib
import uuid
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from typing import NoReturn

from sft.core.settings import MailSettings
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail

log = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5


class SmtpMailer:
    def __init__(self, *, host: str, port: int, from_header: str, from_domain: str) -> None:
        self._host = host
        self._port = port
        self._from = from_header
        self._domain = from_domain

    @classmethod
    def from_settings(cls, settings: MailSettings) -> SmtpMailer:
        return cls(
            host=settings.smtp_host,
            port=settings.smtp_port,
            from_header=formataddr((settings.mail_from_name, settings.mail_from_address)),
            from_domain=settings.mail_from_address.rpartition("@")[2],
        )

    def message(self, email: OutgoingEmail) -> EmailMessage:
        """The MIME message: plain text first, then the HTML alternative."""
        message = EmailMessage()
        message["From"] = self._from
        message["To"] = email.to
        if email.reply_to:
            message["Reply-To"] = email.reply_to
        message["Subject"] = email.subject
        message["Date"] = formatdate(usegmt=True)
        message["Message-ID"] = f"<{uuid.uuid4()}@{self._domain}>"
        message["Auto-Submitted"] = "auto-generated"
        # SES records tags with each event; here they are headers, so tests can read them back.
        for name, value in email.all_tags().items():
            message[f"X-Sft-Tag-{name}"] = value
        message.set_content(email.text, cte="quoted-printable")
        message.add_alternative(email.html, subtype="html", cte="quoted-printable")
        return message

    def release(self, tenant_id: uuid.UUID, address: str) -> None:
        """Nothing to release: the local mail catcher keeps no suppression list."""

    def send(self, email: OutgoingEmail) -> str:
        try:
            message = self.message(email)
        except ValueError as exc:  # a header the email package refuses: this message never goes
            self._fail(email, MailErrorKind.REJECTED, exc)
        smtp = smtplib.SMTP(timeout=_TIMEOUT_SECONDS)
        try:
            code, reply = smtp.connect(self._host, self._port)
            if (
                code != 220
            ):  # what SMTP(host, port) would raise, but with `smtp` still ours to close
                raise smtplib.SMTPConnectError(code, reply)
            smtp.send_message(message)
        except (
            smtplib.SMTPConnectError
        ) as exc:  # the greeting refused us: the server, not the message
            self._fail(email, None, exc)
        except smtplib.SMTPResponseException as exc:  # sender refused, data refused, …
            self._fail(email, _kind(exc.smtp_code), exc)
        except smtplib.SMTPRecipientsRefused as exc:  # its message holds the address
            codes = [code for code, _ in exc.recipients.values()]
            self._fail(email, _kind(min(codes, default=550)), exc)
        except (OSError, smtplib.SMTPException) as exc:  # connection refused, timeout, …
            self._fail(email, None, exc)
        finally:
            _quit(smtp)
        message_id = str(message["Message-ID"])
        log.info(
            "email handed to the provider",
            extra={"provider": "smtp", "email_type": email.email_type, "message_id": message_id},
        )
        return message_id

    @staticmethod
    def _fail(email: OutgoingEmail, kind: MailErrorKind | None, exc: Exception) -> NoReturn:
        code = type(exc).__name__
        if isinstance(exc, smtplib.SMTPResponseException):
            code = f"{code}:{exc.smtp_code}"
        log.warning(
            "email not sent",
            extra={"provider": "smtp", "email_type": email.email_type, "error": code},
        )
        raise MailError(kind or MailErrorKind.UNAVAILABLE, code) from None


def _kind(smtp_code: int) -> MailErrorKind | None:
    """A 5xx refusal is permanent; a 4xx one is temporary, so the send is retried."""
    return MailErrorKind.REJECTED if smtp_code >= 500 else None


def _quit(smtp: smtplib.SMTP) -> None:
    """End the session. Once the server has accepted the message, a failed QUIT changes nothing:
    raising here would send the email again."""
    try:
        smtp.quit()
    except (OSError, smtplib.SMTPException):
        smtp.close()
