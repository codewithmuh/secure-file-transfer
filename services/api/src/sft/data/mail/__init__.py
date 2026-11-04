"""The mail adapter: one interface, SES API v2 in AWS and SMTP for the local stack (ADR-0015).

The service layer renders an email (`sft.service.email`) and hands an `OutgoingEmail` to a
`Mailer`. A mailer only delivers: it never decides who may be emailed, and it never logs or raises
an address, a subject or a body. Its errors carry a kind and the provider's error code, nothing
the provider said, because a provider message can quote the address (ADR-0009, abuse 7.5).

Both adapters block. The notification worker calls them from its thread pool, as it calls SQS.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from sft.core.settings import MailSettings

# SES's rule for tag names and values; the SMTP adapter checks the same, so a test that passes
# locally doesn't fail in AWS.
_TAG = re.compile(r"[A-Za-z0-9_-]{1,256}")
_ADDRESS = re.compile(r"[^\s@<>\",;]+@[^\s@<>\",;]+")
_RESERVED_TAGS = frozenset({"tenant_id", "email_type"})


@dataclass(frozen=True, kw_only=True)
class OutgoingEmail:
    """One email to one address. The repr shows only what is safe to log."""

    tenant_id: UUID
    email_type: str
    to: str = field(repr=False)
    subject: str = field(repr=False)
    text: str = field(repr=False)
    html: str = field(repr=False)
    reply_to: str | None = field(default=None, repr=False)
    # Extra SES message tags, such as the recipient's row ID, so delivery events find their row.
    tags: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # The messages never include the values: an address is personal data.
        for name, address in (("to", self.to), ("reply_to", self.reply_to)):
            if address is not None and not _ADDRESS.fullmatch(address):
                raise ValueError(f"{name} must be one plain email address")
        if not self.subject or any(c in self.subject for c in "\r\n"):
            raise ValueError("subject must be one non-empty line")
        if not _TAG.fullmatch(self.email_type):
            raise ValueError("email_type must be a valid message tag value")
        for name, value in self.tags.items():
            if name in _RESERVED_TAGS or not (_TAG.fullmatch(name) and _TAG.fullmatch(value)):
                raise ValueError(f"tag {name!r} is reserved or not a valid message tag")

    def all_tags(self) -> dict[str, str]:
        """The tags every send carries: the tenant and the email type (ADR-0015), then the rest."""
        return {"tenant_id": str(self.tenant_id), "email_type": self.email_type, **self.tags}


class MailErrorKind(enum.StrEnum):
    THROTTLED = "throttled"  # the provider's rate or quota: back off and retry
    UNAVAILABLE = "unavailable"  # network, timeout or a provider fault: retry
    PAUSED = "paused"  # sending is paused for the tenant or the account: hold the tenant's email
    REJECTED = "rejected"  # this message will never be accepted: don't retry it


_RETRYABLE = frozenset({MailErrorKind.THROTTLED, MailErrorKind.UNAVAILABLE})


class MailError(Exception):
    """A send that failed. Raised `from None`: the provider's own error may quote the address."""

    def __init__(self, kind: MailErrorKind, code: str) -> None:
        super().__init__(f"{kind}: {code}")
        self.kind = kind
        self.code = code

    @property
    def retryable(self) -> bool:
        return self.kind in _RETRYABLE


class Mailer(Protocol):
    """Hands one email to the provider and returns the provider's message ID."""

    def send(self, email: OutgoingEmail) -> str: ...


def mailer_from_settings(settings: MailSettings) -> Mailer:
    """The adapter that `MAIL_BACKEND` names."""
    if settings.mail_backend == "ses":
        from sft.data.mail.ses import SesMailer

        return SesMailer.from_settings(settings)
    from sft.data.mail.smtp import SmtpMailer

    return SmtpMailer.from_settings(settings)


__all__ = [
    "MailError",
    "MailErrorKind",
    "Mailer",
    "OutgoingEmail",
    "mailer_from_settings",
]
