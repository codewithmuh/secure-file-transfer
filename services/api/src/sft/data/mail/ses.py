"""SES API v2 `SendEmail`, through boto3 (ADR-0015).

In AWS the notification worker reaches SES through the SES API's VPC endpoint, whose private DNS
name is the default endpoint, so no endpoint is configured here (ADR-0021). Credentials come from
the pod's identity, never from settings.
"""

from __future__ import annotations

import logging
from email.utils import formataddr
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.core.settings import MailSettings
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail

if TYPE_CHECKING:
    from types_boto3_sesv2.client import SESV2Client
    from types_boto3_sesv2.type_defs import SendEmailRequestTypeDef

log = logging.getLogger(__name__)

# NFR-7 hands an email to SES within 10 s at p95: short timeouts, and botocore's standard retries
# for throttling and faults, with the worker's own backoff after that. SendEmail takes no
# idempotency key, so a retry after a read timeout can send an email twice: sends are at least once.
_CONFIG = Config(
    connect_timeout=2,
    read_timeout=5,
    retries={"mode": "standard", "max_attempts": 3},
)

# SendEmail's errors (the SES API v2 reference), by what the worker should do.
_KINDS = {
    "TooManyRequestsException": MailErrorKind.THROTTLED,
    "LimitExceededException": MailErrorKind.THROTTLED,
    "Throttling": MailErrorKind.THROTTLED,
    "ThrottlingException": MailErrorKind.THROTTLED,
    "SendingPausedException": MailErrorKind.PAUSED,
    "AccountSuspendedException": MailErrorKind.PAUSED,
    # Only these say something about the message itself.
    "MessageRejected": MailErrorKind.REJECTED,
    "BadRequestException": MailErrorKind.REJECTED,
    # These fail every send until someone fixes our setup: an IAM regression, an expired pod
    # identity, a configuration set or SES tenant missing (after a failover to Osaka, say).
    "MailFromDomainNotVerifiedException": MailErrorKind.MISCONFIGURED,
    "NotFoundException": MailErrorKind.MISCONFIGURED,
    "AccessDeniedException": MailErrorKind.MISCONFIGURED,
    "AccessDenied": MailErrorKind.MISCONFIGURED,
    "ExpiredTokenException": MailErrorKind.MISCONFIGURED,
    "ExpiredToken": MailErrorKind.MISCONFIGURED,
    "UnrecognizedClientException": MailErrorKind.MISCONFIGURED,
    "InvalidClientTokenId": MailErrorKind.MISCONFIGURED,
    "InvalidSignatureException": MailErrorKind.MISCONFIGURED,
    "SignatureDoesNotMatch": MailErrorKind.MISCONFIGURED,
    "IncompleteSignature": MailErrorKind.MISCONFIGURED,
    "MissingAuthenticationTokenException": MailErrorKind.MISCONFIGURED,
}

_AUTO_SUBMITTED = {"Name": "Auto-Submitted", "Value": "auto-generated"}  # RFC 3834: no auto-replies


class SesMailer:
    def __init__(
        self,
        client: SESV2Client,
        *,
        from_header: str,
        configuration_set: str,
        name_tenants: bool,
    ) -> None:
        self._client = client
        self._from = from_header
        self._configuration_set = configuration_set
        self._name_tenants = name_tenants

    @classmethod
    def from_settings(cls, settings: MailSettings) -> SesMailer:
        if not settings.ses_configuration_set:  # the settings check this too
            raise ValueError("SES needs SES_CONFIGURATION_SET")
        client = boto3.client("sesv2", region_name=settings.ses_region, config=_CONFIG)
        return cls(
            client,
            from_header=formataddr((settings.mail_from_name, settings.mail_from_address)),
            configuration_set=settings.ses_configuration_set,
            name_tenants=settings.ses_tenants,
        )

    def request(self, email: OutgoingEmail) -> SendEmailRequestTypeDef:
        """The `SendEmail` parameters for `email`."""
        request: dict[str, Any] = {
            "FromEmailAddress": self._from,
            "Destination": {"ToAddresses": [email.to]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": email.subject, "Charset": "UTF-8"},
                    "Body": {
                        "Text": {"Data": email.text, "Charset": "UTF-8"},
                        "Html": {"Data": email.html, "Charset": "UTF-8"},
                    },
                    "Headers": [_AUTO_SUBMITTED],
                }
            },
            "ConfigurationSetName": self._configuration_set,
            "EmailTags": [{"Name": k, "Value": v} for k, v in email.all_tags().items()],
        }
        if email.reply_to:
            request["ReplyToAddresses"] = [email.reply_to]
        if self._name_tenants:
            # One SES tenant per tenant, named by its ID, created by createTenant (ADR-0015).
            request["TenantName"] = str(email.tenant_id)
        return request  # type: ignore[return-value]  # built as a dict to add keys conditionally

    def send(self, email: OutgoingEmail) -> str:
        try:
            response = self._client.send_email(**self.request(email))
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", "Unknown"))
            # An unknown code is retried, never dropped: the worker's retry cap and the
            # dead-letter queue end it if it never clears.
            kind = _KINDS.get(code, MailErrorKind.UNAVAILABLE)
            log.warning(
                "email not sent",
                extra={"provider": "ses", "email_type": email.email_type, "error": code},
            )
            raise MailError(kind, code) from None
        except BotoCoreError as exc:  # connection errors and timeouts, after botocore's retries
            code = type(exc).__name__
            log.warning(
                "email not sent",
                extra={"provider": "ses", "email_type": email.email_type, "error": code},
            )
            raise MailError(MailErrorKind.UNAVAILABLE, code) from None
        message_id = response["MessageId"]
        log.info(
            "email handed to the provider",
            extra={"provider": "ses", "email_type": email.email_type, "message_id": message_id},
        )
        return message_id
