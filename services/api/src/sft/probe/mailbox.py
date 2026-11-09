"""The probe's mailbox: where the link and code emails to its address land.

- **In AWS**, SES receives mail for the probe domain (an MX record and a receipt rule) and writes
  each message, raw, to the mailbox bucket under `probe/` (docs/runbooks/synthetic-probe.md).
  `S3Mailbox` lists that prefix, reads each new object once, keeps those addressed to this run,
  and deletes them when the run ends; a lifecycle rule removes anything older than a day.
- **Locally**, the notification worker's mail goes to Mailpit, and `MailpitMailbox` searches it.

Only two things are read out of a message: the link token after `/t#` and a verification code.
Neither is ever logged (architecture 5.5).
"""

from __future__ import annotations

import email
import email.policy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Any, Final, Protocol

import boto3
import httpx2 as httpx
from botocore.config import Config

LINK_TOKEN: Final = re.compile(r"/t#([A-Za-z0-9_-]{22,128})")
CODE: Final = re.compile(r"(?<![0-9])([0-9]{6,10})(?![0-9])")


@dataclass(frozen=True, slots=True)
class Mail:
    id: str
    text: str


def link_token(text: str) -> str | None:
    found = LINK_TOKEN.search(text)
    return found.group(1) if found else None


def code(text: str) -> str | None:
    """The code in a verification email; never a link email's digits (a date, say)."""
    if LINK_TOKEN.search(text):
        return None
    found = CODE.search(text)
    return found.group(1) if found else None


class Mailbox(Protocol):
    def messages_to(self, address: str) -> list[Mail]:
        """Every message to `address` now in the mailbox, oldest first."""
        ...

    def delete(self, ids: Sequence[str]) -> None: ...

    def close(self) -> None: ...


class MailpitMailbox:
    """Mailpit's HTTP API: the local stack's inbox (docs/local-development.md)."""

    def __init__(self, base_url: str, *, transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(base_url=base_url, timeout=15, transport=transport)

    def messages_to(self, address: str) -> list[Mail]:
        found = self._http.get("/api/v1/search", params={"query": f'to:"{address}"', "limit": 50})
        found.raise_for_status()
        mails = []
        for message in reversed(found.json().get("messages") or []):
            body = self._http.get(f"/api/v1/message/{message['ID']}")
            body.raise_for_status()
            mails.append(Mail(str(message["ID"]), str(body.json().get("Text") or "")))
        return mails

    def delete(self, ids: Sequence[str]) -> None:
        if ids:
            self._http.request("DELETE", "/api/v1/messages", json={"IDs": list(ids)})

    def close(self) -> None:
        self._http.close()


class _S3Client(Protocol):
    """The calls of boto3's S3 client the mailbox makes."""

    def list_objects_v2(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def delete_objects(self, **kwargs: Any) -> Mapping[str, Any]: ...


def parse_raw(raw: bytes) -> tuple[set[str], str]:
    """The recipients and the plain text of one raw message, as SES stores it."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(message, EmailMessage)  # noqa: S101 - the default policy's class
    recipients = {
        address.lower()
        for _, address in getaddresses(
            [str(v) for header in ("to", "cc") for v in message.get_all(header, [])]
        )
        if address
    }
    part = message.get_body(preferencelist=("plain", "html"))
    text = part.get_content() if part is not None else ""
    return recipients, str(text)


class S3Mailbox:
    """The SES receipt rule's bucket and prefix: one object per received message."""

    def __init__(self, client: _S3Client, bucket: str, prefix: str) -> None:
        self._client = client
        self._bucket = bucket
        self._prefix = prefix
        self._seen: dict[str, tuple[set[str], str]] = {}

    @classmethod
    def create(
        cls, *, region: str, bucket: str, prefix: str, endpoint_url: str | None = None
    ) -> S3Mailbox:
        client: Any = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=endpoint_url,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5),
        )
        return cls(client, bucket, prefix)

    def _keys(self) -> list[tuple[str, Any]]:
        keys: list[tuple[str, Any]] = []
        token: str | None = None
        while True:
            page = self._client.list_objects_v2(
                Bucket=self._bucket,
                Prefix=self._prefix,
                **({"ContinuationToken": token} if token else {}),
            )
            keys += [(o["Key"], o.get("LastModified")) for o in page.get("Contents", [])]
            token = page.get("NextContinuationToken")
            if not token:
                return keys

    def messages_to(self, address: str) -> list[Mail]:
        wanted = address.lower()
        found = []
        for key, modified in self._keys():
            if key not in self._seen:
                body = self._client.get_object(Bucket=self._bucket, Key=key)["Body"]
                self._seen[key] = parse_raw(body.read())
            recipients, text = self._seen[key]
            if wanted in recipients:
                found.append((modified, Mail(key, text)))
        found.sort(key=lambda pair: (pair[0] is None, pair[0]))
        return [mail for _, mail in found]

    def delete(self, ids: Sequence[str]) -> None:
        if ids:
            self._client.delete_objects(
                Bucket=self._bucket, Delete={"Objects": [{"Key": k} for k in ids], "Quiet": True}
            )

    def close(self) -> None:
        self._seen.clear()
