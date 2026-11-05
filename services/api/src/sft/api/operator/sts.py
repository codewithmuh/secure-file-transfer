"""The `Sts` seam over HTTPS: forwards an operator's signed `GetCallerIdentity` (authn-authz 8.2).

The request goes to the endpoint in the configuration, the regional STS endpoint by default, and
never to a host taken from the request. Only the headers `sft.service.operator_auth` chose are
sent, plus `Host`, which the operator signed and which must be the endpoint's own for STS to
accept the signature. No AWS credentials of the pod are involved: the operator's signature is the
credential.

The standard library's client runs in a thread, as boto3 does in the workers (ADR-0002): one call
per sign-in, so a thread is no cost, and no new dependency is needed.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit
from xml.etree import ElementTree

from sft.service.operator_auth import CallerIdentity, StsRefusedError, StsUnavailableError

TIMEOUT_SECONDS: Final = 5.0
MAX_RESPONSE_BYTES: Final = 64 * 1024
_NAMESPACE: Final = "{https://sts.amazonaws.com/doc/2011-06-15/}"


class HttpSts:
    """Sends signed requests to one STS endpoint, such as `https://sts.ap-northeast-1.amazonaws.com`."""

    def __init__(self, endpoint: str, *, timeout: float = TIMEOUT_SECONDS) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ValueError("the STS endpoint is an http(s) URL")
        self._url = f"{parts.scheme}://{parts.netloc}/"
        self.host = parts.netloc
        self._timeout = timeout

    async def get_caller_identity(self, headers: Mapping[str, str], body: str) -> CallerIdentity:
        return await asyncio.to_thread(self._send, dict(headers), body)

    def _send(self, headers: dict[str, str], body: str) -> CallerIdentity:
        request = urllib.request.Request(  # noqa: S310 - the URL is the configured endpoint
            self._url,
            data=body.encode(),
            headers={**headers, "Host": self.host},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                document = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if _throttled(exc):
                # Too many calls, not a bad signature: the operator retries later (503).
                raise StsUnavailableError("throttled") from None
            if 400 <= exc.code < 500:
                raise StsRefusedError(str(exc.code)) from None
            raise StsUnavailableError(str(exc.code)) from None
        except (OSError, TimeoutError) as exc:  # URLError is an OSError
            raise StsUnavailableError(type(exc).__name__) from None
        if len(document) > MAX_RESPONSE_BYTES:
            raise StsUnavailableError("response too large")
        return parse_identity(document)


def _throttled(error: urllib.error.HTTPError) -> bool:
    """STS's throttling: HTTP 429, or 400 with the error code `Throttling`."""
    if error.code == 429:
        return True
    if error.code != 400:
        return False
    try:
        root = ElementTree.fromstring(error.read(MAX_RESPONSE_BYTES))  # noqa: S314 - as below
    except (ElementTree.ParseError, OSError):
        return False
    return root.findtext(f"{_NAMESPACE}Error/{_NAMESPACE}Code") == "Throttling"


def parse_identity(document: bytes) -> CallerIdentity:
    """`Account` and `Arn` from STS's XML answer."""
    try:
        # The answer comes from the configured STS endpoint over TLS, and is size-capped;
        # ElementTree resolves no external entities, and expat limits entity expansion.
        root = ElementTree.fromstring(document)  # noqa: S314
    except ElementTree.ParseError:
        raise StsUnavailableError("unreadable response") from None
    result = root.find(f"{_NAMESPACE}GetCallerIdentityResult")
    account = None if result is None else result.findtext(f"{_NAMESPACE}Account")
    arn = None if result is None else result.findtext(f"{_NAMESPACE}Arn")
    if not account or not arn:
        raise StsUnavailableError("unexpected response")
    return CallerIdentity(account=account.strip(), arn=arn.strip())
