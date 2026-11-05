"""Test helpers for the operator API: signed STS requests, a fake STS, the environment's policy.

Requests are signed with botocore's own SigV4 signer and obviously fake credentials, as the
operator CLI would sign them with an operator's Identity Center credentials.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from sft.service.operator_auth import (
    GET_CALLER_IDENTITY,
    CallerIdentity,
    OperatorPolicy,
    StsRefusedError,
    StsUnavailableError,
)

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
ROLE = "AWSReservedSSO_Operator_0123456789abcdef"
BREAK_GLASS_ROLE = "AWSReservedSSO_BreakGlass_0123456789abcdef"
REGION = "ap-northeast-1"
AUDIENCE = "operator-api-dev"
OPERATOR_NAME = "alice@example.test"
STS_URL = f"https://sts.{REGION}.amazonaws.com/"

POLICY = OperatorPolicy(region=REGION, audience=AUDIENCE, account_id=ACCOUNT, role_name=ROLE)


def assumed_role(role: str = ROLE, account: str = ACCOUNT, name: str = OPERATOR_NAME) -> str:
    return f"arn:aws:sts::{account}:assumed-role/{role}/{name}"


def signed_headers(
    *,
    region: str = REGION,
    service: str = "sts",
    audience: str | None = AUDIENCE,
    url: str = STS_URL,
    body: str = GET_CALLER_IDENTITY,
) -> dict[str, str]:
    """A signed request's headers. A fresh session token each time, so each signature differs."""
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    if audience is not None:
        headers["X-SFT-Audience"] = audience
    request = AWSRequest(method="POST", url=url, data=body, headers=headers)
    credentials = Credentials("TESTKEYID0000000FAKE", "test-only-secret", secrets.token_hex(16))
    SigV4Auth(credentials, service, region).add_auth(request)
    return dict(request.headers.items())


@dataclass
class FakeSts:
    """Answers as STS would, or refuses, or is unreachable; records what it was sent."""

    arn: str = field(default_factory=assumed_role)
    account: str = ACCOUNT
    error: Exception | None = None
    calls: list[Mapping[str, str]] = field(default_factory=list)

    async def get_caller_identity(self, headers: Mapping[str, str], body: str) -> CallerIdentity:
        self.calls.append(dict(headers))
        if self.error is not None:
            raise self.error
        return CallerIdentity(account=self.account, arn=self.arn)


def refusing_sts() -> FakeSts:
    return FakeSts(error=StsRefusedError("403"))


def unreachable_sts() -> FakeSts:
    return FakeSts(error=StsUnavailableError("timeout"))
