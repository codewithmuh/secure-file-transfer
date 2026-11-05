"""The STS adapter (`sft.api.operator.sts`), against a local HTTP server standing in for STS."""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from sft.api.operator.sts import MAX_RESPONSE_BYTES, HttpSts, parse_identity
from sft.service.operator_auth import (
    GET_CALLER_IDENTITY,
    CallerIdentity,
    StsRefusedError,
    StsUnavailableError,
)

pytestmark = pytest.mark.anyio

ANSWER = b"""<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Operator_0123456789abcdef/alice</Arn>
    <UserId>AROAEXAMPLEEXAMPLE:alice</UserId>
    <Account>111111111111</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>0</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"""


class FakeStsHandler(BaseHTTPRequestHandler):
    status: ClassVar[int] = 200
    body: ClassVar[bytes] = ANSWER
    seen: ClassVar[list[tuple[str, dict[str, str], bytes]]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        FakeStsHandler.seen.append((self.path, dict(self.headers.items()), self.rfile.read(length)))
        self.send_response(self.status)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def sts_server() -> Iterator[str]:
    FakeStsHandler.status, FakeStsHandler.body, FakeStsHandler.seen = 200, ANSWER, []
    server = HTTPServer(("127.0.0.1", 0), FakeStsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


async def test_it_forwards_the_signed_request_to_its_own_endpoint(sts_server: str) -> None:
    sts = HttpSts(sts_server)
    identity = await sts.get_caller_identity(
        {"authorization": "AWS4-HMAC-SHA256 test", "x-sft-audience": "operator-api-dev"},
        GET_CALLER_IDENTITY,
    )
    assert identity == CallerIdentity(
        account="111111111111",
        arn="arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Operator_0123456789abcdef/alice",
    )
    [(path, headers, body)] = FakeStsHandler.seen
    assert (path, body) == ("/", GET_CALLER_IDENTITY.encode())
    # The host is the configured endpoint's, whatever the caller signed.
    received = {name.lower(): value for name, value in headers.items()}
    assert received["host"] == sts_server.removeprefix("http://")
    assert received["x-sft-audience"] == "operator-api-dev"


@pytest.mark.parametrize(("status", "error"), [(403, StsRefusedError), (503, StsUnavailableError)])
async def test_a_refusal_and_a_failure_are_told_apart(
    status: int, error: type[Exception], sts_server: str
) -> None:
    FakeStsHandler.status, FakeStsHandler.body = status, b"<ErrorResponse/>"
    with pytest.raises(error):
        await HttpSts(sts_server).get_caller_identity({}, GET_CALLER_IDENTITY)


THROTTLED = b"""<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error>
  <RequestId>0</RequestId>
</ErrorResponse>"""
DENIED = THROTTLED.replace(b"Throttling", b"SignatureDoesNotMatch")


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        (429, b"", StsUnavailableError),
        (400, THROTTLED, StsUnavailableError),
        (400, DENIED, StsRefusedError),
        (400, b"not xml", StsRefusedError),
        (403, THROTTLED, StsRefusedError),  # only a 400 or a 429 says throttled
    ],
)
async def test_throttling_is_a_failure_not_a_refusal(
    status: int, body: bytes, error: type[Exception], sts_server: str
) -> None:
    FakeStsHandler.status, FakeStsHandler.body = status, body
    with pytest.raises(error):
        await HttpSts(sts_server).get_caller_identity({}, GET_CALLER_IDENTITY)


async def test_an_oversized_answer_is_a_failure(sts_server: str) -> None:
    FakeStsHandler.body = b"x" * (MAX_RESPONSE_BYTES + 10)
    with pytest.raises(StsUnavailableError):
        await HttpSts(sts_server).get_caller_identity({}, GET_CALLER_IDENTITY)


async def test_an_endpoint_that_doesnt_answer_is_a_failure() -> None:
    with pytest.raises(StsUnavailableError):
        await HttpSts("http://127.0.0.1:1", timeout=1).get_caller_identity({}, GET_CALLER_IDENTITY)


@pytest.mark.parametrize(
    "document",
    [
        b"not xml",
        b"<GetCallerIdentityResponse/>",
        ANSWER.replace(b"<Account>111111111111</Account>", b""),
    ],
)
def test_an_answer_without_the_identity_is_a_failure(document: bytes) -> None:
    with pytest.raises(StsUnavailableError):
        parse_identity(document)


@pytest.mark.parametrize("endpoint", ["sts.amazonaws.com", "ftp://sts.example", "https://"])
def test_the_endpoint_is_an_http_url(endpoint: str) -> None:
    with pytest.raises(ValueError, match="http"):
        HttpSts(endpoint)
