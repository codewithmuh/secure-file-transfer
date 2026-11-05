"""SQS, behind a thin adapter (ADR-0013; delivery plan risk "local emulators differ from AWS").

Workers talk to `Queues`, never to boto3. `SqsQueues` is the real one, for AWS and for ElasticMQ
locally; the tests use an in-memory fake, and one integration test runs `SqsQueues` against
ElasticMQ. Queues are named by `sft.data.outbox.Queue` and the environment's prefix
(`sft-dev-notify`), and their URLs are looked up once.

**boto3 in a thread pool, not an async client.** boto3 is synchronous (ADR-0002), so each call runs
in a small thread pool that this adapter owns, never in the event loop. The async alternative,
aiobotocore, pins botocore to a narrow range a few releases behind boto3's, and the service needs
boto3 anyway (M4 signs IAM database tokens with it), so the two would have to move in lockstep. The
relay makes about one call a second at design load (capacity 3.1), far too few for threads to
cost anything, and a consumer's 20-second long poll holds one thread, not the loop.

Timeouts are short and retries few, so a call ends well inside the 10 seconds a transaction may sit
idle (data model 2.5): the relay holds its claimed rows' locks across the send.

Each call is a CLIENT span (`sft.core.telemetry.trace_aws_client`) under the span it was made in:
the thread pool runs it in a copy of the caller's context, as `asyncio.to_thread` would. A long
poll (`ReceiveMessage`) has none: it lasts up to 20 s with or without a message and would make a
slow trace of its own every time, which the gateway keeps (ADR-0009). A message's trace goes on
in the consumer's span instead.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.core.telemetry import trace_aws_client

if TYPE_CHECKING:
    from types_boto3_sqs.client import SQSClient
    from types_boto3_sqs.type_defs import SendMessageBatchRequestEntryTypeDef

MAX_BATCH = 10
"""SQS's limit on messages in one SendMessageBatch call."""


class QueueError(Exception):
    """A call to SQS failed as a whole. `code` is SQS's error code or the client's error type.

    `sender_fault` means SQS refused the request itself (a 400 that isn't throttling), such as a
    batch with one message too long: sending the same request again would fail again.
    """

    def __init__(self, code: str, *, sender_fault: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.sender_fault = sender_fault


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    id: str
    """Unique within one batch; the relay uses the outbox row's ID."""
    body: str
    delay_seconds: int = 0
    group_id: str | None = None
    """The message group of a fair queue: the tenant (ADR-0013). None on other queues."""


@dataclass(frozen=True, slots=True)
class SendFailure:
    id: str
    code: str


@dataclass(frozen=True, slots=True)
class ReceivedMessage:
    body: str
    receipt_handle: str
    receive_count: int
    """How many times SQS has handed this message out, this time included."""


class Queues(Protocol):
    async def send_batch(
        self, queue: str, messages: Sequence[OutgoingMessage]
    ) -> list[SendFailure]:
        """Send up to 10 messages to `queue`; the ones that failed, or `QueueError` for all."""
        ...

    async def receive(
        self, queue: str, *, max_messages: int, wait_seconds: int
    ) -> list[ReceivedMessage]:
        """Up to `max_messages`, waiting up to `wait_seconds` for the first (long polling)."""
        ...

    async def delete(self, queue: str, receipt_handle: str) -> None: ...

    async def close(self) -> None: ...


_QUEUE_MISSING = frozenset(
    {"QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue", "NonExistentQueue"}
)


def _queue_error(exc: ClientError | BotoCoreError) -> QueueError:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", "ClientError"))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 500)
        # Throttling passes, and a missing queue fails every message alike: neither is about one
        # message in the batch, so neither is worth sending row by row.
        whole_queue = "throttl" in code.lower() or code in _QUEUE_MISSING
        return QueueError(code, sender_fault=status == 400 and not whole_queue)
    return QueueError(type(exc).__name__)


class SqsQueues:
    """`Queues` through boto3, each call in this adapter's own thread pool."""

    def __init__(self, client: SQSClient, prefix: str, *, threads: int) -> None:
        self._client = client
        self._prefix = prefix
        self._executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="sqs")
        self._urls: dict[str, str] = {}

    @classmethod
    def create(
        cls,
        *,
        region: str,
        prefix: str,
        endpoint_url: str | None = None,
        read_timeout: float = 3.0,
        threads: int = 4,
    ) -> SqsQueues:
        """A client for one environment's queues. Credentials come from the pod's IAM role.

        A consumer that long-polls needs `read_timeout` above its wait (20 s); the relay keeps the
        default, so a send gives up in seconds.
        """
        config = Config(
            region_name=region,
            connect_timeout=1,
            read_timeout=read_timeout,
            retries={"mode": "standard", "max_attempts": 2},
            max_pool_connections=threads,
        )
        client = boto3.session.Session().client("sqs", endpoint_url=endpoint_url, config=config)
        trace_aws_client(client, untraced={"ReceiveMessage"})
        return cls(client, prefix, threads=threads)

    async def _call[T](self, fn: Callable[..., T], /, **kwargs: object) -> T:
        loop = asyncio.get_running_loop()
        # In the caller's context, so the call's span is a child of the caller's (module docstring).
        call = functools.partial(contextvars.copy_context().run, fn, **kwargs)
        try:
            return await loop.run_in_executor(self._executor, call)
        except (ClientError, BotoCoreError) as exc:
            raise _queue_error(exc) from exc

    async def resolve(self, queues: Iterable[str]) -> None:
        """Look up and cache the queues' URLs at startup, not inside the relay's first batch."""
        for queue in queues:
            await self._url(queue)

    async def _url(self, queue: str) -> str:
        if queue not in self._urls:
            response = await self._call(self._client.get_queue_url, QueueName=self._prefix + queue)
            self._urls[queue] = response["QueueUrl"]
        return self._urls[queue]

    async def send_batch(
        self, queue: str, messages: Sequence[OutgoingMessage]
    ) -> list[SendFailure]:
        if not 1 <= len(messages) <= MAX_BATCH:
            raise ValueError(f"send 1 to {MAX_BATCH} messages at a time")
        entries: list[SendMessageBatchRequestEntryTypeDef] = []
        for message in messages:
            entry: SendMessageBatchRequestEntryTypeDef = {
                # Batch entry IDs allow only letters, digits, hyphens and underscores.
                "Id": message.id,
                "MessageBody": message.body,
                "DelaySeconds": message.delay_seconds,
            }
            if message.group_id is not None:
                entry["MessageGroupId"] = message.group_id
            entries.append(entry)
        url = await self._url(queue)
        response = await self._call(self._client.send_message_batch, QueueUrl=url, Entries=entries)
        return [SendFailure(f["Id"], f.get("Code", "Failed")) for f in response.get("Failed", [])]

    async def receive(
        self, queue: str, *, max_messages: int, wait_seconds: int
    ) -> list[ReceivedMessage]:
        url = await self._url(queue)
        response = await self._call(
            self._client.receive_message,
            QueueUrl=url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=wait_seconds,
            MessageSystemAttributeNames=["ApproximateReceiveCount"],
        )
        return [
            ReceivedMessage(
                body=m["Body"],
                receipt_handle=m["ReceiptHandle"],
                receive_count=int(m.get("Attributes", {}).get("ApproximateReceiveCount", "1")),
            )
            for m in response.get("Messages", [])
        ]

    async def delete(self, queue: str, receipt_handle: str) -> None:
        url = await self._url(queue)
        await self._call(self._client.delete_message, QueueUrl=url, ReceiptHandle=receipt_handle)

    async def close(self) -> None:
        """Wait for calls in flight, then close the client. Call it once, at shutdown."""
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        self._client.close()
