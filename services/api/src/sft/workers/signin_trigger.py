"""The Cognito sign-in triggers' Lambda function (#238): `python -m sft.workers.signin_trigger`, the
API image's entry point for the function's container image.

One function serves both the pre-authentication and the post-authentication trigger; the event's
`triggerSource` picks the work (`sft.service.signin_triggers`). The image carries no Lambda runtime
client, so this module speaks the Lambda Runtime API itself: a loop that asks the runtime for the
next event (`AWS_LAMBDA_RUNTIME_API`), handles it, and posts the answer, or the error that makes
Cognito refuse the sign-in. It is a few lines of the standard library, and needs no dependency.

The process keeps one event loop, one counter store client and one SQS client between
invocations, so a warm function reuses its connections. Settings come from the function's
environment (`SignInTriggerSettings`); bad ones are reported to the runtime as an init error, and
every sign-in is then refused, which is the failure mode the design wants (fail closed).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import urllib.request
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Final

from prometheus_client import CollectorRegistry

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, SignInTriggerSettings, load_settings
from sft.data.counters import CounterMetrics, CounterStore, ValkeyIam
from sft.data.outbox import Queue
from sft.service.signin_triggers import SignInDenied, SignInTriggers
from sft.workers.queues import OutgoingMessage, Queues, SqsQueues

log = logging.getLogger(__name__)

RUNTIME_VERSION: Final = "2018-06-01"
REQUEST_ID: Final = "Lambda-Runtime-Aws-Request-Id"

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def sender(queues: Queues) -> Callable[[Sequence[tuple[str, int]]], Awaitable[None]]:
    """The triggers' `Send`: one batch to `signin-events`; any message SQS refused raises."""

    async def send(messages: Sequence[tuple[str, int]]) -> None:
        batch = [
            OutgoingMessage(id=f"m{index}", body=body, delay_seconds=delay)
            for index, (body, delay) in enumerate(messages)
        ]
        failed = await queues.send_batch(Queue.SIGNIN_EVENTS.value, batch)
        if failed:
            raise RuntimeError(f"SQS refused {len(failed)} sign-in events")

    return send


class RuntimeApi:
    """The Lambda Runtime API, on the function's local address. Calls run in a thread: the next
    invocation is a long poll, and the event loop keeps the clients' connections alive."""

    def __init__(self, address: str) -> None:
        self._base = f"http://{address}/{RUNTIME_VERSION}/runtime"

    def _call(self, path: str, body: bytes | None = None) -> tuple[dict[str, str], bytes]:
        request = urllib.request.Request(  # noqa: S310 - the runtime's own local http address
            self._base + path,
            data=body,
            method="GET" if body is None else "POST",
            headers={} if body is None else {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:  # noqa: S310 - as above
            return dict(response.headers.items()), response.read()

    async def next(self) -> tuple[str, bytes]:
        headers, body = await asyncio.to_thread(self._call, "/invocation/next")
        return headers[REQUEST_ID], body

    async def respond(self, request_id: str, result: object) -> None:
        body = json.dumps(result).encode()
        await asyncio.to_thread(self._call, f"/invocation/{request_id}/response", body)

    async def fail(self, request_id: str, error_type: str, message: str) -> None:
        body = json.dumps({"errorType": error_type, "errorMessage": message}).encode()
        await asyncio.to_thread(self._call, f"/invocation/{request_id}/error", body)

    async def init_failed(self, message: str) -> None:
        body = json.dumps({"errorType": "InitError", "errorMessage": message}).encode()
        await asyncio.to_thread(self._call, "/init/error", body)


async def serve(api: RuntimeApi, handler: Handler, *, invocations: int | None = None) -> None:
    """Handle invocations until the process ends (or `invocations` of them, for tests)."""
    done = 0
    while invocations is None or done < invocations:
        request_id, body = await api.next()
        try:
            event = json.loads(body)
            if not isinstance(event, dict):
                raise TypeError("a trigger event is a JSON object")
            result = await handler(event)
        except SignInDenied as denied:
            await api.fail(request_id, "SignInDenied", str(denied))
        except Exception:
            # Anything unexpected refuses the sign-in too, with the same message (fail closed).
            log.exception("sign-in trigger failed; sign-in denied")
            await api.fail(request_id, "SignInDenied", str(SignInDenied()))
        else:
            await api.respond(request_id, result)
        done += 1


async def run(settings: SignInTriggerSettings, api: RuntimeApi) -> int:
    metrics = CounterMetrics.create(CollectorRegistry())  # logged, not scraped, in Lambda
    store = CounterStore.connect(
        settings.valkey_url.get_secret_value(),
        metrics,
        iam=ValkeyIam.of(settings.valkey_iam_cache, settings.aws_region),
    )
    queues = SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
    )
    triggers = SignInTriggers(store, metrics, sender(queues))
    try:
        await serve(api, triggers.handle)
    finally:
        await queues.close()
        await store.close()
    return 0


def main() -> int:
    address = os.environ.get("AWS_LAMBDA_RUNTIME_API")
    if not address:
        print("AWS_LAMBDA_RUNTIME_API is unset: this runs as a Lambda function", file=sys.stderr)
        return EXIT_BAD_SETTINGS
    api = RuntimeApi(address)
    settings = load_settings(SignInTriggerSettings)
    if settings is None:
        asyncio.run(api.init_failed("invalid settings"))
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(run(settings, api))


if __name__ == "__main__":
    sys.exit(main())
