"""A stand-in for GuardDuty Malware Protection for S3, for the compose stack and the tests (#234):
`python -m sft.workers.guardduty_standin`.

GuardDuty isn't available outside AWS, so locally this process plays its part for the
large-files bucket, closely enough that the scan worker's path is the one it takes in AWS:

1. Every `GUARDDUTY_POLL_SECONDS` it lists the bucket's object versions, as a protection plan sees
   each new object.
2. Each version without GuardDuty's tag (`GuardDutyMalwareScanStatus`) is read once and judged:
   `THREATS_FOUND` if it holds the EICAR test file's marker, otherwise `NO_THREATS_FOUND`. It is not
   an engine; it only lets the local flow end both ways.
3. It tags the version with the result, keeping its other tags, then sends the result event, as
   EventBridge delivers it, to the `guardduty-results` queue (`sft.service.guardduty.event_body`).
   Tag first, then event, as GuardDuty does; the worker retries an event whose tag it can't see.

It refuses to start unless `ENVIRONMENT` is local or test (`GuardDutyStandInSettings`). It never
deletes, and it writes nothing but its own tag.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import signal
import sys
import uuid
from collections.abc import AsyncIterator, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol

import boto3
from botocore.config import Config

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, GuardDutyStandInSettings, load_settings
from sft.data.outbox import Queue
from sft.service.guardduty import TAG, Status, event_body
from sft.workers.queues import OutgoingMessage, Queues, SqsQueues

log = logging.getLogger(__name__)

MARKER: Final = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
"""Part of the EICAR test file: enough to tell the test file from any other bytes."""
READ_CHUNK: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Version:
    key: str
    version_id: str


class StandInBucket(Protocol):
    """What the stand-in needs of the large-files bucket."""

    @property
    def name(self) -> str: ...

    async def versions(self) -> list[Version]: ...

    def read(self, version: Version) -> AsyncIterator[bytes]: ...

    async def tags(self, version: Version) -> Mapping[str, str]: ...

    async def put_tags(self, version: Version, tags: Mapping[str, str]) -> None: ...


async def judge(chunks: AsyncIterator[bytes]) -> Status:
    """`THREATS_FOUND` if the bytes hold the EICAR marker anywhere, chunk edges included."""
    tail = b""
    async for chunk in chunks:
        window = tail + chunk
        if MARKER in window:
            return Status.THREATS_FOUND
        tail = window[-(len(MARKER) - 1) :]
    return Status.NO_THREATS_FOUND


class GuardDutyStandIn:
    def __init__(
        self,
        bucket: StandInBucket,
        queues: Queues,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.bucket = bucket
        self.queues = queues
        self.clock = clock

    async def scan_new(self) -> list[tuple[Version, Status]]:
        """One pass: every version without GuardDuty's tag is judged, tagged and announced."""
        done = []
        for version in await self.bucket.versions():
            tags = await self.bucket.tags(version)
            if TAG in tags:
                continue
            status = await judge(self.bucket.read(version))
            await self.bucket.put_tags(version, {**tags, TAG: status.value})
            event_id = str(uuid.uuid4())
            body = event_body(
                event_id=event_id,
                bucket=self.bucket.name,
                key=version.key,
                version_id=version.version_id,
                status=status,
                time=self.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            failed = await self.queues.send_batch(
                Queue.GUARDDUTY_RESULTS.value, [OutgoingMessage(id="result", body=body)]
            )
            if failed:  # pragma: no cover - ElasticMQ refused it; the next pass won't retry it
                log.warning("result event not sent", extra={"code": failed[0].code})
            log.info("stand-in scan", extra={"status": status.value})
            done.append((version, status))
        return done

    async def run(self, stopping: asyncio.Event, poll_seconds: float) -> None:
        while not stopping.is_set():
            try:
                await self.scan_new()
            except Exception:  # keep polling: the stack may still be starting
                log.exception("stand-in pass failed; trying again")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stopping.wait(), poll_seconds)


class S3StandInBucket:
    """The large-files bucket in S3Mock, through boto3 in a thread pool."""

    def __init__(self, client: Any, name: str) -> None:
        self._client = client
        self._name = name
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="standin")

    @classmethod
    def create(cls, settings: GuardDutyStandInSettings) -> S3StandInBucket:
        config = Config(
            region_name=settings.aws_region,
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"mode": "standard", "max_attempts": 2},
        )
        client = boto3.session.Session().client(
            "s3", endpoint_url=settings.s3_endpoint_url, config=config
        )
        return cls(client, settings.s3_large_files_bucket)

    @property
    def name(self) -> str:
        return self._name

    async def _call(self, fn: Callable[..., Any], /, **kwargs: object) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, functools.partial(fn, **kwargs))

    async def versions(self) -> list[Version]:
        found: list[Version] = []
        marker: dict[str, str] = {}
        while True:
            page = await self._call(self._client.list_object_versions, Bucket=self._name, **marker)
            found += [
                Version(v["Key"], v["VersionId"])
                for v in page.get("Versions", [])
                if v.get("VersionId") not in (None, "null")
            ]
            if not page.get("IsTruncated"):
                return found
            marker = {
                "KeyMarker": page["NextKeyMarker"],
                "VersionIdMarker": page["NextVersionIdMarker"],
            }

    async def read(self, version: Version) -> AsyncIterator[bytes]:
        response = await self._call(
            self._client.get_object,
            Bucket=self._name,
            Key=version.key,
            VersionId=version.version_id,
        )
        body = response["Body"]
        try:
            while chunk := await asyncio.get_running_loop().run_in_executor(
                self._executor, body.read, READ_CHUNK
            ):
                yield chunk
        finally:
            body.close()

    async def tags(self, version: Version) -> Mapping[str, str]:
        response = await self._call(
            self._client.get_object_tagging,
            Bucket=self._name,
            Key=version.key,
            VersionId=version.version_id,
        )
        return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

    async def put_tags(self, version: Version, tags: Mapping[str, str]) -> None:
        await self._call(
            self._client.put_object_tagging,
            Bucket=self._name,
            Key=version.key,
            VersionId=version.version_id,
            Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]},
        )

    async def close(self) -> None:
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        self._client.close()


async def run_standin(settings: GuardDutyStandInSettings) -> int:
    bucket = S3StandInBucket.create(settings)
    queues = SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
    )
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopping.set)
    try:
        await GuardDutyStandIn(bucket, queues).run(stopping, settings.guardduty_poll_seconds)
    finally:
        await queues.close()
        await bucket.close()
    return 0


def main() -> int:
    settings = load_settings(GuardDutyStandInSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(run_standin(settings))


if __name__ == "__main__":
    sys.exit(main())
