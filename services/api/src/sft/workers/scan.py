"""The scan worker: `python -m sft.workers.scan`, one per pool (`SCAN_POOL`), on the scan nodes
(ADR-0019, ADR-0022; architecture 4.1, 4.6; #175, #176).

For each `file.scan` (small pool) or `file.scan_large` (large pool) message:

1. **Re-read the file** in the message's tenant scope; the message is only a prompt (T-50). A file
   that isn't `scanning` any more has its tag and its transfer's evaluation made good (both are
   safe to repeat), and the message is done.
2. **The tenant's cap.** A tenant runs at most 4 small-file scans at once, and one fewer
   large-file scans than the large pool has workers (at least one), counted with leases in the
   counter store. A scan over the cap is written to the outbox again, delayed 30 seconds, in the
   transaction that records this message as processed; the message is then deleted, never put
   back by changing its visibility, so no deferred scan nears the dead-letter queue. Without the
   counter store the caps are skipped (ADR-0019).
3. **One read, two engines.** The worker reads the object version recorded at completion, never
   the latest, and tees each chunk to clamd (`INSTREAM`, `sft.workers.clamd`) and to the DLP
   inspector (`sft.dlp.client`) at once. The inspector may stop after the first 64 KiB of a type it
   can't read; clamd still gets every byte. The read follows clamd, never the inspector: the
   inspector may fall 64 MiB behind, and if it stays that far behind for 30 seconds it is dropped
   for the attempt (a failed inspection), so a slow inspector can't make clamd time out. Each
   engine has a timeout that grows with the file's size (`sft.service.scan_timing`). No
   transaction is open meanwhile (data model 2.5).
4. **Map the answers** (ADR-0019, abuse 6.4): clean, infected, or unscannable for encrypted
   content and every limit alert. The inspector's answer is checked against its schema; an error,
   a crash, a timeout or an answer that breaks the schema is a failed attempt, as is any clamd
   error or timeout. A failed attempt raises, and SQS delivers the message again after its
   visibility timeout. On the last receive (the 5th) the worker records what it has instead:
   `scan_failed` if clamd never answered, otherwise clamd's result with the inspection `failed`.
   An infected file needs no inspection: it is recorded at once, its inspection `skipped`.
5. **Record** the result, the inspection and the findings, with the audit event and the message's
   `processed_messages` row, in one transaction, only while the file is still `scanning`
   (`sft.service.scans.record`). A duplicate does the work once; a result after `scan_failed`
   changes nothing.
6. **Then the tag, then the evaluation.** After the commit, the `scan` tag is set on the version,
   keeping its other tags, and the transfer is evaluated under its row lock. If either fails, the
   message comes back, and step 1 finishes the job.

While a message is in hand, the loop extends its visibility every half visibility timeout, so a
long scan isn't handed to a second worker. Metrics (abuse 8.1): `scan_results_total{state,reason}`,
`scan_deferrals_total`, `dlp_inspection_seconds`, `dlp_inspection_results_total{state,reason}` and
`dlp_inspector_failures_total{kind}`: detector IDs and counts never appear in a label, and no value
anywhere (NFR-26).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import sys
import time
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar, Final
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter, Histogram
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, ScanSettings, load_settings
from sft.core.telemetry import configure_tracing
from sft.data import files
from sft.data.access import NotFoundError
from sft.data.counters import CounterMetrics, CounterStore, CounterStoreUnavailableError
from sft.data.database import Database
from sft.data.findings import Counts
from sft.data.models import (
    FileState,
    InspectionReason,
    InspectionState,
    ScanDetail,
    StorageClass,
)
from sft.data.outbox import FILE_SCAN, FILE_SCAN_LARGE, Queue, Topic, enqueue
from sft.data.processed import record_processed
from sft.data.scope import Scope
from sft.dlp import client as inspector_client
from sft.dlp.detect import BUILTIN_DETECTORS
from sft.dlp.protocol import MalformedAnswerError, ProtocolError, Result
from sft.runtime.s3 import S3Objects
from sft.service import scan_timing, scans
from sft.service.evaluation import evaluate
from sft.service.objects import SCAN_TAG, ObjectStoreError, ScannedObjects
from sft.service.scans import InspectionResult, ScanResult, SystemActor
from sft.workers.clamd import ClamdError, ClamdResult, Verdict, instream
from sft.workers.consumer import (
    LONG_POLL_SECONDS,
    Consumer,
    ConsumerLoop,
    ConsumerMetrics,
    Delivery,
    Outcome,
)
from sft.workers.process import WorkerProcess
from sft.workers.queues import SqsQueues

log = logging.getLogger(__name__)

SERVICE_NAME: Final = "sft-scan-worker"
DEFER: Final = timedelta(seconds=30)
"""How long a scan over its tenant's cap waits before it is tried again (abuse 6.4)."""
LEASE_MARGIN: Final = timedelta(minutes=1)
TEE_DEPTH: Final = 4
"""Chunks clamd may fall behind the S3 read before the read waits for it."""
INSPECTOR_BUFFER: Final = 64
"""Chunks the inspector may fall behind clamd: 64 MiB of the S3 read's 1 MiB chunks."""
INSPECTOR_STALL: Final = 30.0
"""Seconds the read waits for an inspector whose buffer is full before it drops it for this
attempt; clamd's timeout allows for one such wait."""


SCANNED: Final = frozenset(
    {FileState.CLEAN, FileState.INFECTED, FileState.UNSCANNABLE, FileState.SCAN_FAILED}
)
"""States with a scan result, whose tag and evaluation `_finish` makes good."""
GONE: Final = frozenset({"NoSuchKey", "NoSuchVersion", "404", "NotFound"})
FAILED_DETAILS: Final = frozenset(
    {
        ScanDetail.ENGINE_ERROR,
        ScanDetail.DEADLINE_PASSED,
        ScanDetail.LARGE_FILE_SCANNING_UNAVAILABLE,
    }
)
FAILURE_KINDS: Final = (
    "bad_request",
    "engine_error",
    "sandbox_unavailable",
    "malformed",
    "protocol",
    "timeout",
    "connection",
    "read",
)
"""The kinds of `dlp_inspector_failures_total`: the inspector's error codes, then the worker's."""


class AttemptFailedError(Exception):
    """An engine failed this attempt, and attempts are left: SQS delivers the message again."""


@dataclass(frozen=True)
class ScanMetrics:
    results: Counter
    deferrals: Counter
    inspection_seconds: Histogram
    inspection_results: Counter
    inspector_failures: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> ScanMetrics:
        metrics = cls._create(registry)
        # The alerts' series exist at zero from the start, so a first failure shows as an
        # increase (deploy/alerts/scanning.rules.yaml).
        for detail in ScanDetail:
            if detail in FAILED_DETAILS:
                metrics.results.labels(FileState.SCAN_FAILED.value, detail.value)
        metrics.inspection_results.labels(InspectionState.FAILED.value, "none")
        for kind in FAILURE_KINDS:
            metrics.inspector_failures.labels(kind)
        return metrics

    @classmethod
    def _create(cls, registry: CollectorRegistry) -> ScanMetrics:
        return cls(
            results=Counter(
                "scan_results_total",
                "Scan results recorded, by file state and reason (scan_detail, or none).",
                ["state", "reason"],
                registry=registry,
            ),
            deferrals=Counter(
                "scan_deferrals_total",
                "Scans sent again later because their tenant was at its cap (ADR-0019).",
                registry=registry,
            ),
            inspection_seconds=Histogram(
                "dlp_inspection_seconds",
                "Time from the first byte to the inspector's answer, per file (NFR-23).",
                buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 900),
                registry=registry,
            ),
            inspection_results=Counter(
                "dlp_inspection_results_total",
                "Inspections recorded, by state and reason (each reason counted; none if none).",
                ["state", "reason"],
                registry=registry,
            ),
            inspector_failures=Counter(
                "dlp_inspector_failures_total",
                "Failed inspection attempts, by kind: the inspector's error code, malformed, "
                "protocol, timeout, connection or read.",
                ["kind"],
                registry=registry,
            ),
        )


@dataclass(frozen=True)
class Engines:
    """Where clamd and the inspector listen: the node-local Services beside this worker."""

    clamd_host: str
    clamd_port: int
    inspector_host: str
    inspector_port: int
    connect_timeout: float = 5.0


class Leases:
    """The per-tenant scan caps (ADR-0019), as leases in the counter store."""

    def __init__(
        self, store: CounterStore | None, pool: Queue, cap: int, clock: Callable[[], float]
    ) -> None:
        self._store = store
        self._pool = pool
        self._cap = cap
        self._clock = clock

    def _key(self, tenant_id: UUID) -> str:
        return f"scan:{self._pool.value}:{tenant_id}"

    async def acquire(self, tenant_id: UUID, member: str, ttl: timedelta) -> bool:
        """True if the scan may run now: under the cap, or the store unavailable."""
        if self._store is None:
            return True
        try:
            return await self._store.acquire_lease(
                self._key(tenant_id),
                member,
                now_ms=int(self._clock() * 1000),
                ttl_ms=int(ttl.total_seconds() * 1000),
                cap=self._cap,
            )
        except CounterStoreUnavailableError:
            log.warning("counter store unavailable: the tenant's scan cap is skipped")
            return True

    async def release(self, tenant_id: UUID, member: str) -> None:
        if self._store is None:
            return
        with contextlib.suppress(CounterStoreUnavailableError):
            await self._store.release_lease(self._key(tenant_id), member)


# ---- one read, two engines ----

_END: Final = object()


@dataclass(frozen=True)
class _Lane:
    """How a branch of the tee is fed: up to `depth` chunks ahead, and, with `stall`, given up on
    when it is still full after that many seconds."""

    depth: int
    stall: float | None = None


class _Tee:
    """One source, read once, fed to each branch. A branch that stops early (the inspector after
    the first 64 KiB of a type it can't read) is closed, and the read goes on for the rest.

    clamd is the lane the read follows, since its timeout assumes it reads alone. The inspector's
    lane buffers up to `INSPECTOR_BUFFER` chunks ahead of it, and if it stays full for
    `INSPECTOR_STALL`, the inspector is dropped for this attempt (its branch raises
    `TimeoutError`, a failed inspection) and clamd reads on. So a slow inspector holds clamd up by
    one stall at most, never into clamd's timeout."""

    def __init__(self, source: AsyncIterator[bytes], lanes: Sequence[_Lane]) -> None:
        self._source = source
        self._lanes = list(lanes)
        self._queues: list[asyncio.Queue[object]] = [asyncio.Queue(lane.depth) for lane in lanes]
        self._closed = [False] * len(lanes)
        self._given_up: dict[int, Callable[[], None]] = {}

    async def branch(self, index: int) -> AsyncGenerator[bytes]:
        queue = self._queues[index]
        try:
            while True:
                item = await queue.get()
                if item is _END:
                    return
                if isinstance(item, BaseException):
                    raise item
                assert isinstance(item, bytes)  # noqa: S101 - only bytes, _END or an error
                yield item
        finally:
            self.close(index)

    def close(self, index: int) -> None:
        """The branch takes nothing more; the read goes on for the others. Its consumer calls it
        when it is done, early or not, even if it never started reading."""
        self._closed[index] = True
        queue = self._queues[index]
        while not queue.empty():  # free the read if it waits to put
            queue.get_nowait()

    def on_give_up(self, index: int, callback: Callable[[], None]) -> None:
        """Call `callback` if the read gives up on the branch, to stop its consumer."""
        self._given_up[index] = callback

    def _give_up(self, index: int) -> None:
        self.close(index)
        self._queues[index].put_nowait(TimeoutError("fell behind the read"))
        callback = self._given_up.get(index)
        if callback is not None:
            callback()

    async def _put(self, item: object) -> None:
        for index, queue in enumerate(self._queues):
            if self._closed[index]:
                continue
            stall = self._lanes[index].stall
            if stall is None:
                await queue.put(item)
                continue
            try:
                await asyncio.wait_for(queue.put(item), stall)
            except TimeoutError:
                self._give_up(index)

    async def pump(self) -> None:
        """Read the source to its end, or to the first error, which each open branch raises."""
        try:
            async for chunk in self._source:
                await self._put(chunk)
                if all(self._closed):
                    return
        except Exception as exc:
            await self._put(exc)
        else:
            await self._put(_END)
        finally:
            close = getattr(self._source, "aclose", None)
            if close is not None:
                await close()


@dataclass
class EngineAnswers:
    clamd: ClamdResult | BaseException
    inspection: Result | BaseException
    inspection_seconds: float = 0.0
    sha256: bytes | None = None
    """The digest of the whole version, when the read reached its end: the downloads' `ETag`."""


def _failure_kind(exc: BaseException) -> str:
    if isinstance(exc, inspector_client.InspectorError):
        return exc.code
    if isinstance(exc, MalformedAnswerError):
        return "malformed"
    if isinstance(exc, ProtocolError):
        return "protocol"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ObjectStoreError):
        return "read"
    return "connection"


_UNSCANNABLE: Final = {Verdict.ENCRYPTED: ScanDetail.ENCRYPTED}


def _scan_result(answer: ClamdResult) -> ScanResult:
    if answer.verdict is Verdict.CLEAN:
        return ScanResult(FileState.CLEAN)
    if answer.verdict is Verdict.INFECTED:
        return ScanResult(FileState.INFECTED)
    detail = _UNSCANNABLE.get(answer.verdict, ScanDetail.LIMIT_EXCEEDED)
    return ScanResult(FileState.UNSCANNABLE, detail)


def _inspection_result(answer: Result) -> InspectionResult:
    return InspectionResult(
        state=InspectionState(answer.state),
        reasons=tuple(InspectionReason(r) for r in answer.reasons),
        engine_version=answer.engine_version,
        findings=tuple(
            Counts(f.detector, f.counts.low, f.counts.medium, f.counts.high)
            for f in answer.findings
        ),
    )


class ScanConsumer(Consumer):
    """The scan pipeline of the module docstring, for one pool."""

    topic: ClassVar[Topic]

    def __init__(
        self,
        database: Database,
        objects: ScannedObjects,
        engines: Engines,
        metrics: ScanMetrics,
        leases: Leases,
        *,
        attempts: int = scan_timing.ATTEMPTS,
    ) -> None:
        super().__init__(database)
        self.objects = objects
        self.engines = engines
        self.metrics = metrics
        self.leases = leases
        self.attempts = attempts

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:  # pragma: no cover
        raise NotImplementedError("the scan runs between transactions: see process")

    async def process(self, delivery: Delivery) -> Outcome:
        message = delivery.message
        file_id = message.payload.get("file_id")
        if not isinstance(file_id, UUID):
            raise ValueError("a scan message names one file")
        scope = Scope.tenant(message.tenant_id)
        async with self.database.transaction(scope) as session:
            try:
                target = await files.scan_target(session, file_id)
            except NotFoundError:
                target = None
        if target is None or target.state is not FileState.SCANNING:
            if target is not None and target.state in SCANNED:
                await self._finish(message.tenant_id, file_id)
            return await self._done(scope, str(message.id))
        if target.storage_class is StorageClass.LARGE:
            # Over 2 GB: GuardDuty's (M6), never ClamAV's. A message from before #175 routed these
            # here; completion fails them now, and the sweep a file left from before.
            return await self._done(scope, str(message.id))
        size = target.actual_size or 0
        # One lease per attempt: two copies of a message scanning at once hold two, and neither
        # ends the other's when it finishes.
        member = f"{file_id}:{uuid.uuid4().hex}"
        ttl = scan_timing.attempt_timeout(size) + LEASE_MARGIN
        if not await self.leases.acquire(message.tenant_id, member, ttl):
            return await self._defer(scope, str(message.id), file_id)
        try:
            answers = await self._read_once(target, size)
        finally:
            await self.leases.release(message.tenant_id, member)
        scan, inspection = self._decide(answers, last=delivery.receive_count >= self.attempts)
        async with self.database.transaction(scope) as session:
            if not await record_processed(session, consumer=self.name, message_id=str(message.id)):
                return Outcome.DUPLICATE
            recorded = await scans.record(
                session,
                file_id,
                target.transfer_id,
                scan,
                inspection,
                attempts=delivery.receive_count,
                sha256=answers.sha256,
            )
        if recorded:
            self._count(scan, inspection, answers)
            log.info(
                "scan recorded",
                extra={
                    "file_id": str(file_id),
                    "state": scan.state.value,
                    "inspection_state": inspection.state.value,
                    "attempt": delivery.receive_count,
                },
            )
            await self._finish(message.tenant_id, file_id)
        return Outcome.PROCESSED

    async def _done(self, scope: Scope, message_id: str) -> Outcome:
        async with self.database.transaction(scope) as session:
            if not await record_processed(session, consumer=self.name, message_id=message_id):
                return Outcome.DUPLICATE
        return Outcome.PROCESSED

    async def _defer(self, scope: Scope, message_id: str, file_id: UUID) -> Outcome:
        async with self.database.transaction(scope) as session:
            if not await record_processed(session, consumer=self.name, message_id=message_id):
                return Outcome.DUPLICATE
            await enqueue(session, self.topic, {"file_id": file_id}, delay=DEFER)
        self.metrics.deferrals.inc()
        log.info("scan deferred: the tenant is at its cap", extra={"file_id": str(file_id)})
        return Outcome.PROCESSED

    async def _read_once(self, target: files.ScanTarget, size: int) -> EngineAnswers:
        if target.s3_version_id is None:  # pragma: no cover - a scanning file has its version
            raise RuntimeError("a scanning file has no recorded version")
        read = self.objects.read_version(
            target.storage_class, target.storage_key, target.s3_version_id
        )
        digest = hashlib.sha256()
        seen = 0

        async def source() -> AsyncIterator[bytes]:
            # The SHA-256 of the bytes as they pass, for downloads' strong ETag (#180): no
            # second read of the file.
            nonlocal seen
            async for chunk in read:
                digest.update(chunk)
                seen += len(chunk)
                yield chunk

        tee = _Tee(source(), [_Lane(TEE_DEPTH), _Lane(INSPECTOR_BUFFER, INSPECTOR_STALL)])
        clamd_seconds = scan_timing.clamd_timeout(size).total_seconds() + INSPECTOR_STALL
        answers = EngineAnswers(ClamdError("not run"), ProtocolError("not run"))

        async def clamd() -> None:
            body = tee.branch(0)
            try:
                async with asyncio.timeout(clamd_seconds):
                    answers.clamd = await instream(
                        self.engines.clamd_host,
                        self.engines.clamd_port,
                        body,
                        connect_timeout=self.engines.connect_timeout,
                    )
            except Exception as exc:
                answers.clamd = exc
            finally:
                tee.close(0)
                await body.aclose()

        async def inspector() -> None:
            body = tee.branch(1)
            start = time.monotonic()
            try:
                async with asyncio.timeout(scan_timing.inspector_timeout(size).total_seconds()):
                    answers.inspection = await self._inspect(body, size)
                answers.inspection_seconds = time.monotonic() - start
            except Exception as exc:
                answers.inspection = exc
            finally:
                tee.close(1)
                await body.aclose()

        inspecting = asyncio.create_task(inspector())

        def drop_inspector() -> None:
            # Its lane stayed full: it may be stuck sending, so stop it rather than wait.
            answers.inspection = TimeoutError("the inspector fell behind the read")
            inspecting.cancel()

        tee.on_give_up(1, drop_inspector)
        await asyncio.gather(clamd(), tee.pump())
        with contextlib.suppress(asyncio.CancelledError):
            await inspecting
        if seen == size:
            answers.sha256 = digest.digest()
        return answers

    async def _inspect(self, body: AsyncIterator[bytes], size: int) -> Result:
        async with asyncio.timeout(self.engines.connect_timeout):
            sock = await inspector_client.connect(
                self.engines.inspector_host, self.engines.inspector_port
            )
        # Closed whatever happens, at once: a stopped or failed inspection leaves nothing to wait
        # for, and the client has read the answer, if there was one, before it returns.
        with sock:
            # No tenant detectors before DLP-4 creates them and the DLP data key (ADR-0022).
            return await inspector_client.inspect(
                sock, size=size, body=body, builtin_detectors=BUILTIN_DETECTORS
            )

    def _decide(self, answers: EngineAnswers, *, last: bool) -> tuple[ScanResult, InspectionResult]:
        if isinstance(answers.inspection, BaseException):
            kind = _failure_kind(answers.inspection)
            self.metrics.inspector_failures.labels(kind).inc()
            log.warning("inspection attempt failed", extra={"kind": kind})
        if isinstance(answers.clamd, BaseException):
            log.warning("clamd attempt failed", extra={"error": type(answers.clamd).__name__})
            if not last:
                raise AttemptFailedError("clamd didn't answer") from answers.clamd
            return ScanResult(FileState.SCAN_FAILED, ScanDetail.ENGINE_ERROR), scans.SKIPPED
        scan = _scan_result(answers.clamd)
        if scan.state is FileState.INFECTED:
            return scan, scans.SKIPPED
        if isinstance(answers.inspection, BaseException):
            if not last:
                raise AttemptFailedError("the inspector didn't answer") from answers.inspection
            return scan, InspectionResult(InspectionState.FAILED)
        return scan, _inspection_result(answers.inspection)

    def _count(
        self, scan: ScanResult, inspection: InspectionResult, answers: EngineAnswers
    ) -> None:
        reason = scan.detail.value if scan.detail else "none"
        self.metrics.results.labels(scan.state.value, reason).inc()
        if inspection.state is InspectionState.SKIPPED:
            return
        for label in [r.value for r in inspection.reasons] or ["none"]:
            self.metrics.inspection_results.labels(inspection.state.value, label).inc()
        if answers.inspection_seconds:
            self.metrics.inspection_seconds.observe(answers.inspection_seconds)

    async def _finish(self, tenant_id: UUID, file_id: UUID) -> None:
        """After the result commits: the tag, then the evaluation. Both are safe to repeat."""
        scope = Scope.tenant(tenant_id)
        async with self.database.transaction(scope) as session:
            target = await files.scan_target(session, file_id)
        if target.state is FileState.SCANNING or target.s3_version_id is None:
            return
        value = scans.tag_value(target.state, target.unscannable_allowed, target.inspection_state)
        try:
            tags = await self.objects.object_tags(
                target.storage_class, target.storage_key, target.s3_version_id
            )
            if tags.get(SCAN_TAG) != value:
                await self.objects.put_object_tags(
                    target.storage_class,
                    target.storage_key,
                    target.s3_version_id,
                    {**tags, SCAN_TAG: value},
                )
        except ObjectStoreError as exc:
            if exc.code not in GONE:
                raise
            # The deletion job removed it already: there is nothing left to tag.
            log.info("object already deleted; no tag", extra={"file_id": str(file_id)})
        async with self.database.transaction(scope) as session:
            await evaluate(
                session,
                target.transfer_id,
                actor=scans.SYSTEM,
                now=datetime.now(UTC),
                details={"system_actor": SystemActor.SCAN_WORKER},
            )


class SmallScanConsumer(ScanConsumer):
    name = "scan-small"
    queue = Queue.SCAN_SMALL
    topic = FILE_SCAN


class LargeScanConsumer(ScanConsumer):
    name = "scan-large"
    queue = Queue.SCAN_LARGE
    topic = FILE_SCAN_LARGE


CONSUMERS: Final[dict[str, type[ScanConsumer]]] = {
    "small": SmallScanConsumer,
    "large": LargeScanConsumer,
}


def scan_queues(settings: ScanSettings) -> SqsQueues:
    """The SQS client of a worker that long-polls: its read timeout outlasts the 20 s wait."""
    return SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
        read_timeout=LONG_POLL_SECONDS + 10,
    )


async def run_scan_worker(settings: ScanSettings, *, handle_signals: bool = True) -> int:
    """The scan worker process: its pools, clients and probes, until a signal."""
    process = WorkerProcess(settings)
    database = Database.connect(
        settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
    )
    queues = scan_queues(settings)
    objects = S3Objects.create(
        region=settings.aws_region,
        files_bucket=settings.s3_files_bucket,
        large_files_bucket=settings.s3_large_files_bucket,
        endpoint_url=settings.s3_endpoint_url,
        threads=4,
    )
    store = (
        None
        if settings.valkey_url is None
        else CounterStore.connect(
            settings.valkey_url.get_secret_value(), CounterMetrics.create(process.registry)
        )
    )
    consumer_type = CONSUMERS[settings.scan_pool]
    leases = Leases(store, consumer_type.queue, settings.tenant_cap, time.time)
    consumer = consumer_type(
        database,
        objects,
        Engines(
            clamd_host=settings.clamd_host,
            clamd_port=settings.clamd_port,
            inspector_host=settings.inspector_host,
            inspector_port=settings.inspector_port,
            connect_timeout=settings.clamd_connect_timeout_seconds,
        ),
        ScanMetrics.create(process.registry),
        leases,
    )
    visibility = int(scan_timing.VISIBILITY[consumer_type.queue].total_seconds())
    loop = ConsumerLoop(
        consumer,
        queues,
        ConsumerMetrics.create(process.registry),
        # One message at a time: a scan takes a while, and messages received but not started
        # would wait out their visibility timeout in this worker instead of another's.
        max_messages=1,
        heartbeat_seconds=visibility // 2,
    )
    closers: list[Callable[[], Awaitable[None]]] = [queues.close, objects.close, database.dispose]
    if store is not None:
        closers.insert(0, store.close)
    try:
        return await process.run(loop.run, handle_signals=handle_signals)
    finally:
        for close in closers:
            await close()


def main() -> int:
    settings = load_settings(ScanSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    tracing = configure_tracing(
        SERVICE_NAME, settings.app_version, settings.otel_exporter_otlp_endpoint
    )
    try:
        return asyncio.run(run_scan_worker(settings))
    finally:
        tracing.shutdown()


if __name__ == "__main__":
    sys.exit(main())
