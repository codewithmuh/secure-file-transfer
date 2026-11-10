"""The recovery job: what the restore, failover and failback runbooks run (#258; architecture 7;
data model 2.5, 4.2, 6; docs/operations/disaster-recovery.md 4).

`python -m sft.workers.recovery` runs it once, as `sft_recovery` in recovery scope, from the
always-suspended `recovery` CronJob, rendered by hand with its steps and times
(`RECOVERY_STEPS`, `RECOVERY_SINCE`, `RECOVERY_REWIND_TO`). It reads this region's audit archive
and calls `sft.service.recovery_replay` for each step it is given, always in this order:

1. **`generation`.** The highest generation in the archive is the largest `g<n>/` prefix the
   archive job wrote (0 if none); the cursor's generation becomes one more, rewound to the oldest
   event since `RECOVERY_REWIND_TO` (`start_generation`). Running it again changes nothing.
2. **`partitions`.** The monthly audit partitions from the oldest record's month
   (`prepare_partitions`).
3. **`replay`.** Every archived record after `RECOVERY_SINCE`, read under **both layouts**: the
   API's security-critical records, `security-critical/v1/<tenant or platform>/<yyyy>/<mm>/<dd>/
   <event ID>.json`, and the archive job's batches, `g<n>/<yyyy>/<mm>/<dd>/*.jsonl.gz`, in every
   generation; from `RECOVERY_SINCE`'s UTC day to today's. `replay` merges them, drops duplicates
   by `id` and re-imports and re-applies oldest first.
4. **`outbox`.** Every outbox message published since `RECOVERY_SINCE` goes back to unsent
   (`republish_outbox`). The runbooks run it on its own, with a `RECOVERY_SINCE` 24 hours back.

Records are read whole into memory before the replay, as the replay needs them oldest first and
the partitions step needs the oldest: a failover's hour, or a restore's few hours, is thousands to
hundreds of thousands of records. An object that isn't a record fails the run, since skipping it
could skip a revocation; the error names its key, which holds IDs and dates only.

What it logs is counts, the generation and the newest record's time (the drill's RPO evidence),
never a record's content.
"""

from __future__ import annotations

import gzip
import logging
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Final, Protocol

from sft.data.database import Database
from sft.service import recovery_replay
from sft.service.audit_archive import PREFIX
from sft.service.recovery_replay import Outcome, Record, day_prefixes, parse_record

log = logging.getLogger(__name__)

_GENERATION: Final = re.compile(r"^g([1-9][0-9]{0,8})/$")


class Step(StrEnum):
    GENERATION = "generation"
    PARTITIONS = "partitions"
    REPLAY = "replay"
    OUTBOX = "outbox"


ORDER: Final = (Step.GENERATION, Step.PARTITIONS, Step.REPLAY, Step.OUTBOX)
"""The order the steps run in, whatever order they are named in."""


def parse_steps(value: str) -> tuple[Step, ...]:
    """`RECOVERY_STEPS`, a comma-separated list, in `ORDER`. Raises `ValueError` for an unknown or
    empty one."""
    named = {part.strip() for part in value.split(",") if part.strip()}
    if not named:
        raise ValueError("name at least one step: generation, partitions, replay or outbox")
    unknown = named - {step.value for step in Step}
    if unknown:
        raise ValueError(f"unknown recovery steps: {', '.join(sorted(unknown))}")
    return tuple(step for step in ORDER if step.value in named)


class ArchiveReadError(Exception):
    """A list or a read of the archive failed. `code` is S3's error code or the client's error
    type."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ArchiveReader(Protocol):
    """One region's audit archive, read (`sft.runtime.archive.S3ArchiveReader`)."""

    async def prefixes(self, prefix: str) -> list[str]:
        """The `/`-delimited prefixes directly under `prefix`, each ending in `/`."""
        ...

    async def keys(self, prefix: str) -> list[str]:
        """Every key under `prefix`."""
        ...

    async def get(self, key: str) -> bytes: ...

    async def close(self) -> None: ...


async def highest_generation(reader: ArchiveReader) -> int:
    """The largest `g<n>/` the archive holds, or 0 when the archive job never wrote."""
    return max(await _generations(reader), default=0)


def _days(first: date, last: date) -> list[date]:
    return [date.fromordinal(n) for n in range(first.toordinal(), last.toordinal() + 1)]


async def read_records(reader: ArchiveReader, *, since: datetime, today: date) -> list[Record]:
    """Every record of both layouts dated from `since`'s UTC day to `today` (module docstring).
    `replay` drops the ones at or before `since`, and the duplicates."""
    first = since.astimezone(UTC).date()
    found: list[Record] = []
    owners = [p.removeprefix(f"{PREFIX}/").rstrip("/") for p in await reader.prefixes(f"{PREFIX}/")]
    for owner in owners:
        for prefix in day_prefixes(PREFIX, owner, first, today):
            for key in await reader.keys(prefix):
                found.append(_record(key, await reader.get(key)))
    for generation in await _generations(reader):
        for day in _days(first, today):
            for key in await reader.keys(f"g{generation}/{day:%Y/%m/%d}/"):
                found.extend(_batch(key, await reader.get(key)))
    return found


async def _generations(reader: ArchiveReader) -> list[int]:
    return sorted(int(m.group(1)) for p in await reader.prefixes("") if (m := _GENERATION.match(p)))


def _record(key: str, body: bytes) -> Record:
    try:
        return parse_record(body)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"the archive object {key} isn't a record") from exc


def _batch(key: str, body: bytes) -> list[Record]:
    try:
        lines = gzip.decompress(body).decode().splitlines()
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError(f"the archive object {key} isn't a gzipped batch") from exc
    return [_record(key, line.encode()) for line in lines if line.strip()]


@dataclass
class RecoveryReport:
    """What one run did: counts and times only."""

    steps: tuple[Step, ...]
    generation: int | None = None
    highest_in_archive: int | None = None
    records: int = 0
    newest: datetime | None = None
    """The newest record after `RECOVERY_SINCE`: the archive's last word before the failure."""
    partitions: dict[str, str] = field(default_factory=dict)
    replayed: Counter[str] = field(default_factory=Counter)
    reapplied: list[tuple[str, str | None, str | None]] = field(default_factory=list)
    """(action, tenant, target) of each change made again: IDs, for the drill log."""
    republished: int | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "steps": [step.value for step in self.steps],
            "generation": self.generation,
            "highest_in_archive": self.highest_in_archive,
            "records": self.records,
            "newest": None if self.newest is None else self.newest.isoformat(),
            "partitions_created": sorted(
                name for name, status in self.partitions.items() if status == "created"
            ),
            "replayed": dict(self.replayed),
            "reapplied": [list(item) for item in self.reapplied],
            "republished": self.republished,
        }


async def run_recovery(
    database: Database,
    reader: ArchiveReader,
    *,
    steps: Sequence[Step],
    since: datetime | None,
    rewind_to: datetime | None,
    today: date,
) -> RecoveryReport:
    """Run `steps` in `ORDER` (module docstring). `since` is needed by every step but
    `generation`, `rewind_to` by `generation`; both carry their offset."""
    ordered = tuple(step for step in ORDER if step in steps)
    for name, value in (("since", since), ("rewind_to", rewind_to)):
        if value is not None and value.tzinfo is None:
            raise ValueError(f"{name} must carry its offset")
    if since is None and any(step is not Step.GENERATION for step in ordered):
        raise ValueError("RECOVERY_SINCE is needed by partitions, replay and outbox")
    if rewind_to is None and Step.GENERATION in ordered:
        raise ValueError("RECOVERY_REWIND_TO is needed by generation")
    report = RecoveryReport(ordered)
    if Step.GENERATION in ordered and rewind_to is not None:
        report.highest_in_archive = await highest_generation(reader)
        report.generation = await recovery_replay.start_generation(
            database, highest_in_archive=report.highest_in_archive, rewind_to=rewind_to
        )
        log.info(
            "recovery: archive generation started",
            extra={"generation": report.generation, "highest": report.highest_in_archive},
        )
    if since is None:
        return report
    if Step.PARTITIONS in ordered or Step.REPLAY in ordered:
        records = recovery_replay.merge(
            await read_records(reader, since=since, today=today), since=since
        )
        report.records = len(records)
        report.newest = max((r.occurred_at for r in records), default=None)
        log.info(
            "recovery: archive read",
            extra={
                "records": report.records,
                "newest": None if report.newest is None else report.newest.isoformat(),
            },
        )
        if Step.PARTITIONS in ordered:
            report.partitions = await recovery_replay.prepare_partitions(database, records)
        if Step.REPLAY in ordered:
            replayed = await recovery_replay.replay(database, records, since=since)
            for (action, outcome), count in replayed.counts.items():
                report.replayed[f"{action}:{Outcome(outcome).value}"] += count
            report.reapplied = [
                (action, None if tenant is None else str(tenant), None if t is None else str(t))
                for action, tenant, t in replayed.reapplied
            ]
    if Step.OUTBOX in ordered:
        report.republished = await recovery_replay.republish_outbox(database, since=since)
    return report
