"""The NFR-23 inspection-time benchmark (#250): the design-load mix of file types through the scan
worker's own pass, clamd and the DLP inspector at once, timed per file, with p95 and p99 per size
class.

    uv run python -m tools.benchmark_inspection --clamd 127.0.0.1:3310 --inspector 127.0.0.1:8070 \\
        --files 60 --large 2 --concurrency 2 --json report.json

NFR-23: from a file's scan starting to its malware and inspection results recorded, p95 <= 60 s and
p99 <= 3 minutes for files up to 100 MB, p95 <= 10 minutes for files up to 2,000,000,000 bytes, at
design load. Each file goes through `ScanConsumer._read_once`, the worker's one read teed to clamd
(`INSTREAM`) and to the inspector, with the worker's own lanes, stall rule and timeouts, and its
answers through `_decide` as on a last attempt, so a timeout or engine error shows as the result the
worker would record. What it leaves out is the S3 read and the database transaction around it: the
bytes come from memory, so the time is the engines' and the tee's. The load test's
`scan_pass_duration_seconds` histogram measures the whole pass, S3 and the database included, at
design load (docs/operations/performance.md).

**The corpus** is made here, in memory, at run time, from the mix of [CAP] 3.5 and A45: 40 % of
files carry text to extract (plain text in UTF-8 and Shift_JIS, CSV, `.docx`, `.xlsx`, PDF and zip
archives of text, a quarter of them with a synthetic My Number), the rest are binary (images,
video), which the inspector stops reading after 64 KiB. Sizes follow the load test's bands up to
`--max-bytes`; `--large` files go to the large class (100 MB to 2 GB, up to `--max-large-bytes`).
Nothing is written to disk, and no value is printed: the report holds types, sizes, times and
states.

It runs with no database, queue or AWS credentials, so it can run beside the engines anywhere:
locally against the compose stack's clamd and inspector, and in staging as a Job on a scan node
(loadtest/benchmark-inspection-job.yaml), where `--concurrency` is the pool's trios. It exits 1
when a threshold is missed or a file failed, 2 on bad arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import math
import random
import sys
import time
import uuid
import zipfile
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final, cast
from xml.sax.saxutils import escape

from prometheus_client import CollectorRegistry

from sft.data.database import Database
from sft.data.files import ScanTarget
from sft.data.models import FileState, InspectionState, StorageClass
from sft.workers.scan import (
    Engines,
    LargeScanConsumer,
    Leases,
    ScanConsumer,
    ScanMetrics,
    SmallScanConsumer,
)

MB: Final = 1_000_000
SMALL_MAX: Final = 100 * MB
CHUNK: Final = 1024 * 1024
"""The S3 read's chunk size (sft.runtime.s3)."""
THRESHOLDS: Final = {"small": {"p95": 60.0, "p99": 180.0}, "large": {"p95": 600.0}}
"""NFR-23, in seconds."""
TEXT_KINDS: Final = ("txt", "txt-sjis", "csv", "docx", "xlsx", "pdf", "zip")
PDF_MAX: Final = 8 * MB
"""Larger PDFs would pass the inspector's 5,000-page limit; real ones so large are mostly images."""
WORDS: Final = (
    *("report", "review", "quarterly", "budget", "meeting", "draft", "final", "schedule"),
    *("project", "summary", "contract", "invoice", "delivery", "partner", "notes", "plan"),
)
JA_WORDS: Final = ("報告", "会議", "予算", "契約", "請求書", "納品", "議事録", "計画")


# ---- the corpus ----


def my_number(rng: random.Random) -> str:
    """A synthetic My Number with a valid check digit (the DLP corpus's rule)."""
    digits = [rng.randrange(10) for _ in range(11)]
    total = sum(digits[10 - i] * (i + 2 if i + 1 <= 6 else i - 4) for i in range(11))
    rest = total % 11
    return "".join(map(str, digits)) + str(0 if rest <= 1 else 11 - rest)


def _text(rng: random.Random, size: int, words: Sequence[str] = WORDS) -> str:
    out: list[str] = []
    length = 0
    while length < size:
        line = " ".join(rng.choice(words) for _ in range(12)) + "\n"
        out.append(line)
        length += len(line.encode())
    return "".join(out)


def _fit(data: bytes, size: int) -> bytes:
    return data[:size] if len(data) >= size else data + b"\n" * (size - len(data))


def _zip(members: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
        for name, body in members.items():
            # A fixed time, so one seed always makes the same bytes.
            archive.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), body)
    return out.getvalue()


def _docx(paragraphs: Sequence[str]) -> bytes:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = "".join(f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs)
    return _zip(
        {
            "[Content_Types].xml": (
                b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/'
                b'package/2006/content-types"><Default Extension="rels" ContentType="application/'
                b'vnd.openxmlformats-package.relationships+xml"/>'
                b'<Override PartName="/word/document.xml" '
                b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.'
                b'main+xml"/></Types>'
            ),
            "_rels/.rels": (
                b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
                b'openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://'
                b'schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                b'Target="word/document.xml"/></Relationships>'
            ),
            "word/document.xml": (
                f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="{w}"><w:body>{body}'
                "</w:body></w:document>"
            ).encode(),
        }
    )


def _xlsx(rows: Sequence[Sequence[str]]) -> bytes:
    s = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    r = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    cells = "".join(
        "<row>"
        + "".join(f'<c t="inlineStr"><is><t>{escape(v)}</t></is></c>' for v in row)
        + "</row>"
        for row in rows
    )
    ct = "application/vnd.openxmlformats-officedocument.spreadsheetml"
    return _zip(
        {
            "[Content_Types].xml": (
                '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/'
                'package/2006/content-types"><Default Extension="rels" ContentType="application/'
                'vnd.openxmlformats-package.relationships+xml"/>'
                '<Override PartName="/xl/workbook.xml" '
                f'ContentType="{ct}.sheet.main+xml"/>'
                '<Override PartName="/xl/worksheets/sheet1.xml" '
                f'ContentType="{ct}.worksheet+xml"/></Types>'
            ).encode(),
            "_rels/.rels": (
                '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
                'openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="'
                f'{r}/officeDocument" Target="xl/workbook.xml"/></Relationships>'
            ).encode(),
            "xl/workbook.xml": (
                '<?xml version="1.0" encoding="UTF-8"?>'
                f'<workbook xmlns="{s}" xmlns:r="{r}"><sheets>'
                '<sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
            ).encode(),
            "xl/_rels/workbook.xml.rels": (
                '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
                'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="'
                f'{r}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
            ).encode(),
            "xl/worksheets/sheet1.xml": (
                f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{s}"><sheetData>{cells}'
                "</sheetData></worksheet>"
            ).encode(),
        }
    )


def _pdf(pages: Sequence[str]) -> bytes:
    """A PDF with a text layer: one Helvetica text object per page."""
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]
    kids = []
    for text in pages:
        lines = " T* ".join(
            "(" + line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ") Tj"
            for line in text.splitlines()
        )
        stream = f"BT /F1 9 Tf 11 TL 36 806 Td {lines} ET".encode()
        content = len(objects) + 1
        objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents %d 0 R "
            b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> "
            b">> >> >>" % content
        )
        kids.append(len(objects))
    objects[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % k for k in kids),
        len(kids),
    )
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    )
    return out.getvalue()


@dataclass(frozen=True)
class CorpusFile:
    kind: str
    size_class: str
    marked: bool
    data: bytes


def make_file(rng: random.Random, kind: str, size: int, *, marked: bool) -> bytes:
    """One file of `kind`, about `size` bytes (exactly, for text, CSV and binary)."""
    mark = f"Individual Number: {my_number(rng)}\n" if marked else ""
    if kind == "binary":
        return rng.randbytes(size)
    if kind == "txt":
        return _fit((mark + _text(rng, size)).encode(), size)
    if kind == "txt-sjis":
        return _fit((mark + _text(rng, size // 2, JA_WORDS)).encode("cp932"), size)
    if kind == "csv":
        rows = ["id,customer,amount,note"]
        length = 0
        while length < size:
            row = f"{len(rows)},{rng.choice(WORDS)},{rng.randrange(100, 99999)},{rng.choice(WORDS)}"
            rows.append(row)
            length += len(row) + 1
        if marked:
            rows[1] = f"1,{my_number(rng)},100,id"
        return _fit("\n".join(rows).encode(), size)
    if kind == "docx":
        paragraphs = (
            [mark, *_text(rng, size).splitlines()] if mark else _text(rng, size).splitlines()
        )
        return _docx(paragraphs)
    if kind == "xlsx":
        table = [line.split(" ")[:6] for line in _text(rng, size // 2).splitlines()]
        if marked:
            table.insert(0, ["Individual Number", my_number(rng)])
        return _xlsx(table)
    if kind == "pdf":
        text = mark + _text(rng, min(size, PDF_MAX) // 2)
        lines = text.splitlines()
        return _pdf(["\n".join(lines[i : i + 60]) for i in range(0, len(lines), 60)])
    if kind == "zip":
        half = max(1, size // 2)
        return _zip(
            {
                "notes.txt": (mark + _text(rng, half)).encode(),
                "table.csv": make_file(rng, "csv", size - half, marked=False),
            }
        )
    raise ValueError(kind)


def _log_uniform(rng: random.Random, low: float, high: float) -> int:
    return round(math.exp(rng.uniform(math.log(low), math.log(high))))


SMALL_BANDS: Final = (
    (0.25 / 0.92, 1000, 1 * MB),
    (0.5 / 0.92, 1 * MB, 10 * MB),
    (0.17 / 0.92, 10 * MB, 100 * MB),
)
"""The load test's size bands up to 100 MB (loadtest/k6/lib/corpus.js), renormalised."""


@dataclass(frozen=True)
class Planned:
    """One file of the run, before its bytes exist: made when its scan starts, dropped after, so
    memory holds `--concurrency` files at most, not the corpus."""

    kind: str
    size: int
    marked: bool
    seed: int

    def make(self) -> CorpusFile:
        rng = random.Random(self.seed)  # noqa: S311 - synthetic test data, not a secret
        data = make_file(rng, self.kind, self.size, marked=self.marked)
        return CorpusFile(
            self.kind, "large" if len(data) > SMALL_MAX else "small", self.marked, data
        )


def plan(seed: int, files: int, large: int, max_bytes: int, max_large_bytes: int) -> list[Planned]:
    rng = random.Random(seed)  # noqa: S311 - synthetic test data, not a secret
    out = []
    for n in range(files + large):
        is_large = n >= files
        if is_large:
            size = _log_uniform(rng, SMALL_MAX + 1, max(SMALL_MAX + 2, max_large_bytes))
        else:
            roll = rng.random()
            low, high = SMALL_BANDS[-1][1:]
            for share, band_low, band_high in SMALL_BANDS:
                if roll < share:
                    low, high = band_low, band_high
                    break
                roll -= share
            size = min(_log_uniform(rng, low, high), max_bytes)
        text = rng.random() < (0.2 if is_large else 0.42)
        kind = rng.choice(TEXT_KINDS) if text else "binary"
        if kind == "pdf" and is_large:
            kind = "zip"  # a 100 MB text-layer PDF passes the page limit; large text is archives
        out.append(Planned(kind, size, text and rng.random() < 0.25, rng.getrandbits(32)))
    return out


def corpus(
    seed: int, files: int, large: int, max_bytes: int, max_large_bytes: int
) -> list[CorpusFile]:
    """The whole corpus in memory, for a small run or a test."""
    return [p.make() for p in plan(seed, files, large, max_bytes, max_large_bytes)]


# ---- the scan pass ----


class MemoryObjects:
    """`ScannedObjects` over bytes in memory, in the S3 read's 1 MiB chunks."""

    def __init__(self, files: Mapping[str, bytes]) -> None:
        self._files = files

    async def read_version(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> AsyncIterator[bytes]:
        data = self._files[key]
        for start in range(0, len(data), CHUNK):
            yield data[start : start + CHUNK]
            await asyncio.sleep(0)

    async def object_tags(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> Mapping[str, str]:
        return {}

    async def put_object_tags(
        self, storage_class: StorageClass, key: str, version_id: str, tags: Mapping[str, str]
    ) -> None:
        return None

    async def close(self) -> None:
        return None


@dataclass(frozen=True)
class Timed:
    kind: str
    size_class: str
    bytes: int
    marked: bool
    seconds: float
    scan_state: str
    inspection_state: str
    inspection_reasons: tuple[str, ...]


def consumer_for(size_class: str, engines: Engines, objects: MemoryObjects) -> ScanConsumer:
    """The pool's consumer, as the worker builds it, with no database: the pass never opens one."""
    kind: type[ScanConsumer] = SmallScanConsumer if size_class == "small" else LargeScanConsumer
    return kind(
        cast(Database, None),
        objects,
        engines,
        ScanMetrics.create(CollectorRegistry()),
        Leases(None, kind.queue, 1, time.time),
    )


async def scan_one(consumer: ScanConsumer, key: str, file: CorpusFile) -> Timed:
    target = ScanTarget(
        id=uuid.uuid4(),
        transfer_id=None,
        state=FileState.SCANNING,
        storage_class=StorageClass.STANDARD,
        storage_key=key,
        s3_version_id="memory",
        actual_size=len(file.data),
        unscannable_allowed=False,
        inspection_state=InspectionState.PENDING,
    )
    started = time.monotonic()
    answers = await consumer._read_once(target, len(file.data))
    seconds = time.monotonic() - started
    scan, inspection = consumer._decide(answers, last=True)
    return Timed(
        file.kind,
        file.size_class,
        len(file.data),
        file.marked,
        round(seconds, 3),
        scan.state.value,
        inspection.state.value,
        tuple(r.value for r in inspection.reasons),
    )


async def run(
    files: Sequence[CorpusFile | Planned], engines: Engines, concurrency: int
) -> list[Timed]:
    keys: dict[str, bytes] = {}
    objects = MemoryObjects(keys)
    gate = asyncio.Semaphore(concurrency)

    async def one(n: int, item: CorpusFile | Planned) -> Timed:
        async with gate:
            file = item.make() if isinstance(item, Planned) else item
            key = f"bench/{n}"
            keys[key] = file.data
            try:
                return await scan_one(consumer_for(file.size_class, engines, objects), key, file)
            finally:
                del keys[key]

    return list(await asyncio.gather(*(one(n, f) for n, f in enumerate(files))))


# ---- the report ----


def percentile(values: Sequence[float], p: float) -> float:
    """Nearest rank, as a threshold reads it: no interpolation past the worst file."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p / 100 * len(ordered)) - 1)]


FAILED_STATES: Final = frozenset({FileState.SCAN_FAILED.value})


def report(results: Sequence[Timed]) -> dict[str, Any]:
    classes: dict[str, Any] = {}
    ok = True
    for size_class, limits in THRESHOLDS.items():
        seconds = [r.seconds for r in results if r.size_class == size_class]
        if not seconds:
            classes[size_class] = {"files": 0}
            continue
        found = {"p95": percentile(seconds, 95), "p99": percentile(seconds, 99)}
        missed = {k: found[k] for k, limit in limits.items() if found[k] > limit}
        ok = ok and not missed
        classes[size_class] = {
            "files": len(seconds),
            "bytes": sum(r.bytes for r in results if r.size_class == size_class),
            **found,
            "max": max(seconds),
            "thresholds": limits,
            "missed": missed,
        }
    failures = [
        asdict(r)
        for r in results
        if r.scan_state in FAILED_STATES or r.inspection_state == InspectionState.FAILED.value
    ]
    by_kind: dict[str, dict[str, Any]] = {}
    for r in results:
        entry = by_kind.setdefault(r.kind, {"files": 0, "seconds": []})
        entry["files"] += 1
        entry["seconds"].append(r.seconds)
    kinds = {
        k: {"files": v["files"], "p95": percentile(v["seconds"], 95), "max": max(v["seconds"])}
        for k, v in by_kind.items()
    }
    return {
        "passed": ok and not failures,
        "classes": classes,
        "kinds": kinds,
        "failures": failures,
        "files": [asdict(r) for r in results],
    }


def _endpoint(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError("HOST:PORT")
    return host, int(port)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NFR-23: the scan pass on the design-load mix")
    parser.add_argument("--clamd", type=_endpoint, default=("127.0.0.1", 3310))
    parser.add_argument("--inspector", type=_endpoint, default=("127.0.0.1", 8070))
    parser.add_argument("--files", type=int, default=60, help="files up to 100 MB")
    parser.add_argument("--large", type=int, default=0, help="files of 100 MB to 2 GB")
    parser.add_argument("--max-bytes", type=int, default=20 * MB, help="cap on a small file")
    parser.add_argument("--max-large-bytes", type=int, default=150 * MB)
    parser.add_argument(
        "--concurrency", type=int, default=2, help="scans at once: the pool's trios"
    )
    parser.add_argument("--seed", type=int, default=250)
    parser.add_argument("--json", type=Path, help="write the full report here")
    args = parser.parse_args(argv)
    if args.files < 1 or args.concurrency < 1 or args.max_large_bytes > 2_000_000_000:
        parser.error(
            "--files and --concurrency are at least 1; --max-large-bytes at most 2,000,000,000"
        )
    files = plan(args.seed, args.files, args.large, args.max_bytes, args.max_large_bytes)
    engines = Engines(args.clamd[0], args.clamd[1], args.inspector[0], args.inspector[1])
    started = time.monotonic()
    results = asyncio.run(run(files, engines, args.concurrency))
    summary = report(results)
    summary["seconds"] = round(time.monotonic() - started, 1)
    summary["concurrency"] = args.concurrency
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2))
    for size_class, found in summary["classes"].items():
        if not found["files"]:
            print(f"{size_class}: no files")
            continue
        verdict = "MISSED " + ", ".join(found["missed"]) if found["missed"] else "ok"
        print(
            f"{size_class}: {found['files']} files, p95 {found['p95']:.1f} s, "
            f"p99 {found['p99']:.1f} s, "
            f"max {found['max']:.1f} s (NFR-23 {found['thresholds']}): {verdict}"
        )
    for kind, found in sorted(summary["kinds"].items()):
        print(
            f"  {kind}: {found['files']} files, p95 {found['p95']:.1f} s, max {found['max']:.1f} s"
        )
    if summary["failures"]:
        print(f"{len(summary['failures'])} files failed a scan or an inspection")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
