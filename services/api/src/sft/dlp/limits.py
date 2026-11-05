"""The inspector's limits per file (ADR-0022), in one place so every check names its number.

Past a limit the rest isn't inspected: the file is `partial` with the reason `limit_exceeded`, and
the findings so far count. A limit is never a pass. Tests pass smaller limits; production uses
these.

Each tenant pattern also has a scan-time budget per file, 0.5 s of CPU plus 50 ms per MiB scanned
and 100,000 matches (`sft.dlp.detect.tenant.PatternBudget`, #147). It isn't one of these limits: a
pattern past it stops alone, the file's state doesn't change, and the result names the pattern.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


@dataclass(frozen=True, slots=True)
class Limits:
    """Every limit of ADR-0022, plus the few the design left to the implementation (marked so)."""

    # Files over this aren't read at all: GuardDuty scans them, `too_large` (ADR-0019).
    max_input_bytes: int = 2_000_000_000
    # The inspector reads this much first and decides whether to read the rest (architecture 4.6).
    prefix_bytes: int = 64 * KIB
    # Containers around a piece of content: a zip, a tar, a gzip (with its tar), an Office or
    # OpenDocument file each count as one. Content 3 containers deep is read; 4 deep isn't.
    max_depth: int = 3
    # Entries read from zip and tar archives and Office containers, over the whole file.
    max_members: int = 10_000
    # Bytes decompressed or unpacked from every container in the file, together.
    max_decompressed_bytes: int = 4 * GIB
    # Decompressed bytes per compressed byte, per member...
    max_ratio: int = 100
    # ...checked once a member has given this many bytes (implementation): small, repetitive
    # Office parts pass 100:1 often, and a bomb only matters by volume.
    ratio_grace_bytes: int = 1 * MIB
    # Characters of text handed to the detectors, over the whole file.
    max_text_chars: int = 256 * MIB
    max_pdf_pages: int = 5_000
    cpu_seconds: int = 600
    wall_seconds: int = 900
    memory_bytes: int = 2 * GIB
    # The scratch volume (ADR-0022): the input file and the members unpacked to disk share it.
    scratch_bytes: int = 4 * GIB
    # Implementation: a longer line, paragraph or page is cut into units of this many characters,
    # each overlapping the one before by `unit_overlap_chars`, so a match on a cut isn't lost.
    max_unit_chars: int = 1 * MIB
    unit_overlap_chars: int = 256
    # Implementation: the child stops itself this long before the wall-clock limit, so it can still
    # return the findings so far; the parent kills it at the limit.
    wall_grace_seconds: int = 15
    # Implementation: after the soft CPU limit the child gets this much more before the kernel
    # kills it.
    cpu_grace_seconds: int = 5

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


DEFAULT_LIMITS = Limits()
