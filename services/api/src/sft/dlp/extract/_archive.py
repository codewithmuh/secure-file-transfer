"""Zip, gzip and tar archives, recursively, behind our own limit checks (ADR-0022).

`zipfile` and `tarfile` from the standard library read the structure; every byte they unpack goes
through `CountingReader`, which enforces the decompressed total and the per-member ratio, and each
member is spooled to an unnamed scratch file before it is read as its own type.
"""

from __future__ import annotations

import functools
import gzip
import tarfile
import zipfile
from collections.abc import Callable
from typing import IO, Final

from sft.dlp.extract._core import Context, CountingReader, MemberLimit, StopExtraction
from sft.dlp.extract._sniff import Kind, sniff

_ENCRYPTED: Final = 0x1
_UTF8_NAMES: Final = 0x800


def open_zip(data: IO[bytes]) -> zipfile.ZipFile:
    """A zip whose member names without the UTF-8 flag are read as CP932, as Japanese archivers
    write them ([detectors] 2); if they aren't valid CP932, as the standard's CP437."""
    try:
        return zipfile.ZipFile(data, metadata_encoding="cp932")
    except UnicodeDecodeError:
        data.seek(0)
        return zipfile.ZipFile(data)


def extract_zip(ctx: Context, zf: zipfile.ZipFile, depth: int, path: tuple[str, ...]) -> None:
    for info in zf.infolist():
        if info.is_dir():
            continue
        ctx.budget.member()
        if info.flag_bits & _ENCRYPTED:
            ctx.report.add("encrypted")
            continue
        _member(ctx, depth, (*path, info.filename), functools.partial(_open, zf, info))


def _open(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[IO[bytes], int | None]:
    return zf.open(info), info.compress_size


def extract_tar(ctx: Context, data: IO[bytes], depth: int, path: tuple[str, ...]) -> None:
    """A tar's regular files. Links, devices and directories hold no content and are skipped."""
    try:
        archive = tarfile.open(fileobj=data, mode="r:")  # noqa: SIM115 - closed below
    except tarfile.TarError:
        ctx.report.add("parse_error")
        return
    try:
        while True:
            try:
                info = archive.next()
            except tarfile.TarError:
                ctx.report.add("parse_error")
                return
            if info is None:
                return
            if not info.isreg():
                continue
            ctx.budget.member()
            _member(ctx, depth, (*path, info.name), functools.partial(_tar_member, archive, info))
    finally:
        archive.close()


def _tar_member(archive: tarfile.TarFile, info: tarfile.TarInfo) -> tuple[IO[bytes], int | None]:
    raw = archive.extractfile(info)
    if raw is None:  # pragma: no cover - only for non-regular members, which are skipped
        raise tarfile.TarError("no data")
    return raw, None  # stored, not compressed: the decompressed total still applies


def extract_gzip(
    ctx: Context, data: IO[bytes], size: int, depth: int, path: tuple[str, ...]
) -> None:
    """A gzip stream's content is one member. A tar inside it is read with it as one level."""
    if depth + 1 > ctx.limits.max_depth:
        ctx.report.add("limit_exceeded")
        return
    reader = CountingReader(gzip.GzipFile(fileobj=data, mode="rb"), ctx.budget, size)
    try:
        with ctx.spool(reader) as member:
            head = member.read(ctx.limits.prefix_bytes)
            member.seek(0)
            if sniff(head) is Kind.TAR:
                extract_tar(ctx, member, depth, path)
            else:
                ctx.nested(member, depth + 1, path)
    except MemberLimit:
        ctx.report.add("limit_exceeded")
    except StopExtraction:
        raise
    except Exception:  # a corrupt stream: BadGzipFile, EOFError, zlib.error
        ctx.report.add("parse_error")


def _member(
    ctx: Context,
    depth: int,
    path: tuple[str, ...],
    opener: Callable[[], tuple[IO[bytes], int | None]],
) -> None:
    try:
        raw, compressed = opener()
        with raw, ctx.spool(CountingReader(raw, ctx.budget, compressed)) as member:
            ctx.nested(member, depth + 1, path)
    except MemberLimit:
        ctx.report.add("limit_exceeded")
    except NotImplementedError:  # a compression method zipfile can't read, such as Deflate64
        ctx.report.add("unsupported_type")
    except StopExtraction:
        raise
    except Exception:  # BadZipFile (bad CRC, overlapping entries), zlib.error, EOFError, ...
        ctx.report.add("parse_error")
