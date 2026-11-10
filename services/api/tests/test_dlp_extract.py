"""Text extraction (ADR-0022, DLP-2): every format from a fixture, and every limit against a bomb.

Extraction runs in-process here, without the sandbox, so each case is fast; test_dlp_sandbox.py
runs the same code in the confined child.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

import dlp_fixtures as fx
from sft.dlp.extract import Outcome, early_stop, extract
from sft.dlp.limits import MIB, Limits
from sft.dlp.units import TextUnit


def run(data: bytes, tmp_path: Path, limits: Limits | None = None) -> tuple[Outcome, str]:
    units: list[TextUnit] = []
    outcome = extract(
        io.BytesIO(data), emit=units.append, limits=limits or Limits(), scratch_dir=tmp_path
    )
    return outcome, "\n".join(unit.text for unit in units)


TEXT = "TOKEN-0001 注文番号 TOKEN-0002"


@pytest.mark.parametrize(
    "data",
    [
        TEXT.encode("utf-8"),
        "﻿".encode("utf-16-le") + TEXT.encode("utf-16-le"),
        TEXT.encode("cp932"),
        TEXT.encode("euc-jp"),
        TEXT.encode("iso-2022-jp"),
    ],
    ids=["utf-8", "utf-16", "cp932", "euc-jp", "iso-2022-jp"],
)
def test_text_encodings(data: bytes, tmp_path: Path) -> None:
    outcome, text = run(data, tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0001" in text
    assert "注文番号" in text


def test_csv(tmp_path: Path) -> None:
    outcome, text = run(b"id,code\n1,TOKEN-0001\n2,TOKEN-0002\n", tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0002" in text


@pytest.mark.parametrize(
    ("data", "tokens"),
    [
        (
            fx.docx(
                ["TOKEN-0001"],
                header="TOKEN-0002",
                footer="TOKEN-0003",
                comment="TOKEN-0004",
                textbox="TOKEN-0005",
            ),
            5,
        ),
        (fx.xlsx({"Sheet1": [["code"], ["TOKEN-0001"]]}, comment="TOKEN-0002"), 2),
        (fx.pptx([["TOKEN-0001"]], notes={1: "TOKEN-0002"}), 2),
        (fx.odt(["TOKEN-0001"], footer="TOKEN-0002"), 2),
        (fx.ods({"Sheet1": [["code"], ["TOKEN-0001"]]}), 1),
        (fx.odp(["TOKEN-0001"], notes="TOKEN-0002"), 2),
        (fx.pdf(["TOKEN-0001", "TOKEN-0002"]), 2),
        (fx.zip_bytes({"a.txt": "TOKEN-0001"}), 1),
        (fx.gzip_bytes(b"TOKEN-0001"), 1),
        (fx.tar_bytes({"a.txt": b"TOKEN-0001"}), 1),
        (fx.gzip_bytes(fx.tar_bytes({"a.txt": b"TOKEN-0001"})), 1),
        (fx.cp932_names_zip("名前.txt", b"TOKEN-0001"), 1),
    ],
    ids=[
        "docx",
        "xlsx",
        "pptx",
        "odt",
        "ods",
        "odp",
        "pdf",
        "zip",
        "gzip",
        "tar",
        "tgz",
        "zip-cp932",
    ],
)
def test_formats(data: bytes, tokens: int, tmp_path: Path) -> None:
    outcome, text = run(data, tmp_path)
    assert outcome.state == "inspected", outcome
    for i in range(1, tokens + 1):
        assert f"TOKEN-{i:04}" in text


@pytest.mark.parametrize(
    ("data", "state", "reason"),
    [
        (fx.pdf([None], image=True), "not_inspected", "no_text"),
        (fx.pdf(["TOKEN-0001"], encrypted=True), "not_inspected", "encrypted"),
        (fx.odt(["TOKEN-0001"], encrypted=True), "not_inspected", "encrypted"),
        (fx.cfb(encrypted=True), "not_inspected", "encrypted"),
        (fx.cfb(encrypted=False), "not_inspected", "unsupported_type"),
        (
            fx.encrypt_flag(fx.zip_bytes({"a.txt": "TOKEN-0001"}), "a.txt"),
            "not_inspected",
            "encrypted",
        ),
        (b"\x89PNG\r\n\x1a\n" + b"\0" * 64, "not_inspected", "unsupported_type"),
        # PDFium can't open either. One reads as text, so it is read as text too (#4 of the
        # review), and still says it was a broken PDF; the other is binary.
        (b"%PDF-1.7\n garbage", "partial", "parse_error"),
        (b"%PDF-1.7\n\x00\x01\x02\x03 garbage", "not_inspected", "parse_error"),
    ],
    ids=[
        "pdf-image",
        "pdf-encrypted",
        "odt-encrypted",
        "office-encrypted",
        "legacy-office",
        "zip-encrypted",
        "png",
        "pdf-broken",
        "pdf-broken-binary",
    ],
)
def test_reasons(data: bytes, state: str, reason: str, tmp_path: Path) -> None:
    outcome, _ = run(data, tmp_path)
    assert outcome.state == state
    assert reason in outcome.reasons


def test_early_stop() -> None:
    assert early_stop(b"\x89PNG\r\n\x1a\n") == "unsupported_type"
    assert early_stop(b"TOKEN-0001") is None


def test_entity_bomb_is_not_expanded(tmp_path: Path) -> None:
    outcome, text = run(fx.docx(["TOKEN-0001"], doctype=fx.ENTITY_BOMB, raw="&lol9;"), tmp_path)
    assert "lollollol" not in text
    assert outcome.state != "inspected" or "TOKEN-0001" in text


def test_tar_symlink_is_not_followed(tmp_path: Path) -> None:
    _, text = run(fx.tar_bytes({"a.txt": b"TOKEN-0001"}, symlink="link"), tmp_path)
    assert "root:" not in text


def test_depth_limit(tmp_path: Path) -> None:
    outcome, text = run(fx.nested_zip(3, b"TOKEN-0001"), tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0001" in text
    outcome, text = run(fx.nested_zip(4, b"TOKEN-0001"), tmp_path)
    assert "limit_exceeded" in outcome.reasons
    assert "TOKEN-0001" not in text


def test_ratio_limit(tmp_path: Path) -> None:
    outcome, _ = run(fx.ratio_bomb(8 * MIB), tmp_path, Limits(ratio_grace_bytes=MIB))
    assert "limit_exceeded" in outcome.reasons


def test_member_limit(tmp_path: Path) -> None:
    outcome, text = run(fx.many_members(20), tmp_path, Limits(max_members=10))
    assert outcome.state == "partial"
    assert "limit_exceeded" in outcome.reasons
    assert "TOKEN-0000" in text


def test_decompressed_limit(tmp_path: Path) -> None:
    data = fx.zip_bytes({f"m{i}.txt": "TOKEN-0001 " * 1000 for i in range(5)})
    outcome, _ = run(data, tmp_path, Limits(max_decompressed_bytes=20_000))
    assert outcome.state == "partial"
    assert "limit_exceeded" in outcome.reasons


def test_text_chars_limit(tmp_path: Path) -> None:
    outcome, _ = run(b"TOKEN-0001 " * 1000, tmp_path, Limits(max_text_chars=100))
    assert outcome.state == "partial"
    assert "limit_exceeded" in outcome.reasons


def test_pdf_pages_limit(tmp_path: Path) -> None:
    outcome, text = run(
        fx.pdf(["TOKEN-0001", "TOKEN-0002", "TOKEN-0003"]), tmp_path, Limits(max_pdf_pages=2)
    )
    assert "limit_exceeded" in outcome.reasons
    assert "TOKEN-0001" in text


def test_scratch_limit(tmp_path: Path) -> None:
    data = fx.gzip_bytes(fx.tar_bytes({"a.txt": b"TOKEN-0001 " * 10_000}))
    outcome, _ = run(data, tmp_path, Limits(scratch_bytes=1000))
    assert "limit_exceeded" in outcome.reasons


def test_long_lines_are_cut_with_overlap(tmp_path: Path) -> None:
    units: list[TextUnit] = []
    data = b"x" * 1000 + b"TOKEN-0001" + b"x" * 1000
    extract(
        io.BytesIO(data),
        emit=units.append,
        scratch_dir=tmp_path,
        limits=Limits(max_unit_chars=1005, unit_overlap_chars=20),
    )
    assert len(units) > 1
    assert any("TOKEN-0001" in unit.text for unit in units)


# ---- review fixes ----


def test_a_bomb_in_the_content_types_part_stops_at_the_ratio(tmp_path: Path) -> None:
    # `[Content_Types].xml` is a member like any other: counted, and held to the 100:1 ratio.
    bomb = '<?xml version="1.0"?><Types>' + " " * (64 * MIB) + "</Types>"
    outcome, _ = run(fx.zip_bytes({"[Content_Types].xml": bomb, "a.txt": "TOKEN-0001"}), tmp_path)
    assert outcome.reasons == ("limit_exceeded",)
    small = Limits(max_decompressed_bytes=MIB, max_ratio=10**9)
    outcome, _ = run(fx.zip_bytes({"[Content_Types].xml": bomb}), tmp_path, small)
    assert outcome.reasons == ("limit_exceeded",)


def test_a_tar_whose_first_member_is_named_like_a_pdf_is_read(tmp_path: Path) -> None:
    data = fx.tar_bytes({"%PDF-notes.csv": b"id,code\n1,TOKEN-0001\n"})
    outcome, text = run(data, tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0001" in text


def test_a_csv_that_mentions_a_pdf_header_is_text(tmp_path: Path) -> None:
    outcome, text = run(b"id,note\n1,see %PDF-1.7 in the spec\n2,TOKEN-0001\n", tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0001" in text


def test_text_that_starts_like_a_pdf_falls_back_to_text(tmp_path: Path) -> None:
    # PDFium can't open it, and it reads as text: its text is inspected, and the reason says it
    # wasn't the PDF it looked like.
    outcome, text = run(b"%PDF-notes: TOKEN-0001 is not a PDF\n", tmp_path)
    assert (outcome.state, outcome.reasons) == ("partial", ("parse_error",))
    assert "TOKEN-0001" in text


def test_a_pdf_after_junk_a_reader_tolerates_is_still_a_pdf(tmp_path: Path) -> None:
    outcome, text = run(b"\n\x00 " + fx.pdf(["TOKEN-0001"]), tmp_path)
    assert outcome.state == "inspected"
    assert "TOKEN-0001" in text


def test_a_word_file_whose_text_part_is_refused_is_not_inspected(tmp_path: Path) -> None:
    # Its relationships read, but they hold no text: nothing people wrote was inspected.
    main = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    data = fx.zip_bytes(
        {
            "[Content_Types].xml": fx._content_types({"word/document.xml": main}),
            "_rels/.rels": fx._rels([("rId1", fx.REL_DOC, "word/document.xml")]),
            "word/document.xml": '<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY a "x">]>'
            f'<w:document xmlns:w="{fx.W}"><w:body>{fx._w_p("TOKEN-0001")}</w:body></w:document>',
        }
    )
    outcome, _ = run(data, tmp_path)
    assert (outcome.state, outcome.reasons) == ("not_inspected", ("parse_error",))


# ---- reading text once (#166) ----


class CountingBytes(io.BytesIO):
    """A file that counts the bytes read from it."""

    read_bytes = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.read_bytes += len(data)
        return data

    def readinto(self, buffer: Any, /) -> int:
        count = super().readinto(buffer)
        self.read_bytes += count
        return count


def units_of(data: bytes, tmp_path: Path) -> tuple[Outcome, list[TextUnit]]:
    units: list[TextUnit] = []
    outcome = extract(io.BytesIO(data), emit=units.append, limits=Limits(), scratch_dir=tmp_path)
    return outcome, units


def lines_as(data: bytes, encoding: str) -> list[tuple[str, str]]:
    """The units a reading of the whole file in `encoding` hands on: each non-blank line."""
    return [
        (f"line {n}", line)
        for n, line in enumerate(data.decode(encoding).splitlines(), 1)
        if line.strip()
    ]


ASCII_LINES = b"".join(b"order %06d TOKEN-0001 shipped\n" % n for n in range(4000))
"""About 120 KiB of ASCII: past the 64 KiB prefix, so the prefix decodes as UTF-8 first."""


def test_a_text_file_that_decodes_is_decoded_once(tmp_path: Path) -> None:
    # Before #166 the whole file was decoded once to choose the encoding, then again to read it.
    data = ("注文番号 TOKEN-0001\n" * 200_000).encode()
    counted = CountingBytes(data)
    units: list[TextUnit] = []
    outcome = extract(counted, emit=units.append, limits=Limits(), scratch_dir=tmp_path)
    assert outcome.state == "inspected"
    assert len(units) == 200_000
    # The 64 KiB prefix the sniffing reads, then the file once.
    assert counted.read_bytes <= len(data) + Limits().prefix_bytes


def test_a_file_that_turns_cp932_after_the_prefix_reads_as_cp932_line_by_line(
    tmp_path: Path,
) -> None:
    # UTF-8 is the best candidate for the prefix, but the file is CP932: the lines read before
    # the first CP932 byte stay inspected, the rest is read as CP932, and every line is handed on
    # once, as reading the whole file as CP932 would.
    data = ASCII_LINES + "注文番号 TOKEN-0002\n".encode("cp932") * 100
    outcome, units = units_of(data, tmp_path)
    assert outcome.state == "inspected"
    assert [(u.location, u.text) for u in units] == lines_as(data, "cp932")


def test_a_csv_that_turns_cp932_after_the_prefix_hands_each_row_on_once(tmp_path: Path) -> None:
    rows = b"".join(b"%d,TOKEN-0001\r\n" % n for n in range(8000))
    data = b"id,code\r\n" + rows + "9001,注文番号\r\n".encode("cp932")
    outcome, units = units_of(data, tmp_path)
    assert outcome.state == "inspected"
    locations = [u.location for u in units]
    assert len(locations) == len(set(locations)) == 8002
    assert units[-1].text == "9001\t注文番号"
    assert units[-1].cells[1].header == "code"


def test_bytes_no_candidate_decodes_are_replaced_and_no_line_is_handed_on_twice(
    tmp_path: Path,
) -> None:
    # No candidate decodes \x85\x40.
    data = ASCII_LINES + b"bad \x85\x40 byte\n" + b"after TOKEN-0003\n"
    outcome, units = units_of(data, tmp_path)
    assert outcome.state == "partial"
    assert outcome.reasons == ("parse_error",)
    locations = [u.location for u in units]
    assert len(locations) == len(set(locations)) == 4002
    assert units[-1].text == "after TOKEN-0003"
    assert "�" in units[-2].text


def test_a_crlf_cut_between_its_cr_and_lf_ends_one_line(tmp_path: Path) -> None:
    units: list[TextUnit] = []
    data = b"x" * 99 + b"\r\nTOKEN-0001\n"
    extract(
        io.BytesIO(data),
        emit=units.append,
        scratch_dir=tmp_path,
        limits=Limits(max_unit_chars=110, unit_overlap_chars=10),
    )
    assert [u.location for u in units] == ["line 1", "line 2"]
