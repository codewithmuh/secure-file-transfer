"""The strict-schema answers and the child's frames, in-process (ADR-0022, T-92, T-99)."""

from __future__ import annotations

import asyncio
import io
import json
import random
import socket
import string
import threading
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

import dlp_stub
from dlp_corpus import generate as corpus
from sft.dlp import child, client
from sft.dlp.engine import Engine, load_engine
from sft.dlp.limits import Limits
from sft.dlp.protocol import (
    PROTOCOL_VERSION,
    Decision,
    Error,
    MalformedAnswerError,
    ProtocolError,
    Request,
    Result,
    encode_frame,
    frame_length,
    parse_answer,
    result,
)
from sft.dlp.sandbox import Go, LimitsModel, Start, read_frame
from sft.dlp.units import Finding

BUILTIN = frozenset({"stub_token"})


def _answer(**fields: object) -> bytes:
    base: dict[str, object] = {
        "type": "result",
        "version": PROTOCOL_VERSION,
        "engine_version": "x1+dstub",
        "state": "inspected",
        "reasons": [],
        "findings": [],
    }
    return json.dumps(base | fields).encode()


FINDING = {
    "detector": "stub_token",
    "counts": {"low": 0, "medium": 0, "high": 1},
    "locations": ["page 1"],
    "previews": ["masked"],
}


def test_a_valid_result() -> None:
    answer = parse_answer(_answer(findings=[FINDING]), builtin_detectors=BUILTIN)
    assert isinstance(answer, Result)


@pytest.mark.parametrize(
    "fields",
    [
        {"state": "inspected", "reasons": ["parse_error"]},
        {"state": "partial", "reasons": []},
        {"state": "not_inspected", "reasons": ["no_text"], "findings": [FINDING]},
        {"state": "partial", "reasons": ["too_large"]},
        {"state": "partial", "reasons": ["no_text", "no_text"]},
        {"findings": [FINDING, FINDING]},
        {"findings": [FINDING | {"counts": {"low": 0, "medium": 0, "high": 0}}]},
        {"findings": [FINDING | {"detector": "other"}]},
        {"findings": [FINDING | {"locations": ["a\nb"]}]},
        {"findings": [FINDING | {"value": "x"}]},
        {"extra": 1},
    ],
)
def test_malformed_results_are_refused(fields: dict[str, object]) -> None:
    with pytest.raises(MalformedAnswerError):
        parse_answer(_answer(**fields), builtin_detectors=BUILTIN)


def test_frames() -> None:
    frame = encode_frame(Decision(type="decision", read_rest=True))
    assert frame_length(frame[:4], 100) == len(frame) - 4
    with pytest.raises(ProtocolError):
        frame_length(frame[:4], 2)
    with pytest.raises(ProtocolError):
        frame_length(b"\0", 100)
    assert read_frame(io.BytesIO(frame), 100) == frame[4:]
    with pytest.raises(ProtocolError):
        read_frame(io.BytesIO(frame[:6]), 100)


def test_custom_detector_ids_must_be_unique() -> None:
    spec = {"kind": "keywords", "id": "a", "terms": ["x"]}
    with pytest.raises(ValueError, match="unique"):
        Request.model_validate(
            {"type": "inspect", "version": 1, "size": 1, "tenant_detectors": [spec, spec]}
        )


def _frames(data: bytes) -> list[Decision | Result | Error]:
    stream = io.BytesIO(data)
    out: list[Decision | Result | Error] = []
    while header := stream.read(4):
        payload = stream.read(frame_length(header, 1 << 20))
        answer = parse_answer(payload, builtin_detectors=None)
        out.append(answer)
    return out


def _run_child(
    data: bytes, tmp_path: Path, engine: Engine = dlp_stub.ENGINE, **request: object
) -> list[Decision | Result | Error]:
    input_path = tmp_path / "input"
    input_path.write_bytes(data)
    req = Request.model_validate({"type": "inspect", "version": 1, "size": len(data)} | request)
    start = Start(type="start", limits=LimitsModel(**Limits().as_dict()), request=req)
    control = io.BytesIO(
        encode_frame(start) + encode_frame(Go(type="prefix")) + encode_frame(Go(type="complete"))
    )
    out = io.BytesIO()
    child.run(control, out, input_path, tmp_path, engine=engine, confine=False)
    return _frames(out.getvalue())


def test_child_inspects_a_file(tmp_path: Path) -> None:
    decision, answer = _run_child(b"TOKEN-0001 TOKEN-0002", tmp_path)
    assert decision == Decision(type="decision", read_rest=True)
    assert isinstance(answer, Result)
    assert answer.state == "inspected"
    assert answer.findings[0].counts.high == 2


def test_child_stops_after_an_unsupported_prefix(tmp_path: Path) -> None:
    decision, answer = _run_child(b"\x89PNG\r\n\x1a\n", tmp_path)
    assert decision == Decision(type="decision", read_rest=False)
    assert isinstance(answer, Result)
    assert answer.reasons == ["unsupported_type"]


def test_child_refuses_a_bad_tenant_detector(tmp_path: Path) -> None:
    spec = {"kind": "keywords", "id": "invalid", "terms": ["x"]}
    *_, answer = _run_child(b"TOKEN-0001", tmp_path, tenant_detectors=[spec])
    assert answer == Error(type="error", code="bad_request")


def test_child_reports_a_detector_failure(tmp_path: Path) -> None:
    *_, answer = _run_child(b"RAISE-IN-DETECTOR", tmp_path)
    assert answer == Error(type="error", code="engine_error")


class _FailsAtTheEnd(dlp_stub.StubScanner):
    def findings(self) -> list[Finding]:
        raise RuntimeError("detector bug")


def test_child_reports_a_failure_in_findings(tmp_path: Path) -> None:
    engine = Engine(
        new_scanner=_FailsAtTheEnd, builtin_detectors=dlp_stub.BUILTIN, detectors_version="t"
    )
    *_, answer = _run_child(b"TOKEN-0001", tmp_path, engine=engine)
    assert answer == Error(type="error", code="engine_error")


def test_child_with_the_real_detectors(tmp_path: Path) -> None:
    # The secret waits for a key ID that never comes: only `findings()` counts it, so this shows
    # the child asks for findings after the last unit (DLP-1's scanner contract).
    secret = corpus.aws_secret(random.Random(99))  # noqa: S311 - reproducible test data
    text = f"[default]\naws_secret_access_key = {secret}\n"
    engine = load_engine()
    decision, answer = _run_child(text.encode(), tmp_path, engine=engine)
    assert decision == Decision(type="decision", read_rest=True)
    assert isinstance(answer, Result)
    assert answer.state == "inspected"
    assert answer.engine_version == engine.version
    found = {finding.detector: finding for finding in answer.findings}
    assert found["cloud_credential"].counts.medium == 1
    assert found["cloud_credential"].previews == ["AWS secret access key"]
    assert secret not in answer.model_dump_json()


def test_child_reports_a_pattern_past_its_budget_with_the_other_findings(tmp_path: Path) -> None:
    # #147: the example pattern of the issue, on 1 MiB of random text, through the real detectors.
    rng = random.Random(147)  # noqa: S311 - reproducible test data
    noise = "".join(
        rng.choice(string.ascii_letters + string.digits + " .,") for _ in range(1 << 20)
    )
    text = f"mihon.taro@example.com\n{noise}\n"
    slow = {"kind": "pattern", "id": "slow", "expression": r"(?:.{0,30}\d){1,2}q"}
    *_, answer = _run_child(text.encode(), tmp_path, engine=load_engine(), tenant_detectors=[slow])
    assert isinstance(answer, Result)
    assert answer.state == "inspected"  # the file's state doesn't depend on a tenant's pattern
    assert answer.budget_exceeded == ["custom:slow"]
    assert {f.detector for f in answer.findings} >= {"email_address"}


def test_child_refuses_a_bad_start_frame(tmp_path: Path) -> None:
    out = io.BytesIO()
    status = child.run(io.BytesIO(b"\0\0\0\2{}"), out, tmp_path / "x", tmp_path, confine=False)
    assert status == child.EXIT_FAILED
    assert _frames(out.getvalue()) == [Error(type="error", code="bad_request")]


def test_finding_model_cuts_to_the_schema() -> None:
    from sft.dlp.protocol import finding_model

    model = finding_model(
        Finding(
            detector="stub_token",
            counts={"high": 2**40},
            locations=tuple(f"p\n{i}" for i in range(20)),
            previews=("",),
        )
    )
    assert model.counts.high == 2**31 - 1
    assert len(model.locations) == 10
    assert model.locations[0] == "p 0"
    assert model.previews == ["-"]
    assert result(engine_version="x1", state="inspected", reasons=[], findings=[model])


# ---- the client against an inspector that answers early (review fixes) ----


def _early_inspector(answer: bytes) -> tuple[socket.socket, threading.Thread]:
    """An inspector that reads the request, answers at once and closes, unread bytes and all."""
    server, worker = socket.socketpair()

    def serve() -> None:
        with server:
            header = server.recv(4, socket.MSG_WAITALL)
            server.recv(frame_length(header, 1 << 20), socket.MSG_WAITALL)
            server.sendall(answer)

    thread = threading.Thread(target=serve)
    thread.start()
    return worker, thread


async def _body(size: int) -> AsyncIterator[bytes]:
    chunk = b"x" * (1 << 20)
    for start in range(0, size, len(chunk)):
        yield chunk[: min(len(chunk), size - start)]


def _client_inspect(worker: socket.socket, size: int, prefix_bytes: int) -> Result:
    async def scan() -> Result:
        reader, writer = await asyncio.open_connection(sock=worker)
        try:
            return await client.inspect(
                reader,
                writer,
                size=size,
                body=_body(size),
                builtin_detectors=dlp_stub.BUILTIN,
                prefix_bytes=prefix_bytes,
            )
        finally:
            writer.close()

    return asyncio.run(scan())


LATE = result(engine_version="t", state="partial", reasons=["limit_exceeded"])


def test_the_client_takes_a_result_as_the_first_answer() -> None:
    # The child stopped at a limit before deciding: the inspector's first frame is the result.
    worker, thread = _early_inspector(encode_frame(LATE))
    answer = _client_inspect(worker, 1000, 64 * 1024)
    thread.join(timeout=10)
    assert answer == LATE


@pytest.mark.parametrize("answer", [LATE, Error(type="error", code="bad_request")])
def test_an_answer_sent_while_the_client_still_sends_is_read(answer: Result | Error) -> None:
    # 32 MiB can't all fit in the socket buffers, so the client is still sending when the
    # inspector closes: it gets a broken pipe or a reset, and still reads the answer.
    for _ in range(5):
        worker, thread = _early_inspector(encode_frame(answer))
        size = 32 << 20
        if isinstance(answer, Result):
            assert _client_inspect(worker, size, size) == answer
        else:
            with pytest.raises(client.InspectorError) as error:
                _client_inspect(worker, size, size)
            assert error.value.code == "bad_request"
        thread.join(timeout=10)


def test_a_connection_that_ends_with_no_answer_is_a_protocol_error() -> None:
    worker, thread = _early_inspector(b"")
    with pytest.raises(ProtocolError):
        _client_inspect(worker, 32 << 20, 32 << 20)
    thread.join(timeout=10)
