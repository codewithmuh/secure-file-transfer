import contextvars
import io
import json
import logging
import sys

from sft.core.logs import JsonFormatter, bind_context, configure_logging


def format_record(**fields: object) -> dict[str, object]:
    record = logging.makeLogRecord({"msg": "hi", "levelname": "INFO", "name": "t", **fields})
    return json.loads(JsonFormatter().format(record))  # type: ignore[no-any-return]


def test_one_json_object_with_the_extra_fields() -> None:
    out = format_record(route="/v1/x", status=200)
    assert out["msg"] == "hi"
    assert out["level"] == "info"
    assert out["logger"] == "t"
    assert out["route"] == "/v1/x"
    assert out["status"] == 200
    assert "ts" in out


def test_drops_uvicorns_coloured_copy_of_the_message() -> None:
    assert "color_message" not in format_record(color_message="\x1b[1mhi\x1b[0m")


def test_includes_the_exception() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        out = format_record(exc_info=sys.exc_info())
    assert "ValueError: boom" in str(out["exc"])


def test_request_and_trace_ids_come_from_the_context() -> None:
    def in_a_request() -> dict[str, object]:
        bind_context(request_id="req_1", trace_id="a" * 32)
        return format_record()

    out = contextvars.copy_context().run(in_a_request)
    assert out["request_id"] == "req_1"
    assert out["trace_id"] == "a" * 32


def test_no_ids_outside_a_request() -> None:
    out = contextvars.Context().run(format_record)
    assert "request_id" not in out
    assert "trace_id" not in out


def test_configure_logging_sends_everything_through_one_json_handler() -> None:
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        stream = io.StringIO()
        configure_logging("warning", stream)
        logging.getLogger("uvicorn.error").warning("from uvicorn")
        logging.getLogger("anything").info("below the level")
        lines = [json.loads(line) for line in stream.getvalue().splitlines()]
        assert [line["msg"] for line in lines] == ["from uvicorn"]
        assert root.level == logging.WARNING
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
