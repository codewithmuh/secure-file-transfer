"""JSON logs on stdout, one line per event, so Loki or CloudWatch can parse them (ADR-0009).

Every line logged while a request or a message is handled carries its `request_id` and `trace_id`.
They live in context variables, so code in any layer gets them without passing them around: the
API sets them per request from the request's span, and `continued_trace` (sft.core.telemetry) sets
the trace ID per message from the trace context in the outbox (architecture 5.3).

Never log file names, message text, email addresses, tokens, codes, cookies, `Authorization`
headers or query strings (ADR-0009, architecture 5.5).
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TextIO

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)

# Attributes every LogRecord has; anything else came from `extra=` and is logged as a field.
# uvicorn adds `color_message`, a copy of the message with terminal colour codes.
_SKIP = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "color_message"}

# The fields the formatter writes itself. An `extra=` field with one of these names can't replace
# them; it is logged as `extra_<name>` instead.
_CORE_FIELDS = frozenset({"ts", "level", "logger", "msg", "request_id", "trace_id", "exc"})


def bind_context(*, request_id: str | None, trace_id: str | None) -> None:
    """Set the IDs that every log line in the current context carries."""
    request_id_var.set(request_id)
    trace_id_var.set(trace_id)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if (request_id := request_id_var.get()) is not None:
            payload["request_id"] = request_id
        if (trace_id := trace_id_var.get()) is not None:
            payload["trace_id"] = trace_id
        for key, value in vars(record).items():
            if key not in _SKIP:
                payload[f"extra_{key}" if key in _CORE_FIELDS else key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str, stream: TextIO = sys.stdout) -> None:
    """Send every logger, uvicorn's included, through one JSON handler."""
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
