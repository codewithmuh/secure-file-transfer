import io
import json
import logging
from collections.abc import Callable, Iterator

import pytest

from sft.core.logs import JsonFormatter


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def json_logs() -> Iterator[Callable[[], list[dict[str, object]]]]:
    """Capture what the root logger writes, as the service writes it: one JSON object per line."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    def lines() -> list[dict[str, object]]:
        return [json.loads(line) for line in stream.getvalue().splitlines()]

    yield lines
    root.removeHandler(handler)
    root.setLevel(old_level)
