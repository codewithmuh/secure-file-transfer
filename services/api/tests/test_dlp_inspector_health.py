"""The DLP inspector's health port (#184): probes that never reach the framed protocol."""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from pydantic import ValidationError

from sft.core.settings import InspectorSettings
from sft.dlp.inspector import Health, health_server
from test_server import free_ports


def get(port: int, path: str) -> tuple[int, dict[str, str]]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_liveness_answers_while_readiness_follows_the_listener() -> None:
    [port] = free_ports(1)
    health = Health()
    server = health_server("127.0.0.1", port, health)
    try:
        assert get(port, "/healthz") == (200, {"status": "ok"})
        assert get(port, "/readyz") == (503, {"status": "starting"})
        health.listening = True
        assert get(port, "/readyz") == (200, {"status": "ready"})
        health.stopping = True
        assert get(port, "/readyz") == (503, {"status": "stopping"})
        assert get(port, "/healthz") == (200, {"status": "ok"})
        assert get(port, "/metrics")[0] == 404  # nothing else, and nothing about a file
    finally:
        server.shutdown()
        server.server_close()


def test_the_health_port_is_not_the_inspectors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECTOR_SCRATCH_DIR", "/scratch")
    monkeypatch.setenv("INSPECTOR_PORT", "8001")
    with pytest.raises(ValidationError, match="must differ"):
        InspectorSettings()


def test_probes_leave_no_inspection_in_the_log(tmp_path: Path) -> None:
    """The process end to end: ready on its health port, probed, then SIGTERM. Probes are no
    connections to the inspector, so no "file inspected" line and no bad_request."""
    inspector_port, internal_port = free_ports(2)
    env = {
        **os.environ,
        "INSPECTOR_PORT": str(inspector_port),
        "INTERNAL_PORT": str(internal_port),
        "INSPECTOR_SCRATCH_DIR": str(tmp_path),
        "LOG_LEVEL": "info",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "sft.dlp.inspector"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        for _ in range(200):
            try:
                if get(internal_port, "/readyz")[0] == 200:
                    break
            except (urllib.error.URLError, ConnectionError):
                pass
            if process.poll() is not None:
                break
            time.sleep(0.05)
        else:
            pytest.fail("the inspector never became ready")
        assert process.poll() is None, process.stdout.read() if process.stdout else ""
        for _ in range(3):
            assert get(internal_port, "/healthz")[0] == 200
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 0, output
    lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    messages = [line["msg"] for line in lines]
    assert "inspector listening" in messages
    assert "file inspected" not in messages
    assert "inspector stopping" in messages
