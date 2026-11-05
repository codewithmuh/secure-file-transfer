"""Run as `python -I tests/dlp_probe.py`: confine this process as the inspector's child is, then
try each thing the sandbox must refuse, and print one JSON object with what happened."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import sys
import threading

from sft.dlp.limits import Limits
from sft.dlp.sandbox import harden


def attempt(action) -> str:  # type: ignore[no-untyped-def]
    try:
        action()
    except PermissionError:
        return "refused"
    except OSError as exc:
        return f"error {exc.errno}"
    return "allowed"


def ptrace() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.ptrace(0, 0, None, None) != 0:  # PTRACE_TRACEME
        raise OSError(ctypes.get_errno(), "ptrace")


def thread() -> None:
    done = []
    worker = threading.Thread(target=lambda: done.append(True))
    worker.start()
    worker.join()
    if not done:
        raise OSError(0, "thread didn't run")


def memory() -> str:
    try:
        bytearray(256 * 1024 * 1024)
    except MemoryError:
        return "refused"
    return "allowed"


harden(Limits(memory_bytes=192 * 1024 * 1024, cpu_seconds=30))
print(
    json.dumps(
        {
            "socket": attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
            "unix_socket": attempt(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
            "socketpair": attempt(socket.socketpair),
            "exec": attempt(lambda: os.execv("/bin/true", ["/bin/true"])),  # noqa: S606
            "subprocess": attempt(lambda: subprocess.run(["/bin/true"], check=False)),
            "fork": attempt(os.fork),
            "ptrace": attempt(ptrace),
            "thread": attempt(thread),
            "open_file": attempt(lambda: open(sys.executable, "rb").close()),
            "memory": memory(),
        }
    ),
    flush=True,
)
