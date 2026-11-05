"""The inspector child's seccomp filter (ADR-0022, T-91): no new sockets, no exec, no ptrace.

**Why our own filter, not a library.** libseccomp's Python bindings aren't published on PyPI: they
come with distribution packages built for the distribution's Python, not the image's 3.13. The one
PyPI wrapper, `pyseccomp`, had its last release in January 2021. A filter this small doesn't need
either: it is a dozen classic BPF instructions, built here, checked by unit tests instruction by
instruction and by a test that runs a hardened child and tries each refused call. It is installed
with the `seccomp(2)` system call through ctypes, with `SECCOMP_FILTER_FLAG_TSYNC`, so it covers
every thread of the child, after `PR_SET_NO_NEW_PRIVS`, which lets a non-root process install one.

**What it refuses**, with `EPERM` (so Python raises `PermissionError`) unless noted:

- new sockets: `socket`, `socketpair`. The child has no socket to begin with: its only descriptors
  are two pipes to its parent and the files it opens. (The pod has no network either; this stops a
  parser exploit even from reaching the loopback interface.)
- running programs: `execve`, `execveat`.
- reading or changing other processes: `ptrace`, `process_vm_readv`, `process_vm_writev`.
- new processes: `fork` and `vfork`, and `clone` without `CLONE_THREAD`; threads are still allowed.
  `clone3` gets `ENOSYS`, because its flags are in memory a filter can't read, and the C library
  then falls back to `clone`.
- ways around a filter: `io_uring_setup` (io_uring runs operations a filter never sees), `bpf`,
  `userfaultfd` and `perf_event_open`.
- any other architecture or ABI (32-bit x86, x32): the process is killed.

Only Linux on x86_64 and aarch64 is supported: the image's platforms. Anything else raises
`SeccompUnavailableError`, and the inspector refuses to inspect rather than run a parser unfiltered.
"""

from __future__ import annotations

import ctypes
import platform
import struct
import sys
from dataclasses import dataclass
from typing import Final

# Classic BPF opcodes (linux/filter.h).
_LD_W_ABS: Final = 0x20
_JEQ_K: Final = 0x15
_JGE_K: Final = 0x35
_JSET_K: Final = 0x45
_RET_K: Final = 0x06

# seccomp return actions (linux/seccomp.h).
RET_KILL_PROCESS: Final = 0x80000000
RET_ERRNO: Final = 0x00050000
RET_ALLOW: Final = 0x7FFF0000
EPERM: Final = 1
ENOSYS: Final = 38

# Offsets in struct seccomp_data: nr, arch, instruction_pointer, then args[6] of 8 bytes each. On
# a little-endian machine the low 32 bits of args[0] come first.
_NR: Final = 0
_ARCH: Final = 4
_ARG0_LOW: Final = 16

CLONE_THREAD: Final = 0x00010000
_X32_SYSCALL_BIT: Final = 0x40000000

PR_SET_NO_NEW_PRIVS: Final = 38
SECCOMP_SET_MODE_FILTER: Final = 1
SECCOMP_FILTER_FLAG_TSYNC: Final = 1


@dataclass(frozen=True, slots=True)
class Arch:
    audit_arch: int
    seccomp_nr: int
    refused: dict[str, int]  # name -> system call number, refused with EPERM
    clone: int
    clone3: int
    x32_bit: bool  # whether x32 system call numbers exist and must be killed


ARCHES: Final = {
    "x86_64": Arch(
        audit_arch=0xC000003E,
        seccomp_nr=317,
        refused={
            "socket": 41,
            "socketpair": 53,
            "fork": 57,
            "vfork": 58,
            "execve": 59,
            "ptrace": 101,
            "perf_event_open": 298,
            "process_vm_readv": 310,
            "process_vm_writev": 311,
            "bpf": 321,
            "execveat": 322,
            "userfaultfd": 323,
            "io_uring_setup": 425,
        },
        clone=56,
        clone3=435,
        x32_bit=True,
    ),
    # The generic system call table: no fork or vfork, which the C library makes from clone.
    "aarch64": Arch(
        audit_arch=0xC00000B7,
        seccomp_nr=277,
        refused={
            "ptrace": 117,
            "socket": 198,
            "socketpair": 199,
            "execve": 221,
            "perf_event_open": 241,
            "process_vm_readv": 270,
            "process_vm_writev": 271,
            "bpf": 280,
            "execveat": 281,
            "userfaultfd": 282,
            "io_uring_setup": 425,
        },
        clone=220,
        clone3=435,
        x32_bit=False,
    ),
}


class SeccompUnavailableError(Exception):
    """The filter can't be installed here, so the inspector must not run a parser."""


@dataclass(frozen=True, slots=True)
class Insn:
    code: int
    jt: int
    jf: int
    k: int


def build(arch: Arch) -> list[Insn]:
    """The filter program for `arch`, its jumps resolved to the four returns at the end."""
    # (code, jump-true label, jump-false label, k); a label is None for "next instruction".
    body: list[tuple[int, str | None, str | None, int]] = [
        (_LD_W_ABS, None, None, _ARCH),
        (_JEQ_K, None, "kill", arch.audit_arch),
        (_LD_W_ABS, None, None, _NR),
    ]
    if arch.x32_bit:
        body.append((_JGE_K, "kill", None, _X32_SYSCALL_BIT))
    body += [(_JEQ_K, "eperm", None, nr) for nr in arch.refused.values()]
    body += [
        (_JEQ_K, "enosys", None, arch.clone3),
        (_JEQ_K, None, "allow", arch.clone),
        (_LD_W_ABS, None, None, _ARG0_LOW),
        (_JSET_K, "allow", "eperm", CLONE_THREAD),
    ]
    returns = {
        "allow": RET_ALLOW,
        "eperm": RET_ERRNO | EPERM,
        "enosys": RET_ERRNO | ENOSYS,
        "kill": RET_KILL_PROCESS,
    }
    at = {label: len(body) + i for i, label in enumerate(returns)}

    def offset(here: int, label: str | None) -> int:
        if label is None:
            return 0
        jump = at[label] - here - 1
        if not 0 <= jump <= 255:  # pragma: no cover - the program is far shorter
            raise ValueError("jump out of range")
        return jump

    program = [
        Insn(code, offset(i, jt), offset(i, jf), k) for i, (code, jt, jf, k) in enumerate(body)
    ]
    program += [Insn(_RET_K, 0, 0, action) for action in returns.values()]
    return program


def encode(program: list[Insn]) -> bytes:
    """struct sock_filter[], in the machine's byte order."""
    return b"".join(struct.pack("=HBBI", i.code, i.jt, i.jf, i.k) for i in program)


def current_arch() -> Arch:
    if sys.platform != "linux":
        raise SeccompUnavailableError("not Linux")
    arch = ARCHES.get(platform.machine())
    if arch is None:
        raise SeccompUnavailableError("unsupported architecture")
    return arch


class _SockFprog(ctypes.Structure):
    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.c_void_p))


def install() -> None:
    """Install the filter on the calling process, every thread. It can never be removed."""
    arch = current_arch()
    program = encode(build(arch))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompUnavailableError(f"prctl failed: errno {ctypes.get_errno()}")
    buffer = ctypes.create_string_buffer(program, len(program))
    prog = _SockFprog(len(program) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    status = libc.syscall(
        ctypes.c_long(arch.seccomp_nr),
        ctypes.c_ulong(SECCOMP_SET_MODE_FILTER),
        ctypes.c_ulong(SECCOMP_FILTER_FLAG_TSYNC),
        ctypes.byref(prog),
    )
    if status != 0:
        raise SeccompUnavailableError(
            f"seccomp failed: status {status}, errno {ctypes.get_errno()}"
        )
