"""The seccomp filter's program, run instruction by instruction in a small BPF interpreter (T-91).

test_dlp_sandbox.py installs it for real; this checks every rule on both architectures, on any OS.
"""

from __future__ import annotations

import struct

import pytest

from sft.dlp import seccomp
from sft.dlp.seccomp import ARCHES, Arch, Insn

DENY = seccomp.RET_ERRNO | seccomp.EPERM
NOSYS = seccomp.RET_ERRNO | seccomp.ENOSYS


def run(program: list[Insn], *, arch: int, nr: int, arg0: int = 0) -> int:
    """Evaluate a classic BPF program on a seccomp_data of (nr, arch, ip=0, args[0]=arg0)."""
    data = struct.pack("=iIQQ", nr, arch, 0, arg0) + b"\0" * 40
    acc, pc = 0, 0
    while True:
        insn = program[pc]
        op = insn.code
        if op == 0x20:  # ld w abs
            (acc,) = struct.unpack_from("=I", data, insn.k)
            pc += 1
        elif op == 0x06:  # ret k
            return insn.k
        else:
            taken = {0x15: acc == insn.k, 0x35: acc >= insn.k, 0x45: bool(acc & insn.k)}[op]
            pc += 1 + (insn.jt if taken else insn.jf)


@pytest.mark.parametrize("name", list(ARCHES))
def test_rules(name: str) -> None:
    arch: Arch = ARCHES[name]
    program = seccomp.build(arch)
    assert len(seccomp.encode(program)) == 8 * len(program)
    audit = arch.audit_arch
    for nr in arch.refused.values():
        assert run(program, arch=audit, nr=nr) == DENY
    assert run(program, arch=audit, nr=arch.clone3) == NOSYS
    assert run(program, arch=audit, nr=arch.clone, arg0=seccomp.CLONE_THREAD | 0xF00) == (
        seccomp.RET_ALLOW
    )
    assert run(program, arch=audit, nr=arch.clone, arg0=0x11) == DENY  # SIGCHLD: a fork
    for allowed in (0, 1, 3, 63):  # read, write, close, ...
        assert run(program, arch=audit, nr=allowed) == seccomp.RET_ALLOW
    assert run(program, arch=0x40000003, nr=1) == seccomp.RET_KILL_PROCESS  # 32-bit x86
    if arch.x32_bit:
        assert run(program, arch=audit, nr=seccomp._X32_SYSCALL_BIT | 1) == (
            seccomp.RET_KILL_PROCESS
        )
