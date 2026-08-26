"""Live lifecycle test (M3 exit): import COFF fixture → analyze → decompile → disassemble → read.

Run with: `$env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run python -m pytest tests/live -m live`
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path

import pytest

from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.ghidra.protocols import DecompileRequest, InstructionsRequest, OpenSpec

pytestmark = pytest.mark.live

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bin" / "tiny_x86.coff"


@pytest.fixture(scope="module")
def krate(jvm):
    settings = jvm.settings
    backend = GhidraBackend(jvm, settings)
    yield settings, jvm, backend
    # Drain analysis tasks + close projects BEFORE the session JVM stops:
    # disposing programs under a live analysis thread caused ClosedException
    # noise and native access violations at jpype.shutdownJVM.
    with contextlib.suppress(Exception):
        backend.shutdown()


def _wait_analyzed(backend: GhidraBackend, pid: str, wait: float = 180.0) -> None:
    deadline = time.time() + wait
    probe = InstructionsRequest(target="function", start="start", count=1)
    while time.time() < deadline:
        listing = {p.pid: p for p in backend.list_open()}
        if listing[pid].function_count > 0 and backend.instructions(pid, probe):
            return
        time.sleep(1.0)


def test_open_consume_decompile_cycle(
    krate,
):
    _, _, backend = krate
    spec = OpenSpec(
        path=str(FIXTURE), analyze="auto", language="x86:LE:64:default", compiler="default"
    )
    info = backend.open(spec)
    assert info.format and info.language == "x86:LE:64:default"
    assert info.image_base is not None

    _wait_analyzed(backend, info.pid)
    info = {p.pid: p for p in backend.list_open()}[info.pid]
    assert info.function_count > 0, "analysis must produce functions"
    assert backend.current() == info.pid

    # decompile both functions by name
    functions = backend.decompile(info.pid, DecompileRequest(targets=["start", "add2"]))
    names = {f.name for f in functions}
    assert {"start", "add2"} <= names
    for fn in functions:
        assert fn.lines, "decompiler must produce C text"

    # disassemble the function (COFF .text lands at 0x2100)
    insns = backend.instructions(
        info.pid, InstructionsRequest(target="function", start="start", count=8, include_bytes=True)
    )
    assert insns, "expected at least one instruction"
    assert insns[0].mnemonic.lower() in ("push", "mov", "xor", "lea", "nop"), insns[0].mnemonic

    # read code bytes at the function entry
    data = backend.read(info.pid, insns[0].address, 8)
    assert len(data) == 8
    assert data[:2] == b"\x55\x48"  # push rbp ; mov rbp,rsp

    # modification number is stable
    assert backend.modification_number(info.pid) >= 0
    backend.close(info.pid)
    assert info.pid not in [p.pid for p in backend.list_open()]


def test_reopen_reuses_cached_project(krate):
    _, _, backend = krate
    spec = OpenSpec(
        path=str(FIXTURE), analyze="none", language="x86:LE:64:default", compiler="default"
    )
    first = backend.open(spec)
    second = backend.open(spec)
    assert first.pid != second.pid
    assert first.function_count == second.function_count
    backend.close(first.pid)
    backend.close(second.pid)


def test_auto_analysis_task(krate):
    _, _, backend = krate
    spec = OpenSpec(
        path=str(FIXTURE), analyze="auto", language="x86:LE:64:default", compiler="default"
    )
    info = backend.open(spec)
    try:
        _wait_analyzed(backend, info.pid)
        listing = {p.pid: p for p in backend.list_open()}
        assert listing[info.pid].function_count > 0
    finally:
        backend.close(info.pid)
