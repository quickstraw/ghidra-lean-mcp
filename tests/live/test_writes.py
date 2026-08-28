"""Live write-path tests (M6/M7): annotation + memory tools against real Ghidra.

Every live test gets its own throwaway projects_dir so re-runs never trip on
persisted annotations (renames/blocks saved into the shared project cache).

Run with:
    $env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run pytest -m live tests/live
(faulthandler is disabled by tests/live/conftest.py — JVM-internal SEH noise.)
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path

import pytest

from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.ghidra.protocols import CommentRequest, OpenSpec, PrototypeRequest, RenameRequest
from ghmcp.platform.config import Settings
from ghmcp.platform.errors import GhmcpError

pytestmark = pytest.mark.live

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bin" / "tiny_x86.coff"
LANGUAGE = "x86:LE:64:default"


@pytest.fixture(scope="module")
def wrate(jvm):
    settings = Settings(projects_dir=Path(tempfile.mkdtemp(prefix="ghmcp-live-writes-")))
    backend = GhidraBackend(jvm, settings)
    yield settings, jvm, backend
    with contextlib.suppress(Exception):
        backend.shutdown()


def _open(backend: GhidraBackend, writable: bool = True):
    return backend.open(
        OpenSpec(
            path=str(FIXTURE),
            analyze="auto",
            language=LANGUAGE,
            compiler="default",
            writable=writable,
        )
    )


def _wait_analyzed(backend: GhidraBackend, info, wait: float = 120.0) -> None:
    """Wait for the auto-analysis TASK (not just function count): analysis
    keeps a transaction open, so save() must wait until it is truly done.
    `info` must come from open() itself — list_open() rebuilds snapshots
    without the analysis_task_id."""
    import time

    deadline = time.time() + wait
    if info.analysis_task_id:
        while time.time() < deadline:
            status = backend.task_status(info.analysis_task_id)  # TaskFailed if it errored
            if status.get("state") != "running":
                break
            time.sleep(0.5)
    while time.time() < deadline:
        infos = {p.pid: p for p in backend.list_open()}
        if infos.get(info.pid) and infos[info.pid].function_count > 0:
            return
        time.sleep(1.0)
    raise AssertionError("analysis did not finish in time")


def test_write_cycle(wrate):
    _, _, backend = wrate
    info = _open(backend)
    pid = info.pid
    assert info.writable
    _wait_analyzed(backend, info)  # prototypes need an analyzed program (12.x)

    backend.rename(pid, RenameRequest(kind="function", target="start", new_name="probe_start"))
    # Rename back: the shared project cache must stay reusable across runs.
    backend.rename(pid, RenameRequest(kind="function", target="probe_start", new_name="start"))

    backend.set_comment(pid, CommentRequest(kind="plate", address="0x2100", text="hello"))

    backend.define_types(pid, "typedef int myword;")
    assert "myword" in backend.list_types(pid)

    # Pointer fields must be pointers (not 1-byte pointee values): a struct
    # with one 'char *name' field is one pointer (8 bytes on x64).
    backend.define_types(pid, "struct PS2 { char *name; };")
    assert backend.get_type(pid, "PS2")["size"] == 8, "pointer field must be pointer-sized"

    backend.set_prototype(pid, PrototypeRequest(function="start", signature="int start();"))

    backend.create_block(pid, "probe_tbl", 0x600100, 0x1000, "rw")
    names = [b["name"] for b in backend.memory_map(pid)]
    assert "probe_tbl" in names

    backend.save(pid)
    backend.close(pid)


def test_write_gated_on_read_only_session(wrate):
    _, _, backend = wrate
    info = _open(backend, writable=False)
    with pytest.raises(GhmcpError, match="read-only"):
        backend.rename(info.pid, RenameRequest(kind="function", target="start", new_name="x"))
    backend.close(info.pid)


def test_diff_bytes_unmapped_range_raises(wrate):
    _, _, backend = wrate
    a = _open(backend, writable=False)
    b = _open(backend, writable=False)
    try:
        with pytest.raises(GhmcpError, match="cannot read"):
            backend.diff_bytes(a.pid, b.pid, 0xFF000000, 0xFF00000F)
    finally:
        backend.close(a.pid)
        backend.close(b.pid)
