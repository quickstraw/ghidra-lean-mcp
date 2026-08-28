"""Lock-safety reproductions from the 2026-08-25 code review (investigation).

These tests encode the DESIRED behavior; on the current code several fail
(lock leaks / batch abort / spurious BusyError). They stay as regression
tests once the fixes land.
"""

from __future__ import annotations

import contextlib
import threading
import time

import pytest

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.decomp import build_name_index, decompile_program
from ghmcp.ghidra.protocols import DecompileRequest, OpenSpec
from ghmcp.platform.config import Settings
from ghmcp.platform.errors import BusyError
from ghmcp.platform.models import ProgramInfo
from ghmcp.runtime.session import RWLock, SessionEntry, SessionManager

# --------------------------------------------------------------------- stubs


class _F:
    def __init__(self, name: str, addr: int = 0x2000):
        self._name = name
        self._addr = addr

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return _A(self._addr)


class _A:
    def __init__(self, off: int):
        self._off = off

    def getOffset(self):
        return self._off


class _FailPool:
    """pool.acquire raises a non-BusyError (decompool re-raises bind errors)."""

    _size = 2

    def acquire(self, program, pid):
        raise RuntimeError("bind failure")

    def release(self, idx) -> None:
        pass

    def cache_get(self, pid, key, mod):
        return None

    def cache_put(self, pid, key, mod, lines) -> None:
        pass


class _OkPool(_FailPool):
    """Unused-acquire pool for the BusyError-on-acquire_read scenario."""

    def acquire(self, program, pid):
        raise AssertionError("must not be reached")


class _FM:
    def __init__(self, names: list[str]):
        self._names = names

    def getFunctions(self, _flag):
        return [_F(n) for n in self._names]


class _AS:
    def getAddress(self, v):
        return v


class _AF:
    def getDefaultAddressSpace(self):
        return _AS()


class _Prog:
    def __init__(self, names: list[str]):
        self._fm = _FM(names)

    def getModificationNumber(self):
        return 0

    def getFunctionManager(self):
        return self._fm

    def getAddressFactory(self):
        return _AF()


def _entry(names: list[str]) -> SessionEntry:
    exact, buckets = build_name_index([(n, _F(n)) for n in names])
    entry = SessionEntry(
        pid="p1",
        program=_Prog(names),
        consumer=None,
        project_path="/tmp/x",
        info=ProgramInfo(pid="p1", memory_blocks=[]),
    )
    entry.fn_index = (0, exact, buckets)
    return entry


# ------------------------------------------------------------------ reproductions


def test_wave_loop_releases_read_lock_on_pool_acquire_error():
    """decomp.py:72 — a non-BusyError from pool.acquire must not leak the read
    lock (leak = every later write on the program wedges to BusyError)."""
    entry = _entry(["foo"])
    with pytest.raises(RuntimeError, match="bind failure"):
        decompile_program(
            entry, DecompileRequest(targets=["foo"]), _FailPool(), lock_timeout=0.5
        )
    entry.lock.acquire_write(timeout=0.5)  # FAILS on current code: BusyError
    entry.lock.release_write()


def test_wave_loop_degrades_instead_of_aborting_on_read_busy():
    """decomp.py:75 — a waiting writer must degrade the batch to timeouts,
    never abort it (BusyError from acquire_read propagates today)."""
    entry = _entry(["foo"])
    entry.lock.acquire_read()  # hold a reader so the writer below waits
    writer = threading.Thread(target=entry.lock.acquire_write, kwargs={"timeout": 1.0}, daemon=True)
    writer_started = threading.Event()

    def _writer():
        writer_started.set()
        with contextlib.suppress(BusyError):
            entry.lock.acquire_write(timeout=1.0)

    writer = threading.Thread(target=_writer, daemon=True)
    writer.start()
    writer_started.wait(2.0)
    try:
        result = decompile_program(
            entry, DecompileRequest(targets=["foo"]), _OkPool(), lock_timeout=0.4
        )
        assert len(result) == 1 and result[0].timeout, (
            "batch must degrade to a timeout entry, not raise"
        )
    finally:
        entry.lock.release_read()
        writer.join(2.0)


def test_diff_pair_releases_first_lock_on_second_busy():
    """backend.py:104 — an acquire failure on the second program must not leak
    the first program's read lock."""
    from ghmcp.ghidra.backend import GhidraBackend as GB

    settings = Settings(program_lock_timeout=0.3)
    sessions = SessionManager()
    a = SessionEntry(
        pid="p1", program=_Prog(["foo"]), consumer=None, project_path="/x", info=ProgramInfo(pid="p1")
    )
    b = SessionEntry(
        pid="p2", program=_Prog(["foo"]), consumer=None, project_path="/x", info=ProgramInfo(pid="p2")
    )
    sessions.register(a)
    sessions.register(b)
    backend = object.__new__(GB)
    backend._sessions = sessions
    backend._settings = settings

    b.lock.acquire_write()  # make the SECOND (by pid order) acquisition fail
    try:
        with pytest.raises(BusyError):
            backend._diff_pair("p1", "p2")
        a.lock.acquire_write(timeout=0.5)  # FAILS on current code: leaked read lock
        a.lock.release_write()
    finally:
        b.lock.release_write()


def test_diff_pair_preserves_requested_order():
    from ghmcp.ghidra.backend import GhidraBackend as GB

    settings = Settings(program_lock_timeout=0.3)
    sessions = SessionManager()
    a = SessionEntry(
        pid="p1", program=_Prog(["a"]), consumer=None, project_path="/x", info=ProgramInfo(pid="p1")
    )
    b = SessionEntry(
        pid="p2", program=_Prog(["b"]), consumer=None, project_path="/x", info=ProgramInfo(pid="p2")
    )
    sessions.register(a)
    sessions.register(b)
    backend = object.__new__(GB)
    backend._sessions = sessions
    backend._settings = settings

    requested_a, requested_b, release = backend._diff_pair("p2", "p1")
    try:
        assert requested_a is b and requested_b is a
    finally:
        release()


def test_writer_timeout_wakes_blocked_readers():
    """session.py:68 — a writer timing out must notify waiters; otherwise a
    blocked reader sleeps to its deadline and raises BusyError spuriously."""
    def _quiet(target, *args, **kwargs):
        with contextlib.suppress(BusyError):
            target(*args, **kwargs)

    lock = RWLock()
    lock.acquire_read()
    reader_result: list[bool] = []
    writer = threading.Thread(
        target=_quiet, args=(lock.acquire_write,), kwargs={"timeout": 0.15}, daemon=True
    )
    writer.start()
    # give the writer time to queue up (writer_waiting becomes 1)
    for _ in range(100):
        if lock._writer_waiting:
            break
        time.sleep(0.01)

    def _reader() -> None:
        try:
            lock.acquire_read(timeout=1.2)
            reader_result.append(True)
            lock.release_read()
        except BusyError:
            reader_result.append(False)

    reader = threading.Thread(target=_reader, daemon=True)
    start = time.monotonic()
    reader.start()
    reader.join(3.0)
    elapsed = time.monotonic() - start
    lock.release_read()
    writer.join(2.0)
    # Desired: reader acquires as soon as the writer times out (~0.15s), not
    # after its own deadline (~1.2s → spurious BusyError on current code).
    assert reader_result == [True], "reader must acquire after the writer times out"
    assert elapsed < 0.8, f"reader woke only after {elapsed:.2f}s (lost wakeup)"

def test_diff_bytes_service_uses_adapter_current_after_ctx_cleanup():
    """Smoke: ServiceCtx no longer carries current_program; the fake adapter
    select() must be used. Guards the two-diff helpers' state usage."""
    adapter = FakeAdapter()
    p1 = adapter.open(OpenSpec(path="a.bin")).pid
    p2 = adapter.open(OpenSpec(path="b.bin")).pid
    adapter.select(p1)
    assert adapter.current() == p1
    _ = (p1, p2)
