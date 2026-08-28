"""Session state: open programs, handles, current selection, per-program RWLock.

Many readers, one writer per program (plan §5.1). The program Java object
stays alive for the whole server session; close() releases it. The per-entry
`lock` is the real one: every read tool acquires it shared, every mutation and
`close()`/`save()` exclusively, via `ghidra/backend.py`. Locks carry a timeout
(`settings.program_lock_timeout`); expiry raises BusyError so contention never
hangs a worker thread while the tool budget still has time.

Lock ordering rule (deadlock-free): the program lock is always acquired
BEFORE a decompiler-pool lease (never after), and no op holds two program
locks at once — a two-program diff acquires both in pid order.
"""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ghmcp.platform.errors import BusyError, NotFound
from ghmcp.platform.models import ProgramInfo


class RWLock:
    """Priority-favoring writer lock: writers exclude all, readers share.

    `acquire_*` take a timeout; on expiry (or during pool shutdown) they raise
    BusyError so the caller can surface it instead of hanging the worker.
    """

    def __init__(self) -> None:
        self._cv = threading.Condition()
        self._readers = 0
        self._writers = 0
        self._writer_waiting = 0

    @property
    def writer_active(self) -> bool:
        return self._writers > 0

    def acquire_read(self, timeout: float | None = None) -> None:
        deadline = _deadline(timeout)
        with self._cv:
            while self._writers > 0 or self._writer_waiting > 0:
                _wait_or_bust(self._cv, deadline, "read")
            self._readers += 1

    def release_read(self) -> None:
        with self._cv:
            self._readers -= 1
            if self._readers == 0:
                self._cv.notify_all()

    def acquire_write(self, timeout: float | None = None) -> None:
        deadline = _deadline(timeout)
        with self._cv:
            self._writer_waiting += 1
            timed_out = False
            try:
                while self._writers > 0 or self._readers > 0:
                    try:
                        _wait_or_bust(self._cv, deadline, "write")
                    except BaseException:
                        timed_out = True
                        raise
                self._writers += 1
            finally:
                self._writer_waiting -= 1
                if timed_out:
                    # Readers blocked behind writer_waiting never got a wakeup —
                    # wake them so they re-check their predicate (the lock may
                    # be free for reading now) instead of sleeping to deadline.
                    self._cv.notify_all()

    def release_write(self) -> None:
        with self._cv:
            self._writers -= 1
            self._cv.notify_all()


def _deadline(timeout: float | None) -> float | None:
    return None if timeout is None else time.monotonic() + max(0.0, timeout)


def _wait_or_bust(cv: threading.Condition, deadline: float | None, mode: str) -> None:
    if deadline is None:
        cv.wait()
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BusyError(
            f"program lock busy for {mode}",
            hint="concurrent tools are holding the program; retry when they drain, "
            "or raise program_lock_timeout in config",
        )
    cv.wait(timeout=remaining)
    if time.monotonic() >= deadline:
        raise BusyError(
            f"program lock busy for {mode}",
            hint="concurrent tools are holding the program; retry when they drain, "
            "or raise program_lock_timeout in config",
        )


@dataclass
class SessionEntry:
    pid: str
    program: Any  # Ghidra Program
    consumer: Any  # Java consumer to release on close
    project_path: str
    info: ProgramInfo
    alias: str | None = None
    lock: RWLock = field(default_factory=RWLock)
    mod_number: int = 0
    open_flags: dict[str, Any] = field(default_factory=dict)  # writable, analyze, preset
    fn_index: tuple[int, dict[str, Any], dict[str, dict[str, Any]]] | None = None
    """Program-scoped function-name index: (mod, exact, buckets); freed on close."""
    snap_cache: dict[str, Any] | None = None
    """Snapshot scratch keyed by modification number ({'entry_points': ...}); freed on close."""

    def bump_mod(self, value: int) -> None:
        self.mod_number = value


class SessionManager:
    def __init__(self) -> None:
        self._entries: dict[str, SessionEntry] = {}
        self._current: str | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ lifecycle

    def register(self, entry: SessionEntry) -> None:
        with self._lock:
            self._entries[entry.pid] = entry
            if self._current is None:
                self._current = entry.pid

    def close(self, pid: str) -> None:
        with self._lock:
            entry = self._entries.pop(pid, None)
            if entry is None:
                raise NotFound(f"program {pid!r} is not open", hint="list open programs first")
            with contextlib.suppress(Exception):
                entry.program.release(entry.consumer)  # best-effort release on shutdown
            if self._current == pid:
                self._current = next(iter(self._entries), None)

    def get(self, pid: str) -> SessionEntry:
        entry = self._entries.get(pid)
        if entry is None:
            raise NotFound(
                f"program {pid!r} is not open", hint="call open_program or program_session list"
            )
        return entry

    def list(self) -> list[ProgramInfo]:
        with self._lock:
            return [entry.info for entry in self._entries.values()]

    def select(self, pid: str) -> None:
        self.get(pid)  # raises if unknown
        self._current = pid

    def current(self) -> str | None:
        return self._current

    def current_entry(self) -> SessionEntry | None:
        if self._current is None:
            return None
        return self._entries.get(self._current)

    def open_pids(self) -> list[str]:
        return list(self._entries)
