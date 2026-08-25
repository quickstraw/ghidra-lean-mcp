"""DecompInterface pool: each instance owns a native decompiler process and its
methods are synchronized per instance (plan §5.2). Interfaces are leased: a
caller holds the exclusive use of an interface until it releases it, so two
overlapping decompile requests can never call decompileFunction on the same
native process concurrently. LRU result cache keyed by modification number."""

from __future__ import annotations

import contextlib
import threading
import time
from collections import OrderedDict

from ghmcp.platform.config import Settings
from ghmcp.platform.errors import BusyError
from ghmcp.platform.telemetry import log_event


class DecompPool:
    def __init__(self, settings: Settings, cache_size: int = 512, lease_timeout: float = 120.0):
        self._size = max(1, settings.decompool_size)
        self._interfaces: list[object] = []
        self._current_program: dict[int, str | None] = {}
        self._in_use: list[bool] = []
        self._cache: OrderedDict[tuple[str, str, int], list[str]] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Condition()
        self._next = 0
        self._lease_timeout = lease_timeout
        self._closing = False

    # ------------------------------------------------------------------ pool

    def acquire(self, program: object, pid: str) -> tuple[object, int]:
        """Lease one interface bound to `program`. Blocks until an interface is
        free; raises BusyError after `lease_timeout` seconds. On any bind error
        the slot is released again (never strands the pool)."""
        deadline = time.monotonic() + self._lease_timeout
        with self._lock:
            if self._closing:
                raise BusyError("decompiler pool is closing", hint="the server is shutting down")
            if not self._interfaces:
                self._warm_all()
            while True:
                for _ in range(len(self._interfaces)):
                    idx = self._next
                    self._next = (self._next + 1) % len(self._interfaces)
                    if not self._in_use[idx]:
                        self._in_use[idx] = True
                        try:
                            self._bind(idx, program, pid)
                        except BaseException:
                            self._in_use[idx] = False
                            self._lock.notify_all()
                            raise
                        return self._interfaces[idx], idx
                if time.monotonic() > deadline:
                    raise BusyError(
                        "decompiler pool is busy",
                        hint="retry when concurrent decompile requests drain, or raise decompool_size",
                    )
                self._lock.wait(timeout=0.5)

    def release(self, idx: int) -> None:
        with self._lock:
            if 0 <= idx < len(self._in_use):
                self._in_use[idx] = False
                self._lock.notify_all()

    def _bind(self, idx: int, program: object, pid: str) -> None:
        """Bind an interface to a program; the program object is only switched
        while we hold the exclusive lease."""
        if self._current_program.get(idx) != pid:
            with contextlib.suppress(Exception):
                self._interfaces[idx].closeProgram()
            self._interfaces[idx].openProgram(program)
            self._current_program[idx] = pid

    def _warm_all(self) -> None:
        from ghidra.app.decompiler import DecompInterface  # type: ignore[import-not-found]

        for _ in range(self._size):
            iface = DecompInterface()
            iface.toggleCCode(True)
            iface.setSimplificationStyle("decompile")
            self._interfaces.append(iface)
            self._in_use.append(False)
        log_event("decompool_warm", size=self._size)

    def close(self, drain_timeout: float = 10.0) -> None:
        """Quiesce then release native decompiler processes. Blocks new leases,
        waits (bounded) for in-use ones to drain (release() updates _in_use in
        place), then disposes — so an interface is never disposed under a live
        decompile and the following JVM teardown does not race JNI."""
        with self._lock:
            self._closing = True
            self._lock.notify_all()
        deadline = time.monotonic() + drain_timeout
        while any(self._in_use) and time.monotonic() < deadline:
            time.sleep(0.1)
        with self._lock:
            interfaces, self._interfaces = self._interfaces, []
            self._current_program = {}
            self._in_use = []
        for iface in interfaces:
            with contextlib.suppress(Exception):
                iface.dispose()

    # ------------------------------------------------------------------ cache

    def cache_get(self, pid: str, entry: str, mod_number: int):
        with self._lock:
            got = self._cache.get((pid, entry, mod_number))
            if got is not None:
                self._cache.move_to_end((pid, entry, mod_number))
            return got

    def cache_put(self, pid: str, entry: str, mod_number: int, lines: list[str]) -> None:
        with self._lock:
            key = (pid, entry, mod_number)
            self._cache[key] = lines
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)


def decompile_with(iface: object, function: object, timeout: float) -> str | None:
    """One function through one decompiler; returns C text or None on timeout/error."""
    try:
        results = iface.decompileFunction(function, int(max(1, timeout)), None)
    except Exception:
        return None
    if results is None or getattr(results, "getDecompiledFunction", lambda: None)() is None:
        return None
    return results.getDecompiledFunction().getC()
