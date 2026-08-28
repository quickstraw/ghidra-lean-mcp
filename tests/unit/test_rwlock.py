"""RWLock semantics: reader sharing, writer exclusion, writer priority, timeouts.

The lock is the per-program serialization for real-backend ops (plan §5.1);
timeouts make contention bounded (BusyError, never a hung worker).
"""

from __future__ import annotations

import threading

import pytest

from ghmcp.platform.errors import BusyError
from ghmcp.runtime.session import RWLock


def test_readers_share() -> None:
    lock = RWLock()
    lock.acquire_read()
    got = threading.Event()
    done = threading.Event()

    def reader() -> None:
        lock.acquire_read()
        got.set()
        lock.release_read()
        done.set()

    t = threading.Thread(target=reader)
    t.start()
    assert got.wait(2.0), "a second reader must not block behind the first"
    t.join(2.0)
    lock.release_read()
    assert done.wait(2.0)


def test_writer_excludes_readers() -> None:
    lock = RWLock()
    lock.acquire_read()
    wrote = threading.Event()

    def writer() -> None:
        lock.acquire_write()
        wrote.set()
        lock.release_write()

    t = threading.Thread(target=writer)
    t.start()
    assert not wrote.wait(0.2), "writer must wait while a reader holds the lock"
    lock.release_read()
    assert wrote.wait(2.0), "writer proceeds once readers drain"
    t.join(2.0)


def test_writer_priority_blocks_new_readers() -> None:
    lock = RWLock()
    lock.acquire_read()
    wrote = threading.Event()

    def writer() -> None:
        lock.acquire_write()
        wrote.set()
        lock.release_write()

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    # A waiting writer must exclude a new reader (priority) — bounded by timeout.
    with pytest.raises(BusyError, match="program lock busy for read"):
        lock.acquire_read(timeout=0.2)
    lock.release_read()
    t.join(2.0)
    lock.acquire_read(timeout=1.0)
    lock.release_read()


def test_write_timeout_raises_busy_and_recovers() -> None:
    lock = RWLock()
    lock.acquire_read()
    errors: list[Exception] = []

    def writer() -> None:
        try:
            lock.acquire_write(timeout=0.1)
        except BusyError as exc:
            errors.append(exc)

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    t.join(2.0)
    assert errors, "writer must time out with BusyError"
    # The timed-out writer released its waiting slot: a fresh reader gets in.
    lock.acquire_read(timeout=0.5)
    lock.release_read()
    lock.release_read()


def test_read_timeout_raises_busy() -> None:
    lock = RWLock()
    lock.acquire_write()
    with pytest.raises(BusyError, match="program lock busy for read"):
        lock.acquire_read(timeout=0.1)
    lock.release_write()
    lock.acquire_read(timeout=0.5)
    lock.release_read()


def test_many_writers_are_fair() -> None:
    lock = RWLock()
    order: list[str] = []
    done = threading.Event()

    def writer(tag: str) -> None:
        lock.acquire_write()
        order.append(tag)
        lock.release_write()
        if tag == "b":
            done.set()

    threads = [threading.Thread(target=writer, args=(tag,)) for tag in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(2.0)
    assert done.wait(2.0)
    assert order == ["a", "b"], f"writers must exclude each other, got {order}"
