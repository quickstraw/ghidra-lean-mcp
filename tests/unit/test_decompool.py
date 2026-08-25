"""Decompiler pool lease semantics (no JVM needed: fake interfaces)."""

from __future__ import annotations

import pytest

from ghmcp.platform.config import Settings
from ghmcp.platform.errors import BusyError
from ghmcp.runtime.decompool import DecompPool


class FakeIface:
    def __init__(self, fail_open: bool = False):
        self.fail_open = fail_open
        self._open_calls = 0
        self.disposed = False
        self.closed = 0
        self.opened = 0

    def closeProgram(self) -> None:
        self.closed += 1

    def openProgram(self, program) -> None:
        self._open_calls += 1
        if self.fail_open and self._open_calls == 1:
            raise RuntimeError("openProgram exploded")
        self.opened += 1

    def dispose(self) -> None:
        self.disposed = True


def make_pool(count: int, interfaces: list[FakeIface] | None = None) -> DecompPool:
    settings = Settings(fake=True)
    pool = DecompPool(settings)
    pool._size = count
    pool._interfaces = list(interfaces) if interfaces else [FakeIface() for _ in range(count)]
    pool._in_use = [False] * count
    return pool


def test_acquire_release_cycle():
    ifaces = [FakeIface(), FakeIface()]
    pool = make_pool(2, ifaces)
    iface_a, lease_a = pool.acquire("prog1", "p1")
    iface_b, lease_b = pool.acquire("prog2", "p2")
    assert iface_a is ifaces[0] and iface_b is ifaces[1]
    pool.release(lease_a)
    pool.release(lease_b)
    # both free again: same-round robin is fine, but all must be acquirable
    iface_a2, _ = pool.acquire("prog1", "p1")
    iface_b2, _ = pool.acquire("prog2", "p2")
    assert len({id(iface_a2), id(iface_b2)}) == 2


def test_bind_failure_releases_the_slot():
    broken = FakeIface(fail_open=True)
    healthy = FakeIface()
    pool = make_pool(2, [broken, healthy])
    with pytest.raises(RuntimeError):
        pool.acquire("prog1", "p1")  # slot 0 fails on first openProgram
    assert pool._in_use[0] is False, "failed bind must not strand the lease"
    # broken slot recovered after the failure: both slots usable again
    iface_a, lease_a = pool.acquire("prog1", "p1")
    iface_b, lease_b = pool.acquire("prog2", "p2")
    assert {id(iface_a), id(iface_b)} == {id(broken), id(healthy)}
    pool.release(lease_a)
    pool.release(lease_b)


def test_saturated_pool_raises_busy():
    ifaces = [FakeIface()]
    pool = make_pool(1, ifaces)
    pool._lease_timeout = 0.3
    _, lease = pool.acquire("prog1", "p1")
    with pytest.raises(BusyError):
        pool.acquire("prog2", "p2")  # only one interface, still leased
    pool.release(lease)
    iface, lease2 = pool.acquire("prog3", "p3")
    assert iface is ifaces[0]
    pool.release(lease2)


def test_release_is_idempotent():
    pool = make_pool(1)
    _, lease = pool.acquire("p", "p1")
    pool.release(lease)
    pool.release(lease)  # no error
    _, lease2 = pool.acquire("p", "p1")
    pool.release(lease2)


def test_close_disposes_natives():
    ifaces = [FakeIface()]
    pool = make_pool(1, ifaces)
    pool.acquire("p", "p1")
    pool.close()
    assert ifaces[0].disposed is True
    assert pool._in_use == []
