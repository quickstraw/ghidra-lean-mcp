"""runtime.tasks: target-tagged tasks, bounded waits, and pool drain."""

from __future__ import annotations

import time

from ghmcp.runtime import tasks


def _reset():
    # drain() resets the pool; a fresh pool is created lazily on next use.
    tasks.drain(timeout=1.0)


def test_start_task_records_target():
    _reset()
    tid = tasks.start_task("analysis", lambda: 42, target="p1")
    st = tasks.task_status(tid)
    assert st["state"] == "done"
    assert st["target"] == "p1"
    assert st["result"] == 42


def test_wait_for_target_blocks_only_own_target():
    _reset()
    started = time.monotonic()

    def slow():
        time.sleep(0.4)

    tid_slow = tasks.start_task("analysis", slow, target="pA")
    tasks.wait_for_target("pOTHER", timeout=0.05)  # no matching task → instant
    assert time.monotonic() - started < 0.2
    tasks.wait_for_target("pA", timeout=5.0)  # waits for pA only
    assert tasks.task_status(tid_slow)["state"] == "done"


def test_wait_for_target_is_bounded():
    _reset()

    def slower():
        time.sleep(3.0)

    tasks.start_task("analysis", slower, target="pB")
    t0 = time.monotonic()
    tasks.wait_for_target("pB", timeout=0.2)
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, f"wait must return on timeout, took {elapsed:.2f}s"


def test_drain_cancels_pending_and_resets_pool():
    _reset()

    def blocker():
        time.sleep(0.3)

    tasks.start_task("analysis", blocker, target="pC")
    tasks.start_task("analysis", blocker, target="pC")  # queued behind the worker
    t0 = time.monotonic()
    tasks.drain(timeout=5.0)
    assert time.monotonic() - t0 < 5.0
    # pool reset: a fresh task still schedules on a new executor.
    tid = tasks.start_task("analysis", lambda: 1, target="pD")
    assert tasks.task_status(tid)["state"] == "done"
    tasks.drain(timeout=1.0)
