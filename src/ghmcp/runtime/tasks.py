"""Background task store: open_program(analyze="full") and analysis(action="run")
get task ids; the rest of the server is synchronous (plan §5.1)."""

from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from ghmcp.platform.errors import NotFound, TaskFailed

_TASKS: dict[str, dict] = {}
_FUTURES: dict[str, object] = {}  # task_id -> concurrent.futures.Future


def start_task(kind: str, fn, *, target: str | None = None) -> str:
    pool = _get_pool()
    task_id = uuid.uuid4().hex[:12]
    _TASKS[task_id] = {
        "id": task_id,
        "kind": kind,
        "target": target,
        "state": "running",
        "progress": 0,
        "result": None,
        "error": None,
    }

    def _run():
        t0 = time.perf_counter()
        try:
            result = fn()
            _TASKS[task_id].update(state="done", result=result, progress=1.0)
        except Exception as exc:
            task = _TASKS.get(task_id)
            if task is not None:
                task.update(state="failed", error=str(exc))
        finally:
            _FUTURES.pop(task_id, None)
            task = _TASKS.get(task_id)
            if task is not None:
                task["elapsed_s"] = round(time.perf_counter() - t0, 2)

    _FUTURES[task_id] = pool.submit(_run)
    return task_id


def task_status(task_id: str) -> dict:
    task = _TASKS.get(task_id)
    if task is None:
        raise NotFound(
            f"unknown task {task_id!r}", hint="tasks are tracked per server session only"
        )
    out = dict(task)
    if out["state"] == "failed":
        raise TaskFailed(out.get("error") or "task failed", hint=None)
    return out


def wait_for_target(target: str, timeout: float = 10.0) -> None:
    """Wait (bounded) until every task for `target` is no longer running.

    `close()` uses this before disposing a program: disposing while pyghidra
    analysis is still touching it raises DomainObjectException inside the JVM
    (Ghidra 12.1.2) and native access violations at JVM shutdown.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        running = any(
            t.get("state") == "running" and t.get("target") == target
            for t in _TASKS.values()
        )
        if not running:
            return
        time.sleep(0.1)


def drain(timeout: float = 30.0) -> None:
    """Cancel pending tasks and wait (bounded) for running ones.

    Called by backend.shutdown BEFORE programs are disposed. Resets the pool
    so a later backend (restart, tests) lazily creates a fresh one — a
    shut-down executor cannot be resubmitted to. A cancelled (never-started)
    future never runs its wrapper, so its task entry is transitioned to
    "cancelled" explicitly; otherwise the wait below would burn the full
    timeout on entries stuck in "running".
    """
    pool = _pool_holder[0]
    _pool_holder[0] = None
    if pool is None:
        return
    pool.shutdown(wait=False, cancel_futures=True)
    for tid, fut in list(_FUTURES.items()):
        if getattr(fut, "cancelled", lambda: False)():
            task = _TASKS.get(tid)
            if task is not None and task.get("state") == "running":
                task.update(state="cancelled", error="cancelled by shutdown", elapsed_s=0.0)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(t.get("state") == "running" for t in _TASKS.values()):
            break
        time.sleep(0.1)
    _TASKS.clear()
    _FUTURES.clear()


_pool_holder: list[ThreadPoolExecutor | None] = [None]


def _get_pool() -> ThreadPoolExecutor:
    if _pool_holder[0] is None:
        _pool_holder[0] = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ghmcp-task")
    return _pool_holder[0]
