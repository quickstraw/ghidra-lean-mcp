"""Background task store: open_program(analyze="full") and analysis(action="run")
get task ids; the rest of the server is synchronous (plan §5.1)."""

from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from ghmcp.platform.errors import NotFound, TaskFailed

_TASKS: dict[str, dict] = {}


def start_task(kind: str, fn) -> str:
    pool = _get_pool()
    task_id = uuid.uuid4().hex[:12]
    _TASKS[task_id] = {
        "id": task_id,
        "kind": kind,
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
            _TASKS[task_id].update(state="failed", error=str(exc))
        finally:
            _TASKS[task_id]["elapsed_s"] = round(time.perf_counter() - t0, 2)

    pool.submit(_run)
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


_pool_holder: list[ThreadPoolExecutor | None] = [None]


def _get_pool() -> ThreadPoolExecutor:
    if _pool_holder[0] is None:
        _pool_holder[0] = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ghmcp-task")
    return _pool_holder[0]
