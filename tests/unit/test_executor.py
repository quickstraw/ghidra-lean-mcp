"""Executor: pinned pool, timeouts, backpressure, outcome timing."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from ghmcp.platform.errors import BusyError, Timeout
from ghmcp.runtime.executor import ExecOutcome, Executor


class _Spec:
    """Minimal spec stand-in; executor only touches .service/.name/.timeout."""

    def __init__(self, name: str, timeout: float, service):
        self.name = name
        self.timeout = timeout
        self.service = service


def test_runs_on_worker_and_returns_outcome():
    def service(params, ctx):
        return ("ran", params)

    executor = Executor(pool_size=2)
    out = asyncio.run(executor.run(_Spec("t", 5.0, service), 7))
    assert isinstance(out, ExecOutcome)
    assert out.result == ("ran", 7)
    assert out.jvm_ms >= 0.0
    executor.shutdown()


def test_service_receives_params_and_ctx():
    calls = []

    def service(params, ctx):
        calls.append((params, ctx))
        return "ok"

    executor = Executor(pool_size=1)
    executor.set_ctx_factory(lambda: {"who": "ctx"})
    assert asyncio.run(executor.run(_Spec("t", 5.0, service), 42)).result == "ok"
    assert calls == [(42, {"who": "ctx"})]
    executor.shutdown()


def test_timeout_raises_gmcp_timeout():
    def slow(params, ctx):
        time.sleep(5)
        return "late"

    executor = Executor(pool_size=1)
    with pytest.raises(Timeout):
        asyncio.run(executor.run(_Spec("slow", 0.2, slow), None))
    executor.shutdown()


def test_queue_overflow_raises_busy():
    def blocked(params, ctx):
        time.sleep(2)
        return params

    def quick(params, ctx):
        return params

    executor = Executor(pool_size=1)

    async def main():
        first = asyncio.create_task(executor.run(_Spec("blocked", 10.0, blocked), 0))
        await asyncio.sleep(0.2)  # worker picks up the blocking task
        queued = asyncio.create_task(executor.run(_Spec("quick", 10.0, quick), 1))
        await asyncio.sleep(0.2)  # the queue slot is now full
        with pytest.raises(BusyError):
            await executor.run(_Spec("overflow", 10.0, quick), 2)
        await first
        await queued

    asyncio.run(main())
    executor.shutdown()


def test_pool_scales_and_reuses_pinned_workers():
    seen_threads: set[int] = set()

    def service(params, ctx):
        seen_threads.add(threading.get_ident())
        return params

    executor = Executor(pool_size=4)

    async def main():
        return await asyncio.gather(*[executor.run(_Spec("t", 5.0, service), i) for i in range(4)])

    results = asyncio.run(main())
    assert [r.result for r in results] == [0, 1, 2, 3]
    assert len(seen_threads) <= 4, "workers must be pinned, not one thread per task"
    executor.shutdown()
