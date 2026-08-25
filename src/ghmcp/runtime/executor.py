"""Pinned long-lived worker pool for sync services.

Design (plan §5.1): workers are created once at boot and reused forever,
because JPype auto-attaches a Python thread on its first Java call and every
attach costs JVM resources. Workers call java.lang.Thread.detach() when they
exit (JVM shutdown), never between tasks. A bounded queue rejects overload
instead of letting the server drift into unbounded JVM threads.

Per-call timeout fires from the caller side: the worker keeps running until
the JVM call returns (JPype calls cannot be force-killed), but the client
gets a bounded `Timeout` result. The worker is reused, so a straggler never
leaks a thread — only its result is dropped.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from queue import Empty, Full, Queue

import anyio

from ghmcp.platform.errors import BusyError, Timeout
from ghmcp.platform.telemetry import log_event

_Task = tuple[Callable, tuple, Future]


@dataclass
class ExecOutcome:
    """Result of one JVM-bound call: the service result plus in-worker wall time."""

    result: object
    jvm_ms: float


class Executor:
    def __init__(
        self, pool_size: int | None = None, ctx_factory: Callable[[], object] | None = None
    ):
        self._pool_size = max(1, pool_size or 4)
        self._ctx_factory = ctx_factory
        self._queue: Queue[_Task] = Queue(maxsize=self._pool_size)
        self._shutdown = threading.Event()
        self._workers = [
            threading.Thread(target=self._worker_loop, name=f"ghmcp-worker-{i}", daemon=True)
            for i in range(self._pool_size)
        ]
        for w in self._workers:
            w.start()

    def set_ctx_factory(self, factory: Callable[[], object] | None) -> None:
        self._ctx_factory = factory

    # ------------------------------------------------------------------ tasks

    def _worker_loop(self) -> None:
        try:
            while not self._shutdown.is_set():
                try:
                    task = self._queue.get(timeout=0.5)
                except Empty:
                    continue
                job, args, future = task
                try:
                    if not future.set_running_or_notify_cancel():
                        continue
                    t0 = time.perf_counter()
                    try:
                        result = job(*args)
                    finally:
                        jvm_ms = (time.perf_counter() - t0) * 1000.0
                    future.set_result(ExecOutcome(result=result, jvm_ms=jvm_ms))
                except Exception as exc:  # surfaced to the caller
                    future.set_exception(exc)
                finally:
                    self._queue.task_done()
        finally:
            _detach_current_thread()

    async def run(self, spec: object, params: object) -> ExecOutcome:
        """Run spec.service(params, ctx) with spec.timeout, returning ExecOutcome."""
        ctx = self._ctx_factory() if self._ctx_factory is not None else None
        future: Future = Future()
        try:
            self._queue.put_nowait((spec.service, (params, ctx), future))
        except Full:
            raise BusyError(
                f"JVM worker pool is saturated ({self._pool_size} workers)",
                hint="retry after the current batch drains, or raise worker_pool_size in config",
            ) from None
        try:
            with anyio.fail_after(spec.timeout):
                outcome = await asyncio.shield(asyncio.wrap_future(future))
        except TimeoutError as exc:
            raise Timeout(
                f"tool {spec.name!r} exceeded its {spec.timeout:g}s budget",
                hint="retry with a smaller range/limit or raise the tool timeout in config",
            ) from exc
        log_event("call", tool=spec.name, ok=True, jvm_ms=round(outcome.jvm_ms, 2))
        return outcome

    def shutdown(self, join_timeout: float = 10.0) -> None:
        """Quiesce workers before JVM teardown: signal, then join without a
        tiny cap so in-flight JVM calls can finish (jpype.shutdownJVM must not
        fire while a worker is still inside the JVM)."""
        self._shutdown.set()
        for w in self._workers:
            w.join(timeout=max(join_timeout, 0.5))


def _detach_current_thread() -> None:
    """Called only when a worker thread is about to die (JVM shutdown)."""
    try:
        import jpype

        if jpype.isJVMStarted():
            import jpype._jvm  # ensure jpype JVM module loaded

            java_lang_thread = jpype.JClass("java.lang.Thread")
            java_lang_thread.detach()
    except Exception:
        pass  # JVM already down or never started — nothing to detach
