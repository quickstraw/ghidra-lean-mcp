"""Runtime state: the thing the lifespan owns and the wrappers run against.

start() boots either the JVM (real Ghidra) or the fake adapter; close() tears
the latter down and stops the JVM from the main thread (JPype rule).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ghmcp.platform.config import Settings
from ghmcp.platform.errors import ConfigError
from ghmcp.runtime.executor import Executor


@dataclass
class Runtime:
    settings: Settings
    ctx_factory: Callable[[], Any] | None = None
    started: bool = False
    adapter: Any | None = None  # GhidraBackend (JVM) or FakeAdapter (--fake)
    jvm: Any | None = None  # runtime.jvm.JvmManager; None in fake mode
    executor: Executor | None = field(default=None)

    def __post_init__(self) -> None:
        # Constructed eagerly so registration can bind the runner before lifespan runs.
        if self.executor is None:
            self.executor = Executor(pool_size=self.settings.worker_pool_size, ctx_factory=None)

    async def start(self) -> None:
        if self.started:
            return
        if self.ctx_factory is not None:
            self.executor.set_ctx_factory(self.ctx_factory)

        if not self.settings.fake:
            from ghmcp.runtime.jvm import JvmManager

            self.jvm = JvmManager(self.settings)
            if self.settings.warm_jvm:
                self._start_jvm(self.jvm)
        self.started = True

    @staticmethod
    def _start_jvm(jvm: object) -> None:
        try:
            jvm.start()
        except ConfigError:
            raise
        except Exception as exc:
            raise ConfigError(
                f"JVM failed to start: {exc}",
                hint="is GHIDRA_INSTALL_DIR set to the extracted Ghidra release?",
            ) from exc

    def attach_adapter(self, adapter: Any) -> None:
        """Server wires the adapter in after start(): runtime may not import ghidra (layering)."""
        self.adapter = adapter

    async def close(self) -> None:
        if self.executor is not None:
            self.executor.shutdown()
        if self.jvm is not None and self.jvm.started:
            self.jvm.shutdown()
        self.started = False
