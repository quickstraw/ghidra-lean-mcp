"""Owns the one JVM: launch via HeadlessPyGhidraLauncher, single-start guard,
safe shutdown from the main thread, post-start info for env/doctor.

Only place allowed to call pyghidra/JPype (together with ghidra/ adapters and
runtime/ internals). Everything here must be importable with PyGhidra absent —
imports are deferred so `ghmcp server doctor` still runs on a machine without
a JVM install.
"""

from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path

from ghmcp.platform.config import Settings
from ghmcp.platform.errors import ConfigError
from ghmcp.platform.telemetry import log_event


def resolve_install_dir(settings: Settings) -> Path | None:
    """Priority: settings.ghidra_install_dir → GHIDRA_INSTALL_DIR → None (pyghidra's lookup)."""
    if settings.ghidra_install_dir is not None:
        return Path(settings.ghidra_install_dir)
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        return Path(env)
    return None


class JvmManager:
    """Single JVM lifecycle. `start()` is idempotent; `shutdown()` must run on
    the main Python thread (JPype rule, §0.1) — call it from lifespan exit,
    which runs on the main thread of asyncio.run()."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._launcher = None
        self._started = False
        self._info: dict = {"version": None, "extension_dir": None, "install_dir": None}
        self._start_lock = threading.Lock()

    @property
    def started(self) -> bool:
        return self._started

    def start(self) -> dict:
        """Idempotent; thread-safe (warm_jvm=False lazy-boots from a worker thread)."""
        with self._start_lock:
            if self._started:
                return self._info
            return self._start_locked()

    def _start_locked(self) -> dict:
        if self.settings.fake:
            raise ConfigError("fake mode — do not start the JVM")

        from pyghidra.launcher import HeadlessPyGhidraLauncher

        install_dir = resolve_install_dir(self.settings)
        if install_dir is not None and not install_dir.exists():
            raise ConfigError(
                f"Ghidra install dir {install_dir} does not exist",
                hint="set GHIDRA_INSTALL_DIR to the extracted Ghidra release",
            )

        launcher = HeadlessPyGhidraLauncher(verbose=False, install_dir=install_dir)
        vmargs = [
            f"-Xmx{self.settings.jvm_heap}",
            "-XX:+UseG1GC",
            "-Djava.awt.headless=true",
            *self.settings.jvm_vmargs,
        ]
        launcher.add_vmargs(*vmargs)
        log_event(
            "jvm_start",
            heap=self.settings.jvm_heap,
            install_dir=str(install_dir) if install_dir else None,
        )
        launcher.start(convertStrings=True)
        self._launcher = launcher
        self._started = True
        self._refresh_info()
        log_event("jvm_started", version=self._info["version"])
        return self._info

    def _refresh_info(self) -> None:
        assert self._launcher is not None
        version = getattr(self._launcher.app_info, "version", None)
        with contextlib.suppress(RuntimeError):
            extension_dir = str(self._launcher.extension_path)
        self._info = {
            "version": version,
            "extension_dir": extension_dir,
            "install_dir": str(self._launcher.install_dir) if self._launcher.install_dir else None,
        }

    def info(self) -> dict:
        if self._started:
            self._refresh_info()
        return dict(self._info)

    def shutdown(self) -> None:
        """Main-thread JVM shutdown. Idempotent; safe to call when not started."""
        if not self._started:
            return
        try:
            import jpype

            if jpype.isJVMStarted():
                jpype.shutdownJVM()
        except Exception as exc:  # pragma: no cover - best-effort teardown
            log_event("jvm_stop_error", error=str(exc))
        finally:
            self._started = False
            log_event("jvm_stopped")
