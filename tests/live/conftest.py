"""Shared JVM lifecycle for the live test modules.

JPype cannot restart a JVM: two module-scoped `JvmManager.start()` calls in
one pytest process crash natively (access violation + "JVM cannot be
restarted"), so there is exactly ONE session-scoped JVM per `-m live` run and
every live module consumes it instead of starting its own.

faulthandler is disabled by default for live runs: on Windows, faulthandler's
SEH filter reports the JVM's internally-handled access violations as noisy
'Windows fatal exception' dumps while the run happily passes. When chasing a
real crash, opt back in with `$env:GHMCP_FAULTHANDLER=1` (or `-p faulthandler`).

Run: `$env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run pytest -m live`
"""

from __future__ import annotations

import faulthandler
import os

import pytest

from ghmcp.platform.config import Settings
from ghmcp.runtime.jvm import JvmManager


def pytest_sessionstart(session):
    # Session start runs AFTER every pytest_configure (including the
    # faulthandler plugin's enable) — this is the last word. Opt-out gate:
    # keep diagnostics available for real native crashes.
    if os.environ.get("GHMCP_FAULTHANDLER") != "1":
        faulthandler.disable()


@pytest.fixture(scope="session")
def jvm() -> JvmManager:
    settings = Settings()
    assert not settings.fake, "live tests must not run in fake mode"
    assert os.environ.get("GHIDRA_INSTALL_DIR"), (
        "GHIDRA_INSTALL_DIR must be set for live tests"
    )
    manager = JvmManager(settings)
    info = manager.start()
    assert info["version"], f"expected a Ghidra version, got {info}"
    yield manager
    manager.shutdown()
