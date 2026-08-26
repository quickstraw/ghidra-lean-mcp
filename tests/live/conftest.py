"""Shared JVM lifecycle for the live test modules.

JPype cannot restart a JVM: two module-scoped `JvmManager.start()` calls in
one pytest process crash natively (access violation + "JVM cannot be
restarted"), so there is exactly ONE session-scoped JVM per `-m live` run and
every live module consumes it instead of starting its own.

Run: `$env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run pytest -m live`
"""

from __future__ import annotations

import os

import pytest

from ghmcp.platform.config import Settings
from ghmcp.runtime.jvm import JvmManager


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
