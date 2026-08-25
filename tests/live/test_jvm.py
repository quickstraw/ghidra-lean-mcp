"""Live JVM tests: require a Ghidra install (marker `live`).

One JVM per process (JPype cannot restart a JVM), so these tests share a
module-scoped JvmManager.

Run: `$env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run pytest -m live`
"""

from __future__ import annotations

import pytest

from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.platform.config import Settings
from ghmcp.runtime.jvm import JvmManager, resolve_install_dir

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def jvm():
    settings = Settings()
    assert not settings.fake, "live tests must not run in fake mode"
    manager = JvmManager(settings)
    info = manager.start()
    assert info["version"], f"expected a Ghidra version, got {info}"
    yield manager
    manager.shutdown()


def test_resolve_install_dir_from_env():
    settings = Settings()
    assert resolve_install_dir(settings) is not None, (
        "GHIDRA_INSTALL_DIR must be set for live tests"
    )
    assert resolve_install_dir(settings).exists()


def test_jvm_start_info(jvm: JvmManager):
    assert jvm.started
    info = jvm.info()
    assert info["version"]
    assert info["install_dir"]


def test_backend_env(jvm: JvmManager):
    backend = GhidraBackend(jvm, Settings())
    env = backend.env()
    assert env.ghidra_version == jvm.info()["version"]
    assert env.extension_dirs, (
        "extension dirs must be reported post-start (userSettings/Extensions)"
    )
