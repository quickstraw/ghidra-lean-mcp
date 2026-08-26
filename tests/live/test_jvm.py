"""Live JVM tests: require a Ghidra install (marker `live`).

One JVM per process (JPype cannot restart a JVM), so the live modules share
the session-scoped `jvm` fixture from tests/live/conftest.py.

Run: `$env:GHIDRA_INSTALL_DIR="<ghidra dir>"; uv run pytest -m live`
"""

from __future__ import annotations

import pytest

from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.platform.config import Settings
from ghmcp.runtime.jvm import JvmManager, resolve_install_dir

pytestmark = pytest.mark.live


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
