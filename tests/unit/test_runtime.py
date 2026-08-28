"""warm_jvm honoring: eager (default) vs lazy boot, and backend lazy bootstrap.

No JVM is started here — JvmManager is stubbed; these tests pin the boot
semantics that the real backend depends on.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.platform.config import Settings
from ghmcp.runtime.runtime import Runtime


class _FakeJvm:
    def __init__(self, settings):
        self.settings = settings
        self.started = False
        self.calls = 0

    def start(self):
        self.calls += 1
        self.started = True
        return {"version": "fake"}

    def shutdown(self):
        self.started = False

    def info(self):
        return {"version": "fake", "extension_dir": None, "install_dir": None}


def _settings(**overrides) -> Settings:
    return Settings(fake=False, ghidra_install_dir=Path("x"), **overrides)


def test_warm_jvm_true_starts_eagerly(monkeypatch):
    made = []

    def factory(settings):
        jvm = _FakeJvm(settings)
        made.append(jvm)
        return jvm

    monkeypatch.setattr("ghmcp.runtime.jvm.JvmManager", factory)
    rt = Runtime(_settings(warm_jvm=True))
    asyncio.run(rt.start())
    assert made and made[0].started, "warm_jvm=True must boot the JVM at server start"
    asyncio.run(rt.close())


def test_warm_jvm_false_defers_boot(monkeypatch):
    made = []

    def factory(settings):
        jvm = _FakeJvm(settings)
        made.append(jvm)
        return jvm

    monkeypatch.setattr("ghmcp.runtime.jvm.JvmManager", factory)
    rt = Runtime(_settings(warm_jvm=False))
    asyncio.run(rt.start())
    assert made and not made[0].started, "warm_jvm=False must defer the boot"
    asyncio.run(rt.close())


def test_backend_bootstraps_jvm_lazily_once():
    settings = _settings(warm_jvm=False)
    jvm = _FakeJvm(settings)
    backend = GhidraBackend(jvm, settings)
    assert not jvm.started
    backend._bootstrap()
    assert jvm.started and jvm.calls == 1, "first adapter use boots the JVM"
    backend._bootstrap()
    assert jvm.calls == 1, "lazy boot must be idempotent"


def test_backend_env_bootstraps_jvm_lazily():
    settings = _settings(warm_jvm=False)
    jvm = _FakeJvm(settings)
    backend = GhidraBackend(jvm, settings)
    env = backend.env()
    assert jvm.started and env.ghidra_version == "fake"
    backend.shutdown()
