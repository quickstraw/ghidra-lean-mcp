"""Adapter parity: real and fake must expose the same method set (plan §4.4)."""

from __future__ import annotations

import inspect

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.backend import GhidraBackend
from ghmcp.ghidra.protocols import GhidraAdapter


def adapter_methods(cls: type) -> set[str]:
    return {
        name for name, fn in inspect.getmembers(cls, inspect.isfunction) if not name.startswith("_")
    }


def test_real_and_fake_method_sets_match():
    real = adapter_methods(GhidraBackend)
    fake = adapter_methods(FakeAdapter)
    assert real == fake, (
        f"adapter drift: only-real={real - fake}, only-fake={fake - real}. "
        "Extend protocols.py, implement both, keep fake/ stubs mirroring real/."
    )


def test_real_implements_protocol():
    # runtime_checkable Protocol: is-a check + at least one duck-compatible method.
    backend = object.__new__(GhidraBackend)
    assert isinstance(backend, GhidraAdapter)
    # env() is the M1 live method; its absence would fail the protocol at call time.
    assert hasattr(backend, "env")


def test_fake_implements_protocol():
    adapter = FakeAdapter()
    assert isinstance(adapter, GhidraAdapter)
    assert hasattr(adapter, "env")


def test_no_bare_not_implemented_stubs():
    """Every backend method must be implemented by the end of the milestone run.

    A bare `raise NotImplementedError(...)` in either adapter (real or fake) is a
    loud reminder that an advertised capability silently no-ops.
    """
    import inspect

    for cls in (GhidraBackend, FakeAdapter):
        for name in adapter_methods(cls):
            fn = getattr(cls, name)
            try:
                src = inspect.getsource(fn)
            except (OSError, TypeError):  # pragma: no cover - C-impls lack source
                continue
            body = src.split(":", 1)[-1]
            stripped = body.strip()
            if stripped.startswith("raise NotImplementedError"):
                raise AssertionError(f"{cls.__name__}.{name} is still an unimplemented stub")
