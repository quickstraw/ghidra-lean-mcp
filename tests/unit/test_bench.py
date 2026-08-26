"""Bench harness unit test: the fake profile must produce complete, serializable
rows (the real profile needs a JVM and is gated by tests/perf, plan §5.5/§9)."""

from __future__ import annotations

import json

from ghmcp.benchmark import run_fake
from ghmcp.fake.adapter import FakeAdapter


def test_fake_profile_completes():
    adapter = FakeAdapter()
    rows = run_fake(adapter)
    assert rows, "the bench must always emit rows"
    for row in rows:
        assert row.measured_ms is not None, f"{row.name} must measure in fake mode"
        assert not row.skipped
        assert json.dumps(row.as_dict())  # serializable


def test_targets_are_of_probable_size():
    """Every scenario must declare a concrete §5.5 target (a 0ms gate is a typo)."""
    from ghmcp.benchmark import (
        DECOMPILE_BATCH_8_MS,
        ENV_PROBE_MS,
        MASKED_SEARCH_8MB_MS,
        REOPEN_CACHED_MS,
        SYMBOLS_PAGE_100_MS,
        WARM_DECOMPILE_MS,
        XREFS_SWEEP_1000_MS,
    )

    adapter = FakeAdapter()
    targets = {r.name: r.target_ms for r in run_fake(adapter)}
    for name, target in targets.items():
        assert target > 0, f"{name} has no positive target"
    for name, expected in {
        "warm_decompile": WARM_DECOMPILE_MS,
        "find_symbols_page_100": SYMBOLS_PAGE_100_MS,
        "xrefs_sweep_1000": XREFS_SWEEP_1000_MS,
        "masked_search_8mb": MASKED_SEARCH_8MB_MS,
        "env_probe": ENV_PROBE_MS,
    }.items():
        assert targets[name] == expected
    assert DECOMPILE_BATCH_8_MS > 0 and REOPEN_CACHED_MS > 0

    rows = run_fake(adapter)
    assert {"env_probe", "find_symbols_page_100", "warm_decompile", "read_typed"} <= {
        r.name for r in rows
    }
