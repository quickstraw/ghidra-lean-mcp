"""Perf gates (plan §9): the §5.5 table asserted against the live backend.

Run with `-m perf` on a machine with GHIDRA_INSTALL_DIR; without it the tests
skip (they have no meaning against a missing JVM). Results are written to
bench/results/ so regressions show up in git diffs.

`uv run pytest tests/perf -m perf`
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf


def _ghidra_or_skip() -> str:
    import os

    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install or not Path(install).exists():
        pytest.skip("GHIDRA_INSTALL_DIR is not set for perf runs")
    return install


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bin" / "tiny_x86.coff"


def test_perf_table():
    _ghidra_or_skip()
    assert FIXTURE.exists(), f"missing perf fixture {FIXTURE}"

    import contextlib

    from ghmcp.benchmark import run_real
    from ghmcp.ghidra.backend import GhidraBackend
    from ghmcp.platform.config import Settings
    from ghmcp.runtime.jvm import JvmManager

    settings = Settings()
    jvm = JvmManager(settings)
    jvm.start()
    backend = GhidraBackend(jvm, settings)
    try:
        rows = run_real(backend, settings, FIXTURE)
    finally:
        # Drain analysis tasks + close projects before the JVM stops (a
        # shutdown under a live analysis thread corrupts the JVM).
        with contextlib.suppress(Exception):
            backend.shutdown()
        jvm.shutdown()

    measured = [r for r in rows if not r.skipped]
    skipped = [r for r in rows if r.skipped]
    for row in measured:
        assert row.measured_ms is not None
        assert row.measured_ms <= row.target_ms, (
            f"{row.name}: {row.measured_ms:.1f}ms exceeds the §5.5 gate {row.target_ms}ms"
        )
    # At least the non-volume core must be measurable on the tiny fixture.
    measured_names = {r.name for r in measured}
    for core in ("env_probe", "warm_decompile", "find_symbols_page_100", "reopen_cached"):
        assert core in measured_names, f"{core} skipped: {next((r.reason for r in skipped if r.name == core), '?')}"

    results_dir = Path(__file__).resolve().parents[2] / "bench" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    # Stable name: a committed perf-latest.json diffs run-to-run (plan §9)
    # instead of accumulating timestamped files.
    dest = results_dir / "perf-latest.json"
    dest.write_text(
        json.dumps({"fixture": str(FIXTURE), "rows": [r.as_dict() for r in rows]}, indent=2),
        encoding="utf-8",
    )
