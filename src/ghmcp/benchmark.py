"""Perf scenarios (plan §5.5): the hot paths are measured, not guessed.

Each scenario is (name, target_ms, reason, run) where run returns the measured
milliseconds. Data-volume scenarios (masked search over an 8 MB block, a
1 000-target xref sweep) require a fixture big enough to mean anything: they
skip with a reason instead of timing a 60-byte COFF and reporting a lie.

run_real() drives the live GhidraBackend; run_fake() drives FakeAdapter so the
harness itself is exercised on CI (budgets are only asserted for the real
profile by tests/perf, which needs GHIDRA_INSTALL_DIR).
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghmcp.ghidra.protocols import (
    DecompileRequest,
    OpenSpec,
    RefsRequest,
    SearchQuery,
    StringQuery,
    SymbolQuery,
)

WARM_DECOMPILE_MS = 400.0
DECOMPILE_BATCH_8_MS = 1500.0
SYMBOLS_PAGE_100_MS = 80.0
XREFS_SWEEP_1000_MS = 1000.0
MASKED_SEARCH_8MB_MS = 700.0
REOPEN_CACHED_MS = 3000.0
ENV_PROBE_MS = 500.0
DISASSEMBLE_MS = 500.0
SCAN_STRINGS_MS = 200.0


@dataclass
class BenchRow:
    name: str
    target_ms: float
    measured_ms: float | None = None
    skipped: bool = False
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target_ms": self.target_ms,
            "measured_ms": self.measured_ms,
            "skipped": self.skipped,
            "reason": self.reason,
            **self.extra,
        }


def _timed(run: Callable[[], Any]) -> tuple[float, Any]:
    t0 = time.perf_counter()
    out = run()
    return (time.perf_counter() - t0) * 1000.0, out


def _skip(name: str, target: float, reason: str) -> BenchRow:
    return BenchRow(name, target, skipped=True, reason=reason)


# --------------------------------------------------------------------- real


def run_real(backend: Any, settings: Any, binary: Path) -> list[BenchRow]:
    """Measure the §5.5 table against the live backend + one fixture binary.

    Budgets are steady-state (§5.5): each scenario is primed once (cold JVM
    probe, decompiler spin-up) so the measured number is the warm path — a
    cold first call is a startup cost, not a per-call one.
    """
    rows: list[BenchRow] = []
    open_spec = OpenSpec(path=str(binary), analyze="auto", writable=False)

    backend.env()  # prime the JVM probe + TTL caches, then measure warm
    ms, _ = _timed(lambda: backend.env())
    rows.append(BenchRow("env_probe", ENV_PROBE_MS, ms))

    pid = backend.open(open_spec).pid
    try:
        for _ in range(300):  # wait for background analysis (plan §5.1: it is async)
            infos = {p.pid: p for p in backend.list_open()}
            if infos[pid].function_count > 0:
                break
            time.sleep(0.5)

        symbols = backend.symbols(pid, SymbolQuery(query="*", kind="function", limit=1000))[0]
        if not symbols:
            rows.append(_skip("warm_decompile", WARM_DECOMPILE_MS, "fixture produced no functions"))
        else:
            first = symbols[0].name
            if len(symbols) > 1:
                backend.decompile(pid, DecompileRequest(targets=[symbols[1].name]))
            ms, out = _timed(
                lambda: backend.decompile(pid, DecompileRequest(targets=[first]))
            )
            rows.append(
                BenchRow(
                    "warm_decompile", WARM_DECOMPILE_MS, ms,
                    extra={"function": first, "lines": sum(len(f.lines) for f in out)},
                )
            )

        if len(symbols) >= 8:
            names = [s.name for s in symbols[:8]]
            ms, _ = _timed(lambda: backend.decompile(pid, DecompileRequest(targets=names)))
            rows.append(BenchRow("decompile_batch_8", DECOMPILE_BATCH_8_MS, ms))
        else:
            rows.append(
                _skip(
                    "decompile_batch_8", DECOMPILE_BATCH_8_MS,
                    f"fixture has only {len(symbols)} function(s)",
                )
            )

        ms, _ = _timed(lambda: backend.symbols(pid, SymbolQuery(query="*", limit=100)))
        rows.append(BenchRow("find_symbols_page_100", SYMBOLS_PAGE_100_MS, ms))

        sweep = [s.address for s in symbols[:1000]]
        if len(sweep) >= 8:
            req = RefsRequest(targets=[(a, a) for a in sweep], limit=1000)
            ms, out = _timed(lambda: backend.refs(pid, req))
            rows.append(
                BenchRow(
                    "xrefs_sweep_1000", XREFS_SWEEP_1000_MS, ms,
                    extra={"targets": len(sweep), "refs": len(out[0])},
                )
            )
        else:
            rows.append(
                _skip(
                    "xrefs_sweep_1000", XREFS_SWEEP_1000_MS,
                    f"fixture has only {len(sweep)} function target(s)",
                )
            )

        blocks = backend.memory_map(pid)
        biggest = max(
            (b for b in blocks if b.get("initialized")),
            key=lambda b: b["size"],
            default=None,
        )
        if biggest is not None and biggest["size"] >= 8 * 1024 * 1024:
            req = SearchQuery(mode="bytes", pattern="de ad be ef", limit=16)
            ms, hits = _timed(lambda: backend.find(pid, req))
            rows.append(
                BenchRow(
                    "masked_search_8mb", MASKED_SEARCH_8MB_MS, ms,
                    extra={
                        "block": biggest["name"],
                        "block_mb": biggest["size"] // (1 << 20),
                        "hits": len(hits),
                    },
                )
            )
        else:
            rows.append(
                _skip(
                    "masked_search_8mb", MASKED_SEARCH_8MB_MS,
                    f"largest initialized block is "
                    f"{biggest['size'] // (1 << 20) if biggest else 0} MB (need 8)",
                )
            )

        known = next((s.name for s in symbols if s.name), None)
        if known is not None:
            from ghmcp.ghidra.protocols import InstructionsRequest

            ms, _ = _timed(
                lambda: backend.instructions(
                    pid, InstructionsRequest(target="function", start=known, count=100)
                )
            )
            rows.append(BenchRow("disassemble_page_100", DISASSEMBLE_MS, ms))
        else:
            rows.append(_skip("disassemble_page_100", DISASSEMBLE_MS, "no named function"))
    finally:
        for info in backend.list_open():
            with contextlib.suppress(Exception):
                backend.close(info.pid)

    def _reopen():
        again = backend.open(open_spec)
        backend.close(again.pid)

    reopen_ms, _ = _timed(_reopen)
    rows.append(BenchRow("reopen_cached", REOPEN_CACHED_MS, reopen_ms))
    return rows


# --------------------------------------------------------------------- fake


def run_fake(adapter: Any) -> list[BenchRow]:
    """Harness smoke: same row shape, no JVM. Budgets are not asserted here."""
    rows: list[BenchRow] = []
    pid = adapter.open(OpenSpec(path="bench.bin", analyze="none")).pid

    ms, _ = _timed(lambda: adapter.env())
    rows.append(BenchRow("env_probe", ENV_PROBE_MS, ms))
    ms, _ = _timed(lambda: adapter.symbols(pid, SymbolQuery(query="*", limit=100)))
    rows.append(BenchRow("find_symbols_page_100", SYMBOLS_PAGE_100_MS, ms))
    ms, _ = _timed(lambda: adapter.decompile(pid, DecompileRequest(targets=["main"])))
    rows.append(BenchRow("warm_decompile", WARM_DECOMPILE_MS, ms))
    req = RefsRequest(targets=[(0x2000, 0x2000), (0x1000, 0x3000)], limit=100)
    ms, _ = _timed(lambda: adapter.refs(pid, req))
    rows.append(BenchRow("xrefs_sweep_1000", XREFS_SWEEP_1000_MS, ms))
    ms, _ = _timed(lambda: adapter.find(pid, SearchQuery(mode="text", pattern="th")))
    rows.append(BenchRow("masked_search_8mb", MASKED_SEARCH_8MB_MS, ms))
    ms, _ = _timed(lambda: adapter.strings(pid, StringQuery(source="scan", limit=50)))
    rows.append(BenchRow("find_strings_scan", SCAN_STRINGS_MS, ms))
    ms, _ = _timed(lambda: adapter.read_typed(pid, 0x5000, 32))
    rows.append(BenchRow("read_typed", 30.0, ms))
    return rows
