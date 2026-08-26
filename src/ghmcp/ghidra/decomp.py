"""Decompilation adapter: batch over the pool, per-function timeouts, LRU.

Resolution is shared with disassemble via ghidra.listing.lookup_function (same
precedence: address → exact name → case-insensitive exact → prefix), but runs
against a program-scoped name index stored on the session entry — built once
per modification number and freed when the program closes, so a K-target batch
costs one pass over the function manager and no index survives its program.

The batching is wave-based: at most `pool._size` leases are held at once, and
each wave is awaited before the next is leased, so a pool-sized server never
blocks its submit loop and a timed-out batch releases its leases as it drains.
"""

from __future__ import annotations

import contextlib
import time
from concurrent.futures import ThreadPoolExecutor

from ghmcp.ghidra.protocols import DecompiledFn, DecompileRequest
from ghmcp.platform.errors import BadTarget, BusyError, NotFound
from ghmcp.platform.targets import parse_address
from ghmcp.platform.telemetry import log_event


def decompile_program(entry: object, request: DecompileRequest, pool: object) -> list[DecompiledFn]:
    """Resolve each target to a function and decompile; never fail the batch on
    one function (it degrades that entry only).

    Batching is wave-based (at most pool._size leases at once). The per-function
    timeout scales to the batch size so a full batch fits inside the tool
    budget (120 s default): per_fn = min(60, 90/waves), and scheduling stops
    once the budget is spent — remaining targets degrade to timeout.
    """
    program = entry.program
    cache_key_mod = None
    with contextlib.suppress(Exception):
        cache_key_mod = int(program.getModificationNumber())

    targets = _resolve_functions(entry, request.targets)

    lines_by_address: dict[int, list[str]] = {}
    wave = _pool_workers(pool)
    todo: list[tuple[object, str]] = []
    for fn, target in targets:
        mod = cache_key_mod or 0
        cached = pool.cache_get(entry.pid, f"fn:{target}", mod)
        if cached is not None:
            lines_by_address[int(fn.getEntryPoint().getOffset())] = cached
        else:
            todo.append((fn, target))

    per_fn, max_targets = _batch_plan(len(todo), wave)
    # A batch larger than the pool can serve at a usable per-function budget
    # is split: the overflow is reported as deferred (not timeout) so the agent
    # runs another call with the remainder, instead of under-timing everything.
    deferred_points = {int(fn.getEntryPoint().getOffset()) for fn, _ in todo[max_targets:]}
    if deferred_points:
        todo = todo[:max_targets]
    deadline = time.monotonic() + 110.0
    with ThreadPoolExecutor(max_workers=wave) as ex:
        for start in range(0, len(todo), wave):
            if time.monotonic() > deadline:
                break  # budget spent: the remaining targets degrade to timeout
            leased = []
            for fn, target in todo[start : start + wave]:
                if time.monotonic() > deadline:
                    break
                try:
                    iface, lease = pool.acquire(program, entry.pid)
                except BusyError:
                    break  # degrade this and the remaining targets, never abort the batch
                try:
                    leased.append(
                        (
                            target,
                            ex.submit(
                                _decompile_one,
                                iface,
                                fn,
                                target,
                                pool,
                                entry,
                                cache_key_mod or 0,
                                lease,
                                per_fn,
                            ),
                        )
                    )
                except BaseException:
                    pool.release(lease)
                    raise
            for target, fut in leased:
                try:
                    entry_point, lines = fut.result()
                    if lines is not None:
                        lines_by_address[entry_point] = lines
                except Exception as exc:
                    log_event(
                        "decompile_fn_failed", tool="decompile", target=target, error=str(exc)
                    )

    result: list[DecompiledFn] = []
    for fn, _target in targets:
        entry_point = int(fn.getEntryPoint().getOffset())
        if entry_point in lines_by_address:
            result.append(
                DecompiledFn(
                    name=str(fn.getName()),
                    address=entry_point,
                    lines=lines_by_address[entry_point],
                )
            )
            continue
        if entry_point in deferred_points:
            result.append(
                DecompiledFn(
                    name=str(fn.getName()),
                    address=entry_point,
                    lines=[],
                    deferred=True,
                )
            )
            continue
        result.append(
            DecompiledFn(
                name=str(fn.getName()),
                address=entry_point,
                lines=[],
                timeout=True,
            )
        )
    return result


def _decompile_one(
    iface: object,
    fn: object,
    target: str,
    pool: object,
    entry: object,
    mod: int,
    lease: object,
    timeout: float,
):
    from ghmcp.runtime.decompool import decompile_with

    try:
        c_text = decompile_with(iface, fn, timeout)
        if c_text is None:
            return int(
                fn.getEntryPoint().getOffset()
            ), None  # timeout/error: degrade, no fake success
        lines = [line for line in c_text.splitlines() if line.strip()]
        if lines:
            pool.cache_put(entry.pid, f"fn:{target}", mod, lines)
        return int(fn.getEntryPoint().getOffset()), lines
    finally:
        pool.release(lease)


def _pool_workers(pool: object) -> int:
    return max(1, getattr(pool, "_size", 2))


def _batch_plan(todo_len: int, wave: int) -> tuple[float, int]:
    """(per_fn, max_targets): keep the per-function budget usable (≥8 s) and
    fit the batch inside the ~90 s schedule window of the 120 s tool budget."""
    waves = max(1, -(-todo_len // wave))
    per_fn = max(8.0, min(60.0, 90.0 / waves))
    # 90.0/per_fn is mathematically `waves` but floating-point division can
    # land a hair below (e.g. 90/7): int(90.0 // per_fn) would then truncate
    # one whole wave off the cap and defer targets that fit. round() fixes
    # that (11.25 still rounds to 11; the 8s floor still caps at 11 waves).
    max_targets = max(wave, wave * max(1, round(90.0 / per_fn)))
    return per_fn, max_targets


# --------------------------------------------------------------------------
# Pure index helpers (unit-testable without a JVM)
# --------------------------------------------------------------------------


def build_name_index(
    functions: list[tuple[str, object]],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """One pass over the function manager.

    Returns (exact, buckets): `exact` maps original-case names to functions
    (setdefault: the first matching name wins); `buckets` maps a 1-2 char
    prefix of the lowered name to a lowered-name → function dict (insertion
    order = program order).
    """
    exact: dict[str, object] = {}
    buckets: dict[str, dict[str, object]] = {}
    for name, fn in functions:
        text = str(name)
        low = text.lower()
        key = low[:2] if len(low) >= 2 else low or "_"
        bucket = buckets.setdefault(key, {})
        bucket.setdefault(low, fn)
        exact.setdefault(text, fn)
    return exact, buckets


def lookup_in_index(
    exact: dict[str, object], buckets: dict[str, dict[str, object]], name: str
) -> object | None:
    """Mirror listing.lookup_function's precedence on the prebuilt index:
    case-sensitive exact → case-insensitive exact (first in program order) →
    first prefix match, scanning the prefix bucket (≈1/256 of M) and then the
    whole index as a last resort."""
    fn = exact.get(name)
    if fn is not None:
        return fn
    low = name.lower()
    if not low:
        return None
    key = low[:2] if len(low) >= 2 else low
    bucket = buckets.get(key)
    if bucket is not None:
        fn = bucket.get(low)
        if fn is not None:
            return fn
        for cand, cand_fn in bucket.items():
            if cand.startswith(low) and cand != low:
                return cand_fn
    for other in buckets.values():
        if other is bucket:
            continue
        for cand, cand_fn in other.items():
            if cand.startswith(low) and cand != low:
                return cand_fn
    return None


def _resolve_functions(entry: object, targets: list[str]) -> list[tuple[object, str]]:
    """Order-preserving resolution: address → function at/containing; else the
    session-scoped name index (exact, case-insensitive exact, prefix)."""
    program = entry.program
    fm = program.getFunctionManager()
    exact, buckets = _name_index(entry, program, fm)
    out: list[tuple[object, str]] = []
    for target in targets:
        t = target.strip()
        fn = None
        try:
            value = parse_address(t)
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
            fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        except BadTarget:
            pass
        if fn is None:
            fn = lookup_in_index(exact, buckets, t)
        if fn is None:
            raise NotFound(
                f"no function at or named {t!r}",
                hint="check the address, or use find_symbols to get the exact name",
            )
        out.append((fn, t))
    return out


def _name_index(
    entry: object, program: object, fm: object
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Session-scoped cache, rebuilt when the program's modification number
    changes; freed by SessionEntry.clear_index() on program close."""
    try:
        mod = int(program.getModificationNumber())
    except Exception:
        mod = 0
    cached = entry.fn_index
    if cached is not None and cached[0] == mod:
        return cached[1], cached[2]
    functions: list[tuple[str, object]] = []
    for fn in fm.getFunctions(True) or []:
        try:
            functions.append((str(fn.getName()), fn))
        except Exception:
            continue
    exact, buckets = build_name_index(functions)
    entry.fn_index = (mod, exact, buckets)
    return exact, buckets
