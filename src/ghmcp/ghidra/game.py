"""Game-specials adapter: memory_map, diff_programs, analysis (plan §7).

`analysis(action=run)` is the one async surface; it schedules on runtime.tasks
and returns a task id the service polls with `analysis(action=status)`. The sync
primitive `run_analysis` performs the work (also reused by open_program auto).
"""

from __future__ import annotations

from ghmcp.platform.errors import BadTarget


def memory_map(entry: object) -> list[dict]:
    program = entry.program
    blocks = []
    for b in program.getMemory().getBlocks():
        blocks.append(
            {
                "name": str(b.getName()),
                "start": int(b.getStart().getOffset()),
                "end": int(b.getEnd().getOffset()),
                "size": int(b.getSize()),
                "read": bool(b.isRead()),
                "write": bool(b.isWrite()),
                "execute": bool(b.isExecute()),
                "initialized": bool(b.isInitialized()),
                "volatile": bool(b.isVolatile()),
                "space": str(b.getStart().getAddressSpace()),
            }
        )
    return blocks


def create_block(entry: object, name: str, address: int, size: int, flags: str) -> None:
    """Create a memory block.

    Ghidra 12.1's API only exposes the template overload
    `createBlock(MemoryBlock prototype, name, addr, size)` (verified live on
    12.1.2); the old `(name, addr, size)` / `(BlockType, ...)` overloads are
    tried as fallbacks for pre-12 installs. `flags` are best-effort: the
    template form clones the prototype block's permissions, so the closest
    permission-matching initialized block is picked as the prototype."""
    program = entry.program
    memory = program.getMemory()
    addr = _addr(program, address)
    perms = flags or "rw"
    want = ("r" in perms, "w" in perms, "x" in perms)
    try:
        return memory.createBlock(_template_block(program, want), name, addr, size)
    except TypeError:
        pass
    try:
        return memory.createBlock(name, addr, size)
    except TypeError:
        pass
    from ghidra.program.model.mem import MemoryBlockType

    return memory.createBlock(
        MemoryBlockType.DEFAULT,
        name,
        addr,
        size,
        False,
        want[0],
        want[1],
        want[2],
        False,
    )


def _template_block(program: object, want: tuple[bool, bool, bool]) -> object:
    """The initialized block whose (read, write, execute) flags are closest to
    `want` (tie → first in memory order; exact match short-circuits)."""
    best = None
    best_score = None
    for blk in program.getMemory().getBlocks():
        if not blk.isInitialized():
            continue
        score = sum(
            a != b for a, b in zip(want, (blk.isRead(), blk.isWrite(), blk.isExecute()), strict=True)
        )
        if best_score is None or score < best_score:
            best, best_score = blk, score
            if score == 0:
                break
    if best is None:
        from ghmcp.platform.errors import GhmcpError

        raise GhmcpError(
            "no initialized memory block to use as a createBlock template",
            hint="open a program with initialized memory first",
        )
    return best


def rebase(entry: object, new_base: int) -> None:
    entry.program.setImageBase(_addr(entry.program, new_base), True)


def diff_functions(a: object, b: object) -> dict:
    fa = _fn_index(a.program)
    fb = _fn_index(b.program)
    added = sorted(set(fb) - set(fa))
    removed = sorted(set(fa) - set(fb))
    common = sorted(set(fa) & set(fb))
    return {
        "a_name": str(getattr(getattr(a, "info", None), "alias", None)) or a.pid,
        "b_name": str(getattr(getattr(b, "info", None), "alias", None)) or b.pid,
        "added": added,
        "removed": removed,
        "common": common,
        "a_function_count": len(fa),
        "b_function_count": len(fb),
    }


MAX_DIFF_BYTES = 16 * 1024 * 1024  # cap a single bytes-diff allocation (~§7 bounded tool design)


def diff_bytes(program_a: object, program_b: object, start: int, end: int, a_name: str = "a", b_name: str = "b") -> dict:
    if end < start:
        raise BadTarget("diff range end before start", hint="pass start <= end")
    length = end - start + 1
    if length > MAX_DIFF_BYTES:
        raise BadTarget(
            f"diff range is {length} bytes (cap {MAX_DIFF_BYTES})",
            hint="split the range or use mode='functions'",
        )
    abytes = read_bytes(program_a, start, length, a_name)
    bbytes = read_bytes(program_b, start, length, b_name)
    differing = [i for i in range(length) if abytes[i] != bbytes[i]]
    return {
        "start": start,
        "end": end,
        "length": length,
        "equal": not differing,
        "differing_bytes": len(differing),
        "first_diff": (start + differing[0]) if differing else None,
    }


def analysis_state(entry: object) -> str:
    program = entry.program
    from ghidra.program.util import GhidraProgramUtilities

    try:
        analyzed = bool(GhidraProgramUtilities.isProgramAnalyzed(program))
    except BaseException:
        analyzed = False
    try:
        instructions = int(program.getListing().getNumInstructions())
    except BaseException:
        instructions = 0
    return "analyzed" if analyzed else ("partial" if instructions else "none")


def run_analysis(entry: object, options: dict | None) -> None:
    import pyghidra

    if options:
        for key, value in (options or {}).items():
            with _suppress():
                pyghidra.analysis_property(entry.program, key, value)
    pyghidra.analyze(entry.program, None)


def analysis_options(entry: object) -> dict:
    import pyghidra

    out = {}
    try:
        for prop in pyghidra.analysis_properties(entry.program):
            try:
                out[str(prop.getName())] = str(prop.getValue())
            except BaseException:
                continue
    except BaseException:
        return {}
    return out


# -------------------------------------------------------------------------- helpers

def _addr(program: object, offset: int):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(offset))


def _fn_index(program: object) -> dict:
    fm = program.getFunctionManager()
    return {str(fn.getName()): int(fn.getEntryPoint().getOffset()) for fn in fm.getFunctions(True)}


def read_bytes(program: object, start: int, length: int, side: str = "") -> bytes:
    """Shared memory read for read_memory and diff_bytes: raise on any
    memory-subsystem failure (never zero-fill — an unreadable span must not
    compare as equal to anything, and a read error must surface as one
    GhmcpError with a hint, not a raw JPype exception)."""
    from jpype import JArray, JByte

    addr = _addr(program, start)
    out = JArray(JByte)(length)
    try:
        program.getMemory().getBytes(addr, out)
    except BaseException as exc:
        from ghmcp.platform.errors import GhmcpError

        who = f" ({side})" if side else ""
        raise GhmcpError(
            f"cannot read {length} bytes at {start:#x}{who}: {exc}",
            hint="the span likely falls outside initialized memory; restrict reads/diffs to mapped blocks",
        ) from exc
    try:
        return bytes(out)
    except Exception:
        return bytes(bytearray(out))


def _suppress():
    import contextlib

    return contextlib.suppress(BaseException)
