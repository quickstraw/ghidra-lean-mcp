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
    program = entry.program
    memory = program.getMemory()
    addr = _addr(program, address)
    perms = flags or "rw"
    try:
        memory.createBlock(name, addr, size)
        return
    except TypeError:
        pass
    # BlockType-based overload: try the permissions variant.
    from ghidra.program.model.mem import MemoryBlockType

    return memory.createBlock(
        MemoryBlockType.DEFAULT,
        name,
        addr,
        size,
        False,
        "r" in perms,
        "w" in perms,
        "x" in perms,
        False,
    )


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


def diff_bytes(program_a: object, program_b: object, start: int, end: int) -> dict:
    if end < start:
        raise BadTarget("diff range end before start", hint="pass start <= end")
    length = end - start + 1
    if length > MAX_DIFF_BYTES:
        raise BadTarget(
            f"diff range is {length} bytes (cap {MAX_DIFF_BYTES})",
            hint="split the range or use mode='functions'",
        )
    abytes = _read_range(program_a, start, length)
    bbytes = _read_range(program_b, start, length)
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


def _read_range(program: object, start: int, length: int) -> bytes:
    from jpype import JArray, JByte

    addr = _addr(program, start)
    out = JArray(JByte)(length)
    try:
        program.getMemory().getBytes(addr, out)
    except BaseException:
        return b"\x00" * length
    try:
        return bytes(out)
    except Exception:
        return bytes(bytearray(out))


def _suppress():
    import contextlib

    return contextlib.suppress(BaseException)
