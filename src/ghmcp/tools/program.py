"""Tools: M3 surface (open_program, program_session, decompile, disassemble, read_memory)."""

from mcp.types import ToolAnnotations

from ghmcp.platform.registry import ToolSpec
from ghmcp.services import decompile, memory, open_program, session


def _join(fns) -> str:
    return ", ".join(f.name for f in fns)


OPEN_SPEC = ToolSpec(
    name="open_program",
    summary="Open (or reuse) a binary in Ghidra; ops apply to the current program.",
    params=open_program.OpenProgramParams,
    result=open_program.OpenProgramResult,
    service=open_program.run,
    summarize=lambda r: (
        f"{r.program.format or 'program'} {r.program.language} — "
        f"{r.program.function_count} functions, image base {r.program.image_base:#x} "
        + (f", preset {r.preset!r}" if r.preset else "")
    ),
    timeout=300.0,
    annotations=ToolAnnotations(
        read_only_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)

SESSION_SPEC = ToolSpec(
    name="program_session",
    summary="Manage open programs (list/info/select/close/save/env).",
    params=session.SessionParams,
    result=session.SessionResult,
    service=session.run,
    summarize=lambda r: (
        f"{r.action}: {len(r.programs)} program(s)"
        + (f", current={r.current}" if r.current else ", none selected")
        + (f", ghidra {r.env.ghidra_version}" if r.env else "")
    ),
    timeout=30.0,
    # The action is mixed: list/info/env/select read state, while close/save
    # mutate the server/project, so advertise the safe aggregate contract.
    annotations=ToolAnnotations(read_only_hint=False, idempotent_hint=False, open_world_hint=False),
)

DECOMPILE_SPEC = ToolSpec(
    name="decompile",
    summary="Decompile one or more functions to C.",
    params=decompile.DecompileParams,
    result=decompile.DecompileResult,
    service=decompile.run,
    summarize=lambda r: (
        f"decompiled={len(r.functions)} "
        + (f", timed out {sum(1 for f in r.functions if f.timeout)}" if r.truncated else "")
    ),
    timeout=120.0,
    annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
)

DISASSEMBLE_SPEC = ToolSpec(
    name="disassemble",
    summary="Disassemble a function, address range or byte window.",
    params=memory.DisassembleParams,
    result=memory.DisassembleResult,
    service=memory.disassemble_run,
    summarize=lambda r: (
        f"{len(r.instructions)} instruction(s)" + (", truncated" if r.truncated else "")
    ),
    timeout=60.0,
    annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
)

READ_SPEC = ToolSpec(
    name="read_memory",
    summary="Read raw memory at an address as hex, ascii or words.",
    params=memory.ReadParams,
    result=memory.ReadResult,
    service=memory.read_run,
    summarize=lambda r: f"{r.length} bytes @ {r.address} ({r.format})",
    timeout=30.0,
    annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
)
