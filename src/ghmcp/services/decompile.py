"""decompile use-case: pass-through with batch sizing."""

from __future__ import annotations

from pydantic import Field

from ghmcp.ghidra.protocols import DecompiledFn, DecompileRequest, Model
from ghmcp.platform.errors import BadTarget
from ghmcp.services import ServiceCtx


class DecompileParams(Model):
    targets: list[str] = Field(min_length=1, max_length=64)
    program: str | None = None
    include_line_addresses: bool = False
    max_lines: int = 400


class DecompileResult(Model):
    functions: list[DecompiledFn] = Field(default_factory=list)
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


def run(params: DecompileParams, ctx: ServiceCtx) -> DecompileResult:
    adapter = ctx.require_adapter()
    pid = _resolve_program(adapter, params.program)
    request = DecompileRequest(
        targets=params.targets,
        program=params.program,
        include_line_addresses=params.include_line_addresses,
        max_lines=params.max_lines,
    )
    functions = adapter.decompile(pid, request)
    truncated = any(f.timeout for f in functions)
    notes = [f"{f.name}: decompile timed out" for f in functions if f.timeout]
    notes += [
        f"{f.name}: deferred (batch cap — split targets or rerun for the rest)"
        for f in functions
        if f.deferred
    ]
    return DecompileResult(functions=functions, truncated=truncated, notes=notes)


def _resolve_program(adapter: object, program: str | None) -> str:
    if program is not None:
        return program
    current = adapter.current()
    if current is None:
        raise BadTarget("no program open", hint="open_program first")
    return current
