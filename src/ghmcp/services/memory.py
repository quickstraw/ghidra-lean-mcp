"""disassemble + read_memory use-cases."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import Insn, InstructionsRequest, Model, TypedValue
from ghmcp.platform import format as fmt
from ghmcp.platform.errors import BadTarget
from ghmcp.platform.targets import parse_address
from ghmcp.services import ServiceCtx
from ghmcp.services.decompile import _resolve_program


class DisassembleParams(Model):
    target: Literal["function", "range", "bytes"] = "function"
    address: str | None = None
    length: int | None = None
    count: int | None = None
    include_bytes: bool = False
    program: str | None = None
    start: str | None = None
    end: str | None = None


class DisassembleResult(Model):
    instructions: list[Insn]
    truncated: bool = False


class ReadParams(Model):
    address: str
    length: int = Field(16, ge=1, le=256)
    format: Literal["hex", "ascii", "words", "typed"] = "hex"
    type: str | None = None
    program: str | None = None


class ReadResult(Model):
    address: str
    length: int
    data: str
    truncated: bool = False
    typed: list[TypedValue] | None = None  # only when format="typed"


def disassemble_run(params: DisassembleParams, ctx: ServiceCtx) -> DisassembleResult:
    adapter = ctx.require_adapter()
    pid = _resolve_program(adapter, params.program)
    if params.target == "function":
        if params.address is None:
            raise BadTarget(
                "function disassembly needs address (function name or entry 0x…)",
                hint="pass address='FUN_...': name is accepted for named functions",
            )
        start = params.start or params.address
    else:
        start = params.start or params.address or ""
        if not start:
            raise BadTarget(
                f"disassemble target={params.target!r} needs start", hint="pass start=0x…"
            )
    if params.target == "range" and not params.end and not params.length:
        raise BadTarget("range disassembly needs end", hint="pass end=0x…")
    if params.target == "bytes" and not params.length:
        raise BadTarget("byte disassembly needs length", hint="pass length=N bytes")

    request = InstructionsRequest(
        target=params.target,
        start=start,
        end=params.end,
        length=params.length,
        count=params.count,
        include_bytes=params.include_bytes,
        program=params.program,
    )
    insns = adapter.instructions(pid, request)
    return DisassembleResult(instructions=insns, truncated=False)


def read_run(params: ReadParams, ctx: ServiceCtx) -> ReadResult:
    adapter = ctx.require_adapter()
    pid = _resolve_program(adapter, params.program)

    text = params.address.strip()
    try:
        value = parse_address(text)
    except BadTarget:
        raise BadTarget(f"not an address: {text!r}", hint="pass 0x88…. or a plain number") from None

    if params.format == "typed":
        values = adapter.read_typed(pid, value, params.length, params.type)
        return ReadResult(
            address=fmt.hexaddr(value),
            length=params.length,
            data=_render_typed(values),
            typed=values,
        )

    data = adapter.read(pid, value, params.length)
    rendered = _render(data, params.format)
    return ReadResult(address=fmt.hexaddr(value), length=params.length, data=rendered)


def _render(data: bytes, fmt_mode: str) -> str:
    if fmt_mode == "hex":
        return fmt.fmt_bytes(data)
    if fmt_mode == "ascii":
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    if fmt_mode == "words":
        words = [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data) - 3, 4)]
        return " ".join(f"{w:08x}" for w in words)
    return fmt.fmt_bytes(data)


def _render_typed(values: list[TypedValue]) -> str:
    if not values:
        return "(no defined data in range)"
    return "\n".join(
        f"{v.address:#x}  {v.type_name or '?'}  [{v.size}]  {v.value}" for v in values
    )
