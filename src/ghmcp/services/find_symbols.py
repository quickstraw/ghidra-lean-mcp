"""find_symbols use-case (plan §7)."""

from __future__ import annotations

from pydantic import Field

from ghmcp.ghidra.protocols import Model, Symbol, SymbolQuery
from ghmcp.platform import format as fmt
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class FindSymbolsParams(Model):
    query: str | None = None
    kind: str | None = None
    undefined_only: bool = False
    min_size: int = Field(0, ge=0)
    range_: str | None = None
    offset: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    program: str | None = None


class FindSymbolsResult(Model):
    symbols: list[Symbol] = Field(default_factory=list)
    truncated: bool = False
    next_offset: int | None = None


def run(params: FindSymbolsParams, ctx: ServiceCtx) -> FindSymbolsResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    request = SymbolQuery(
        query=params.query,
        kind=params.kind,
        undefined_only=params.undefined_only,
        min_size=params.min_size,
        range_=params.range_,
        offset=params.offset,
        limit=params.limit,
        program=params.program,
    )
    rows, more = adapter.symbols(pid, request)
    truncated, next_offset = fmt.paginate(params.offset, len(rows), params.limit, more=more)
    return FindSymbolsResult(symbols=rows, truncated=truncated, next_offset=next_offset)
