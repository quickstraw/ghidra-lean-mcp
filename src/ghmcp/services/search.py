"""search_binary use-case (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import Hit, Model, SearchQuery
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class SearchParams(Model):
    pattern: str
    mode: Literal["bytes", "text", "instructions", "scalars"] = "bytes"
    range_: str | None = None
    limit: int = Field(64, ge=1, le=1000)
    program: str | None = None


class SearchResult(Model):
    mode: str
    hits: list[Hit] = Field(default_factory=list)
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


def run(params: SearchParams, ctx: ServiceCtx) -> SearchResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    request = SearchQuery(
        mode=params.mode,
        pattern=params.pattern,
        range_=params.range_,
        limit=params.limit,
        program=params.program,
    )
    hits = adapter.find(pid, request)
    truncated = len(hits) >= params.limit
    return SearchResult(mode=params.mode, hits=hits[: params.limit], truncated=truncated)
