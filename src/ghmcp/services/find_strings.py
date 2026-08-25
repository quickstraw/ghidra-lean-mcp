"""find_strings use-case (plan §7)."""

from __future__ import annotations

from pydantic import Field

from ghmcp.ghidra.protocols import Model, StringEntry, StringQuery
from ghmcp.platform import format as fmt
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class FindStringsParams(Model):
    query: str | None = None  # substring filter on the string value
    source: str = "defined"  # defined | scan
    min_length: int = Field(0, ge=0)
    encoding: str | None = None  # utf8 | utf-16 | latin1
    with_xrefs: bool = False
    offset: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    program: str | None = None


class FindStringsResult(Model):
    strings: list[StringEntry] = Field(default_factory=list)
    truncated: bool = False
    next_offset: int | None = None


def run(params: FindStringsParams, ctx: ServiceCtx) -> FindStringsResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    request = StringQuery(
        query=params.query,
        source=params.source,
        min_length=params.min_length,
        encoding=params.encoding,
        with_xrefs=params.with_xrefs,
        offset=params.offset,
        limit=params.limit,
        program=params.program,
    )
    rows, more = adapter.strings(pid, request)
    truncated, next_offset = fmt.paginate(params.offset, len(rows), params.limit, more=more)
    return FindStringsResult(strings=rows, truncated=truncated, next_offset=next_offset)
