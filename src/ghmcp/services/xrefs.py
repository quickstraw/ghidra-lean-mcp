"""xrefs use-case: bulk + range reference sweeps (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import Model, Ref, RefsRequest
from ghmcp.platform import format as fmt
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program, resolve


class XrefsParams(Model):
    targets: list[str] = Field(min_length=1, max_length=64)
    direction: Literal["to", "from", "both"] = "to"
    kinds: list[Literal["flow", "data", "computed"]] = Field(default_factory=list)
    offset: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=2000)
    program: str | None = None


class XrefRow(Model):
    target: str
    address: int
    is_range: bool = False
    symbol: str | None = None
    refs: list[Ref] = Field(default_factory=list)


class XrefsResult(Model):
    results: list[XrefRow] = Field(default_factory=list)
    truncated: bool = False
    next_offset: int | None = None
    notes: list[str] = Field(default_factory=list)


def run(params: XrefsParams, ctx: ServiceCtx) -> XrefsResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)

    resolved = [resolve(adapter, pid, t) for t in params.targets]
    request = RefsRequest(
        targets=[(r.start, r.end) for r in resolved],
        direction=params.direction,
        kinds=list(params.kinds),
        offset=params.offset,
        limit=params.limit,
    )
    rows, more = adapter.refs(pid, request)

    by_target: dict[int, list[Ref]] = {}
    for row in rows:
        by_target.setdefault(row.target if row.target is not None else 0, []).append(row)

    results: list[XrefRow] = []
    total = 0
    for idx, (target, r) in enumerate(zip(params.targets, resolved, strict=False)):
        refs = by_target.get(idx, [])
        total += len(refs)
        results.append(
            XrefRow(
                target=target,
                address=r.start,
                is_range=r.is_range,
                symbol=r.symbol,
                refs=refs,
            )
        )
    truncated, next_offset = fmt.paginate(params.offset, len(rows), params.limit, more=more)
    return XrefsResult(results=results, truncated=truncated, next_offset=next_offset)
