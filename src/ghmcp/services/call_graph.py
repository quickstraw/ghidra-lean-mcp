"""call_graph use-case (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import CallGraphRequest, FunctionBrief, Model
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class CallGraphParams(Model):
    target: str
    direction: Literal["callers", "callees", "both"] = "callees"
    depth: int = Field(1, ge=1, le=5)
    path_to: str | None = None
    program: str | None = None


class CallGraphResult(Model):
    root: FunctionBrief | None = None
    callers: list[FunctionBrief] = Field(default_factory=list)
    callees: list[FunctionBrief] = Field(default_factory=list)
    path: list[FunctionBrief] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    truncated: bool = False


def run(params: CallGraphParams, ctx: ServiceCtx) -> CallGraphResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    request = CallGraphRequest(
        target=params.target,
        program=params.program,
        direction=params.direction,
        depth=params.depth,
        path_to=params.path_to,
    )
    page = adapter.call_graph(pid, request)
    return CallGraphResult(
        root=page.root,
        callers=page.callers,
        callees=page.callees,
        path=page.path,
        truncated=page.truncated,
    )
