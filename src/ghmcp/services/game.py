"""Game-special use-cases: memory_map, diff_programs, analysis (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import Model
from ghmcp.platform.errors import GhmcpError
from ghmcp.platform.targets import parse_address
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class MemoryMapParams(Model):
    action: Literal["list", "create", "rebase"] = "list"
    name: str | None = None
    address: str | None = None
    size: int = Field(0, ge=0)
    flags: str = "rwx"
    new_base: str | None = None
    program: str | None = None


class MemoryMapResult(Model):
    action: str
    blocks: list[dict] = Field(default_factory=list)
    image_base: int | None = None


class DiffParams(Model):
    a: str
    b: str
    mode: Literal["functions", "bytes"] = "functions"
    range_: str | None = None


class DiffResult(Model):
    mode: str
    a_name: str = ""
    b_name: str = ""
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    common: list[str] = Field(default_factory=list)
    a_function_count: int = 0
    b_function_count: int = 0
    equal: bool = True
    differing_bytes: int = 0
    first_diff: int | None = None


class AnalysisParams(Model):
    action: Literal["status", "run", "options"] = "status"
    task_id: str | None = None
    program: str | None = None


class AnalysisResult(Model):
    action: str
    state: str | None = None
    task_id: str | None = None
    progress: float = 0.0
    options: dict = Field(default_factory=dict)


# ------------------------------------------------------------------ memory_map


def memory_map_run(params: MemoryMapParams, ctx: ServiceCtx) -> MemoryMapResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    if params.action == "list":
        return MemoryMapResult(action="list", blocks=adapter.memory_map(pid))
    if params.action == "create":
        if not params.name or params.address is None:
            raise GhmcpError(
                "create needs name= and address=", hint="pass name='overlay' address='0x…' size=N"
            )
        adapter.create_block(
            pid, params.name, parse_address(params.address), params.size, params.flags
        )
        return MemoryMapResult(action="create", blocks=adapter.memory_map(pid))
    if params.action == "rebase":
        if not params.new_base:
            raise GhmcpError("rebase needs new_base=", hint="pass new_base='0x08804000'")
        adapter.rebase(pid, parse_address(params.new_base))
        return MemoryMapResult(action="rebase", blocks=adapter.memory_map(pid))
    raise GhmcpError(f"unknown memory_map action {params.action!r}", hint="list | create | rebase")


# ------------------------------------------------------------------ diff_programs


def diff_run(params: DiffParams, ctx: ServiceCtx) -> DiffResult:
    adapter = ctx.require_adapter()
    if params.mode == "bytes":
        if not params.range_:
            raise GhmcpError("bytes diff needs range_=", hint="pass range_='0x1000-0x2000'")
        rng = parse_address_range(params.range_)
        result = adapter.diff_bytes(params.a, params.b, rng[0], rng[1])
        return DiffResult(
            mode="bytes",
            a_name=result.get("a_name", params.a),
            b_name=result.get("b_name", params.b),
            equal=result.get("equal", True),
            differing_bytes=result.get("differing_bytes", 0),
            first_diff=result.get("first_diff"),
        )
    result = adapter.diff_functions(params.a, params.b)
    return DiffResult(
        mode="functions",
        a_name=result.get("a_name", params.a),
        b_name=result.get("b_name", params.b),
        added=result.get("added", []),
        removed=result.get("removed", []),
        common=result.get("common", []),
        a_function_count=result.get("a_function_count", 0),
        b_function_count=result.get("b_function_count", 0),
    )


# ------------------------------------------------------------------ analysis


def analysis_run(params: AnalysisParams, ctx: ServiceCtx) -> AnalysisResult:
    adapter = ctx.require_adapter()
    if params.action == "status":
        if not params.task_id:
            raise GhmcpError("status needs task_id=", hint="analysis(action='run') first")
        task = adapter.task_status(params.task_id)
        state = "running" if task.get("state") == "running" else task.get("state")
        if task.get("state") == "failed":
            raise GhmcpError(task.get("error") or "analysis failed", hint="re-run analysis")
        return AnalysisResult(
            action="status", state=state, task_id=params.task_id, progress=float(task.get("progress", 0))
        )
    if params.action == "run":
        pid = require_program(adapter, params.program)
        task_id = adapter.analyze_async(pid, None)
        return AnalysisResult(action="run", task_id=task_id, state="running")
    if params.action == "options":
        pid = require_program(adapter, params.program)
        options = adapter.analysis_options(pid)
        state = adapter.analysis_state(pid)
        return AnalysisResult(
            action="options", state=state, options={k: v for k, v in options.items()}
        )
    raise GhmcpError(f"unknown analysis action {params.action!r}", hint="status | run | options")


def parse_address_range(text: str) -> tuple[int, int]:
    from ghmcp.platform.targets import parse_range

    rng = parse_range(text)
    if rng is None:
        raise GhmcpError(f"invalid range {text!r}", hint="pass 0x1000-0x2000")
    return rng
