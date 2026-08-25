"""run_script use-case (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import Model
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class RunScriptParams(Model):
    kind: Literal["python", "ghidra_script"] = "python"
    code: str | None = None
    path: str | None = None
    args: list[str] = Field(default_factory=list)
    write: bool = False
    program: str | None = None


class RunScriptResult(Model):
    stdout: str = ""
    result: dict | None = None
    error: str | None = None
    write: bool = False


def run(params: RunScriptParams, ctx: ServiceCtx) -> RunScriptResult:
    adapter = ctx.require_adapter()
    if params.kind == "ghidra_script" and not params.path:
        from ghmcp.platform.errors import TaskFailed

        raise TaskFailed("ghidra_script needs path=", hint="point path= at a .py Ghidra script")
    pid = require_program(adapter, params.program)
    out = adapter.run_script(pid, params.kind, params.code, params.path, list(params.args))
    return RunScriptResult(
        stdout=out.get("stdout", ""),
        result=out.get("result"),
        error=out.get("error"),
        write=params.write,
    )
