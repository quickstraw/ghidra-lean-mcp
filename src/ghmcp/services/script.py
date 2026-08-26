"""run_script use-case (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, ValidationError

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
    if params.write:
        _assert_writable_session(adapter, pid)
    out = adapter.run_script(pid, params.kind, params.code, params.path, list(params.args))
    try:
        return RunScriptResult(
            stdout=out.get("stdout", ""),
            result=out.get("result"),
            error=out.get("error"),
            write=params.write,
        )
    except ValidationError as exc:
        # A script set `result = [...]` or `result = 123`: surfaces as a bounded
        # tool error instead of a raw 500 (result must be a JSON object).
        from ghmcp.platform.errors import GhmcpError

        raise GhmcpError(
            "run_script result must be a JSON object (dict)",
            hint=(
                f"set result = {{...}} in the script, e.g. "
                f"result = {{'area': program.getImageBase().getOffset()}} ({exc.errors()[0]['type']})"
            ),
        ) from exc


def _assert_writable_session(adapter: object, pid: str) -> None:
    """write=true on a read-only session is a mistake, not a silent no-op:
    refuse up front so the agent re-opens writable instead of believing the
    script persisted (plan §5.1 write gating). Read the session's open flags
    directly — list_open snapshots do not carry the flag truthfully."""
    from ghmcp.platform.errors import ReadOnly

    if not adapter.is_writable(pid):
        raise ReadOnly(
            "run_script(write=true) needs a writable session",
            hint="re-open with open_program(writable=true) to persist script changes",
        )
