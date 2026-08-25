"""program_session use-case: list/info/select/close/save/env."""

from __future__ import annotations

from pydantic import Field

from ghmcp.ghidra.protocols import EnvInfo, Model, ProgramInfo
from ghmcp.platform.errors import GhmcpError
from ghmcp.services import ServiceCtx


class SessionParams(Model):
    action: str = "list"
    pid: str | None = None


class SessionResult(Model):
    action: str
    current: str | None = None
    programs: list[ProgramInfo] = Field(default_factory=list)
    detail: ProgramInfo | None = None
    env: EnvInfo | None = None  # only for action="env"


def run(params: SessionParams, ctx: ServiceCtx) -> SessionResult:
    adapter = ctx.require_adapter()
    action = params.action
    if action == "list":
        return SessionResult(action=action, current=adapter.current(), programs=adapter.list_open())
    if action == "info":
        if params.pid is None:
            raise GhmcpError("info needs pid", hint="program_session list first")
        for info in adapter.list_open():
            if info.pid == params.pid:
                return SessionResult(
                    action=action, current=adapter.current(), programs=[info], detail=info
                )
        raise GhmcpError(f"program {params.pid!r} is not open", hint="program_session list first")
    if action == "select":
        if params.pid is None:
            raise GhmcpError("select needs pid", hint="program_session list first")
        adapter.select(params.pid)
        return SessionResult(action=action, current=adapter.current(), programs=adapter.list_open())
    if action == "close":
        if params.pid is None:
            raise GhmcpError("close needs pid", hint="program_session list first")
        adapter.close(params.pid)
        return SessionResult(action=action, current=adapter.current(), programs=adapter.list_open())
    if action == "save":
        if params.pid is None:
            raise GhmcpError("save needs pid", hint="program_session list first")
        adapter.save(params.pid)
        return SessionResult(action=action, current=adapter.current(), programs=adapter.list_open())
    if action == "env":
        return SessionResult(
            action=action,
            current=adapter.current(),
            programs=adapter.list_open(),
            env=adapter.env(),
        )
    raise GhmcpError(
        f"unknown session action {action!r}", hint="list | info | select | close | save | env"
    )
