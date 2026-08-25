"""Annotation use-cases: rename, set_prototype, types, set_comment (plan §7)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ghmcp.ghidra.protocols import CommentRequest, Model, PrototypeRequest, RenameRequest
from ghmcp.platform.errors import GhmcpError
from ghmcp.services import ServiceCtx
from ghmcp.services.resolve import require_program


class RenameParams(Model):
    target: str
    new_name: str
    kind: Literal["function", "label", "data", "variable"] = "function"
    program: str | None = None


class RenameResult(Model):
    target: str
    new_name: str
    kind: str


class SetPrototypeParams(Model):
    function: str
    signature: str
    calling_convention: str | None = None
    program: str | None = None


class SetPrototypeResult(Model):
    function: str
    signature: str


class TypesParams(Model):
    action: Literal["define", "apply", "get", "list"] = "list"
    c_decl: str | None = None
    name: str | None = None
    address: str | None = None
    variable: str | None = None
    program: str | None = None


class TypesResult(Model):
    action: str
    names: list[str] = Field(default_factory=list)
    detail: dict | None = None


class SetCommentParams(Model):
    address: str
    text: str
    kind: Literal["plate", "pre", "eol", "post"] = "plate"
    batch: dict[str, str] | None = None
    program: str | None = None


class SetCommentResult(Model):
    address: str
    kind: str
    count: int


def rename_run(params: RenameParams, ctx: ServiceCtx) -> RenameResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    adapter.rename(
        pid,
        RenameRequest(kind=params.kind, target=params.target, new_name=params.new_name),
    )
    return RenameResult(target=params.target, new_name=params.new_name, kind=params.kind)


def set_prototype_run(params: SetPrototypeParams, ctx: ServiceCtx) -> SetPrototypeResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    adapter.set_prototype(
        pid,
        PrototypeRequest(
            function=params.function,
            signature=params.signature,
            calling_convention=params.calling_convention,
        ),
    )
    return SetPrototypeResult(function=params.function, signature=params.signature)


def types_run(params: TypesParams, ctx: ServiceCtx) -> TypesResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    if params.action == "define":
        if not params.c_decl:
            raise GhmcpError("define needs c_decl=", hint="pass a C typedef/struct declaration")
        names = adapter.define_types(pid, params.c_decl)
        return TypesResult(action=params.action, names=names)
    if params.action == "apply":
        if not params.name:
            raise GhmcpError(
                "apply needs name= (the type to apply in) and address=",
                hint="e.g. types(action='apply', name='MyStruct', address='0x5000')",
            )
        if not params.address:
            raise GhmcpError("apply needs address=", hint="pass the address to retype")
        from ghmcp.platform.targets import parse_address

        adapter.apply_type(pid, parse_address(params.address), params.name, params.variable)
        return TypesResult(action=params.action)
    if params.action == "get":
        if not params.name:
            raise GhmcpError("get needs name=", hint="pass a type name")
        return TypesResult(action=params.action, detail=adapter.get_type(pid, params.name))
    return TypesResult(action=params.action, names=adapter.list_types(pid))


def set_comment_run(params: SetCommentParams, ctx: ServiceCtx) -> SetCommentResult:
    adapter = ctx.require_adapter()
    pid = require_program(adapter, params.program)
    adapter.set_comment(
        pid,
        CommentRequest(
            address=params.address, kind=params.kind, text=params.text, batch=params.batch
        ),
    )
    return SetCommentResult(
        address=params.address,
        kind=params.kind,
        count=len(params.batch) if params.batch else 1,
    )
