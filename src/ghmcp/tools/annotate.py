"""M6 tools: rename, set_prototype, types, set_comment (plan §7)."""

from mcp.types import ToolAnnotations

from ghmcp.platform.registry import ToolSpec
from ghmcp.services import annotate as annotate_svc

_WRITE = ToolAnnotations(
    read_only_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)

RENAME_SPEC = ToolSpec(
    name="rename",
    summary="Rename a function, label, data or variable (writable session).",
    params=annotate_svc.RenameParams,
    result=annotate_svc.RenameResult,
    service=annotate_svc.rename_run,
    summarize=lambda r: f"renamed {r.kind} {r.target!r} -> {r.new_name!r}",
    timeout=30.0,
    annotations=_WRITE,
)

SETPROTOTYPE_SPEC = ToolSpec(
    name="set_prototype",
    summary="Set a function's C prototype and optional calling convention.",
    params=annotate_svc.SetPrototypeParams,
    result=annotate_svc.SetPrototypeResult,
    service=annotate_svc.set_prototype_run,
    summarize=lambda r: f"prototype {r.function!r} set",
    timeout=30.0,
    annotations=_WRITE,
)

TYPES_SPEC = ToolSpec(
    name="types",
    summary="Define/apply/list/get data types from C declarations.",
    params=annotate_svc.TypesParams,
    result=annotate_svc.TypesResult,
    service=annotate_svc.types_run,
    summarize=lambda r: f"types[{r.action}]: {len(r.names)} name(s)",
    timeout=30.0,
    annotations=_WRITE,
)

SETCOMMENT_SPEC = ToolSpec(
    name="set_comment",
    summary="Set a plate/pre/eol/post comment at an address.",
    params=annotate_svc.SetCommentParams,
    result=annotate_svc.SetCommentResult,
    service=annotate_svc.set_comment_run,
    summarize=lambda r: f"comment {r.kind} @ {r.address} ({r.count})",
    timeout=30.0,
    annotations=_WRITE,
)
