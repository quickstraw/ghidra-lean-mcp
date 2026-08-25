"""M5 tools: search_binary, run_script (plan §7)."""

from mcp.types import ToolAnnotations

from ghmcp.platform.registry import ToolSpec
from ghmcp.services import script as script_svc
from ghmcp.services import search as search_svc

SEARCH_SPEC = ToolSpec(
    name="search_binary",
    summary="Scan memory: masked bytes, encoded text, instruction regex or scalars.",
    params=search_svc.SearchParams,
    result=search_svc.SearchResult,
    service=search_svc.run,
    summarize=lambda r: (
        f"{len(r.hits)} hit(s) [{r.mode}]" + (", truncated" if r.truncated else "")
    ),
    timeout=60.0,
    annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
)

SCRIPT_SPEC = ToolSpec(
    name="run_script",
    summary="Run inline Python on the flat Ghidra API, or a .py Ghidra script.",
    params=script_svc.RunScriptParams,
    result=script_svc.RunScriptResult,
    service=script_svc.run,
    summarize=lambda r: (
        f"stdout {len(r.stdout)} chars"
        + (f", error: {r.error}" if r.error else "")
        + (", write" if r.write else ", read-only")
    ),
    timeout=60.0,
    annotations=ToolAnnotations(read_only_hint=False, idempotent_hint=False, open_world_hint=True),
)
