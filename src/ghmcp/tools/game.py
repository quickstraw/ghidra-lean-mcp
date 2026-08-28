"""M7 tools: memory_map, diff_programs, analysis (plan §7)."""

from mcp.types import ToolAnnotations

from ghmcp.platform.registry import ToolSpec
from ghmcp.services import game as game_svc

_READ = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, idempotent_hint=False, open_world_hint=False)


MEMORY_MAP_SPEC = ToolSpec(
    name="memory_map",
    summary="List/create memory blocks or rebase the image base (write for create/rebase).",
    params=game_svc.MemoryMapParams,
    result=game_svc.MemoryMapResult,
    service=game_svc.memory_map_run,
    summarize=lambda r: f"memory_map[{r.action}]: {len(r.blocks)} block(s)",
    timeout=30.0,
    # list is read-only, but create/rebase write the imported program.
    annotations=_WRITE,
)

DIFF_SPEC = ToolSpec(
    name="diff_programs",
    summary="Diff two open programs by function set (JP↔US) or a byte range.",
    params=game_svc.DiffParams,
    result=game_svc.DiffResult,
    service=game_svc.diff_run,
    summarize=lambda r: (
        f"diff[{r.mode}]: "
        + (
            f"{len(r.added)} added, {len(r.removed)} removed, {len(r.common)} common"
            if r.mode == "functions"
            else f"{r.differing_bytes} byte(s) differ"
        )
    ),
    timeout=60.0,
    annotations=_READ,
)

ANALYSIS_SPEC = ToolSpec(
    name="analysis",
    summary="Analysis status/run/options. run is asynchronous: returns a task id.",
    params=game_svc.AnalysisParams,
    result=game_svc.AnalysisResult,
    service=game_svc.analysis_run,
    summarize=lambda r: f"analysis[{r.action}]: {r.state or ''}" + (f" task={r.task_id}" if r.task_id else ""),
    timeout=30.0,
    annotations=_WRITE,
)
