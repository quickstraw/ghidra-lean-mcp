"""`health` tool: server/JVM/extension status without touching a binary."""

from __future__ import annotations

from mcp.types import ToolAnnotations

from ghmcp.ghidra.protocols import Model
from ghmcp.platform.registry import ToolSpec
from ghmcp.services import health
from ghmcp.services.models import HealthResult


class HealthParamsModel(Model):
    pass


SPEC = ToolSpec(
    name="health",
    summary="Report server, JVM, Ghidra and extension status.",
    params=HealthParamsModel,
    result=HealthResult,
    service=health.run,
    summarize=lambda r: (
        f"ghidra-lean-mcp {r.version} — "
        + (
            f"JVM up ({r.ghidra_version}, heap {r.jvm_heap})"
            if r.jvm_started
            else "JVM not started"
        )
        + (f", {len(r.extension_warnings)} warning(s)" if r.extension_warnings else "")
    ),
    timeout=10.0,
    annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
)
