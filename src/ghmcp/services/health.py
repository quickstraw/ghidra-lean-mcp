"""Health/env use-case: pure Python; JVM state comes from the adapter's env()."""

from __future__ import annotations

from ghmcp import __version__
from ghmcp.services import ServiceCtx
from ghmcp.services.models import HealthResult


def run(params: object, ctx: ServiceCtx) -> HealthResult:
    settings = ctx.settings
    adapter = ctx.adapter

    extension_warnings: list[str] = []
    if adapter is not None:
        env = adapter.env()
        ghidra_version = env.ghidra_version
        if env.drift_warning:
            extension_warnings.append(env.drift_warning)
    else:
        ghidra_version = None

    return HealthResult(
        version=__version__,
        jvm_started=adapter is not None,
        ghidra_version=ghidra_version,
        jvm_heap=(settings.jvm_heap if settings else ""),
        projects_dir=str(settings.projects_dir) if settings else "",
        byte_cap=settings.byte_cap if settings else 0,
        extensions_dir=(str(settings.ext_dir) if settings else ""),
        extension_warnings=extension_warnings,
    )
