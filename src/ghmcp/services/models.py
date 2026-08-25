"""Shared result models (services, tools and schemas all reuse these)."""

from __future__ import annotations

from pydantic import Field

from ghmcp.ghidra.protocols import Model  # re-export for imports


class HealthResult(Model):
    version: str = ""
    jvm_started: bool = False
    ghidra_version: str | None = None
    jvm_heap: str = ""
    projects_dir: str = ""
    byte_cap: int = 0
    extensions_dir: str = ""
    extension_warnings: list[str] = Field(default_factory=list)
