"""Service context: everything a use-case service may touch (plain objects only)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ghmcp.platform.config import Settings


@dataclass
class ServiceCtx:
    settings: Settings | None = None
    adapter: Any | None = None

    def require_settings(self) -> Settings:
        if self.settings is None:
            raise RuntimeError("ServiceCtx has no settings — is the runtime started?")
        return self.settings

    def require_adapter(self) -> Any:
        if self.adapter is None:
            from ghmcp.platform.errors import GhmcpError

            raise GhmcpError(
                "no Ghidra backend is connected", hint="start the server without --fake"
            )
        return self.adapter
