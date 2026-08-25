"""MCPServer assembly: lifespan owns the Runtime, registry drives registration.

All MCP SDK contact lives here (plus __main__.py for transport selection), so
an SDK rename stays a two-file change (plan §10.1).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer

from ghmcp import __version__
from ghmcp.platform.config import Settings
from ghmcp.platform.registry import build_wrapper, validate_catalog
from ghmcp.runtime.runtime import Runtime
from ghmcp.services import ServiceCtx
from ghmcp.tools import ALL_SPECS


def make_ctx_factory(runtime: Runtime):
    def factory() -> ServiceCtx:
        return ServiceCtx(settings=runtime.settings, adapter=runtime.adapter)

    return factory


def build_server(settings: Settings | None = None, *, runtime: Runtime | None = None) -> MCPServer:
    """Assemble the MCPServer: lifespan, Runtime, registry-driven registration."""
    settings = settings or Settings()
    runtime = runtime or Runtime(settings=settings)
    runtime.ctx_factory = make_ctx_factory(runtime)

    validate_catalog(ALL_SPECS, max_tools=settings.max_tools)

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[Runtime]:
        await runtime.start()
        if runtime.settings.fake:
            from ghmcp.fake.adapter import FakeAdapter

            runtime.attach_adapter(FakeAdapter(runtime.settings))
        else:
            from ghmcp.ghidra.backend import GhidraBackend

            runtime.attach_adapter(GhidraBackend(runtime.jvm, runtime.settings))
        try:
            yield runtime
        finally:
            if runtime.adapter is not None:
                with contextlib.suppress(Exception):
                    runtime.adapter.shutdown()  # best-effort native teardown
            await runtime.close()

    server = MCPServer(
        name="ghidra-headless-mcp",
        title="ghidra-headless-mcp",
        description="Headless Ghidra MCP server for reverse engineering video games.",
        version=__version__,
        lifespan=lifespan,
    )

    runner = runtime.executor.run if runtime.executor else None

    for spec in ALL_SPECS:
        if runner is None:
            raise RuntimeError("executor not initialized before registration")
        wrapper = build_wrapper(spec, runner)
        server.add_tool(
            wrapper,
            name=spec.name,
            title=spec.title,
            description=spec.description or spec.summary,
            annotations=spec.annotations,
            structured_output=True,
        )
    return server
