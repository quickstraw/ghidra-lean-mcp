"""§0.4 response contract, end-to-end over stdio with the fake backend.

- tools/list publishes output_schema for every tool
- a call returns exactly one text block under the byte cap whose content is
  NOT the raw JSON payload
- structured_content validates against the published output_schema
- fake and real modes behave identically (fake only runs here; real is
  exercised by tests/live/)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

from ghmcp.services.models import HealthResult


def _ghmcp_command() -> list[str]:
    """Invoke ghmcp without relying on it being on PATH: the venv's own
    console script when present, else `python -m ghmcp` (defines main()).
    """
    exe = Path(sys.executable).with_name("ghmcp" + (".exe" if os.name == "nt" else ""))
    if exe.exists():
        return [str(exe)]
    return [sys.executable, "-m", "ghmcp"]


def test_stdio_roundtrip_contract():
    got: dict = {}

    async def main():
        cmd = _ghmcp_command()
        server = StdioServerParameters(command=cmd[0], args=[*cmd[1:], "serve", "--fake"])
        async with (
            stdio_client(server) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            res = await session.call_tool("health", {})
            got["tools"] = tools.tools
            got["res"] = res

    asyncio.run(main())
    tools = got["tools"]
    res: CallToolResult = got["res"]

    assert tools, "expected at least one tool"

    # (1) output_schema published
    assert all(getattr(t, "output_schema", None) for t in tools), (
        "every tool must publish output_schema"
    )

    # (2) exactly one text block, not the JSON payload
    text_blocks = [b for b in res.content if isinstance(b, TextContent)]
    assert len(text_blocks) == 1, f"expected exactly 1 text block, got {len(res.content)}"
    text = text_blocks[0].text
    assert text, "summary text must not be empty"
    assert text != json.dumps(res.structured_content, separators=(",", ":")), (
        "the text block is the JSON payload — summary/structured split broke"
    )
    assert len(text.encode("utf-8")) <= 16_384, "text block exceeds the default byte cap"

    # (3) structured_content validates against the published schema
    payload = json.loads(json.dumps(res.structured_content))
    assert HealthResult.model_validate(payload)
