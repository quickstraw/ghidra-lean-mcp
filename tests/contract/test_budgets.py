"""Contract tests: budgets and layering (no JVM, no Ghidra install needed)."""

from __future__ import annotations

import json
import subprocess

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent  # noqa: F401  (kept available for catalog tests)

from ghmcp.platform.config import Settings
from ghmcp.platform.registry import tools_list_payload
from ghmcp.server import build_server
from ghmcp.tools import ALL_SPECS

MAX_TOOLS = 20
TOKEN_BUDGET_SOFT = 3_000
TOKEN_BUDGET_HARD = 4_000


def test_tool_budget():
    assert len(ALL_SPECS) <= MAX_TOOLS, (
        f"catalog has {len(ALL_SPECS)} tools — the §1 budget is {MAX_TOOLS}; "
        "displace an existing tool or prove run_script can't do it"
    )


def test_tool_names_unique():
    names = [s.name for s in ALL_SPECS]
    assert len(names) == len(set(names))


def test_token_budget():
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
    except Exception:  # pragma: no cover - offline CI without tiktoken weights
        enc = None

    payload: dict[str, object] = {
        "tools": tools_list_payload(ALL_SPECS),
    }
    text = json.dumps(payload, separators=(",", ":"), default=str)
    tokens = len(enc.encode(text)) if enc else len(text) // 4

    assert tokens <= TOKEN_BUDGET_HARD, (
        f"tools/list is {tokens} tokens — §7 hard fail at {TOKEN_BUDGET_HARD}"
    )
    assert tokens <= TOKEN_BUDGET_SOFT, (
        f"tools/list is {tokens} tokens, over the §7 {TOKEN_BUDGET_SOFT} budget — "
        "trim descriptions/schemas before this can merge"
    )


def test_layering_import_linter():
    root = str(__import__("pathlib").Path(__file__).resolve().parents[2])
    result = subprocess.run(
        ["import-linter", "lint", "--config", "pyproject.toml"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert result.returncode == 0, f"import-linter failed:\n{result.stdout}\n{result.stderr}"


def test_server_registers_every_spec():
    import asyncio

    server = build_server(Settings(fake=True))
    assert isinstance(server, MCPServer)
    tools = [t.name for t in ALL_SPECS]
    registered_names = {t.name for t in asyncio.run(server.list_tools())}
    assert all(t in registered_names for t in tools)
    assert not registered_names - set(tools)
