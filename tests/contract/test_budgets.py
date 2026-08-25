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
# Token ceilings, MEASURED (2026-08-25): the MCP SDK publishes input_schema from
# wrapper annotations and output_schema from the result models, whose pydantic-v2
# form is inherently verbose. A 10-tool catalog is ~4.4k tokens by the registry
# measure (~3.9k as clients see it), so the v1 aspirational 3-4k absolute ceiling
# cannot hold for the planned 18-tool catalog (§7). These are kept as a GROWTH
# guard (a 200-tool monster still fails hard), while per-tool leanness is
# enforced by AVG_TOKENS_PER_TOOL. Recalibrated in M8 against the final catalog.
TOKEN_BUDGET_SOFT = 7_500
TOKEN_BUDGET_HARD = 9_000
AVG_TOKENS_PER_TOOL = 520  # every tool must stay lean, not just the catalog


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
        f"tools/list is {tokens} tokens — §7 growth guard hard fail at {TOKEN_BUDGET_HARD}"
    )
    assert tokens <= TOKEN_BUDGET_SOFT, (
        f"tools/list is {tokens} tokens, over the §7 {TOKEN_BUDGET_SOFT} growth bound — "
        "trim descriptions/schemas before this can merge"
    )


def test_catalog_is_lean_per_tool():
    """Every tool must stay individually lean (the true §1 leanness invariant)."""
    import tiktoken

    try:
        enc = tiktoken.get_encoding("cl100k_base")
    except Exception:  # pragma: no cover - offline CI without tiktoken weights
        enc = None

    def _tokens(text: str) -> int:
        return len(enc.encode(text)) if enc else len(text) // 4

    total = 0
    for spec in ALL_SPECS:
        item = {
            "name": spec.name,
            "input_schema": spec.params.model_json_schema(),
            "output_schema": spec.result.model_json_schema(),
        }
        total += _tokens(json.dumps(item, separators=(",", ":"), default=str))
    assert total / max(1, len(ALL_SPECS)) <= AVG_TOKENS_PER_TOOL, (
        f"avg schema tokens/tool is {total / max(1, len(ALL_SPECS)):.0f} — over "
        f"{AVG_TOKENS_PER_TOOL}; a tool is carrying too much schema (§1 displacement rule)"
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
