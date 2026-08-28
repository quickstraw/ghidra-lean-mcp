"""Exercise every MCP tool through the real stdio server and Ghidra JVM.

Set ``GHIDRA_INSTALL_DIR``, ``GHMCP_REAL_PE``, and ``GHMCP_REAL_SECOND_PE``
to opt into this corpus-dependent test. It skips when those inputs are not
available, so the normal live suite remains portable.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

pytestmark = pytest.mark.live


def _ghmcp_command() -> list[str]:
    exe = Path(sys.executable).with_name("ghmcp.exe" if os.name == "nt" else "ghmcp")
    if exe.exists():
        return [str(exe)]
    return [sys.executable, "-m", "ghmcp"]


async def _call(session: ClientSession, name: str, arguments: dict) -> dict:
    result = await session.call_tool(name, arguments)
    assert not result.is_error, f"{name} failed: {result.content}"
    assert isinstance(result.structured_content, dict), f"{name} returned no structured payload"
    return result.structured_content


async def _wait_analysis(session: ClientSession, pid: str, task_id: str | None) -> None:
    if not task_id:
        return
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        status = await _call(session, "analysis", {"action": "status", "task_id": task_id})
        if status["state"] != "running":
            assert status["state"] in ("done", "completed"), status
            return
        await asyncio.sleep(0.5)
    raise AssertionError(f"analysis task {task_id} for {pid} did not finish")


def test_every_tool_over_real_mcp_stdio(tmp_path):
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    pe = os.environ.get("GHMCP_REAL_PE")
    second_pe = os.environ.get("GHMCP_REAL_SECOND_PE")
    missing = [
        name
        for name, value in (
            ("GHIDRA_INSTALL_DIR", ghidra_dir),
            ("GHMCP_REAL_PE", pe),
            ("GHMCP_REAL_SECOND_PE", second_pe),
        )
        if not value
    ]
    if missing:
        pytest.skip("set " + ", ".join(missing) + " for real-binary MCP coverage")
    assert ghidra_dir is not None and pe is not None and second_pe is not None
    if not Path(ghidra_dir).is_dir() or not Path(pe).is_file() or not Path(second_pe).is_file():
        pytest.skip("configured real-binary inputs are not available")

    stderr_path = tmp_path / "server.stderr"
    script_path = tmp_path / "probe.py"
    script_path.write_text(
        "print('ghidra-script-ok:', currentProgram.getName())\n"
        "print('arg0:', getScriptArgs()[0])\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "GHMCP_PROJECTS_DIR": str(tmp_path / "projects"),
            "GHMCP_JVM_HEAP": "4g",
            "GHMCP_WORKER_POOL_SIZE": "2",
            "GHMCP_DECOMPOOL_SIZE": "1",
        }
    )
    names: list[str] = []

    async def exercise() -> None:
        cmd = _ghmcp_command()
        params = StdioServerParameters(
            command=cmd[0],
            args=[*cmd[1:], "serve"],
            env=env,
            cwd=Path(__file__).resolve().parents[2],
        )
        with stderr_path.open("w+", encoding="utf-8") as errlog:
            async with (
                stdio_client(params, errlog=errlog) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                tools = await session.list_tools()
                names.extend(tool.name for tool in tools.tools)
                health = await _call(session, "health", {})
                assert health["ghidra_version"] == "12.1.2"

                opened = await _call(
                    session,
                    "open_program",
                    {"path": pe, "analyze": "auto", "writable": True},
                )
                program = opened["program"]
                pid = program["pid"]
                await _wait_analysis(session, pid, program.get("analysis_task_id"))

                listed = await _call(session, "program_session", {"action": "list"})
                assert any(item["pid"] == pid for item in listed["programs"])
                assert (await _call(session, "program_session", {"action": "info", "pid": pid}))["detail"]
                env_result = await _call(session, "program_session", {"action": "env"})
                assert env_result["env"]["loaders"] and env_result["env"]["languages"]
                assert (await _call(session, "program_session", {"action": "select", "pid": pid}))["current"] == pid

                memory_map = await _call(session, "memory_map", {"action": "list", "program": pid})
                executable = [block for block in memory_map["blocks"] if block["execute"]]
                assert executable
                symbols = await _call(
                    session,
                    "find_symbols",
                    {"kind": "function", "limit": 1000, "program": pid},
                )
                fn = next(
                    (
                        candidate
                        for candidate in symbols["symbols"]
                        if any(
                            block["start"] <= candidate["address"] <= block["end"]
                            for block in executable
                        )
                    ),
                    None,
                )
                assert fn, "expected a function in executable memory"

                decompiled = await _call(
                    session,
                    "decompile",
                    {"targets": [fn["name"]], "program": pid, "max_lines": 80},
                )
                assert decompiled["functions"] and not decompiled["functions"][0]["timeout"]
                disassembled = await _call(
                    session,
                    "disassemble",
                    {
                        "target": "function",
                        "address": fn["name"],
                        "count": 8,
                        "include_bytes": True,
                        "program": pid,
                    },
                )
                first = disassembled["instructions"][0]
                assert first["bytes"]
                address = f"0x{first['address']:x}"
                await _call(
                    session,
                    "disassemble",
                    {
                        "target": "range",
                        "start": address,
                        "end": f"0x{first['address'] + 16:x}",
                        "count": 4,
                        "program": pid,
                    },
                )
                await _call(
                    session,
                    "disassemble",
                    {
                        "target": "bytes",
                        "address": address,
                        "length": 8,
                        "count": 4,
                        "program": pid,
                    },
                )
                for format_name in ("hex", "ascii", "words", "typed"):
                    await _call(
                        session,
                        "read_memory",
                        {"address": address, "length": 8, "format": format_name, "program": pid},
                    )
                await _call(session, "xrefs", {"targets": [fn["name"]], "direction": "both", "program": pid})
                scanned = await _call(
                    session,
                    "find_strings",
                    {"source": "scan", "min_length": 8, "limit": 8, "program": pid},
                )
                defined = await _call(
                    session,
                    "find_strings",
                    {"source": "defined", "min_length": 4, "limit": 8, "program": pid},
                )
                assert scanned["strings"]
                graph = await _call(
                    session,
                    "call_graph",
                    {"target": fn["name"], "direction": "both", "depth": 1, "program": pid},
                )
                assert graph["root"]

                await _call(
                    session,
                    "search_binary",
                    {
                        "mode": "bytes",
                        "pattern": " ".join(first["bytes"].split()[:2]),
                        "limit": 4,
                        "program": pid,
                    },
                )
                assert (
                    await _call(
                        session,
                        "search_binary",
                        {"mode": "text", "pattern": scanned["strings"][0]["value"][:4], "limit": 4, "program": pid},
                    )
                )["hits"]
                await _call(session, "search_binary", {"mode": "instructions", "pattern": ".", "limit": 4, "program": pid})
                await _call(session, "search_binary", {"mode": "scalars", "pattern": "0x0", "limit": 4, "program": pid})

                inline = await _call(
                    session,
                    "run_script",
                    {
                        "kind": "python",
                        "code": "print('inline-ok')\nresult = {'format': str(program.getExecutableFormat())}",
                        "program": pid,
                    },
                )
                assert inline["error"] is None and "inline-ok" in inline["stdout"]
                external = await _call(
                    session,
                    "run_script",
                    {
                        "kind": "ghidra_script",
                        "path": str(script_path),
                        "args": ["passed"],
                        "program": pid,
                    },
                )
                assert external["error"] is None
                assert "ghidra-script-ok:" in external["stdout"] and "arg0: passed" in external["stdout"]

                original_name = fn["name"]
                renamed = f"ghmcp_probe_{fn['address']:x}"
                await _call(
                    session,
                    "rename",
                    {"target": original_name, "new_name": renamed, "program": pid},
                )
                await _call(
                    session,
                    "rename",
                    {"target": renamed, "new_name": original_name, "program": pid},
                )
                await _call(
                    session,
                    "set_comment",
                    {"address": address, "kind": "plate", "text": "ghmcp live probe", "program": pid},
                )
                await _call(
                    session,
                    "set_prototype",
                    {"function": original_name, "signature": f"int {original_name}()", "program": pid},
                )
                defined_type = await _call(
                    session,
                    "types",
                    {"action": "define", "c_decl": "typedef int ghmcp_word;", "program": pid},
                )
                assert "ghmcp_word" in defined_type["names"]
                assert "ghmcp_word" in (
                    await _call(session, "types", {"action": "list", "program": pid})
                )["names"]
                assert (
                    await _call(
                        session,
                        "types",
                        {"action": "get", "name": "ghmcp_word", "program": pid},
                    )
                )["detail"]
                if defined["strings"]:
                    await _call(
                        session,
                        "types",
                        {
                            "action": "apply",
                            "name": "ghmcp_word",
                            "address": f"0x{defined['strings'][0]['address']:x}",
                            "program": pid,
                        },
                    )

                current_blocks = (await _call(session, "memory_map", {"action": "list", "program": pid}))["blocks"]
                overlay = max(block["end"] for block in current_blocks) + 0x1000
                await _call(
                    session,
                    "memory_map",
                    {
                        "action": "create",
                        "name": "ghmcp_probe",
                        "address": f"0x{overlay:x}",
                        "size": 0x1000,
                        "flags": "rw",
                        "program": pid,
                    },
                )
                await _call(session, "analysis", {"action": "options", "program": pid})
                analysis = await _call(session, "analysis", {"action": "run", "program": pid})
                await _wait_analysis(session, pid, analysis.get("task_id"))
                status = await _call(
                    session,
                    "analysis",
                    {"action": "status", "task_id": analysis["task_id"]},
                )
                assert status["state"] in ("done", "completed")

                second = await _call(
                    session,
                    "open_program",
                    {"path": second_pe, "analyze": "auto"},
                )
                await _wait_analysis(session, second["program"]["pid"], second["program"].get("analysis_task_id"))
                await _call(
                    session,
                    "diff_programs",
                    {"a": pid, "b": second["program"]["pid"], "mode": "functions"},
                )
                await _call(
                    session,
                    "diff_programs",
                    {
                        "a": pid,
                        "b": pid,
                        "mode": "bytes",
                        "range_": f"{address}-0x{first['address'] + 7:x}",
                    },
                )
                await _call(
                    session,
                    "memory_map",
                    {"action": "rebase", "new_base": f"0x{program['image_base'] + 0x1000:x}", "program": pid},
                )
                await _call(session, "program_session", {"action": "save", "pid": pid})
                await _call(session, "program_session", {"action": "close", "pid": second["program"]["pid"]})
                await _call(session, "program_session", {"action": "close", "pid": pid})
                final_health = await _call(session, "health", {})
                assert final_health["ghidra_version"] == "12.1.2"
            errlog.flush()

    asyncio.run(exercise())
    assert set(names) == {
        "health",
        "open_program",
        "program_session",
        "decompile",
        "disassemble",
        "read_memory",
        "xrefs",
        "find_symbols",
        "find_strings",
        "call_graph",
        "search_binary",
        "run_script",
        "rename",
        "set_prototype",
        "types",
        "set_comment",
        "memory_map",
        "diff_programs",
        "analysis",
    }
    stderr = stderr_path.read_text(encoding="utf-8")
    bad_lines = [
        line
        for line in stderr.splitlines()
        if re.search(r"warn|error|traceback|exception|failed|fatal|access violation", line, re.I)
    ]
    assert not bad_lines, "server emitted warning/error diagnostics:\n" + "\n".join(bad_lines)
    assert "Traceback" not in stderr
    assert "Windows fatal exception" not in stderr
