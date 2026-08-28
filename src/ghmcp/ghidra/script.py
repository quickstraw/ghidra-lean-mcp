"""run_script backend: inline python on the flat API, or a pyghidra script (plan §7).

Inline python runs in-process against the live `Program` (the same object the
server holds), so scripts see the analyzed DB unchanged. A `result` dict binding
is returned for structured output; stdout is captured. Scripts always run
under the server's EXCLUSIVE per-program lock (a script body can mutate via
the flat API even in a read-only session — it may open its own transaction),
so concurrent readers are never racing a script. A writable session
additionally wraps each script call in a transaction; `write=true` is gated on
the session at the service layer.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

from ghmcp.platform.errors import TaskFailed


def run_script(
    entry: object,
    kind: str,
    code: str | None,
    path: str | None,
    args: list[str],
    *,
    project: object | None = None,
) -> dict:
    if kind == "ghidra_script":
        return _ghidra_script(entry, project, path, args)
    return _inline(entry, code, args)


def _inline(entry: object, code: str | None, args: list[str]) -> dict:
    if not code:
        raise TaskFailed(
            "run_script needs code=", hint="pass the python source, or kind='ghidra_script' path=…"
        )
    writable = bool((entry.open_flags or {}).get("writable"))
    program = entry.program
    ns = {
        "program": program,
        "currentProgram": program,
        "listing": program.getListing(),
        "fm": program.getFunctionManager(),
        "memory": program.getMemory(),
        "symbols": program.getSymbolTable(),
        "currentAddress": program.getMemory().getMinAddress(),
        "args": list(args),
        "result": None,
    }
    buf = io.StringIO()
    error = None
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            if writable:
                from ghmcp.runtime.txn import txn

                with txn(program, "ghmcp: run_script"):
                    exec(compile(code, "<run_script>", "exec"), ns, ns)
            else:
                exec(compile(code, "<run_script>", "exec"), ns, ns)
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        buf.write(f"\n{error}")
    return {"stdout": buf.getvalue(), "result": ns.get("result"), "error": error}


def _ghidra_script(
    entry: object, project: object | None, path: str | None, args: list[str]
) -> dict:
    if not path:
        raise TaskFailed("ghidra_script needs path=", hint="point path= at a .py Ghidra script")
    if project is None:
        raise TaskFailed(
            "ghidra_script needs a Ghidra project context",
            hint="open a program through the server before running the script",
        )
    stdout = ""
    stderr = ""
    try:
        # PyGhidra 3.1 still passes an untyped None as the PluginTool argument
        # to GhidraState. Ghidra 12's overload resolver rejects that, so keep
        # the same headless execution path with a typed null instead.
        import pyghidra
        from generic.jar import ResourceFile
        from ghidra.app.script import GhidraScriptUtil, GhidraState, ScriptControls
        from java.io import File, PrintWriter, StringWriter
        from java.lang import System
        from jpype import JClass, JObject

        GhidraScriptUtil.acquireBundleHostReference()
        try:
            source_file = ResourceFile(File(path))
            if not source_file.exists():
                raise TaskFailed(f'"{path}" was not found')
            provider = GhidraScriptUtil.getProvider(source_file)
            if provider is None:
                raise TaskFailed(f'"{path}" is not a supported Ghidra script')
            script_instance = provider.getScriptInstance(source_file, PrintWriter(System.out))
            if script_instance is None:
                raise TaskFailed(f'"{path}" was not found')
            plugin_tool = JClass("ghidra.framework.plugintool.PluginTool")
            state = GhidraState(
                JObject(None, plugin_tool), project, entry.program, None, None, None
            )
            stdout_writer = StringWriter()
            stderr_writer = StringWriter()
            controls = ScriptControls(
                PrintWriter(stdout_writer, True),
                PrintWriter(stderr_writer, True),
                pyghidra.task_monitor(),
            )
            script_instance.setScriptArgs(args)
            script_instance.execute(state, controls)
            stdout = str(stdout_writer)
            stderr = str(stderr_writer)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
    except BaseException as exc:
        return {"stdout": stdout, "result": None, "error": f"{type(exc).__name__}: {exc}"}
    return {"stdout": stdout, "result": None, "error": stderr.strip() or None}
