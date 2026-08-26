"""run_script backend: inline python on the flat API, or a pyghidra script (plan §7).

Inline python runs in-process against the live `Program` (the same object the
server holds), so scripts see the analyzed DB unchanged. A `result` dict binding
is returned for structured output; stdout is captured. `write` gates a
transaction wrapper: scripts can only persist a session opened writable.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

from ghmcp.platform.errors import TaskFailed


def run_script(entry: object, kind: str, code: str | None, path: str | None, args: list[str]) -> dict:
    if kind == "ghidra_script":
        return _ghidra_script(entry, path, args)
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


def _ghidra_script(entry: object, path: str | None, args: list[str]) -> dict:
    if not path:
        raise TaskFailed("ghidra_script needs path=", hint="point path= at a .py Ghidra script")
    import pyghidra

    buf = io.StringIO()
    error = None
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            pyghidra.ghidra_script(path, entry.program, None, echo_stdout=False, echo_stderr=False)
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
    return {"stdout": buf.getvalue(), "result": None, "error": error}
