"""Call-graph adapter: callers/callees with bounded BFS and path queries.

Uses Function.getCallingFunctions / getCalledFunctions (Ghidra 11.x). A BFS
caps the expansion so an untidy graph cannot blow the process: nodes are
bounded per depth and the result is truncated, never silently dropped.
"""

from __future__ import annotations

from collections import deque

from ghmcp.ghidra.listing import lookup_function
from ghmcp.ghidra.protocols import CallGraphPage, CallGraphRequest, FunctionBrief
from ghmcp.platform.errors import NotFound
from ghmcp.platform.telemetry import log_event

MAX_NODES = 500
MAX_DEPTH = 5


def call_graph(entry: object, request: CallGraphRequest) -> CallGraphPage:
    program = entry.program
    root = lookup_function(program, request.target, entry)
    depth = max(1, min(request.depth, MAX_DEPTH))
    page = CallGraphPage(
        root=_brief(root, 0, ""),
        callers=[],
        callees=[],
        path=[],
        truncated=False,
    )

    if request.direction in ("callers", "both"):
        rows, truncated = _walk(program, root, _expand_callers, depth)
        page.callers = rows
        page.truncated = page.truncated or truncated
    if request.direction in ("callees", "both"):
        rows, truncated = _walk(program, root, _expand_callees, depth)
        page.callees = rows
        page.truncated = page.truncated or truncated
    if request.path_to:
        path = _find_path(entry, program, root, request.path_to)
        page.path = path
    return page


def _walk(program: object, root: object, expand, depth: int) -> tuple[list[FunctionBrief], bool]:
    """BFS expansion favouring functions close to the root; truncated past MAX_NODES."""
    seen: set[object] = {root}
    frontier = [root]
    depth_of: dict[object, int] = {root: 0}
    via: dict[object, object] = {}
    rows: list[FunctionBrief] = []
    truncated = False
    for _ in range(depth):
        nxt: list[object] = []
        for f in frontier:
            for child in expand(program, f):
                if child in seen:
                    continue
                seen.add(child)
                via[child] = f
                depth_of[child] = depth_of.get(f, 0) + 1
                rows.append(
                    FunctionBrief(
                        name=str(child.getName()),
                        address=int(child.getEntryPoint().getOffset()),
                        depth=depth_of[child],
                        via=str(via[child].getName()),
                    )
                )
                nxt.append(child)
                if len(seen) >= MAX_NODES:
                    truncated = True
                    return rows, truncated
        frontier = nxt
        if not frontier:
            break
    return rows, truncated


def _expand_callers(program: object, fn: object):
    from ghidra.util.task import TaskMonitor

    try:
        return fn.getCallingFunctions(TaskMonitor.DUMMY) or []
    except BaseException as exc:
        log_event("callgraph_expand_failed", fn=str(fn.getName()), error=str(exc))
        return []


def _expand_callees(program: object, fn: object):
    from ghidra.util.task import TaskMonitor

    try:
        return fn.getCalledFunctions(TaskMonitor.DUMMY) or []
    except BaseException as exc:
        log_event("callgraph_expand_failed", fn=str(fn.getName()), error=str(exc))
        return []


def _find_path(entry: object, program: object, root: object, target_token: str) -> list[FunctionBrief]:
    """Shortest callers-path root → target (target calls root back)."""
    try:
        dest = lookup_function(program, target_token, entry)
    except NotFound:
        return []
    if dest is root:
        return [_brief(root, 0, "")]
    seen: set[object] = {root}
    parent: dict[object, object] = {}
    dq = deque([root])
    found = None
    while dq and found is None:
        if len(seen) >= MAX_NODES:
            break
        cur = dq.popleft()
        for caller in _expand_callers(program, cur):
            if caller in seen:
                continue
            seen.add(caller)
            parent[caller] = cur
            if caller is dest:
                found = caller
                break
            dq.append(caller)
    if found is None:
        return []
    chain: list[object] = []
    node: object = found
    while node is not root:
        chain.append(node)
        node = parent[node]
    chain.reverse()
    out: list[FunctionBrief] = [_brief(root, 0, "")]
    for i, node in enumerate(chain, start=1):
        out.append(_brief(node, i, out[i - 1].name))
    return out


def _brief(fn: object, depth: int, via: str) -> FunctionBrief:
    return FunctionBrief(
        name=str(fn.getName()),
        address=int(fn.getEntryPoint().getOffset()),
        depth=depth,
        via=via,
    )
