"""M4 tools: xrefs, find_symbols, find_strings, call_graph (plan §7)."""

from mcp.types import ToolAnnotations

from ghmcp.platform.registry import ToolSpec
from ghmcp.services import call_graph as call_graph_svc
from ghmcp.services import find_strings as find_strings_svc
from ghmcp.services import find_symbols as find_symbols_svc
from ghmcp.services import xrefs as xrefs_svc

_READ = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False)


XREFS_SPEC = ToolSpec(
    name="xrefs",
    summary="References to/from/both one or more addresses, symbols or ranges.",
    params=xrefs_svc.XrefsParams,
    result=xrefs_svc.XrefsResult,
    service=xrefs_svc.run,
    summarize=lambda r: (
        f"{sum(len(x.refs) for x in r.results)} reference(s) across "
        f"{len(r.results)} target(s)" + (", truncated" if r.truncated else "")
    ),
    timeout=60.0,
    annotations=_READ,
)

FINDSYMBOLS_SPEC = ToolSpec(
    name="find_symbols",
    summary="Discover symbols by name (prefix or *glob*), kind and address range.",
    params=find_symbols_svc.FindSymbolsParams,
    result=find_symbols_svc.FindSymbolsResult,
    service=find_symbols_svc.run,
    summarize=lambda r: f"{len(r.symbols)} symbol(s)" + (", truncated" if r.truncated else ""),
    timeout=30.0,
    annotations=_READ,
)

FINDSTRINGS_SPEC = ToolSpec(
    name="find_strings",
    summary="Strings: defined table (analyzed) or raw memory scan (analyze=none).",
    params=find_strings_svc.FindStringsParams,
    result=find_strings_svc.FindStringsResult,
    service=find_strings_svc.run,
    summarize=lambda r: f"{len(r.strings)} string(s)" + (", truncated" if r.truncated else ""),
    timeout=60.0,
    annotations=_READ,
)

CALLGRAPH_SPEC = ToolSpec(
    name="call_graph",
    summary="Callers/callees of a function, or the path between two functions.",
    params=call_graph_svc.CallGraphParams,
    result=call_graph_svc.CallGraphResult,
    service=call_graph_svc.run,
    summarize=lambda r: _cg_summary(r),
    timeout=30.0,
    annotations=_READ,
)


def _cg_summary(r) -> str:
    root = r.root.name if r.root else "?"
    parts = [f"{root}"]
    if r.callers:
        parts.append(f"{len(r.callers)} caller(s)")
    if r.callees:
        parts.append(f"{len(r.callees)} callee(s)")
    if r.path:
        parts.append(f"path→{r.path[-1].name}")
    return ", ".join(parts) + (", truncated" if r.truncated else "")
