"""Tool catalog: every tool module exports one `SPEC`; this package owns the list."""

from __future__ import annotations

from ghmcp.platform.registry import validate_catalog
from ghmcp.tools import health
from ghmcp.tools.annotate import RENAME_SPEC, SETCOMMENT_SPEC, SETPROTOTYPE_SPEC, TYPES_SPEC
from ghmcp.tools.game import ANALYSIS_SPEC, DIFF_SPEC, MEMORY_MAP_SPEC
from ghmcp.tools.nav import CALLGRAPH_SPEC, FINDSTRINGS_SPEC, FINDSYMBOLS_SPEC, XREFS_SPEC
from ghmcp.tools.program import DECOMPILE_SPEC, DISASSEMBLE_SPEC, OPEN_SPEC, READ_SPEC, SESSION_SPEC
from ghmcp.tools.search import SCRIPT_SPEC, SEARCH_SPEC

ALL_SPECS = [
    health.SPEC,
    OPEN_SPEC,
    SESSION_SPEC,
    DECOMPILE_SPEC,
    DISASSEMBLE_SPEC,
    READ_SPEC,
    XREFS_SPEC,
    FINDSYMBOLS_SPEC,
    FINDSTRINGS_SPEC,
    CALLGRAPH_SPEC,
    SEARCH_SPEC,
    SCRIPT_SPEC,
    RENAME_SPEC,
    SETPROTOTYPE_SPEC,
    TYPES_SPEC,
    SETCOMMENT_SPEC,
    MEMORY_MAP_SPEC,
    DIFF_SPEC,
    ANALYSIS_SPEC,
]

validate_catalog(ALL_SPECS, max_tools=20)
