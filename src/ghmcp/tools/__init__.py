"""Tool catalog: every tool module exports one `SPEC`; this package owns the list."""

from __future__ import annotations

from ghmcp.platform.registry import validate_catalog
from ghmcp.tools import health
from ghmcp.tools.program import DECOMPILE_SPEC, DISASSEMBLE_SPEC, OPEN_SPEC, READ_SPEC, SESSION_SPEC

ALL_SPECS = [
    health.SPEC,
    OPEN_SPEC,
    SESSION_SPEC,
    DECOMPILE_SPEC,
    DISASSEMBLE_SPEC,
    READ_SPEC,
]

validate_catalog(ALL_SPECS, max_tools=20)
