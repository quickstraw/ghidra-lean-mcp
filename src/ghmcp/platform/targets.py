"""Address parsing: the ONE convention shared by every tool (plan §4.3).

    0x…       hex
    bare      digits-only → decimal, digits-with-a-f → hex

Nothing else lives here: target/name/range expressions are resolved against a
program by the consumers (ghidra.listing.lookup_function,
ghidra.decomp._resolve_functions), which decide whether a token is an address
or a symbol — so there is no speculative Target AST to keep in sync.
"""

from __future__ import annotations

import re

from ghmcp.platform.errors import BadTarget

HEX_RE = re.compile(r"^(?:0x|0X)?([0-9a-fA-F]+)$")
DEC_RE = re.compile(r"^[0-9]+$")


def parse_address(text: str) -> int:
    """`0x` prefix → hex; bare digits → decimal; bare digits-with-a-f → hex."""
    s = text.strip()
    if not s:
        raise BadTarget("empty address", hint="provide an address like 0x8804a1c0")
    if s[:2].lower() == "0x":
        if not HEX_RE.fullmatch(s):
            raise BadTarget(f"invalid hex address {s!r}")
        return int(s, 16)
    if DEC_RE.fullmatch(s):
        return int(s, 10)
    if HEX_RE.fullmatch(s):
        return int(s, 16)
    raise BadTarget(f"not an address: {text!r}", hint="pass 0x… or a plain number")
