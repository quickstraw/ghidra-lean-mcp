"""Address parsing: the ONE convention shared by every tool (plan §4.3).

    0x…       hex
    bare      digits-only → decimal, digits-with-a-f → hex
    A-B       address range (closed interval [A, B])
    A+L       address window (start + length → [A, A+L-1])
    name@0x…  explicit-address hinted name (name is advisory, addr wins)

Nothing else lives here: names are resolved against a program by the
consumers (ghidra.listing.lookup_function, ghidra.decomp._resolve_functions,
ghmcp.services.resolve), which decide whether a token is an address or a
symbol — so there is no speculative Target AST to keep in sync.
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


def parse_range(text: str) -> tuple[int, int] | None:
    """Parse a closed address range: `0x1000-0x2000` or `0x1000+0x100`.

    Returns (start, end) with end inclusive, or None when the token is not a
    range expression (so callers can fall back to a plain address).
    """
    s = text.strip()
    if not s:
        raise BadTarget("empty target", hint="pass an address, name, or range like 0x1000-0x2000")
    if "-" in s:
        left, _, right = s.partition("-")
        if not left.strip() or not right.strip():
            return None
        start = parse_address(left)
        end = parse_address(right)
        if end < start:
            raise BadTarget(
                f"range end {end:#x} before start {start:#x}", hint="pass end= after start="
            )
        return start, end
    if "+" in s:
        start_s, _, length_s = s.partition("+")
        if not start_s.strip() or not length_s.strip():
            return None
        start = parse_address(start_s)
        length = parse_address(length_s)
        if length <= 0:
            raise BadTarget("range length must be positive", hint="0x1000+0x100 means 0x1000..0x10ff")
        return start, start + length - 1
    return None


def split_name_addr(token: str) -> tuple[str | None, str | None]:
    """`symbol@0x…` → (symbol, 0x…); anything else → (token, None).

    The address always wins for navigation; the name is kept as a display/note
    hint for the resolver (plan §4.3: `name@0x…` form).
    """
    s = token.strip()
    if "@" in s:
        name, _, addr = s.partition("@")
        name = name.strip()
        addr = addr.strip()
        if name and addr:
            try:
                parse_address(addr)
            except BadTarget:
                return (s, None)
            return (name or None, addr)
    return (s, None)
