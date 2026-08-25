"""Text formatting helpers shared by every tool: addresses, ranges, hexdumps."""

from __future__ import annotations


def hexaddr(value: int) -> str:
    return f"0x{value:08x}"


def paginate(offset: int, returned: int, limit: int, *, more: bool = False) -> tuple[bool, int | None]:
    """Response-discipline envelope (§7): (truncated, next_offset).

    `more` is the flag the backends set when the source had rows beyond the
    page; it is the single source of truth. With it, a page that ends exactly
    at the limit stays truncated so the agent continues.
    """
    if not more:
        return False, None
    cursor = offset + returned
    return True, cursor if returned else None


def page(source, offset: int, limit: int) -> tuple[list, bool]:
    """Collect up to `limit` rows past `offset` from a post-filter source.

    Reads one row past the page and reports `more` exactly, including the
    boundary case where the source has exactly `limit + 1` rows (that page is
    truncated). Sharing this keeps the off-by-one of the `more` flag out of
    every backend.
    """
    rows: list = []
    seen = 0
    more = False
    for row in source:
        seen += 1
        if seen <= offset:
            continue
        if len(rows) >= limit + 1:
            more = True
            break
        rows.append(row)
    more = more or len(rows) > limit
    return rows[:limit], more


def fmt_bytes(data: bytes, columns: int = 16) -> str:
    """Classic xxd-style hexdump; columns defaults to 16 bytes per line."""
    lines: list[str] = []
    for off in range(0, len(data), columns):
        chunk = data[off : off + columns]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{columns * 3}}  {asc}")
    return "\n".join(lines)
