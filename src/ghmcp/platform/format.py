"""Text formatting helpers shared by every tool: addresses, ranges, hexdumps."""

from __future__ import annotations


def hexaddr(value: int) -> str:
    return f"0x{value:08x}"


def fmt_bytes(data: bytes, columns: int = 16) -> str:
    """Classic xxd-style hexdump; columns defaults to 16 bytes per line."""
    lines: list[str] = []
    for off in range(0, len(data), columns):
        chunk = data[off : off + columns]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{columns * 3}}  {asc}")
    return "\n".join(lines)
