"""Target resolution: token → concrete address/range against a live adapter.

The single place a raw target string (address, name, name@addr, range,
name-glob) becomes an address or [start, end] window, plus the
"did you mean" suggestions on a miss (plan §7 response discipline). It only
reads via the adapter's `symbols` page — no Ghidra types here.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches

from ghmcp.platform.errors import BadTarget, GhmcpError, NotFound
from ghmcp.platform.models import SymbolQuery
from ghmcp.platform.targets import parse_address, parse_range, split_name_addr


@dataclass
class Resolved:
    token: str
    start: int
    end: int  # inclusive
    is_range: bool = False
    symbol: str | None = None


def require_program(adapter: object, program: str | None) -> str:
    """Current-program resolution shared by every tool."""
    if program is not None:
        return program
    current = adapter.current()
    if current is None:
        raise BadTarget("no program open", hint="open_program first")
    return current


def resolve(adapter: object, pid: str, token: str) -> Resolved:
    """Resolve one token: range → address → symbol name (in that precedence)."""
    token = token.strip()
    if not token:
        raise BadTarget("empty target", hint="pass 0x…, a name, or 0x1000-0x2000")

    name, addr_hint = split_name_addr(token)

    if addr_hint is not None:
        value = _parse(addr_hint, token)
        return Resolved(token=token, start=value, end=value, symbol=name)

    rng = _try_range(token)
    if rng is not None:
        return Resolved(token=token, start=rng[0], end=rng[1], is_range=True)

    addr = _try_addr(token)
    if addr is not None:
        return Resolved(token=token, start=addr, end=addr)

    return _resolve_symbol(adapter, pid, token)


def _try_addr(token: str) -> int | None:
    try:
        return parse_address(token)
    except BadTarget:
        return None


def _try_range(token: str) -> tuple[int, int] | None:
    # A name may legitimately contain '-' or '+'; only treat as a range when
    # BOTH sides parse as addresses.
    for sep in ("-", "+"):
        if sep not in token:
            continue
        left, _, right = token.partition(sep)
        if not left or not right:
            continue
        if _try_addr(left) is not None and _try_addr(right) is not None:
            try:
                return parse_range(token)
            except BadTarget:
                return None
    return None


def _parse(addr_hint: str, token: str) -> int:
    try:
        return parse_address(addr_hint)
    except BadTarget:
        raise BadTarget(f"invalid address hint {addr_hint!r} in {token!r}") from None


def _resolve_symbol(adapter: object, pid: str, token: str) -> Resolved:
    """Name resolution matching the listing/decompile precedence (exact →
    case-insensitive exact → first prefix), with did-you-mean on a miss.

    Uses a bare prefix query so the backend's indexed prefix iterator runs
    instead of a substring glob that would scan the whole symbol corpus
    (plan §5.3: never materialise a full scan for a single lookup).
    """
    needle = token.replace("*", "").replace("%", "")
    rows, _ = adapter.symbols(pid, SymbolQuery(query=needle, limit=64))
    low = needle.lower()
    ci_exact = None
    prefix = None
    for row in rows:
        name = row.name
        if name == needle:
            return Resolved(token=token, start=row.address, end=row.address, symbol=name)
        if name.lower() == low:
            ci_exact = ci_exact or row
        elif name.lower().startswith(low) and prefix is None:
            prefix = row
    if ci_exact is not None:
        return Resolved(token=token, start=ci_exact.address, end=ci_exact.address, symbol=ci_exact.name)
    if prefix is not None:
        return Resolved(token=token, start=prefix.address, end=prefix.address, symbol=prefix.name)
    raise NotFound(
        f"no symbol named {token!r}",
        hint=_not_found_hint(adapter, pid, token),
    )


def _not_found_hint(adapter: object, pid: str, token: str) -> str:
    """A "did you mean" hint, or a plain fallback when there are no close
    matches (the `+`/`or` precedence trap would otherwise leave a bare colon)."""
    try:
        names = suggest(adapter, pid, token)
    except GhmcpError:
        names = []
    return ("did you mean: " + ", ".join(names)) if names else "try find_symbols"


def suggest(adapter: object, pid: str, token: str, limit: int = 3) -> list[str]:
    """Nearest symbol names to `token` via difflib over a candidate set."""
    candidates = _candidate_names(adapter, pid, token)
    if not candidates:
        return []
    return get_close_matches(token, candidates, n=limit, cutoff=0.4)


def _candidate_names(adapter: object, pid: str, token: str) -> list[str]:
    """A candidate name set for difflib: globs around the token plus symbolic
    prefix probes, so a typo still finds `play_song` from `pla_sng`."""
    out: list[str] = []
    q = token.strip()
    probes = [f"{q}*", f"*{q}*"]
    probes += [f"{q[:n]}*" for n in (4, 3, 2, 1) if len(q) > n and q[:n]]
    for wild in probes:
        rows, _ = adapter.symbols(pid, SymbolQuery(query=wild, limit=64))
        out.extend(r.name for r in rows)
        if len(out) >= 64:
            break
    return list(dict.fromkeys(out))[:64]
