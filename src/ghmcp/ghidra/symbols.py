"""Symbol discovery adapter: find_symbols (plan §7).

Query semantics: a bare query is a case-insensitive name PREFIX (natural for
`FUN_…`, `play_…`); a query containing `*` or `%` is a glob substring search
(`*song*`, `snd_%`). Filters (kind / undefined_only / min_size / range_) are
applied while the Ghidra iterator runs, so `offset`/`limit` skip real matches,
not everything. Prefix queries use the SymbolTable's indexed prefix iterator.
"""

from __future__ import annotations

import re

from ghmcp.ghidra.protocols import Symbol, SymbolQuery
from ghmcp.platform import format as fmt
from ghmcp.platform.errors import BadTarget
from ghmcp.platform.targets import parse_range

_KIND_BY_TYPE = {
    "FUNCTION": "function",
    "LABEL": "label",
    "DATA": "data",
    "CLASS": "class",
    "LIBRARY": "library",
    "NAMESPACE": "namespace",
    "PARAMETER": "parameter",
    "MODULE": "namespace",
}


def symbols_page(program: object, request: SymbolQuery) -> tuple[list[Symbol], bool]:
    """Page of symbols matching the query + filters; returns (rows, more)."""
    rng = _parse_range(request.range_) if request.range_ else None
    listing = program.getListing()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    matcher = _QueryMatcher(request.query)

    def gen():
        for sym in _sym_iter(st, matcher):
            if matcher and not matcher.matches(str(sym.getName())):
                continue
            addr = _addr_off(sym)
            kind = _classify(sym)
            if request.kind and kind != request.kind:
                continue
            if rng is not None and not rng[0] <= addr <= rng[1]:
                continue
            if request.undefined_only and _is_defined(program, listing, fm, sym):
                continue
            size = _data_size(listing, sym, addr)
            if request.min_size and size is not None and size < request.min_size:
                continue
            yield Symbol(
                name=str(sym.getName()),
                address=addr,
                kind=kind,
                namespace=str(sym.getParentNamespace().getName() or ""),
                size=size or 0,
                n_refs=_sym_refs(sym),
            )

    return fmt.page(gen(), request.offset, request.limit)


def _addr_off(sym: object) -> int:
    try:
        return int(sym.getAddress().getOffset())
    except BaseException:
        return 0


def _sym_refs(sym: object) -> int:
    try:
        return int(sym.getReferenceCount())
    except BaseException:
        return 0


class _QueryMatcher:
    """None (match all), prefix, or glob (substring) matcher on symbol names."""

    def __init__(self, query: str | None):
        if query is None:
            self._prefix = None
            self._glob = None
            return
        q = query.strip()
        if not q or q in ("*", "%"):
            self._prefix = None
            self._glob = None
            return
        if "*" in q or "%" in q:
            self._prefix = None
            self._glob = re.compile(_glob_re(q), re.IGNORECASE)
        else:
            self._prefix = q.lower()
            self._glob = None

    @property
    def wants_all(self) -> bool:
        return self._prefix is None and self._glob is None

    def matches(self, name: str) -> bool:
        if self._prefix is None and self._glob is None:
            return True
        if self._prefix is not None:
            return name.lower().startswith(self._prefix)
        return bool(self._glob.search(name))


def _glob_re(query: str) -> str:
    return "^" + re.escape(query.replace("%", "*")).replace(r"\*", ".*") + "$"


def _sym_iter(st: object, matcher: _QueryMatcher):
    if not matcher.wants_all and matcher._prefix is not None:
        return st.getSymbolIterator(matcher._prefix, False) or []
    return st.getAllSymbols(False) or []


def _classify(sym: object) -> str:
    try:
        t = str(sym.getSymbolType()).upper()
    except BaseException:
        t = "LABEL"
    return _KIND_BY_TYPE.get(t, "other" if t not in ("LABEL",) else "label")


def _is_defined(program: object, listing: object, fm: object, sym: object) -> bool:
    try:
        addr = sym.getAddress()
        if fm.getFunctionAt(addr) is not None:
            return True
        data = listing.getDataAt(addr)
        return data is not None and bool(data.isDefined())
    except BaseException:
        return False


def _data_size(listing: object, sym: object, addr: int) -> int | None:
    try:
        data = listing.getDataAt(sym.getAddress())
        if data is not None and bool(data.isDefined()):
            return int(data.getLength())
    except BaseException:
        pass
    return None


def _parse_range(text: str) -> tuple[int, int]:
    rng = parse_range(text)
    if rng is None:
        raise BadTarget(f"invalid range {text!r}", hint="pass a range like 0x1000-0x2000")
    return rng
