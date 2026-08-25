"""Reference adapter: xref sweeps to/from/both over points and ranges (plan §7 xrefs).

Kinds are a coarse classification (flow | data | computed | other) derived from
the Ghidra RefType, so the agent can say kinds=['flow'] without knowing the
Ghidra-specific taxonomy. Point targets use the indexed per-address iterators;
range targets fall back to a single forward pass over the reference corpus,
filtering — one JPype crossing per reference, no materialisation in Python.
"""

from __future__ import annotations

from ghmcp.ghidra.protocols import Ref, RefsRequest
from ghmcp.platform import format as fmt


def refs_page(program: object, request: RefsRequest) -> tuple[list[Ref], bool]:
    """Collect references for the resolved targets; returns (page, more).

    Targets arrive as closed [start, end] pairs. Rows are emitted in request
    order with `Ref.target` set to the request-level index so the service can
    regroup per requested target. `more` is exact (one row past the page read).
    """
    mgr = program.getReferenceManager()
    space = program.getAddressFactory().getDefaultAddressSpace()

    def gen():
        for ti, (start, end) in enumerate(request.targets):
            for ref in _iter_target_refs(program, mgr, space, start, end, request.direction):
                if request.kinds and ref.kind not in request.kinds:
                    continue
                ref.target = ti
                yield ref

    return fmt.page(gen(), request.offset, request.limit)


def _iter_target_refs(program: object, mgr: object, space: object, start: int, end: int, direction: str):
    """Yield Ref rows for one target (point or range) in Ghidra order."""
    if end == start:
        seen: set[tuple[int, int, str]] = set()
        addr = space.getAddress(start)
        if direction in ("to", "both"):
            for r in mgr.getReferencesTo(addr) or []:
                fro = int(r.getFromAddress().getOffset())
                ref = Ref(
                    address=fro,
                    kind=_ref_kind(r),
                    source=fro,
                    label=_label_at(program, r.getFromAddress()),
                    target=None,
                )
                if (ref.address, ref.source, ref.kind) not in seen:
                    seen.add((ref.address, ref.source, ref.kind))
                    yield ref
        if direction in ("from", "both"):
            for r in mgr.getReferencesFrom(addr) or []:
                to = int(r.getToAddress().getOffset())
                ref = Ref(
                    address=to,
                    kind=_ref_kind(r),
                    source=start,
                    label=_label_at(program, r.getToAddress()),
                    target=None,
                )
                if (ref.address, ref.source, ref.kind) not in seen:
                    seen.add((ref.address, ref.source, ref.kind))
                    yield ref
        return
    seen: set[tuple[int, int, str]] = set()
    # "from": references that ORIGINATE in the range. The reference iterator is
    # sorted by from-address, so start it at the range start and stop once the
    # from-address passes the range end — bounded to the window.
    if direction in ("from", "both"):
        it = mgr.getReferenceIterator(space.getAddress(start))
        while True:
            r = _next(it)
            if r is None:
                break
            fro = int(r.getFromAddress().getOffset())
            if fro > end:
                break
            if fro >= start:
                ref = Ref(
                    address=int(r.getToAddress().getOffset()),
                    kind=_ref_kind(r),
                    source=fro,
                    label=_label_at(program, r.getToAddress()),
                    target=None,
                )
                if (ref.address, ref.source, ref.kind) not in seen:
                    seen.add((ref.address, ref.source, ref.kind))
                    yield ref
    # "to": references that POINT INTO the range. A matching reference can
    # originate anywhere (from < start), so this pass must scan the whole corpus
    # — correctness first.
    if direction in ("to", "both"):
        it = mgr.getReferenceIterator(space.getMinAddress())
        while True:
            r = _next(it)
            if r is None:
                return
            to = int(r.getToAddress().getOffset())
            if start <= to <= end:
                fro = int(r.getFromAddress().getOffset())
                ref = Ref(
                    address=fro,
                    kind=_ref_kind(r),
                    source=fro,
                    label=_label_at(program, r.getFromAddress()),
                    target=None,
                )
                if (ref.address, ref.source, ref.kind) not in seen:
                    seen.add((ref.address, ref.source, ref.kind))
                    yield ref


def _next(it: object):
    if it is None:
        return None
    if hasattr(it, "hasNext"):
        try:
            return it.next() if it.hasNext() else None
        except BaseException:
            return None
    try:
        return next(iter(it))
    except BaseException:
        return None


def _ref_kind(r: object) -> str:
    try:
        rt = r.getReferenceType()
        if rt.isFlow():
            return "flow"
        if rt.isData():
            return "data"
        if rt.isComputed():
            return "computed"
        return "other"
    except BaseException:
        return "other"


def _label_at(program: object, address: object) -> str | None:
    try:
        sym = program.getSymbolTable().getSymbol(address)
        return str(sym.getName()) if sym is not None else None
    except BaseException:
        return None
