"""Instruction listing adapter: function / range / bytes targets."""

from __future__ import annotations

from ghmcp.ghidra.protocols import Insn, InstructionsRequest, TypedValue
from ghmcp.platform.errors import BadTarget, NotFound
from ghmcp.platform.targets import parse_address


def listing_program(entry: object, request: InstructionsRequest) -> list[Insn]:
    program = entry.program
    listing = program.getListing()
    program.getFunctionManager()

    target = request.target
    include_bytes = request.include_bytes
    if target == "range":
        start = _address(program, request.start)
        end = _address(program, request.end or "")
        if end is None or end.getOffset() <= start.getOffset():
            raise BadTarget(
                "disassemble range needs end after start",
                hint="pass end=0x… after start (e.g. target='range', start=0x1000, end=0x1200)",
            )
        iterator = instructions_in_range(listing, start, end)
        return _collect(iterator, include_bytes, request.count or 500)
    if target == "bytes":
        if request.length is None:
            raise BadTarget("target='bytes' needs length")
        start = _address(program, request.start)
        end = _address(program, hex(start.getOffset() + request.length))
        iterator = instructions_in_range(listing, start, end)
        return _collect(iterator, include_bytes, request.count or 500)
    if target == "function":
        fn = lookup_function(program, request.start, entry)
        body = fn.getBody()
        start = body.getMinAddress()
        if start is None:
            return []
        insns: list[Insn] = []
        insn = listing.getInstructionAt(start)
        while insn is not None and len(insns) < (request.count or 500):
            try:
                if not body.contains(insn.getAddress()):
                    break
            except BaseException:
                break
            insns.append(_insn_from(insn, include_bytes))
            insn = listing.getInstructionAfter(insn.getAddress())
        return insns
    raise BadTarget(
        f"unknown disassemble target {target!r}",
        hint="target is function | range | bytes",
    )


def lookup_function(program: object, name_or_addr: str, entry: object = None) -> object:
    """Canonical function resolution shared by disassemble/decompile/annotate:
    address → function at/containing; else exact name; else case-insensitive
    exact; else case-insensitive prefix. Raises NotFound on a miss. Whitespace
    is normalized the same way decompile normalizes its targets.

    When `entry` is given, the name path runs against the session-scoped
    index (decomp._name_index, cached by modification number) — the O(N)
    `getFunctions` scan is paid once per modification, not per call."""
    name_or_addr = name_or_addr.strip()
    if not name_or_addr:
        raise BadTarget("empty function target", hint="pass a name or address")
    fm = program.getFunctionManager()
    addr = None
    try:
        value = parse_address(name_or_addr)
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
    except BadTarget:
        pass
    if addr is not None:
        fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if fn is not None:
            return fn

    fn = _resolve_name(program, fm, name_or_addr, entry)
    if fn is not None:
        return fn
    raise NotFound(
        f"no function at or named {name_or_addr!r}",
        hint="check the exact name with find_symbols, or pass a plain address",
    )


def _resolve_name(program: object, fm: object, name_or_addr: str, entry: object) -> object | None:
    """Name path with the same precedence either way; the index is a cache
    over exactly the same function enumeration (getFunctions(True))."""
    if entry is not None:
        from ghmcp.ghidra.decomp import _name_index, lookup_in_index

        exact, buckets = _name_index(entry, program, fm)
        return lookup_in_index(exact, buckets, name_or_addr)

    low = name_or_addr.lower()
    ci_exact = None
    fallback = None
    for cand in list(fm.getFunctions(True) or []):
        n = str(cand.getName())
        if n == name_or_addr:
            return cand
        if n.lower() == low:
            ci_exact = ci_exact or cand
        elif n.lower().startswith(low) and fallback is None:
            fallback = cand
    return ci_exact or fallback


def lookup_symbol(program: object, name_or_addr: str) -> object:
    """Resolve a symbol (label/data/function) by name or address; raises on a miss.

    Address → primary symbol at that address; else name → exact → case-insensitive
    exact → first prefix, via the SymbolTable.
    """
    name_or_addr = name_or_addr.strip()
    if not name_or_addr:
        raise BadTarget("empty symbol target", hint="pass a name or address")
    addr = None
    try:
        value = parse_address(name_or_addr)
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
    except BadTarget:
        pass
    st = program.getSymbolTable()
    if addr is not None:
        sym = st.getSymbol(addr)
        if sym is not None:
            return sym
    low = name_or_addr.lower()
    ci_exact = None
    fallback = None
    for sym in st.getAllSymbols(False) or []:
        n = str(sym.getName())
        if n == name_or_addr:
            return sym
        if n.lower() == low:
            ci_exact = ci_exact or sym
        elif n.lower().startswith(low) and fallback is None:
            fallback = sym
    if ci_exact is not None:
        return ci_exact
    if fallback is not None:
        return fallback
    raise NotFound(
        f"no symbol at or named {name_or_addr!r}",
        hint="check the exact name with find_symbols, or pass a plain address",
    )


def typed_values(
    program: object, start: int, length: int, type_name: str | None = None
) -> list[TypedValue]:
    """Defined data items in [start, start+length) with type name + rendered value.

    Raises BadTarget only when length is not positive. When `type_name` is
    given, only items whose top-level data type matches are returned (so a
    struct field at a packed address is skipped, not misrendered).
    """
    if length <= 0:
        raise BadTarget("typed read needs a positive length", hint="pass length=N bytes")
    listing = program.getListing()
    start_addr = _address(program, hex(start))
    end_addr = _address(program, hex(start + length - 1))
    out: list[TypedValue] = []
    try:
        iterator = listing.getDefinedData(start_addr, end_addr, True)
    except BaseException:
        return out
    for data in _make_iterator(iterator):
        try:
            name = str(data.getDataType().getName())
        except BaseException:
            name = ""
        if type_name and name != type_name:
            continue
        out.append(
            TypedValue(
                address=int(data.getAddress().getOffset()),
                type_name=name,
                value=_data_value_text(data),
                size=int(data.getLength()),
            )
        )
    return out


def _data_value_text(data: object) -> str:
    try:
        v = data.getValue()
        if v is not None:
            return str(v)
    except BaseException:
        pass
    try:
        return str(data.getDefaultValueRepresentation())
    except BaseException:
        return ""


def _address(program: object, text: str) -> object:
    if text.strip() == "":
        return None
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(parse_address(text))


def _insn_from(insn: object, include_bytes: bool) -> Insn:
    try:
        insn_bytes = (
            " ".join(f"{int(b) & 0xFF:02x}" for b in insn.getBytes()) if include_bytes else ""
        )
    except BaseException:
        insn_bytes = ""
    try:
        mnemonic = str(insn.getMnemonicString())
    except BaseException:
        mnemonic = str(insn.getMnemonic()) if hasattr(insn, "getMnemonic") else ""
    return Insn(
        address=int(insn.getAddress().getOffset()),
        mnemonic=mnemonic,
        bytes=insn_bytes,
        text=str(insn),
    )


def _collect(iterator: object, include_bytes: bool, limit: int) -> list[Insn]:
    it = _make_iterator(iterator)
    out: list[Insn] = []
    while len(out) < limit:
        try:
            insn = next(it)
        except StopIteration:
            break
        except BaseException:
            break
        out.append(_insn_from(insn, include_bytes))
    return out


def _make_iterator(iterator: object):
    """Java Iterable → Python iterator (JPype has both shapes)."""
    if hasattr(iterator, "iterator"):
        it = iterator.iterator()
    elif hasattr(iterator, "__iter__"):
        it = iter(iterator)
    else:
        it = iterator
    return it


def instructions_in_range(listing: object, start: object, end: object) -> object:
    """Use Listing's AddressSetView overload (the 3-arg overload was removed in 12.x)."""
    from ghidra.program.model.address import AddressSet

    address_set = AddressSet()
    address_set.add(start, end)
    return listing.getInstructions(address_set, True)
