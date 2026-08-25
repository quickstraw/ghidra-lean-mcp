"""Instruction listing adapter: function / range / bytes targets."""

from __future__ import annotations

from ghmcp.ghidra.protocols import Insn, InstructionsRequest
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
        iterator = listing.getInstructions(start, end, True)
        return _collect(iterator, include_bytes, request.count or 500)
    if target == "bytes":
        if request.length is None:
            raise BadTarget("target='bytes' needs length")
        start = _address(program, request.start)
        end = _address(program, hex(start.getOffset() + request.length))
        iterator = listing.getInstructions(start, end, True)
        return _collect(iterator, include_bytes, request.count or 500)
    if target == "function":
        fn = lookup_function(program, request.start)
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


def lookup_function(program: object, name_or_addr: str) -> object:
    """Canonical function resolution shared by disassemble/decompile:
    address → function at/containing; else exact name; else case-insensitive
    exact; else case-insensitive prefix. Raises NotFound on a miss. Whitespace
    is normalized the same way decompile normalizes its targets."""
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
    if ci_exact is not None:
        return ci_exact
    if fallback is not None:
        return fallback
    raise NotFound(
        f"no function at or named {name_or_addr!r}",
        hint="check the exact name with find_symbols, or pass a plain address",
    )


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
