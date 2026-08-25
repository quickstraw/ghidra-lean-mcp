"""Search adapter: binary/text/instruction/scalar scans (plan §7 search_binary).

- bytes: masked Memory.findBytes (Java side), `??` wildcards become mask bits.
- text: raw encoded-memory scan of a byte pattern (works with analyze="none").
- instructions: regex over the disassembled instruction text.
- scalars: instructions whose operand equals a constant (lui/ori hunting).

All searches honour `range_` (closed [start,end]) when given and page at the
request limit; every scan crosses the JPype bridge per block/instruction, not
per element (plan §5.3).
"""

from __future__ import annotations

import re

from ghmcp.ghidra.protocols import Hit, SearchQuery
from ghmcp.platform.errors import BadTarget
from ghmcp.platform.targets import parse_address, parse_range


def search_page(program: object, request: SearchQuery) -> list[Hit]:
    if request.mode == "bytes":
        return _bytes(program, request)
    if request.mode == "text":
        return _text(program, request)
    if request.mode == "instructions":
        return _instructions(program, request)
    if request.mode == "scalars":
        return _scalars(program, request)
    raise BadTarget(
        f"unknown search mode {request.mode!r}",
        hint="mode is bytes | text | instructions | scalars",
    )


def _bounds(program: object, range_: str | None) -> tuple[object, object]:
    space = program.getAddressFactory().getDefaultAddressSpace()
    if range_:
        rng = parse_range(range_)
        if rng is None:
            raise BadTarget(f"invalid search range {range_!r}", hint="pass 0x1000-0x2000")
        return space.getAddress(rng[0]), space.getAddress(rng[1])
    mem = program.getMemory()
    return mem.getMinAddress(), mem.getMaxAddress()


def _bytes(program: object, request: SearchQuery) -> list[Hit]:
    pat, mask = _parse_byte_pattern(request.pattern)
    if pat is None:
        raise BadTarget(
            f"invalid byte pattern {request.pattern!r}",
            hint="pass bytes like 'de ad be ef' or a hex string, '??' for wildcards",
        )
    start, end = _bounds(program, request.range_)
    memory = program.getMemory()
    from ghidra.util.task import TaskMonitor
    from jpype import JArray, JByte

    jpat = JArray(JByte)([b & 0xFF for b in pat])
    jmask = JArray(JByte)([m & 0xFF for m in mask])
    hits: list[Hit] = []
    addr = start
    while len(hits) < request.limit:
        found = memory.findBytes(addr, jpat, jmask, True, TaskMonitor.DUMMY)
        if found is None or found.getOffset() > end.getOffset():
            break
        off = int(found.getOffset())
        data = _read(program, off, min(16, len(pat) + 8))
        hits.append(
            Hit(address=off, kind="bytes", preview=" ".join(f"{b:02x}" for b in data))
        )
        addr = _next_addr(program, found)
        if addr is None or addr.getOffset() >= end.getOffset():
            break
    return hits


def _text(program: object, request: SearchQuery) -> list[Hit]:
    pat = _encode_text(request.pattern)
    if not pat:
        raise BadTarget("empty text pattern")
    start, end = _bounds(program, request.range_)
    hits: list[Hit] = []
    memory = program.getMemory()
    block_start = start
    while True:
        block = memory.getBlock(block_start)
        if block is None or block.getStart().getOffset() > end.getOffset():
            break
        raw = _block_bytes(block)
        if raw is not None:
            block_off = int(block.getStart().getOffset())
            lo = start.getOffset() - block_off
            hi = end.getOffset() - block_off
            window = raw[max(0, lo) : min(len(raw), hi + 1)]
            needle = pat
            idx = 0
            while len(hits) < request.limit:
                pos = window.find(needle, idx)
                if pos < 0:
                    break
                addr = block_off + max(0, lo) + pos
                preview = window[pos : pos + min(32, len(needle) * 2)].decode("latin-1", "replace")
                hits.append(Hit(address=addr, kind="text", preview=preview))
                idx = pos + 1
        nxt = block.getNext()
        if nxt is None or nxt.getOffset() > end.getOffset():
            break
        block_start = nxt
    return hits


def _instructions(program: object, request: SearchQuery) -> list[Hit]:
    try:
        rx = re.compile(request.pattern, re.IGNORECASE)
    except re.error as exc:
        raise BadTarget(f"invalid instruction regex: {exc}") from None
    start, end = _bounds(program, request.range_)
    listing = program.getListing()
    hits: list[Hit] = []
    for insn in _iter(listing.getInstructions(start, end, True)):
        text = str(insn)
        if rx.search(text):
            hits.append(Hit(address=int(insn.getAddress().getOffset()), kind="instructions", preview=text))
            if len(hits) >= request.limit:
                break
    return hits


def _scalars(program: object, request: SearchQuery) -> list[Hit]:
    value = _parse_scalar(request.pattern)
    if value is None:
        raise BadTarget(
            f"invalid scalar {request.pattern!r}", hint="pass a constant like 0x8804a1c0 or 0x20"
        )
    start, end = _bounds(program, request.range_)
    listing = program.getListing()
    hits: list[Hit] = []
    for insn in _iter(listing.getInstructions(start, end, True)):
        for idx in range(insn.getNumOperands() or 1):
            try:
                scalar = insn.getScalar(idx)
            except BaseException:
                scalar = None
            if scalar is None:
                continue
            if int(scalar.getValue()) & 0xFFFFFFFF == value:
                hits.append(
                    Hit(address=int(insn.getAddress().getOffset()), kind="scalars", preview=str(insn))
                )
                break
        if len(hits) >= request.limit:
            break
    return hits


def _parse_byte_pattern(pattern: str) -> tuple[list[int], list[int]] | None:
    s = pattern.strip()
    if not s:
        return None, None
    tokens: list[str] = []
    if s[:2].lower() == "0x" and all(c in "0123456789abcdefABCDEF" for c in s[2:]) and len(s[2:]) <= 32:
        s = s[2:]
        tokens = [s[i : i + 2] for i in range(0, len(s), 2)]
    else:
        for tok in re.split(r"[\s,:]+", s):
            if tok:
                tokens.append(tok)
    pat: list[int] = []
    mask: list[int] = []
    for tok in tokens:
        if tok.lower() in ("??", "?"):
            pat.append(0)
            mask.append(0)
            continue
        tok = tok[2:] if tok[:2].lower() == "0x" else tok
        if not (len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok)):
            return None, None
        pat.append(int(tok, 16))
        mask.append(0xFF)
    return pat, mask


def _encode_text(text: str) -> bytes:
    return text.encode("utf-8")


def _parse_scalar(pattern: str) -> int | None:
    try:
        return parse_address(pattern) & 0xFFFFFFFF
    except BadTarget:
        return None


def _read(program: object, off: int, length: int) -> bytes:
    try:
        from jpype import JArray, JByte

        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        out = JArray(JByte)(length)
        program.getMemory().getBytes(addr, out)
        try:
            return bytes(out)
        except Exception:
            return bytes(bytearray(out))
    except BaseException:
        return b""


def _next_addr(program: object, addr: object):
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress(addr.getOffset() + 1)


def _block_bytes(block: object) -> bytes | None:
    try:
        from jpype import JArray, JByte

        size = int(block.getSize())
        out = JArray(JByte)(size)
        block.getData(out, 0, size)
        try:
            return bytes(out)
        except Exception:
            return bytes(bytearray(out))
    except BaseException:
        return None


def _iter(it: object):
    while True:
        nxt = _next(it)
        if nxt is None:
            return
        yield nxt


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
