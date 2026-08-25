"""String discovery adapter: find_strings (plan §7).

- source="defined" reads Ghidra's string table (needs analysis).
- source="scan" raw-scans memory blocks for printable runs, so it works with
  analyze="none" and catches strings Ghidra never defined.

Scan does one getBytes crossing per memory block (plan §5.3), decodes each
block once, and slices candidate runs in Python.
"""

from __future__ import annotations

import re

from ghmcp.ghidra.protocols import StringEntry, StringQuery
from ghmcp.platform import format as fmt
from ghmcp.platform.errors import BadTarget

_ASCII_PRINTABLE = "".join(chr(c) for c in range(0x20, 0x7F))
_PRINTABLE_RUNS = re.compile(f"[{re.escape(_ASCII_PRINTABLE)}]+")
_UTF16_RUNS = re.compile(r"[!-~]+")


def strings_page(program: object, request: StringQuery) -> tuple[list[StringEntry], bool]:
    """Page of strings for the requested source; returns (page, more)."""
    if request.source == "scan":
        return _scan(program, request)
    return _defined(program, request)


def _defined(program: object, request: StringQuery) -> tuple[list[StringEntry], bool]:
    listing = program.getListing()
    it = _iter(listing.getDefinedStrings(True) if _has_defined_strings(listing) else listing.getDefinedData(True))

    def gen():
        for data in it:
            try:
                if not _is_string_data(data):
                    continue
            except BaseException:
                continue
            value = _string_value(data)
            if value is None:
                continue
            if request.query and request.query.lower() not in value.lower():
                continue
            if request.min_length and len(value) < request.min_length:
                continue
            if request.encoding and request.encoding != _encoding(data):
                continue
            yield StringEntry(
                value=value[:512],
                address=int(data.getAddress().getOffset()),
                encoding=_encoding(data),
                size=int(data.getLength()),
                xrefs=_xref_count(data) if request.with_xrefs else 0,
            )

    return fmt.page(gen(), request.offset, request.limit)


def _has_defined_strings(listing: object) -> bool:
    return hasattr(listing, "getDefinedStrings")


def _scan(program: object, request: StringQuery) -> tuple[list[StringEntry], bool]:
    mine = (request.encoding or "utf8").lower()
    if mine not in ("utf8", "utf-16", "latin1"):
        raise BadTarget(
            f"unsupported scan encoding {mine!r}",
            hint="scan encodes: utf8 | utf-16 | latin1",
        )
    q = (request.query or "").lower()
    min_len = max(request.min_length or 4, 4)

    def gen():
        for block in _blocks(program):
            raw = _block_bytes(block)
            if raw is None:
                continue
            base = int(block.getStart().getOffset())
            scan = _scan_utf8 if mine in ("utf8", "latin1") else _scan_utf16
            for addr, value in scan(raw, base):
                if len(value) < min_len:
                    continue
                if q and q not in value.lower():
                    continue
                yield StringEntry(
                    value=value[:512],
                    address=addr,
                    encoding=mine,
                    size=len(value),
                    xrefs=_xrefs_to(program, addr) if request.with_xrefs else 0,
                )

    return fmt.page(gen(), request.offset, request.limit)


def _scan_utf8(raw: bytes, base: int):
    text = raw.decode("utf-8", errors="ignore")
    for m in _PRINTABLE_RUNS.finditer(text):
        yield base + m.start(), m.group(0)


def _scan_utf16(raw: bytes, base: int):
    text = _utf16_text(raw)
    for m in _UTF16_RUNS.finditer(text):
        yield base + m.start() * 2, m.group(0)


def _utf16_text(raw: bytes) -> str:
    return "".join(
        chr(code) if 0x20 <= (code := raw[i] | (raw[i + 1] << 8)) < 0x7F else "\x00"
        for i in range(0, len(raw) - 1, 2)
    )


def _blocks(program: object):
    try:
        for block in program.getMemory().getBlocks():
            if not block.isInitialized():
                continue
            yield block
    except BaseException:
        return


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


def _is_string_data(data: object) -> bool:
    try:
        from ghidra.program.model.data import StringDataInstance

        return bool(StringDataInstance.isString(data))
    except BaseException:
        dt = str(data.getDataType().getName()).lower()
        return any(k in dt for k in ("string", "unicode"))


def _string_value(data: object) -> str | None:
    try:
        v = data.getValue()
        if v is None:
            v = data.getDefaultValueRepresentation()
        return str(v).strip() if v is not None else None
    except BaseException:
        return None


def _encoding(data: object) -> str:
    try:
        cs = str(data.getCharset()).lower()
    except BaseException:
        try:
            cs = str(data.getDataType().getName()).lower()
        except BaseException:
            cs = ""
    if "16" in cs or "unicode" in cs:
        return "utf-16"
    if "latin" in cs or "8859" in cs:
        return "latin1"
    return "utf8"


def _xref_count(data: object) -> int:
    try:
        return int(data.getNumReferenceTo())
    except BaseException:
        return 0


def _xrefs_to(program: object, addr: int) -> int:
    try:
        from ghidra.util.task import TaskMonitor

        del TaskMonitor
        target = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr)
        it = program.getReferenceManager().getReferencesTo(target)
        return _count(it)
    except BaseException:
        return 0


def _count(it: object) -> int:
    n = 0
    while True:
        if it is None:
            return n
        if hasattr(it, "hasNext"):
            try:
                if not it.hasNext():
                    return n
            except BaseException:
                return n
            try:
                it.next()
            except BaseException:
                return n
        else:
            try:
                next(iter(it))
            except BaseException:
                return n
        n += 1


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
