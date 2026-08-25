"""Annotation adapter: rename, prototypes, types, comments (plan §7).

Write paths run inside ghaddra.transaction (runtime/txn.py) and resolve targets
through the same listing.symbol machinery as the read tools, so a name/address
accepted by `decompile` is accepted here. Ghidra API details that vary by version
are guarded; an unsupported path raises a clear error rather than crashing.
"""

from __future__ import annotations

import contextlib
import re

from ghmcp.ghidra.listing import lookup_function, lookup_symbol
from ghmcp.ghidra.protocols import CommentRequest, PrototypeRequest, RenameRequest
from ghmcp.platform.errors import BadTarget, GhmcpError, NotFound


def rename(program: object, request: RenameRequest) -> None:
    source = _source()
    kind = request.kind
    if kind == "function":
        fn = lookup_function(program, request.target)
        fn.setName(request.new_name, source)
        return
    if kind in ("label", "data"):
        addr = _symbol_or_addr(program, request.target)
        st = program.getSymbolTable()
        sym = st.getSymbol(addr)
        if sym is not None:
            sym.setName(request.new_name, source)
        else:
            st.createLabel(addr, request.new_name, source)
        return
    if kind == "variable":
        fn, varname = _split_function_var(request.target)
        fn = lookup_function(program, fn)
        var = _find_variable(fn, varname)
        if var is None:
            raise GhmcpError(f"no variable {varname!r} in {fn.getName()!r}")
        var.setName(request.new_name, source)
        return
    raise BadTarget(
        f"unsupported rename kind {kind!r}",
        hint="kind is function | label | data | variable",
    )


def set_prototype(program: object, request: PrototypeRequest) -> None:
    fn = lookup_function(program, request.function)
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

    cmd = ApplyFunctionSignatureCmd(request.signature, fn, _source())
    if not cmd.applyTo(program):
        raise BadTarget(
            f"could not apply signature {request.signature!r}",
            hint="check the C prototype (e.g. 'int foo(char *a, int b)')",
        )
    if request.calling_convention:
        fn.setCallingConvention(request.calling_convention)


def set_comment(program: object, request: CommentRequest) -> None:
    listing = program.getListing()
    ctype = _comment_type(request.kind)
    if request.batch:
        for addr_text, text in request.batch.items():
            listing.setComment(_addr(program, addr_text), ctype, text)
        return
    listing.setComment(_addr(program, request.address), ctype, request.text)


def define_types(program: object, c_decl: str) -> list[str]:
    """Define C types; returns the names defined.

    Handles `typedef <base> <name>;` aliases and `struct <name> { <fields> };`
    with primitive field types. Unsupported declarations raise BadTarget so the
    agent falls back to run_script for complex types.
    """
    dtm = program.getDataTypeManager()
    names: list[str] = []
    for decl in _split_decls(c_decl):
        m = re.match(r"^\s*typedef\s+(.+?)\s+(\w+)\s*;\s*$", decl)
        if m:
            base, name = m.group(1).strip(), m.group(2)
            parent = _data_type(dtm, base)
            if parent is None:
                raise BadTarget(f"unknown base type {base!r} in typedef")
            _add_typedef(dtm, name, parent)
            names.append(name)
            continue
        m = re.match(r"^\s*struct\s+(\w+)\s*\{(.*)\}\s*;\s*$", decl, re.S)
        if not m:
            raise BadTarget(f"unsupported type declaration: {decl.strip()}")
        from ghidra.program.model.data import StructureDataType

        struct = StructureDataType(m.group(1), 0)
        for field in _field_defs(m.group(2)):
            ftype = _data_type(dtm, field["type"])
            if ftype is None:
                raise BadTarget(f"unknown field type {field['type']!r}")
            struct.add(ftype, field["name"])
        dtm.addDataType(struct, _conflict())
        names.append(struct.getName())
    return names


def apply_type(program: object, address: int, c_type: str, variable: str | None) -> None:
    dtm = program.getDataTypeManager()
    data_type = _data_type(dtm, c_type)
    if data_type is None:
        raise BadTarget(f"unknown type {c_type!r}")
    addr = _addr(program, address)
    if variable:
        fn, varname = _split_function_var(variable)
        fn = lookup_function(program, fn)
        var = _find_variable(fn, varname)
        if var is not None:
            var.setDataType(data_type, _source())
            return
    data = program.getListing().getDataAt(addr)
    if data is not None:
        data.setDataType(data_type, True, 1, _source())
        return
    raise BadTarget(f"no data at {address:#x} to retype")


def list_types(program: object) -> list[str]:
    dtm = program.getDataTypeManager()
    return sorted(str(t.getName()) for t in dtm.getAllDataTypes() if t.getName())


def get_type(program: object, name: str) -> dict:
    dt = program.getDataTypeManager().getDataType(name)
    if dt is None:
        raise NotFound(f"no such type {name!r}", hint="use types(action='list') first")
    return {"name": str(dt.getName()), "size": int(getattr(dt, "getLength", lambda: 0)())}


# -------------------------------------------------------------------------- helpers

def _source():
    from ghidra.program.model.symbol import SourceType

    return SourceType.USER_DEFINED


def _comment_type(kind: str):
    from ghidra.program.model.listing import CodeUnit

    table = {
        "plate": CodeUnit.PLATE_COMMENT,
        "pre": CodeUnit.PRE_COMMENT,
        "eol": CodeUnit.EOL_COMMENT,
        "post": CodeUnit.POST_COMMENT,
    }
    if kind not in table:
        from ghmcp.platform.errors import BadTarget

        raise BadTarget(f"unknown comment kind {kind!r}", hint="plate | pre | eol | post")
    return table[kind]


def _addr(program: object, text):
    """Resolve an address from a hex/plain string or an int offset."""
    from ghmcp.platform.targets import parse_address

    return program.getAddressFactory().getDefaultAddressSpace().getAddress(
        parse_address(text if isinstance(text, str) else f"0x{int(text):x}")
    )


def _symbol_or_addr(program: object, target: str) -> object:
    """Resolve a label/data target: address preferred, else a symbol name."""
    try:
        return _addr(program, target)
    except BadTarget:
        sym = lookup_symbol(program, target)
        return sym.getAddress()


def _split_function_var(target: str) -> tuple[str, str]:
    if "::" in target:
        fn, _, var = target.partition("::")
        return fn, var
    return target.split(".")[0], target


def _find_variable(fn: object, name: str) -> object:
    candidates = []
    with contextlib.suppress(BaseException):
        candidates += list(fn.getParameters())
    with contextlib.suppress(BaseException):
        if hasattr(fn, "getLocalVariables"):
            candidates += list(fn.getLocalVariables())
    for v in candidates:
        try:
            if str(v.getName()) in (name, "_" + name):
                return v
        except BaseException:
            continue
    return None


def _split_decls(c_decl: str) -> list[str]:
    import re

    return [d.strip() for d in re.split(r";\s*(?=\s*(?:typedef|struct)\s)", c_decl) if d.strip()]


def _field_defs(body: str) -> list[dict]:
    out = []
    for part in body.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if len(tokens) == 2:
            out.append({"type": tokens[0], "name": tokens[1]})
    return out


def _data_type(dtm: object, base: str) -> object:
    base = base.strip()
    if "*" in base:
        base = base.split("*")[0].split()[-1]
    for candidate in (base, f"/{base}"):
        with contextlib.suppress(BaseException):
            dt = dtm.getDataType(candidate)
            if dt is not None:
                return dt
    return None


def _add_typedef(dtm: object, name: str, parent: object) -> None:
    from ghidra.program.model.data import DataTypeConflictHandler, TypedefDataType

    td = TypedefDataType(name, parent)
    handler = getattr(DataTypeConflictHandler, "KEEP_HANDLER", None)
    dtm.addDataType(td, handler if handler is not None else None)


def _conflict():
    from ghidra.program.model.data import DataTypeConflictHandler

    return getattr(DataTypeConflictHandler, "KEEP_HANDLER", None)
