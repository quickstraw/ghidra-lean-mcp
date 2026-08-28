"""Annotation adapter: rename, prototypes, types, comments (plan §7).

Write paths run inside ghaddra.transaction (runtime/txn.py) and resolve targets
through the same listing.symbol machinery as the read tools, so a name/address
accepted by `decompile` is accepted here. Functions take the SessionEntry so
name lookup uses the session-scoped function index. Ghidra API details that
vary by version are guarded; an unsupported path raises a clear error rather
than crashing.
"""

from __future__ import annotations

import contextlib
import re

from ghmcp.ghidra.listing import lookup_function, lookup_symbol
from ghmcp.ghidra.protocols import CommentRequest, PrototypeRequest, RenameRequest
from ghmcp.platform.errors import BadTarget, GhmcpError, NotFound


def rename(entry: object, request: RenameRequest) -> None:
    program = entry.program
    source = _source()
    kind = request.kind
    if kind == "function":
        fn = lookup_function(program, request.target, entry)
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
        fn = lookup_function(program, fn, entry)
        var = _find_variable(fn, varname)
        if var is None:
            raise GhmcpError(f"no variable {varname!r} in {fn.getName()!r}")
        var.setName(request.new_name, source)
        return
    raise BadTarget(
        f"unsupported rename kind {kind!r}",
        hint="kind is function | label | data | variable",
    )


def set_prototype(entry: object, request: PrototypeRequest) -> None:
    program = entry.program
    fn = lookup_function(program, request.function, entry)
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

    # Ghidra 12.x (verified live on 12.1.2) removed the text-parsing
    # (String, Function, SourceType) constructor: parse the prototype with
    # FunctionSignatureParser and apply by entry address. 11.x keeps the
    # String constructor — try it first, fall back on the TypeError.
    try:
        cmd = ApplyFunctionSignatureCmd(request.signature, fn, _source())
    except TypeError:
        from ghidra.app.util.parser import FunctionSignatureParser

        text = request.signature.strip().rstrip(";").strip()
        parser = FunctionSignatureParser(program.getDataTypeManager(), None)
        try:
            signature = parser.parse(fn.getSignature(), text)
        except Exception as exc:
            raise BadTarget(
                f"could not parse signature {request.signature!r}: {type(exc).__name__}",
                hint="check the C prototype (e.g. 'int foo(char *a, int b)')",
            ) from exc
        if signature is None:
            raise BadTarget(
                f"could not parse signature {request.signature!r}",
                hint="check the C prototype (e.g. 'int foo(char *a, int b)')",
            ) from None
        cmd = ApplyFunctionSignatureCmd(fn.getEntryPoint(), signature, _source())
    if not cmd.applyTo(program):
        status = ""
        with contextlib.suppress(Exception):
            status = str(cmd.getStatusMsg() or "")
        hint = (
            "run analysis first (open with analyze='auto') — prototypes need "
            "an analyzed program" if "invalid signature" in status.lower() else None
        )
        raise BadTarget(
            f"could not apply signature {request.signature!r}" + (f" ({status})" if status else ""),
            hint=hint or "check the C prototype (e.g. 'int foo(char *a, int b)')",
        )
    if request.calling_convention:
        fn.setCallingConvention(request.calling_convention)


def set_comment(entry: object, request: CommentRequest) -> None:
    program = entry.program
    listing = program.getListing()
    ctype = _comment_type(request.kind)
    if request.batch:
        for addr_text, text in request.batch.items():
            listing.setComment(_addr(program, addr_text), ctype, text)
        return
    listing.setComment(_addr(program, request.address), ctype, request.text)


def define_types(entry: object, c_decl: str) -> list[str]:
    """Define C types; returns the names defined.

    Handles `typedef <base> <name>;` aliases and `struct <name> { <fields> };`
    with primitive (and pointer) field types. Unsupported declarations raise
    BadTarget so the agent falls back to run_script for complex types.
    """
    dtm = entry.program.getDataTypeManager()
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
            try:
                struct.add(ftype, field["name"])
            except TypeError:
                # Ghidra 12.x (verified live) dropped add(DataType, String):
                # same add with an empty comment.
                struct.add(ftype, field["name"], "")
        dtm.addDataType(struct, _conflict())
        names.append(struct.getName())
    return names


def apply_type(entry: object, address: int, c_type: str, variable: str | None) -> None:
    program = entry.program
    dtm = program.getDataTypeManager()
    data_type = _data_type(dtm, c_type)
    if data_type is None:
        raise BadTarget(f"unknown type {c_type!r}")
    addr = _addr(program, address)
    if variable:
        fn, varname = _split_function_var(variable)
        fn = lookup_function(program, fn, entry)
        var = _find_variable(fn, varname)
        if var is not None:
            var.setDataType(data_type, _source())
            return
    from ghidra.app.cmd.data import CreateDataCmd

    # DataDB.setDataType was removed in Ghidra 12. CreateDataCmd is the
    # supported transaction-aware path and force=True replaces conflicting
    # defined data at the requested address.
    cmd = CreateDataCmd(addr, True, data_type)
    if cmd.applyTo(program):
        return
    status = ""
    with contextlib.suppress(BaseException):
        status = str(cmd.getStatusMsg() or "")
    raise BadTarget(
        f"could not apply type {c_type!r} at {address:#x}" + (f": {status}" if status else ""),
        hint="pass the start of defined data outside an instruction",
    )


def list_types(entry: object) -> list[str]:
    dtm = entry.program.getDataTypeManager()
    return sorted(str(t.getName()) for t in dtm.getAllDataTypes() if t.getName())


def get_type(entry: object, name: str) -> dict:
    dtm = entry.program.getDataTypeManager()
    dt = None
    for candidate in (name, f"/{name}"):
        with contextlib.suppress(BaseException):
            dt = dtm.getDataType(candidate)
            if dt is not None:
                break
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
    """Parse struct fields; raises BadTarget for anything not representable.

    Supported: `<base-type> <name>` and `<base-type> * <name>` / `<base-type> *name`
    (pointers fold into the type string, which _data_type strips). Everything
    else (arrays, bitfields, initializers, comma lists) raises rather than
    silently dropping a field and defining a partial struct.
    """
    out: list[dict] = []
    for part in body.split(";"):
        part = part.strip()
        if not part:
            continue
        for bad in ("[", "]", "=", ":", ","):
            if bad in part:
                raise BadTarget(
                    f"unsupported field declaration: {part!r}",
                    hint="arrays/bitfields/initializers need run_script; keep primitives+pointers here",
                )
        tokens = part.split()
        if len(tokens) < 2:
            raise BadTarget(
                f"unsupported field declaration: {part!r}",
                hint="field syntax is '<type> <name>' (e.g. 'int x', 'char *name')",
            )
        head, tail = tokens[:-1], tokens[-1]
        if tail.startswith("*"):
            ptr = len(tail) - len(tail.lstrip("*"))
            name = tail.lstrip("*")
            if not name:
                raise BadTarget(f"unsupported field declaration: {part!r}")
            ftype = " ".join([*head, "*" * ptr])
        elif tail.isidentifier():
            name = tail
            ftype = " ".join(head)
        else:
            raise BadTarget(f"unsupported field declaration: {part!r}")
        out.append({"type": ftype, "name": name})
    return out


def _data_type(dtm: object, base: str) -> object:
    """Resolve a type string to a DataType.

    Multiword bases collapse to the last token ('unsigned int' -> 'int',
    'struct Inner' -> 'Inner' via the DTM) so `_field_defs` and this resolver
    accept the same language. Pointers ('char *', 'int **') actually resolve
    to pointer types built from the pointee — never to the pointee's value
    type, which would silently produce 1-byte fields and value-typed
    variables. Raises BadTarget (instead of returning None) when the pointee
    is unknown, so structs/variables never half-resolve silently.
    """
    base = base.strip()
    if "*" in base:
        star_count = base.count("*")
        core = base.split("*", 1)[0].strip()
        pointee = _resolve_names(dtm, core)
        if pointee is None:
            raise BadTarget(
                f"unknown base type {core!r} in {base!r}",
                hint=f"define {core!r} first, or use run_script for custom types",
            )
        data = pointee
        # Explicit pointer size from the program's data organization (the 1-arg
        # getPointer defaults to a 4-byte pointer on Ghidra 12.1.2 — a 64-bit
        # program's fields would be half-size; verified live).
        pointer_size = 0
        with contextlib.suppress(BaseException):
            pointer_size = int(dtm.getDataOrganization().getPointerSize())
        for _ in range(star_count):
            try:
                data = dtm.getPointer(data, pointer_size)
            except TypeError:
                data = dtm.getPointer(data)
        return data
    return _resolve_names(dtm, base)


def _resolve_names(dtm: object, base: str) -> object | None:
    """Name resolution against the program DTM (bare + '/'-rooted), then the
    BuiltInDataTypeManager (12.1 primitives live under '/<name>')."""
    words = base.split()
    last = words[-1] if words else base
    names = [base]
    if last != base and last not in names:
        names.append(last)
    for candidate in names:
        for try_name in (candidate, f"/{candidate}"):
            with contextlib.suppress(BaseException):
                dt = dtm.getDataType(try_name)
                if dt is not None:
                    return dt
    try:
        from jpype import JClass

        BuiltIn = JClass("ghidra.program.model.data.BuiltInDataTypeManager")
        builtin = BuiltIn.getDataTypeManager()
        for candidate in names:
            with contextlib.suppress(BaseException):
                dt = builtin.getDataType(f"/{candidate}")
                if dt is not None:
                    return dt
    except BaseException:
        pass
    return None


def _add_typedef(dtm: object, name: str, parent: object) -> None:
    from ghidra.program.model.data import DataTypeConflictHandler, TypedefDataType

    td = TypedefDataType(name, parent)
    handler = getattr(DataTypeConflictHandler, "KEEP_HANDLER", None)
    dtm.addDataType(td, handler if handler is not None else None)


def _conflict():
    from ghidra.program.model.data import DataTypeConflictHandler

    return getattr(DataTypeConflictHandler, "KEEP_HANDLER", None)
