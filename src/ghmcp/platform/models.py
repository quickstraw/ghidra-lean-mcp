"""Plain data models shared by every layer (no Ghidra, no JSON tricks).

Everything here is JSON-serializable and used directly in tool result models —
no aliases and no property maps (registry.build_wrapper validates structured
output *without* by_alias, plan §0.4).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Model(BaseModel):
    """Base for all result payloads: strict schema, no extra keys."""

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------
# Program/env vocabulary
# --------------------------------------------------------------------------


class ProgramInfo(Model):
    pid: str
    alias: str | None = None
    path: str | None = None
    format: str | None = None
    language: str | None = None
    compiler: str | None = None
    image_base: int | None = None
    entry_points: list[int] = []
    memory_blocks: list[str] = []
    symbol_count: int = 0
    function_count: int = 0
    string_count: int = 0
    analysis_state: str = "unknown"
    writable: bool = False


class EnvInfo(Model):
    ghidra_version: str | None = None
    full_version: str | None = None
    java_heap: str = ""
    extension_dirs: list[str] = []
    installed_extensions: list[str] = []
    active_extensions: list[str] = []
    loaders: list[str] = []
    languages: list[str] = []
    presets: list[str] = []
    preset_status: dict[str, str] = {}
    drift_warning: str | None = None


class DecompiledFn(Model):
    name: str
    address: int
    lines: list[str]
    timeout: bool = False
    error: str | None = None
    deferred: bool = False  # capped out of this batch (split targets to decompile the rest)


class Insn(Model):
    address: int
    mnemonic: str
    bytes: str = ""
    text: str = ""


class Ref(Model):
    address: int  # the other end of the reference
    kind: str = ""
    source: int | None = None  # referencing instruction/location, null for data refs


class Symbol(Model):
    name: str
    address: int
    kind: str = "data"  # function | label | data | ...
    namespace: str = ""
    size: int = 0
    n_refs: int = 0


class StringEntry(Model):
    value: str
    address: int
    encoding: str = "utf8"
    size: int = 0
    xrefs: int = 0


class Hit(Model):
    address: int | None = None
    offset: int | None = None  # for file-scope scans
    kind: str = "bytes"
    preview: str = ""


# --------------------------------------------------------------------------
# Queries / requests
# --------------------------------------------------------------------------


class OpenSpec(Model):
    path: str
    preset: str | None = None
    loader_name: str | None = None
    loader_args: dict[str, str] | None = None
    language: str | None = None
    compiler: str | None = None
    image_base: int | None = None
    analyze: str = "auto"  # auto | full | none
    writable: bool = False
    alias: str | None = None


class DecompileRequest(Model):
    targets: list[str]
    program: str | None = None
    include_line_addresses: bool = False
    max_lines: int = 400


class InstructionsRequest(Model):
    target: str  # function | range | bytes
    start: str
    end: str | None = None
    length: int | None = None
    count: int | None = None
    include_bytes: bool = False
    program: str | None = None


class RefsRequest(Model):
    targets: list[str]
    direction: str = "to"  # to | from | both
    kinds: list[str] = []
    offset: int = 0
    limit: int = 100
    program: str | None = None


class SymbolQuery(Model):
    query: str | None = None
    kind: str | None = None
    undefined_only: bool = False
    min_size: int = 0
    range_: str | None = None
    offset: int = 0
    limit: int = 100
    program: str | None = None


class StringQuery(Model):
    query: str | None = None
    source: str = "defined"  # defined | scan
    min_length: int = 0
    encoding: str | None = None
    with_xrefs: bool = False
    offset: int = 0
    limit: int = 100
    program: str | None = None


class ReadRequest(Model):
    address: str
    length: int
    format: str = "hex"  # hex | ascii | words | typed
    type: str | None = None
    program: str | None = None


class SearchQuery(Model):
    mode: str = "bytes"  # bytes | text | instructions | scalars
    pattern: str
    range_: str | None = None
    limit: int = 64
    program: str | None = None


class RenameRequest(Model):
    kind: str = "function"  # function | label | data | variable | field
    target: str
    new_name: str
    program: str | None = None


class PrototypeRequest(Model):
    function: str
    signature: str
    calling_convention: str | None = None
    program: str | None = None


class CommentRequest(Model):
    address: str
    kind: str = "plate"  # plate | pre | eol | post
    text: str
    batch: dict[str, str] | None = None  # address -> text when batch is requested
    program: str | None = None


class DiffRequest(Model):
    a: str
    b: str
    mode: str = "functions"  # functions | bytes
    range_: str | None = None
