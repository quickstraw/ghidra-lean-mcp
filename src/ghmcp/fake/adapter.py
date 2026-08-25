"""In-memory GhidraAdapter for CI and fake mode.

Same method set as ghidra.backend.GhidraBackend (parity is asserted by
tests/contract/test_adapter_parity.py). M1: env() + lifecycle-ish state only;
methods added in M3+ get a minimal in-memory twin at the same time.
"""

from __future__ import annotations

from ghmcp.ghidra.protocols import (
    CallGraphPage,
    CallGraphRequest,
    CommentRequest,
    DecompileRequest,
    EnvInfo,
    FunctionBrief,
    Hit,
    InstructionsRequest,
    OpenSpec,
    ProgramInfo,
    PrototypeRequest,
    Ref,
    RefsRequest,
    RenameRequest,
    SearchQuery,
    StringEntry,
    StringQuery,
    Symbol,
    SymbolQuery,
)
from ghmcp.platform.errors import GhmcpError, ReadOnly


def _assert_writable(entry: dict) -> None:
    if not bool((entry.get("spec") or {}).writable):
        raise ReadOnly(
            "this program was opened read-only",
            hint="re-open with open_program(writable=true) to annotate",
        )


def _page(source, offset: int, limit: int) -> tuple[list, bool]:
    """In-memory twin of ghmcp.platform.format.page (keeps the fake self-contained)."""
    from ghmcp.platform.format import page

    return page(source, offset, limit)


def _fake_type_names(c_decl: str) -> list[str]:
    import re

    names = []
    for m in re.finditer(r"(?:typedef\s+.+?\s+(\w+)|struct\s+(\w+))\s*;?\s*", c_decl):
        names.append(m.group(1) or m.group(2))
    return [n for n in names if n]


def _parse_byte_pattern(pattern: str) -> list[int] | None:
    import re

    s = pattern.strip()
    if not s:
        return None
    if s[:2].lower() == "0x":
        s = s[2:]
        tokens = [s[i : i + 2] for i in range(0, len(s), 2)]
    else:
        tokens = [t for t in re.split(r"[\s,:]+", s) if t]
    out = []
    for tok in tokens:
        if tok.lower() in ("??", "?"):
            out.append(0)
            continue
        tok = tok[2:] if tok[:2].lower() == "0x" else tok
        if not (len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok)):
            return None
        out.append(int(tok, 16))
    return out


def _find_bytes(data: bytes, pat: list[int], start: int) -> int:
    n = pat.count(0)
    for i in range(start, len(data) - len(pat) + 1):
        if n and data[i : i + len(pat)].count(0) < n:
            continue
        if all(p == 0 or data[i + j] == p for j, p in enumerate(pat)):
            return i
    return -1


class FakeAdapter:
    def __init__(self, settings: object = None):
        self._settings = settings
        self._programs: dict[str, dict] = {}
        self._next_pid = 0
        self._current: str | None = None

    # ------------------------------------------------------------------ env

    def env(self) -> EnvInfo:
        return EnvInfo(
            ghidra_version="fake-9.9",
            full_version="fake-9.9",
            java_heap=getattr(self._settings, "jvm_heap", "8g") if self._settings else "8g",
        )

    # ------------------------------------------------------------ lifecycle

    def open(self, spec: OpenSpec) -> ProgramInfo:
        self._next_pid += 1
        pid = f"f{self._next_pid}"
        base = spec.image_base or 0x100000
        info = ProgramInfo(
            pid=pid,
            alias=spec.alias,
            path=spec.path,
            format="fake-format" if spec.loader_name is None else spec.loader_name,
            language=spec.language or "FAKE:LE:32:default",
            compiler=spec.compiler or "default",
            image_base=base,
            entry_points=[base + 0x1000],
            memory_blocks=[f"block_{spec.language or 'fake'}"],
            symbol_count=12,
            function_count=8,
            string_count=5,
            analysis_state="analyzed" if spec.analyze != "none" else "none",
            writable=spec.writable,
        )
        self._programs[pid] = {
            "info": info,
            "spec": spec,
            "mod": 0,
            "bytes": bytes(range(256)) * 8,
            "functions": {
                "play_song": 0x1000,
                "FUN_00001000": 0x1000,
                "main": 0x2000,
                "render": 0x3000,
            },
            "symbols": _seed_symbols(),
            "refs": _seed_refs(),
            "strings": _seed_strings(),
        }
        if self._current is None:
            self._current = pid
        return info

    def close(self, pid: str) -> None:
        if pid not in self._programs:
            raise GhmcpError(f"program {pid!r} is not open")
        del self._programs[pid]
        if self._current == pid:
            self._current = next(iter(self._programs), None)

    def shutdown(self) -> None:
        self._programs.clear()
        self._current = None

    def save(self, pid: str) -> None:
        self._require(pid)

    def list_open(self) -> list[ProgramInfo]:
        return [self._programs[p]["info"] for p in self._programs]

    def modification_number(self, pid: str) -> int:
        return self._require(pid)["mod"]

    def select(self, pid: str) -> None:
        self._require(pid)
        self._current = pid

    def current(self) -> str | None:
        return self._current

    def _require(self, pid: str) -> dict:
        entry = self._programs.get(pid)
        if entry is None:
            raise GhmcpError(f"program {pid!r} is not open", hint="open_program first")
        return entry

    # ------------------------------------------------------------------ read

    def decompile(self, pid: str, request: DecompileRequest) -> list[object]:
        from ghmcp.ghidra.protocols import DecompiledFn

        entry = self._require(pid)
        specs = entry["functions"]
        out = []
        for target in request.targets:
            name = target.split("@")[0].split("/")[-1]
            addr = specs.get(name, 0x1000)
            out.append(
                DecompiledFn(
                    name=name,
                    address=addr,
                    lines=["// fake decompile", f"int {name}() {{", "    return 0;", "}"],
                )
            )
        return out

    def instructions(self, pid: str, request: InstructionsRequest) -> list[object]:
        from ghmcp.ghidra.protocols import Insn
        from ghmcp.platform.targets import parse_address

        self._require(pid)
        start = parse_address(request.start)
        count = request.count or 4
        return [
            Insn(
                address=start + i * 4,
                mnemonic=f"fake{i}",
                bytes="00 01 02 03" if request.include_bytes else "",
                text=f"fake{i} {start + i * 4:#x}",
            )
            for i in range(count)
        ]

    def read(self, pid: str, address: int, length: int) -> bytes:
        entry = self._require(pid)
        data = entry["bytes"]
        start = address % len(data)
        return b"".join(data[start : start + length] for _ in range(1))

    def find(self, pid: str, request: SearchQuery) -> list[object]:
        entry = self._require(pid)
        data = entry["bytes"]
        mode = request.mode
        if mode == "bytes":
            pat = _parse_byte_pattern(request.pattern)
            if pat is None:
                from ghmcp.platform.errors import BadTarget

                raise BadTarget(f"invalid byte pattern {request.pattern!r}")
            hits = []
            idx = 0
            while len(hits) < request.limit:
                pos = _find_bytes(data, pat, idx)
                if pos < 0:
                    break
                hits.append(Hit(address=pos, kind="bytes", preview=" ".join(f"{b:02x}" for b in data[pos : pos + len(pat)])))
                idx = pos + 1
            return hits
        if mode == "text":
            needle = request.pattern.encode("utf-8")
            hits = []
            idx = 0
            while len(hits) < request.limit:
                pos = data.find(needle, idx)
                if pos < 0:
                    break
                hits.append(Hit(address=pos, kind="text", preview=data[pos : pos + len(needle)].decode("latin-1", "replace")))
                idx = pos + 1
            return hits
        if mode == "instructions":
            import re

            hits = []
            addr = 0x1000
            for i in range(min(request.limit, 8)):
                text = f"insn {addr:#x} mov r{i}"
                if re.search(request.pattern, text, re.IGNORECASE):
                    hits.append(Hit(address=addr, kind="instructions", preview=text))
                addr += 4
            return hits
        from ghmcp.platform.errors import BadTarget

        raise BadTarget(f"unknown search mode {request.mode!r}", hint="bytes|text|instructions|scalars")

    def run_script(
        self, pid: str | None, kind: str, code: str | None, path: str | None, args: list[str]
    ) -> dict:
        self._require(pid)
        if kind != "python":
            raise NotImplementedError("ghidra_script: M5 (fake)")
        ns: dict = {"args": list(args), "result": None}
        import io
        from contextlib import redirect_stderr, redirect_stdout

        buf = io.StringIO()
        error = None
        try:
            with redirect_stdout(buf), redirect_stderr(buf):
                exec(code or "", ns, ns)
        except BaseException as exc:
            error = f"{type(exc).__name__}: {exc}"
            buf.write(f"\n{error}")
        return {"stdout": buf.getvalue(), "result": ns.get("result"), "error": error}

    def refs(self, pid: str, request: RefsRequest) -> tuple[list[object], bool]:
        entry = self._require(pid)

        def gen():
            for ti, (start, end) in enumerate(request.targets):
                for ref in _iter_fake_refs(entry, start, end, request.direction):
                    if request.kinds and ref.kind not in request.kinds:
                        continue
                    ref.target = ti
                    yield ref

        return _page(gen(), request.offset, request.limit)

    def symbols(self, pid: str, request: SymbolQuery) -> tuple[list[object], bool]:
        entry = self._require(pid)
        matcher = _FakeNameMatcher(request.query)

        def gen():
            for name in sorted(entry["symbols"], key=lambda n: entry["symbols"][n]["addr"]):
                sym = entry["symbols"][name]
                addr, kind, size = sym["addr"], sym["kind"], sym.get("size", 0)
                if matcher and not matcher(name):
                    continue
                if request.kind and kind != request.kind:
                    continue
                if request.range_:
                    r = _parse_range(request.range_)
                    if not (r[0] <= addr <= r[1]):
                        continue
                if request.undefined_only and kind != "label":
                    continue
                if request.min_size and size and size < request.min_size:
                    continue
                yield Symbol(
                    name=name,
                    address=addr,
                    kind=kind,
                    namespace="",
                    size=size,
                    n_refs=_count_refs_to(entry, addr),
                )

        return _page(gen(), request.offset, request.limit)

    def strings(self, pid: str, request: StringQuery) -> tuple[list[object], bool]:
        entry = self._require(pid)
        if request.source == "scan":
            data = entry["bytes"]
            q = (request.query or "").lower()
            min_len = max(request.min_length or 4, 4)

            def scan_gen():
                for addr, value in _scan_bytes(data, min_len):
                    if q and q not in value.lower():
                        continue
                    yield StringEntry(
                        value=value,
                        address=addr,
                        encoding=request.encoding or "utf8",
                        size=len(value),
                        xrefs=0,
                    )

            return _page(scan_gen(), request.offset, request.limit)

        def gen():
            for s in entry["strings"]:
                if request.query and request.query.lower() not in s["value"].lower():
                    continue
                if request.min_length and len(s["value"]) < request.min_length:
                    continue
                if request.encoding and request.encoding != s["encoding"]:
                    continue
                yield StringEntry(
                    value=s["value"],
                    address=s["addr"],
                    encoding=s["encoding"],
                    size=s["size"],
                    xrefs=_count_refs_to(entry, s["addr"]) if request.with_xrefs else 0,
                )

        return _page(gen(), request.offset, request.limit)

    def call_graph(self, pid: str, request: CallGraphRequest) -> CallGraphPage:
        entry = self._require(pid)
        root_addr = _resolve_fake_fn(entry, request.target)
        root = FunctionBrief(
            name=_fn_name(entry, root_addr), address=root_addr, depth=0, via=""
        )
        graph = _build_fake_graph(entry)
        page = CallGraphPage(root=root, callers=[], callees=[], path=[], truncated=False)
        depth = max(1, min(request.depth, 5))
        if request.direction in ("callers", "both"):
            page.callers = _bfs(graph, entry, root_addr, upward=True, depth=depth)
        if request.direction in ("callees", "both"):
            page.callees = _bfs(graph, entry, root_addr, upward=False, depth=depth)
        if request.path_to:
            dest = _resolve_node(entry, request.path_to)
            page.path = _fake_path(graph, entry, root_addr, dest)
        return page

    # ------------------------------------------------------------------ write

    def rename(self, pid: str, request: RenameRequest) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        kind, target, new = request.kind, request.target, request.new_name
        if kind == "function":
            addr = _resolve_fake_fn(entry, target)
            name = _label_at_addr(entry, addr)
            if name and name in entry["symbols"]:
                entry["symbols"][new] = entry["symbols"].pop(name)
            else:
                entry["symbols"][new] = {"addr": addr, "kind": "function"}
            entry["mod"] += 1
            return
        if kind in ("label", "data"):
            # Mirror real annotate._symbol_or_addr precedence: address → exact →
            # case-insensitive exact → first prefix (via the shared resolver).
            addr = _resolve_fake_fn(entry, target)
            entry["symbols"][new] = {"addr": addr, "kind": "label"}
            entry["mod"] += 1
            return
        raise GhmcpError(f"unsupported rename kind {kind!r}")

    def set_prototype(self, pid: str, request: PrototypeRequest) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["prototypes"] = entry.get("prototypes", {})
        entry["prototypes"][request.function] = request.signature
        entry["mod"] += 1

    def set_comment(self, pid: str, request: CommentRequest) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["comments"] = entry.get("comments", {})
        if request.batch:
            entry["comments"].update(request.batch)
        else:
            entry["comments"][request.address] = request.text
        entry["mod"] += 1

    def define_types(self, pid: str, c_decl: str) -> list[str]:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["types"] = entry.get("types", [])
        names = _fake_type_names(c_decl)
        entry["types"].extend(names)
        entry["mod"] += 1
        return names

    def apply_type(self, pid: str, address: int, c_type: str, variable: str | None) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["applied_types"] = entry.get("applied_types", {})
        entry["applied_types"][variable or address] = c_type
        entry["mod"] += 1

    def list_types(self, pid: str) -> list[str]:
        entry = self._require(pid)
        return sorted(set(entry.get("types", [])))

    def get_type(self, pid: str, name: str) -> dict:
        entry = self._require(pid)
        if name not in entry.get("types", []):
            raise GhmcpError(f"no such type {name!r}")
        return {"name": name, "size": 0}

    # ------------------------------------------------------------ game specials

    def memory_map(self, pid: str) -> list[dict]:
        entry = self._require(pid)
        info = entry["info"]
        base = info.image_base
        blocks = [
            {
                "name": "code",
                "start": base,
                "end": base + 0x4000,
                "size": 0x4000,
                "read": True,
                "write": True,
                "execute": True,
                "initialized": True,
                "volatile": False,
                "space": "default",
            }
        ]
        blocks.extend(entry.get("blocks", []))
        return blocks

    def create_block(self, pid: str, name: str, address: int, size: int, flags: str) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["blocks"] = entry.get("blocks", [])
        entry["blocks"].append({"name": name, "start": address, "end": address + size, "size": size})
        entry["mod"] += 1

    def rebase(self, pid: str, new_base: int) -> None:
        entry = self._require(pid)
        _assert_writable(entry)
        entry["info"].image_base = new_base
        entry["mod"] += 1

    def diff_functions(self, a_pid: str, b_pid: str) -> dict:
        a = self._require(a_pid)
        b = self._require(b_pid)
        fa = _fn_index(a)
        fb = _fn_index(b)
        return {
            "a_name": a["info"].alias or a_pid,
            "b_name": b["info"].alias or b_pid,
            "added": sorted(set(fb) - set(fa)),
            "removed": sorted(set(fa) - set(fb)),
            "common": sorted(set(fa) & set(fb)),
            "a_function_count": len(fa),
            "b_function_count": len(fb),
        }

    def diff_bytes(self, a_pid: str, b_pid: str, start: int, end: int) -> dict:
        if end < start:
            raise GhmcpError("diff range end before start")
        from ghmcp.ghidra.game import MAX_DIFF_BYTES

        length = end - start + 1
        if length > MAX_DIFF_BYTES:
            raise GhmcpError(f"diff range is {length} bytes (cap {MAX_DIFF_BYTES})")
        a = self._require(a_pid)
        b = self._require(b_pid)
        da, db = a["bytes"], b["bytes"]
        xa = _window(da, start, length)
        xb = _window(db, start, length)
        differing = [i for i in range(min(len(xa), len(xb))) if xa[i] != xb[i]]
        return {
            "start": start,
            "end": end,
            "length": length,
            "equal": not differing,
            "differing_bytes": len(differing),
            "first_diff": start + differing[0] if differing else None,
        }

    def analysis_state(self, pid: str) -> str:
        entry = self._require(pid)
        return entry["info"].analysis_state

    def run_analysis(self, pid: str, options: dict) -> None:
        entry = self._require(pid)
        entry["info"].analysis_state = "analyzed"
        entry["analysis_options"] = dict(options or {})
        entry["mod"] += 1

    def analysis_options(self, pid: str) -> dict:
        entry = self._require(pid)
        return dict(entry.get("analysis_options", {}))

    # ------------------------------------------------------------------ tasks

    def analyze_async(self, pid: str, options: dict | None) -> str:
        import uuid

        entry = self._require(pid)
        task_id = uuid.uuid4().hex[:12]
        self._tasks = getattr(self, "_tasks", {})
        self._tasks[task_id] = {"state": "done", "progress": 1.0, "kind": "analysis", "result": None}
        entry["info"].analysis_state = "analyzed"
        return task_id

    def task_status(self, task_id: str) -> dict:
        self._tasks = getattr(self, "_tasks", {})
        task = self._tasks.get(task_id)
        if task is None:
            raise GhmcpError(f"unknown task {task_id!r}")
        return dict(task)

    def require_program(self, pid: str) -> object:
        raise GhmcpError(f"program {pid!r} is not available", hint="open_program first")


def _seed_symbols() -> dict:
    return {
        "play_song": {"addr": 0x1000, "kind": "function"},
        "FUN_00001000": {"addr": 0x1000, "kind": "function"},
        "main": {"addr": 0x2000, "kind": "function"},
        "render": {"addr": 0x3000, "kind": "function"},
        "startup": {"addr": 0x3100, "kind": "function"},
        "snd_coin": {"addr": 0x5000, "kind": "data", "size": 16},
        "snd_jump": {"addr": 0x5010, "kind": "data", "size": 16},
        "label_unc": {"addr": 0x6000, "kind": "label"},
    }


def _seed_refs() -> list:
    # (from, to, kind): main calls play_song/render; startup uses snd_coin and a string.
    return [
        (0x2000, 0x1000, "flow"),
        (0x2000, 0x3000, "flow"),
        (0x2000, 0x4000, "data"),
        (0x3100, 0x5000, "flow"),
        (0x3100, 0x5050, "data"),
        (0x2000, 0x5050, "data"),
    ]


def _seed_strings() -> list:
    return [
        {"addr": 0x5050, "value": "Intro: Welcome!", "size": 18, "encoding": "utf8"},
        {"addr": 0x5060, "value": "Press Start", "size": 12, "encoding": "utf8"},
        {"addr": 0x5070, "value": "exit", "size": 5, "encoding": "utf8"},
    ]


def _label_at_addr(entry: dict, addr: int):
    for name, sym in entry["symbols"].items():
        if sym["addr"] == addr:
            return name
    return None


def _count_refs_to(entry: dict, addr: int) -> int:
    return sum(1 for (_f, to, _k) in entry["refs"] if to == addr)


def _fn_index(entry: dict) -> dict:
    return {
        n: sym["addr"] for n, sym in entry["symbols"].items() if sym["kind"] == "function"
    }


def _window(data: bytes, start: int, length: int) -> bytes:
    """Linear read of [start, start+length) with zero-fill OOB — matches the real
    backend's game._read_range semantics (no modulo wrap)."""
    out = bytearray(length)
    for i in range(length):
        idx = start + i
        if 0 <= idx < len(data):
            out[i] = data[idx]
    return bytes(out)


def _iter_fake_refs(entry: dict, start: int, end: int, direction: str):
    for (fro, to, kind) in entry["refs"]:
        if end == start:
            if direction in ("to", "both") and to == start:
                yield Ref(address=fro, kind=kind, source=fro, label=_label_at_addr(entry, fro), target=None)
            if direction in ("from", "both") and fro == start:
                yield Ref(address=to, kind=kind, source=fro, label=_label_at_addr(entry, to), target=None)
            continue
        if direction in ("to", "both") and start <= to <= end:
            yield Ref(address=fro, kind=kind, source=fro, label=_label_at_addr(entry, fro), target=None)
        elif direction in ("from", "both") and start <= fro <= end:
            yield Ref(address=to, kind=kind, source=fro, label=_label_at_addr(entry, to), target=None)


class _FakeNameMatcher:
    """Mirror the real symbols._QueryMatcher: bare query = prefix; a query with
    `*`/`%` = anchored glob (`^…$`, `*`→`.*`). Keeps find_symbols identical
    between the real and fake backends (no substring-vs-prefix drift)."""

    def __init__(self, query: str | None):
        import re

        q = (query or "").strip()
        self._none = not q or q in ("*", "%")
        self._glob = None
        self._prefix = None
        if not self._none:
            if "*" in q or "%" in q:
                self._glob = re.compile(
                    "^" + re.escape(q.replace("%", "*")).replace(r"\*", ".*") + "$",
                    re.IGNORECASE,
                )
            else:
                self._prefix = q.lower()

    def __call__(self, name: str) -> bool:
        if self._none:
            return True
        if self._glob is not None:
            return bool(self._glob.search(name))
        return name.lower().startswith(self._prefix or "")


def _parse_range(text: str) -> tuple[int, int]:
    from ghmcp.platform.targets import parse_range

    rng = parse_range(text)
    if rng is None:
        from ghmcp.platform.errors import BadTarget

        raise BadTarget(f"invalid range {text!r}")
    return rng


def _scan_bytes(data: bytes, min_len: int):
    run = None
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if run is None:
                run = ""
                start = i
            run += chr(b)
        else:
            if run is not None and len(run) >= min_len:
                yield start, run
            run = None
    if run is not None and len(run) >= min_len:
        yield start, run


def _resolve_fake_fn(entry: dict, token: str) -> int:
    from ghmcp.platform.errors import BadTarget, NotFound
    from ghmcp.platform.targets import parse_address

    t = token.strip()
    try:
        return parse_address(t)
    except BadTarget:
        pass
    syms = entry["symbols"]
    if t in syms:
        return syms[t]["addr"]
    low = t.lower()
    cand = [name for name in syms if name.lower() == low]
    if cand:
        return syms[cand[0]]["addr"]
    cand = [name for name in syms if name.lower().startswith(low)]
    if cand:
        return syms[cand[0]]["addr"]
    raise NotFound(f"no symbol named {token!r}", hint="try find_symbols")


def _fn_name(entry: dict, addr: int) -> str:
    return _label_at_addr(entry, addr) or f"FUN_{addr:08x}"


def _build_fake_graph(entry: dict) -> dict:
    graph: dict[int, dict] = {}
    for (fro, to, kind) in entry["refs"]:
        if kind != "flow":
            continue
        graph.setdefault(fro, {"callers": set(), "callees": set()})
        graph.setdefault(to, {"callers": set(), "callees": set()})
        graph[fro]["callees"].add(to)
        graph[to]["callers"].add(fro)
    return graph


def _node_name(entry: dict, addr: int) -> str:
    return _label_at_addr(entry, addr) or f"FUN_{addr:08x}"


def _bfs(graph: dict, entry: dict, root: int, *, upward: bool, depth: int):
    key = "callers" if upward else "callees"
    seen = {root}
    frontier = [root]
    rows = []
    hop = 0
    while frontier and hop < depth:
        nxt = []
        hop += 1
        for node in frontier:
            for child in graph.get(node, {}).get(key) or ():
                if child in seen:
                    continue
                seen.add(child)
                rows.append(
                    FunctionBrief(
                        name=_node_name(entry, child),
                        address=child,
                        depth=hop,
                        via=_node_name(entry, node),
                    )
                )
                nxt.append(child)
        frontier = nxt
    return rows


def _resolve_node(entry: dict, token: str) -> int:
    return _resolve_fake_fn(entry, token)


def _fake_path(graph: dict, entry: dict, a: int, b: int):
    if a == b:
        return []
    from collections import deque

    parent = {a: None}
    dq = deque([a])
    while dq:
        cur = dq.popleft()
        for caller in graph.get(cur, {}).get("callers") or ():
            if caller in parent:
                continue
            parent[caller] = cur
            if caller == b:
                chain = [a]
                node = caller
                while node is not a:
                    chain.append(node)
                    node = parent[node]
                return [
                    FunctionBrief(
                        name=_node_name(entry, x),
                        address=x,
                        depth=i,
                        via="" if i == 0 else _node_name(entry, chain[i - 1]),
                    )
                    for i, x in enumerate(chain)
                ]
            dq.append(caller)
    return []
