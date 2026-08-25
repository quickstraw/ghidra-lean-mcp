"""In-memory GhidraAdapter for CI and fake mode.

Same method set as ghidra.backend.GhidraBackend (parity is asserted by
tests/contract/test_adapter_parity.py). M1: env() + lifecycle-ish state only;
methods added in M3+ get a minimal in-memory twin at the same time.
"""

from __future__ import annotations

from ghmcp.ghidra.protocols import (
    CommentRequest,
    DecompileRequest,
    EnvInfo,
    InstructionsRequest,
    OpenSpec,
    ProgramInfo,
    PrototypeRequest,
    RefsRequest,
    RenameRequest,
    SearchQuery,
    StringQuery,
    SymbolQuery,
)
from ghmcp.platform.errors import GhmcpError


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
        raise NotImplementedError("find: M5 (fake)")

    def refs(self, pid: str, request: RefsRequest) -> list[object]:
        raise NotImplementedError("refs: M4 (fake)")

    def symbols(self, pid: str, request: SymbolQuery) -> tuple[list[object], bool]:
        raise NotImplementedError("symbols: M4 (fake)")

    def strings(self, pid: str, request: StringQuery) -> tuple[list[object], bool]:
        raise NotImplementedError("strings: M4 (fake)")

    # ------------------------------------------------------------------ write

    def rename(self, pid: str, request: RenameRequest) -> None:
        raise NotImplementedError("rename: M6 (fake)")

    def set_prototype(self, pid: str, request: PrototypeRequest) -> None:
        raise NotImplementedError("set_prototype: M6 (fake)")

    def set_comment(self, pid: str, request: CommentRequest) -> None:
        raise NotImplementedError("set_comment: M6 (fake)")

    def define_types(self, pid: str, c_decl: str) -> list[str]:
        raise NotImplementedError("define_types: M6 (fake)")

    def apply_type(self, pid: str, address: int, c_type: str, variable: str | None) -> None:
        raise NotImplementedError("apply_type: M6 (fake)")

    # ------------------------------------------------------------ game specials

    def memory_map(self, pid: str) -> list[dict]:
        raise NotImplementedError("memory_map: M7 (fake)")

    def create_block(self, pid: str, name: str, address: int, size: int, flags: str) -> None:
        raise NotImplementedError("create_block: M7 (fake)")

    def rebase(self, pid: str, new_base: int) -> None:
        raise NotImplementedError("rebase: M7 (fake)")

    def diff_functions(self, a_pid: str, b_pid: str) -> dict:
        raise NotImplementedError("diff_functions: M7 (fake)")

    def diff_bytes(self, a_pid: str, b_pid: str, start: int, end: int) -> dict:
        raise NotImplementedError("diff_bytes: M7 (fake)")

    def analysis_state(self, pid: str) -> str:
        raise NotImplementedError("analysis_state: M7 (fake)")

    def run_analysis(self, pid: str, options: dict) -> None:
        raise NotImplementedError("run_analysis: M7 (fake)")

    def analysis_options(self, pid: str) -> dict:
        raise NotImplementedError("analysis_options: M7 (fake)")

    # ------------------------------------------------------------------ scripts

    def run_script(
        self, pid: str | None, kind: str, code: str | None, path: str | None, args: list[str]
    ) -> dict:
        raise NotImplementedError("run_script: M5 (fake)")

    # ------------------------------------------------------------------ tasks

    def analyze_async(self, pid: str, options: dict | None) -> str:
        raise NotImplementedError("analyze_async: M7 (fake)")

    def task_status(self, task_id: str) -> dict:
        raise NotImplementedError("task_status: M7 (fake)")

    def require_program(self, pid: str) -> object:
        raise GhmcpError(f"program {pid!r} is not available", hint="open_program first")
