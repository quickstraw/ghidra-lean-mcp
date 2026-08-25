"""Real Ghidra adapter: the only place Ghidra program APIs are touched.

Milestone map: M1 env(); M3 lifecycle + decompile/instructions/read;
M4 xrefs/symbols/strings; M5 search/scripts; M6 writes; M7 game specials.
Unimplemented milestones stay loud (NotImplementedError, never a silent no-op).
"""

from __future__ import annotations

import contextlib
from pathlib import Path

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
from ghmcp.platform.errors import GhmcpError, NotFound
from ghmcp.platform.telemetry import log_event


class GhidraBackend:
    """Implements GhidraAdapter over runtime.jvm.JvmManager."""

    def __init__(self, jvm: object, settings: object = None):
        self._jvm = jvm
        self._settings = settings
        self._project_mgr = None
        self._sessions = None
        self._decompool = None
        self._pid = 0
        self._closed = False

    # ------------------------------------------------------------------ plumbing

    def _bootstrap(self) -> None:
        """Lazy runtime singletons; called on first session use (never at import —
        JVM is already up by then). After shutdown() this is terminal: a late
        call raises instead of re-creating native state while teardown runs."""
        if self._closed:
            raise GhmcpError("the server is shutting down", hint="retry after the server restarts")
        if self._sessions is not None:
            return
        from ghmcp.runtime.decompool import DecompPool
        from ghmcp.runtime.project import ProjectManager
        from ghmcp.runtime.session import SessionManager

        self._sessions = SessionManager()
        self._project_mgr = ProjectManager(Path(self._settings.projects_dir))
        self._decompool = DecompPool(self._settings)

    # ------------------------------------------------------------------ env

    def env(self) -> EnvInfo:
        info = self._jvm.info()
        loaders, languages, active = self._probe_registry()
        return EnvInfo(
            ghidra_version=info.get("version"),
            full_version=info.get("version"),
            java_heap=getattr(self._jvm.settings, "jvm_heap", ""),
            extension_dirs=[info["extension_dir"]] if info.get("extension_dir") else [],
            loaders=loaders,
            languages=languages,
            active_extensions=active,
        )

    def _probe_registry(self) -> tuple[list[str], list[str], list[str]]:
        """Live LoaderService + language service + active extensions (§0.3)."""
        loaders: list[str] = []
        languages: list[str] = []
        active: list[str] = []
        try:
            from jpype import JClass

            LoaderService = JClass("ghidra.app.util.opinion.LoaderService")
            loaders = sorted(str(n) for n in LoaderService.getAllLoaderNames() or [])
        except Exception:
            pass
        try:
            from jpype import JClass

            lang_svc = JClass("ghidra.program.util.DefaultLanguageService").getLanguageService()
            descriptions = lang_svc.getLanguageDescriptions(True) or []
            langs: list[str] = []
            for desc in descriptions:
                try:
                    langs.append(
                        str(desc.getLanguageID()) if hasattr(desc, "getLanguageID") else str(desc)
                    )
                except Exception:
                    langs.append(str(desc))
            languages = sorted(set(langs))
        except Exception:
            pass
        try:
            from jpype import JClass

            eu = JClass("ghidra.util.extensions.ExtensionUtils")
            for details in eu.getActiveInstalledExtensions() or []:
                try:
                    active.append(
                        str(details.getName()) if hasattr(details, "getName") else str(details)
                    )
                except Exception:
                    active.append(str(details))
            active = sorted(set(active))
        except Exception:
            pass
        return loaders, languages, active

    # ------------------------------------------------------------------ lifecycle

    def open(self, spec: OpenSpec) -> ProgramInfo:
        self._bootstrap()
        path = Path(spec.path)
        if not path.exists():
            raise NotFound(
                f"file {spec.path!r} does not exist",
                hint="check the path (MCP clients see cwd-relative paths)",
            )
        if not path.is_file():
            raise NotFound(
                f"path {spec.path!r} is not a file", hint="open_program takes one binary"
            )

        from ghmcp.runtime.project import LoadSpec

        loader_spec = LoadSpec(
            loader_name=spec.loader_name,
            language=spec.language,
            compiler=spec.compiler,
            loader_args=spec.loader_args or {},
            image_base=spec.image_base,
        )
        project_path = self._project_mgr.import_program(path, loader_spec)
        program, consumer = self._project_mgr.consume(project_path, writable=spec.writable)

        if spec.image_base is not None and program.getImageBase().getOffset() != spec.image_base:
            from ghmcp.runtime.txn import txn

            with txn(program, "ghmcp: setImageBase"):
                program.setImageBase(self._addr(program, spec.image_base), True)

        if spec.analyze != "none":
            self._maybe_analyze(program, mode=spec.analyze)

        self._pid += 1
        pid = f"p{self._pid}"
        info = self._snapshot(program, pid, spec=spec)
        from ghmcp.runtime.session import SessionEntry

        entry = SessionEntry(
            pid=pid,
            program=program,
            consumer=consumer,
            project_path=project_path,
            info=info,
            alias=spec.alias,
            mod_number=self._mod(program),
            open_flags={"writable": spec.writable, "analyze": spec.analyze},
        )
        self._sessions.register(entry)
        log_event(
            "program_opened", pid=pid, path=str(path), preset=spec.preset, analyze=spec.analyze
        )
        return info

    def _maybe_analyze(self, program: object, mode: str) -> None:
        from ghmcp.runtime import tasks

        if mode == "none":
            return
        if self._is_analyzed(program) and self._has_instructions(program):
            return
        tasks.start_task("analysis", lambda: _run_analysis(program))

    @staticmethod
    def _has_instructions(program: object) -> bool:
        try:
            return int(program.getListing().getNumInstructions()) > 0
        except Exception:
            return False

    def close(self, pid: str) -> None:
        self._bootstrap()
        self._sessions.close(pid)

    def shutdown(self) -> None:
        """Release native decompiler processes and the project-dir lock.

        Terminal: after this, `_bootstrap` raises instead of re-creating native
        state while teardown runs (a re-bootstrapped ProjectManager would
        self-lock on the still-open .ghmcp.lock fd)."""
        if self._closed:
            return
        self._closed = True
        if self._decompool is not None:
            self._decompool.close()
        if self._project_mgr is not None:
            with contextlib.suppress(Exception):
                self._project_mgr.close()
        self._decompool = None
        self._sessions = None
        self._project_mgr = None

    def save(self, pid: str) -> None:
        self._bootstrap()
        entry = self._sessions.get(pid)
        entry.program.getDomainFile().save(None)
        entry.bump_mod(self._mod(entry.program))

    def list_open(self) -> list[ProgramInfo]:
        self._bootstrap()
        infos = []
        for pid in self._sessions.open_pids():
            entry = self._sessions.get(pid)
            infos.append(self._snapshot(entry.program, pid, spec=None))
        return infos

    def modification_number(self, pid: str) -> int:
        entry = self._sessions.get(pid)
        return self._mod(entry.program)

    def select(self, pid: str) -> None:
        self._sessions.select(pid)

    def current(self) -> str | None:
        self._bootstrap()
        return self._sessions.current()

    # ------------------------------------------------------------------ read

    def decompile(self, pid: str, request: DecompileRequest) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.decomp import decompile_program

        entry = self._sessions.get(pid)
        return decompile_program(entry, request, self._decompool)

    def instructions(self, pid: str, request: InstructionsRequest) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.listing import listing_program

        entry = self._sessions.get(pid)
        return listing_program(entry, request)

    def read(self, pid: str, address: int, length: int) -> bytes:
        self._bootstrap()
        entry = self._sessions.get(pid)
        program = entry.program
        if length <= 0:
            raise GhmcpError("length must be positive")
        from ghidra.program.model.mem import MemoryAccessException  # type: ignore[import-not-found]
        from jpype import JArray, JByte

        try:
            out = JArray(JByte)(length)
            program.getMemory().getBytes(self._addr(program, address), out)
        except MemoryAccessException as exc:
            raise GhmcpError(f"cannot read {length} bytes at {address:#x}: {exc}") from exc
        try:
            return bytes(out)
        except Exception:
            return bytes(bytearray(out))

    # ------------------------------------------------------------------ xrefs/symbols (M4)

    def refs(self, pid: str, request: RefsRequest) -> list[object]:
        raise NotImplementedError("refs: M4")

    def symbols(self, pid: str, request: SymbolQuery) -> tuple[list[object], bool]:
        raise NotImplementedError("symbols: M4")

    def strings(self, pid: str, request: StringQuery) -> tuple[list[object], bool]:
        raise NotImplementedError("strings: M4")

    # ------------------------------------------------------------------ search (M5)

    def find(self, pid: str, request: SearchQuery) -> list[object]:
        raise NotImplementedError("find: M5")

    # ------------------------------------------------------------------ write (M6)

    def rename(self, pid: str, request: RenameRequest) -> None:
        raise NotImplementedError("rename: M6")

    def set_prototype(self, pid: str, request: PrototypeRequest) -> None:
        raise NotImplementedError("set_prototype: M6")

    def set_comment(self, pid: str, request: CommentRequest) -> None:
        raise NotImplementedError("set_comment: M6")

    def define_types(self, pid: str, c_decl: str) -> list[str]:
        raise NotImplementedError("define_types: M6")

    def apply_type(self, pid: str, address: int, c_type: str, variable: str | None) -> None:
        raise NotImplementedError("apply_type: M6")

    # ------------------------------------------------------------------ game specials (M7)

    def memory_map(self, pid: str) -> list[dict]:
        raise NotImplementedError("memory_map: M7")

    def create_block(self, pid: str, name: str, address: int, size: int, flags: str) -> None:
        raise NotImplementedError("create_block: M7")

    def rebase(self, pid: str, new_base: int) -> None:
        raise NotImplementedError("rebase: M7")

    def diff_functions(self, a_pid: str, b_pid: str) -> dict:
        raise NotImplementedError("diff_functions: M7")

    def diff_bytes(self, a_pid: str, b_pid: str, start: int, end: int) -> dict:
        raise NotImplementedError("diff_bytes: M7")

    def analysis_state(self, pid: str) -> str:
        raise NotImplementedError("analysis_state: M7")

    def run_analysis(self, pid: str, options: dict) -> None:
        raise NotImplementedError("run_analysis: M7")

    def analysis_options(self, pid: str) -> dict:
        raise NotImplementedError("analysis_options: M7")

    # ------------------------------------------------------------------ scripts (M5)

    def run_script(
        self, pid: str | None, kind: str, code: str | None, path: str | None, args: list[str]
    ) -> dict:
        raise NotImplementedError("run_script: M5")

    # ------------------------------------------------------------------ tasks (M7)

    def analyze_async(self, pid: str, options: dict | None) -> str:
        raise NotImplementedError("analyze_async: M7")

    def task_status(self, task_id: str) -> dict:
        raise NotImplementedError("task_status: M7")

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _addr(program: object, offset: int) -> object:
        """Ghidra 12.1 removed AddressFactory.getAddress(long); go via the default space."""
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(offset))

    @staticmethod
    def _mod(program: object) -> int:
        try:
            return int(program.getModificationNumber())
        except Exception:
            return 0

    @staticmethod
    def _is_analyzed(program: object) -> bool:
        from ghidra.program.util import GhidraProgramUtilities  # type: ignore[import-not-found]

        try:
            return GhidraProgramUtilities.isProgramAnalyzed(program)
        except Exception:
            return True  # state unknown: don't re-analyze on every open

    def _snapshot(self, program: object, pid: str, spec: OpenSpec | None = None) -> ProgramInfo:
        fmt = "unknown"
        lang = ""
        compiler = ""
        entry_points: list[int] = []
        blocks: list[str] = []
        with contextlib.suppress(Exception):
            fmt = str(program.getExecutableFormat())
        try:
            lang = str(program.getLanguageID())
            compiler = str(program.getCompiler().getCompilerSpecID())
        except Exception:
            pass
        try:
            block_iter = iter(program.getMemory().getBlocks())
            blocks = [str(b.getName()) for b in block_iter]
        except Exception:
            pass
        try:
            st = program.getSymbolTable()
            ext = st.getExternalEntryPoints() if hasattr(st, "getExternalEntryPoints") else None
            if ext:
                for s in ext:
                    try:
                        entry_points.append(int(s.getAddress().getOffset()))
                    except Exception:
                        continue
        except Exception:
            pass
        counts = self._counts(program)
        self._entry_points_fallback(program, entry_points)
        return ProgramInfo(
            pid=pid,
            alias=(spec.alias if spec is not None else None) or None,
            path=str(spec.path) if spec is not None else None,
            format=fmt,
            language=lang,
            compiler=compiler,
            image_base=int(program.getImageBase().getOffset()),
            entry_points=sorted(set(entry_points))[:16],
            memory_blocks=blocks,
            writable=bool(spec and spec.writable),
            **counts,
        )

    @staticmethod
    def _counts(program: object) -> dict:
        out: dict = {
            "symbol_count": 0,
            "function_count": 0,
            "string_count": 0,
            "analysis_state": "unknown",
        }
        with contextlib.suppress(Exception):
            out["function_count"] = int(program.getFunctionManager().getFunctionCount())
        with contextlib.suppress(Exception):
            out["symbol_count"] = int(program.getSymbolTable().getNumSymbols())
        return out

    @staticmethod
    def _entry_points_fallback(program: object, entry_points: list[int]) -> None:
        if entry_points:
            return
        try:
            from ghidra.program.model.symbol import SymbolType  # type: ignore[import-not-found]

            st = program.getSymbolTable()
            for symbol in st.getAllSymbols(True) or []:
                try:
                    if symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isGlobal():
                        entry_points.append(int(symbol.getAddress().getOffset()))
                        if len(entry_points) >= 16:
                            break
                except Exception:
                    continue
        except Exception:
            pass

    def require_program(self, pid: str) -> object:
        self._bootstrap()
        return self._sessions.get(pid)


def _run_analysis(program: object) -> None:
    import pyghidra

    pyghidra.analyze(program, None)
    log_event("analysis_done", format=str(getattr(program, "getExecutableFormat", lambda: "?")()))
