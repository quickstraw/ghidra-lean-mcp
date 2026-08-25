"""Real Ghidra adapter: the only place Ghidra program APIs are touched.

Milestone map: M1 env(); M3 lifecycle + decompile/instructions/read;
M4 xrefs/symbols/strings; M5 search/scripts; M6 writes; M7 game specials.
Unimplemented milestones stay loud (NotImplementedError, never a silent no-op).
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from ghmcp.ghidra.protocols import (
    CallGraphPage,
    CallGraphRequest,
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
from ghmcp.platform.errors import GhmcpError, NotFound, ReadOnly
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

    def _write(self, entry: object, description: str, fn):
        """Run a write inside a transaction; requite a writable session and
        record the mutation so the decompile/store cache invalidates (plan §5.2)."""
        if not bool((entry.open_flags or {}).get("writable")):
            raise ReadOnly(
                "this program was opened read-only",
                hint="re-open with open_program(writable=true) to annotate",
            )
        from ghmcp.runtime.txn import txn

        with txn(entry.program, description):
            result = fn()
        entry.bump_mod(self._mod(entry.program))
        return result

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

    def refs(self, pid: str, request: RefsRequest) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.refs import refs_page

        entry = self._sessions.get(pid)
        return refs_page(entry.program, request)

    def symbols(self, pid: str, request: SymbolQuery) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.symbols import symbols_page

        entry = self._sessions.get(pid)
        return symbols_page(entry.program, request)

    def strings(self, pid: str, request: StringQuery) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.strings import strings_page

        entry = self._sessions.get(pid)
        return strings_page(entry.program, request)

    def call_graph(self, pid: str, request: CallGraphRequest) -> CallGraphPage:
        self._bootstrap()
        from ghmcp.ghidra.callgraph import call_graph

        entry = self._sessions.get(pid)
        return call_graph(entry, request)

    # ------------------------------------------------------------------ search (M5)

    def find(self, pid: str, request: SearchQuery) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.search import search_page

        entry = self._sessions.get(pid)
        return search_page(entry.program, request)

    # ------------------------------------------------------------------ scripts (M5)

    def run_script(
        self, pid: str | None, kind: str, code: str | None, path: str | None, args: list[str]
    ) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.script import run_script

        entry = self._sessions.get(pid) if pid else self._sessions.current_entry()
        if entry is None:
            raise GhmcpError("no program open for run_script", hint="open_program first")
        return run_script(entry, kind, code, path, args)

    # ------------------------------------------------------------------ write (M6)

    def rename(self, pid: str, request: RenameRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import rename

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: rename", lambda: rename(entry.program, request))

    def set_prototype(self, pid: str, request: PrototypeRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import set_prototype

        entry = self._sessions.get(pid)
        self._write(
            entry, "ghmcp: set_prototype", lambda: set_prototype(entry.program, request)
        )

    def set_comment(self, pid: str, request: CommentRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import set_comment

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: set_comment", lambda: set_comment(entry.program, request))

    def define_types(self, pid: str, c_decl: str) -> list[str]:
        self._bootstrap()
        from ghmcp.ghidra.annotate import define_types

        entry = self._sessions.get(pid)
        return self._write(
            entry, "ghmcp: define_types", lambda: define_types(entry.program, c_decl)
        )

    def apply_type(self, pid: str, address: int, c_type: str, variable: str | None) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import apply_type

        entry = self._sessions.get(pid)
        self._write(
            entry,
            "ghmcp: apply_type",
            lambda: apply_type(entry.program, address, c_type, variable),
        )

    def list_types(self, pid: str) -> list[str]:
        self._bootstrap()
        from ghmcp.ghidra.annotate import list_types

        entry = self._sessions.get(pid)
        return list_types(entry.program)

    def get_type(self, pid: str, name: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.annotate import get_type

        entry = self._sessions.get(pid)
        return get_type(entry.program, name)

    # ------------------------------------------------------------------ game specials (M7)

    def memory_map(self, pid: str) -> list[dict]:
        self._bootstrap()
        from ghmcp.ghidra.game import memory_map

        entry = self._sessions.get(pid)
        return memory_map(entry)

    def create_block(self, pid: str, name: str, address: int, size: int, flags: str) -> None:
        self._bootstrap()
        from ghmcp.ghidra.game import create_block

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: create_block", lambda: create_block(entry, name, address, size, flags))

    def rebase(self, pid: str, new_base: int) -> None:
        self._bootstrap()
        from ghmcp.ghidra.game import rebase

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: rebase", lambda: rebase(entry, new_base))

    def diff_functions(self, a_pid: str, b_pid: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import diff_functions

        return diff_functions(self._sessions.get(a_pid), self._sessions.get(b_pid))

    def diff_bytes(self, a_pid: str, b_pid: str, start: int, end: int) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import diff_bytes

        return diff_bytes(
            self._sessions.get(a_pid).program, self._sessions.get(b_pid).program, start, end
        )

    def analysis_state(self, pid: str) -> str:
        self._bootstrap()
        from ghmcp.ghidra.game import analysis_state

        return analysis_state(self._sessions.get(pid))

    def run_analysis(self, pid: str, options: dict) -> None:
        self._bootstrap()
        from ghmcp.ghidra.game import run_analysis

        entry = self._sessions.get(pid)
        run_analysis(entry, options)
        entry.bump_mod(self._mod(entry.program))

    def analysis_options(self, pid: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import analysis_options

        return analysis_options(self._sessions.get(pid))

    # ------------------------------------------------------------------ tasks (M7)

    def analyze_async(self, pid: str, options: dict | None) -> str:
        self._bootstrap()
        from ghmcp.runtime import tasks

        entry = self._sessions.get(pid)

        def job():
            from ghmcp.ghidra.game import run_analysis

            run_analysis(entry, options)

        return tasks.start_task("analysis", job)

    def task_status(self, task_id: str) -> dict:
        from ghmcp.runtime import tasks

        return tasks.task_status(task_id)

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
