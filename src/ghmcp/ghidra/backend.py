"""Real Ghidra adapter: the only place Ghidra program APIs are touched.

Milestone map: M1 env(); M3 lifecycle + decompile/instructions/read;
M4 xrefs/symbols/strings; M5 search/scripts; M6 writes; M7 game specials.
Unimplemented milestones stay loud (NotImplementedError, never a silent no-op).
"""

from __future__ import annotations

import contextlib
import time
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

    # Extension dir/registry state changes only on install/uninstall; TTL keeps
    # the drift warning fresh (plan §6.6) without a JVM probe + FS scan on
    # every env() (that would blow the §5.1 per-call overhead budget).
    _EXT_META_TTL = 30.0
    _REGISTRY_TTL = 30.0

    def __init__(self, jvm: object, settings: object = None):
        self._jvm = jvm
        self._settings = settings
        self._project_mgr = None
        self._sessions = None
        self._decompool = None
        self._pid = 0
        self._closed = False
        self._meta_cache: tuple[float, list[str], str | None] | None = None
        self._registry_cache: tuple[float, list[str], list[str], list[str]] | None = None

    # ------------------------------------------------------------------ plumbing

    def _bootstrap(self) -> None:
        """Lazy runtime singletons; called on first session use (never at import —
        JVM is already up by then). After shutdown() this is terminal: a late
        call raises instead of re-creating native state while teardown runs."""
        if self._closed:
            raise GhmcpError("the server is shutting down", hint="retry after the server restarts")
        if self._jvm is not None and not getattr(self._jvm, "started", False):
            # warm_jvm=False: the first adapter use pays the boot. start() is
            # idempotent and thread-safe (may be called from a worker thread).
            self._jvm.start()
        if self._sessions is not None:
            return
        from ghmcp.runtime.decompool import DecompPool
        from ghmcp.runtime.project import ProjectManager
        from ghmcp.runtime.session import SessionManager

        self._sessions = SessionManager()
        self._project_mgr = ProjectManager(Path(self._settings.projects_dir))
        self._decompool = DecompPool(self._settings)

    def _lock_timeout(self) -> float:
        # Single source of truth: config declares the default (30.0, gt=0).
        return self._settings.program_lock_timeout

    def _locked(self, pid: str, write: bool, fn):
        """Run `fn(entry)` under the per-program RWLock; BusyError past the
        timeout so contention never hangs a worker thread."""
        entry = self._sessions.get(pid)
        lock = entry.lock
        (lock.acquire_write if write else lock.acquire_read)(timeout=self._lock_timeout())
        try:
            return fn(entry)
        finally:
            (lock.release_write if write else lock.release_read)()

    def _diff_pair(self, a_pid: str, b_pid: str):
        """(entry_a, entry_b, release) for a two-program read.

        Pids are locked in sorted order (deadlock-free; two diffs racing with
        swapped arguments cannot deadlock). A self-diff takes one lock."""
        if a_pid == b_pid:
            entry = self._sessions.get(a_pid)
            entry.lock.acquire_read(timeout=self._lock_timeout())
            return entry, entry, entry.lock.release_read
        a_entry = self._sessions.get(a_pid)
        b_entry = self._sessions.get(b_pid)
        entries = sorted(
            (a_entry, b_entry), key=lambda e: e.pid
        )
        first, second = entries
        first.lock.acquire_read(timeout=self._lock_timeout())
        try:
            second.lock.acquire_read(timeout=self._lock_timeout())
        except BaseException:
            first.lock.release_read()
            raise

        def release() -> None:
            second.lock.release_read()
            first.lock.release_read()

        # Lock order is an implementation detail; diff direction follows the
        # caller's requested a/b order.
        return a_entry, b_entry, release

    def _write(self, entry: object, description: str, fn):
        """Run a write inside a transaction; requires a writable session and
        records the mutation so the decompile/store cache invalidates (plan
        §5.2). The per-program write lock excludes concurrent readers/writers
        (plan §5.1); the transaction is never opened without the lock."""
        if not bool((entry.open_flags or {}).get("writable")):
            raise ReadOnly(
                "this program was opened read-only",
                hint="re-open with open_program(writable=true) to annotate",
            )
        entry.lock.acquire_write(timeout=self._lock_timeout())
        try:
            from ghmcp.runtime.txn import txn

            with txn(entry.program, description):
                result = fn()
        finally:
            entry.lock.release_write()
        entry.bump_mod(self._mod(entry.program))
        return result

    # ------------------------------------------------------------------ env

    def env(self) -> EnvInfo:
        # Health/session environment calls can be the first adapter use when
        # warm_jvm is disabled, so they must trigger the same lazy bootstrap as
        # program operations.
        self._bootstrap()
        info = self._jvm.info()
        loaders, languages, active = self._cached_registry()
        env = EnvInfo(
            ghidra_version=info.get("version"),
            full_version=info.get("version"),
            java_heap=getattr(self._jvm.settings, "jvm_heap", ""),
            extension_dirs=[info["extension_dir"]] if info.get("extension_dir") else [],
            active_extensions=active,
            loaders=loaders,
            languages=languages,
        )
        self._fill_env_meta(env, active)
        return env

    def _cached_registry(self) -> tuple[list[str], list[str], list[str]]:
        """Loader/language/active probe — static for the JVM lifetime, but
        TTL-cached so hot env() calls (every open_program, health, session env)
        stay in the §5.1 per-call budget instead of paying a JVM probe
        round-trip each time."""
        now = time.monotonic()
        if self._registry_cache is not None and now - self._registry_cache[0] < self._REGISTRY_TTL:
            return self._registry_cache[1], self._registry_cache[2], self._registry_cache[3]
        loaders, languages, active = self._probe_registry()
        self._registry_cache = (now, loaders, languages, active)
        return loaders, languages, active

    def _fill_env_meta(self, env: EnvInfo, active: list[str]) -> None:
        """Preset satisfiability + installed list + drift warning (plan §6.5/§6.6).

        The installed probe and the extension-dir filesystem scan are cached
        for `_EXT_META_TTL` seconds — the state only changes when the user
        installs/uninstalls an extension, and a drift report must land at the
        next env call after that (restart required). Shared `enrich_env` keeps
        the fake and real adapters from disagreeing about preset status.
        """
        from ghmcp.extensions.verify import enrich_env

        installed, drift = self._cached_meta(active)
        env.installed_extensions = installed
        enrich_env(
            env,
            loaders=list(env.loaders),
            languages=list(env.languages),
            active_extensions=list(active),
            installed_extensions=list(installed),
        )
        env.drift_warning = drift

    def _cached_meta(self, active: list[str]) -> tuple[list[str], str | None]:
        now = time.monotonic()
        if self._meta_cache is not None and now - self._meta_cache[0] < self._EXT_META_TTL:
            return self._meta_cache[1], self._meta_cache[2]
        installed = self._probe_installed()
        drift = self._extension_drift(active)
        self._meta_cache = (now, installed, drift)
        return installed, drift

    def _probe_installed(self) -> list[str]:
        installed: list[str] = []
        try:
            from jpype import JClass

            eu = JClass("ghidra.util.extensions.ExtensionUtils")
            for details in eu.getInstalledExtensions() or []:
                try:
                    installed.append(
                        str(details.getName()) if hasattr(details, "getName") else str(details)
                    )
                except Exception:
                    installed.append(str(details))
        except Exception:
            pass
        return sorted(set(installed))

    def _extension_drift(self, active: list[str]) -> str | None:
        """Names on disk in the user extension dir that are not active in this
        JVM (a `ghmcp ext install` under a running server — restart required)."""
        info = self._jvm.info()
        ext_dir = info.get("extension_dir")
        if not ext_dir:
            return None
        active_lower = {a.lower() for a in active}
        on_disk: list[str] = []
        try:
            for child in Path(ext_dir).iterdir():
                if not child.is_dir():
                    continue
                names = sorted(
                    p.name for p in child.iterdir() if p.name.startswith("extension.properties")
                )
                if names:
                    on_disk.append(child.name)
        except OSError:
            return None
        stale = [
            name
            for name in on_disk
            if name.lower() not in active_lower and _dir_not_disabled(Path(ext_dir) / name)
        ]
        if not stale:
            return None
        return (
            f"extension dir has {', '.join(sorted(stale))} not active in this JVM — "
            "install/uninstall requires a server restart"
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

        self._pid += 1
        pid = f"p{self._pid}"
        if spec.analyze != "none":
            task_id = self._maybe_analyze(program, mode=spec.analyze, target=pid)
        else:
            task_id = None
        info = self._snapshot(program, pid, spec=spec, analysis_task_id=task_id)
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

    def _maybe_analyze(self, program: object, mode: str, target: str | None = None) -> str | None:
        """Start background analysis; returns the task id when one was started
        (plan §5.1: open_program(analyze="full") is the async surface the agent
        polls via analysis(action="status"))."""
        from ghmcp.runtime import tasks

        if mode == "none":
            return None
        if self._is_analyzed(program) and self._has_instructions(program):
            return None
        return tasks.start_task("analysis", lambda: _run_analysis(program), target=target)

    @staticmethod
    def _has_instructions(program: object) -> bool:
        try:
            return int(program.getListing().getNumInstructions()) > 0
        except Exception:
            return False

    def close(self, pid: str) -> None:
        self._bootstrap()
        from ghmcp.runtime import tasks

        tasks.wait_for_target(pid, timeout=10.0)
        # Write lock: no op may still be touching the program when the Java
        # consumer is released (otherwise use-after-release inside the JVM).
        self._locked(
            pid, True, lambda entry: self._sessions.close(entry.pid)
        )

    def shutdown(self) -> None:
        """Release native decompiler processes and the project-dir lock.

        Terminal: after this, `_bootstrap` raises instead of re-creating native
        state while teardown runs (a re-bootstrapped ProjectManager would
        self-lock on the still-open .ghmcp.lock fd). Analysis tasks are
        drained FIRST so no pyghidra thread touches a program that is being
        disposed (ClosedException / native access violations otherwise)."""
        if self._closed:
            return
        self._closed = True
        from ghmcp.runtime import tasks

        tasks.drain(timeout=30.0)
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

        def _do(entry: object) -> None:
            try:
                entry.program.getDomainFile().save(None)
            except Exception as exc:
                if "active transaction" in str(exc).lower():
                    raise GhmcpError(
                        "cannot save while analysis holds an open transaction",
                        hint="wait for analysis(status) to report done, then save again",
                    ) from exc
                raise
            entry.bump_mod(self._mod(entry.program))

        self._locked(pid, True, _do)

    def list_open(self) -> list[ProgramInfo]:
        self._bootstrap()
        infos = []

        def _snap(entry: object) -> ProgramInfo:
            return self._snapshot(
                entry.program,
                entry.pid,
                spec=None,
                writable=bool(entry.open_flags.get("writable")),
                entry=entry,
            )

        for pid in self._sessions.open_pids():
            infos.append(self._locked(pid, False, _snap))
        return infos

    def is_writable(self, pid: str) -> bool:
        """True when the session was opened writable; the snapshot's `writable`
        is not a reliable carry (list_open rebuilds it), so write gating must
        read the entry's open flags directly."""
        self._bootstrap()
        entry = self._sessions.get(pid)
        return bool(entry.open_flags.get("writable"))

    def modification_number(self, pid: str) -> int:
        self._bootstrap()
        return self._locked(pid, False, lambda entry: self._mod(entry.program))

    def select(self, pid: str) -> None:
        self._sessions.select(pid)

    def current(self) -> str | None:
        self._bootstrap()
        return self._sessions.current()

    # ------------------------------------------------------------------ read

    def decompile(self, pid: str, request: DecompileRequest) -> list[object]:
        """Batch decompile: per-function locks (no whole-batch lock, so a
        write can interleave between wave members); the lock is acquired
        before each pool lease inside decompile_program (session.py order)."""
        self._bootstrap()
        from ghmcp.ghidra.decomp import decompile_program

        entry = self._sessions.get(pid)
        return decompile_program(entry, request, self._decompool, self._lock_timeout())

    def instructions(self, pid: str, request: InstructionsRequest) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.listing import listing_program

        return self._locked(
            pid, False, lambda entry: listing_program(entry, request)
        )

    def read(self, pid: str, address: int, length: int) -> bytes:
        self._bootstrap()

        def _do(entry: object) -> bytes:
            if length <= 0:
                raise GhmcpError("length must be positive")
            from ghmcp.ghidra.game import read_bytes

            return read_bytes(entry.program, address, length, side="read")

        return self._locked(pid, False, _do)

    def read_typed(
        self, pid: str, address: int, length: int, type_name: str | None = None
    ) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.listing import typed_values

        return self._locked(
            pid, False, lambda entry: typed_values(entry.program, address, length, type_name)
        )

    # ------------------------------------------------------------------ xrefs/symbols (M4)

    def refs(self, pid: str, request: RefsRequest) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.refs import refs_page

        return self._locked(pid, False, lambda entry: refs_page(entry.program, request))

    def symbols(self, pid: str, request: SymbolQuery) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.symbols import symbols_page

        return self._locked(pid, False, lambda entry: symbols_page(entry.program, request))

    def strings(self, pid: str, request: StringQuery) -> tuple[list[object], bool]:
        self._bootstrap()
        from ghmcp.ghidra.strings import strings_page

        return self._locked(pid, False, lambda entry: strings_page(entry.program, request))

    def call_graph(self, pid: str, request: CallGraphRequest) -> CallGraphPage:
        self._bootstrap()
        from ghmcp.ghidra.callgraph import call_graph

        return self._locked(pid, False, lambda entry: call_graph(entry, request))

    # ------------------------------------------------------------------ search (M5)

    def find(self, pid: str, request: SearchQuery) -> list[object]:
        self._bootstrap()
        from ghmcp.ghidra.search import search_page

        return self._locked(pid, False, lambda entry: search_page(entry.program, request))

    # ------------------------------------------------------------------ scripts (M5)

    def run_script(
        self, pid: str | None, kind: str, code: str | None, path: str | None, args: list[str]
    ) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.script import run_script

        entry = self._sessions.get(pid) if pid else self._sessions.current_entry()
        if entry is None:
            raise GhmcpError("no program open for run_script", hint="open_program first")
        # Script bodies can ALWAYS mutate via the flat API (they may open
        # their own transactions), so every run_script runs under the
        # EXCLUSIVE lock — a shared read lock around a possible mutator would
        # race other readers. The session's writable flag only adds the
        # transaction wrapper inside script.py.
        project = self._project_mgr.project()
        return self._locked(
            entry.pid,
            True,
            lambda entry: run_script(entry, kind, code, path, args, project=project),
        )

    # ------------------------------------------------------------------ write (M6)

    def rename(self, pid: str, request: RenameRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import rename

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: rename", lambda: rename(entry, request))

    def set_prototype(self, pid: str, request: PrototypeRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import set_prototype

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: set_prototype", lambda: set_prototype(entry, request))

    def set_comment(self, pid: str, request: CommentRequest) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import set_comment

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: set_comment", lambda: set_comment(entry, request))

    def define_types(self, pid: str, c_decl: str) -> list[str]:
        self._bootstrap()
        from ghmcp.ghidra.annotate import define_types

        entry = self._sessions.get(pid)
        return self._write(entry, "ghmcp: define_types", lambda: define_types(entry, c_decl))

    def apply_type(self, pid: str, address: int, c_type: str, variable: str | None) -> None:
        self._bootstrap()
        from ghmcp.ghidra.annotate import apply_type

        entry = self._sessions.get(pid)
        self._write(
            entry,
            "ghmcp: apply_type",
            lambda: apply_type(entry, address, c_type, variable),
        )

    def list_types(self, pid: str) -> list[str]:
        self._bootstrap()
        from ghmcp.ghidra.annotate import list_types

        return self._locked(pid, False, lambda entry: list_types(entry))

    def get_type(self, pid: str, name: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.annotate import get_type

        return self._locked(pid, False, lambda entry: get_type(entry, name))

    # ------------------------------------------------------------------ game specials (M7)

    def memory_map(self, pid: str) -> list[dict]:
        self._bootstrap()
        from ghmcp.ghidra.game import memory_map

        return self._locked(pid, False, lambda entry: memory_map(entry))

    def create_block(self, pid: str, name: str, address: int, size: int, flags: str) -> None:
        self._bootstrap()
        from ghmcp.ghidra.game import create_block

        entry = self._sessions.get(pid)
        self._write(
            entry, "ghmcp: create_block", lambda: create_block(entry, name, address, size, flags)
        )

    def rebase(self, pid: str, new_base: int) -> None:
        self._bootstrap()
        from ghmcp.ghidra.game import rebase

        entry = self._sessions.get(pid)
        self._write(entry, "ghmcp: rebase", lambda: rebase(entry, new_base))

    def diff_functions(self, a_pid: str, b_pid: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import diff_functions

        a, b, release = self._diff_pair(a_pid, b_pid)
        try:
            return diff_functions(a, b)
        finally:
            release()

    def diff_bytes(self, a_pid: str, b_pid: str, start: int, end: int) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import diff_bytes

        a, b, release = self._diff_pair(a_pid, b_pid)
        try:
            return diff_bytes(a.program, b.program, start, end, a.pid, b.pid)
        finally:
            release()

    def analysis_state(self, pid: str) -> str:
        self._bootstrap()
        from ghmcp.ghidra.game import analysis_state

        return self._locked(pid, False, lambda entry: analysis_state(entry))

    def run_analysis(self, pid: str, options: dict) -> None:
        """Synchronous analysis: deliberately NOT under the program lock —
        analysis is incremental under Ghidra's own locks and stalls readers
        for minutes otherwise (see session.py: analysis/exclusion note)."""
        self._bootstrap()
        from ghmcp.ghidra.game import run_analysis

        entry = self._sessions.get(pid)
        run_analysis(entry, options)
        entry.bump_mod(self._mod(entry.program))

    def analysis_options(self, pid: str) -> dict:
        self._bootstrap()
        from ghmcp.ghidra.game import analysis_options

        return self._locked(pid, False, lambda entry: analysis_options(entry))

    # ------------------------------------------------------------------ tasks (M7)

    def analyze_async(self, pid: str, options: dict | None) -> str:
        self._bootstrap()
        from ghmcp.runtime import tasks

        entry = self._sessions.get(pid)

        def job():
            from ghmcp.ghidra.game import run_analysis

            run_analysis(entry, options)

        return tasks.start_task("analysis", job, target=pid)

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

    def _snapshot(
        self,
        program: object,
        pid: str,
        spec: OpenSpec | None = None,
        writable: bool | None = None,
        analysis_task_id: str | None = None,
        entry: object | None = None,
    ) -> ProgramInfo:
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
        mod = self._mod(program)
        entry_cache = getattr(entry, "snap_cache", None)
        if entry is not None and entry_cache is not None and entry_cache.get("mod") == mod:
            entry_points = list(entry_cache["entry_points"])
        if not entry_points:
            try:
                st = program.getSymbolTable()
                ext = (
                    st.getExternalEntryPoints() if hasattr(st, "getExternalEntryPoints") else None
                )
                if ext:
                    for s in ext:
                        try:
                            entry_points.append(int(s.getAddress().getOffset()))
                        except Exception:
                            continue
            except Exception:
                pass
        counts = self._counts(program)
        # Fallback costs one full symbol-table pass: skip when analysis has not
        # produced functions (fresh import) and cache on the entry by mod so
        # list_open() never repeats it.
        if not entry_points and counts["function_count"]:
            self._entry_points_fallback(program, entry_points)
        if entry is not None:
            entry.snap_cache = {"mod": mod, "entry_points": list(entry_points)}
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
            analysis_task_id=analysis_task_id,
            writable=bool(writable if writable is not None else spec and spec.writable),
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


def _dir_not_disabled(path: Path) -> bool:
    """True when an extension dir is enabled (no .uninstalled disable marker)."""
    return not (path / "extension.properties.uninstalled").exists()
