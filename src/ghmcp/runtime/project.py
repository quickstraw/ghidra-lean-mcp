"""Persistent Ghidra project + import-or-reuse of program DBs (plan §5.4).

One project lives under settings.projects_dir per workspace. Program key =
sha256(file) + loader + language + compiler + base; the program file name IS
the key, so a cache hit is a `consume_program(project, "/<key>")` and a miss
is AutoImporter.importByUsingSpecificLoaderClassAndLcs.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ghmcp.platform.errors import GhmcpError
from ghmcp.platform.telemetry import log_event

PROJECT_NAME = "ghmcp"
_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class LoadSpec:
    """Fully resolved open request: what import needs."""

    loader_name: str | None  # display name, e.g. "PSP Executable (ELF)"
    language: str | None  # "Allegrex:LE:32:default"
    compiler: str | None  # "default"
    loader_args: dict[str, str] = None  # type: ignore[assignment]
    image_base: int | None = None


def program_key(path: Path, spec: LoadSpec) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    loader = spec.loader_name or "auto"
    lang = spec.language or "auto"
    compiler = spec.compiler or "auto"
    base = f"{spec.image_base:x}" if spec.image_base is not None else "auto"
    raw = f"{digest.hexdigest()[:12]}-{loader}-{lang}-{compiler}-{base}".replace(":", "-")
    return re.sub(r"-+", "-", raw.strip("-"))[:80]


def _pairs(args: dict[str, str]):
    """generic.stl.Pair list for loader args (ProgramLoader.addLoaderArg pairs)."""
    from jpype import JClass

    Pair = JClass("generic.stl.Pair")
    ArrayList = JClass("java.util.ArrayList")
    lst = ArrayList()
    for k, v in args.items():
        lst.add(Pair(k, str(v)))
    return lst


class ProjectManager:
    """Owns the persistent project and program import/consume transitions.

    Cross-process safety: the Ghidra project lives under a machine-global dir
    (settings.projects_dir), so a file lock guards open/create — two server
    processes must never open the same Ghidra project DB concurrently.
    """

    def __init__(self, projects_dir: Path):
        self._projects_dir = projects_dir
        self._project = None
        self._lock_fd: int | None = None
        self._lock_path: Path | None = None

    def _open_project(self) -> object:
        if self._project is not None:
            return self._project
        self._acquire_dir_lock()
        import pyghidra

        self._projects_dir.mkdir(parents=True, exist_ok=True)
        self._project = pyghidra.open_project(str(self._projects_dir), PROJECT_NAME, create=True)
        log_event("project_opened", dir=str(self._projects_dir), name=PROJECT_NAME)
        return self._project

    def _acquire_dir_lock(self) -> None:
        """Non-blocking exclusive lock on <projects_dir>/.ghmcp.lock for this
        process; raises GhmcpError when another server holds it. Idempotent:
        a failed project-open retry must not re-lock the same fd against
        itself (flock/msvcrt locks are per open-file-description). The fd is
        released in close() (shutdown); stale locks on network shares are
        detectable because the owner pid is recorded in the lock file."""
        import os
        import stat

        if self._lock_fd is not None:
            return
        self._projects_dir.mkdir(parents=True, exist_ok=True)
        self._lock_path = self._projects_dir / ".ghmcp.lock"
        # Refuse pre-planted symlinks/reparse points (Windows O_NOFOLLOW is a
        # no-op): a junction at the lock path would redirect the OS lock and
        # the pid write into an attacker-chosen file.
        try:
            lst = os.lstat(self._lock_path)
            if stat.S_ISLNK(lst.st_mode) or (
                getattr(lst, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise GhmcpError(
                    "the project lock path is a link/reparse point",
                    hint=f"remove or replace {self._lock_path} with a regular file",
                )
        except FileNotFoundError:
            pass
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self._lock_path, flags)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise GhmcpError(
                    "the project lock path is not a regular file",
                    hint=f"refusing to lock a non-regular file at {self._lock_path}",
                )
            os.ftruncate(fd, 0)
            os.write(fd, str(os.getpid()).encode())
        except GhmcpError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise GhmcpError(
                "the Ghidra project dir is in use by another ghmcp instance",
                hint=f"close the other server (it holds {self._lock_path}), or point projects_dir elsewhere",
            ) from exc
        self._lock_fd = fd

    def close(self) -> None:
        """Release the dir lock and drop the project handle (shutdown path)."""
        import os

        if self._lock_fd is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    with contextlib.suppress(OSError):
                        msvcrt.locking(self._lock_fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    with contextlib.suppress(OSError):
                        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None
        self._project = None

    def project(self) -> object:
        """Return the live Ghidra project for APIs that need project context."""
        return self._open_project()

    def list_programs(self) -> list[str]:
        import pyghidra

        found: list[str] = []

        def collect(domain_file: object) -> None:
            with contextlib.suppress(Exception):
                found.append(str(domain_file.getPathname()))

        pyghidra.walk_project(self._open_project(), collect)
        return found

    def import_program(self, path: Path, spec: LoadSpec) -> str:
        """Import (or reuse) and return the project path string; caller consumes.

        AutoImporter saves into a folder named after the key, with the original
        file name inside: /<key>/<file-name>.
        """
        project = self._open_project()
        key = program_key(path, spec)
        project_path = f"/{key}/{path.name}"
        if project_path in self.list_programs():
            log_event("program_reused", path=str(path), key=key)
            return project_path

        message_log = self._new_message_log()
        monitor = self._new_monitor()
        from jpype import JClass

        AutoImporter = JClass("ghidra.app.util.importer.AutoImporter")
        JFile = JClass("java.io.File")

        loader_class = None
        if spec.loader_name:
            loader_class = self._resolve_loader_class(spec.loader_name, path)
        language = self._resolve_language(spec.language) if spec.language else None
        compiler = self._resolve_compiler(language, spec.compiler) if language is not None else None

        log_event(
            "program_import",
            path=str(path),
            loader=spec.loader_name or "auto",
            language=spec.language or "auto",
            compiler=spec.compiler or "auto",
        )
        try:
            results = self._auto_import(
                AutoImporter,
                JFile(str(path)),
                project,
                key,
                loader_class,
                language,
                compiler,
                spec.loader_args or {},
                message_log,
                monitor,
            )
            results.save(monitor)  # persist to the project; load happens in-memory otherwise
            results.release(None)
            results.close()
        except Exception as exc:
            note = str(message_log)
            raise GhmcpError(
                f"import of {path.name} failed: {exc}",
                hint=f"{note[:400]}\nrun 'ghmcp ext verify' to check that the required loader/language is present",
            ) from exc

        log_event("program_imported", path=str(path), key=key)
        return project_path

    @staticmethod
    def _auto_import(
        AutoImporter: object,
        file: object,
        project: object,
        name: str,
        loader_class: object | None,
        language: object | None,
        compiler: object | None,
        loader_args: dict[str, str],
        message_log: object,
        monitor: object,
    ) -> object:
        from java.lang import Object  # type: ignore[import-not-found]

        consumer = Object()
        if loader_class is not None and language is not None and compiler is not None:
            return AutoImporter.importByUsingSpecificLoaderClassAndLcs(
                file,
                project,
                name,
                loader_class,
                _pairs(loader_args),
                language,
                compiler,
                consumer,
                message_log,
                monitor,
            )
        if loader_class is not None:
            return AutoImporter.importByUsingSpecificLoaderClass(
                file,
                project,
                name,
                loader_class,
                _pairs(loader_args),
                consumer,
                message_log,
                monitor,
            )
        return AutoImporter.importByUsingBestGuess(
            file, project, name, consumer, message_log, monitor
        )

    def consume(self, project_path: str, writable: bool = False):
        """(Program, consumer) for a project path; caller owns release.

        pyghidra's consume_program always opens read-only; writable sessions
        go directly through DomainFile.getDomainObject(consumer, readOnly, …).
        """
        project = self._open_project()
        if not writable:
            import pyghidra

            return pyghidra.consume_program(project, project_path)
        from jpype import JClass

        df = project.getProjectData().getFile(project_path)
        if df is None:
            raise GhmcpError(
                f"project file {project_path} not found", hint="re-open the file to re-import"
            )
        consumer = JClass("java.lang.Object")()
        domain_obj = df.getDomainObject(consumer, False, True, self._new_monitor())
        return domain_obj, consumer

    # ------------------------------------------------------------------ helpers

    def _resolve_loader_class(self, display_name: str, path: Path):
        """Display-name → Loader Class via LoaderMap(allSupportedLoadSpecs(provider)).
        Falls back to LoaderService.getLoaderClassByName for short class names and
        reports the candidates that *could* read this file when nothing matches
        (plan §6.5 diagnostic)."""
        from jpype import JClass

        LoaderService = JClass("ghidra.app.util.opinion.LoaderService")
        provider = self._byte_provider(path)
        supported_names: list[str] = []
        try:
            loader_map = LoaderService.getAllSupportedLoadSpecs(provider)
            for loader in loader_map.keySet() or []:
                try:
                    name = str(loader.getName())
                except Exception:
                    continue
                supported_names.append(name)
                if name == display_name:
                    return loader.getClass()
        except BaseException:
            pass  # provider-level hiccup → try the short-name path

        attempt = LoaderService.getLoaderClassByName(display_name)
        if attempt is not None:
            return attempt
        preview = ", ".join(supported_names[:8])
        raise GhmcpError(
            f"loader {display_name!r} is not available for this file",
            hint=f"loaders that can read it: [{preview}{', ...' if len(supported_names) > 8 else ''}] — "
            "the providing extension may be missing or inactive; run 'ghmcp ext verify'",
        )

    @staticmethod
    def _byte_provider(path: Path):
        from jpype import JClass

        ByteArrayProvider = JClass("ghidra.app.util.bin.ByteArrayProvider")
        data = path.read_bytes()
        return ByteArrayProvider(data, path.name)

    @staticmethod
    def _resolve_language(language_id: str):
        from jpype import JClass

        lang_service = JClass("ghidra.program.util.DefaultLanguageService").getLanguageService()
        lang = lang_service.getLanguage(JClass("ghidra.program.model.lang.LanguageID")(language_id))
        if lang is None:
            raise GhmcpError(
                f"language {language_id!r} is not registered",
                hint="run 'ghmcp ext verify' — the processor module may be missing",
            )
        return lang

    @staticmethod
    def _resolve_compiler(language: object, name: str | None):
        """Resolve a compiler spec name ('default' works everywhere; otherwise a
        compatible spec id). Tolerant to per-thread API hiccups: each fallback
        path is wrapped separately."""
        if name is None:
            return language.getDefaultCompilerSpec()
        from jpype import JClass

        for _attempt in range(2):
            try:
                for desc in language.getCompatibleCompilerSpecDescriptions() or []:
                    try:
                        if str(desc.getCompilerSpecID()) == name:
                            return language.getCompilerSpecByID(
                                JClass("ghidra.program.model.lang.CompilerSpecID")(name)
                            )
                    except Exception:
                        continue
                if name == "default":
                    return language.getDefaultCompilerSpec()
                break
            except Exception:
                continue
        raise GhmcpError(
            f"compiler spec {name!r} is not available for {language.getLanguageID()}",
            hint="omit compiler to use the language default",
        )

    @staticmethod
    def _new_monitor():
        from jpype import JClass

        return JClass("ghidra.util.task.ConsoleTaskMonitor")()

    @staticmethod
    def _new_message_log():
        from jpype import JClass

        return JClass("ghidra.app.util.importer.MessageLog")()
