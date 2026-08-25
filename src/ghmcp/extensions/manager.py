"""Extension install pipeline (plan §6.3).

Order of artifact resolution:
  1. local path passed by the user
  2. cached zip under <cache>/ext/<id>/<ghidra_version>/
  3. GitHub release asset matching asset_regex (only with allow_download)
  4. build from source (only with allow_build, builder.py)

Install: JVM-authoritative path (ExtensionUtils) by default; --no-jvm falls
back to plain unzip into the user extension dir, documented best-effort.
Version gate: extension `version` must match the running Ghidra release
(minor) per community convention; --force-version-override rewrites it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import tomllib
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ghmcp.extensions.catalog import ExtRecord, get_extension, presets_for_extension
from ghmcp.platform.config import Settings
from ghmcp.platform.errors import ExtensionError
from ghmcp.platform.telemetry import log_event

MARKER_NAME = ".ghmcp-install.json"
LOCK_NAME = "extensions.lock"


@dataclass
class InstallResult:
    ext_id: str
    state: str  # installed | already_installed | disabled | failed
    detail: str = ""
    path: Path | None = None
    sha256: str = ""


@dataclass
class LockState:
    entries: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> LockState:
        if not path.exists():
            return cls()
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
            return cls(entries={k: dict(v) for k, v in data.get("extension", {}).items()})
        except Exception:
            return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        def fmt(value: object) -> str:
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, (int, float)):
                return str(value)
            # json.dumps → TOML basic string: backslashes and quotes are escaped
            # correctly (repr() would double them inside a literal string).
            return json.dumps(str(value))

        blocks = ["# ghmcp extension lock — machine reproducibility. Do not edit by hand."]
        for key, item in sorted(self.entries.items()):
            blocks.append(f"[extension.{key}]")
            for k, v in item.items():
                blocks.append(f"{re.sub(r'[^a-zA-Z0-9_]', '_', str(k))} = {fmt(v)}")
        path.write_text("\n".join(blocks) + "\n", encoding="utf-8")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_version(text: str) -> tuple[int, ...]:
    """'12.1.2' / '12.1.2-PUBLIC' → (12,1,2). '11.0.4' → (11,0,4)."""
    out: list[int] = []
    for part in text.split("-")[0].split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits:
            out.append(int(digits))
    return tuple(out)


def versions_compatible(ext_version: str, ghidra_version: str) -> bool:
    if not ext_version or not ghidra_version:
        return True  # unknown on either side: refuse to block
    ev, gv = parse_version(ext_version), parse_version(ghidra_version)
    return ev[:2] == gv[:2]  # major.minor must match (community convention)


class ExtensionManager:
    def __init__(
        self,
        settings: Settings,
        *,
        allow_download: bool = False,
        allow_build: bool = False,
        force_version_override: bool = False,
        no_jvm: bool = False,
        ghidra_version: str | None = None,
    ):
        self._settings = settings
        self.allow_download = allow_download
        self.allow_build = allow_build
        self.force_version_override = force_version_override
        self.no_jvm = no_jvm
        self.ghidra_version = ghidra_version  # post-JVM-start; None → no gate
        self.ext_cache = settings.ext_dir
        self.lock_path = settings.ext_dir / LOCK_NAME
        self._lock = LockState.load(self.lock_path)
        self.user_ext_dir: Path | None = None
        self._jvm = None

    def attach_jvm(self, jvm) -> None:
        """Bind a started JvmManager: unlocks the authoritative extension dir + version gate."""
        self._jvm = jvm
        info = jvm.info()
        self.set_ghidra_version(info.get("version") or "")
        if info.get("extension_dir"):
            self.set_user_ext_dir(Path(info["extension_dir"]))

    def shutdown(self) -> None:
        if self._jvm is not None:
            try:
                self._jvm.shutdown()
            finally:
                self._jvm = None

    # ------------------------------------------------------------------ paths

    def _cache_dir_for(self, ext_id: str) -> Path:
        return self.ext_cache / ext_id

    def _staged_dir(self, ext_id: str) -> Path:
        return self.ext_cache / "stage" / ext_id

    def set_ghidra_version(self, version: str) -> None:
        self.ghidra_version = version

    # ------------------------------------------------------------------ artifacts

    def resolve_artifact(self, record: ExtRecord, *, local_path: Path | None = None) -> Path:
        ghidra_ver_path = self._cache_dir_for(record.id) / (self.ghidra_version or "any")
        candidates: list[tuple[str, Path | None]] = []

        if local_path is not None:
            candidates.append(("local", local_path))
        cached = sorted(ghidra_ver_path.glob("*.zip"))
        candidates.append(("cache", cached[0] if cached else None))

        if self.allow_download and record.repo:
            url = self._find_release_asset(record)
            if url is not None:
                downloaded = self._download(record, url, ghidra_ver_path)
                candidates.append(("download", downloaded))

        if self.allow_build and record.build_tool:
            from ghmcp.extensions.builder import build_from_source

            built = build_from_source(record, self._settings, self.ghidra_version)
            candidates.append(("build", built))

        for source, candidate in candidates:
            if candidate is not None and candidate.exists():
                if not zipfile.is_zipfile(candidate):
                    if source == "local":
                        raise ExtensionError(
                            f"{candidate} is not a zip", hint="point --local at the extension zip"
                        )
                    continue
                log_event("ext_artifact", ext=record.id, source=source, path=str(candidate))
                return candidate
        raise ExtensionError(
            f"no artifact for {record.id!r}",
            hint=(
                "run with --allow-download (fetch the GitHub release), --allow-build (gradle), "
                "or pass --local <path/to/zip>"
            ),
        )

    def _find_release_asset(self, record: ExtRecord) -> str | None:
        if not record.asset_regex:
            return None
        api = f"https://api.github.com/repos/{record.repo}/releases/latest"
        req = urllib.request.Request(
            api, headers={"User-Agent": "ghmcp", "Accept": "application/vnd.github+json"}
        )
        try:
            with urllib.request.urlopen(
                req, timeout=30, context=ssl.create_default_context()
            ) as resp:
                release = json.load(resp)
        except urllib.error.URLError as exc:
            raise ExtensionError(
                f"GitHub lookup failed for {record.repo}: {exc}", hint="retry with --offline=false"
            ) from exc
        assets = release.get("assets", []) if isinstance(release, dict) else []
        candidates = []
        for asset in assets:
            name = str(asset.get("name", ""))
            if record.matches_asset(name):
                candidates.append(
                    (self._asset_score(name), name, asset.get("browser_download_url", ""))
                )
        if not candidates:
            raise ExtensionError(
                f"no asset of {record.repo} matches {record.asset_regex!r}",
                hint="pass --local with the zip, or enable --allow-build to compile the extension",
            )
        candidates.sort(key=lambda item: (-item[0], item[1]))
        best = candidates[0][2]
        log_event(
            "ext_asset_found",
            ext=record.id,
            name=candidates[0][1],
            score=candidates[0][0],
            url=best,
        )
        return best or None

    def _asset_score(self, name: str) -> int:
        """Prefer the asset built for the running Ghidra (12.1.2 → the 12.1 asset
        beats 12.0.x: exact triple wins, then minor, then major, then unknown)."""
        if not self.ghidra_version:
            return 0
        m = re.search(r"(?:ghidra|Ghidra)[_.]?(?:PUBLIC[_.]?)?(\d+\.\d+(?:\.\d+)?)", name)
        if not m:
            m = re.search(r"Ghidra_(\d+\.\d+)", name)
        if not m:
            return 0
        asset_ver = parse_version(m.group(1))
        target_ver = parse_version(self.ghidra_version)
        if asset_ver[:2] == target_ver[:2]:
            return 3 if asset_ver[:3] == target_ver[:3] else 2
        if asset_ver[:1] == target_ver[:1]:
            return 1
        return 0

    def _download(self, record: ExtRecord, url: str, dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / f"{url.split('/')[-1]}"
        req = urllib.request.Request(url, headers={"User-Agent": "ghmcp"})
        with (
            urllib.request.urlopen(req, timeout=120, context=ssl.create_default_context()) as resp,
            target.open("wb") as out,
        ):
            shutil.copyfileobj(resp, out, length=1 << 20)
        log_event("ext_downloaded", ext=record.id, path=str(target), bytes=target.stat().st_size)
        return target

    # ------------------------------------------------------------------ install

    def install_zip(self, record: ExtRecord, zip_path: Path) -> InstallResult:
        """Stage + version-gate + install the zip into the user extension dir.

        Crash safety: an "installing" journal is written (atomically) before
        any filesystem side effect and removed after the marker; a re-run with
        a journal but no marker treats the leftover dir as ghmcp residue and
        repairs, instead of refusing (no manual cleanup required).
        """
        marker_path = self._ext_marker(record.id)
        journal = self._ext_journal(record.id)
        if marker_path.exists():
            journal.unlink(missing_ok=True)
            return InstallResult(record.id, "already_installed", detail=str(marker_path))
        self._check_archive_limits(zip_path)
        sha = sha256_of(zip_path)

        stage = self._staged_dir(record.id)
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(stage)

        ext_props = self._find_extension_properties(stage)
        properties = self._read_properties(ext_props) if ext_props else {}
        ext_version = properties.get("version", "")
        overridden = False
        if (
            ext_version
            and self.ghidra_version
            and not versions_compatible(ext_version, self.ghidra_version)
        ):
            if not self.force_version_override:
                raise ExtensionError(
                    f"extension {record.id!r} v{ext_version} targets a different Ghidra than "
                    f"{self.ghidra_version}",
                    hint=f"install a release built for Ghidra {self.ghidra_version} or rerun with --force-version-override",
                )
            properties["version"] = self.ghidra_version
            self._write_properties(ext_props, properties)
            overridden = True
            log_event(
                "ext_version_overridden", ext=record.id, from_=ext_version, to=self.ghidra_version
            )

        target = self._install_dir()
        # Foreign-dir check runs BEFORE the journal exists: a dir present with
        # neither marker nor journal is not ours — refuse. A dir with a
        # leftover journal is crash residue and is repaired below (both paths).
        self._check_dest_conflict(target, record, stage)
        if not self.no_jvm:
            # JVM path: ExtensionUtils extracts into the user dir itself, so
            # journal-marked residue must be cleaned here (it never goes
            # through _unzip_into).
            self._clean_jvm_residue(target, stage, record)
        self._write_journal(journal, record, target)
        try:
            if self.no_jvm:
                self._unzip_into(stage, target, record)
                install_path = zip_path
            else:
                # ExtensionUtils reads the version from the archive, so the override
                # must land in a repacked zip — otherwise it silently does nothing.
                install_path = (
                    self._repack_with_override(record, stage, zip_path) if overridden else zip_path
                )
                self._install_via_ghidra(record, stage, install_path)

            sha = sha256_of(install_path)
            marker = {
                "id": record.id,
                "source": str(install_path),
                "sha256": sha,
                "ghidra_version": self.ghidra_version or ext_version,
                "target": str(target),
                # The dir name Ghidra actually installs. For a zip-root layout
                # (extension.properties at the archive root) the no-JVM path
                # installs into target/<ext_id> (the staged root) and the JVM
                # path names it after the extension's declared name — record
                # both candidates so uninstall can never orphan the install.
                "module_dir": self._installed_module_dir(stage, ext_props, properties, record),
            }
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text(json.dumps(marker, indent=2), encoding="utf-8")
            journal.unlink(missing_ok=True)
        except BaseException:
            # Keep the journal: it marks any half-landed dir as ghmcp residue
            # so a re-run repairs instead of refusing.
            raise
        self._lock.entries[record.id] = {
            "sha256": sha,
            "version": self.ghidra_version or ext_version,
            "source": str(install_path),
            "installed": True,
        }
        self._lock.save(self.lock_path)
        log_event("ext_installed", ext=record.id, sha256=sha, target=str(target))
        return InstallResult(
            record.id,
            "installed",
            detail=f"installed {record.id} v{self.ghidra_version or ext_version}",
            path=target,
            sha256=sha,
        )

    # ------------------------------------------------------------------ safety

    MAX_MEMBER_BYTES = 512 * 1024 * 1024
    MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

    def _check_archive_limits(self, zip_path: Path) -> None:
        """Reject archives that would decompress to unbounded sizes (zip bombs)
        or carry unsafe member names/attributes onto the JVM extract path:
        caps and name checks apply before extractall and before any member read."""
        total = 0
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                size = info.file_size
                if size > self.MAX_MEMBER_BYTES:
                    raise ExtensionError(
                        f"archive member {info.filename!r} decompresses to "
                        f"{size} bytes (cap {self.MAX_MEMBER_BYTES})",
                        hint="this does not look like a normal Ghidra extension zip",
                    )
                total += size
                if total > self.MAX_TOTAL_BYTES:
                    raise ExtensionError(
                        f"archive decompresses to over {self.MAX_TOTAL_BYTES} bytes total",
                        hint="this does not look like a normal Ghidra extension zip",
                    )
                name = info.filename.replace("\\", "/")
                if (
                    name.startswith("/")
                    or name.startswith("//")
                    or re.match(r"^[A-Za-z]:", name)
                    or ".." in name.split("/")
                ):
                    raise ExtensionError(
                        f"unsafe member name {info.filename!r}",
                        hint="this does not look like a normal Ghidra extension zip",
                    )

    def _module_candidates(self, stage: Path, props: Path | None, record: ExtRecord) -> set[str]:
        """Every plausible installed-dir name for this zip: the registry module
        name, the zip's module root (dir containing extension.properties), and
        the extension's declared name — the three can legitimately differ."""
        names = {record.module_name}
        if props is not None:
            if props.parent != stage:
                names.add(props.parent.name)
            else:
                # zip-root layout: no-JVM installs as target/<ext_id>, the JVM
                # path names the dir from the declared properties name.
                names.add(record.id)
                declared = self._read_properties(props).get("name")
                if declared:
                    names.add(declared)
        return {n for n in names if n}

    def _installed_module_dir(
        self, stage: Path, props: Path | None, properties: dict, record: ExtRecord
    ) -> str:
        """Marker module_dir: prefer the zip module root (no-JVM path), else
        the declared properties name (JVM path), else the registry name."""
        if props is not None and props.parent != stage:
            return props.parent.name
        declared = properties.get("name") or ""
        return declared or record.module_name or record.id

    def installed_module_dir(self, ext_id: str) -> str | None:
        """The module_dir recorded at install time (None when not installed)."""
        marker_path = self._ext_marker(ext_id)
        if not marker_path.exists():
            return None
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            return marker.get("module_dir") or None
        except Exception:
            return None

    def _clean_jvm_residue(self, target: Path, stage: Path, record: ExtRecord) -> None:
        """Repair before the JVM install: if a previous run left a journal, the
        target module dir is ghmcp residue (crash mid-extension-utils-install)
        and must be removed or ExtensionUtils will install into a half state."""
        if not self._ext_journal(record.id).exists():
            return
        props = self._find_extension_properties(stage)
        for name in self._module_candidates(stage, props, record):
            dest = target / name
            if dest.exists():
                shutil.rmtree(dest)

    def _check_dest_conflict(self, target: Path, record: ExtRecord, stage: Path) -> None:
        """Refuse to touch an extension dir that is not ours (no marker) and
        has no crash journal. Runs before the journal is written; checks every
        plausible installed-dir name (registry name, zip module root, declared
        name — they can differ in test/derived zips)."""
        props = self._find_extension_properties(stage)
        for name in self._module_candidates(stage, props, record):
            dest = target / name
            if (
                dest.exists()
                and not self._ext_marker(record.id).exists()
                and not self._ext_journal(record.id).exists()
            ):
                raise ExtensionError(
                    f"{dest} already exists and is not ghmcp-managed",
                    hint=f"move it aside or remove it first, then rerun the install ({dest})",
                )

    def _write_journal(self, journal: Path, record: ExtRecord, target: Path) -> None:
        journal.parent.mkdir(parents=True, exist_ok=True)
        tmp = journal.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"id": record.id, "target": str(target)}, indent=2), encoding="utf-8"
        )
        os.replace(tmp, journal)  # atomic: a torn journal can never exist

    def _ext_journal(self, ext_id: str) -> Path:
        return self.ext_cache / "installed" / f"{ext_id}.installing"

    def _repack_with_override(self, record: ExtRecord, stage: Path, zip_path: Path) -> Path:
        """Rewrite extension.properties inside a copy of the archive so the
        forced version lives in the artifact ExtensionUtils actually installs.

        Member names were validated by _check_archive_limits; attributes are
        rebuilt (regular file/dir modes only) so symlink/device bits from the
        source archive can never reach the JVM extract."""
        self._check_archive_limits(zip_path)
        patched_dir = self.ext_cache / "patched"
        patched_dir.mkdir(parents=True, exist_ok=True)
        target = patched_dir / f"{record.id}.zip"

        with (
            zipfile.ZipFile(zip_path) as src,
            zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out,
        ):
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename.endswith("extension.properties"):
                    staged = self._find_extension_properties(stage)
                    data = staged.read_bytes() if staged else data
                clean = zipfile.ZipInfo(info.filename, info.date_time)
                clean.compress_type = info.compress_type
                clean.external_attr = 0o644 << 16  # regular file, no symlink/device bits
                out.writestr(clean, data)
        return target

    def uninstall(self, ext_id: str) -> InstallResult:
        record = get_extension(ext_id)
        marker_path = self._ext_marker(ext_id)
        if not marker_path.exists():
            raise ExtensionError(
                f"{ext_id!r} is not installed (no marker)",
                hint="run 'ghmcp ext install <id>' first",
            )
        # The marker holds the dir name the zip actually created (its module
        # root); fall back to the registry name for pre-existing markers.
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            module_dir = marker.get("module_dir") or record.module_name
        except Exception:
            module_dir = record.module_name
        target = self._install_dir()
        ghidra_dir = target / module_dir
        if ghidra_dir.exists():
            props = ghidra_dir / "extension.properties"
            uninstalled = ghidra_dir / "extension.properties.uninstalled"
            if props.exists() and not self.no_jvm:
                # Ghidra's own disable convention: rename the properties file
                # (PROPERTIES_FILE_NAME_UNINSTALLED) — keeps the install, deactivates it.
                props.rename(uninstalled)
                state = "disabled"
            elif uninstalled.exists() and not self.no_jvm:
                state = "disabled"
            else:
                shutil.rmtree(ghidra_dir, ignore_errors=True)
                state = "removed"
        else:
            state = "removed"
        marker_path.unlink(missing_ok=True)
        self._lock.entries.pop(ext_id, None)
        self._lock.save(self.lock_path)
        log_event("ext_uninstalled", ext=ext_id, state=state)
        return InstallResult(
            ext_id, state, detail=f"{ext_id} {state} — restart the server to pick it up"
        )

    # ------------------------------------------------------------------ status

    def status(self, ext_id: str) -> dict:
        record = get_extension(ext_id)
        marker_path = self._ext_marker(ext_id)
        return {
            "id": ext_id,
            "title": record.title,
            "repo": record.repo,
            "marker": marker_path.exists(),
            "lock": self._lock.entries.get(ext_id),
            "presets": presets_for_extension(ext_id),
            "validate": record.validate,
        }

    # ------------------------------------------------------------------ internals

    def _ext_marker(self, ext_id: str) -> Path:
        return self.ext_cache / "installed" / f"{ext_id}-{MARKER_NAME}"

    def _install_dir(self) -> Path:
        if self.user_ext_dir is not None:
            return self.user_ext_dir  # explicit: launcher path (JVM mode) or test/override target
        if self.no_jvm:
            derived = Path.home() / ".ghmcp-extensions"
            log_event("ext_dir_fallback", dir=str(derived), mode="best-effort")
            return derived
        raise ExtensionError(
            "JVM mode used without a Ghidra user extension dir",
            hint="start via a JVM-aware flow so the launcher reports paths, or use --no-jvm",
        )

    def set_user_ext_dir(self, path: Path) -> None:
        self.user_ext_dir = path

    @staticmethod
    def _find_extension_properties(stage: Path) -> Path | None:
        # Extension zips contain extension.properties at their module root.
        direct = stage / "extension.properties"
        if direct.exists():
            return direct
        for child in stage.rglob("extension.properties"):
            return child
        return None

    @staticmethod
    def _read_properties(path: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in path.read_text(encoding="utf8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
        return out

    @staticmethod
    def _write_properties(path: Path, props: dict[str, str]) -> None:
        path.write_text("\n".join(f"{k} = {v}" for k, v in props.items()) + "\n", encoding="utf8")

    def _unzip_into(self, stage: Path, target: Path, record: ExtRecord) -> None:
        target.mkdir(parents=True, exist_ok=True)
        props = self._find_extension_properties(stage)
        if props is None:
            raise ExtensionError("zip has no extension.properties — is this a Ghidra extension?")
        module_root = props.parent
        module_name = module_root.name
        dest = target / module_name
        if dest.exists():
            marker_present = self._ext_marker(record.id).exists()
            journal_present = self._ext_journal(record.id).exists()
            if not marker_present and not journal_present:
                # Never clobber a dir we don't own: it may be an extension the
                # user installed through the Ghidra GUI (no ghmcp marker).
                raise ExtensionError(
                    f"{dest} already exists and is not ghmcp-managed",
                    hint=f"move it aside or remove it first, then rerun the install ({dest})",
                )
            # marker or journal present → ghmcp-owned (possibly crash residue):
            # replacing/repairing is safe.
            shutil.rmtree(dest)
        shutil.move(str(module_root), dest)

    def _install_via_ghidra(self, record: ExtRecord, stage: Path, zip_path: Path) -> dict:
        """ExtensionUtils.install — requires a started JVM and the user ext dir.

        Verified against Ghidra 12.1.2 via javap: getExtension(File,bool),
        install(ExtensionDetails, File, TaskMonitor) -> bool. The install File
        must be the *archive* (isFile()==true): Ghidra then takes the
        unzipToInstallationFolder branch and lands the extension in the user
        extension dir. A directory hits copyToInstallationFolder instead,
        which refuses non-clone sources and returns false headlessly."""
        if self.user_ext_dir is None:
            raise ExtensionError(
                "JVM mode used without a Ghidra user extension dir",
                hint="start via a JVM-aware flow so the launcher reports paths, or use --no-jvm",
            )
        try:
            return self._install_via_extension_utils(record, zip_path)
        except ImportError as exc:
            raise ExtensionError(
                "ExtensionUtils is not available in this Ghidra install — using the documented "
                "best-effort unzip path requires --no-jvm",
                hint=f"see error: {exc}",
            ) from exc

    def _install_via_extension_utils(self, record: ExtRecord, zip_path: Path) -> dict:
        from jpype import JClass

        ExtensionUtils = JClass("ghidra.util.extensions.ExtensionUtils")
        JFile = JClass("java.io.File")
        ConsoleTaskMonitor = JClass("ghidra.util.task.ConsoleTaskMonitor")

        zip_file = JFile(str(zip_path))
        ExtensionUtils.initializeExtensions()  # fills the static `extensions` cache install() needs
        details = ExtensionUtils.getExtension(zip_file, True)
        if details is None:
            raise ExtensionError(
                f"ExtensionUtils could not parse {record.id!r} archive {zip_path.name}",
                hint="the zip may be malformed — pass --local to a known-good release zip",
            )
        monitor = ConsoleTaskMonitor()
        ok = ExtensionUtils.install(details, zip_file, monitor)
        if not ok:
            raise ExtensionError(f"ExtensionUtils.install returned false for {record.id!r}")
        ExtensionUtils.reload()
        return {"widget": "ExtensionUtils.install", "archive": str(zip_path)}
