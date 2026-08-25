"""Optional build-from-source (plan §6.4): gradle in a temp clone, cache dist zips.

Opt-in only (allow_build); absence degrades to a clear error, never a silent
skip. Requires the extension's build tool on PATH (gradlew for Switch) and a
compatible JDK.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ghmcp.extensions.catalog import ExtRecord
from ghmcp.platform.config import Settings
from ghmcp.platform.errors import ExtensionError
from ghmcp.platform.telemetry import log_event


def build_from_source(record: ExtRecord, settings: Settings, ghidra_version: str | None) -> Path:
    if record.repo is None or record.build_tool is None:
        raise ExtensionError(
            f"{record.id!r} declares no build recipe",
            hint="no --allow-build path for this extension",
        )

    install_dir = settings.ghidra_install_dir
    if install_dir is None and settings.ghidra_install_dir is None:
        import os

        install_dir = Path(os.environ.get("GHIDRA_INSTALL_DIR", "")) or None
    if install_dir is None or not Path(install_dir).exists():
        raise ExtensionError(
            "build-from-source needs GHIDRA_INSTALL_DIR",
            hint="set GHIDRA_INSTALL_DIR or ghidra_install_dir in config",
        )

    cache_key = (record.repo.replace("/", "_"), ghidra_version or "any")
    cache_dir = settings.ext_dir / "build" / cache_key[0] / cache_key[1]
    cached = sorted(cache_dir.glob("*.zip")) if cache_dir.exists() else []
    if cached:
        log_event("ext_build_cache", ext=record.id, path=str(cached[0]))
        return cached[0]

    with tempfile.TemporaryDirectory(prefix="ghmcp-build-") as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "src"
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                f"https://github.com/{record.repo}.git",
                str(repo_dir),
            ],
            check=True,
            capture_output=True,
        )
        gradle = repo_dir / "gradlew"
        if not gradle.exists():
            raise ExtensionError(
                f"{record.repo} has no gradlew wrapper",
                hint="add a build recipe or install a release zip",
            )
        cmd = [str(gradle), "buildExtension", f"-PGHIDRA_INSTALL_DIR={install_dir}"]
        log_event("ext_build_start", ext=record.id, cmd=" ".join(cmd))
        try:
            subprocess.run(cmd, cwd=repo_dir, check=True, capture_output=True, timeout=900)
        except subprocess.CalledProcessError as exc:
            raise ExtensionError(
                f"extension build failed for {record.id!r}",
                hint=(exc.stderr or exc.stdout or "")[-600:],
            ) from exc
        dists = sorted((repo_dir / "dist").glob("*.zip")) if (repo_dir / "dist").exists() else []
        if not dists:
            raise ExtensionError(
                f"build produced no dist/*.zip for {record.id!r}", hint="check the build output"
            )
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / dists[0].name
        shutil.copy2(dists[0], dest)
        log_event("ext_built", ext=record.id, path=str(dest))
        return dest


def require_jdk(version: int | None = None) -> None:
    """Verify a `java` binary is on PATH and (optionally) matches the wanted major version."""
    try:
        out = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10)
        text = out.stderr or out.stdout
        match = re.search(r'"(?:1\.)?(\d+)(?:\.\d+)*', text)
        major = int(match.group(1)) if match else None
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ExtensionError(
            "no java on PATH", hint="install the JDK the extension build needs"
        ) from exc
    if version is not None and major is not None and major != version:
        log_event("ext_jdk_mismatch", wanted=version, found=major)
        raise ExtensionError(
            f"found Java {major}, but this extension builds with JDK {version}",
            hint=f"put a JDK {version} first on PATH",
        )
