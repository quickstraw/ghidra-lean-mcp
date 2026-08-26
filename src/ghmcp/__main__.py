"""Typer CLI: ghmcp serve | ext | doctor | bench | docs."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from ghmcp import __version__
from ghmcp.platform.config import Settings, get_settings
from ghmcp.platform.errors import ConfigError

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
ext_app = typer.Typer(no_args_is_help=True, help="Console extension subsystem (plan §6).")
app.add_typer(ext_app, name="ext")


@app.command()
def serve(
    transport: Annotated[str, typer.Option(help="stdio | http")] = "stdio",
    host: Annotated[str, typer.Option(help="Listen address (http)")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="Listen port (http)")] = 8080,
    fake: Annotated[bool, typer.Option(help="Run with the fake backend (no JVM).")] = False,
) -> None:
    """Start the MCP server."""
    settings = get_settings(fake=fake)
    if fake:
        settings.warm_jvm = False

    from ghmcp.server import build_server

    server = build_server(settings)

    try:
        if transport == "http":
            import uvicorn

            http_app = server.streamable_http_app()
            uvicorn.run(http_app, host=host, port=port, log_level="warning")
        else:
            asyncio.run(server.run_stdio_async())
    except ConfigError as exc:
        typer.echo(f"error: {exc.message}", err=True)
        if exc.hint:
            typer.echo(f"hint: {exc.hint}", err=True)
        raise typer.Exit(1) from exc


@app.command()
def docs() -> None:
    """Regenerate docs/tools.md from the live registry."""
    from ghmcp.platform.registry import generate_tools_md
    from ghmcp.tools import ALL_SPECS

    content = generate_tools_md(ALL_SPECS)
    target = Path(__file__).resolve().parents[2] / "docs" / "tools.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    typer.echo(f"wrote {target} ({len(ALL_SPECS)} tools)")


def _boot_jvm(settings: Settings, *, probe: bool = False):
    """Start the throwaway CLI JVM; returns (jvm_manager, version)."""
    from ghmcp.runtime.jvm import JvmManager

    manager = JvmManager(settings)
    info = manager.start()
    return manager, info


# --------------------------------------------------------------------------- ext


def _manager(
    settings: Settings,
    *,
    allow_download: bool,
    allow_build: bool,
    force_version_override: bool,
    no_jvm: bool,
    local: Path | None,
) -> object:
    from ghmcp.extensions.manager import ExtensionManager

    manager = ExtensionManager(
        settings,
        allow_download=allow_download,
        allow_build=allow_build,
        force_version_override=force_version_override,
        no_jvm=no_jvm,
    )
    if not no_jvm:
        try:
            from ghmcp.runtime.jvm import JvmManager

            jvm = JvmManager(settings)
            jvm.start()
            manager.attach_jvm(jvm)
            return manager
        except Exception as exc:
            typer.echo(
                f"[warn] JVM-mode install unavailable ({exc}); falling back to --no-jvm", err=True
            )
            manager.no_jvm = True
    return manager


@ext_app.command("list")
def ext_list(
    offline: Annotated[bool, typer.Option(help="No network (registry only)")] = False,
) -> None:
    """List registry extensions with install/verify status."""
    from ghmcp.extensions.catalog import load_extensions

    settings = get_settings()
    from ghmcp.extensions.manager import ExtensionManager

    probe = ExtensionManager(settings)
    out = []
    for ext in load_extensions().values():
        status = probe.status(ext.id)
        out.append(
            (
                ext.id,
                ext.title,
                "installed" if status["marker"] else "-",
                ",".join(status["presets"]),
            )
        )
    if not out:
        typer.echo("no extensions in registry.toml")
        return
    width = max(len(n) for n, *_ in out)
    for ext_id, title, state, presets in out:
        typer.echo(f" {ext_id:<{width}}  {state:<9}  {title}  ({presets})")


@ext_app.command("install")
def ext_install(
    extension: Annotated[str | None, typer.Argument(help="Extension id from registry.toml")] = None,
    preset: Annotated[str | None, typer.Option(help="Install the preset's requirements")] = None,
    local: Annotated[Path | None, typer.Option(help="Use this zip instead of fetching")] = None,
    allow_download: Annotated[bool, typer.Option(help="Fetch release assets from GitHub")] = False,
    allow_build: Annotated[
        bool, typer.Option(help="Build from source (gradle) when no prebuilt zip")
    ] = False,
    force_version_override: Annotated[
        bool, typer.Option(help="Rewrite extension version to match the running Ghidra")
    ] = False,
    no_jvm: Annotated[
        bool, typer.Option(help="Best-effort unzip install without ExtensionUtils")
    ] = False,
) -> None:
    """Install a console extension (offline by default; --allow-download opts in)."""
    settings = get_settings()
    from ghmcp.extensions.catalog import get_extension, get_preset

    targets = [extension] if extension else None
    if preset:
        for req in get_preset(preset).requires:
            targets = (targets or []) + [req]
    if not targets:
        raise typer.BadParameter("pass an extension id or --preset")
    if len(targets) != 1:
        typer.echo(f"preset {preset!r} requires: {', '.join(targets)}")

    manager = _manager(
        settings,
        allow_download=allow_download,
        allow_build=allow_build,
        force_version_override=force_version_override,
        no_jvm=no_jvm,
        local=local,
    )
    for ext_id in targets:
        record = get_extension(ext_id)
        artifact = manager.resolve_artifact(record, local_path=local)
        result = manager.install_zip(record, artifact)
        typer.echo(f"{result.ext_id}: {result.state} — {result.detail}")
    manager.shutdown()
    typer.echo("restart required: extension jars enter the classpath at launch (plan §0.2)")


@ext_app.command("verify")
def ext_verify() -> None:
    """Prove that installed extensions registered their loaders/languages (post-JVM)."""
    settings = get_settings()
    manager = _manager(
        settings,
        allow_download=False,
        allow_build=False,
        force_version_override=False,
        no_jvm=False,
        local=None,
    )
    assert manager._jvm is not None
    backend = __import__("ghmcp.ghidra.backend", fromlist=["GhidraBackend"]).GhidraBackend(
        manager._jvm, settings
    )
    env = backend.env()
    from ghmcp.extensions.catalog import load_extensions
    from ghmcp.extensions.verify import preset_status, verify_extensions

    installed = {
        ext_id: d for ext_id in load_extensions() if (d := manager.installed_module_dir(ext_id))
    }
    results = verify_extensions(env, installed_dirs=installed)
    for r in results:
        flag = "OK " if r["ok"] else "MISS"
        detail = f" (missing: {', '.join(r['missing'])})" if r["missing"] else ""
        typer.echo(f" {flag}  {r['id']:<14} {r['title']}{detail}")

    for name, status in preset_status(results).items():
        typer.echo(f"      preset {name:<10} -> {status}")
    manager.shutdown()


@ext_app.command("uninstall")
def ext_uninstall(
    extension: Annotated[str, typer.Argument(help="Extension id from registry.toml")],
    no_jvm: Annotated[
        bool, typer.Option(help="Remove the dir instead of setting the disable marker")
    ] = False,
) -> None:
    """Disable (marker) or remove a console extension."""
    settings = get_settings()
    from ghmcp.extensions.catalog import get_extension

    get_extension(extension)  # validate id early
    manager = _manager(
        settings,
        allow_download=False,
        allow_build=False,
        force_version_override=False,
        no_jvm=no_jvm,
        local=None,
    )
    result = manager.uninstall(extension)
    typer.echo(f"{result.state}: {result.detail}")
    if manager._jvm is not None:
        manager._jvm.shutdown()


@ext_app.command("build")
def ext_build(
    extension: Annotated[str, typer.Argument(help="Extension id from registry.toml")],
) -> None:
    """Build from source (gradle) into the cache — no install."""
    settings = get_settings()
    from ghmcp.extensions.builder import build_from_source
    from ghmcp.extensions.catalog import get_extension

    record = get_extension(extension)
    manager = _manager(
        settings,
        allow_download=False,
        allow_build=True,
        force_version_override=False,
        no_jvm=True,
        local=None,
    )
    path = build_from_source(record, settings, manager.ghidra_version)
    typer.echo(f"built: {path}")


# --------------------------------------------------------------------------- doctor


@app.command()
def doctor() -> None:
    """Environment report: Ghidra version, extension dirs, loaders/languages, preset status."""
    settings = get_settings()
    typer.echo(f"ghidra-headless-mcp {__version__}")
    typer.echo(
        f"  ghidra_install_dir: {settings.ghidra_install_dir or '(from GHIDRA_INSTALL_DIR)'}"
    )
    typer.echo(f"  projects_dir:      {settings.projects_dir}")
    typer.echo(f"  ext_cache_dir:     {settings.ext_dir}")
    typer.echo("  booting preview JVM (throws the real thing at it)…")
    try:
        manager = _manager(
            settings,
            allow_download=False,
            allow_build=False,
            force_version_override=False,
            no_jvm=False,
            local=None,
        )
    except Exception as exc:
        typer.echo(f"  JVM: unavailable — {exc}")
        return
    assert manager._jvm is not None
    info = manager._jvm.info()
    typer.echo(f"  ghidra:            {info.get('version')}")
    typer.echo(f"  extension_dir:     {info.get('extension_dir')}")
    backend = __import__("ghmcp.ghidra.backend", fromlist=["GhidraBackend"]).GhidraBackend(
        manager._jvm, settings
    )
    env = backend.env()
    typer.echo(f"  loaders:           {len(env.loaders)} total")
    typer.echo(f"  languages:         {len(env.languages)} languages")
    from ghmcp.extensions.catalog import load_extensions
    from ghmcp.extensions.verify import preset_status, verify_extensions

    installed = {
        ext_id: d for ext_id in load_extensions() if (d := manager.installed_module_dir(ext_id))
    }
    results = verify_extensions(env, installed_dirs=installed)
    for r in results:
        flag = "OK " if r["ok"] else "MISS"
        typer.echo(f"  {flag} {r['id']:<14} {r['title']}")
    for name, status in preset_status(results).items():
        typer.echo(f"      preset {name:<10} -> {status}")
    manager._jvm.shutdown()


@app.command()
def bench(
    fake: Annotated[bool, typer.Option(help="Run the scenarios against the fake backend.")] = False,
    binary: Annotated[
        Path | None, typer.Option(help="Fixture binary for the real scenarios")
    ] = None,
    out: Annotated[
        Path | None, typer.Option(help="Write the results JSON here")
    ] = None,
) -> None:
    """Run the §5.5 performance scenarios; results go to bench/results/."""
    settings = get_settings(fake=fake)
    from ghmcp.benchmark import run_fake, run_real

    if fake:
        from ghmcp.fake.adapter import FakeAdapter

        rows = run_fake(FakeAdapter(settings))
    else:
        fixture = binary or (
            Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "bin" / "tiny_x86.coff"
        )
        if not Path(fixture).exists():
            typer.echo(f"bench needs a binary fixture (pass --binary), none at {fixture}", err=True)
            raise typer.Exit(2)
        from ghmcp.ghidra.backend import GhidraBackend
        from ghmcp.runtime.jvm import JvmManager

        jvm = JvmManager(settings)
        backend = None
        try:
            jvm.start()
            backend = GhidraBackend(jvm, settings)
            rows = run_real(backend, settings, Path(fixture))
        finally:
            from contextlib import suppress

            if backend is not None:
                with suppress(Exception):
                    backend.shutdown()
            if jvm.started:
                jvm.shutdown()

    for row in rows:
        state = "SKIP" if row.skipped else "ok  "
        measured = f"{row.measured_ms:8.1f}ms" if row.measured_ms is not None else "  (skip)"
        flag = ""
        if row.measured_ms is not None and row.measured_ms > row.target_ms:
            flag = "  OVER TARGET"
        detail = f"  ({row.reason})" if row.skipped else ""
        typer.echo(f" {state}  {row.name:<20} target {row.target_ms:7.1f}ms  {measured}{flag}{detail}")

    # Default destination is cwd-relative (a wheel install has no repo layout)
    # and the name is stable (bench-latest.json) so repeated runs show up as a
    # diff instead of accumulating timestamped files in the repo.
    dest = out or (Path.cwd() / "bench" / "results" / "bench-latest.json")
    payload = {
        "fake": fake,
        "rows": [r.as_dict() for r in rows],
    }
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        typer.echo(f"could not write bench results to {dest}: {exc}", err=True)
        typer.echo("pass --out <path> to write the results somewhere writable", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"wrote {dest}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
