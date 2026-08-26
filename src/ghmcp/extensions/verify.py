"""Post-JVM verification: prove an extension's loaders/languages registered.

Compares each registry extension's `provides` against the live
LoaderService.getAllLoaderNames() and the language service, cross-checked with
ExtensionUtils.getActiveInstalledExtensions(); then derives preset
satisfiability (plan §6.5). Pure data in, pure data out — Ghidra access stays
in the backend's env().
"""

from __future__ import annotations

from ghmcp.extensions.catalog import load_extensions, load_presets


def extension_active(env_active: list[str], ext: object, extra_names: tuple[str, ...] = ()) -> bool:
    """One exact-match rule for "is this registry extension active in the JVM".

    Used by both verify (doctor/ext verify) and open_program's preset status so
    the two surfaces can never disagree about the same JVM state. Exact match
    on the lowered module_name (registry id as a secondary key, plus the
    marker's installed module_dir passed by the install path) against the
    lowered active list — no substring, so suffixed names never cause false
    positives. `extra_names` lets the verify surface resolve identity the same
    way install/uninstall do (the installed dir name can differ from the
    registry module_name beyond case)."""
    lowered = {a.lower() for a in env_active}
    module_name = getattr(ext, "module_name", "") or ""
    ext_id = getattr(ext, "id", "") or ""
    candidates = {module_name.lower(), ext_id.lower()}
    candidates.update(str(x).lower() for x in extra_names if x)
    return bool(lowered & candidates)


def extension_missing(env_loaders: list[str], env_languages: list[str], ext: object) -> list[str]:
    """Missing loader/language names for this extension under ONE policy:
    bidirectional substring (Ghidra names often add qualifiers, e.g. 'PS2 ELF
    (foo)' contains the registry name 'PS2 ELF')."""
    loaders = [str(x) for x in env_loaders]
    languages = [str(x) for x in env_languages]
    missing: list[str] = []
    for loader in getattr(ext, "provides_loaders", ()) or ():
        if not any(loader in live or live in loader for live in loaders):
            missing.append(loader)
    for lang in getattr(ext, "provides_languages", ()) or ():
        key = lang.split(":")[0]
        if not any(key in live or live in key for live in languages):
            missing.append(lang)
    return missing


def extension_available(env_loaders: list[str], env_languages: list[str], ext: object) -> bool:
    """True when no loader/language requirement is missing (see extension_missing)."""
    return not extension_missing(env_loaders, env_languages, ext)


def verify_extensions(
    backend_env: object, installed_dirs: dict[str, str] | None = None
) -> list[dict]:
    """Check every registry extension against the live env probe.

    `backend_env` is the EnvInfo-style object from the adapter; `installed_dirs`
    maps ext id → the installed dir name recorded at install time (marker
    module_dir) so the active check sees the identity install actually used.
    """
    loaders = list(getattr(backend_env, "loaders", []) or [])
    languages = list(getattr(backend_env, "languages", []) or [])
    active = list(getattr(backend_env, "active_extensions", []) or [])

    results: list[dict] = []
    for ext in load_extensions().values():
        extra = (installed_dirs.get(ext.id),) if installed_dirs and ext.id in installed_dirs else ()
        missing = extension_missing(loaders, languages, ext)
        if ext.module_name and active and not extension_active(active, ext, extra_names=extra):
            missing.append(f"active:{ext.module_name}")
        results.append(
            {
                "id": ext.id,
                "title": ext.title,
                "ok": not missing,
                "missing": missing,
                "provides": {
                    "loaders": sorted(ext.provides_loaders),
                    "languages": sorted(ext.provides_languages),
                },
            }
        )
    return results


def preset_status(verify_results: list[dict]) -> dict[str, str]:
    """Derive preset satisfiability from verification results."""
    ok_ids = {item["id"] for item in verify_results if item["ok"]}
    status: dict[str, str] = {}
    for preset in load_presets().values():
        missing = [r for r in preset.requires if r not in ok_ids]
        status[preset.name] = f"missing_extension:{','.join(missing)}" if missing else "satisfiable"
    return status


def enrich_env(env: object, *, loaders: list[str] | None = None,
               languages: list[str] | None = None,
               active_extensions: list[str] | None = None,
               installed_extensions: list[str] | None = None) -> object:
    """Fill the shared EnvInfo meta (presets + preset_status) from live lists.

    Single source of truth for both adapters (plan §6.5): `environment`
    surfaces preset satisfiability, and `ext/verify`/`doctor` derive status
    from the same `verify_extensions` pass, so the two never disagree.
    """
    env.presets = sorted(p.name for p in load_presets().values())
    env.loaders = list(loaders if loaders else getattr(env, "loaders", []))
    env.languages = list(languages if languages else getattr(env, "languages", []))
    env.active_extensions = list(
        active_extensions if active_extensions else getattr(env, "active_extensions", [])
    )
    env.installed_extensions = list(
        installed_extensions if installed_extensions else getattr(env, "installed_extensions", [])
    )
    env.preset_status = preset_status(verify_extensions(env))
    return env
