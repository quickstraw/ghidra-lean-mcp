"""Load registry.toml / presets.toml into typed records (stdlib tomllib)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files

from ghmcp.platform.errors import ConfigError, ExtensionError

_SOURCE = "registry.toml"
_PRESET_SOURCE = "presets.toml"


@dataclass(frozen=True)
class ExtRecord:
    id: str
    title: str = ""
    repo: str = ""
    module_name: str = ""
    provides_languages: tuple[str, ...] = ()
    provides_loaders: tuple[str, ...] = ()
    asset_regex: str | None = None
    ghidra_min: str = ""
    consoles: tuple[str, ...] = ()
    validate: bool = False
    build_tool: str | None = None
    build_jdk: int | None = None

    def matches_asset(self, name: str) -> bool:
        if not self.asset_regex:
            return False
        return re.search(self.asset_regex, name) is not None


@dataclass(frozen=True)
class PresetRecord:
    name: str
    title: str = ""
    requires: tuple[str, ...] = ()
    loader_name: str | None = None
    loader_args: dict[str, str] = field(default_factory=dict)
    language: str | None = None
    compiler: str | None = None
    image_base: int | None = None
    analysis: dict[str, bool] = field(default_factory=dict)
    notes: str = ""


def _read_toml(name: str) -> dict:
    resource = files("ghmcp.extensions").joinpath(name)
    try:
        with resource.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read bundled {name}: {exc}") from exc


def _section(data: dict, prefix: str) -> dict[str, dict]:
    """TOML nests [extension.allegrex] as {extension: {allegrex: {...}}};
    tolerate the flattened-key form too."""
    clipped = prefix[:-1]  # "extension." -> "extension"
    nested = data.get(clipped)
    if isinstance(nested, dict):
        return {k: v for k, v in nested.items() if isinstance(v, dict)}
    out: dict[str, dict] = {}
    for key, value in data.items():
        if isinstance(key, str) and key.startswith(prefix) and isinstance(value, dict):
            out[key[len(prefix) :]] = value
    return out


@lru_cache(maxsize=1)
def load_extensions() -> dict[str, ExtRecord]:
    data = _read_toml(_SOURCE)
    records = _section(data, "extension.")
    out: dict[str, ExtRecord] = {}
    for ext_id, raw in records.items():
        build = raw.get("build") or {}
        provides = raw.get("provides") or {}
        out[ext_id] = ExtRecord(
            id=ext_id,
            title=str(raw.get("title", "")),
            repo=str(raw.get("repo", "")),
            module_name=str(raw.get("module_name", "")),
            provides_languages=tuple(provides.get("languages", ())),
            provides_loaders=tuple(provides.get("loaders", ())),
            asset_regex=str(raw["asset_regex"]) if raw.get("asset_regex") else None,
            ghidra_min=str(raw.get("ghidra_min", "")),
            consoles=tuple(raw.get("consoles", ())),
            validate=bool(raw.get("validate", False)),
            build_tool=str(build["tool"]) if build.get("tool") else None,
            build_jdk=int(build["jdk"]) if build.get("jdk") else None,
        )
    if not out:
        raise ConfigError(f"no [extension.*] sections found in {_SOURCE}")
    return out


def _parse_image_base(value: object) -> int | None:
    """Single address convention (platform.targets.parse_address): 0x → hex,
    bare digits → decimal, bare digits-with-a-f → hex. Preset data must not
    use a different convention than the tools."""
    if value is None:
        return None
    from ghmcp.platform.errors import BadTarget
    from ghmcp.platform.targets import parse_address

    try:
        return parse_address(str(value))
    except BadTarget as exc:
        raise ConfigError(f"invalid image_base {value!r} — {exc.message}") from None


@lru_cache(maxsize=1)
def load_presets() -> dict[str, PresetRecord]:
    data = _read_toml(_PRESET_SOURCE)
    records = _section(data, "preset.")
    out: dict[str, PresetRecord] = {}
    for name, raw in records.items():
        image_base = _parse_image_base(raw.get("image_base"))
        out[name] = PresetRecord(
            name=name,
            title=str(raw.get("title", "")),
            requires=tuple(raw.get("requires", ())),
            loader_name=str(raw["loader_name"]) if raw.get("loader_name") else None,
            loader_args=dict(raw.get("loader_args") or {}),
            language=str(raw["language"]) if raw.get("language") else None,
            compiler=str(raw["compiler"]) if raw.get("compiler") else None,
            image_base=image_base,
            analysis=dict(raw.get("analysis") or {}),
            notes=str(raw.get("notes", "")),
        )
    return out


def get_extension(ext_id: str) -> ExtRecord:
    try:
        return load_extensions()[ext_id]
    except KeyError:
        known = sorted(load_extensions())
        raise ExtensionError(
            f"unknown extension {ext_id!r}", hint=f"known: {', '.join(known)}"
        ) from None


def get_preset(name: str) -> PresetRecord:
    try:
        return load_presets()[name]
    except KeyError:
        known = sorted(load_presets())
        raise ExtensionError(
            f"unknown preset {name!r}", hint=f"known: {', '.join(known)}"
        ) from None


def presets_for_extension(ext_id: str) -> list[str]:
    return [p.name for p in load_presets().values() if ext_id in p.requires]


def requirements_for(preset: PresetRecord) -> list[ExtRecord]:
    missing = [r for r in preset.requires if r not in load_extensions()]
    if missing:
        raise ExtensionError(
            f"preset {preset.name!r} requires unknown extensions: {', '.join(missing)}",
            hint="check extensions/registry.toml",
        )
    return [load_extensions()[r] for r in preset.requires]
