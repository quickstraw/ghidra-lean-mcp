"""open_program use-case: preset merge → OpenSpec → adapter.open.

Preset semantics (plan §6.5): requires gate, loader_name/loader_args/language/
compiler come from the preset, image_base is applied post-load by the adapter,
explicit arguments always win.
"""

from __future__ import annotations

from pydantic import Field

from ghmcp.extensions.catalog import get_preset, load_extensions
from ghmcp.ghidra.protocols import Model, OpenSpec, ProgramInfo
from ghmcp.platform.errors import PresetUnsatisfiable
from ghmcp.services import ServiceCtx


class OpenProgramParams(Model):
    path: str
    preset: str | None = None
    loader_name: str | None = None
    loader_args: dict[str, str] | None = None
    language: str | None = None
    compiler: str | None = None
    image_base: int | None = None
    analyze: str = "auto"  # auto | full | none
    writable: bool = False
    alias: str | None = None


class OpenProgramResult(Model):
    program: ProgramInfo
    preset: str | None
    preset_status: dict[str, str] = Field(default_factory=dict)


def run(params: OpenProgramParams, ctx: ServiceCtx) -> OpenProgramResult:
    adapter = ctx.require_adapter()
    spec = _merge(preset_name=params.preset, params=params)
    info = adapter.open(spec)
    try:
        env = adapter.env()
        status = dict(env.preset_status)  # filled by the adapter (plan §6.5)
    except Exception:
        status = {}
    return OpenProgramResult(program=info, preset=params.preset, preset_status=status)


def _merge(preset_name: str | None, params: OpenProgramParams) -> OpenSpec:
    """Preset → explicit merge; explicit wins; missing requirements raise."""
    loader_name = params.loader_name
    loader_args = dict(params.loader_args or {})
    language = params.language
    compiler = params.compiler
    image_base = params.image_base

    if preset_name is not None:
        preset = get_preset(preset_name)
        missing = [r for r in preset.requires if r not in load_extensions()]
        if missing:
            raise PresetUnsatisfiable(
                f"preset {preset_name!r} requires unknown extensions: {', '.join(missing)}",
                hint="check extensions/registry.toml",
            )
        loader_name = loader_name or preset.loader_name
        loader_args = {**preset.loader_args, **loader_args}
        language = language or preset.language
        compiler = compiler or preset.compiler
        image_base = image_base if image_base is not None else preset.image_base

    return OpenSpec(
        path=params.path,
        preset=preset_name,
        loader_name=loader_name,
        loader_args=loader_args,
        language=language,
        compiler=compiler,
        image_base=image_base,
        analyze=params.analyze,
        writable=params.writable,
        alias=params.alias,
    )
