"""Tool registry: specs, async wrappers, budget guards, docs generation.

Pure plumbing: no runtime, no Ghidra. The executor that actually runs a
service is injected as `runner` by server.py, keeping platform → runtime
imports illegal (import-linter contract in pyproject.toml).
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic_core import PydanticUndefined

from ghmcp.platform import telemetry
from ghmcp.platform.errors import ConfigError, GhmcpError, error_text

ServiceFn = Callable[..., Any]  # (params_model, ctx) -> result_model
SummarizeFn = Callable[[Any], str]
RunnerFn = Callable[["ToolSpec", Any], Any]  # (spec, params_model) -> result_model


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of one MCP tool."""

    name: str
    summary: str
    params: type[Any]
    result: type[Any]
    service: ServiceFn
    summarize: SummarizeFn
    timeout: float = 60.0
    annotations: ToolAnnotations | None = field(default=None, repr=False)
    title: str | None = None
    description: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ConfigError(
                f"tool {self.name!r} must have a positive timeout, got {self.timeout}"
            )


def validate_catalog(specs: Sequence[ToolSpec], max_tools: int) -> None:
    """Budget gate: unique names, cap on count, serializable schemas."""
    if max_tools <= 0:
        raise ConfigError(f"max_tools must be positive, got {max_tools}")
    seen: set[str] = set()
    for spec in specs:
        if spec.name in seen:
            raise ConfigError(f"duplicate tool name {spec.name!r}")
        seen.add(spec.name)
    if len(specs) > max_tools:
        raise ConfigError(
            f"tool catalog has {len(specs)} tools, budget is {max_tools} (§1 displacement rule)"
        )
    for spec in specs:
        spec.params.model_json_schema()
        spec.result.model_json_schema()


def _wrapper_signature(spec: ToolSpec) -> inspect.Signature:
    """A signature mirroring spec.params, so the SDK derives the right input schema.

    func_metadata honours `__signature__`; without it the wrapper's **kwargs
    would become a single required "kwargs" field and reject every call.
    """
    params: list[inspect.Parameter] = []
    for name, fi in spec.params.model_fields.items():
        if fi.annotation is None:
            raise ConfigError(f"tool {spec.name!r}: param {name!r} has no annotation")
        annotation: Any = fi.annotation
        if fi.default is not PydanticUndefined:
            default: Any = fi.default
        elif fi.default_factory is not None:
            # Optional in the generated signature (factory runs in
            # model_validate); inspect.Parameter.empty would make the field
            # REQUIRED, so the SDK would demand a value the model treats as
            # optional.
            default = None
        else:
            default = inspect.Parameter.empty
        params.append(
            inspect.Parameter(
                name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=annotation,
                default=default,
            )
        )
    return inspect.Signature(params, return_annotation=spec.result)


def build_wrapper(spec: ToolSpec, runner: RunnerFn) -> Callable[..., Any]:
    """Turn a spec into an async MCP tool fn.

    Body returns CallToolResult directly: the SDK's convert_result passes
    CallToolResult through unchanged and validates its structured_content
    against the declared output model (func_metadata.pass_through), giving
    the "compact summary text + full structured payload" split with a
    published output_schema. Result models must therefore not define field
    aliases: the pass-through validates *without* by_alias.
    """

    async def wrapper(**kwargs: Any) -> CallToolResult:
        # Drop None arguments entirely: the SDK injects None for fields whose
        # signature default we emit (default_factory fields and Optional fields
        # defaulting to None). model_validate then applies the model default —
        # the factory for factory fields, None for optional ones. Keeping the
        # None would validate it against a non-Optional list/dict and fail.
        clean = {k: v for k, v in kwargs.items() if v is not None}
        params = spec.params.model_validate(clean)
        timer = telemetry.Timer().start()
        try:
            outcome = await runner(spec, params)
        except GhmcpError as exc:
            telemetry.log_event(
                "call", tool=spec.name, ok=False, code=exc.code, ms=round(timer.split_ms(), 2)
            )
            return CallToolResult(
                content=[TextContent(type="text", text=error_text(exc))],
                is_error=True,
            )
        except Exception:
            telemetry.log_event("call", tool=spec.name, ok=False, ms=round(timer.split_ms(), 2))
            raise
        # Duck-typed ExecOutcome: platform may not import runtime (layering).
        result = getattr(outcome, "result", outcome)
        jvm_ms = getattr(outcome, "jvm_ms", None)
        telemetry.log_event(
            "call",
            tool=spec.name,
            ok=True,
            py_ms=round(timer.split_ms(), 2),
            jvm_ms=round(jvm_ms, 2) if jvm_ms is not None else None,
        )
        text = spec.summarize(result)
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=result.model_dump(mode="json"),
        )

    wrapper.__name__ = spec.name
    wrapper.__doc__ = spec.summary
    wrapper.__annotations__["return"] = spec.result
    wrapper.__signature__ = _wrapper_signature(spec)  # type: ignore[attr-defined]
    wrapper._ghmcp_spec = spec  # type: ignore[attr-defined]
    return wrapper


def tools_list_payload(specs: Sequence[ToolSpec]) -> list[dict[str, Any]]:
    """The shape a client sees in `tools/list` (used by the token-budget gate)."""
    payload: list[dict[str, Any]] = []
    for spec in specs:
        item: dict[str, Any] = {
            "name": spec.name,
            "title": spec.title or spec.name,
            "description": spec.description or spec.summary,
            "input_schema": spec.params.model_json_schema(),
        }
        output_schema = spec.result.model_json_schema()
        if output_schema:
            item["output_schema"] = output_schema
        if spec.annotations is not None:
            item["annotations"] = spec.annotations.model_dump(exclude_none=True)
        payload.append(item)
    return payload


def generate_tools_md(specs: Sequence[ToolSpec]) -> str:
    """Regenerate docs/tools.md from the live specs; CI fails if stale."""
    lines = [
        "# ghmcp tool catalog",
        "",
        f"{len(specs)} tools. Generated by `ghmcp docs` — do not edit by hand.",
        "",
    ]
    for spec in specs:
        lines += [
            f"## {spec.name}",
            "",
            spec.summary,
            "",
            f"- Timeout: {spec.timeout:g}s",
            f"- Read-only: {bool(spec.annotations and spec.annotations.read_only_hint)}",
            "",
            "### Parameters",
            "",
            "```json",
            json.dumps(spec.params.model_json_schema(), indent=2),
            "```",
            "",
            "### Result",
            "",
            "```json",
            json.dumps(spec.result.model_json_schema(), indent=2),
            "```",
            "",
        ]
    return "\n".join(lines)
