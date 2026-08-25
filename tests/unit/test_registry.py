from __future__ import annotations

import asyncio

import pytest
from mcp.types import ToolAnnotations
from pydantic import Field, ValidationError

from ghmcp.ghidra.protocols import Model
from ghmcp.platform.errors import GhmcpError, NotFound
from ghmcp.platform.registry import (
    ToolSpec,
    build_wrapper,
    generate_tools_md,
    tools_list_payload,
    validate_catalog,
)
from ghmcp.services.models import HealthResult


class EchoParamsModel(Model):
    name: str
    count: int = 3


class EchoResult(Model):
    greeting: str


def _echo_service(params: EchoParamsModel, ctx: object) -> EchoResult:
    return EchoResult(greeting=f"hello {params.name}" * params.count)


SPEC = ToolSpec(
    name="echo",
    summary="Echo test tool.",
    params=EchoParamsModel,
    result=EchoResult,
    service=_echo_service,
    summarize=lambda r: r.greeting,
    timeout=5.0,
    annotations=ToolAnnotations(read_only_hint=True),
)


class _Runner:
    def __init__(self, fail: Exception | None = None):
        self.calls = 0
        self.fail = fail

    async def __call__(self, spec: ToolSpec, params: object):
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return spec.service(params, None)


def test_wrapper_calls_service_and_returns_structured_result():
    spec = SPEC
    wrapper = build_wrapper(spec, _Runner())

    result = asyncio.run(wrapper(name="world", count=2))
    assert result.is_error is not True
    assert result.content[0].text == "hello worldhello world"
    assert result.structured_content == {"greeting": "hello worldhello world"}


def test_wrapper_validates_params():
    wrapper = build_wrapper(SPEC, _Runner())

    with pytest.raises(ValidationError):
        asyncio.run(wrapper(nope=1))


def test_wrapper_gmcp_error_becomes_is_error_result():
    wrapper = build_wrapper(SPEC, _Runner(fail=NotFound("no such symbol", hint="try find_symbols")))

    result = asyncio.run(wrapper(name="x"))
    assert result.is_error is True
    assert "[not_found]" in result.content[0].text
    assert "hint: try find_symbols" in result.content[0].text


def test_signature_reflects_params_and_result():
    wrapper = build_wrapper(SPEC, _Runner())
    import inspect

    sig = inspect.signature(wrapper)
    assert list(sig.parameters) == ["name", "count"]
    assert sig.parameters["count"].default == 3
    assert sig.return_annotation is EchoResult


class FactoryParamsModel(Model):
    name: str
    tags: list[str] = Field(default_factory=list)


class FactoryResult(Model):
    name: str
    tags: list[str]


def test_default_factory_params_stay_optional_in_signature():
    spec = ToolSpec(
        name="factory_echo",
        summary="t",
        params=FactoryParamsModel,
        result=FactoryResult,
        service=lambda p, c: FactoryResult(name=p.name, tags=p.tags),
        summarize=lambda r: r.name,
        timeout=5.0,
    )
    import inspect

    wrapper = build_wrapper(spec, _Runner())
    sig = inspect.signature(wrapper)
    assert sig.parameters["tags"].default is None, "factory field must be optional in the signature"

    result = asyncio.run(wrapper(name="x"))
    assert result.structured_content["tags"] == [], (
        "factory must fill the field when the client omits it"
    )


def test_default_factory_params_survive_sdk_injected_none():
    """The SDK injects None for signature-default params; None must be dropped
    so the factory fills the field instead of a ValidationError on list[str]."""
    spec = ToolSpec(
        name="factory_echo2",
        summary="t",
        params=FactoryParamsModel,
        result=FactoryResult,
        service=lambda p, c: FactoryResult(name=p.name, tags=p.tags),
        summarize=lambda r: r.name,
        timeout=5.0,
    )
    wrapper = build_wrapper(spec, _Runner())

    result = asyncio.run(wrapper(name="x", tags=None))
    assert result.structured_content["tags"] == [], (
        "None from the SDK must not reach model_validate"
    )


def test_no_result_model_aliases():
    """The SDK validates structured_content without by_alias — aliases would break every call."""
    assert EchoResult.model_fields["greeting"].alias is None
    assert HealthResult.model_fields["jvm_started"].alias is None


def test_validate_catalog_duplicate_names():
    with pytest.raises(GhmcpError):
        validate_catalog([SPEC, SPEC], max_tools=20)


def test_validate_catalog_budget():
    with pytest.raises(GhmcpError):
        validate_catalog([SPEC] * 21, max_tools=20)


def test_validate_catalog_ok():
    validate_catalog([SPEC], max_tools=20)


def test_tools_list_payload_shape():
    payload = tools_list_payload([SPEC])
    assert payload[0]["name"] == "echo"
    assert payload[0]["input_schema"]["properties"]["name"]["type"] == "string"
    assert payload[0]["output_schema"]["properties"]["greeting"]["type"] == "string"
    assert payload[0]["annotations"]["read_only_hint"] is True


def test_generate_docs():
    md = generate_tools_md([SPEC])
    assert "## echo" in md
    assert "Echo test tool." in md
