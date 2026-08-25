"""M5 services against the fake backend: search_binary, run_script."""

from __future__ import annotations

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.protocols import OpenSpec
from ghmcp.services import ServiceCtx
from ghmcp.services import script as script_svc
from ghmcp.services import search as search_svc


def _ctx() -> ServiceCtx:
    adapter = FakeAdapter()
    pid = adapter.open(OpenSpec(path="test.bin")).pid
    return ServiceCtx(adapter=adapter, current_program=pid)


# ------------------------------------------------------------------ search_binary


def test_search_bytes_pattern():
    ctx = _ctx()
    res = search_svc.run(search_svc.SearchParams(mode="bytes", pattern="01 02 03"), ctx)
    assert res.hits, "bytes pattern should match the sequenced fake bytes"
    assert res.hits[0].kind == "bytes"


def test_search_bytes_hex_repr():
    ctx = _ctx()
    res = search_svc.run(search_svc.SearchParams(mode="bytes", pattern="0x00010203"), ctx)
    assert res.hits  # 0x00 01 02 03 appears at the start of each 256-byte block
    assert len(res.hits) == 8  # once per repetition


def test_search_text_match():
    ctx = _ctx()
    res = search_svc.run(search_svc.SearchParams(mode="text", pattern="\x41\x42\x43"), ctx)
    # bytes 0x41 0x42 0x43 = 'ABC' present in the range(256) sequence
    assert res.hits and res.hits[0].kind == "text"


def test_search_instructions_regex():
    ctx = _ctx()
    res = search_svc.run(
        search_svc.SearchParams(mode="instructions", pattern="mov", limit=3), ctx
    )
    assert len(res.hits) == 3 and all(h.kind == "instructions" for h in res.hits)


def test_search_unknown_mode_raises():
    ctx = _ctx()
    import pytest

    from ghmcp.platform.errors import BadTarget

    with pytest.raises(BadTarget):
        search_svc.run(search_svc.SearchParams(mode="bytes", pattern="zz"), ctx)


# ------------------------------------------------------------------ run_script


def test_run_script_inline_captures_stdout_and_result():
    ctx = _ctx()
    res = script_svc.run(
        script_svc.RunScriptParams(kind="python", code="print('hi')\nresult = {'a': 1}"), ctx
    )
    assert res.error is None
    assert res.stdout.strip() == "hi"
    assert res.result == {"a": 1}


def test_run_script_inline_error_reported():
    ctx = _ctx()
    res = script_svc.run(script_svc.RunScriptParams(kind="python", code="1/0"), ctx)
    assert res.error is not None
    assert "ZeroDivisionError" in res.error


def test_run_script_ghidra_script_requires_path():
    ctx = _ctx()
    import pytest

    from ghmcp.platform.errors import TaskFailed

    with pytest.raises(TaskFailed):
        script_svc.run(script_svc.RunScriptParams(kind="ghidra_script"), ctx)
