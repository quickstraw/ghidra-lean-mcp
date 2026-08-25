"""M7 game-special services against the fake backend: memory_map, diff, analysis."""

from __future__ import annotations

import pytest

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.protocols import OpenSpec
from ghmcp.platform.errors import GhmcpError
from ghmcp.services import ServiceCtx
from ghmcp.services import game as game_svc


def _ctx(writable: bool = False) -> tuple[FakeAdapter, ServiceCtx, str]:
    adapter = FakeAdapter()
    p1 = adapter.open(OpenSpec(path="a.bin", writable=writable)).pid
    p2 = adapter.open(OpenSpec(path="b.bin", writable=writable)).pid
    # Mainstream the fake's two programs differ so a diff has signal.
    return adapter, ServiceCtx(adapter=adapter, current_program=p1), p2


# ------------------------------------------------------------------ memory_map


def test_memory_map_list():
    _adapter, ctx, _p2 = _ctx()
    res = game_svc.memory_map_run(game_svc.MemoryMapParams(action="list"), ctx)
    assert res.blocks and res.blocks[0]["name"] == "code"


def test_memory_map_create_requires_writable():
    _adapter, ctx, _p2 = _ctx(writable=True)
    res = game_svc.memory_map_run(
        game_svc.MemoryMapParams(action="create", name="overlay", address="0x100000", size=0x1000),
        ctx,
    )
    assert any(b["name"] == "overlay" for b in res.blocks)


def test_memory_map_create_read_only_raises():
    _adapter, ctx, _p2 = _ctx(writable=False)
    with pytest.raises(GhmcpError):
        game_svc.memory_map_run(
            game_svc.MemoryMapParams(action="create", name="overlay", address="0x100000", size=0x1000),
            ctx,
        )


# ------------------------------------------------------------------ diff_programs


def test_diff_functions():
    _adapter, ctx, p2 = _ctx()
    res = game_svc.diff_run(game_svc.DiffParams(a=ctx.current_program, b=p2, mode="functions"), ctx)
    assert res.mode == "functions"
    assert res.a_function_count > 0


def test_diff_bytes():
    _adapter, ctx, p2 = _ctx()
    res = game_svc.diff_run(
        game_svc.DiffParams(a=ctx.current_program, b=p2, mode="bytes", range_="0x1000-0x1010"), ctx
    )
    assert res.mode == "bytes"
    assert res.differing_bytes >= 0


# ------------------------------------------------------------------ analysis


def test_analysis_run_and_status():
    _adapter, ctx, _p2 = _ctx()
    run = game_svc.analysis_run(game_svc.AnalysisParams(action="run"), ctx)
    assert run.task_id and run.state == "running"
    status = game_svc.analysis_run(game_svc.AnalysisParams(action="status", task_id=run.task_id), ctx)
    assert status.state == "done"


def test_analysis_options():
    _adapter, ctx, _p2 = _ctx()
    res = game_svc.analysis_run(game_svc.AnalysisParams(action="options"), ctx)
    assert res.action == "options"


def test_analysis_status_requires_task():
    _adapter, ctx, _p2 = _ctx()
    with pytest.raises(GhmcpError):
        game_svc.analysis_run(game_svc.AnalysisParams(action="status"), ctx)
