"""M4 nav services against the fake backend: resolve, xrefs, symbols, strings, call graph."""

from __future__ import annotations

import pytest

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.protocols import OpenSpec
from ghmcp.platform.errors import NotFound
from ghmcp.services import ServiceCtx
from ghmcp.services import call_graph as call_graph_svc
from ghmcp.services import find_strings as find_strings_svc
from ghmcp.services import find_symbols as find_symbols_svc
from ghmcp.services import resolve as resolve_svc
from ghmcp.services import xrefs as xrefs_svc


def _ctx() -> tuple[FakeAdapter, ServiceCtx]:
    adapter = FakeAdapter()
    pid = adapter.open(OpenSpec(path="test.bin")).pid
    return adapter, ServiceCtx(adapter=adapter, current_program=pid)


# ------------------------------------------------------------------ resolve


def test_resolve_address_and_suffix():
    _adapter, ctx = _ctx()
    r = resolve_svc.resolve(_adapter, ctx.current_program, "0x2000")
    assert (r.start, r.end) == (0x2000, 0x2000)
    assert not r.is_range
    assert r.symbol is None


def test_resolve_range_and_window():
    _adapter, ctx = _ctx()
    r = resolve_svc.resolve(_adapter, ctx.current_program, "0x1000-0x2000")
    assert r.is_range and (r.start, r.end) == (0x1000, 0x2000)
    r = resolve_svc.resolve(_adapter, ctx.current_program, "0x4000+0x10")
    assert r.is_range and (r.start, r.end) == (0x4000, 0x400F)


def test_resolve_symbol_and_name_at_addr():
    _adapter, ctx = _ctx()
    r = resolve_svc.resolve(_adapter, ctx.current_program, "main")
    assert r.symbol == "main" and r.start == 0x2000
    r = resolve_svc.resolve(_adapter, ctx.current_program, "Play_song")
    assert r.symbol == "play_song" and r.start == 0x1000
    r = resolve_svc.resolve(_adapter, ctx.current_program, "main@0x2100")
    assert r.start == 0x2100 and r.symbol == "main"


def test_resolve_miss_suggests():
    _adapter, ctx = _ctx()
    with pytest.raises(NotFound) as ei:
        resolve_svc.resolve(_adapter, ctx.current_program, "playsong")
    hint = ei.value.hint or ""
    assert "did you mean" in hint and "play_song" in hint


def test_resolve_miss_fallback_hint_not_bare():
    """A total miss with no close candidate must yield the plain fallback, not a
    bare 'did you mean: ' (the +/or precedence trap leaves a trailing colon)."""
    _adapter, ctx = _ctx()
    with pytest.raises(NotFound) as ei:
        resolve_svc.resolve(_adapter, ctx.current_program, "zzzqqxx")
    hint = (ei.value.hint or "").strip()
    assert hint and hint != "did you mean:"


def test_resolve_precedence_matches_listing_prefix():
    """resolve must pick the first prefix match like listing/decompile do, not
    raise Ambiguous on a shared prefix (otherwise xrefs disagrees with decompile)."""
    _adapter, ctx = _ctx()
    r = resolve_svc.resolve(_adapter, ctx.current_program, "pla")
    assert r.symbol == "play_song"


def test_suggest_returns_close_names():
    _adapter, ctx = _ctx()
    got = resolve_svc.suggest(_adapter, ctx.current_program, "pla_sng")
    assert "play_song" in got


# ------------------------------------------------------------------ xrefs


def test_xrefs_to_play_song():
    _adapter, ctx = _ctx()
    res = xrefs_svc.run(xrefs_svc.XrefsParams(targets=["play_song"]), ctx)
    assert len(res.results) == 1
    refs = res.results[0].refs
    assert any(r.address == 0x2000 for r in refs)  # main references play_song
    assert all(r.source is not None for r in refs)


def test_xrefs_from_main_respects_kinds():
    _adapter, ctx = _ctx()
    res = xrefs_svc.run(xrefs_svc.XrefsParams(targets=["main"], direction="from"), ctx)
    row = res.results[0]
    flows = [r for r in row.refs if r.kind == "flow"]
    assert {r.address for r in flows} == {0x1000, 0x3000}
    res = xrefs_svc.run(xrefs_svc.XrefsParams(targets=["main"], direction="from", kinds=["data"]), ctx)
    assert {r.address for r in res.results[0].refs} == {0x4000, 0x5050}


def test_xrefs_range_to_string_table():
    _adapter, ctx = _ctx()
    res = xrefs_svc.run(xrefs_svc.XrefsParams(targets=["0x5000-0x5060"]), ctx)
    row = res.results[0]
    assert row.is_range
    sources = {r.address for r in row.refs}
    assert sources == {0x2000, 0x3100}


def test_xrefs_pagination():
    _adapter, ctx = _ctx()
    res = xrefs_svc.run(
        xrefs_svc.XrefsParams(targets=["main"], direction="from", limit=2, offset=1), ctx
    )
    assert len(res.results[0].refs) <= 2
    assert res.truncated or len(res.results[0].refs) == 4


# ------------------------------------------------------------------ find_symbols


def test_find_symbols_prefix_and_kind():
    _adapter, ctx = _ctx()
    res = find_symbols_svc.run(find_symbols_svc.FindSymbolsParams(query="snd"), ctx)
    names = {s.name for s in res.symbols}
    assert names == {"snd_coin", "snd_jump"}
    res = find_symbols_svc.run(find_symbols_svc.FindSymbolsParams(query="*", kind="function"), ctx)
    assert {s.name for s in res.symbols} >= {"main", "render"}


def test_find_symbols_range_and_pagination():
    _adapter, ctx = _ctx()
    res = find_symbols_svc.run(
        find_symbols_svc.FindSymbolsParams(query="*", range_="0x1000-0x3000"), ctx
    )
    assert min((s.address for s in res.symbols), default=0) >= 0x1000
    assert max((s.address for s in res.symbols), default=0) <= 0x3000
    res = find_symbols_svc.run(find_symbols_svc.FindSymbolsParams(query="*", limit=3), ctx)
    assert len(res.symbols) == 3 and res.truncated and res.next_offset == 3


# ------------------------------------------------------------------ find_strings


def test_find_strings_defined():
    _adapter, ctx = _ctx()
    res = find_strings_svc.run(find_strings_svc.FindStringsParams(query="Intro"), ctx)
    assert len(res.strings) == 1
    assert res.strings[0].address == 0x5050
    res = find_strings_svc.run(find_strings_svc.FindStringsParams(min_length=11), ctx)
    assert {s.value for s in res.strings} >= {"Intro: Welcome!", "Press Start"}


def test_find_strings_scan_works_without_analysis():
    _adapter, ctx = _ctx()
    res = find_strings_svc.run(
        find_strings_svc.FindStringsParams(source="scan", min_length=10, limit=5), ctx
    )
    assert res.strings, "raw scan should find printable runs in the fake bytes"
    assert all(len(s.value) >= 10 for s in res.strings)


# ------------------------------------------------------------------ call_graph


def test_call_graph_callees():
    _adapter, ctx = _ctx()
    res = call_graph_svc.run(call_graph_svc.CallGraphParams(target="main"), ctx)
    assert res.root.name == "main"
    assert {c.name for c in res.callees} == {"play_song", "render"}


def test_call_graph_callers_and_path_to():
    _adapter, ctx = _ctx()
    res = call_graph_svc.run(call_graph_svc.CallGraphParams(target="play_song", direction="callers"), ctx)
    assert {c.name for c in res.callers} == {"main"}
    res = call_graph_svc.run(call_graph_svc.CallGraphParams(target="main", path_to="render"), ctx)
    assert res.path == [] or res.path[-1].name == "render"
