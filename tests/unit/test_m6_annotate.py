"""M6 annotation services against the fake backend (write-gated, persisted)."""

from __future__ import annotations

import pytest

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.protocols import OpenSpec
from ghmcp.platform.errors import GhmcpError
from ghmcp.services import ServiceCtx
from ghmcp.services import annotate as annotate_svc


def _ctx(writable: bool = True) -> ServiceCtx:
    adapter = FakeAdapter()
    pid = adapter.open(OpenSpec(path="test.bin", writable=writable)).pid
    return ServiceCtx(adapter=adapter, current_program=pid)


# ------------------------------------------------------------------ rename


def test_rename_function():
    ctx = _ctx()
    res = annotate_svc.rename_run(
        annotate_svc.RenameParams(kind="function", target="main", new_name="entrypoint"), ctx
    )
    assert res.new_name == "entrypoint"
    adapter = ctx.adapter
    infos = adapter.list_open()
    # rename bumps the modification number (cache invalidation signal)
    assert adapter.modification_number(infos[0].pid) > 0


def test_rename_read_only_raises():
    ctx = _ctx(writable=False)
    with pytest.raises(GhmcpError):
        annotate_svc.rename_run(
            annotate_svc.RenameParams(kind="function", target="main", new_name="x"), ctx
        )


def test_rename_label_prefix_matches_real_precedence():
    """A label/data target that is a prefix (not an exact name) must resolve via
    the first-prefix fallback, matching the real annotate._symbol_or_addr path."""
    ctx = _ctx()
    res = annotate_svc.rename_run(
        annotate_svc.RenameParams(kind="label", target="snd_", new_name="sfx_coin"), ctx
    )
    assert res.new_name == "sfx_coin"


# ------------------------------------------------------------------ set_prototype


def test_set_prototype():
    ctx = _ctx()
    res = annotate_svc.set_prototype_run(
        annotate_svc.SetPrototypeParams(function="render", signature="int render(char *s)"), ctx
    )
    assert res.signature == "int render(char *s)"


# ------------------------------------------------------------------ types


def test_types_define_list_get():
    ctx = _ctx()
    res = annotate_svc.types_run(annotate_svc.TypesParams(action="define", c_decl="typedef int Foo;"), ctx)
    assert "Foo" in res.names
    listed = annotate_svc.types_run(annotate_svc.TypesParams(action="list"), ctx)
    assert "Foo" in listed.names
    got = annotate_svc.types_run(annotate_svc.TypesParams(action="get", name="Foo"), ctx)
    assert got.detail["name"] == "Foo"


def test_types_apply_requires_name():
    ctx = _ctx()
    with pytest.raises(GhmcpError):
        annotate_svc.types_run(annotate_svc.TypesParams(action="apply", address="0x5000"), ctx)


# ------------------------------------------------------------------ set_comment


def test_set_comment_single_and_batch():
    ctx = _ctx()
    res = annotate_svc.set_comment_run(
        annotate_svc.SetCommentParams(address="0x1000", kind="plate", text="hello"), ctx
    )
    assert res.count == 1
    res = annotate_svc.set_comment_run(
        annotate_svc.SetCommentParams(
            address="0x1000", kind="pre", text="", batch={"0x1000": "a", "0x2000": "b"}
        ),
        ctx,
    )
    assert res.count == 2
