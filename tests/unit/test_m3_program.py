"""M3/M5/M6/M7 behaviors against the fake backend: lifecycle, typed reads,
session env meta, analysis task id, run_script write gating."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghmcp.fake.adapter import FakeAdapter
from ghmcp.ghidra.protocols import OpenSpec
from ghmcp.platform.errors import ReadOnly
from ghmcp.platform.targets import parse_address
from ghmcp.services import ServiceCtx
from ghmcp.services import memory as memory_svc
from ghmcp.services import script as script_svc
from ghmcp.services import session as session_svc


def _adapter(analyze: str = "auto", writable: bool = False) -> tuple[FakeAdapter, ServiceCtx, str]:
    adapter = FakeAdapter()
    info = adapter.open(
        OpenSpec(path="test.bin", analyze=analyze, writable=writable, language="FAKE:LE:32:default")
    )
    adapter.select(info.pid)  # current program is adapter state, not ServiceCtx (services read adapter.current())
    return adapter, ServiceCtx(adapter=adapter), info.pid


# ------------------------------------------------------------------ open_program


def test_auto_analysis_surfaces_task_id():
    adapter = FakeAdapter()
    info = adapter.open(OpenSpec(path="test.bin", analyze="auto"))
    assert info.analysis_task_id, "analyze=auto must return the background task id (plan §5.1)"
    # The fake task store knows it.
    assert adapter.task_status(info.analysis_task_id)["state"] == "done"


def test_none_analysis_has_no_task_id():
    adapter = FakeAdapter()
    info = adapter.open(OpenSpec(path="test.bin", analyze="none"))
    assert info.analysis_task_id is None


# ------------------------------------------------------------------ read_memory


def test_read_memory_typed_lists_defined_data():
    _a, ctx, _pid = _adapter()
    res = memory_svc.read_run(memory_svc.ReadParams(address="0x5000", length=32, format="typed"), ctx)
    assert res.typed, "data-kind symbols inside the window must surface"
    addrs = [t.address for t in res.typed]
    assert 0x5000 in addrs and 0x5010 in addrs
    assert all(t.value for t in res.typed)
    assert res.data.startswith("0x5000")


def test_read_memory_typed_type_filter():
    _a, ctx, _pid = _adapter()
    res = memory_svc.read_run(
        memory_svc.ReadParams(address="0x5000", length=32, format="typed", type="snd_jump"), ctx
    )
    assert [t.address for t in res.typed] == [0x5010]


def test_read_memory_typed_json_shape():
    _a, ctx, _pid = _adapter()
    res = memory_svc.read_run(memory_svc.ReadParams(address="0x5000", length=16, format="typed"), ctx)
    payload = res.model_dump(mode="json")
    assert all(set(t) == {"address", "type_name", "value", "size"} for t in payload["typed"])
    assert payload["typed"][0]["size"] > 0


def test_read_memory_hex_ascii_words():
    _a, ctx, _pid = _adapter()
    hex_data = memory_svc.read_run(memory_svc.ReadParams(address="0x1000", length=32), ctx)
    assert "\n" in hex_data.data  # hexdump is multi-line
    ascii_data = memory_svc.read_run(
        memory_svc.ReadParams(address="0x1000", length=16, format="ascii"), ctx
    )
    assert len(ascii_data.data) == 16
    words = memory_svc.read_run(
        memory_svc.ReadParams(address="0x1000", length=16, format="words"), ctx
    )
    assert len(words.data.split(" ")) == 4


def test_read_memory_rejects_negative_length():
    _a, _ctx, _pid = _adapter()
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        memory_svc.ReadParams(address="0x1000", length=-1)
    with pytest.raises(ValidationError):
        memory_svc.ReadParams(address="0x1000", length=0)


# ------------------------------------------------------------------ session env


def test_session_env_carries_preset_status():
    _a, ctx, _pid = _adapter()
    res = session_svc.run(session_svc.SessionParams(action="env"), ctx)
    assert res.env is not None
    assert res.env.presets, "env must list the bundled presets"
    assert set(res.env.preset_status) >= set(res.env.presets)
    assert res.env.drift_warning is None  # fake mode has no on-disk extension state


def test_open_program_result_reports_preset_status():
    from ghmcp.services import open_program as open_svc

    adapter = FakeAdapter()
    res = open_svc.run(open_svc.OpenProgramParams(path="test.bin", analyze="none"), ServiceCtx(adapter=adapter))
    assert res.program.pid
    # Every bundled preset key is present ("missing_extension:…" in fake mode is honest).
    for name in res.preset_status:
        assert res.preset_status[name].startswith(("satisfiable", "missing_extension"))


# ------------------------------------------------------------------ run_script


def test_run_script_write_on_readonly_raises():
    _a, ctx, pid = _adapter(writable=False)
    with pytest.raises(ReadOnly):
        script_svc.run(
            script_svc.RunScriptParams(code="result = 1", write=True, program=pid), ctx
        )


def test_run_script_write_on_writable_session_ok():
    _a, ctx, pid = _adapter(writable=True)
    res = script_svc.run(
        script_svc.RunScriptParams(code="result = {'ok': True}", write=True, program=pid), ctx
    )
    assert res.result == {"ok": True} and res.error is None


def test_run_script_inline_sees_args():
    _a, ctx, pid = _adapter(writable=True)
    res = script_svc.run(
        script_svc.RunScriptParams(code="result = {'got': args}", args=["a", "b"], program=pid), ctx
    )
    assert res.result == {"got": ["a", "b"]}


def test_run_script_non_dict_result_is_bounded_error():
    """A script setting result=<list> must surface a bounded tool error, not a
    raw ValidationError 500 (plan §7: result is a dict for structured output)."""
    _a, ctx, pid = _adapter(writable=True)
    from ghmcp.platform.errors import GhmcpError

    with pytest.raises(GhmcpError) as ei:
        script_svc.run(
            script_svc.RunScriptParams(code="result = [1, 2]", program=pid), ctx
        )
    assert "must be a JSON object" in ei.value.message


def test_run_script_ghidra_script_fake_matches_real_shape(tmp_path: Path):
    """ghidra_script output is stdout-only (result=None mirrors the real
    backend — a structured result binding is inline-python only)."""
    _a, ctx, pid = _adapter()
    script = tmp_path / "probe.py"
    script.write_text("print('x is None:', currentProgram is None)", encoding="utf-8")
    res = script_svc.run(
        script_svc.RunScriptParams(kind="ghidra_script", path=str(script), program=pid), ctx
    )
    assert res.error is None
    assert res.result is None
    assert "x is None:" in res.stdout


# ------------------------------------------------------------------ helpers


def test_parse_address_unchanged():
    assert parse_address("0x8804a1c0") == 0x8804A1C0
    assert parse_address("123") == 123
