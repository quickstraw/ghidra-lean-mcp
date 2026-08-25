"""Extension registry: TOML data, version gate, no-JVM install/uninstall cycle."""

from __future__ import annotations

import json
import textwrap
import zipfile
from pathlib import Path

import pytest

from ghmcp.extensions.catalog import (
    get_extension,
    load_extensions,
    load_presets,
    presets_for_extension,
)
from ghmcp.extensions.manager import (
    ExtensionManager,
    LockState,
    parse_version,
    versions_compatible,
)
from ghmcp.platform.config import Settings
from ghmcp.platform.errors import ExtensionError


def make_ext_zip(path: Path, module: str = "fake-ext", version: str = "13.4.0") -> None:
    with zipfile.ZipFile(path, "w") as zf:
        inner = f"{module}/"
        zf.writestr(
            f"{inner}extension.properties",
            textwrap.dedent(f"""\
            name = Fake Extension
            author = ghmcp-tests
            createdOn = 2026-01-01
            version = {version}
        """),
        )
        zf.writestr(f"{inner}FakeExtension.jar", b"JAR")


def named_zip(tmp_path: Path, name: str = "fake-ext-1.0.zip", **kw) -> Path:
    p = tmp_path / name
    make_ext_zip(p, **kw)
    return p


# --------------------------------------------------------------------------- catalog


def test_registry_catalog_loads():
    exts = load_extensions()
    assert "allegrex" in exts and "switch" in exts
    assert exts["allegrex"].repo == "kotcrab/ghidra-allegrex"
    assert exts["allegrex"].matches_asset("ghidra_12.1_PUBLIC_20260520_ghidra-allegrex.zip")
    assert not exts["allegrex"].matches_asset("other.zip")


def test_presets_load_and_require():
    presets = load_presets()
    psp = presets["psp"]
    assert psp.requires == ("allegrex",)
    assert psp.loader_name == "PSP Executable (ELF)"
    assert psp.image_base == 0x08804000
    assert presets_for_extension("allegrex") == ["psp"]


def test_unknown_extension_has_fix_hint():
    with pytest.raises(ExtensionError) as ei:
        get_extension("nope")
    assert "known:" in ei.value.hint


# --------------------------------------------------------------------------- version gate


def test_parse_version_forms():
    assert parse_version("12.1.2") == (12, 1, 2)
    assert parse_version("12.1.2-PUBLIC") == (12, 1, 2)
    assert parse_version("11.0.4") == (11, 0, 4)


def test_compatibility_rule():
    assert versions_compatible("12.1.2", "12.1.2")
    assert versions_compatible("12.1.3", "12.1.2")  # same minor: patch drift tolerated
    assert not versions_compatible("12.0.1", "12.1.2")
    assert versions_compatible("", "12.1.2")  # unknown → don't block


# --------------------------------------------------------------------------- no-JVM install cycle


def settings_with_tmp(tmp_path: Path) -> Settings:
    s = Settings(fake=True)
    object.__setattr__(s, "ext_cache_dir", tmp_path / "cache")
    return s


def make_manager(tmp_path: Path, **kw) -> ExtensionManager:
    """ExtensionManager isolated from the real user dir (no-JVM install target)."""
    settings = settings_with_tmp(tmp_path)
    manager = ExtensionManager(settings, no_jvm=True, **kw)
    manager.set_user_ext_dir(tmp_path / "exts")
    return manager


def test_lock_file_round_trip_windows_paths(tmp_path: Path):
    """The lock writer must round-trip backslash paths (Windows) losslessly."""
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    win_path = r"C:\Users\someone\AppData\Local\ghmcp\cache\ext\allegrex\allegrex.zip"
    manager._lock.entries["allegrex"] = {
        "sha256": "abc123",
        "version": "12.1.2",
        "source": win_path,
        "installed": True,
    }
    manager._lock.save(manager.lock_path)
    loaded = LockState.load(manager.lock_path)
    assert loaded.entries["allegrex"]["source"] == win_path, (
        "paths must round-trip without doubling backslashes"
    )


def test_install_unzip_cycle(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="13.4.0")
    artifact = named_zip(tmp_path, "fake-ext-13.4.zip", version="13.4.0")
    record = get_extension("allegrex")
    record = type(record)(
        id="allegrex",
        title=record.title,
        repo=record.repo,
        module_name="fake-ext",
        provides_languages=record.provides_languages,
        provides_loaders=record.provides_loaders,
    )

    result = manager.install_zip(record, artifact)
    assert result.state == "installed"

    # idempotent: second install is a no-op
    again = manager.install_zip(record, artifact)
    assert again.state == "already_installed"

    # lockfile persisted
    lock = LockState.load(manager.lock_path)
    assert lock.entries["allegrex"]["sha256"]


def test_install_version_gate_blocks_mismatch(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    artifact = named_zip(tmp_path, "fake-ext-13.zip", version="13.4.0")
    with pytest.raises(ExtensionError) as ei:
        manager.install_zip(get_extension("allegrex"), artifact)
    assert "--force-version-override" in ei.value.hint


def test_install_force_version_override(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2", force_version_override=True)
    artifact = named_zip(tmp_path, "fake-ext-13.zip", version="13.4.0")
    result = manager.install_zip(get_extension("allegrex"), artifact)
    assert result.state == "installed"


def test_uninstall_removes_dir_and_marker(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    record = get_extension("allegrex")
    record = type(record)(id="allegrex", title="t", repo="r", module_name="fake-ext")
    manager.install_zip(record, named_zip(tmp_path, "x.zip", module="fake-ext", version="12.1.2"))

    result = manager.uninstall("allegrex")
    assert result.state == "removed"

    with pytest.raises(ExtensionError):
        manager.uninstall("allegrex")


def test_install_refuses_to_clobber_unmanaged_dir(tmp_path: Path):
    """A pre-existing extension dir without a ghmcp marker must never be deleted."""
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    target = manager._install_dir()
    (target / "fake-ext").mkdir(parents=True, exist_ok=True)
    (target / "fake-ext" / "user_file.txt").write_text("mine", encoding="utf8")
    with pytest.raises(ExtensionError):
        manager.install_zip(
            get_extension("allegrex"),
            named_zip(tmp_path, "x.zip", module="fake-ext", version="12.1.2"),
        )
    assert (target / "fake-ext" / "user_file.txt").exists(), "unmanaged dir must survive"


def test_install_repairs_crash_residue_with_journal(tmp_path: Path):
    """A dir left behind by a crash (journal present, no marker) is ghmcp
    residue: re-run must repair instead of refusing."""
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    target = manager._install_dir()
    residue = target / "fake-ext"
    residue.mkdir(parents=True, exist_ok=True)
    (residue / "leftover.txt").write_text("junk", encoding="utf8")
    journal = manager._ext_journal("allegrex")
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_text("{}", encoding="utf8")

    result = manager.install_zip(
        get_extension("allegrex"),
        named_zip(tmp_path, "x.zip", module="fake-ext", version="12.1.2"),
    )
    assert result.state == "installed"
    assert not journal.exists(), "journal must be removed after success"
    assert not (residue / "leftover.txt").exists(), "residue must be replaced"


def test_install_rejects_archive_bomb(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    manager.MAX_MEMBER_BYTES = 1024  # shrink the cap so the test stays fast
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w") as zf:
        zf.writestr(
            "fake-ext/extension.properties",
            textwrap.dedent("""\
                name = Fake
                version = 12.1.2
            """),
        )
        zf.writestr("fake-ext/huge.bin", b"\x00" * 4096)
    with pytest.raises(ExtensionError):
        manager.install_zip(get_extension("allegrex"), bomb)


def test_extension_active_shared_rule():
    """verify + open_program surfaces must agree; exact match on lowered names."""
    from ghmcp.extensions.verify import extension_active

    ext = get_extension("allegrex")
    assert extension_active(["ghidra-allegrex"], ext)
    assert extension_active(["Ghidra-Allegrex"], ext)
    assert extension_active(["ghidra-allegrex-1.0"], ext) is False, "substring must not match"
    assert extension_active([], ext) is False
    # marker module_dir identity: a zip root that differs beyond case still counts
    assert extension_active(["fake-ext"], ext, extra_names=("fake-ext",)) is True
    assert extension_active(["fake-ext"], ext) is False


def test_verify_extensions_uses_marker_identity():
    from dataclasses import dataclass, field

    from ghmcp.extensions.verify import verify_extensions

    @dataclass
    class FakeEnv:
        loaders: list[str] = field(default_factory=lambda: ["PSP Executable (ELF)"])
        languages: list[str] = field(default_factory=lambda: ["Allegrex:LE:32:default"])
        active_extensions: list[str] = field(
            default_factory=lambda: ["fake-ext"]  # installed zip root, not registry name
        )

    results = verify_extensions(FakeEnv(), installed_dirs={"allegrex": "fake-ext"})
    by_id = {r["id"]: r for r in results}
    assert by_id["allegrex"]["ok"] is True, "verify must accept the installed dir name"


def test_extension_available_shared_policy():
    """Loader availability policy must be identical across surfaces: bidirectional
    substring (Ghidra names carry qualifiers, e.g. 'PS2 ELF (foo)')."""
    from ghmcp.extensions.verify import extension_available

    ext = get_extension("allegrex")
    assert extension_available(["PSP Executable (ELF)"], ["Allegrex:LE:32:default"], ext)
    assert extension_available(["PSP Executable (ELF) (foo)"], ["Allegrex"], ext)
    assert extension_available([], ["Allegrex"], ext) is False


def test_unsafe_member_names_rejected(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../escaped.txt", "boom")
        zf.writestr("fake-ext/extension.properties", "name = Fake\nversion = 12.1.2\n")
    with pytest.raises(ExtensionError):
        manager.install_zip(get_extension("allegrex"), evil)


def test_repack_strips_symlink_attributes(tmp_path: Path):
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    src = tmp_path / "orig.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("fake-ext/extension.properties", "name = x\nversion = 13.4\n")
        info = zipfile.ZipInfo("fake-ext/link.txt")
        info.create_system = 3  # unix
        info.external_attr = (0xA1FF << 16) | 0  # symlink mode bits
        zf.writestr(info, b"data")
    stage = tmp_path / "stage"
    (stage / "fake-ext").mkdir(parents=True)
    (stage / "fake-ext" / "extension.properties").write_text("name=x\nversion=12.1.2\n")
    record = type(get_extension("allegrex"))(
        id="allegrex", title="t", repo="r", module_name="fake-ext"
    )

    out = manager._repack_with_override(record, stage, src)
    with zipfile.ZipFile(out) as zf:
        zi = zf.getinfo("fake-ext/link.txt")
        rebuilt = (zi.external_attr >> 16) & 0xF000
        assert rebuilt == 0, f"symlink/device bits must be stripped, got {rebuilt:#o}"


def test_uninstall_uses_marker_module_dir(tmp_path: Path):
    """The zip root ('fake-ext') differs from record.module_name
    ('ghidra-allegrex'): uninstall must remove the dir the zip actually created."""
    manager = make_manager(tmp_path, ghidra_version="12.1.2")
    marker_path = manager._ext_marker("allegrex")
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        json.dumps({"module_dir": "fake-ext", "target": str(manager._install_dir())}),
        encoding="utf8",
    )
    target = manager._install_dir()
    (target / "fake-ext").mkdir(parents=True, exist_ok=True)
    (target / "fake-ext" / "extension.properties").write_text("name = x\n", encoding="utf8")

    result = manager.uninstall("allegrex")
    assert result.state == "removed"
    assert not (target / "fake-ext").exists(), "uninstall must remove the dir the zip created"
    assert not marker_path.exists()
