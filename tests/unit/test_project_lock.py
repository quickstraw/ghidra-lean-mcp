"""Cross-process project-dir lock: acquisition, idempotence, retry safety."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghmcp.platform.errors import GhmcpError
from ghmcp.runtime.project import ProjectManager


def test_lock_acquired_once_per_manager(tmp_path: Path):
    pm = ProjectManager(tmp_path)
    pm._acquire_dir_lock()
    fd1 = pm._lock_fd
    assert fd1 is not None
    pm._acquire_dir_lock()  # idempotent: must not re-open/self-lock
    assert pm._lock_fd is fd1


def test_second_manager_locked_out(tmp_path: Path):
    first = ProjectManager(tmp_path)
    first._acquire_dir_lock()
    second = ProjectManager(tmp_path)
    with pytest.raises(GhmcpError):
        second._acquire_dir_lock()
    assert second._lock_fd is None


def test_lock_file_exists_and_is_retained(tmp_path: Path):
    pm = ProjectManager(tmp_path)
    pm._acquire_dir_lock()
    assert (tmp_path / ".ghmcp.lock").exists()
    assert pm._lock_fd is not None


def test_close_releases_lock_for_reactquisition(tmp_path: Path):
    pm = ProjectManager(tmp_path)
    pm._acquire_dir_lock()
    pm.close()
    assert pm._lock_fd is None
    pm2 = ProjectManager(tmp_path)
    pm2._acquire_dir_lock()
    assert pm2._lock_fd is not None
    pm2.close()


def test_lock_records_owner_pid(tmp_path: Path):
    pm = ProjectManager(tmp_path)
    pm._acquire_dir_lock()
    import os

    # Read via the held fd itself: the byte-range lock blocks other handles
    # on Windows from reading the same file.
    os.lseek(pm._lock_fd, 0, 0)
    payload = os.read(pm._lock_fd, 32).decode("utf8", errors="replace")
    assert str(os.getpid()) in payload
