from __future__ import annotations

import pytest
from pydantic import ValidationError

from ghmcp.platform.config import Settings


def test_defaults_are_sane():
    s = Settings()
    assert s.max_tools == 20
    assert s.jvm_heap == "8g"
    assert s.byte_cap >= 256
    assert s.decompool_size >= 1
    assert s.ext_cache_dir is None or s.ext_cache_dir == s.cache_dir / "ext"


def test_env_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GHMCP_JVM_HEAP", "4g")
    s = Settings()
    assert s.jvm_heap == "4g"


def test_invalid_worker_pool_rejected():
    with pytest.raises(ValidationError):
        Settings(worker_pool_size=0)
