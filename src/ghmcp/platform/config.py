"""Runtime configuration for ghmcp.

Precedence: env vars (GHMCP_*) > TOML file > defaults.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _cpu_cap(default: int) -> int:
    n = os.cpu_count() or default
    return max(1, min(default, n))


class Settings(BaseSettings):
    """All knobs of the server. Environment prefix GHMCP_ (e.g. GHMCP_JVM_HEAP=4g)."""

    model_config = SettingsConfigDict(
        env_prefix="GHMCP_",
        env_file=".ghmcp.toml",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- JVM -----------------------------------------------------------------
    jvm_heap: str = Field("8g", description="Java heap for the Ghidra JVM (-Xmx).")
    jvm_vmargs: list[str] = Field(
        default_factory=list,
        description="Extra JVM args appended after the defaults (-XX:+UseG1GC, -Djava.awt.headless=true).",
    )
    warm_jvm: bool = Field(True, description="Start the JVM eagerly at server boot.")
    ghidra_install_dir: Path | None = Field(
        None,
        description="Ghidra install dir; defaults to GHIDRA_INSTALL_DIR then the lastrun/`pyghidra` lookup.",
    )

    # --- Concurrency ----------------------------------------------------------
    worker_pool_size: int = Field(
        default_factory=lambda: _cpu_cap(8),
        ge=1,
        le=64,
        description="JVM worker threads (pinned and long-lived; each attach costs JVM resources).",
    )
    decompool_size: int = Field(
        2, ge=1, le=16, description="Warm DecompInterface instances (each is a native process)."
    )
    program_lock_timeout: float = Field(
        30.0, gt=0, description="Seconds to wait for the program read/write lock."
    )

    # --- Paths ----------------------------------------------------------------
    projects_dir: Path = Field(
        default_factory=lambda: (
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".cache"))) / "ghmcp" / "projects"
        ),
        description="Persistent Ghidra project dir (program DBs + annotations).",
    )
    cache_dir: Path = Field(
        default_factory=lambda: (
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".cache"))) / "ghmcp" / "cache"
        ),
        description="Misc cache (extension zips, build artifacts, LRU spill).",
    )
    ext_cache_dir: Path | None = Field(None, description="Defaults to <cache_dir>/ext.")

    # --- Per-call budgets -------------------------------------------------------
    default_timeout: float = Field(
        120.0, ge=1, le=3600, description="Default per-tool timeout in seconds."
    )
    byte_cap: int = Field(16_384, ge=256, le=1_048_576, description="Max text bytes per response.")
    max_workers: int = Field(
        0, ge=0, description="Reserved; keeps CLI/config surface forward-compatible."
    )

    # --- Catalog budget ---------------------------------------------------------
    max_tools: int = Field(20, ge=1, le=64, description="Hard cap on tool count (§1).")
    tool_list_token_budget: int = Field(
        3_000, ge=1, description="Perf gate: tools/list JSON tokens (hard fail 4000)."
    )

    # --- Misc -------------------------------------------------------------------
    fake: bool = Field(False, description="Run with the fake adapter instead of a JVM (--fake).")
    log_level: str = Field("INFO", description="Log level for structured stderr events.")

    def model_post_init(self, __context: object) -> None:
        if self.ext_cache_dir is None:
            object.__setattr__(self, "ext_cache_dir", self.cache_dir / "ext")

    @property
    def ext_dir(self) -> Path:
        assert self.ext_cache_dir is not None
        return self.ext_cache_dir


@lru_cache(maxsize=1)
def get_settings(**overrides) -> Settings:
    """Bare `get_settings()` returns the cached instance; pass overrides for one-off configs."""
    return Settings(**overrides)
