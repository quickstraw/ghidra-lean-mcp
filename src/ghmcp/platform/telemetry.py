"""Structured stderr telemetry: one JSON object per line, machine-greppable.

Kept synchronous and allocation-light: it runs on every call including hot
paths, and a slow logger would eat the §5.5 python-side budget.
"""

from __future__ import annotations

import json
import logging
import sys
import time

_LOGGER = logging.getLogger("ghmcp.telemetry")
_INITIALIZED = False


def init(level: str = "INFO") -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    _LOGGER.setLevel(getattr(logging, level.upper(), logging.INFO))
    _LOGGER.propagate = False
    if not _LOGGER.handlers:
        _LOGGER.addHandler(logging.StreamHandler(sys.stderr))
    _INITIALIZED = True


def log_event(event: str, **fields) -> None:
    """Emit one structured line: `{"event": ..., ...}`."""
    record = {"event": event, **fields}
    _LOGGER.info(json.dumps(record, default=str, separators=(",", ":")))


class Timer:
    """Wall-clock timer; used for the python-vs-jvm timing split (§5)."""

    __slots__ = ("_t0",)

    def __init__(self) -> None:
        self._t0: float | None = None

    def start(self) -> Timer:
        self._t0 = time.perf_counter()
        return self

    def split_ms(self) -> float:
        if self._t0 is None:
            self.start()
        assert self._t0 is not None
        return (time.perf_counter() - self._t0) * 1000.0

    def __enter__(self) -> Timer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self._t0 = None
