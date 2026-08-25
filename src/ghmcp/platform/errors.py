"""Stable error taxonomy. Every failure surfaces as text plus an actionable hint."""

from __future__ import annotations


class GhmcpError(Exception):
    """Base class; subclasses map to distinct codes.

    `hint` is the next command/action the agent should take (rendered with the
    message in the tool error text, so the recovery step is never implicit).
    """

    code = "error"

    def __init__(self, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def payload(self) -> dict:
        return {"code": self.code, "message": self.message, "hint": self.hint}


class NotFound(GhmcpError):
    """The requested object (symbol, function, string, program) does not exist."""

    code = "not_found"


class Ambiguous(GhmcpError):
    """A name resolves to more than one candidate; the caller must disambiguate."""

    code = "ambiguous"


class BadTarget(GhmcpError):
    """Target syntax parsed but is invalid for the current program."""

    code = "bad_target"


class ReadOnly(GhmcpError):
    """A write was attempted on a read-only session or a disabled capability."""

    code = "read_only"


class Timeout(GhmcpError):
    """The operation exceeded its per-call budget; partial results were dropped on the floor."""

    code = "timeout"


class ExtensionMissing(GhmcpError):
    """A console extension the requested preset requires is not installed/active."""

    code = "extension_missing"


class PresetUnsatisfiable(GhmcpError):
    """The preset exists in presets.toml but cannot be satisfied without a fix."""

    code = "preset_unsatisfiable"


class AnalysisPending(GhmcpError):
    """The operation needs analysis results that are not available yet."""

    code = "analysis_pending"


class TaskFailed(GhmcpError):
    """A background task (analysis run, long script) failed."""

    code = "task_failed"


class BusyError(GhmcpError):
    """The JVM worker pool is saturated; the call was rejected, not queued."""

    code = "busy"


class ExtensionError(GhmcpError):
    """Extension subsystem failure (install/verify/build)."""

    code = "extension_error"


class ConfigError(GhmcpError):
    """Invalid configuration (bad value or combination)."""

    code = "config_error"


def error_text(err: GhmcpError) -> str:
    text = f"[{err.code}] {err.message}"
    if err.hint:
        text += f"\nhint: {err.hint}"
    return text
