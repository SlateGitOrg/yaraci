"""Pluggable YARA engines: YARA-X (default) and classic libyara."""

from __future__ import annotations

from yaraci.engine.base import (
    Backend,
    CompiledRules,
    CompileResult,
    Diagnostic,
    RuleCompileError,
    RuleMatch,
    ScanOutcome,
    SourceUnit,
)
from yaraci.errors import ConfigError

BACKENDS = ("yara-x", "libyara")


def get_backend(name: str = "yara-x") -> Backend:
    """Return the backend called ``name`` (``yara-x`` or ``libyara``)."""
    if name == "yara-x":
        from yaraci.engine.yarax import YaraXBackend  # noqa: PLC0415 - optional native import

        return YaraXBackend()
    if name == "libyara":
        from yaraci.engine.libyara import LibyaraBackend  # noqa: PLC0415 - optional native import

        return LibyaraBackend()
    raise ConfigError(f"unknown engine {name!r}; choose one of {', '.join(BACKENDS)}")


__all__ = [
    "BACKENDS",
    "Backend",
    "CompileResult",
    "CompiledRules",
    "Diagnostic",
    "RuleCompileError",
    "RuleMatch",
    "ScanOutcome",
    "SourceUnit",
    "get_backend",
]
