"""Engine-neutral types shared by the YARA backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from yaraci.errors import EngineError


@dataclass(frozen=True, slots=True)
class SourceUnit:
    """One YARA source text and the path it is reported under."""

    path: str
    text: str


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """A compiler error or warning, located in the original source file."""

    severity: str  # "error" | "warning"
    code: str
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A rule that matched one sample, with the identifiers of its matching patterns."""

    rule: str
    namespace: str
    patterns: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    matches: tuple[RuleMatch, ...]
    timed_out: bool = False

    @property
    def rule_names(self) -> frozenset[str]:
        return frozenset(m.rule for m in self.matches)


class CompiledRules(Protocol):
    """A compiled rule set that can scan in-memory data."""

    def scan(self, data: bytes) -> ScanOutcome: ...


@dataclass(slots=True)
class CompileResult:
    rules: CompiledRules
    warnings: list[Diagnostic] = field(default_factory=list)


class RuleCompileError(EngineError):
    """Compilation produced at least one error; ``diagnostics`` lists them all."""

    def __init__(self, diagnostics: list[Diagnostic]) -> None:
        first = diagnostics[0] if diagnostics else None
        where = f"{first.path}:{first.line}: " if first and first.path else ""
        super().__init__(f"{where}{first.message if first else 'compilation failed'}")
        self.diagnostics = diagnostics


class Backend(Protocol):
    """A YARA engine binding."""

    name: str

    @property
    def version(self) -> str: ...

    def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
        """Compile ``units`` into one namespace. Raises :class:`RuleCompileError`."""
        ...
