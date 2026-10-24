"""Lint finding model and the check registry."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraci.config import Config
    from yaraci.pack import PackRule, RulePack


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, text: str) -> Severity:
        return cls[text.upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    """One quality problem, located in source, attributable to a rule when possible."""

    code: str
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    rule: str | None = None

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.path or "", self.line or 0, self.column or 0, self.code)


@dataclass(frozen=True, slots=True)
class CheckSpec:
    """Documentation and defaults for one check code."""

    code: str
    name: str
    category: str
    severity: Severity
    summary: str
    rationale: str


@dataclass(frozen=True, slots=True)
class Hit:
    """What a check function yields: a message and an optional precise position."""

    message: str
    line: int | None = None
    column: int | None = None


@dataclass(slots=True)
class LintContext:
    config: Config
    pack: RulePack
    today: date


RuleCheck = Callable[[LintContext, "PackRule"], Iterator[Hit]]

SPECS: dict[str, CheckSpec] = {}
RULE_CHECKS: list[tuple[CheckSpec, RuleCheck]] = []


def register_spec(spec: CheckSpec) -> CheckSpec:
    if spec.code in SPECS:
        raise ValueError(f"duplicate check code {spec.code}")
    SPECS[spec.code] = spec
    return spec


def check(
    code: str, name: str, category: str, severity: Severity, *, summary: str, rationale: str
) -> Callable[[RuleCheck], RuleCheck]:
    """Decorator registering a per-rule check function under ``code``."""
    spec = register_spec(CheckSpec(code, name, category, severity, summary, rationale))

    def decorator(func: RuleCheck) -> RuleCheck:
        RULE_CHECKS.append((spec, func))
        return func

    return decorator
