"""Regression gate: turn stage reports into a pass/fail verdict and an exit code.

Exit codes are a bitmask so a CI log shows every failing gate at once::

    0   all gates passed
    1   lint gate (findings at/above [gate].lint_fail_on)
    2   true-positive gate (failing fixture, or untested rule if configured)
    4   false-positive gate (more goodware matches than [gate].max_fp)
    8   performance gate (slow rule)
    16  quality gate (a rule graded below [gate].min_grade)
    32  the rule set does not compile (later stages were skipped)

Values >= 64 are *not* bitmasks: 64 = usage/configuration error, 70 = internal
error (BSD sysexits EX_USAGE / EX_SOFTWARE).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag

from yaraci.config import GateConfig
from yaraci.fp import FPReport
from yaraci.lint import Finding, Severity
from yaraci.profiling import ProfileReport
from yaraci.quality import Scorecard, grade_at_least
from yaraci.testing import TPReport

EXIT_USAGE = 64
EXIT_INTERNAL = 70


class GateFailure(IntFlag):
    NONE = 0
    LINT = 1
    TP = 2
    FP = 4
    PERF = 8
    QUALITY = 16
    COMPILE = 32


@dataclass(slots=True)
class GateResult:
    code: GateFailure = GateFailure.NONE
    reasons: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.code == GateFailure.NONE

    def fail(self, flag: GateFailure, reason: str) -> None:
        self.code |= flag
        self.reasons.append(reason)


def evaluate(
    cfg: GateConfig,
    findings: list[Finding],
    compiled: bool,
    tp: TPReport | None = None,
    fp: FPReport | None = None,
    profile: ProfileReport | None = None,
    cards: list[Scorecard] | None = None,
) -> GateResult:
    """Apply the ``[gate]`` policy to whichever stage reports exist."""
    result = GateResult()
    if not compiled:
        result.fail(GateFailure.COMPILE, "rule set does not compile")
    if cfg.lint_fail_on != "never":
        threshold = Severity.parse(cfg.lint_fail_on)
        blocking = [f for f in findings if f.severity >= threshold]
        if cfg.fail_on_compile_warnings:
            blocking += [f for f in findings if f.code == "YC502" and f.severity < threshold]
        if blocking:
            result.fail(GateFailure.LINT, f"{len(blocking)} lint finding(s) at or above '{cfg.lint_fail_on}'")
    if tp is not None:
        if cfg.fail_on_tp and tp.failures:
            result.fail(GateFailure.TP, f"{len(tp.failures)} fixture expectation(s) failed")
        if cfg.fail_on_untested and tp.untested:
            result.fail(GateFailure.TP, f"{len(tp.untested)} rule(s) without a match fixture")
    if fp is not None:
        count = len(fp.effective)
        if count > cfg.max_fp:
            result.fail(GateFailure.FP, f"{count} goodware match(es) (max {cfg.max_fp})")
    if profile is not None and cfg.fail_on_slow and profile.slow_rules:
        names = ", ".join(r.rule for r in profile.slow_rules)
        result.fail(GateFailure.PERF, f"slow rule(s): {names}")
    if cards is not None and cfg.min_grade:
        below = [c.rule for c in cards if not grade_at_least(c.grade, cfg.min_grade)]
        if below:
            result.fail(GateFailure.QUALITY, f"{len(below)} rule(s) graded below {cfg.min_grade}")
    return result
