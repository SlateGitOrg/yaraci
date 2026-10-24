"""The rule-quality model: one scorecard per rule across five dimensions.

========== ==================================== =================================
Dimension  Evidence                             Deduction (from 100)
========== ==================================== =================================
Validity   compiles in the configured engine    pack-level gate (no score)
Hygiene    lint findings attributed to the rule error 15, warning 5, info 1 (cap 40)
Coverage   >= 1 ``match`` fixture               untested: 25
Accuracy   fixture expectations hold            any failing fixture: 40
Precision  matches on goodware (not allowlisted) 20 per sample (cap 60)
Cost       profiler verdict                     slow: 20
========== ==================================== =================================

Grades: A >= 90, B >= 75, C >= 60, D >= 40, else F. The weights are a
documented heuristic, chosen so that a single false positive or failing fixture
always costs more than any amount of style debt; they are not statistically
calibrated. Private helper rules are scored on hygiene and cost only, since they
never alert by themselves.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from yaraci.fp import FPReport
from yaraci.lint import Finding, Severity
from yaraci.pack import RulePack
from yaraci.profiling import ProfileReport
from yaraci.testing import TPReport

LINT_WEIGHTS = {Severity.ERROR: 15, Severity.WARNING: 5, Severity.INFO: 1}
LINT_CAP = 40
UNTESTED_PENALTY = 25
TP_FAILURE_PENALTY = 40
FP_PENALTY = 20
FP_CAP = 60
SLOW_PENALTY = 20
GRADE_FLOORS = (("A", 90), ("B", 75), ("C", 60), ("D", 40))
GRADE_ORDER = "ABCDF"


def grade_for(score: int) -> str:
    for grade, floor in GRADE_FLOORS:
        if score >= floor:
            return grade
    return "F"


def grade_at_least(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) <= GRADE_ORDER.index(minimum)


@dataclass(slots=True)
class Scorecard:
    rule: str
    private: bool
    score: int = 100
    grade: str = "A"
    lint: Counter[str] = field(default_factory=Counter)
    positives: int = 0
    tp_failures: int = 0
    false_positives: int = 0
    slow: bool | None = None
    us_per_mb: float | None = None
    deductions: list[str] = field(default_factory=list)

    def deduct(self, points: int, why: str) -> None:
        if points > 0:
            self.score -= points
            self.deductions.append(f"-{points} {why}")


def _apply_tp(cards: dict[str, Scorecard], tp: TPReport) -> None:
    untested = set(tp.untested)
    failures = Counter(r.case.rule for r in tp.failures)
    for card in cards.values():
        card.positives = tp.positives_for(card.rule)
        card.tp_failures = failures.get(card.rule, 0)
        if card.private:
            continue
        if card.rule in untested:
            card.deduct(UNTESTED_PENALTY, "no match fixture")
        if card.tp_failures:
            card.deduct(TP_FAILURE_PENALTY, f"{card.tp_failures} failing fixture(s)")


def _apply_fp(cards: dict[str, Scorecard], fp: FPReport) -> None:
    for rule, count in fp.by_rule().items():
        if rule in cards:
            cards[rule].false_positives = count
            cards[rule].deduct(min(FP_CAP, FP_PENALTY * count), f"{count} goodware match(es)")


def _apply_profile(cards: dict[str, Scorecard], profile: ProfileReport) -> None:
    for prof in profile.rules:
        card = cards.get(prof.rule)
        if card is None or prof.error:
            continue
        card.slow, card.us_per_mb = prof.slow, prof.us_per_mb
        if prof.slow:
            card.deduct(SLOW_PENALTY, f"slow: {prof.reason}")


def score_pack(
    pack: RulePack,
    findings: list[Finding],
    tp: TPReport | None = None,
    fp: FPReport | None = None,
    profile: ProfileReport | None = None,
) -> list[Scorecard]:
    """Compute a scorecard for every rule from whichever stage reports are available."""
    cards = {r.name: Scorecard(r.name, r.rule.is_private) for r in pack.rules}
    for f in findings:
        if f.rule in cards:
            cards[f.rule].lint[f.severity.label] += 1
    for card in cards.values():
        lint_points = sum(LINT_WEIGHTS[Severity.parse(sev)] * n for sev, n in card.lint.items())
        card.deduct(min(LINT_CAP, lint_points), f"lint ({dict(card.lint)})")
    if tp is not None:
        _apply_tp(cards, tp)
    if fp is not None:
        _apply_fp(cards, fp)
    if profile is not None:
        _apply_profile(cards, profile)
    for card in cards.values():
        card.score = max(0, card.score)
        card.grade = grade_for(card.score)
    return sorted(cards.values(), key=lambda c: (c.score, c.rule))
