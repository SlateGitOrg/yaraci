"""Uniform "issue" view over every stage, shared by the SARIF, JUnit and text writers.

Lint findings already carry a code; scan-stage results are mapped onto
stage codes here so that every consumer sees one list of located issues.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from yaraci.lint import SPECS, Finding, Severity
from yaraci.pipeline import CheckResult
from yaraci.quality import grade_at_least


@dataclass(frozen=True, slots=True)
class StageCode:
    code: str
    name: str
    severity: Severity
    summary: str


STAGE_CODES = {
    "YC601": StageCode("YC601", "fixture-failed", Severity.ERROR, "A fixture expectation did not hold."),
    "YC602": StageCode("YC602", "untested-rule", Severity.ERROR, "A public rule has no match fixture."),
    "YC603": StageCode("YC603", "orphan-fixtures", Severity.WARNING, "A fixture directory names no rule."),
    "YC701": StageCode("YC701", "goodware-match", Severity.ERROR, "The rule matched a goodware sample."),
    "YC702": StageCode("YC702", "expired-allowlist", Severity.WARNING, "An FP allowlist entry has expired."),
    "YC801": StageCode("YC801", "slow-rule", Severity.ERROR, "The rule is a scan-time outlier."),
    "YC901": StageCode(
        "YC901", "low-quality-grade", Severity.ERROR, "The rule's quality grade is below the minimum."
    ),
}


def code_info(code: str) -> tuple[str, str, Severity]:
    """``(name, summary, default severity)`` for a lint or stage code."""
    if code in SPECS:
        spec = SPECS[code]
        return spec.name, spec.summary, spec.severity
    stage = STAGE_CODES[code]
    return stage.name, stage.summary, stage.severity


def display_path(pack_root: Path, relative: str | None) -> str | None:
    """Path of a pack file relative to the current directory when possible."""
    if relative is None:
        return None
    absolute = (pack_root / relative).resolve()
    try:
        return Path(os.path.relpath(absolute, Path.cwd())).as_posix()
    except ValueError:
        return absolute.as_posix()


def collect_issues(result: CheckResult) -> list[Finding]:
    """All lint findings plus scan-stage results expressed as findings."""
    pack = result.pack
    issues = list(result.findings)

    def at_rule(code: str, rule: str, message: str) -> Finding:
        pr = pack.by_name.get(rule)
        sev = STAGE_CODES[code].severity
        if pr is None:
            return Finding(code, sev, message, rule=rule)
        return Finding(code, sev, message, pr.path, pr.rule.pos.line, pr.rule.pos.column, rule)

    if result.tp is not None:
        for res in result.tp.failures:
            want = "match" if res.case.expect_match else "not match"
            why = "timed out" if res.timed_out else f"expected to {want}"
            issues.append(at_rule("YC601", res.case.rule, f"{res.case.sample.name}: {why}"))
        for name in result.tp.untested:
            issues.append(at_rule("YC602", name, f"rule {name} has no fixtures/{name}/match/ files"))
        for orphan in result.tp.orphans:
            issues.append(
                Finding("YC603", Severity.WARNING, f"fixtures/{orphan}/ does not correspond to any rule")
            )
    if result.fp is not None:
        for hit in result.fp.effective:
            pats = ", ".join(hit.patterns) or "condition only"
            issues.append(at_rule("YC701", hit.rule, f"matched goodware {hit.sample} ({hit.origin}; {pats})"))
        for entry in result.fp.expired_allowlist:
            issues.append(
                at_rule(
                    "YC702", entry.rule, f"allowlist entry for {entry.sha256[:12]} expired {entry.expires}"
                )
            )
    if result.profile is not None:
        for prof in result.profile.slow_rules:
            issues.append(at_rule("YC801", prof.rule, f"{prof.us_per_mb:,.0f} us/MiB: {prof.reason}"))
    minimum = pack.config.gate.min_grade
    if minimum:
        for card in result.cards:
            if not grade_at_least(card.grade, minimum):
                issues.append(
                    at_rule("YC901", card.rule, f"grade {card.grade} ({card.score}/100) below {minimum}")
                )
    return issues
