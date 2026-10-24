"""True-positive testing against per-rule fixtures.

Layout convention inside the pack's fixtures directory::

    fixtures/<RuleName>/match/<files>     every file MUST be matched by RuleName
    fixtures/<RuleName>/nomatch/<files>   no file may be matched by RuleName

Fixtures are scanned with the *whole* compiled pack, so tests exercise the rule
exactly as deployed (helper rules, globals and all). A public rule with no
``match`` fixture is reported as *untested*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from yaraci.corpus import Sample, iter_files, sha256
from yaraci.engine import CompiledRules
from yaraci.pack import RulePack

MATCH_DIR = "match"
NOMATCH_DIR = "nomatch"


@dataclass(frozen=True, slots=True)
class FixtureCase:
    rule: str
    expect_match: bool
    sample: Sample


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: FixtureCase
    matched: bool
    other_rules: tuple[str, ...]
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.matched == self.case.expect_match

    @property
    def label(self) -> str:
        kind = MATCH_DIR if self.case.expect_match else NOMATCH_DIR
        return f"{self.case.rule}/{kind}/{Path(self.case.sample.name).name}"


@dataclass(slots=True)
class TPReport:
    results: list[CaseResult] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)
    orphans: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed]

    def positives_for(self, rule: str) -> int:
        return sum(1 for r in self.results if r.case.rule == rule and r.case.expect_match)


def discover_fixtures(pack: RulePack) -> tuple[list[FixtureCase], list[str]]:
    """Return fixture cases and the names of fixture directories with no matching rule."""
    root = pack.config.resolve(pack.config.pack.fixtures)
    cases: list[FixtureCase] = []
    orphans: list[str] = []
    if not root.is_dir():
        return cases, orphans
    for rule_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if rule_dir.name not in pack.by_name:
            orphans.append(rule_dir.name)
            continue
        for kind, expect in ((MATCH_DIR, True), (NOMATCH_DIR, False)):
            for path in iter_files(rule_dir / kind):
                if path.name.startswith("."):
                    continue
                data = path.read_bytes()
                name = path.relative_to(root.parent).as_posix()
                cases.append(FixtureCase(rule_dir.name, expect, Sample(name, data, sha256(data), "fixture")))
    return cases, orphans


def run_tp(pack: RulePack, compiled: CompiledRules) -> TPReport:
    """Scan every fixture with the compiled pack and grade expectations."""
    cases, orphans = discover_fixtures(pack)
    report = TPReport(orphans=orphans)
    for case in cases:
        outcome = compiled.scan(case.sample.data)
        names = outcome.rule_names
        report.results.append(
            CaseResult(
                case=case,
                matched=case.rule in names,
                other_rules=tuple(sorted(names - {case.rule})),
                timed_out=outcome.timed_out,
            )
        )
    tested = {r.case.rule for r in report.results if r.case.expect_match}
    report.untested = [r.name for r in pack.public_rules if r.name not in tested]
    return report
