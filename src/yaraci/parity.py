"""Engine parity: does the pack behave the same under libyara and YARA-X?

Teams migrating from libyara to YARA-X need to know which rules change
behaviour. Both engines compile the pack and scan the same samples; any rule
whose set of matched samples differs is reported with the differing samples.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from yaraci.corpus import Sample
from yaraci.engine import Backend, RuleCompileError
from yaraci.pack import RulePack


@dataclass(slots=True)
class ParityReport:
    engines: tuple[str, str]
    samples: int = 0
    compile_errors: dict[str, str] = field(default_factory=dict)
    only_left: dict[str, list[str]] = field(default_factory=dict)
    only_right: dict[str, list[str]] = field(default_factory=dict)

    @property
    def divergent_rules(self) -> list[str]:
        return sorted(self.only_left.keys() | self.only_right.keys())

    @property
    def consistent(self) -> bool:
        return not self.compile_errors and not self.divergent_rules


def check_parity(pack: RulePack, left: Backend, right: Backend, samples: list[Sample]) -> ParityReport:
    """Compare per-rule match sets of two engines over ``samples`` (``O(samples)`` scans each)."""
    report = ParityReport((left.name, right.name), len(samples))
    compiled = {}
    for backend in (left, right):
        try:
            compiled[backend.name] = backend.compile(pack.units, pack.config.pack.scan_timeout_s).rules
        except RuleCompileError as exc:
            report.compile_errors[backend.name] = str(exc)
    if report.compile_errors:
        return report
    only_left: dict[str, list[str]] = defaultdict(list)
    only_right: dict[str, list[str]] = defaultdict(list)
    for sample in samples:
        a = compiled[left.name].scan(sample.data).rule_names
        b = compiled[right.name].scan(sample.data).rule_names
        for rule in a - b:
            only_left[rule].append(sample.name)
        for rule in b - a:
            only_right[rule].append(sample.name)
    report.only_left, report.only_right = dict(only_left), dict(only_right)
    return report
