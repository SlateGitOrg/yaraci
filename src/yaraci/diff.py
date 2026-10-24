"""Rule-set diff: what changed between two pack versions, and what it does.

**Structural diff.** Each rule is reduced to a *logic key* (flags, tags, the
canonical rendering of every string and the canonical condition text) and a
*meta key*. Comparing keys separates:

* ``modified``  - detection logic changed;
* ``metadata``  - only meta changed;
* ``cosmetic``  - source text changed but neither key did (whitespace, comments,
  ``0x10`` vs ``16``, string modifier order, ...);
* ``renamed``   - a removed and an added rule share a logic key (paired 1:1 in
  name order);
* ``added`` / ``removed`` / ``unchanged``.

**Impact diff.** Both versions are compiled and every sample of a shared corpus
(both packs' fixtures plus goodware) is scanned with each, ``O(samples)`` scans
per version. Match sets are compared per rule (following renames) and every
change is classified: on goodware a new match is a **new false positive**; on a
fixture whose expectation says "match", a lost match is a **lost true
positive**. These two classes are the regression gate for rule changes.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from yaraci.corpus import CorpusBuilder, Sample
from yaraci.engine import Backend
from yaraci.pack import PackRule, RulePack
from yaraci.syntax import render_string, unparse
from yaraci.testing import discover_fixtures

REMOVED_SUFFIX = " (removed)"


class ChangeKind(Enum):
    ADDED = "added"
    REMOVED = "removed"
    RENAMED = "renamed"
    MODIFIED = "modified"
    METADATA = "metadata"
    COSMETIC = "cosmetic"
    UNCHANGED = "unchanged"


@dataclass(slots=True)
class RuleChange:
    name: str
    kind: ChangeKind
    old_name: str | None = None
    details: list[str] = field(default_factory=list)


def _strings(pr: PackRule) -> dict[str, str]:
    out: dict[str, str] = {}
    for idx, sdef in enumerate(pr.rule.strings):
        key = sdef.identifier if not sdef.is_anonymous else f"$#{idx}"
        out[key] = render_string(sdef)
    return out


def logic_key(pr: PackRule) -> tuple[object, ...]:
    r = pr.rule
    return (
        r.is_private,
        r.is_global,
        tuple(sorted(r.tags)),
        tuple(sorted(_strings(pr).items())),
        unparse(r.condition),
    )


def meta_key(pr: PackRule) -> tuple[tuple[str, str], ...]:
    return tuple((m.key, repr(m.value)) for m in pr.rule.meta)


def _shorten(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def explain_change(old: PackRule, new: PackRule) -> list[str]:
    """Human-readable list of logic and metadata differences between two rules."""
    details: list[str] = []
    o, n = old.rule, new.rule
    if (o.is_private, o.is_global) != (n.is_private, n.is_global):
        details.append(f"flags: private={o.is_private}->{n.is_private}, global={o.is_global}->{n.is_global}")
    if sorted(o.tags) != sorted(n.tags):
        details.append(f"tags: {list(o.tags)} -> {list(n.tags)}")
    os_, ns = _strings(old), _strings(new)
    for ident in sorted(ns.keys() - os_.keys()):
        details.append(f"string added {ident} = {_shorten(ns[ident])}")
    for ident in sorted(os_.keys() - ns.keys()):
        details.append(f"string removed {ident} = {_shorten(os_[ident])}")
    for ident in sorted(os_.keys() & ns.keys()):
        if os_[ident] != ns[ident]:
            details.append(f"string changed {ident}: {_shorten(os_[ident])} -> {_shorten(ns[ident])}")
    oc, nc = unparse(o.condition), unparse(n.condition)
    if oc != nc:
        details.append(f"condition: {_shorten(oc)} -> {_shorten(nc)}")
    om, nm = dict(meta_key(old)), dict(meta_key(new))
    changed_meta = sorted(k for k in om.keys() | nm.keys() if om.get(k) != nm.get(k))
    if changed_meta:
        details.append(f"meta changed: {', '.join(changed_meta)}")
    return details


def classify_pair(old: PackRule, new: PackRule) -> ChangeKind:
    """Kind of change between two versions of the same-named rule."""
    if logic_key(old) != logic_key(new):
        return ChangeKind.MODIFIED
    if meta_key(old) != meta_key(new):
        return ChangeKind.METADATA
    if old.source_text != new.source_text:
        return ChangeKind.COSMETIC
    return ChangeKind.UNCHANGED


def structural_diff(old: RulePack, new: RulePack) -> list[RuleChange]:
    """Classify every rule of both packs (``O(R log R)``)."""
    changes: list[RuleChange] = []
    removed = [r for r in old.rules if r.name not in new.by_name]
    added = [r for r in new.rules if r.name not in old.by_name]
    by_logic: dict[tuple[object, ...], list[PackRule]] = defaultdict(list)
    for r in sorted(removed, key=lambda r: r.name):
        by_logic[logic_key(r)].append(r)
    renamed_from: dict[str, PackRule] = {}
    for r in sorted(added, key=lambda r: r.name):
        candidates = by_logic.get(logic_key(r))
        if candidates:
            renamed_from[r.name] = candidates.pop(0)
    consumed = {r.name for r in renamed_from.values()}
    for new_rule in new.rules:
        name = new_rule.name
        if name in renamed_from:
            prev = renamed_from[name]
            changes.append(RuleChange(name, ChangeKind.RENAMED, prev.name, explain_change(prev, new_rule)))
        elif name not in old.by_name:
            changes.append(RuleChange(name, ChangeKind.ADDED))
        else:
            prev = old.get(name)
            changes.append(
                RuleChange(name, classify_pair(prev, new_rule), None, explain_change(prev, new_rule))
            )
    for r in removed:
        if r.name not in consumed:
            changes.append(RuleChange(r.name, ChangeKind.REMOVED))
    return changes


# --------------------------------------------------------------------------- impact
@dataclass(slots=True)
class RuleImpact:
    rule: str
    old_name: str | None
    old_matches: int = 0
    new_matches: int = 0
    gained: list[str] = field(default_factory=list)
    lost: list[str] = field(default_factory=list)
    new_fp: list[str] = field(default_factory=list)
    fixed_fp: list[str] = field(default_factory=list)
    lost_tp: list[str] = field(default_factory=list)
    gained_tp: list[str] = field(default_factory=list)

    @property
    def removed(self) -> bool:
        return self.rule.endswith(REMOVED_SUFFIX)

    @property
    def names(self) -> set[str]:
        """Every name this rule had in either version."""
        return {self.rule.removesuffix(REMOVED_SUFFIX), self.old_name or ""} - {""}


@dataclass(slots=True)
class DiffReport:
    changes: list[RuleChange]
    impacts: list[RuleImpact]
    samples: int
    goodware_samples: int
    fixture_samples: int
    old_timeouts: int = 0
    new_timeouts: int = 0

    @property
    def new_fp(self) -> int:
        return sum(len(i.new_fp) for i in self.impacts)

    @property
    def lost_tp(self) -> int:
        """Lost true positives of rules that still exist (removals are reported separately)."""
        return sum(len(i.lost_tp) for i in self.impacts if not i.removed)

    @property
    def removed_coverage(self) -> int:
        return sum(len(i.lost_tp) for i in self.impacts if i.removed)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for c in self.changes:
            out[c.kind.value] += 1
        return dict(out)


@dataclass(slots=True)
class _Expectations:
    """Per sample digest: rules that must match it and rules that must not."""

    samples: list[Sample]
    must_match: dict[str, set[str]]
    must_not: dict[str, set[str]]


def _expectations(packs: list[RulePack]) -> _Expectations:
    samples: dict[str, Sample] = {}
    must: dict[str, set[str]] = defaultdict(set)
    must_not: dict[str, set[str]] = defaultdict(set)
    for pack in packs:
        for case in discover_fixtures(pack)[0]:
            samples.setdefault(case.sample.sha256, case.sample)
            (must if case.expect_match else must_not)[case.sample.sha256].add(case.rule)
    return _Expectations(list(samples.values()), must, must_not)


def impact_diff(old: RulePack, new: RulePack, backend: Backend, goodware: CorpusBuilder) -> DiffReport:
    """Scan fixtures + goodware with both versions and attribute match changes per rule."""
    changes = structural_diff(old, new)
    old_compiled = backend.compile(old.units, old.config.pack.scan_timeout_s).rules
    new_compiled = backend.compile(new.units, new.config.pack.scan_timeout_s).rules
    expect = _expectations([old, new])
    goodware_ids = {s.sha256 for s in goodware.samples}
    corpus: dict[str, Sample] = {s.sha256: s for s in goodware.samples}
    for s in expect.samples:
        corpus.setdefault(s.sha256, s)

    renames = {c.name: c.old_name for c in changes if c.kind is ChangeKind.RENAMED}
    impacts: dict[str, RuleImpact] = {}
    for c in changes:
        old_name = renames.get(c.name) or (c.name if c.kind is not ChangeKind.ADDED else None)
        new_key = c.name if c.kind is not ChangeKind.REMOVED else c.name + REMOVED_SUFFIX
        impacts[new_key] = RuleImpact(new_key, old_name if old_name != c.name else None)
    old_to_key = {imp.old_name or imp.rule: key for key, imp in impacts.items()}
    for key in impacts:
        if key.endswith(REMOVED_SUFFIX):
            old_to_key[key.removesuffix(REMOVED_SUFFIX)] = key

    report = DiffReport(changes, [], len(corpus), len(goodware_ids), len(expect.samples))
    for digest, sample in corpus.items():
        old_out, new_out = old_compiled.scan(sample.data), new_compiled.scan(sample.data)
        report.old_timeouts += old_out.timed_out
        report.new_timeouts += new_out.timed_out
        old_hits = {old_to_key[r] for r in old_out.rule_names if r in old_to_key}
        new_hits = {r for r in new_out.rule_names if r in impacts}
        for key in old_hits | new_hits:
            imp = impacts[key]
            was, now = key in old_hits, key in new_hits
            imp.old_matches += was
            imp.new_matches += now
            if was == now:
                continue
            (imp.gained if now else imp.lost).append(sample.name)
            # Goodware and curated negative fixtures must never match: a change there is an FP delta.
            if digest in goodware_ids or imp.names & expect.must_not[digest]:
                (imp.new_fp if now else imp.fixed_fp).append(sample.name)
            elif imp.names & expect.must_match[digest]:
                (imp.gained_tp if now else imp.lost_tp).append(sample.name)
    order = {c.name: i for i, c in enumerate(changes)}
    report.impacts = sorted(impacts.values(), key=lambda i: order.get(i.rule.removesuffix(REMOVED_SUFFIX), 0))
    return report
