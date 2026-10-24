"""TP fixtures, goodware FP, profiling statistics, quality scoring and the gate."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import pytest

from conftest import TODAY, PackFactory, rule
from yaraci.config import GateConfig, ProfileConfig
from yaraci.corpus import CorpusBuilder, Sample, sha256
from yaraci.engine import CompileResult, RuleCompileError, ScanOutcome, SourceUnit, get_backend
from yaraci.errors import ConfigError
from yaraci.fp import run_fp
from yaraci.gate import GateFailure, evaluate
from yaraci.goodware import AllowEntry, Allowlist
from yaraci.lint import Finding, Severity
from yaraci.pack import RulePack
from yaraci.profiling import RuleProfile, classify, profile_pack, time_scans
from yaraci.quality import grade_at_least, grade_for, score_pack
from yaraci.testing import run_tp

FAST = rule("SUSP_Fast_Rule", 'strings: $a = "evilstring" condition: $a')
SLOW = rule("SUSP_Slow_Rule", 'strings: $a = "slowmarker" condition: $a')


# --------------------------------------------------------------------------- TP / FP
def test_tp_report(make_pack: PackFactory) -> None:
    pack = make_pack(
        {"r.yar": FAST + SLOW},
        fixtures={
            "SUSP_Fast_Rule/match/hit.txt": b"an evilstring here",
            "SUSP_Fast_Rule/match/miss.txt": b"nothing",
            "SUSP_Fast_Rule/nomatch/clean.txt": b"evilstring and slowmarker",
            "SUSP_Fast_Rule/match/.hidden": b"ignored",
            "Ghost_Rule/match/x.txt": b"x",
        },
    )
    compiled = get_backend("yara-x").compile(pack.units).rules
    report = run_tp(pack, compiled)
    assert len(report.results) == 3
    assert {r.label for r in report.failures} == {
        "SUSP_Fast_Rule/match/miss.txt",
        "SUSP_Fast_Rule/nomatch/clean.txt",
    }
    assert report.untested == ["SUSP_Slow_Rule"]
    assert report.orphans == ["Ghost_Rule"]
    assert report.positives_for("SUSP_Fast_Rule") == 2
    clean = next(r for r in report.results if r.case.sample.name.endswith("clean.txt"))
    assert clean.other_rules == ("SUSP_Slow_Rule",)


def test_tp_without_fixture_dir(make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": FAST})
    report = run_tp(pack, get_backend("yara-x").compile(pack.units).rules)
    assert report.results == []
    assert report.untested == ["SUSP_Fast_Rule"]


def test_fp_with_allowlist() -> None:
    corpus = CorpusBuilder()
    hit = corpus.add_bytes("doc.txt", b"evilstring", "bundled")
    corpus.add_bytes("other.txt", b"slowmarker", "system")
    corpus.add_bytes("clean.txt", b"clean", "bundled")
    assert hit is not None
    unit = SourceUnit("r.yar", FAST + SLOW)
    compiled = get_backend("libyara").compile([unit]).rules
    allow = Allowlist(
        active=[AllowEntry("SUSP_Fast_Rule", hit.sha256, "known", TODAY)],
        expired=[AllowEntry("SUSP_Slow_Rule", "0" * 64, "old", TODAY)],
    )
    report = run_fp(compiled, corpus, allow)
    assert report.samples == 3
    assert [h.rule for h in report.effective] == ["SUSP_Slow_Rule"]
    assert report.by_rule() == {"SUSP_Slow_Rule": 1}
    assert report.origins == {"bundled": 2, "system": 1}
    assert len(report.expired_allowlist) == 1


# --------------------------------------------------------------------------- profiling
@dataclass
class VirtualClock:
    now: int = 0

    def __call__(self) -> int:
        return self.now


@dataclass
class FakeCompiled:
    clock: VirtualClock
    ns_per_byte: int
    timeout: bool = False

    def scan(self, data: bytes) -> ScanOutcome:
        self.clock.now += self.ns_per_byte * len(data)
        return ScanOutcome((), timed_out=self.timeout)


@dataclass
class FakeBackend:
    """Scan cost is decided by markers in the compiled source: deterministic profiling."""

    clock: VirtualClock
    name: str = "fake"
    costs: dict[str, int] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return "0"

    def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
        text = "\n".join(u.text for u in units)
        if "BROKEN" in text:
            raise RuleCompileError([])
        cost = 1 + sum(c for marker, c in self.costs.items() if marker in text)
        return CompileResult(FakeCompiled(self.clock, cost, timeout="HANG" in text))


def _samples() -> list[Sample]:
    return [Sample(f"s{i}", b"x" * 1024 * (i + 1), sha256(bytes([i])), "corpus") for i in range(4)]


def test_profile_flags_slow_outlier(make_pack: PackFactory) -> None:
    rules = "".join(rule(f"SUSP_Rule_{i}", f'strings: $a = "marker{i}xx" condition: $a') for i in range(6))
    pack = make_pack({"r.yar": rules + SLOW})
    clock = VirtualClock()
    costs = {f"marker{i}xx": 2 + i % 2 for i in range(6)} | {"slowmarker": 5000}
    backend = FakeBackend(clock, costs=costs)
    cfg = ProfileConfig(repeat=2, noise_floor_us_per_mb=10.0)
    report = profile_pack(pack, backend, _samples(), cfg, clock=clock)
    assert [r.rule for r in report.slow_rules] == ["SUSP_Slow_Rule"]
    assert report.rules[0].rule == "SUSP_Slow_Rule"
    assert report.rules[0].slowest_sample == "s3"
    assert report.pack_us_per_mb > 0
    assert report.pack_mb_per_s > 0
    loo = profile_pack(pack, backend, _samples(), cfg, clock=clock, method="leave-one-out")
    assert loo.slow_rules[0].rule == "SUSP_Slow_Rule"
    with pytest.raises(ConfigError):
        profile_pack(pack, backend, _samples(), cfg, clock=clock, method="guess")


def test_profile_errors_timeouts_and_dependents(make_pack: PackFactory) -> None:
    helper = rule("INFO_Helper", "condition: uint8(0) == 1", prefix="private ")
    user = rule("SUSP_User", 'strings: $a = "zzzzzzzz" condition: INFO_Helper and $a')
    hang = rule("SUSP_Hang", 'strings: $a = "HANG" condition: $a')
    pack = make_pack({"r.yar": helper + user + hang})
    clock = VirtualClock()
    backend = FakeBackend(clock)
    report = profile_pack(pack, backend, _samples(), ProfileConfig(repeat=1), clock=clock)
    hung = next(r for r in report.rules if r.rule == "SUSP_Hang")
    assert hung.slow
    assert "timed out" in hung.reason
    loo = profile_pack(
        pack, backend, _samples(), ProfileConfig(repeat=1), clock=clock, method="leave-one-out"
    )
    helper_prof = next(r for r in loo.rules if r.rule == "INFO_Helper")
    assert "referenced" in helper_prof.error


def test_profile_compile_error_is_recorded(make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": FAST + rule("SUSP_Broken", 'strings: $a = "BROKEN1" condition: $a')})
    clock = VirtualClock()

    class PartlyBroken(FakeBackend):
        def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
            if len(units) == 1 and units[0].path.endswith("#SUSP_Broken"):
                raise RuleCompileError([])
            return super().compile([SourceUnit(u.path, u.text.replace("BROKEN", "ok")) for u in units])

    backend = PartlyBroken(clock)
    report = profile_pack(pack, backend, _samples(), ProfileConfig(repeat=1), clock=clock)
    assert next(r for r in report.rules if r.rule == "SUSP_Broken").error == "compilation failed"

    class NeedsFast(FakeBackend):
        def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
            if units[0].path != "<baseline>" and not any("SUSP_Fast_Rule" in u.text for u in units):
                raise RuleCompileError([])
            return super().compile([SourceUnit(u.path, u.text.replace("BROKEN", "ok")) for u in units])

    loo = profile_pack(
        pack, NeedsFast(clock), _samples(), ProfileConfig(repeat=1), clock=clock, method="leave-one-out"
    )
    assert next(r for r in loo.rules if r.rule == "SUSP_Fast_Rule").error == "compilation failed"


def test_time_scans_takes_minimum() -> None:
    clock = VirtualClock()
    compiled = FakeCompiled(clock, 1)
    assert time_scans(compiled, [Sample("a", b"x" * 2000, "h", "c")], 3, clock) == [2.0]


def test_classify_statistics() -> None:
    cfg = ProfileConfig(slow_ratio=4.0, slow_z=3.5, noise_floor_us_per_mb=10.0, budget_us_per_mb=1000.0)
    rules = [RuleProfile(f"r{i}", 0, v) for i, v in enumerate([10, 11, 12, 13, 100, 2000])]
    rules.append(RuleProfile("broken", 0, 0, error="x"))
    median, mad = classify(rules, cfg)
    assert median == 12.5
    assert mad > 0
    verdict = {r.rule: r.slow for r in rules}
    assert verdict == {
        "r0": False,
        "r1": False,
        "r2": False,
        "r3": False,
        "r4": True,
        "r5": True,
        "broken": False,
    }
    assert "budget" in rules[5].reason
    assert classify([], cfg) == (0.0, 0.0)
    flat = [RuleProfile("a", 0, 5.0), RuleProfile("b", 0, 5.0), RuleProfile("c", 0, 50.0)]
    classify(flat, cfg)
    assert flat[2].slow
    assert math.isinf(flat[2].z)
    zero = [RuleProfile("a", 0, 0.0), RuleProfile("b", 0, 0.0), RuleProfile("c", 0, 0.0)]
    classify(zero, cfg)
    assert not any(r.slow for r in zero)


# --------------------------------------------------------------------------- quality + gate
def test_scorecards_and_grades(make_pack: PackFactory) -> None:
    pack = make_pack(
        {"r.yar": FAST + SLOW + rule("INFO_Priv", "condition: uint8(0) == 1", prefix="private ")},
        fixtures={"SUSP_Fast_Rule/match/a.txt": b"evilstring"},
    )
    compiled = get_backend("yara-x").compile(pack.units).rules
    tp = run_tp(pack, compiled)
    corpus = CorpusBuilder()
    corpus.add_bytes("g.txt", b"slowmarker", "bundled")
    fp = run_fp(compiled, corpus, Allowlist())
    findings = [Finding("YC301", Severity.WARNING, "weak", rule="SUSP_Slow_Rule")]
    cards = {c.rule: c for c in score_pack(pack, findings, tp, fp)}
    assert cards["SUSP_Fast_Rule"].score == 100
    slow = cards["SUSP_Slow_Rule"]
    assert slow.score == 100 - 5 - 25 - 20
    assert slow.grade == "D"
    assert cards["INFO_Priv"].grade == "A"
    assert [grade_for(s) for s in (95, 80, 65, 45, 10)] == list("ABCDF")
    assert grade_at_least("B", "C")
    assert not grade_at_least("D", "C")


def test_gate_bitmask(make_pack: PackFactory) -> None:
    pack: RulePack = make_pack({"r.yar": FAST + SLOW}, fixtures={"SUSP_Fast_Rule/match/a.txt": b"nothing"})
    compiled = get_backend("yara-x").compile(pack.units).rules
    tp = run_tp(pack, compiled)
    corpus = CorpusBuilder()
    corpus.add_bytes("g.txt", b"evilstring", "bundled")
    fp = run_fp(compiled, corpus, Allowlist())
    findings = [
        Finding("YC201", Severity.ERROR, "x", rule="SUSP_Fast_Rule"),
        Finding("YC502", Severity.WARNING, "slow pattern"),
    ]
    cards = score_pack(pack, findings, tp, fp)
    result = evaluate(GateConfig(min_grade="B"), findings, True, tp, fp, None, cards)
    assert result.code == GateFailure.LINT | GateFailure.TP | GateFailure.FP | GateFailure.QUALITY
    assert not result.passed
    lenient = GateConfig(lint_fail_on="never", fail_on_tp=False, fail_on_untested=False, max_fp=5)
    assert evaluate(lenient, findings, True, tp, fp).passed
    strict = GateConfig(lint_fail_on="error", fail_on_compile_warnings=True)
    assert evaluate(strict, findings[1:], False).code == GateFailure.LINT | GateFailure.COMPILE
