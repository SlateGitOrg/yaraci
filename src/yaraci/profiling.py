"""Per-rule scan-time profiling and slow-rule detection.

Method
------
Every rule is compiled *in isolation* (with its dependency closure) and each
corpus sample is scanned ``repeat`` times; the minimum is kept, because timing
noise on a shared machine is one-sided (interference only ever adds time). A
baseline rule set containing a single ``condition: false`` rule is timed the
same way and subtracted. The baseline holds one never-matching pattern with a
strong atom, so it pays for the engine's pattern-scan pass; the difference is
the cost the rule adds on top of a minimal rule::

    net(rule) = sum over samples of max(0, min_k t(rule, s) - min_k t(base, s))

Costs are normalised to microseconds per MiB scanned so packs and corpora of
different sizes compare. A rule is *slow* when either

* it exceeds the absolute budget (``budget_us_per_mb``), or
* it is a robust outlier: ``ratio >= slow_ratio`` against the pack median and a
  robust z-score ``(x - median) / (1.4826 * MAD) >= slow_z``, and it is above the
  noise floor (so a pack of uniformly fast rules flags nothing).

Median/MAD rather than mean/stddev: one pathological rule must not inflate the
statistics it is judged against. Cost is ``O(R * F * repeat)`` scans.
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from yaraci.config import ProfileConfig
from yaraci.corpus import Sample
from yaraci.engine import Backend, CompiledRules, RuleCompileError, SourceUnit
from yaraci.errors import ConfigError
from yaraci.pack import RulePack

log = logging.getLogger(__name__)

MIB = 1024 * 1024
# One never-matching pattern with a strong 9-byte atom: the baseline pays for the
# engine's scan pass, so a rule's net cost is what it adds on top of that pass.
BASELINE_SOURCE = (
    "rule yaraci_profile_baseline { strings: $a = { 79 61 72 61 63 69 00 FE ED } condition: $a }"
)
Clock = Callable[[], int]
METHODS = ("isolated", "leave-one-out")


@dataclass(slots=True)
class RuleProfile:
    rule: str
    net_us: float
    us_per_mb: float
    slowest_sample: str = ""
    slowest_us: float = 0.0
    timeouts: int = 0
    ratio: float = 0.0
    z: float = 0.0
    slow: bool = False
    reason: str = ""
    error: str = ""


@dataclass(slots=True)
class ProfileReport:
    engine: str
    engine_version: str
    samples: int
    corpus_bytes: int
    repeat: int
    method: str = "isolated"
    pack_us_per_mb: float = 0.0
    baseline_us_per_mb: float = 0.0
    median_us_per_mb: float = 0.0
    mad_us_per_mb: float = 0.0
    rules: list[RuleProfile] = field(default_factory=list)

    @property
    def slow_rules(self) -> list[RuleProfile]:
        return [r for r in self.rules if r.slow]

    @property
    def pack_mb_per_s(self) -> float:
        return MIB / self.pack_us_per_mb if self.pack_us_per_mb > 0 else math.inf


def time_scans(compiled: CompiledRules, samples: list[Sample], repeat: int, clock: Clock) -> list[float]:
    """Minimum-of-``repeat`` scan time (µs) per sample, plus timeouts as ``inf``."""
    out: list[float] = []
    for sample in samples:
        best = math.inf
        for _ in range(repeat):
            start = clock()
            outcome = compiled.scan(sample.data)
            elapsed = (clock() - start) / 1000.0
            if outcome.timed_out:
                best = math.inf
                break
            best = min(best, elapsed)
        out.append(best)
    return out


def classify(rules: list[RuleProfile], cfg: ProfileConfig) -> tuple[float, float]:
    """Mark slow rules in place; return ``(median, MAD)`` of µs/MiB."""
    values = [r.us_per_mb for r in rules if not r.error and math.isfinite(r.us_per_mb)]
    if not values:
        return 0.0, 0.0
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    scale = 1.4826 * mad
    for r in rules:
        if r.error:
            continue
        if r.timeouts:
            r.slow, r.reason = True, f"timed out on {r.timeouts} sample(s)"
            r.ratio = r.z = math.inf
            continue
        r.ratio = r.us_per_mb / median if median > 0 else (math.inf if r.us_per_mb > 0 else 1.0)
        if scale > 0:
            r.z = (r.us_per_mb - median) / scale
        else:
            r.z = math.inf if r.us_per_mb > median else 0.0
        if r.us_per_mb > cfg.budget_us_per_mb:
            r.slow = True
            r.reason = f"{r.us_per_mb:,.0f} us/MiB exceeds budget {cfg.budget_us_per_mb:,.0f}"
        elif r.ratio >= cfg.slow_ratio and r.z >= cfg.slow_z and r.us_per_mb >= cfg.noise_floor_us_per_mb:
            r.slow = True
            r.reason = f"{r.ratio:.1f}x pack median (robust z={r.z:.1f})"
    return median, mad


def _per_mb(total_us: float, corpus_bytes: int) -> float:
    return total_us / (corpus_bytes / MIB) if corpus_bytes else 0.0


def _summarise(name: str, nets: list[float], samples: list[Sample]) -> RuleProfile:
    finite = [n for n in nets if math.isfinite(n)]
    worst = max(range(len(nets)), key=lambda i: nets[i] if math.isfinite(nets[i]) else -1.0, default=-1)
    total = sum(finite)
    corpus_bytes = sum(s.size for s in samples)
    return RuleProfile(
        rule=name,
        net_us=total,
        us_per_mb=_per_mb(total, corpus_bytes),
        slowest_sample=samples[worst].name if worst >= 0 else "",
        slowest_us=nets[worst] if worst >= 0 and math.isfinite(nets[worst]) else 0.0,
        timeouts=len(nets) - len(finite),
    )


def _isolated(
    pack: RulePack,
    backend: Backend,
    name: str,
    samples: list[Sample],
    cfg: ProfileConfig,
    clock: Clock,
    base_times: list[float],
) -> RuleProfile:
    try:
        compiled = backend.compile([pack.isolated_unit(name)], pack.config.pack.scan_timeout_s).rules
    except RuleCompileError as exc:
        return RuleProfile(name, 0.0, 0.0, error=str(exc))
    times = time_scans(compiled, samples, cfg.repeat, clock)
    return _summarise(name, [max(0.0, t - b) for t, b in zip(times, base_times, strict=True)], samples)


def _leave_one_out(
    pack: RulePack,
    backend: Backend,
    name: str,
    samples: list[Sample],
    cfg: ProfileConfig,
    clock: Clock,
    full_times: list[float],
) -> RuleProfile:
    if pack.dependents(name):
        return RuleProfile(name, 0.0, 0.0, error="referenced by other rules; cannot be left out")
    try:
        compiled = backend.compile(pack.units_without(name), pack.config.pack.scan_timeout_s).rules
    except RuleCompileError as exc:
        return RuleProfile(name, 0.0, 0.0, error=str(exc))
    times = time_scans(compiled, samples, cfg.repeat, clock)
    return _summarise(name, [max(0.0, f - t) for f, t in zip(full_times, times, strict=True)], samples)


def profile_pack(
    pack: RulePack,
    backend: Backend,
    samples: list[Sample],
    cfg: ProfileConfig,
    clock: Clock = time.perf_counter_ns,
    rules: list[str] | None = None,
    method: str = "isolated",
) -> ProfileReport:
    """Profile every rule (or the named ``rules``) of ``pack`` over ``samples``.

    ``method="isolated"`` times each rule alone against the baseline;
    ``method="leave-one-out"`` times the full pack minus the rule, which also
    captures interaction effects (shared atoms) at the price of one full-pack
    compile per rule. Helper rules referenced by others cannot be left out.
    """
    if method not in METHODS:
        raise ConfigError(f"unknown profiling method {method!r}; choose one of {', '.join(METHODS)}")
    timeout = pack.config.pack.scan_timeout_s
    corpus_bytes = sum(s.size for s in samples)
    report = ProfileReport(
        engine=backend.name,
        engine_version=backend.version,
        samples=len(samples),
        corpus_bytes=corpus_bytes,
        repeat=cfg.repeat,
        method=method,
    )
    baseline = backend.compile([SourceUnit("<baseline>", BASELINE_SOURCE)], timeout).rules
    base_times = time_scans(baseline, samples, cfg.repeat, clock)
    report.baseline_us_per_mb = _per_mb(sum(base_times), corpus_bytes)
    full = backend.compile(pack.units, timeout).rules
    full_times = time_scans(full, samples, cfg.repeat, clock)
    pack_net = sum(max(0.0, t - b) for t, b in zip(full_times, base_times, strict=True))
    report.pack_us_per_mb = _per_mb(pack_net, corpus_bytes)
    for name in rules or [r.name for r in pack.rules]:
        if method == "leave-one-out":
            report.rules.append(_leave_one_out(pack, backend, name, samples, cfg, clock, full_times))
        else:
            report.rules.append(_isolated(pack, backend, name, samples, cfg, clock, base_times))
        log.debug("profiled %s", name)
    report.median_us_per_mb, report.mad_us_per_mb = classify(report.rules, cfg)
    report.rules.sort(key=lambda r: (-r.us_per_mb, r.rule))
    return report
