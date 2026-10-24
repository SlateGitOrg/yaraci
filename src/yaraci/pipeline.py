"""End-to-end ``check`` pipeline: lint -> compile -> TP -> FP -> profile -> score -> gate."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from yaraci.corpus import CorpusBuilder, Sample
from yaraci.engine import Backend, CompiledRules
from yaraci.fp import FPReport, run_fp
from yaraci.gate import GateResult, evaluate
from yaraci.goodware import build_goodware_corpus, limits_for, load_allowlist
from yaraci.lint import Finding, apply_policy, compile_findings, static_findings
from yaraci.pack import RulePack
from yaraci.profiling import ProfileReport, profile_pack
from yaraci.quality import Scorecard, score_pack
from yaraci.testing import TPReport, discover_fixtures, run_tp

log = logging.getLogger(__name__)

STAGES = ("lint", "tp", "fp", "profile")


@dataclass(slots=True)
class CheckOptions:
    stages: tuple[str, ...] = STAGES
    include_system: bool | None = None
    extra_goodware: list[Path] = field(default_factory=list)
    profile_corpus: list[Path] = field(default_factory=list)
    repeat: int | None = None
    method: str = "isolated"
    today: date | None = None


@dataclass(slots=True)
class CheckResult:
    pack: RulePack
    engine: str
    engine_version: str
    findings: list[Finding]
    compiled: bool
    gate: GateResult
    tp: TPReport | None = None
    fp: FPReport | None = None
    profile: ProfileReport | None = None
    cards: list[Scorecard] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)


def profile_samples(pack: RulePack, opts: CheckOptions, goodware: CorpusBuilder | None) -> list[Sample]:
    """Samples for profiling: configured/explicit corpus dirs, else goodware + fixtures.

    The corpus is truncated (whole samples, in a deterministic order) at
    ``[profile].max_corpus_bytes`` to bound memory and run time.
    """
    builder = CorpusBuilder(limits=limits_for(pack.config))
    dirs = opts.profile_corpus or [pack.config.resolve(c) for c in pack.config.profile.corpus]
    if dirs:
        for path in dirs:
            builder.add_tree(path, "corpus")
        samples = builder.samples
    else:
        samples = list(goodware.samples) if goodware else []
        samples += [c.sample for c in discover_fixtures(pack)[0]]
    budget = pack.config.profile.max_corpus_bytes
    chosen: list[Sample] = []
    for sample in samples:
        if budget - sample.size < 0:
            break
        budget -= sample.size
        chosen.append(sample)
    return chosen


def run_check(pack: RulePack, backend: Backend, opts: CheckOptions | None = None) -> CheckResult:
    """Run the selected stages and evaluate the gate."""
    opts = opts or CheckOptions()
    cfg = pack.config
    today = opts.today or date.today()
    timings: dict[str, float] = {}

    started = time.perf_counter()
    static = static_findings(pack, today) if "lint" in opts.stages else []
    engine_findings, compile_result = compile_findings(pack, backend)
    findings = apply_policy(pack, static + engine_findings)
    timings["lint+compile"] = time.perf_counter() - started
    compiled: CompiledRules | None = compile_result.rules if compile_result else None

    tp = fp = None
    profile = None
    goodware: CorpusBuilder | None = None
    if compiled is not None:
        if "tp" in opts.stages:
            started = time.perf_counter()
            tp = run_tp(pack, compiled)
            timings["tp"] = time.perf_counter() - started
        if "fp" in opts.stages:
            started = time.perf_counter()
            goodware = build_goodware_corpus(cfg, opts.include_system, opts.extra_goodware)
            allow = load_allowlist(cfg.resolve(cfg.goodware.allowlist), today)
            fp = run_fp(compiled, goodware, allow)
            timings["fp"] = time.perf_counter() - started
        if "profile" in opts.stages:
            started = time.perf_counter()
            if opts.repeat is not None:
                cfg.profile.repeat = opts.repeat
            samples = profile_samples(pack, opts, goodware)
            profile = profile_pack(pack, backend, samples, cfg.profile, method=opts.method)
            timings["profile"] = time.perf_counter() - started

    cards = score_pack(pack, findings, tp, fp, profile)
    gate = evaluate(cfg.gate, findings, compiled is not None, tp, fp, profile, cards)
    return CheckResult(
        pack=pack,
        engine=backend.name,
        engine_version=backend.version,
        findings=findings,
        compiled=compiled is not None,
        gate=gate,
        tp=tp,
        fp=fp,
        profile=profile,
        cards=cards,
        timings=timings,
    )
