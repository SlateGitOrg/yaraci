"""False-positive testing: any match on goodware is a finding unless allowlisted."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from yaraci.corpus import CorpusBuilder, CorpusStats
from yaraci.engine import CompiledRules
from yaraci.goodware import AllowEntry, Allowlist


@dataclass(frozen=True, slots=True)
class FPHit:
    rule: str
    sample: str
    sha256: str
    origin: str
    patterns: tuple[str, ...]
    allowed_by: AllowEntry | None = None


@dataclass(slots=True)
class FPReport:
    hits: list[FPHit] = field(default_factory=list)
    samples: int = 0
    bytes_scanned: int = 0
    timeouts: list[str] = field(default_factory=list)
    expired_allowlist: list[AllowEntry] = field(default_factory=list)
    corpus: CorpusStats = field(default_factory=CorpusStats)
    origins: dict[str, int] = field(default_factory=dict)

    @property
    def effective(self) -> list[FPHit]:
        """False positives that count against the gate (not allowlisted)."""
        return [h for h in self.hits if h.allowed_by is None]

    def by_rule(self) -> Counter[str]:
        return Counter(h.rule for h in self.effective)


def run_fp(compiled: CompiledRules, corpus: CorpusBuilder, allowlist: Allowlist) -> FPReport:
    """Scan every goodware sample once with the full pack (``O(total corpus bytes)``)."""
    report = FPReport(corpus=corpus.stats, expired_allowlist=list(allowlist.expired))
    origins: Counter[str] = Counter()
    for sample in corpus.samples:
        report.samples += 1
        report.bytes_scanned += sample.size
        origins[sample.origin] += 1
        outcome = compiled.scan(sample.data)
        if outcome.timed_out:
            report.timeouts.append(sample.name)
        for match in outcome.matches:
            report.hits.append(
                FPHit(
                    rule=match.rule,
                    sample=sample.name,
                    sha256=sample.sha256,
                    origin=sample.origin,
                    patterns=match.patterns,
                    allowed_by=allowlist.allows(match.rule, sample.sha256),
                )
            )
    report.origins = dict(origins)
    return report
