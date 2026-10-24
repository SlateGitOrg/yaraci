"""Machine-readable JSON documents for every command."""

from __future__ import annotations

import json
import math
from typing import Any

from yaraci import __version__
from yaraci.diff import DiffReport
from yaraci.lint import Finding
from yaraci.parity import ParityReport
from yaraci.pipeline import CheckResult
from yaraci.profiling import ProfileReport


def _num(value: float) -> float | str:
    return value if math.isfinite(value) else "inf"


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "code": f.code,
        "severity": f.severity.label,
        "message": f.message,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "rule": f.rule,
    }


def profile_dict(p: ProfileReport) -> dict[str, Any]:
    return {
        "engine": p.engine,
        "engine_version": p.engine_version,
        "method": p.method,
        "samples": p.samples,
        "corpus_bytes": p.corpus_bytes,
        "repeat": p.repeat,
        "baseline_us_per_mib": round(p.baseline_us_per_mb, 2),
        "pack_us_per_mib": round(p.pack_us_per_mb, 2),
        "pack_mib_per_s": _num(round(p.pack_mb_per_s, 1)),
        "median_us_per_mib": round(p.median_us_per_mb, 2),
        "mad_us_per_mib": round(p.mad_us_per_mb, 2),
        "rules": [
            {
                "rule": r.rule,
                "us_per_mib": round(r.us_per_mb, 2),
                "net_us": round(r.net_us, 1),
                "ratio_to_median": _num(round(r.ratio, 2)),
                "robust_z": _num(round(r.z, 2)),
                "slow": r.slow,
                "reason": r.reason,
                "slowest_sample": r.slowest_sample,
                "timeouts": r.timeouts,
                "error": r.error,
            }
            for r in p.rules
        ],
    }


def check_dict(result: CheckResult) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "tool": {"name": "yaraci", "version": __version__},
        "engine": {"name": result.engine, "version": result.engine_version},
        "pack": result.pack.config.pack.name or result.pack.root.name,
        "rules": len(result.pack.rules),
        "compiled": result.compiled,
        "gate": {
            "passed": result.gate.passed,
            "exit_code": int(result.gate.code),
            "reasons": result.gate.reasons,
        },
        "findings": [finding_dict(f) for f in result.findings],
        "scorecards": [
            {
                "rule": c.rule,
                "private": c.private,
                "score": c.score,
                "grade": c.grade,
                "lint": dict(c.lint),
                "positives": c.positives,
                "tp_failures": c.tp_failures,
                "false_positives": c.false_positives,
                "slow": c.slow,
                "deductions": c.deductions,
            }
            for c in result.cards
        ],
        "timings_s": {k: round(v, 3) for k, v in result.timings.items()},
    }
    if result.tp is not None:
        doc["tp"] = {
            "cases": [
                {
                    "rule": r.case.rule,
                    "fixture": r.case.sample.name,
                    "expect_match": r.case.expect_match,
                    "matched": r.matched,
                    "passed": r.passed,
                    "other_rules": list(r.other_rules),
                }
                for r in result.tp.results
            ],
            "untested": result.tp.untested,
            "orphans": result.tp.orphans,
        }
    if result.fp is not None:
        doc["fp"] = {
            "samples": result.fp.samples,
            "bytes": result.fp.bytes_scanned,
            "origins": result.fp.origins,
            "hits": [
                {
                    "rule": h.rule,
                    "sample": h.sample,
                    "sha256": h.sha256,
                    "origin": h.origin,
                    "patterns": list(h.patterns),
                    "allowlisted": h.allowed_by is not None,
                }
                for h in result.fp.hits
            ],
            "timeouts": result.fp.timeouts,
        }
    if result.profile is not None:
        doc["profile"] = profile_dict(result.profile)
    return doc


def diff_dict(report: DiffReport) -> dict[str, Any]:
    return {
        "summary": report.counts(),
        "new_fp": report.new_fp,
        "lost_tp": report.lost_tp,
        "removed_coverage": report.removed_coverage,
        "samples": report.samples,
        "changes": [
            {"rule": c.name, "kind": c.kind.value, "old_name": c.old_name, "details": c.details}
            for c in report.changes
        ],
        "impacts": [
            {
                "rule": i.rule,
                "old_name": i.old_name,
                "old_matches": i.old_matches,
                "new_matches": i.new_matches,
                "new_fp": i.new_fp,
                "fixed_fp": i.fixed_fp,
                "lost_tp": i.lost_tp,
                "gained_tp": i.gained_tp,
                "gained": i.gained,
                "lost": i.lost,
            }
            for i in report.impacts
        ],
    }


def parity_dict(report: ParityReport) -> dict[str, Any]:
    return {
        "engines": list(report.engines),
        "samples": report.samples,
        "consistent": report.consistent,
        "compile_errors": report.compile_errors,
        "only_left": report.only_left,
        "only_right": report.only_right,
    }


def dumps(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"
