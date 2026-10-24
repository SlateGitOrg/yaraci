"""Committed profiling benchmark (``make bench``) -> bench/results.json + bench/RESULTS.md.

The corpus is synthetic and deterministic (seeded PRNG, generated in memory,
never written to disk): 48 files x 192 KiB = 9 MiB of random bytes, English-like
text, PE-shaped stubs with random bodies and base64 blocks. It contains no
malware and no real-world files, so absolute numbers only describe this corpus
on this machine; ratios between rules are the meaningful output.

Sections:
  A. per-rule profile of the regressed v2 pack on both engines;
  B. case study - the PowerShell rule before/after the anchoring fix;
  C. whole-pack throughput, v1 vs v2, both engines;
  D. profiler repeatability - spread of each v1 rule's cost over 3 runs;
  E. wall time of a full ``check`` (lint+TP+FP+profile) on v1.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import random
import statistics
import struct
import sys
import time
from pathlib import Path
from typing import Any

from yaraci.config import ProfileConfig
from yaraci.corpus import Sample, sha256
from yaraci.engine import SourceUnit, get_backend
from yaraci.pack import load_pack
from yaraci.pipeline import CheckOptions, run_check
from yaraci.profiling import MIB, ProfileReport, profile_pack, time_scans

ROOT = Path(__file__).resolve().parent.parent
FILES, SIZE, SEED = 48, 192 * 1024, 7
WORDS = [
    "the",
    "of",
    "and",
    "to",
    "in",
    "is",
    "for",
    "that",
    "with",
    "on",
    "as",
    "by",
    "this",
    "be",
    "are",
    "from",
    "at",
    "or",
    "an",
    "it",
    "config",
    "server",
    "file",
    "user",
]

PS_BEFORE = r"""rule PS_Before { strings:
  $ps = "powershell" nocase $enc1 = "-EncodedCommand" nocase
  $enc2 = /-enc?\s+[A-Za-z0-9+\/]{40,400}={0,2}/ nocase $hidden = /-w(indowstyle)?\s+hidden/ nocase
  condition: filesize < 1MB and $ps and any of ($enc*) and $hidden }"""
PS_AFTER = r"""rule PS_After { strings:
  $ps = "powershell" nocase $enc1 = "-EncodedCommand" nocase
  $enc2 = /\s-enc?\s{1,4}[A-Za-z0-9+\/]{40,400}/ nocase $hidden = /\s-w(indowstyle)?\s{1,4}hidden/ nocase
  condition: filesize < 1MB and $ps and any of ($enc*) and $hidden }"""


def corpus() -> list[Sample]:
    rng = random.Random(SEED)
    samples = []
    for i in range(FILES):
        kind = i % 4
        if kind == 0:
            data = rng.randbytes(SIZE)
        elif kind == 1:
            text = " ".join(rng.choice(WORDS) for _ in range(SIZE // 4))
            data = text.encode()[:SIZE]
        elif kind == 2:
            head = bytearray(1024)
            head[0:2] = b"MZ"
            struct.pack_into("<I", head, 0x3C, 0x80)
            head[0x80:0x84] = b"PE\0\0"
            data = bytes(head) + rng.randbytes(SIZE - 1024)
        else:
            blob = base64.b64encode(rng.randbytes(SIZE * 3 // 4)).decode()
            data = "\n".join(blob[j : j + 76] for j in range(0, len(blob), 76)).encode()[:SIZE]
        samples.append(Sample(f"synthetic/{i:02d}-{kind}", data, sha256(data), "bench"))
    return samples


def per_rule(report: ProfileReport) -> list[dict[str, Any]]:
    return [
        {"rule": r.rule, "us_per_mib": round(r.us_per_mb, 1), "slow": r.slow, "error": r.error}
        for r in report.rules
    ]


def run(out: Path) -> dict[str, Any]:
    samples = corpus()
    mib = sum(s.size for s in samples) / MIB
    cfg = ProfileConfig(repeat=5)
    v1, v2 = load_pack(ROOT / "examples/pack-v1"), load_pack(ROOT / "examples/pack-v2")
    results: dict[str, Any] = {
        "machine": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpus": os.cpu_count(),
        },
        "corpus": {"files": len(samples), "mib": round(mib, 2), "seed": SEED},
        "engines": {},
    }
    for engine in ("yara-x", "libyara"):
        backend = get_backend(engine)
        print(f"[{engine}] A. per-rule profile of v2", flush=True)
        v2_report = profile_pack(v2, backend, samples, cfg)
        print(f"[{engine}] B. PowerShell case study", flush=True)
        case = {}
        baseline = time_scans(
            backend.compile([SourceUnit("b", "rule b { condition: false }")]).rules,
            samples,
            5,
            time.perf_counter_ns,
        )
        for label, src in (("before", PS_BEFORE), ("after", PS_AFTER)):
            compiled = backend.compile([SourceUnit(label, src)]).rules
            times = time_scans(compiled, samples, 5, time.perf_counter_ns)
            case[label] = round(sum(times) / mib, 1)
        case["baseline_no_patterns_us_per_mib"] = round(sum(baseline) / mib, 1)
        print(f"[{engine}] C/D. pack throughput and repeatability", flush=True)
        v1_runs = [profile_pack(v1, backend, samples, cfg) for _ in range(3)]
        spread = {}
        for name in sorted(r.rule for r in v1_runs[0].rules):
            values = [next(r.us_per_mb for r in run_.rules if r.rule == name) for run_ in v1_runs]
            spread[name] = {"min": round(min(values), 1), "max": round(max(values), 1),
                            "median": round(statistics.median(values), 1)}  # fmt: skip
        results["engines"][engine] = {
            "version": backend.version,
            "v2_per_rule": per_rule(v2_report),
            "v2_slow_rules": [r.rule for r in v2_report.slow_rules],
            "ps_case_study_us_per_mib": case,
            "pack_mib_per_s": {
                "v1": round(statistics.median(r.pack_mb_per_s for r in v1_runs), 1),
                "v2": round(v2_report.pack_mb_per_s, 1),
            },
            "v1_repeatability_us_per_mib": spread,
            "v1_slow_rules_any_run": sorted({r.rule for run_ in v1_runs for r in run_.slow_rules}),
        }
    print("[yara-x] E. full check wall time on v1", flush=True)
    started = time.perf_counter()
    check = run_check(v1, get_backend("yara-x"), CheckOptions())
    results["check_v1_wall_s"] = round(time.perf_counter() - started, 2)
    results["check_v1_passed"] = check.gate.passed
    results["check_v1_goodware_samples"] = check.fp.samples if check.fp else 0
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    (out / "RESULTS.md").write_text(render(results))
    return results


def render(r: dict[str, Any]) -> str:
    m, c = r["machine"], r["corpus"]
    lines = [
        "# yaraci profiling benchmark",
        "",
        "Generated by `make bench` (`uv run python scripts/bench.py --out bench`). Do not edit by hand.",
        "",
        f"Machine: {m['platform']} ({m['machine']}, {m['cpus']} CPUs), Python {m['python']}. "
        f"Corpus: {c['files']} synthetic files, {c['mib']} MiB, seed {c['seed']} (see scripts/bench.py).",
        "Timings are min-of-5 per sample; the machine was shared with other jobs, so treat absolute",
        "numbers as indicative and ratios as the signal.",
        "",
    ]
    for engine, e in r["engines"].items():
        lines += [
            f"## {engine} {e['version']}",
            "",
            "### A. v2 per-rule cost (isolated, net of baseline)",
            "",
        ]
        lines += ["| Rule | us/MiB | Slow |", "|---|---:|---|"]
        for row in e["v2_per_rule"]:
            value = "n/a" if row["error"] else f"{row['us_per_mib']:,.1f}"
            lines.append(f"| `{row['rule']}` | {value} | {'yes' if row['slow'] else ''} |")
        ps = e["ps_case_study_us_per_mib"]
        lines += [
            "",
            "### B. PowerShell rule before/after anchoring (gross us/MiB, rule compiled alone)",
            "",
            f"before {ps['before']:,.1f}, after {ps['after']:,.1f}, "
            f"no-pattern baseline {ps['baseline_no_patterns_us_per_mib']:,.1f}",
            "",
            "### C. Whole-pack throughput",
            "",
            f"v1 {e['pack_mib_per_s']['v1']:,.1f} MiB/s, v2 {e['pack_mib_per_s']['v2']:,.1f} MiB/s",
            "",
            "### D. Repeatability of v1 rule costs over 3 profiler runs (us/MiB)",
            "",
            "| Rule | min | median | max |",
            "|---|---:|---:|---:|",
        ]
        for name, s in e["v1_repeatability_us_per_mib"].items():
            lines.append(f"| `{name}` | {s['min']:,.1f} | {s['median']:,.1f} | {s['max']:,.1f} |")
        flagged = ", ".join(e["v1_slow_rules_any_run"]) or "none"
        lines += ["", f"v1 rules flagged slow in any run: {flagged}", ""]
    lines += [
        "## E. End-to-end",
        "",
        f"Full `check` of v1 (lint, TP, FP, profile; yara-x): {r['check_v1_wall_s']} s wall, "
        f"gate passed: {r['check_v1_passed']}; goodware samples scanned: {r['check_v1_goodware_samples']} "
        "(includes fetched OSS wheels when `make goodware` has been run).",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the committed profiling benchmark.")
    parser.add_argument("--out", type=Path, default=ROOT / "bench")
    args = parser.parse_args(argv)
    run(args.out)
    print(f"wrote {args.out / 'results.json'} and {args.out / 'RESULTS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
