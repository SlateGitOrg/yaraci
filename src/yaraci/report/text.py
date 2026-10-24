"""Human-readable renderers: console text and GitHub-flavoured Markdown."""

from __future__ import annotations

from collections import Counter

from yaraci.diff import ChangeKind, DiffReport
from yaraci.fp import FPReport
from yaraci.lint import Finding
from yaraci.parity import ParityReport
from yaraci.pipeline import CheckResult
from yaraci.profiling import MIB, ProfileReport
from yaraci.testing import TPReport

TOP_PROFILE_ROWS = 8


def _mib(n: int) -> str:
    return f"{n / MIB:.2f} MiB"


def _throughput(profile: ProfileReport) -> str:
    rate = profile.pack_mb_per_s
    return "n/a" if rate == float("inf") else f"{rate:,.0f} MiB/s"


def render_findings(findings: list[Finding]) -> list[str]:
    lines = []
    for f in findings:
        where = f"{f.path}:{f.line}" if f.path else "<pack>"
        rule = f" [{f.rule}]" if f.rule else ""
        lines.append(f"  {f.severity.label:<7} {f.code} {where}{rule} {f.message}")
    return lines


def lint_summary(findings: list[Finding]) -> str:
    counts = Counter(f.severity.label for f in findings)
    return f"{counts['error']} error, {counts['warning']} warning, {counts['info']} info"


def render_tp(tp: TPReport) -> list[str]:
    passed = len(tp.results) - len(tp.failures)
    lines = [
        f"TP       {len(tp.results)} fixture(s): {passed} passed, {len(tp.failures)} failed; "
        f"untested: {', '.join(tp.untested) or 'none'}"
    ]
    for res in tp.failures:
        want = "match" if res.case.expect_match else "not match"
        lines.append(f"  FAIL {res.label}: expected to {want}")
    if tp.orphans:
        lines.append(f"  orphan fixture dirs: {', '.join(tp.orphans)}")
    return lines


def render_fp(fp: FPReport) -> list[str]:
    origins = ", ".join(f"{k} {v}" for k, v in sorted(fp.origins.items())) or "none"
    lines = [
        f"FP       {fp.samples} goodware sample(s) ({_mib(fp.bytes_scanned)}; {origins}; "
        f"{fp.corpus.archive_members} archive member(s)): {len(fp.effective)} match(es), "
        f"{len(fp.hits) - len(fp.effective)} allowlisted"
    ]
    for hit in fp.effective:
        lines.append(
            f"  FP   {hit.rule} <- {hit.sample} [{hit.origin}] ({', '.join(hit.patterns) or 'condition'})"
        )
    for entry in fp.expired_allowlist:
        lines.append(f"  expired allowlist entry: {entry.rule} {entry.sha256[:12]} ({entry.expires})")
    return lines


def render_profile(profile: ProfileReport, rows: int = TOP_PROFILE_ROWS) -> list[str]:
    lines = [
        f"PROFILE  {profile.method}, {profile.samples} sample(s) / {_mib(profile.corpus_bytes)} "
        f"x{profile.repeat} on {profile.engine} {profile.engine_version}",
        f"  full pack: {profile.pack_us_per_mb:,.0f} us/MiB above baseline ({_throughput(profile)} overall); "
        f"median rule: {profile.median_us_per_mb:,.1f} us/MiB",
        f"  {'rule':<38} {'us/MiB':>10} {'x median':>9}  slowest sample",
    ]
    for prof in profile.rules[:rows]:
        if prof.error:
            lines.append(f"  {prof.rule:<38} {'-':>10} {'-':>9}  ({prof.error})")
            continue
        ratio = "inf" if prof.ratio == float("inf") else f"{prof.ratio:.1f}"
        flag = "  SLOW" if prof.slow else ""
        lines.append(f"  {prof.rule:<38} {prof.us_per_mb:>10,.1f} {ratio:>9}  {prof.slowest_sample}{flag}")
    if len(profile.rules) > rows:
        lines.append(f"  ... {len(profile.rules) - rows} more")
    return lines


def render_check(result: CheckResult, verbose: bool = False) -> str:
    pack = result.pack
    lines = [
        f"yaraci check {pack.config.pack.name or pack.root.name}: {len(pack.rules)} rule(s) in "
        f"{len(pack.units)} file(s), engine {result.engine} {result.engine_version}",
        f"LINT     {lint_summary(result.findings)}",
    ]
    shown = result.findings if verbose else [f for f in result.findings if f.severity.label != "info"]
    lines += render_findings(shown)
    lines.append(f"COMPILE  {'ok' if result.compiled else 'FAILED (scan stages skipped)'}")
    if result.tp is not None:
        lines += render_tp(result.tp)
    if result.fp is not None:
        lines += render_fp(result.fp)
    if result.profile is not None:
        lines += render_profile(result.profile, len(result.profile.rules) if verbose else TOP_PROFILE_ROWS)
    lines.append("SCORECARD")
    for card in result.cards:
        notes = "; ".join(card.deductions) or "clean"
        kind = " (private)" if card.private else ""
        lines.append(f"  {card.grade} {card.score:>3}  {card.rule}{kind}  {notes}")
    verdict = "PASS" if result.gate.passed else "FAIL"
    lines.append(f"GATE     {verdict} (exit {int(result.gate.code)})")
    lines += [f"  - {reason}" for reason in result.gate.reasons]
    return "\n".join(lines) + "\n"


def render_check_markdown(result: CheckResult) -> str:
    pack = result.pack
    verdict = "PASS" if result.gate.passed else "FAIL"
    out = [
        f"## yaraci: {pack.config.pack.name or pack.root.name} - {verdict}",
        "",
        f"Engine `{result.engine} {result.engine_version}`, {len(pack.rules)} rules, gate exit "
        f"`{int(result.gate.code)}`.",
        "",
    ]
    out += [f"- {reason}" for reason in result.gate.reasons] + ([""] if result.gate.reasons else [])
    out += [
        "| Grade | Score | Rule | Lint | TP fixtures | Goodware hits | us/MiB | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c in result.cards:
        lint = ", ".join(f"{n} {sev}" for sev, n in sorted(c.lint.items())) or "-"
        cost = "-" if c.us_per_mb is None else f"{c.us_per_mb:,.1f}"
        out.append(
            f"| {c.grade} | {c.score} | `{c.rule}` | {lint} | {c.positives} (fail {c.tp_failures}) | "
            f"{c.false_positives} | {cost} | {'; '.join(c.deductions) or 'clean'} |"
        )
    return "\n".join(out) + "\n"


def render_diff(report: DiffReport) -> str:
    counts = report.counts()
    summary = ", ".join(f"{counts[k.value]} {k.value}" for k in ChangeKind if counts.get(k.value))
    lines = [
        f"yaraci diff: {summary or 'no rules'}",
        f"corpus: {report.samples} sample(s) ({report.goodware_samples} goodware, "
        f"{report.fixture_samples} fixture)",
    ]
    for change in report.changes:
        if change.kind is ChangeKind.UNCHANGED:
            continue
        label = f"{change.old_name} -> {change.name}" if change.old_name else change.name
        lines.append(f"  {change.kind.value:<9} {label}")
        lines += [f"      {d}" for d in change.details]
    lines.append("impact (matches old -> new; only rules whose matches changed):")
    for imp in report.impacts:
        if not (imp.gained or imp.lost):
            continue
        name = f"{imp.old_name} -> {imp.rule}" if imp.old_name else imp.rule
        lines.append(f"  {name}: {imp.old_matches} -> {imp.new_matches}")
        for label, items in (
            ("NEW FP", imp.new_fp),
            ("fixed FP", imp.fixed_fp),
            ("LOST TP", imp.lost_tp),
            ("gained TP", imp.gained_tp),
        ):
            lines += [f"      {label}: {s}" for s in items]
        other = set(imp.gained + imp.lost) - set(imp.new_fp + imp.fixed_fp + imp.lost_tp + imp.gained_tp)
        lines += [f"      changed: {s}" for s in sorted(other)]
    lines.append(
        f"verdict: {report.new_fp} new FP, {report.lost_tp} lost TP, "
        f"{report.removed_coverage} fixture(s) uncovered by removed rules"
    )
    return "\n".join(lines) + "\n"


def render_diff_markdown(report: DiffReport) -> str:
    out = [
        "## yaraci rule-set diff",
        "",
        f"**{report.new_fp} new false positive(s)**, **{report.lost_tp} lost true positive(s)** over "
        f"{report.samples} samples ({report.goodware_samples} goodware, {report.fixture_samples} fixtures).",
        "",
        "| Change | Rule | Details |",
        "|---|---|---|",
    ]
    for c in report.changes:
        if c.kind is ChangeKind.UNCHANGED:
            continue
        label = f"`{c.old_name}` -> `{c.name}`" if c.old_name else f"`{c.name}`"
        details = "<br>".join(d.replace("|", "\\|") for d in c.details) or "-"
        out.append(f"| {c.kind.value} | {label} | {details} |")
    out += [
        "",
        "| Rule | Matches old -> new | New FP | Lost TP | Fixed FP | Gained TP |",
        "|---|---|---|---|---|---|",
    ]
    for imp in report.impacts:
        if imp.gained or imp.lost:
            out.append(
                f"| `{imp.rule}` | {imp.old_matches} -> {imp.new_matches} | {len(imp.new_fp)} | "
                f"{len(imp.lost_tp)} | {len(imp.fixed_fp)} | {len(imp.gained_tp)} |"
            )
    return "\n".join(out) + "\n"


def render_parity(report: ParityReport) -> str:
    left, right = report.engines
    lines = [f"yaraci parity: {left} vs {right} over {report.samples} sample(s)"]
    for engine, err in report.compile_errors.items():
        lines.append(f"  {engine} failed to compile: {err}")
    for rule in report.divergent_rules:
        for sample in report.only_left.get(rule, []):
            lines.append(f"  {rule}: only {left} matched {sample}")
        for sample in report.only_right.get(rule, []):
            lines.append(f"  {rule}: only {right} matched {sample}")
    lines.append(
        "verdict: "
        + ("consistent" if report.consistent else f"{len(report.divergent_rules)} divergent rule(s)")
    )
    return "\n".join(lines) + "\n"
