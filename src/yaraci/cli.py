"""Command-line interface: ``yaraci <command> ...``.

Every command prints a human report (or JSON/Markdown with ``--format``) and
exits with a gate code; see :mod:`yaraci.gate` for the bitmask.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from yaraci import __version__
from yaraci.corpus import CorpusBuilder
from yaraci.diff import impact_diff
from yaraci.engine import BACKENDS, Backend, get_backend
from yaraci.errors import YaraciError
from yaraci.gate import EXIT_INTERNAL, EXIT_USAGE, GateFailure
from yaraci.goodware import build_goodware_corpus, fetch_packages, limits_for, load_manifest
from yaraci.lint import SPECS, Severity
from yaraci.pack import RulePack, load_pack
from yaraci.parity import check_parity
from yaraci.pipeline import STAGES, CheckOptions, profile_samples, run_check
from yaraci.profiling import METHODS, profile_pack
from yaraci.report import (
    check_dict,
    diff_dict,
    dumps,
    parity_dict,
    profile_dict,
    render_check,
    render_check_markdown,
    render_diff,
    render_diff_markdown,
    render_findings,
    render_parity,
    render_profile,
    write_junit,
    write_sarif,
)
from yaraci.report.model import STAGE_CODES
from yaraci.report.text import lint_summary, render_fp, render_tp

log = logging.getLogger("yaraci")

DEFAULT_MANIFEST = Path("goodware/oss-manifest.toml")
DEFAULT_FETCH_DEST = Path(".cache/goodware")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    log.info("wrote %s", path)


def _emit(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _load(args: argparse.Namespace, pack_dir: Path | None = None) -> tuple[RulePack, Backend]:
    pack = load_pack(pack_dir or args.pack, args.config)
    if args.engine:
        pack.config.pack.engine = args.engine
    return pack, get_backend(pack.config.pack.engine)


def _stages(text: str) -> tuple[str, ...]:
    chosen = tuple(s.strip() for s in text.split(",") if s.strip())
    unknown = set(chosen) - set(STAGES)
    if unknown or not chosen:
        raise argparse.ArgumentTypeError(f"stages must be a comma list of {', '.join(STAGES)}")
    return chosen


# --------------------------------------------------------------------------- commands
def cmd_check(args: argparse.Namespace) -> int:
    pack, backend = _load(args)
    opts = CheckOptions(
        stages=args.stages,
        include_system=True if args.system else None,
        extra_goodware=args.goodware or [],
        profile_corpus=args.corpus or [],
        repeat=args.repeat,
        method=args.method,
    )
    result = run_check(pack, backend, opts)
    if args.junit:
        _write(args.junit, write_junit(result))
    if args.sarif:
        _write(args.sarif, write_sarif(result))
    if args.json:
        _write(args.json, dumps(check_dict(result)))
    if args.markdown:
        _write(args.markdown, render_check_markdown(result))
    if args.format == "json":
        _emit(dumps(check_dict(result)))
    elif args.format == "markdown":
        _emit(render_check_markdown(result))
    else:
        _emit(render_check(result, verbose=args.verbose))
    return int(result.gate.code)


def cmd_lint(args: argparse.Namespace) -> int:
    pack, backend = _load(args)
    result = run_check(pack, backend, CheckOptions(stages=("lint",)))
    threshold = args.fail_on or pack.config.gate.lint_fail_on
    blocking = (
        []
        if threshold == "never"
        else [f for f in result.findings if f.severity >= Severity.parse(threshold)]
    )
    if args.sarif:
        _write(args.sarif, write_sarif(result))
    if args.format == "json":
        _emit(dumps({"findings": check_dict(result)["findings"], "blocking": len(blocking)}))
    else:
        lines = [f"yaraci lint: {lint_summary(result.findings)} ({len(pack.rules)} rules)"]
        lines += render_findings(result.findings)
        _emit("\n".join(lines) + "\n")
    code = GateFailure.LINT if blocking else GateFailure.NONE
    if not result.compiled:
        code |= GateFailure.COMPILE
    return int(code)


def cmd_test(args: argparse.Namespace) -> int:
    pack, backend = _load(args)
    result = run_check(pack, backend, CheckOptions(stages=("tp",)))
    if args.junit:
        _write(args.junit, write_junit(result))
    if result.tp is None:
        _emit("yaraci test: rule set does not compile\n")
        return int(GateFailure.COMPILE)
    if args.format == "json":
        _emit(dumps(check_dict(result)["tp"]))
    else:
        _emit("\n".join(render_tp(result.tp)) + "\n")
    return int(result.gate.code & GateFailure.TP)


def cmd_fp(args: argparse.Namespace) -> int:
    pack, backend = _load(args)
    opts = CheckOptions(
        stages=("fp",), include_system=True if args.system else None, extra_goodware=args.goodware or []
    )
    result = run_check(pack, backend, opts)
    if args.junit:
        _write(args.junit, write_junit(result))
    if result.fp is None:
        _emit("yaraci fp: rule set does not compile\n")
        return int(GateFailure.COMPILE)
    if args.format == "json":
        _emit(dumps(check_dict(result)["fp"]))
    else:
        _emit("\n".join(render_fp(result.fp)) + "\n")
    return int(result.gate.code & GateFailure.FP)


def cmd_profile(args: argparse.Namespace) -> int:
    pack, backend = _load(args)
    if args.repeat is not None:
        pack.config.profile.repeat = args.repeat
    opts = CheckOptions(stages=("profile",), profile_corpus=args.corpus or [], method=args.method)
    goodware = None if (args.corpus or pack.config.profile.corpus) else build_goodware_corpus(pack.config)
    samples = profile_samples(pack, opts, goodware)
    report = profile_pack(
        pack, backend, samples, pack.config.profile, rules=args.rule or None, method=args.method
    )
    if args.output:
        _write(args.output, dumps(profile_dict(report)))
    if args.format == "json":
        _emit(dumps(profile_dict(report)))
    else:
        _emit("\n".join(render_profile(report, rows=len(report.rules))) + "\n")
    slow = report.slow_rules and pack.config.gate.fail_on_slow
    return int(GateFailure.PERF if slow else GateFailure.NONE)


def cmd_diff(args: argparse.Namespace) -> int:
    old, backend = _load(args, args.old)
    new = load_pack(args.new, None)
    goodware = build_goodware_corpus(new.config, True if args.system else None, args.goodware or [])
    report = impact_diff(old, new, backend, goodware)
    if args.output:
        _write(
            args.output,
            render_diff_markdown(report) if args.output.suffix == ".md" else dumps(diff_dict(report)),
        )
    if args.format == "json":
        _emit(dumps(diff_dict(report)))
    elif args.format == "markdown":
        _emit(render_diff_markdown(report))
    else:
        _emit(render_diff(report))
    code = GateFailure.NONE
    if "new-fp" in args.fail_on and report.new_fp:
        code |= GateFailure.FP
    if "lost-tp" in args.fail_on and report.lost_tp:
        code |= GateFailure.TP
    return int(code)


def cmd_parity(args: argparse.Namespace) -> int:
    pack, _ = _load(args)
    builder = CorpusBuilder(limits=limits_for(pack.config))
    for path in args.corpus or [pack.config.resolve(c) for c in pack.config.profile.corpus]:
        builder.add_tree(path, "corpus")
    report = check_parity(pack, get_backend("libyara"), get_backend("yara-x"), builder.samples)
    _emit(dumps(parity_dict(report)) if args.format == "json" else render_parity(report))
    if report.compile_errors:
        return int(GateFailure.COMPILE)
    return 0 if report.consistent else 1


def cmd_explain(args: argparse.Namespace) -> int:
    if args.code:
        code = args.code.upper()
        if code in SPECS:
            spec = SPECS[code]
            _emit(
                f"{spec.code} {spec.name} [{spec.category}, default {spec.severity.label}]\n"
                f"{spec.summary}\n\nWhy: {spec.rationale}\n"
            )
            return 0
        if code in STAGE_CODES:
            stage = STAGE_CODES[code]
            _emit(f"{stage.code} {stage.name} [stage, default {stage.severity.label}]\n{stage.summary}\n")
            return 0
        _emit(f"unknown code {args.code}\n")
        return EXIT_USAGE
    rows = [
        f"{s.code}  {s.severity.label:<7} {s.category:<9} {s.name}"
        for s in sorted(SPECS.values(), key=lambda s: s.code)
    ]
    rows += [f"{s.code}  {s.severity.label:<7} {'stage':<9} {s.name}" for s in STAGE_CODES.values()]
    _emit("\n".join(rows) + "\n")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    packages = load_manifest(args.manifest)
    report = fetch_packages(packages, args.dest)
    for name in report.downloaded:
        _emit(f"downloaded {name}\n")
    for name in report.cached:
        _emit(f"cached     {name}\n")
    for reason in report.failed:
        _emit(f"FAILED     {reason}\n")
    _emit(
        f"{len(packages)} package(s): {len(report.downloaded)} downloaded, "
        f"{len(report.cached)} cached, {len(report.failed)} failed\n"
    )
    return 1 if report.failed else 0


# --------------------------------------------------------------------------- parser
def _common(p: argparse.ArgumentParser, pack: bool = True) -> None:
    if pack:
        p.add_argument("pack", type=Path, help="rule pack directory (contains yaraci.toml)")
    p.add_argument("--config", type=Path, help="explicit config file (default: <pack>/yaraci.toml)")
    p.add_argument("--engine", choices=BACKENDS, help="override [pack].engine")
    p.add_argument("--format", choices=("text", "json", "markdown"), default="text")


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915 - flat declarative CLI definition
    parser = argparse.ArgumentParser(prog="yaraci", description="CI harness for YARA rule quality.")
    parser.add_argument("--version", action="version", version=f"yaraci {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="show info findings and debug logs")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="run every stage and apply the regression gate")
    _common(p)
    p.add_argument("--stages", type=_stages, default=STAGES, help=f"comma list of {','.join(STAGES)}")
    p.add_argument("--system", action="store_true", help="add system binaries to the goodware corpus")
    p.add_argument("--goodware", type=Path, action="append", help="extra goodware directory (repeatable)")
    p.add_argument("--corpus", type=Path, action="append", help="profiling corpus directory (repeatable)")
    p.add_argument("--repeat", type=int, help="override [profile].repeat")
    p.add_argument("--method", choices=METHODS, default="isolated", help="profiling method")
    p.add_argument("--junit", type=Path, help="write JUnit XML here")
    p.add_argument("--sarif", type=Path, help="write SARIF 2.1.0 here")
    p.add_argument("--json", type=Path, help="write the JSON report here")
    p.add_argument("--markdown", type=Path, help="write a Markdown summary here")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("lint", help="static checks plus engine compile diagnostics")
    _common(p)
    p.add_argument(
        "--fail-on", choices=("error", "warning", "info", "never"), help="override [gate].lint_fail_on"
    )
    p.add_argument("--sarif", type=Path, help="write SARIF 2.1.0 here")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("test", help="true-positive fixture tests")
    _common(p)
    p.add_argument("--junit", type=Path, help="write JUnit XML here")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("fp", help="false-positive scan over the goodware corpus")
    _common(p)
    p.add_argument("--system", action="store_true", help="add system binaries to the corpus")
    p.add_argument("--goodware", type=Path, action="append", help="extra goodware directory (repeatable)")
    p.add_argument("--junit", type=Path, help="write JUnit XML here")
    p.set_defaults(func=cmd_fp)

    p = sub.add_parser("profile", help="per-rule scan-time profile and slow-rule detection")
    _common(p)
    p.add_argument("--corpus", type=Path, action="append", help="corpus directory (repeatable)")
    p.add_argument("--repeat", type=int, help="scans per sample (minimum is kept)")
    p.add_argument("--method", choices=METHODS, default="isolated")
    p.add_argument("--rule", action="append", help="profile only this rule (repeatable)")
    p.add_argument("--output", type=Path, help="write the JSON profile here")
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("diff", help="structural + match-impact diff between two pack versions")
    p.add_argument("old", type=Path, help="baseline pack directory")
    p.add_argument("new", type=Path, help="candidate pack directory")
    _common(p, pack=False)
    p.add_argument("--system", action="store_true", help="add system binaries to the corpus")
    p.add_argument("--goodware", type=Path, action="append", help="extra goodware directory (repeatable)")
    p.add_argument("--fail-on", default="new-fp,lost-tp", help="comma list of new-fp, lost-tp (or 'none')")
    p.add_argument("--output", type=Path, help="write the report here (.md = Markdown, else JSON)")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("parity", help="compare libyara and YARA-X match behaviour")
    _common(p)
    p.add_argument("--corpus", type=Path, action="append", help="corpus directory (repeatable)")
    p.set_defaults(func=cmd_parity)

    p = sub.add_parser("explain", help="list check codes or explain one")
    p.add_argument("code", nargs="?", help="check code, e.g. YC301")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("fetch-goodware", help="download the pinned OSS goodware corpus (verified)")
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--dest", type=Path, default=DEFAULT_FETCH_DEST)
    p.set_defaults(func=cmd_fetch)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    func: Callable[[argparse.Namespace], int] = args.func
    try:
        return func(args)
    except YaraciError as exc:
        sys.stderr.write(f"yaraci: error: {exc}\n")
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - last-resort guard, exercised manually
        log.debug("internal error", exc_info=True)
        sys.stderr.write(f"yaraci: internal error: {exc.__class__.__name__}: {exc}\n")
        return EXIT_INTERNAL


__all__ = ["build_parser", "main"]
