"""Runs all lint checks over a pack and applies policy (disable, severity, suppressions)."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import date

from yaraci.engine import Backend, Diagnostic, RuleCompileError
from yaraci.lint import checks_condition, checks_meta, checks_strings  # noqa: F401 - registers checks
from yaraci.lint.model import RULE_CHECKS, SPECS, CheckSpec, Finding, LintContext, Severity, register_spec
from yaraci.pack import RulePack

log = logging.getLogger(__name__)

PARSE_ERROR = register_spec(
    CheckSpec(
        "YC001",
        "parse-error",
        "syntax",
        Severity.ERROR,
        "The yaraci front-end could not parse the file, so static checks were skipped for it.",
        "The engine compile result (YC501) is authoritative for validity; a YC001 without a YC501 "
        "indicates syntax the yaraci parser does not support yet.",
    )
)
INCLUDE_UNSUPPORTED = register_spec(
    CheckSpec(
        "YC002",
        "include-directive",
        "syntax",
        Severity.ERROR,
        "include directives are not supported inside a pack.",
        "Packs are discovered from directories; includes would compile files twice and make "
        "per-rule isolation ambiguous.",
    )
)
DUPLICATE_NAME = register_spec(
    CheckSpec(
        "YC103",
        "duplicate-rule-name",
        "naming",
        Severity.ERROR,
        "Two rules in the pack share a name.",
        "All files compile into one namespace; duplicates fail compilation or shadow each other.",
    )
)
COMPILE_ERROR = register_spec(
    CheckSpec(
        "YC501",
        "compile-error",
        "engine",
        Severity.ERROR,
        "The YARA engine rejected the rule set.",
        "Nothing else can be trusted until the pack compiles.",
    )
)
COMPILE_WARNING = register_spec(
    CheckSpec(
        "YC502",
        "compile-warning",
        "engine",
        Severity.WARNING,
        "The YARA engine emitted a warning (slow pattern, invariant expression, ...).",
        "Engine warnings come from the compiler's own analysis and usually indicate real cost "
        "or logic issues.",
    )
)


def _finding(
    spec: CheckSpec,
    message: str,
    *,
    path: str | None = None,
    line: int | None = None,
    column: int | None = None,
    rule: str | None = None,
) -> Finding:
    return Finding(spec.code, spec.severity, message, path, line, column, rule)


def _engine_findings(diags: list[Diagnostic], spec: CheckSpec) -> list[Finding]:
    out = []
    for d in diags:
        code = f"[{d.code}] " if d.code and d.code != "libyara" else ""
        out.append(_finding(spec, f"{code}{d.message}", path=d.path, line=d.line, column=d.column))
    return out


def _rule_for_line(pack: RulePack, path: str | None, line: int | None) -> str | None:
    if path is None or line is None:
        return None
    for pr in pack.rules:
        if pr.path == path and pr.rule.pos.line <= line <= pr.rule.end_line:
            return pr.name
    return None


def compile_findings(pack: RulePack, backend: Backend) -> tuple[list[Finding], bool]:
    """Compile the pack; return engine findings and whether compilation succeeded."""
    try:
        result = backend.compile(pack.units, pack.config.pack.scan_timeout_s)
    except RuleCompileError as exc:
        return _engine_findings(exc.diagnostics, COMPILE_ERROR), False
    return _engine_findings(result.warnings, COMPILE_WARNING), True


def raw_findings(pack: RulePack, today: date, backend: Backend | None = None) -> list[Finding]:
    """All findings before policy (disable/severity/suppression) is applied."""
    findings: list[Finding] = []
    for err in pack.parse_errors:
        findings.append(_finding(PARSE_ERROR, err.message, path=err.path, line=err.line, column=err.column))
    for rf in pack.files:
        for inc in rf.includes:
            findings.append(
                _finding(INCLUDE_UNSUPPORTED, f"include {inc.path!r}", path=rf.path, line=inc.pos.line)
            )
    first_seen: dict[str, str] = {}
    for pr in pack.rules:
        if pr.name in first_seen:
            findings.append(
                _finding(
                    DUPLICATE_NAME,
                    f"rule {pr.name!r} already defined in {first_seen[pr.name]}",
                    path=pr.path,
                    line=pr.rule.pos.line,
                    rule=pr.name,
                )
            )
        else:
            first_seen[pr.name] = pr.path
    ctx = LintContext(config=pack.config, pack=pack, today=today)
    for pr in pack.rules:
        for spec, func in RULE_CHECKS:
            for hit in func(ctx, pr):
                findings.append(
                    _finding(
                        spec,
                        hit.message,
                        path=pr.path,
                        line=hit.line or pr.rule.pos.line,
                        column=hit.column,
                        rule=pr.name,
                    )
                )
    if backend is not None:
        engine, _ = compile_findings(pack, backend)
        for f in engine:
            rule = _rule_for_line(pack, f.path, f.line)
            findings.append(
                Finding(f.code, f.severity, f.message, f.path, f.line, f.column, rule) if rule else f
            )
    return findings


def apply_policy(pack: RulePack, findings: list[Finding]) -> list[Finding]:
    """Drop disabled/suppressed findings and apply severity overrides."""
    cfg = pack.config.lint
    disabled = set(cfg.disable)
    overrides = {code: Severity.parse(sev) for code, sev in cfg.severity.items()}
    file_supp: dict[str, frozenset[str]] = defaultdict(frozenset)
    for rf in pack.files:
        file_supp[rf.path] = rf.file_suppressions
    rule_supp = {pr.name: pr.rule.suppressions for pr in pack.rules}
    kept: list[Finding] = []
    for f in findings:
        if f.code in disabled:
            continue
        if f.path is not None and f.code in file_supp[f.path]:
            continue
        if f.rule is not None and f.code in rule_supp.get(f.rule, frozenset()):
            continue
        severity = overrides.get(f.code, f.severity)
        kept.append(Finding(f.code, severity, f.message, f.path, f.line, f.column, f.rule))
    unknown = (disabled | set(overrides)) - set(SPECS)
    if unknown:
        log.warning("config references unknown check codes: %s", ", ".join(sorted(unknown)))
    return sorted(kept, key=Finding.sort_key)


def lint_pack(pack: RulePack, today: date | None = None, backend: Backend | None = None) -> list[Finding]:
    """Lint ``pack``; if ``backend`` is given, engine diagnostics are included."""
    return apply_policy(pack, raw_findings(pack, today or date.today(), backend))
