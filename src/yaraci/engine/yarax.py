"""Backend for YARA-X (the Rust rewrite of YARA) via the ``yara-x`` Python package."""

from __future__ import annotations

import contextlib
from importlib import metadata
from typing import Any

import yara_x

from yaraci.engine.base import CompileResult, Diagnostic, RuleCompileError, RuleMatch, ScanOutcome, SourceUnit


def _diagnostic(raw: dict[str, Any], severity: str, origin: str | None) -> Diagnostic:
    labels = raw.get("labels") or []
    detail = labels[0].get("text") if labels else ""
    message = raw.get("title", "")
    if detail and detail not in message:
        message = f"{message}: {detail}"
    return Diagnostic(
        severity=severity,
        code=str(raw.get("code", "")),
        message=message,
        path=origin,
        line=raw.get("line"),
        column=raw.get("column"),
    )


class _YaraXRules:
    def __init__(self, rules: Any, timeout_s: int) -> None:
        self._scanner = yara_x.Scanner(rules)
        self._scanner.set_timeout(timeout_s)

    def scan(self, data: bytes) -> ScanOutcome:
        try:
            results = self._scanner.scan(data)
        except yara_x.TimeoutError:
            return ScanOutcome((), timed_out=True)
        matches = tuple(
            RuleMatch(
                rule=r.identifier,
                namespace=r.namespace,
                patterns=tuple(p.identifier for p in r.patterns if p.matches),
            )
            for r in results.matching_rules
        )
        return ScanOutcome(matches)


class YaraXBackend:
    """Compiles with ``yara_x.Compiler`` (all units share the default namespace)."""

    name = "yara-x"

    @property
    def version(self) -> str:
        return metadata.version("yara-x")

    def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
        compiler = yara_x.Compiler()
        errors: list[Diagnostic] = []
        warnings: list[Diagnostic] = []
        for unit in units:
            seen_errors = len(compiler.errors())
            seen_warnings = len(compiler.warnings())
            # Errors are recorded in compiler.errors(); keep compiling the other units.
            with contextlib.suppress(yara_x.CompileError):
                compiler.add_source(unit.text, origin=unit.path)
            errors += [_diagnostic(e, "error", unit.path) for e in compiler.errors()[seen_errors:]]
            warnings += [_diagnostic(w, "warning", unit.path) for w in compiler.warnings()[seen_warnings:]]
        if errors:
            raise RuleCompileError(errors)
        return CompileResult(_YaraXRules(compiler.build(), timeout_s), warnings)
