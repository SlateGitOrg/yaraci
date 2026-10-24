"""SARIF 2.1.0 writer (GitHub code scanning, Azure DevOps, VS Code SARIF viewer)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from yaraci import __version__
from yaraci.lint import SPECS, Finding, Severity
from yaraci.pipeline import CheckResult
from yaraci.report.model import code_info, collect_issues, display_path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "note"}


def _fingerprint(f: Finding) -> str:
    """Stable across line moves: code + rule + message, not the line number."""
    raw = f"{f.code}|{f.rule or ''}|{f.path or ''}|{f.message}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _result(f: Finding, uri: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ruleId": f.code,
        "level": _LEVELS[f.severity],
        "message": {"text": f"{f.rule}: {f.message}" if f.rule else f.message},
        "partialFingerprints": {"yaraciFinding/v1": _fingerprint(f)},
    }
    if uri is not None:
        region: dict[str, int] = {"startLine": max(1, f.line or 1)}
        if f.column:
            region["startColumn"] = f.column
        entry["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]
    if f.rule:
        entry["properties"] = {"yaraRule": f.rule}
    return entry


def build_sarif(result: CheckResult) -> dict[str, Any]:
    issues = collect_issues(result)
    codes = sorted({f.code for f in issues})
    rules = []
    for code in codes:
        name, summary, severity = code_info(code)
        rules.append(
            {
                "id": code,
                "name": name,
                "shortDescription": {"text": summary},
                "defaultConfiguration": {"level": _LEVELS[severity]},
                "fullDescription": {"text": SPECS[code].rationale if code in SPECS else summary},
            }
        )
    results = [_result(f, display_path(result.pack.root, f.path)) for f in issues]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "yaraci",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "properties": {"engine": f"{result.engine} {result.engine_version}"},
                "results": results,
            }
        ],
    }


def write_sarif(result: CheckResult) -> str:
    return json.dumps(build_sarif(result), indent=2, sort_keys=False) + "\n"
