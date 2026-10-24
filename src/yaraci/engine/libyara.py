"""Backend for classic libyara via ``yara-python``.

libyara compiles one source string per namespace, so all units are concatenated
into a single text and reported line numbers are mapped back to the originating
file with a prefix-sum table (binary search, ``O(log files)`` per diagnostic).
"""

from __future__ import annotations

import bisect
import re
from importlib import metadata
from typing import Any

import yara

from yaraci.engine.base import CompileResult, Diagnostic, RuleCompileError, RuleMatch, ScanOutcome, SourceUnit

_LINE_RE = re.compile(r"^line (\d+): (.*)$", re.DOTALL)


class _LineMap:
    def __init__(self, units: list[SourceUnit]) -> None:
        self.starts: list[int] = []  # 1-based first line of each unit in the joined text
        self.paths: list[str] = []
        line = 1
        for unit in units:
            self.starts.append(line)
            self.paths.append(unit.path)
            line += unit.text.count("\n") + 1  # +1 for the separator newline

    def locate(self, joined_line: int) -> tuple[str | None, int]:
        if not self.starts:
            return None, joined_line
        idx = bisect.bisect_right(self.starts, joined_line) - 1
        idx = max(idx, 0)
        return self.paths[idx], joined_line - self.starts[idx] + 1


def _parse_message(raw: str, severity: str, lines: _LineMap) -> Diagnostic:
    match = _LINE_RE.match(raw.strip())
    if not match:
        return Diagnostic(severity, "libyara", raw.strip())
    path, line = lines.locate(int(match.group(1)))
    return Diagnostic(severity, "libyara", match.group(2), path=path, line=line)


class _LibyaraRules:
    def __init__(self, rules: Any, timeout_s: int) -> None:
        self._rules = rules
        self._timeout = timeout_s

    def scan(self, data: bytes) -> ScanOutcome:
        try:
            found = self._rules.match(data=data, timeout=self._timeout)
        except yara.TimeoutError:
            return ScanOutcome((), timed_out=True)
        return ScanOutcome(
            tuple(
                RuleMatch(
                    rule=m.rule,
                    namespace=m.namespace,
                    patterns=tuple(dict.fromkeys(s.identifier for s in m.strings)),
                )
                for m in found
            )
        )


class LibyaraBackend:
    """Compiles with ``yara.compile`` into the ``default`` namespace."""

    name = "libyara"

    @property
    def version(self) -> str:
        return metadata.version("yara-python")

    def compile(self, units: list[SourceUnit], timeout_s: int = 10) -> CompileResult:
        lines = _LineMap(units)
        joined = "\n".join(unit.text for unit in units)
        try:
            rules = yara.compile(source=joined, error_on_warning=False)
        except yara.SyntaxError as exc:
            raise RuleCompileError([_parse_message(str(exc), "error", lines)]) from None
        except yara.Error as exc:
            raise RuleCompileError([Diagnostic("error", "libyara", str(exc))]) from None
        warnings = [_parse_message(w, "warning", lines) for w in (rules.warnings or [])]
        return CompileResult(_LibyaraRules(rules, timeout_s), warnings)
