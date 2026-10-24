"""Both engine backends behave identically through the Backend protocol."""

from __future__ import annotations

import pytest

from yaraci.engine import BACKENDS, RuleCompileError, SourceUnit, get_backend
from yaraci.engine.libyara import _LineMap, _parse_message
from yaraci.errors import ConfigError

RULES = SourceUnit("a.yar", 'rule A { strings: $x = "needle" $y = "other" condition: any of them }')
HELPER = SourceUnit("b.yar", "private rule P { condition: true }\nrule B { condition: P and filesize == 3 }")


@pytest.mark.parametrize("engine", BACKENDS)
def test_compile_and_scan(engine: str) -> None:
    backend = get_backend(engine)
    assert backend.version
    result = backend.compile([RULES, HELPER])
    outcome = result.rules.scan(b"xx needle xx")
    assert outcome.rule_names == {"A"}
    assert outcome.matches[0].patterns == ("$x",)
    assert not outcome.timed_out
    assert result.rules.scan(b"abc").rule_names == {"B"}


@pytest.mark.parametrize("engine", BACKENDS)
def test_compile_error_located_in_second_unit(engine: str) -> None:
    bad = SourceUnit("bad.yar", "\n\nrule C { condition: undefined_thing }")
    with pytest.raises(RuleCompileError) as info:
        get_backend(engine).compile([RULES, bad])
    diag = info.value.diagnostics[0]
    assert diag.severity == "error"
    assert diag.path == "bad.yar"
    assert diag.line == 3
    assert "bad.yar:3" in str(info.value)


@pytest.mark.parametrize("engine", BACKENDS)
def test_warnings_reported(engine: str) -> None:
    result = get_backend(engine).compile(
        [SourceUnit("w.yar", "rule W { strings: $a = { 00 00 } condition: $a }")]
    )
    assert result.warnings
    assert result.warnings[0].severity == "warning"
    assert result.warnings[0].path == "w.yar"


def test_unknown_backend() -> None:
    with pytest.raises(ConfigError):
        get_backend("clamav")


def test_libyara_line_map() -> None:
    lines = _LineMap([SourceUnit("a", "1\n2"), SourceUnit("b", "x")])
    assert lines.locate(1) == ("a", 1)
    assert lines.locate(2) == ("a", 2)
    assert lines.locate(3) == ("b", 1)
    assert _LineMap([]).locate(5) == (None, 5)
    diag = _parse_message("no line info", "warning", lines)
    assert diag.line is None
    assert diag.message == "no line info"


def test_compile_error_without_diagnostics_message() -> None:
    assert str(RuleCompileError([])) == "compilation failed"
