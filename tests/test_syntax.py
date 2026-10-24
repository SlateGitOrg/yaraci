"""Lexer, parser, hex-string and unparse tests."""

from __future__ import annotations

import pytest

from yaraci.errors import SyntaxParseError
from yaraci.syntax import ast, parse_condition, parse_source, render_string, unparse
from yaraci.syntax.hexstr import HexStringError, fixed_runs, has_unbounded_jump, parse_hex, render_elements
from yaraci.syntax.lexer import tokenize
from yaraci.syntax.tokens import TokenKind

COMPLEX = r"""
import "pe"
// yaraci:ignore-file YC999
private rule IsPE { condition: uint16(0) == 0x5A4D }
global rule G { condition: filesize < 10MB }
rule Lab_Test_One : tag1 tag2 {
  meta:
    author = "x"
    score = -5
    ok = true
    yaraci_ignore = "YC205, YC206"
  strings:
    $a = "hello\x41\"" wide ascii nocase fullword
    $h = { 4D 5A [2-4] ( 90 | CC ) ?? ~00 }
    $r = /ab[\/c]+d/is xor(0x01-0xff) private
    $b = "zz" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
  condition: // yaraci:ignore YC301
    IsPE and 2 of ($a, $h*) and #a in (0..filesize) > 2 and @a[1] < 100 and !a[1] == 5
    and for any i in (1..#a) : ( @a[i] < 0x100 ) and for all of them : ( $ at 0 or # > 1)
    and 50% of them and pe.sections[0].name contains ".text"
    and any of (IsPE, G*) and $r in (0..100) and $h at pe.entry_point and not defined pe.x
    and for any s in pe.sections : ( s.name == "UPX0" ) and with a = 1, b = 2 : ( a + b \ 2 % 3 == 1 )
    and for 2 of ($a*) : ($) and -1 < 2 << 3 and (1 | 2 ^ 3 & ~4) > 0 and "a" matches /x/
    and for any k in (1, 2, 3) : (k == 2) and 1.5 < 2 and all of ($b) at 0 and $b at 0 + 1
}
"""


def test_parses_complex_file() -> None:
    f = parse_source(COMPLEX, "t.yar")
    assert [i.module for i in f.imports] == ["pe"]
    assert f.file_suppressions == {"YC999"}
    names = [r.name for r in f.rules]
    assert names == ["IsPE", "G", "Lab_Test_One"]
    assert f.rules[0].is_private
    assert not f.rules[0].is_global
    assert f.rules[1].is_global
    rule = f.rules[2]
    assert rule.tags == ("tag1", "tag2")
    assert rule.first_meta("score") == -5
    assert rule.first_meta("ok") is True
    assert rule.first_meta("missing") is None
    assert rule.suppressions == {"YC301", "YC205", "YC206"}
    a, h, r, b = rule.strings
    assert a.value == b'helloA"'
    assert [m.name for m in a.modifiers] == ["wide", "ascii", "nocase", "fullword"]
    assert h.kind is ast.StringKind.HEX
    assert r.kind is ast.StringKind.REGEX
    assert r.regex_flags == "is"
    assert r.modifiers[0] == ast.Modifier("xor", (1, 255))
    assert r.has_modifier("private")
    assert b.modifiers[0].name == "base64"
    assert rule.source_path == "t.yar"
    src_text = COMPLEX[rule.start_offset : rule.end_offset]
    assert src_text.startswith("rule Lab_Test_One")
    assert src_text.endswith("}")


def test_unparse_is_a_fixed_point_on_complex_condition() -> None:
    rule = parse_source(COMPLEX).rules[2]
    text = unparse(rule.condition)
    assert unparse(parse_condition(text)) == text


@pytest.mark.parametrize(
    ("given", "canonical"),
    [
        ("$a and ($b or $c)", "$a and ($b or $c)"),
        ("($a and $b) or $c", "$a and $b or $c"),
        ("not ($a or $b)", "not ($a or $b)"),
        ("filesize < 0x10", "filesize < 16"),
        ("filesize < 1KB", "filesize < 1024"),
        ("1 - (2 - 3) == 2", "1 - (2 - 3) == 2"),
        ("(1 - 2) - 3 == -4", "1 - 2 - 3 == -4"),
        ("all of them", "all of them"),
        ("2 of ($a*) in (0..100)", "2 of ($a*) in (0..100)"),
        ("10% of them", "10% of them"),
        ("$a at (pe.entry_point + 2)", "$a at pe.entry_point + 2"),
        ("#a in (0..10) == 1", "#a in (0..10) == 1"),
        ("@a == 1 and !a[2] == 3", "@a == 1 and !a[2] == 3"),
        ("(uint8(0) | 1) == 1", "(uint8(0) | 1) == 1"),
        ('pe.exports("x") and "a\\n" contains "\\x00"', 'pe.exports("x") and "a\\n" contains "\\x00"'),
        ("for any i in (0..#a) : (@a[i] < 10)", "for any i in (0..#a) : (@a[i] < 10)"),
        ("for all of ($a*) : ($ at 0)", "for all of ($a*) : ($ at 0)"),
        ("with x = 1 : (x == 1)", "with x = 1 : (x == 1)"),
        ("defined pe.x", "defined pe.x"),
        ("-(1 + 2) < 0", "-(1 + 2) < 0"),
        ("~1 == 2", "~1 == 2"),
        ("x.y[0].z == 1.5", "x.y[0].z == 1.5"),
        ("n of them", "n of them"),
        ("(1 + 1) of them", "1 + 1 of them"),
        ("any of (Rule_A, Rule_B*)", "any of (Rule_A, Rule_B*)"),
    ],
)
def test_unparse_canonical(given: str, canonical: str) -> None:
    assert unparse(parse_condition(given)) == canonical


@pytest.mark.parametrize(
    "bad",
    [
        "rule { condition: true }",
        "rule a { condition: }",
        "rule a { strings: condition: true }",
        'rule a { strings: $a = "x condition: $a }',
        "rule a : { condition: true }",
        "rule a { meta: x = condition: true }",
        "rule a { condition: them }",
        "rule a { condition: any of ($a, b) }",
        "rule a { condition: for any of (r1) : (true) }",
        "rule a { strings: $a = 5 condition: $a }",
        "rule a { condition: (1 + 2 }",
        "rule a { condition: true ",
        "/* never closed",
        "rule a { condition: 0x }",
        "rule a { condition: 0o }",
        'rule a { strings: $a = "\\q" condition: $a }',
        'rule a { strings: $a = "\\xZZ" condition: $a }',
        "rule a { strings: $a = /abc condition: $a }",
        "rule a { strings: $a = { 41 42 condition: $a }",
        "rule a { condition: true } `",
        "rule a { condition: pe. }",
        "rule a { condition: for any x in (1..2) : true }",
        "rule a { condition: for of them : (true) }",
        "rule a { condition: with : (true) }",
        "rule a { condition: true and }",
    ],
)
def test_parse_errors(bad: str) -> None:
    with pytest.raises(SyntaxParseError) as info:
        parse_source(bad, "bad.yar")
    assert info.value.path == "bad.yar"
    assert info.value.line >= 1


def test_condition_trailing_input_rejected() -> None:
    with pytest.raises(SyntaxParseError):
        parse_condition("true true")


def test_lexer_regex_vs_division_context() -> None:
    tokens, comments = tokenize("$a = /x\\/y/i // c\nmatches /z/ /* b */")
    kinds = [t.kind for t in tokens]
    assert kinds.count(TokenKind.REGEX) == 2
    assert tokens[2].value == ("x\\/y", "i")
    assert [c.text for c in comments] == ["c", "b"]


def test_lexer_float_and_range() -> None:
    tokens, _ = tokenize("(0..10) 1.25 2MB")
    texts = [t.text for t in tokens if t.kind is not TokenKind.EOF]
    assert texts == ["(", "0", "..", "10", ")", "1.25", "2MB"]
    assert tokens[-2].value == 2 * 1024 * 1024


def test_lexer_not_equal_vs_length() -> None:
    tokens, _ = tokenize("!a != 3")
    assert tokens[0].kind is TokenKind.STRING_LENGTH
    assert tokens[1].is_op("!=")


def test_meta_negative_and_keyword_keys() -> None:
    f = parse_source("rule a { meta: version = 3 private = false condition: true }")
    assert f.rules[0].first_meta("private") is False


def test_include_directive_recorded() -> None:
    f = parse_source('include "other.yar"\nrule a { condition: true }')
    assert f.includes[0].path == "other.yar"


def test_hex_parse_and_render() -> None:
    els = parse_hex("4d5a ?? 9? ~00 [4] [2-] [-] (01 02 | 03 [1-2] 04)")
    assert render_elements(els) == "4D 5A ?? 9? ~00 [4] [2-] [-] ( 01 02 | 03 [1-2] 04 )"
    assert has_unbounded_jump(els)
    assert fixed_runs(els) == [b"MZ", b"\x03"]
    assert not has_unbounded_jump(parse_hex("( 01 | 02 [1-3] )"))
    assert has_unbounded_jump(parse_hex("( 01 | 02 [1-] 03 )"))


@pytest.mark.parametrize("bad", ["4", "ZZ", "[1-", "[x]", "[3-1]", "(01", "01 )", "01 | 02"])
def test_hex_errors(bad: str) -> None:
    with pytest.raises(HexStringError):
        parse_hex(bad)


def test_render_string_canonical() -> None:
    f = parse_source(
        'rule a { strings: $a = "x" wide ascii $b = {4d5a} $c = /q/i nocase $d = { 4D ZZ } '
        '$e = "k" xor(1-2) base64("abc") condition: any of them }'
    )
    rendered = [render_string(s) for s in f.rules[0].strings]
    assert rendered[0] == '"x" ascii wide'
    assert rendered[1] == "{ 4D 5A }"
    assert rendered[2] == "/q/i nocase"
    assert rendered[3] == "{ 4D ZZ }"
    assert rendered[4] == '"k" base64("abc") xor(1-2)'
