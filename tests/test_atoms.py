"""Atom-quality heuristics."""

from __future__ import annotations

import pytest

from yaraci.lint.atoms import atom_quality, best_atom, estimate, regex_literal_runs
from yaraci.syntax import parse_source


def strings_of(defs: str) -> list:  # type: ignore[type-arg]
    return list(parse_source(f"rule a {{ strings: {defs} condition: any of them }}").rules[0].strings)


def test_atom_quality_ordering() -> None:
    assert atom_quality(b"") == 0
    assert atom_quality(b"\x00\x00\x00\x00") < atom_quality(b"MZ\x90\x00") < atom_quality(b"UPX!")
    assert atom_quality(b"evil", nocase=True) < atom_quality(b"evil")
    assert atom_quality(b"AAAA") == atom_quality(b"ABCD") // 2


def test_best_atom_picks_strongest_window() -> None:
    est = best_atom([b"\x00\x00\x00\x00\x00", b"xyz\x01q"])
    assert est.atom == b"xyz\x01"


@pytest.mark.parametrize(
    ("pattern", "runs"),
    [
        (r"abc", [[b"abc"]]),
        (r"ab?c", [[b"a", b"c"]]),
        (r"ab*c", [[b"a", b"c"]]),
        (r"ab+c", [[b"ab", b"c"]]),
        (r"ab{2,3}c", [[b"ab", b"c"]]),
        (r"ab{0,3}c", [[b"a", b"c"]]),
        (r"a.b", [[b"a", b"b"]]),
        (r"\x41\x42\.", [[b"AB."]]),
        (r"\d+abc", [[b"abc"]]),
        (r"[abc]{3}xyz", [[b"xyz"]]),
        (r"(foo|bar)baz", [[b"baz"]]),
        (r"one|two", [[b"one"], [b"two"]]),
        (r"a\nb", [[b"a\nb"]]),
        (r"x[^\]]y", [[b"x", b"y"]]),
        (r"\xZZq", [[b"ZZq"]]),
        (r"^start$", [[b"start"]]),
        (r"a{1,2}?b", [[b"a", b"b"]]),
    ],
)
def test_regex_literal_runs(pattern: str, runs: list[list[bytes]]) -> None:
    assert regex_literal_runs(pattern) == runs


def test_estimate_respects_modifiers() -> None:
    plain, wide, both, nocase, xored, hexs, badhex, regex, alt = strings_of(
        '$a = "evilstring" $b = "evilstring" wide $c = "evilstring" wide ascii $d = "evilstring" nocase '
        '$e = "evilstring" xor $f = { 4D 5A ?? 90 00 03 00 } $g = { 4D ZZ } $h = /ev(il|ul)payload/ '
        "$i = /a|longliteral/"
    )
    assert estimate(plain).quality > estimate(wide).quality
    assert estimate(both).quality == estimate(wide).quality
    assert estimate(nocase).quality < estimate(plain).quality
    assert estimate(xored).quality == estimate(plain).quality - 15
    assert estimate(hexs).atom == b"\x90\x00\x03\x00"
    assert estimate(badhex).quality == 0
    assert estimate(regex).atom == b"payl"
    assert estimate(alt).atom == b"a"
