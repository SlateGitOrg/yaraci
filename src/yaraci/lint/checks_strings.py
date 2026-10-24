"""String-definition checks (YC3xx)."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator

from yaraci.lint.atoms import estimate
from yaraci.lint.model import Hit, LintContext, Severity, check
from yaraci.pack import PackRule
from yaraci.syntax import ast, render_string
from yaraci.syntax.hexstr import HexByte, HexStringError, has_unbounded_jump, parse_hex

# "Spanning" atoms can run across arbitrary content: '.', negated classes, \S \W \D.
_SPAN = r"(?:(?<!\\)\.|\[\^[^\]]*\]|\\[SWD])"
_UNBOUNDED_RE = re.compile(_SPAN + r"(?:[*+]|\{\d*,\})")
_LEADING_WILDCARD_RE = re.compile(r"^" + _SPAN + r"[*+{]")


def _text_value(sdef: ast.StringDef) -> bytes | None:
    return sdef.value if sdef.kind is ast.StringKind.TEXT and isinstance(sdef.value, bytes) else None


@check(
    "YC301",
    "weak-atom",
    "strings",
    Severity.WARNING,
    summary="The string's best atom is short or made of common bytes, so it pre-filters poorly.",
    rationale="Engines search for <=4-byte atoms and verify full patterns only on atom hits. A weak atom "
    "(e.g. 'MZ', 00 00 00 00, a regex with no literal run) causes verification on most offsets "
    "of every file and slows the whole rule set, not just this rule.",
)
def weak_atom(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    threshold = ctx.config.lint.min_atom_quality
    for sdef in pr.rule.strings:
        est = estimate(sdef)
        if est.quality < threshold:
            shown = est.atom.hex(" ") if est.atom else "none"
            yield Hit(
                f"{sdef.identifier} has weak atom [{shown}] (quality {est.quality} < {threshold})",
                sdef.pos.line,
                sdef.pos.column,
            )


@check(
    "YC302",
    "regex-unbounded-repetition",
    "strings",
    Severity.WARNING,
    summary="A regular expression uses an unbounded wildcard repetition (.*, .+, [^x]*, {n,}).",
    rationale="Unbounded repetition lets one atom hit trigger verification across the rest of the file "
    "(quadratic in the worst case). Use a bounded quantifier such as .{0,64}.",
)
def regex_unbounded(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        if sdef.kind is not ast.StringKind.REGEX:
            continue
        assert isinstance(sdef.value, str)
        if _LEADING_WILDCARD_RE.match(sdef.value):
            yield Hit(f"{sdef.identifier} starts with a wildcard", sdef.pos.line, sdef.pos.column)
        elif _UNBOUNDED_RE.search(sdef.value):
            yield Hit(f"{sdef.identifier} has unbounded repetition", sdef.pos.line, sdef.pos.column)


@check(
    "YC303",
    "duplicate-string",
    "strings",
    Severity.WARNING,
    summary="Two strings in the same rule have identical value and modifiers.",
    rationale="Duplicates double the atoms and verification work and usually indicate a copy-paste error.",
)
def duplicate_strings(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    seen: dict[str, list[ast.StringDef]] = defaultdict(list)
    for sdef in pr.rule.strings:
        seen[render_string(sdef)].append(sdef)
    for defs in seen.values():
        for dup in defs[1:]:
            yield Hit(f"{dup.identifier} duplicates {defs[0].identifier}", dup.pos.line, dup.pos.column)


@check(
    "YC304",
    "useless-nocase",
    "strings",
    Severity.INFO,
    summary="nocase is applied to a string that contains no letters.",
    rationale="The modifier has no effect and suggests the author misunderstood the pattern.",
)
def useless_nocase(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        value = _text_value(sdef)
        if value is not None and sdef.has_modifier("nocase") and not any(chr(b).isalpha() for b in value):
            yield Hit(f"{sdef.identifier} uses nocase but has no letters", sdef.pos.line, sdef.pos.column)


@check(
    "YC305",
    "redundant-ascii",
    "strings",
    Severity.INFO,
    summary="ascii is specified without wide; ascii is already the default.",
    rationale="Redundant modifiers add noise to reviews and diffs.",
)
def redundant_ascii(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        if sdef.has_modifier("ascii") and not sdef.has_modifier("wide"):
            yield Hit(f"{sdef.identifier} has redundant 'ascii'", sdef.pos.line, sdef.pos.column)


@check(
    "YC306",
    "hex-unbounded-jump",
    "strings",
    Severity.WARNING,
    summary="A hex string contains an unbounded jump ([-] or [n-]).",
    rationale="Unbounded jumps make verification scan to the end of the file from every atom hit.",
)
def hex_unbounded(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        if sdef.kind is not ast.StringKind.HEX:
            continue
        assert isinstance(sdef.value, str)
        try:
            elements = parse_hex(sdef.value)
        except HexStringError as exc:
            yield Hit(f"{sdef.identifier}: {exc}", sdef.pos.line, sdef.pos.column)
            continue
        if has_unbounded_jump(elements):
            yield Hit(f"{sdef.identifier} has an unbounded jump", sdef.pos.line, sdef.pos.column)


@check(
    "YC307",
    "too-many-strings",
    "strings",
    Severity.INFO,
    summary="The rule defines more strings than the configured maximum.",
    rationale="Very large string lists are hard to review and often hide dead or overlapping patterns.",
)
def too_many_strings(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    limit = ctx.config.lint.max_strings
    if len(pr.rule.strings) > limit:
        yield Hit(f"rule defines {len(pr.rule.strings)} strings (max {limit})")


@check(
    "YC308",
    "short-variant-string",
    "strings",
    Severity.WARNING,
    summary="xor/base64 is applied to a string shorter than 8 bytes.",
    rationale="Each modifier multiplies the atom set (xor: up to 256 variants); short inputs give "
    "near-random atoms that hit everywhere.",
)
def short_variant(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        value = _text_value(sdef)
        variants = [m.name for m in sdef.modifiers if m.name in ("xor", "base64", "base64wide")]
        if value is not None and variants and len(value) < 8:
            yield Hit(
                f"{sdef.identifier} uses {'/'.join(variants)} on a {len(value)}-byte string",
                sdef.pos.line,
                sdef.pos.column,
            )


@check(
    "YC309",
    "low-entropy-string",
    "strings",
    Severity.WARNING,
    summary="The string is a single repeated byte.",
    rationale="Runs such as 'AAAAAAAA' or 00 00 00 00 occur in padding and compressed data of benign files.",
)
def low_entropy(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for sdef in pr.rule.strings:
        value = _text_value(sdef)
        if sdef.kind is ast.StringKind.HEX:
            assert isinstance(sdef.value, str)
            try:
                elements = parse_hex(sdef.value)
            except HexStringError:
                continue
            values = {e.value for e in elements if isinstance(e, HexByte) and e.is_fixed}
            if (
                len(elements) > 1
                and len(values) == 1
                and all(isinstance(e, HexByte) and e.is_fixed for e in elements)
            ):
                yield Hit(f"{sdef.identifier} is one repeated byte", sdef.pos.line, sdef.pos.column)
        elif value is not None and len(value) > 1 and len(set(value)) == 1:
            yield Hit(f"{sdef.identifier} is one repeated byte", sdef.pos.line, sdef.pos.column)
