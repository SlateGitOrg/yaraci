"""Naming (YC1xx) and metadata (YC2xx) checks."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from datetime import date

from yaraci.lint.model import Hit, LintContext, Severity, check
from yaraci.pack import PackRule

_TAG_RE = re.compile(r"^[a-z0-9_]+$")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)
_HEX_LENGTHS = {"md5": (32,), "sha1": (40,), "sha256": (64,), "hash": (32, 40, 64)}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DATE_KEYS = ("date", "modified")
_INT_KEYS = ("score", "version")
_MULTI_KEYS = frozenset({"hash", "md5", "sha1", "sha256", "reference", "tag"})


# --------------------------------------------------------------------------- naming
@check(
    "YC101",
    "rule-name-format",
    "naming",
    Severity.WARNING,
    summary="Rule name does not match the configured naming pattern.",
    rationale="Consistent names (Category_Family_Detail) make alerts self-describing and let triage "
    "route detections by prefix without opening the rule.",
)
def name_format(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    if not re.search(ctx.config.lint.name_pattern, pr.name):
        yield Hit(f"rule name {pr.name!r} does not match pattern {ctx.config.lint.name_pattern!r}")


@check(
    "YC102",
    "rule-name-length",
    "naming",
    Severity.WARNING,
    summary="Rule name is longer than the configured maximum.",
    rationale="Very long names are truncated in SIEM columns and alert titles.",
)
def name_length(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    limit = ctx.config.lint.max_name_length
    if len(pr.name) > limit:
        yield Hit(f"rule name is {len(pr.name)} characters (max {limit})")


@check(
    "YC104",
    "rule-name-prefix",
    "naming",
    Severity.WARNING,
    summary="Rule name does not start with an approved category prefix.",
    rationale="A controlled prefix vocabulary (MAL, SUSP, HKTL, ...) encodes alert intent and severity.",
)
def name_prefix(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    prefixes = ctx.config.lint.name_prefixes
    if prefixes and pr.name.split("_", 1)[0] not in prefixes:
        yield Hit(f"rule name prefix {pr.name.split('_', 1)[0]!r} is not one of {', '.join(prefixes)}")


@check(
    "YC105",
    "tag-format",
    "naming",
    Severity.INFO,
    summary="Tag is not lower_snake_case or is repeated.",
    rationale="Tags are matched literally by downstream filters; inconsistent case splits one tag into many.",
)
def tag_format(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for tag, count in Counter(pr.rule.tags).items():
        if not _TAG_RE.match(tag):
            yield Hit(f"tag {tag!r} is not lower_snake_case")
        if count > 1:
            yield Hit(f"tag {tag!r} is repeated {count} times")


# --------------------------------------------------------------------------- metadata
@check(
    "YC201",
    "missing-required-meta",
    "metadata",
    Severity.ERROR,
    summary="A metadata key required by the pack policy is missing.",
    rationale="Detections without author/description/date cannot be triaged, owned or aged out.",
)
def required_meta(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    if pr.rule.is_private:
        return
    present = {m.key for m in pr.rule.meta}
    for key in ctx.config.lint.required_meta:
        if key not in present:
            yield Hit(f"missing required meta key {key!r}")


@check(
    "YC202",
    "missing-recommended-meta",
    "metadata",
    Severity.INFO,
    summary="A recommended metadata key is missing.",
    rationale="References and sample hashes let reviewers verify the detection logic.",
)
def recommended_meta(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    if pr.rule.is_private:
        return
    present = {m.key for m in pr.rule.meta}
    for key in ctx.config.lint.recommended_meta:
        if key not in present:
            yield Hit(f"missing recommended meta key {key!r}")


@check(
    "YC203",
    "invalid-date",
    "metadata",
    Severity.WARNING,
    summary="A date meta value is not an ISO-8601 calendar date or lies in the future.",
    rationale="Rule age drives review and retirement; unparseable dates break that automation.",
)
def meta_dates(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for entry in pr.rule.meta:
        if entry.key not in _DATE_KEYS:
            continue
        match = _DATE_RE.match(str(entry.value))
        if not isinstance(entry.value, str) or not match:
            yield Hit(
                f"meta {entry.key} = {entry.value!r} is not YYYY-MM-DD", entry.pos.line, entry.pos.column
            )
            continue
        try:
            when = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            yield Hit(f"meta {entry.key} = {entry.value!r} is not a real date", entry.pos.line)
            continue
        if when > ctx.today:
            yield Hit(f"meta {entry.key} = {entry.value!r} is in the future", entry.pos.line)


@check(
    "YC204",
    "invalid-hash",
    "metadata",
    Severity.ERROR,
    summary="A hash meta value is not a hex digest of the expected length.",
    rationale="Sample hashes are pivots into threat-intel platforms; a malformed hash silently breaks them.",
)
def meta_hashes(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for entry in pr.rule.meta:
        lengths = _HEX_LENGTHS.get(entry.key)
        if lengths is None:
            continue
        value = str(entry.value)
        if not _HEX_RE.match(value) or len(value) not in lengths:
            want = "/".join(str(n) for n in lengths)
            yield Hit(f"meta {entry.key} is not a {want}-character hex digest", entry.pos.line)


@check(
    "YC205",
    "invalid-reference",
    "metadata",
    Severity.WARNING,
    summary="A reference meta value is not an http(s) URL.",
    rationale="References are followed by analysts; free text belongs in description.",
)
def meta_reference(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for entry in pr.rule.meta:
        if entry.key == "reference" and not _URL_RE.match(str(entry.value)):
            yield Hit(f"meta reference {entry.value!r} is not an http(s) URL", entry.pos.line)


@check(
    "YC206",
    "duplicate-meta-key",
    "metadata",
    Severity.INFO,
    summary="A single-valued metadata key appears more than once.",
    rationale="Tools that read meta into a dict keep only one value, so the duplicate is silently lost.",
)
def meta_duplicates(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    counts = Counter(m.key for m in pr.rule.meta)
    for key, count in counts.items():
        if count > 1 and key not in _MULTI_KEYS:
            yield Hit(f"meta key {key!r} appears {count} times")


@check(
    "YC207",
    "weak-description",
    "metadata",
    Severity.WARNING,
    summary="The description is too short or merely repeats the rule name.",
    rationale="The description is what an analyst reads in the alert; it must say what was detected.",
)
def meta_description(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    value = pr.rule.first_meta("description")
    if value is None:
        return
    text = str(value).strip()
    normalized = re.sub(r"[\s_]+", "", text).lower()
    if len(text) < 15 or normalized == pr.name.replace("_", "").lower():
        yield Hit(f"description {text!r} is too short or repeats the rule name")


@check(
    "YC208",
    "meta-type",
    "metadata",
    Severity.WARNING,
    summary="A typed metadata value has the wrong type or an out-of-vocabulary value.",
    rationale="score/version are compared numerically and severity is mapped to alert priority downstream.",
)
def meta_types(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for entry in pr.rule.meta:
        if entry.key in _INT_KEYS and (isinstance(entry.value, bool) or not isinstance(entry.value, int)):
            yield Hit(f"meta {entry.key} must be an integer, got {entry.value!r}", entry.pos.line)
        elif entry.key == "score" and isinstance(entry.value, int) and not 0 <= entry.value <= 100:
            yield Hit(f"meta score {entry.value} is outside 0..100", entry.pos.line)
        elif entry.key == "severity" and str(entry.value).lower() not in ctx.config.lint.severity_values:
            allowed = ", ".join(ctx.config.lint.severity_values)
            yield Hit(f"meta severity {entry.value!r} is not one of {allowed}", entry.pos.line)
