"""Condition anti-pattern checks (YC4xx).

These are static analyses over the condition AST:

* **constraint detection** (YC401): does the condition depend on file content
  at all, or only on literals and ``filesize``?
* **set cardinality** (YC402): ``N of (...)`` where ``N`` exceeds the set size
  can never be satisfied.
* **filesize interval analysis** (YC403): the top-level ``and`` chain is folded
  into a closed integer interval ``[lo, hi]`` for ``filesize``; ``lo > hi``
  proves the rule can never match. Linear in the number of conjuncts.
* cost heuristics (YC404-YC408) on module use, whole-file functions and loops.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from yaraci.lint.model import Hit, LintContext, Severity, check
from yaraci.pack import PackRule
from yaraci.syntax import ast, unparse
from yaraci.syntax.hexstr import HexStringError, parse_hex
from yaraci.syntax.walk import expand_string_set, free_identifiers, module_roots, walk

_PARSED_MODULES = frozenset({"pe", "elf", "macho", "dotnet", "dex", "lnk"})
_MAGIC_READERS = frozenset(
    f"{sign}int{bits}{endian}" for sign in ("u", "") for bits in (8, 16, 32) for endian in ("", "be")
)
_WHOLE_FILE_FUNCS = frozenset(
    {
        "math.entropy",
        "math.mean",
        "math.deviation",
        "math.serial_correlation",
        "math.monte_carlo_pi",
        "math.count",
        "math.percentage",
        "math.mode",
        "hash.md5",
        "hash.sha1",
        "hash.sha256",
        "hash.crc32",
        "hash.checksum32",
    }
)
_LOOP_ITERATION_LIMIT = 10_000
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def conjuncts(expr: ast.Expr) -> list[ast.Expr]:
    """Flatten a top-level ``and`` chain into its terms, left to right."""
    if isinstance(expr, ast.Binary) and expr.op == "and":
        return conjuncts(expr.left) + conjuncts(expr.right)
    return [expr]


def is_content_constrained(expr: ast.Expr) -> bool:
    """True if evaluating ``expr`` inspects file content (strings, reads, modules, rules)."""
    content_nodes = (
        ast.StringMatch,
        ast.StringCount,
        ast.StringOffset,
        ast.StringLength,
        ast.Of,
        ast.ForOf,
        ast.Call,
        ast.Field,
    )
    if any(isinstance(node, content_nodes) for node in walk(expr)):
        return True
    return bool(free_identifiers(expr))


def _dotted(expr: ast.Expr) -> str | None:
    if isinstance(expr, ast.Ident):
        return expr.name
    if isinstance(expr, ast.Field):
        base = _dotted(expr.obj)
        return f"{base}.{expr.name}" if base else None
    return None


def _is_filesize(expr: ast.Expr) -> bool:
    return isinstance(expr, ast.Keyword) and expr.name == "filesize"


def _const(expr: ast.Expr) -> int | None:
    if isinstance(expr, ast.IntLit):
        return expr.value
    if isinstance(expr, ast.Unary) and expr.op == "-":
        inner = _const(expr.operand)
        return -inner if inner is not None else None
    return None


@dataclass(slots=True)
class Interval:
    """Closed integer interval; ``hi is None`` means unbounded above."""

    lo: int = 0
    hi: int | None = None

    @property
    def empty(self) -> bool:
        return self.hi is not None and self.lo > self.hi

    def apply(self, op: str, value: int) -> None:
        if op == "<":
            self._cap(value - 1)
        elif op == "<=":
            self._cap(value)
        elif op == ">":
            self.lo = max(self.lo, value + 1)
        elif op == ">=":
            self.lo = max(self.lo, value)
        elif op == "==":
            self.lo = max(self.lo, value)
            self._cap(value)

    def _cap(self, value: int) -> None:
        self.hi = value if self.hi is None else min(self.hi, value)


def filesize_interval(expr: ast.Expr) -> Interval:
    """Fold ``filesize <op> const`` conjuncts into an interval (``O(terms)``)."""
    interval = Interval()
    for term in conjuncts(expr):
        if not isinstance(term, ast.Binary) or term.op not in _FLIP:
            continue
        left, right, op = term.left, term.right, term.op
        if _is_filesize(right) and _const(left) is not None:
            left, right, op = right, left, _FLIP[op]
        value = _const(right)
        if _is_filesize(left) and value is not None:
            interval.apply(op, value)
    return interval


def _string_ids(pr: PackRule) -> list[str]:
    return [s.identifier for s in pr.rule.strings]


def _quant_count(quant: ast.Quantifier, size: int) -> int | None:
    """Minimum number of members the quantifier requires, if statically known."""
    if quant.kind is ast.QuantKind.ALL:
        return size
    if quant.kind is ast.QuantKind.ANY:
        return 1
    if quant.kind is ast.QuantKind.NONE:
        return 0
    value = _const(quant.expr) if quant.expr is not None else None
    if value is None:
        return None
    if quant.kind is ast.QuantKind.PERCENT:
        return -1 if value > 100 else -(-value * size // 100)
    return value


@check(
    "YC401",
    "unconstrained-condition",
    "condition",
    Severity.ERROR,
    summary="The condition never inspects file content, so the rule matches (nearly) every file.",
    rationale="A rule such as 'condition: true' or 'condition: filesize < 1MB' alerts on all goodware. "
    "Only global rules (which act as filters) may be content-free.",
)
def unconstrained(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    if pr.rule.is_global:
        return
    cond = pr.rule.condition
    if isinstance(cond, ast.BoolLit) and not cond.value:
        yield Hit("condition is constant 'false'; the rule can never match", cond.pos.line, cond.pos.column)
    elif not is_content_constrained(cond):
        yield Hit(f"condition '{unparse(cond)}' does not depend on file content", cond.pos.line)


@check(
    "YC402",
    "impossible-quantifier",
    "condition",
    Severity.ERROR,
    summary="An 'N of (set)' requires more members than the set contains (or the set is empty).",
    rationale="The expression is always false, so the rule (or that branch) silently never fires.",
)
def impossible_quantifier(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    ids = _string_ids(pr)
    defined_rules = [r.name for r in ctx.pack.rules[: pr.index]]
    for node in walk(pr.rule.condition):
        if isinstance(node, ast.Of | ast.ForOf):
            target = node.target if isinstance(node, ast.Of) else node.strings
            if isinstance(target, ast.StringSet):
                members = expand_string_set(target.patterns, ids)
            else:
                members = expand_string_set(target.patterns, defined_rules)
            need = _quant_count(node.quant, len(members))
            label = unparse(node) if isinstance(node, ast.Of) else "for-of loop"
            if not members:
                yield Hit(f"'{label}' refers to an empty set", node.pos.line, node.pos.column)
            elif need is not None and (need < 0 or need > len(members)):
                yield Hit(
                    f"'{label}' needs more than the {len(members)} member(s) in its set",
                    node.pos.line,
                    node.pos.column,
                )


@check(
    "YC403",
    "contradictory-filesize",
    "condition",
    Severity.ERROR,
    summary="The filesize constraints in the top-level conjunction cannot all hold.",
    rationale="Interval analysis proves the condition is unsatisfiable, e.g. "
    "'filesize > 100KB and filesize < 50KB'.",
)
def contradictory_filesize(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    interval = filesize_interval(pr.rule.condition)
    if interval.empty:
        yield Hit(
            f"filesize must be >= {interval.lo} and <= {interval.hi}: unsatisfiable",
            pr.rule.condition_pos.line,
        )


def _has_magic_check(expr: ast.Expr, module: str) -> bool:
    for node in walk(expr):
        if isinstance(node, ast.Call) and _dotted(node.func) in _MAGIC_READERS:
            return True
        if isinstance(node, ast.StringMatch) and node.at is not None and _const(node.at) == 0:
            return True
        name = _dotted(node)
        if name in {f"{module}.is_pe", f"{module}.is_dll", f"{module}.is_dotnet"}:
            return True
    return False


@check(
    "YC404",
    "module-without-magic",
    "condition",
    Severity.INFO,
    summary="A file-format module is used without a cheap magic-bytes check.",
    rationale="Guarding with uint16(0) == 0x5A4D (or similar) documents intent and short-circuits "
    "module evaluation on files of the wrong format.",
)
def module_without_magic(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for module in sorted(module_roots(pr.rule.condition) & _PARSED_MODULES):
        if not _has_magic_check(pr.rule.condition, module) and not pr.deps:
            yield Hit(f"uses module '{module}' without a magic-bytes guard", pr.rule.condition_pos.line)


@check(
    "YC405",
    "whole-file-function",
    "condition",
    Severity.WARNING,
    summary="A hash/math function runs over the whole file without a filesize upper bound.",
    rationale="math.entropy(0, filesize) and hash.*(0, filesize) are O(filesize) per scanned file; on "
    "large goodware they dominate scan time. Bound filesize first.",
)
def whole_file_function(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    if filesize_interval(pr.rule.condition).hi is not None:
        return
    for node in walk(pr.rule.condition):
        if (
            isinstance(node, ast.Call)
            and _dotted(node.func) in _WHOLE_FILE_FUNCS
            and any(_is_filesize(a) for a in node.args)
        ):
            yield Hit(f"'{unparse(node)}' reads the whole file", node.pos.line, node.pos.column)


def _range_size(rng: ast.Range) -> int | None:
    low, high = _const(rng.low), _const(rng.high)
    return high - low + 1 if low is not None and high is not None else None


@check(
    "YC406",
    "expensive-loop",
    "condition",
    Severity.WARNING,
    summary="A for-loop iterates over a range bounded by filesize or larger than 10,000.",
    rationale="Per-byte loops execute the body once per byte of every scanned file.",
)
def expensive_loop(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for node in walk(pr.rule.condition):
        if not isinstance(node, ast.ForIn) or not isinstance(node.iterable, ast.Range):
            continue
        if any(_is_filesize(n) for n in walk(node.iterable.high)):
            yield Hit("loop range is bounded by filesize", node.pos.line, node.pos.column)
            continue
        size = _range_size(node.iterable)
        if size is not None and size > _LOOP_ITERATION_LIMIT:
            yield Hit(f"loop iterates {size} times", node.pos.line, node.pos.column)


@check(
    "YC407",
    "redundant-range",
    "condition",
    Severity.INFO,
    summary="'in (0..filesize)' restricts nothing.",
    rationale="The whole file is the default search range; the clause only adds evaluation cost.",
)
def redundant_range(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    for node in walk(pr.rule.condition):
        within = node.within if isinstance(node, ast.StringMatch | ast.StringCount | ast.Of) else None
        if within is not None and _const(within.low) == 0 and _is_filesize(within.high):
            yield Hit("range (0..filesize) is redundant", node.pos.line, node.pos.column)


def _is_cheap(term: ast.Expr) -> bool:
    if isinstance(term, ast.Binary) and term.op in _FLIP:
        sides = (term.left, term.right)
        reads = any(isinstance(s, ast.Call) and _dotted(s.func) in _MAGIC_READERS for s in sides)
        return any(_is_filesize(s) for s in sides) or reads
    return False


def _is_expensive(term: ast.Expr) -> bool:
    for node in walk(term):
        if isinstance(node, ast.ForIn | ast.ForOf):
            return True
        if isinstance(node, ast.Call) and _dotted(node.func) in _WHOLE_FILE_FUNCS:
            return True
    return False


@check(
    "YC408",
    "cheap-checks-last",
    "condition",
    Severity.INFO,
    summary="A cheap filesize/magic check comes after an expensive loop or whole-file function.",
    rationale="'and' short-circuits left to right; putting cheap guards first skips the "
    "expensive term for most files.",
)
def cheap_checks_last(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    seen_expensive: ast.Expr | None = None
    for term in conjuncts(pr.rule.condition):
        if _is_expensive(term) and seen_expensive is None:
            seen_expensive = term
        elif _is_cheap(term) and seen_expensive is not None:
            yield Hit(
                f"move '{unparse(term)}' before the expensive term on line {seen_expensive.pos.line}",
                term.pos.line,
                term.pos.column,
            )
            return


@check(
    "YC409",
    "magic-via-string",
    "condition",
    Severity.INFO,
    summary="A short string is matched 'at 0' to test a file magic.",
    rationale="uint16(0) == 0x5A4D is evaluated without atoms or verification; '$mz at 0' needs both.",
)
def magic_via_string(ctx: LintContext, pr: PackRule) -> Iterator[Hit]:
    defs = {s.identifier: s for s in pr.rule.strings}
    for node in walk(pr.rule.condition):
        if isinstance(node, ast.StringMatch) and node.at is not None and _const(node.at) == 0:
            sdef = defs.get(node.name)
            if sdef is None or sdef.kind is ast.StringKind.REGEX or sdef.modifiers:
                continue
            length = _fixed_length(sdef)
            if length in (1, 2, 4):
                yield Hit(
                    f"'{node.name} at 0' tests a {length}-byte magic; prefer uint{length * 8}(0)",
                    node.pos.line,
                    node.pos.column,
                )


def _fixed_length(sdef: ast.StringDef) -> int | None:
    if isinstance(sdef.value, bytes):
        return len(sdef.value)
    try:
        elements = parse_hex(sdef.value)
    except HexStringError:
        return None
    return len(elements)
