"""Generic traversal helpers over condition ASTs."""

from __future__ import annotations

from collections.abc import Iterator

from yaraci.syntax import ast


def children(expr: ast.Expr) -> Iterator[ast.Expr]:  # noqa: PLR0912 - one branch per node type
    """Yield the direct sub-expressions of ``expr``."""
    if isinstance(expr, ast.Field):
        yield expr.obj
    elif isinstance(expr, ast.Index):
        yield expr.obj
        yield expr.index
    elif isinstance(expr, ast.Call):
        yield expr.func
        yield from expr.args
    elif isinstance(expr, ast.Range):
        yield expr.low
        yield expr.high
    elif isinstance(expr, ast.Enumeration):
        yield from expr.items
    elif isinstance(expr, ast.StringMatch):
        if expr.at is not None:
            yield expr.at
        if expr.within is not None:
            yield expr.within
    elif isinstance(expr, ast.StringCount):
        if expr.within is not None:
            yield expr.within
    elif isinstance(expr, ast.StringOffset | ast.StringLength):
        if expr.index is not None:
            yield expr.index
    elif isinstance(expr, ast.Unary):
        yield expr.operand
    elif isinstance(expr, ast.Binary):
        yield expr.left
        yield expr.right
    elif isinstance(expr, ast.Of):
        if expr.quant.expr is not None:
            yield expr.quant.expr
        if expr.within is not None:
            yield expr.within
        if expr.at is not None:
            yield expr.at
    elif isinstance(expr, ast.ForOf):
        if expr.quant.expr is not None:
            yield expr.quant.expr
        yield expr.body
    elif isinstance(expr, ast.ForIn):
        if expr.quant.expr is not None:
            yield expr.quant.expr
        yield expr.iterable
        yield expr.body
    elif isinstance(expr, ast.With):
        for _, value in expr.bindings:
            yield value
        yield expr.body


def walk(expr: ast.Expr) -> Iterator[ast.Expr]:
    """Pre-order traversal of ``expr`` and all its descendants (iterative)."""
    stack = [expr]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(children(node))))


def _bound_names(expr: ast.Expr) -> set[str]:
    names: set[str] = set()
    for node in walk(expr):
        if isinstance(node, ast.ForIn):
            names.update(node.variables)
        elif isinstance(node, ast.With):
            names.update(name for name, _ in node.bindings)
    return names


def free_identifiers(expr: ast.Expr) -> set[str]:
    """Bare identifiers that are not loop/with-bound: rule references and module roots."""
    bound = _bound_names(expr)
    return {n.name for n in walk(expr) if isinstance(n, ast.Ident) and n.name not in bound}


def rule_set_patterns(expr: ast.Expr) -> list[str]:
    """Rule-name patterns used in ``N of (rule_a, rule_b*)`` expressions."""
    out: list[str] = []
    for node in walk(expr):
        if isinstance(node, ast.Of) and isinstance(node.target, ast.RuleSet):
            out.extend(node.target.patterns)
    return out


def module_roots(expr: ast.Expr) -> set[str]:
    """Identifiers used as the root of a field access or call (``pe`` in ``pe.is_pe``)."""
    roots: set[str] = set()
    for node in walk(expr):
        if isinstance(node, ast.Field | ast.Call | ast.Index):
            base: ast.Expr = node
            while isinstance(base, ast.Field | ast.Call | ast.Index):
                base = base.obj if isinstance(base, ast.Field | ast.Index) else base.func
            if isinstance(base, ast.Ident):
                roots.add(base.name)
    return roots


def string_references(expr: ast.Expr) -> list[str]:
    """String identifiers referenced anywhere (``$a``, ``#a``, ``@a``, ``!a`` and set entries).

    ``them`` is reported as ``"$*"``; anonymous loop references (``$``) are skipped.
    """
    refs: list[str] = []
    for node in walk(expr):
        if isinstance(node, ast.StringMatch | ast.StringCount | ast.StringOffset | ast.StringLength):
            if node.name != "$":
                refs.append(node.name)
        elif isinstance(node, ast.Of) and isinstance(node.target, ast.StringSet):
            refs.extend(node.target.patterns or ("$*",))
        elif isinstance(node, ast.ForOf):
            refs.extend(node.strings.patterns or ("$*",))
    return refs


def expand_string_set(patterns: tuple[str, ...] | None, identifiers: list[str]) -> list[str]:
    """Resolve a string set (``None`` = ``them``) against a rule's string identifiers.

    Anonymous strings (``$``) are kept once per definition so that counts such as
    ``3 of them`` see every string.
    """
    if patterns is None:
        return list(identifiers)
    chosen: set[int] = set()
    for pat in patterns:
        for idx, ident in enumerate(identifiers):
            hit = ident.startswith(pat[:-1]) if pat.endswith("*") else ident == pat
            if hit:
                chosen.add(idx)
    return [identifiers[i] for i in sorted(chosen)]
