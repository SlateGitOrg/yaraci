"""Canonical pretty-printer for condition ASTs and string definitions.

Two conditions that differ only in whitespace, comments, redundant parentheses
or integer spelling (``0x10`` vs ``16``, ``1KB`` vs ``1024``) unparse to the
same text. The rule differ relies on this to separate cosmetic edits from
semantic ones.
"""

from __future__ import annotations

from yaraci.syntax import ast
from yaraci.syntax.hexstr import HexStringError, parse_hex, render_elements

# Binding strength; higher binds tighter. Mirrors the parser.
_PRECEDENCE = {
    "or": 1,
    "and": 2,
    "not": 3,
    "defined": 3,
    "==": 4,
    "!=": 4,
    "<": 4,
    "<=": 4,
    ">": 4,
    ">=": 4,
    "contains": 4,
    "icontains": 4,
    "startswith": 4,
    "istartswith": 4,
    "endswith": 4,
    "iendswith": 4,
    "iequals": 4,
    "matches": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "\\": 10,
    "%": 10,
}
_UNARY_PREC = 11
_BITWISE_PREC = 9  # operands of a comparison below this precedence get parenthesised
_ATOM_PREC = 12


def _text(value: bytes) -> str:
    out = []
    for byte in value:
        ch = chr(byte)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        else:
            out.append(f"\\x{byte:02x}")
    return '"' + "".join(out) + '"'


def _quant(q: ast.Quantifier) -> str:
    if q.kind is ast.QuantKind.COUNT:
        assert q.expr is not None
        return unparse(q.expr)
    if q.kind is ast.QuantKind.PERCENT:
        assert q.expr is not None
        return unparse(q.expr) + "%"
    return str(q.kind.value)


def _set(target: ast.StringSet | ast.RuleSet) -> str:
    if isinstance(target, ast.StringSet) and target.patterns is None:
        return "them"
    assert target.patterns is not None
    return "(" + ", ".join(target.patterns) + ")"


def _range(r: ast.Range) -> str:
    return f"({unparse(r.low)}..{unparse(r.high)})"


def _prec(expr: ast.Expr) -> int:
    if isinstance(expr, ast.Binary):
        return _PRECEDENCE[expr.op]
    if isinstance(expr, ast.Unary):
        return _PRECEDENCE["not"] if expr.op in ("not", "defined") else _UNARY_PREC
    if isinstance(expr, ast.StringMatch) and (expr.at is not None or expr.within is not None):
        return _PRECEDENCE["=="]
    if isinstance(expr, ast.Of | ast.ForOf | ast.ForIn | ast.With):
        return _PRECEDENCE["=="]
    return _ATOM_PREC


def _wrap(expr: ast.Expr, minimum: int) -> str:
    text = unparse(expr)
    return f"({text})" if _prec(expr) < minimum else text


def unparse(expr: ast.Expr) -> str:  # noqa: PLR0911, PLR0912 - one branch per node type
    """Render ``expr`` as canonical YARA condition text."""
    if isinstance(expr, ast.BoolLit):
        return "true" if expr.value else "false"
    if isinstance(expr, ast.IntLit):
        return str(expr.value)
    if isinstance(expr, ast.FloatLit):
        return repr(expr.value)
    if isinstance(expr, ast.TextLit):
        return _text(expr.value)
    if isinstance(expr, ast.RegexLit):
        return f"/{expr.pattern}/{expr.flags}"
    if isinstance(expr, ast.Keyword | ast.Ident):
        return expr.name
    if isinstance(expr, ast.Field):
        return f"{_wrap(expr.obj, _ATOM_PREC)}.{expr.name}"
    if isinstance(expr, ast.Index):
        return f"{_wrap(expr.obj, _ATOM_PREC)}[{unparse(expr.index)}]"
    if isinstance(expr, ast.Call):
        return f"{unparse(expr.func)}({', '.join(unparse(a) for a in expr.args)})"
    if isinstance(expr, ast.Range):
        return _range(expr)
    if isinstance(expr, ast.Enumeration):
        return "(" + ", ".join(unparse(i) for i in expr.items) + ")"
    if isinstance(expr, ast.StringMatch):
        if expr.at is not None:
            return f"{expr.name} at {_wrap(expr.at, _PRECEDENCE['|'])}"
        if expr.within is not None:
            return f"{expr.name} in {_range(expr.within)}"
        return expr.name
    if isinstance(expr, ast.StringCount):
        base = "#" + expr.name[1:]
        return f"{base} in {_range(expr.within)}" if expr.within is not None else base
    if isinstance(expr, ast.StringOffset | ast.StringLength):
        sigil = "@" if isinstance(expr, ast.StringOffset) else "!"
        base = sigil + expr.name[1:]
        return f"{base}[{unparse(expr.index)}]" if expr.index is not None else base
    if isinstance(expr, ast.Unary):
        if expr.op in ("not", "defined"):
            return f"{expr.op} {_wrap(expr.operand, _PRECEDENCE['not'])}"
        return f"{expr.op}{_wrap(expr.operand, _UNARY_PREC)}"
    if isinstance(expr, ast.Binary):
        prec = _PRECEDENCE[expr.op]
        # YARA binds bitwise operators tighter than comparisons (unlike C); keep
        # explicit parentheses there so the canonical text cannot be misread.
        clarify = _BITWISE_PREC if prec == _PRECEDENCE["=="] else 0
        left = _wrap(expr.left, max(prec, clarify))
        right = _wrap(expr.right, max(prec + 1, clarify))
        return f"{left} {expr.op} {right}"
    if isinstance(expr, ast.Of):
        text = f"{_quant(expr.quant)} of {_set(expr.target)}"
        if expr.within is not None:
            text += f" in {_range(expr.within)}"
        if expr.at is not None:
            text += f" at {_wrap(expr.at, _PRECEDENCE['|'])}"
        return text
    if isinstance(expr, ast.ForOf):
        return f"for {_quant(expr.quant)} of {_set(expr.strings)} : ({unparse(expr.body)})"
    if isinstance(expr, ast.ForIn):
        names = ", ".join(expr.variables)
        return f"for {_quant(expr.quant)} {names} in {unparse(expr.iterable)} : ({unparse(expr.body)})"
    if isinstance(expr, ast.With):
        binds = ", ".join(f"{name} = {unparse(value)}" for name, value in expr.bindings)
        return f"with {binds} : ({unparse(expr.body)})"
    raise TypeError(f"cannot unparse {type(expr).__name__}")


def render_string(sdef: ast.StringDef) -> str:
    """Render a string definition canonically (modifiers sorted)."""
    if sdef.kind is ast.StringKind.TEXT:
        assert isinstance(sdef.value, bytes)
        body = _text(sdef.value)
    elif sdef.kind is ast.StringKind.HEX:
        assert isinstance(sdef.value, str)
        try:
            body = "{ " + render_elements(parse_hex(sdef.value)) + " }"
        except HexStringError:
            body = "{ " + " ".join(sdef.value.upper().split()) + " }"
    else:
        assert isinstance(sdef.value, str)
        body = f"/{sdef.value}/{sdef.regex_flags}"
    mods = " ".join(sorted(m.render() for m in sdef.modifiers))
    return f"{body} {mods}".rstrip()
