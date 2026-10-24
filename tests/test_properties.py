"""Property-based tests for the front-end and the analyses built on it."""

from __future__ import annotations

import contextlib

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from yaraci.errors import SyntaxParseError, YaraciError
from yaraci.lint.checks_condition import Interval, filesize_interval
from yaraci.syntax import ast, parse_condition, parse_source, unparse
from yaraci.syntax.hexstr import parse_hex, render_elements

P = ast.Pos(1, 1)
idents = st.sampled_from(["$a", "$b", "$c1"])

leaf = st.one_of(
    st.builds(ast.BoolLit, st.just(P), st.booleans()),
    st.builds(ast.IntLit, st.just(P), st.integers(0, 2**20)),
    st.builds(ast.Keyword, st.just(P), st.sampled_from(["filesize", "entrypoint"])),
    st.builds(ast.StringMatch, st.just(P), idents),
    st.builds(ast.StringCount, st.just(P), idents),
    st.builds(ast.TextLit, st.just(P), st.binary(max_size=6)),
    st.builds(ast.Ident, st.just(P), st.sampled_from(["Rule_A", "x"])),
)


def _extend(children: st.SearchStrategy[ast.Expr]) -> st.SearchStrategy[ast.Expr]:
    ops = st.sampled_from(["and", "or", "==", "<", ">=", "+", "-", "*", "\\", "%", "|", "&", "^", "<<"])
    return st.one_of(
        st.builds(ast.Binary, st.just(P), ops, children, children),
        st.builds(ast.Unary, st.just(P), st.sampled_from(["not", "-", "~", "defined"]), children),
        st.builds(ast.Field, st.just(P), st.builds(ast.Ident, st.just(P), st.just("pe")), st.just("number")),
        st.builds(
            ast.Call, st.just(P), st.builds(ast.Ident, st.just(P), st.just("uint16")), st.tuples(children)
        ),
        st.builds(
            ast.Of,
            st.just(P),
            st.builds(ast.Quantifier, st.sampled_from([ast.QuantKind.ALL, ast.QuantKind.ANY])),
            st.just(ast.StringSet(None)),
        ),
    )


exprs = st.recursive(leaf, _extend, max_leaves=12)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(exprs)
def test_unparse_parse_is_a_fixed_point(expr: ast.Expr) -> None:
    text = unparse(expr)
    reparsed = parse_condition(text)
    assert unparse(reparsed) == text


@settings(max_examples=300)
@given(st.text(alphabet=st.sampled_from(list('rule{}()$#@!"=:/ \n\tabc01xX.-*[]|~%<>&^\\')), max_size=80))
def test_parser_fails_only_with_syntax_errors(text: str) -> None:
    with contextlib.suppress(SyntaxParseError):
        parse_source(text)


@settings(max_examples=200)
@given(
    st.lists(
        st.sampled_from(["4D", "5A", "??", "9?", "~00", "[2]", "[1-3]", "(01|02)"]), min_size=1, max_size=10
    )
)
def test_hex_render_round_trip(parts: list[str]) -> None:
    rendered = render_elements(parse_hex(" ".join(parts)))
    assert render_elements(parse_hex(rendered)) == rendered


@settings(max_examples=300)
@given(st.lists(st.tuples(st.sampled_from(["<", "<=", ">", ">=", "=="]), st.integers(0, 1000)), max_size=5))
def test_filesize_interval_matches_brute_force(constraints: list[tuple[str, int]]) -> None:
    text = " and ".join(f"filesize {op} {n}" for op, n in constraints) or "true"
    interval: Interval = filesize_interval(parse_condition(text))
    ops = {"<": int.__lt__, "<=": int.__le__, ">": int.__gt__, ">=": int.__ge__, "==": int.__eq__}
    satisfiable = any(all(ops[op](size, n) for op, n in constraints) for size in range(1002))
    assert satisfiable == (not interval.empty)


def test_errors_share_a_base() -> None:
    assert issubclass(SyntaxParseError, YaraciError)
