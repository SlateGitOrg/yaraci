"""Recursive-descent parser for YARA rule files.

The grammar follows the YARA 4.x / YARA-X surface syntax closely enough for
static analysis: imports, includes, rule modifiers, tags, meta, strings with all
modifiers, and complete condition expressions (``of``, ``for .. of``,
``for .. in``, ``with``, ranges, module field access and calls).

Operator precedence, loosest first::

    or < and < not/defined < comparison/string-ops < | < ^ < & < shift
       < additive < multiplicative < unary minus/~ < postfix (. [] ())

The YARA engine remains the authority on validity; this parser exists so that
lint checks can reason about structure. If it rejects a file the engine accepts,
that is reported as a parser limitation, not a rule defect.
"""

from __future__ import annotations

import re

from yaraci.errors import SyntaxParseError
from yaraci.syntax import ast
from yaraci.syntax.lexer import Comment, tokenize
from yaraci.syntax.tokens import Token, TokenKind

_COMPARISON_OPS = frozenset({"==", "!=", "<", "<=", ">", ">="})
_STRING_OPS = frozenset(
    {
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iequals",
        "matches",
    }
)
_SIMPLE_MODIFIERS = frozenset({"nocase", "wide", "ascii", "fullword", "private"})
_SUPPRESS_RE = re.compile(r"yaraci:\s*ignore(-file)?\s+([A-Z]{2}\d{3}(?:\s*,\s*[A-Z]{2}\d{3})*)")


def _codes(text: str) -> frozenset[str]:
    return frozenset(code.strip() for code in text.split(",") if code.strip())


class Parser:
    """Parses one YARA source file into an :class:`ast.RuleFile`."""

    def __init__(self, source: str, path: str = "<string>") -> None:
        self.source = source
        self.path = path
        self.tokens, self.comments = tokenize(source, path)
        self.i = 0

    # -- token helpers -----------------------------------------------------
    @property
    def tok(self) -> Token:
        return self.tokens[self.i]

    def _peek(self, offset: int = 1) -> Token:
        idx = min(self.i + offset, len(self.tokens) - 1)
        return self.tokens[idx]

    def _next(self) -> Token:
        tok = self.tokens[self.i]
        if tok.kind is not TokenKind.EOF:
            self.i += 1
        return tok

    def _error(self, message: str, tok: Token | None = None) -> SyntaxParseError:
        tok = tok or self.tok
        found = tok.text or "end of file"
        return SyntaxParseError(f"{message} (found {found!r})", self.path, tok.line, tok.column)

    def _expect_op(self, op: str) -> Token:
        if not self.tok.is_op(op):
            raise self._error(f"expected {op!r}")
        return self._next()

    def _expect_kw(self, word: str) -> Token:
        if not self.tok.is_kw(word):
            raise self._error(f"expected {word!r}")
        return self._next()

    def _expect_kind(self, kind: TokenKind, what: str) -> Token:
        if self.tok.kind is not kind:
            raise self._error(f"expected {what}")
        return self._next()

    @staticmethod
    def _pos(tok: Token) -> ast.Pos:
        return ast.Pos(tok.line, tok.column)

    # -- file level -----------------------------------------------------------
    def parse(self) -> ast.RuleFile:
        imports: list[ast.Import] = []
        includes: list[ast.Include] = []
        rules: list[ast.Rule] = []
        while self.tok.kind is not TokenKind.EOF:
            if self.tok.is_kw("import"):
                tok = self._next()
                name = self._expect_kind(TokenKind.TEXT, "module name string")
                assert isinstance(name.value, bytes)
                imports.append(ast.Import(name.value.decode("utf-8"), self._pos(tok)))
            elif self.tok.is_kw("include"):
                tok = self._next()
                name = self._expect_kind(TokenKind.TEXT, "include path string")
                assert isinstance(name.value, bytes)
                includes.append(ast.Include(name.value.decode("utf-8"), self._pos(tok)))
            else:
                rules.append(self._parse_rule())
        file_supp, rule_supp = self._suppressions(rules)
        for rule in rules:
            rule.suppressions = rule_supp.get(rule.name, frozenset()) | rule.suppressions
        return ast.RuleFile(
            path=self.path,
            source=self.source,
            imports=tuple(imports),
            includes=tuple(includes),
            rules=tuple(rules),
            file_suppressions=file_supp,
        )

    def _suppressions(self, rules: list[ast.Rule]) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
        file_level: set[str] = set()
        per_rule: dict[str, frozenset[str]] = {}
        for comment in self.comments:
            match = _SUPPRESS_RE.search(comment.text)
            if not match:
                continue
            codes = _codes(match.group(2))
            if match.group(1):
                file_level |= codes
                continue
            target = self._rule_for_comment(comment, rules)
            if target is not None:
                per_rule[target.name] = per_rule.get(target.name, frozenset()) | codes
        return frozenset(file_level), per_rule

    @staticmethod
    def _rule_for_comment(comment: Comment, rules: list[ast.Rule]) -> ast.Rule | None:
        for rule in rules:
            if rule.pos.line - 1 <= comment.line <= rule.end_line:
                return rule
        return None

    def _parse_rule(self) -> ast.Rule:
        first = self.tok
        is_private = is_global = False
        while self.tok.is_kw("private", "global"):
            if self.tok.text == "private":
                is_private = True
            else:
                is_global = True
            self._next()
        rule_tok = self._expect_kw("rule")
        name_tok = self._expect_kind(TokenKind.IDENT, "rule name")
        tags: list[str] = []
        if self.tok.is_op(":"):
            self._next()
            while self.tok.kind is TokenKind.IDENT:
                tags.append(self._next().text)
            if not tags:
                raise self._error("expected at least one tag after ':'")
        self._expect_op("{")
        meta: tuple[ast.MetaEntry, ...] = ()
        strings: tuple[ast.StringDef, ...] = ()
        if self.tok.is_kw("meta"):
            meta = self._parse_meta()
        if self.tok.is_kw("strings"):
            strings = self._parse_strings()
        cond_tok = self._expect_kw("condition")
        self._expect_op(":")
        condition = self.parse_expression()
        end = self._expect_op("}")
        suppressions: set[str] = set()
        for entry in meta:
            if entry.key == "yaraci_ignore" and isinstance(entry.value, str):
                suppressions |= _codes(entry.value)
        start_tok = first if first.is_kw("private", "global") else rule_tok
        return ast.Rule(
            name=name_tok.text,
            is_private=is_private,
            is_global=is_global,
            tags=tuple(tags),
            meta=meta,
            strings=strings,
            condition=condition,
            pos=self._pos(start_tok),
            end_line=end.line,
            start_offset=start_tok.start,
            end_offset=end.end,
            condition_pos=self._pos(cond_tok),
            source_path=self.path,
            suppressions=frozenset(suppressions),
        )

    def _parse_meta(self) -> tuple[ast.MetaEntry, ...]:
        self._next()
        self._expect_op(":")
        entries: list[ast.MetaEntry] = []
        while self.tok.kind in (TokenKind.IDENT, TokenKind.KEYWORD) and self._peek().is_op("="):
            if self.tok.is_kw("strings", "condition"):
                break
            key_tok = self._next()
            self._next()  # '='
            value = self._parse_meta_value()
            entries.append(ast.MetaEntry(key_tok.text, value, self._pos(key_tok)))
        return tuple(entries)

    def _parse_meta_value(self) -> ast.MetaValue:
        cur = self.tok
        if cur.kind is TokenKind.TEXT:
            self._next()
            assert isinstance(cur.value, bytes)
            return cur.value.decode("utf-8", errors="replace")
        if cur.kind is TokenKind.INTEGER:
            self._next()
            assert isinstance(cur.value, int)
            return cur.value
        if cur.is_op("-") and self._peek().kind is TokenKind.INTEGER:
            self._next()
            number = self._next().value
            assert isinstance(number, int)
            return -number
        if cur.is_kw("true", "false"):
            self._next()
            return cur.text == "true"
        raise self._error("expected meta value")

    def _parse_strings(self) -> tuple[ast.StringDef, ...]:
        self._next()
        self._expect_op(":")
        defs: list[ast.StringDef] = []
        while self.tok.kind is TokenKind.STRING_ID:
            id_tok = self._next()
            self._expect_op("=")
            val = self._next()
            kind: ast.StringKind
            flags = ""
            value: bytes | str
            if val.kind is TokenKind.TEXT:
                kind = ast.StringKind.TEXT
                assert isinstance(val.value, bytes)
                value = val.value
            elif val.kind is TokenKind.HEX:
                kind = ast.StringKind.HEX
                assert isinstance(val.value, str)
                value = val.value
            elif val.kind is TokenKind.REGEX:
                kind = ast.StringKind.REGEX
                assert isinstance(val.value, tuple)
                value, flags = val.value
            else:
                raise self._error("expected text, hex or regex string", val)
            defs.append(
                ast.StringDef(
                    identifier=id_tok.text,
                    kind=kind,
                    value=value,
                    regex_flags=flags,
                    modifiers=self._parse_modifiers(),
                    pos=self._pos(id_tok),
                )
            )
        if not defs:
            raise self._error("expected at least one string definition")
        return tuple(defs)

    def _parse_modifiers(self) -> tuple[ast.Modifier, ...]:
        mods: list[ast.Modifier] = []
        while self.tok.kind is TokenKind.KEYWORD:
            word = self.tok.text
            if word in _SIMPLE_MODIFIERS:
                self._next()
                mods.append(ast.Modifier(word))
            elif word == "xor":
                self._next()
                args: list[int | bytes] = []
                if self.tok.is_op("("):
                    self._next()
                    args.append(self._int_literal())
                    if self.tok.is_op("-"):
                        self._next()
                        args.append(self._int_literal())
                    self._expect_op(")")
                mods.append(ast.Modifier("xor", tuple(args)))
            elif word in ("base64", "base64wide"):
                self._next()
                b64_args: tuple[int | bytes, ...] = ()
                if self.tok.is_op("("):
                    self._next()
                    alpha = self._expect_kind(TokenKind.TEXT, "base64 alphabet")
                    assert isinstance(alpha.value, bytes)
                    b64_args = (alpha.value,)
                    self._expect_op(")")
                mods.append(ast.Modifier(word, b64_args))
            else:
                break
        return tuple(mods)

    def _int_literal(self) -> int:
        tok = self._expect_kind(TokenKind.INTEGER, "integer")
        assert isinstance(tok.value, int)
        return tok.value

    # -- expressions ------------------------------------------------------------
    def parse_expression(self) -> ast.Expr:
        return self._parse_or()

    def _parse_or(self) -> ast.Expr:
        left = self._parse_and()
        while self.tok.is_kw("or"):
            tok = self._next()
            left = ast.Binary(self._pos(tok), "or", left, self._parse_and())
        return left

    def _parse_and(self) -> ast.Expr:
        left = self._parse_not()
        while self.tok.is_kw("and"):
            tok = self._next()
            left = ast.Binary(self._pos(tok), "and", left, self._parse_not())
        return left

    def _parse_not(self) -> ast.Expr:
        if self.tok.is_kw("not", "defined"):
            tok = self._next()
            return ast.Unary(self._pos(tok), tok.text, self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self) -> ast.Expr:
        left = self._parse_bitor()
        while (self.tok.kind is TokenKind.OP and self.tok.text in _COMPARISON_OPS) or (
            self.tok.kind is TokenKind.KEYWORD and self.tok.text in _STRING_OPS
        ):
            tok = self._next()
            left = ast.Binary(self._pos(tok), tok.text, left, self._parse_bitor())
        return left

    def _binary_level(self, ops: frozenset[str], operand: str) -> ast.Expr:
        parse_operand = getattr(self, operand)
        left: ast.Expr = parse_operand()
        while self.tok.kind is TokenKind.OP and self.tok.text in ops:
            if self.tok.text == "%" and self._peek().is_kw("of"):
                break
            tok = self._next()
            left = ast.Binary(self._pos(tok), tok.text, left, parse_operand())
        return left

    def _parse_bitor(self) -> ast.Expr:
        return self._binary_level(frozenset({"|"}), "_parse_bitxor")

    def _parse_bitxor(self) -> ast.Expr:
        return self._binary_level(frozenset({"^"}), "_parse_bitand")

    def _parse_bitand(self) -> ast.Expr:
        return self._binary_level(frozenset({"&"}), "_parse_shift")

    def _parse_shift(self) -> ast.Expr:
        return self._binary_level(frozenset({"<<", ">>"}), "_parse_additive")

    def _parse_additive(self) -> ast.Expr:
        return self._binary_level(frozenset({"+", "-"}), "_parse_multiplicative")

    def _parse_multiplicative(self) -> ast.Expr:
        return self._binary_level(frozenset({"*", "\\", "%"}), "_parse_unary")

    def _parse_unary(self) -> ast.Expr:
        if self.tok.is_op("-", "~"):
            tok = self._next()
            return ast.Unary(self._pos(tok), tok.text, self._parse_unary())
        return self._parse_postfix(self._parse_primary())

    def _parse_postfix(self, expr: ast.Expr) -> ast.Expr:
        while True:
            if self.tok.is_op("."):
                self._next()
                name = self._next()
                if name.kind not in (TokenKind.IDENT, TokenKind.KEYWORD):
                    raise self._error("expected field name", name)
                expr = ast.Field(expr.pos, expr, name.text)
            elif self.tok.is_op("["):
                self._next()
                index = self.parse_expression()
                self._expect_op("]")
                expr = ast.Index(expr.pos, expr, index)
            elif self.tok.is_op("(") and isinstance(expr, ast.Ident | ast.Field):
                self._next()
                args: list[ast.Expr] = []
                if not self.tok.is_op(")"):
                    args.append(self.parse_expression())
                    while self.tok.is_op(","):
                        self._next()
                        args.append(self.parse_expression())
                self._expect_op(")")
                expr = ast.Call(expr.pos, expr, tuple(args))
            else:
                return expr

    def _parse_primary(self) -> ast.Expr:  # noqa: PLR0911, PLR0912, PLR0915 - one branch per token kind
        tok = self.tok
        pos = self._pos(tok)
        kind = tok.kind
        if tok.is_kw("true", "false"):
            self._next()
            return ast.BoolLit(pos, tok.text == "true")
        if tok.is_kw("filesize", "entrypoint"):
            self._next()
            return ast.Keyword(pos, tok.text)
        if tok.is_kw("all", "any", "none"):
            quant = self._parse_quantifier()
            return self._parse_of(pos, quant)
        if tok.is_kw("for"):
            return self._parse_for()
        if tok.is_kw("with"):
            return self._parse_with()
        if tok.is_kw("them"):
            raise self._error("'them' is only valid after 'of'")
        if kind is TokenKind.INTEGER:
            if self._peek().is_kw("of") or (self._peek().is_op("%") and self._peek(2).is_kw("of")):
                quant = self._parse_quantifier()
                return self._parse_of(pos, quant)
            self._next()
            assert isinstance(tok.value, int)
            return ast.IntLit(pos, tok.value)
        if kind is TokenKind.FLOAT:
            self._next()
            assert isinstance(tok.value, float)
            return ast.FloatLit(pos, tok.value)
        if kind is TokenKind.TEXT:
            self._next()
            assert isinstance(tok.value, bytes)
            return ast.TextLit(pos, tok.value)
        if kind is TokenKind.REGEX:
            self._next()
            assert isinstance(tok.value, tuple)
            return ast.RegexLit(pos, tok.value[0], tok.value[1])
        if kind is TokenKind.STRING_ID:
            return self._parse_string_match()
        if kind is TokenKind.STRING_COUNT:
            self._next()
            count_within: ast.Range | None = None
            if self.tok.is_kw("in"):
                self._next()
                count_within = self._parse_range()
            return ast.StringCount(pos, "$" + tok.text[1:], count_within)
        if kind in (TokenKind.STRING_OFFSET, TokenKind.STRING_LENGTH):
            self._next()
            index = None
            if self.tok.is_op("["):
                self._next()
                index = self.parse_expression()
                self._expect_op("]")
            cls = ast.StringOffset if kind is TokenKind.STRING_OFFSET else ast.StringLength
            return cls(pos, "$" + tok.text[1:], index)
        if kind is TokenKind.IDENT:
            if self._peek().is_kw("of"):
                quant = self._parse_quantifier()
                return self._parse_of(pos, quant)
            self._next()
            return ast.Ident(pos, tok.text)
        if tok.is_op("("):
            self._next()
            inner = self.parse_expression()
            self._expect_op(")")
            if self.tok.is_kw("of") or (self.tok.is_op("%") and self._peek().is_kw("of")):
                quant_kind = ast.QuantKind.COUNT
                if self.tok.is_op("%"):
                    self._next()
                    quant_kind = ast.QuantKind.PERCENT
                return self._parse_of(pos, ast.Quantifier(quant_kind, inner))
            return inner
        raise self._error("expected expression")

    def _parse_string_match(self) -> ast.Expr:
        tok = self._next()
        pos = self._pos(tok)
        if self.tok.is_kw("at"):
            self._next()
            return ast.StringMatch(pos, tok.text, at=self._parse_bitor())
        if self.tok.is_kw("in"):
            self._next()
            return ast.StringMatch(pos, tok.text, within=self._parse_range())
        return ast.StringMatch(pos, tok.text)

    def _parse_range(self) -> ast.Range:
        open_tok = self._expect_op("(")
        low = self._parse_bitor()
        self._expect_op("..")
        high = self._parse_bitor()
        self._expect_op(")")
        return ast.Range(self._pos(open_tok), low, high)

    def _parse_quantifier(self) -> ast.Quantifier:
        tok = self.tok
        if tok.is_kw("all", "any", "none"):
            self._next()
            return ast.Quantifier(ast.QuantKind(tok.text))
        expr: ast.Expr
        if tok.kind is TokenKind.INTEGER:
            self._next()
            assert isinstance(tok.value, int)
            expr = ast.IntLit(self._pos(tok), tok.value)
        elif tok.kind is TokenKind.IDENT:
            self._next()
            expr = ast.Ident(self._pos(tok), tok.text)
        elif tok.is_op("("):
            expr = self._parse_paren_quant()
        else:
            raise self._error("expected quantifier")
        if self.tok.is_op("%"):
            self._next()
            return ast.Quantifier(ast.QuantKind.PERCENT, expr)
        return ast.Quantifier(ast.QuantKind.COUNT, expr)

    def _parse_paren_quant(self) -> ast.Expr:
        self._expect_op("(")
        expr = self.parse_expression()
        self._expect_op(")")
        return expr

    def _parse_of(self, pos: ast.Pos, quant: ast.Quantifier) -> ast.Expr:
        self._expect_kw("of")
        target = self._parse_set()
        within: ast.Range | None = None
        at: ast.Expr | None = None
        if isinstance(target, ast.StringSet):
            if self.tok.is_kw("in"):
                self._next()
                within = self._parse_range()
            elif self.tok.is_kw("at"):
                self._next()
                at = self._parse_bitor()
        return ast.Of(pos, quant, target, within, at)

    def _parse_set(self) -> ast.StringSet | ast.RuleSet:
        if self.tok.is_kw("them"):
            self._next()
            return ast.StringSet(None)
        self._expect_op("(")
        items: list[str] = []
        kinds: set[TokenKind] = set()
        while True:
            item = self._next()
            if item.kind is TokenKind.STRING_ID:
                items.append(item.text)
            elif item.kind is TokenKind.IDENT:
                name = item.text
                if self.tok.is_op("*"):
                    self._next()
                    name += "*"
                items.append(name)
            else:
                raise self._error("expected string or rule identifier in set", item)
            kinds.add(item.kind)
            if self.tok.is_op(","):
                self._next()
                continue
            self._expect_op(")")
            break
        if len(kinds) > 1:
            raise self._error("cannot mix string and rule identifiers in one set")
        if TokenKind.STRING_ID in kinds:
            return ast.StringSet(tuple(items))
        return ast.RuleSet(tuple(items))

    def _parse_for(self) -> ast.Expr:
        for_tok = self._next()
        pos = self._pos(for_tok)
        quant = self._parse_quantifier()
        if self.tok.is_kw("of"):
            self._next()
            target = self._parse_set()
            if not isinstance(target, ast.StringSet):
                raise self._error("'for .. of' requires a string set")
            self._expect_op(":")
            body = self._parse_paren_body()
            return ast.ForOf(pos, quant, target, body)
        variables = [self._expect_kind(TokenKind.IDENT, "loop variable").text]
        while self.tok.is_op(","):
            self._next()
            variables.append(self._expect_kind(TokenKind.IDENT, "loop variable").text)
        self._expect_kw("in")
        iterable = self._parse_iterable()
        self._expect_op(":")
        body = self._parse_paren_body()
        return ast.ForIn(pos, quant, tuple(variables), iterable, body)

    def _parse_iterable(self) -> ast.Expr:
        if not self.tok.is_op("("):
            return self._parse_unary()
        open_tok = self._next()
        pos = self._pos(open_tok)
        first = self.parse_expression()
        if self.tok.is_op(".."):
            self._next()
            high = self.parse_expression()
            self._expect_op(")")
            return ast.Range(pos, first, high)
        items = [first]
        while self.tok.is_op(","):
            self._next()
            items.append(self.parse_expression())
        self._expect_op(")")
        return ast.Enumeration(pos, tuple(items))

    def _parse_paren_body(self) -> ast.Expr:
        self._expect_op("(")
        body = self.parse_expression()
        self._expect_op(")")
        return body

    def _parse_with(self) -> ast.Expr:
        tok = self._next()
        bindings: list[tuple[str, ast.Expr]] = []
        while True:
            name = self._expect_kind(TokenKind.IDENT, "binding name").text
            self._expect_op("=")
            bindings.append((name, self.parse_expression()))
            if not self.tok.is_op(","):
                break
            self._next()
        self._expect_op(":")
        return ast.With(self._pos(tok), tuple(bindings), self._parse_paren_body())


def parse_source(source: str, path: str = "<string>") -> ast.RuleFile:
    """Parse YARA ``source`` text. Raises :class:`SyntaxParseError` on failure."""
    return Parser(source, path).parse()


def parse_condition(text: str) -> ast.Expr:
    """Parse a standalone condition expression (used by tests and the differ)."""
    parser = Parser(text, "<condition>")
    expr = parser.parse_expression()
    if parser.tok.kind is not TokenKind.EOF:
        raise parser._error("unexpected trailing input")
    return expr
