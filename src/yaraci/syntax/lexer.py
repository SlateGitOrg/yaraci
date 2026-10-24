"""Hand-written lexer for the YARA rule language.

YARA's grammar is context sensitive in two places: ``{`` after ``=`` opens a hex
string (elsewhere it is a rule-body brace) and ``/`` after ``=`` or ``matches``
opens a regular expression (elsewhere it is not an operator at all; YARA spells
division ``\\``). The lexer resolves both with one token of look-behind, which is
sufficient because ``=`` only ever appears in meta and string definitions.

Comments are not emitted as tokens but are collected in :attr:`Lexer.comments`
so that suppression directives (``// yaraci:ignore YC301``) can be honoured.
"""

from __future__ import annotations

from dataclasses import dataclass

from yaraci.errors import SyntaxParseError
from yaraci.syntax.tokens import KEYWORDS, OPERATORS, Token, TokenKind

_IDENT_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = _IDENT_START | frozenset("0123456789")
_SIGIL_KINDS = {
    "$": TokenKind.STRING_ID,
    "#": TokenKind.STRING_COUNT,
    "@": TokenKind.STRING_OFFSET,
    "!": TokenKind.STRING_LENGTH,
}
_ESCAPES = {"n": 0x0A, "t": 0x09, "r": 0x0D, '"': 0x22, "\\": 0x5C}


@dataclass(frozen=True, slots=True)
class Comment:
    """A source comment and the line it starts on."""

    text: str
    line: int


class Lexer:
    """Converts YARA source text into a list of :class:`Token` objects."""

    def __init__(self, source: str, path: str = "<string>") -> None:
        self.src = source
        self.path = path
        self.pos = 0
        self.line = 1
        self.col = 1
        self.comments: list[Comment] = []
        self._prev: Token | None = None

    # -- helpers -----------------------------------------------------------
    def _error(self, message: str, line: int | None = None, col: int | None = None) -> SyntaxParseError:
        return SyntaxParseError(message, self.path, line or self.line, col or self.col)

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.src[idx] if idx < len(self.src) else ""

    def _advance(self, count: int = 1) -> str:
        chunk = self.src[self.pos : self.pos + count]
        for ch in chunk:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += count
        return chunk

    def _skip_trivia(self) -> None:
        while self.pos < len(self.src):
            ch = self._peek()
            if ch in " \t\r\n\f\v":
                self._advance()
            elif ch == "/" and self._peek(1) == "/":
                line = self.line
                end = self.src.find("\n", self.pos)
                end = len(self.src) if end == -1 else end
                self.comments.append(Comment(self.src[self.pos + 2 : end].strip(), line))
                self._advance(end - self.pos)
            elif ch == "/" and self._peek(1) == "*":
                line, col = self.line, self.col
                end = self.src.find("*/", self.pos + 2)
                if end == -1:
                    raise self._error("unterminated block comment", line, col)
                self.comments.append(Comment(self.src[self.pos + 2 : end].strip(), line))
                self._advance(end + 2 - self.pos)
            else:
                return

    def _make(self, kind: TokenKind, start: int, line: int, col: int, value: object) -> Token:
        tok = Token(kind, self.src[start : self.pos], value, line, col, start, self.pos)
        self._prev = tok
        return tok

    # -- public API ----------------------------------------------------------
    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while True:
            tok = self.next_token()
            tokens.append(tok)
            if tok.kind is TokenKind.EOF:
                return tokens

    def next_token(self) -> Token:  # noqa: PLR0911 - one return per token class
        self._skip_trivia()
        start, line, col = self.pos, self.line, self.col
        if self.pos >= len(self.src):
            return Token(TokenKind.EOF, "", None, line, col, start, start)
        ch = self._peek()
        prev = self._prev
        after_assign = prev is not None and prev.is_op("=")
        if ch == "{" and after_assign:
            return self._lex_hex(start, line, col)
        if ch == "/" and prev is not None and (after_assign or prev.is_kw("matches")):
            return self._lex_regex(start, line, col)
        if ch == '"':
            return self._lex_text(start, line, col)
        if ch.isdigit():
            return self._lex_number(start, line, col)
        if ch in _IDENT_START:
            while self._peek() in _IDENT_CHARS and self._peek():
                self._advance()
            word = self.src[start : self.pos]
            kind = TokenKind.KEYWORD if word in KEYWORDS else TokenKind.IDENT
            return self._make(kind, start, line, col, word)
        if ch in _SIGIL_KINDS and not (ch == "!" and self._peek(1) == "="):
            self._advance()
            while self._peek() and self._peek() in _IDENT_CHARS:
                self._advance()
            if ch == "$" and self._peek() == "*":
                self._advance()
            return self._make(_SIGIL_KINDS[ch], start, line, col, self.src[start : self.pos])
        for op in OPERATORS:
            if self.src.startswith(op, self.pos):
                self._advance(len(op))
                return self._make(TokenKind.OP, start, line, col, op)
        raise self._error(f"unexpected character {ch!r}")

    # -- literal lexers ------------------------------------------------------
    def _lex_text(self, start: int, line: int, col: int) -> Token:
        self._advance()  # opening quote
        out = bytearray()
        while True:
            ch = self._peek()
            if ch in {"", "\n"}:
                raise self._error("unterminated text string", line, col)
            if ch == '"':
                self._advance()
                break
            if ch == "\\":
                esc = self._peek(1)
                if esc in _ESCAPES:
                    out.append(_ESCAPES[esc])
                    self._advance(2)
                elif esc == "x":
                    digits = self.src[self.pos + 2 : self.pos + 4]
                    try:
                        out.append(int(digits, 16))
                    except ValueError:
                        raise self._error(f"invalid \\x escape {digits!r}") from None
                    self._advance(4)
                else:
                    raise self._error(f"invalid escape sequence \\{esc}")
                continue
            out.extend(ch.encode("utf-8"))
            self._advance()
        return self._make(TokenKind.TEXT, start, line, col, bytes(out))

    def _lex_hex(self, start: int, line: int, col: int) -> Token:
        end = self.src.find("}", self.pos)
        if end == -1:
            raise self._error("unterminated hex string", line, col)
        body = self.src[self.pos + 1 : end]
        self._advance(end + 1 - self.pos)
        return self._make(TokenKind.HEX, start, line, col, body.strip())

    def _lex_regex(self, start: int, line: int, col: int) -> Token:
        self._advance()  # opening slash
        in_class = False
        body_start = self.pos
        while True:
            ch = self._peek()
            if ch in {"", "\n"}:
                raise self._error("unterminated regular expression", line, col)
            if ch == "\\":
                self._advance(2)
                continue
            if ch == "[":
                in_class = True
            elif ch == "]":
                in_class = False
            elif ch == "/" and not in_class:
                break
            self._advance()
        pattern = self.src[body_start : self.pos]
        self._advance()  # closing slash
        flag_start = self.pos
        while self._peek() in ("i", "s") and self._peek():
            self._advance()
        flags = self.src[flag_start : self.pos]
        return self._make(TokenKind.REGEX, start, line, col, (pattern, flags))

    def _lex_number(self, start: int, line: int, col: int) -> Token:
        if self._peek() == "0" and self._peek(1) in ("x", "X"):
            self._advance(2)
            while self._peek() and self._peek() in "0123456789abcdefABCDEF":
                self._advance()
            text = self.src[start + 2 : self.pos]
            if not text:
                raise self._error("hex literal without digits", line, col)
            return self._make(TokenKind.INTEGER, start, line, col, int(text, 16))
        if self._peek() == "0" and self._peek(1) == "o":
            self._advance(2)
            while self._peek() and self._peek() in "01234567":
                self._advance()
            text = self.src[start + 2 : self.pos]
            if not text:
                raise self._error("octal literal without digits", line, col)
            return self._make(TokenKind.INTEGER, start, line, col, int(text, 8))
        while self._peek().isdigit():
            self._advance()
        if self._peek() == "." and self._peek(1).isdigit():
            self._advance()
            while self._peek().isdigit():
                self._advance()
            return self._make(TokenKind.FLOAT, start, line, col, float(self.src[start : self.pos]))
        value = int(self.src[start : self.pos])
        if self.src.startswith("KB", self.pos):
            self._advance(2)
            value *= 1024
        elif self.src.startswith("MB", self.pos):
            self._advance(2)
            value *= 1024 * 1024
        return self._make(TokenKind.INTEGER, start, line, col, value)


def tokenize(source: str, path: str = "<string>") -> tuple[list[Token], list[Comment]]:
    """Tokenize ``source`` and return ``(tokens, comments)``."""
    lexer = Lexer(source, path)
    tokens = lexer.tokenize()
    return tokens, lexer.comments
