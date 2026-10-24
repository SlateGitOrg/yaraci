"""Token model for the YARA lexer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TokenKind(Enum):
    """Lexical categories produced by :mod:`yaraci.syntax.lexer`."""

    IDENT = "ident"
    KEYWORD = "keyword"
    STRING_ID = "string_id"  # $name, $name*, $
    STRING_COUNT = "string_count"  # #name, #
    STRING_OFFSET = "string_offset"  # @name, @
    STRING_LENGTH = "string_length"  # !name, !
    INTEGER = "integer"
    FLOAT = "float"
    TEXT = "text"  # "quoted"
    HEX = "hex"  # { 4D 5A ?? }
    REGEX = "regex"  # /re/is
    OP = "op"
    EOF = "eof"


KEYWORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "ascii",
        "at",
        "base64",
        "base64wide",
        "condition",
        "contains",
        "defined",
        "endswith",
        "entrypoint",
        "false",
        "filesize",
        "for",
        "fullword",
        "global",
        "icontains",
        "iendswith",
        "iequals",
        "import",
        "in",
        "include",
        "istartswith",
        "matches",
        "meta",
        "none",
        "nocase",
        "not",
        "of",
        "or",
        "private",
        "rule",
        "startswith",
        "strings",
        "them",
        "true",
        "wide",
        "with",
        "xor",
    }
)

# Multi-character operators must be listed before their prefixes.
OPERATORS = (
    "..",
    "==",
    "!=",
    "<=",
    ">=",
    "<<",
    ">>",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ":",
    "=",
    "<",
    ">",
    "+",
    "-",
    "*",
    "\\",
    "%",
    "&",
    "|",
    "^",
    "~",
    ".",
)


@dataclass(frozen=True, slots=True)
class Token:
    """A lexical token with its source position.

    ``value`` holds the decoded payload: identifier text, integer value, decoded
    text-string bytes, raw hex-string body, ``(pattern, flags)`` for regexes.
    ``start``/``end`` are character offsets into the source text.
    """

    kind: TokenKind
    text: str
    value: object
    line: int
    column: int
    start: int
    end: int

    def is_kw(self, *words: str) -> bool:
        return self.kind is TokenKind.KEYWORD and self.text in words

    def is_op(self, *ops: str) -> bool:
        return self.kind is TokenKind.OP and self.text in ops
