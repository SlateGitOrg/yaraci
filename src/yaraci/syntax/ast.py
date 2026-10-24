"""Abstract syntax tree for YARA rule files.

The tree is deliberately "lossy but faithful": it keeps every semantic element a
quality check needs (names, metadata, string definitions and modifiers, the full
condition expression) plus source positions, but not whitespace or comments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


@dataclass(frozen=True, slots=True)
class Pos:
    """1-based line/column of a node's first token."""

    line: int
    column: int


# ---------------------------------------------------------------------------
# Condition expressions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Expr:
    pos: Pos


@dataclass(frozen=True, slots=True)
class BoolLit(Expr):
    value: bool


@dataclass(frozen=True, slots=True)
class IntLit(Expr):
    value: int


@dataclass(frozen=True, slots=True)
class FloatLit(Expr):
    value: float


@dataclass(frozen=True, slots=True)
class TextLit(Expr):
    value: bytes


@dataclass(frozen=True, slots=True)
class RegexLit(Expr):
    pattern: str
    flags: str


@dataclass(frozen=True, slots=True)
class Keyword(Expr):
    """``filesize`` or ``entrypoint``."""

    name: str


@dataclass(frozen=True, slots=True)
class Ident(Expr):
    """A bare identifier: a rule reference, a module, or a loop variable."""

    name: str


@dataclass(frozen=True, slots=True)
class Field(Expr):
    obj: Expr
    name: str


@dataclass(frozen=True, slots=True)
class Index(Expr):
    obj: Expr
    index: Expr


@dataclass(frozen=True, slots=True)
class Call(Expr):
    func: Expr
    args: tuple[Expr, ...]


@dataclass(frozen=True, slots=True)
class Range(Expr):
    low: Expr
    high: Expr


@dataclass(frozen=True, slots=True)
class StringMatch(Expr):
    """``$a``, ``$a at <expr>`` or ``$a in (<range>)``; ``name`` is ``"$"`` inside for-of."""

    name: str
    at: Expr | None = None
    within: Range | None = None


@dataclass(frozen=True, slots=True)
class StringCount(Expr):
    name: str
    within: Range | None = None


@dataclass(frozen=True, slots=True)
class StringOffset(Expr):
    name: str
    index: Expr | None = None


@dataclass(frozen=True, slots=True)
class StringLength(Expr):
    name: str
    index: Expr | None = None


@dataclass(frozen=True, slots=True)
class Unary(Expr):
    op: str  # "not", "-", "~", "defined"
    operand: Expr


@dataclass(frozen=True, slots=True)
class Binary(Expr):
    op: str
    left: Expr
    right: Expr


class QuantKind(Enum):
    ALL = "all"
    ANY = "any"
    NONE = "none"
    COUNT = "count"
    PERCENT = "percent"


@dataclass(frozen=True, slots=True)
class Quantifier:
    kind: QuantKind
    expr: Expr | None = None  # for COUNT / PERCENT


@dataclass(frozen=True, slots=True)
class StringSet:
    """``them`` (``patterns is None``) or an explicit ``($a, $b*)`` list."""

    patterns: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class RuleSet:
    """A parenthesised list of rule names (wildcards allowed) for ``N of (r1, r2*)``."""

    patterns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Of(Expr):
    quant: Quantifier
    target: StringSet | RuleSet
    within: Range | None = None
    at: Expr | None = None


@dataclass(frozen=True, slots=True)
class ForOf(Expr):
    quant: Quantifier
    strings: StringSet
    body: Expr


@dataclass(frozen=True, slots=True)
class ForIn(Expr):
    quant: Quantifier
    variables: tuple[str, ...]
    iterable: Expr  # Range, Enumeration or an arbitrary expression
    body: Expr


@dataclass(frozen=True, slots=True)
class Enumeration(Expr):
    items: tuple[Expr, ...]


@dataclass(frozen=True, slots=True)
class With(Expr):
    bindings: tuple[tuple[str, Expr], ...]
    body: Expr


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


class StringKind(Enum):
    TEXT = "text"
    HEX = "hex"
    REGEX = "regex"


@dataclass(frozen=True, slots=True)
class Modifier:
    """A string modifier such as ``wide``, ``xor(0x01-0xff)`` or ``base64("...")``."""

    name: str
    args: tuple[int | bytes, ...] = ()

    def render(self) -> str:
        if not self.args:
            return self.name
        parts = []
        for arg in self.args:
            parts.append(f'"{arg.decode("latin-1")}"' if isinstance(arg, bytes) else str(arg))
        sep = "-" if self.name == "xor" and len(self.args) == 2 else ","
        return f"{self.name}({sep.join(parts)})"


@dataclass(frozen=True, slots=True)
class StringDef:
    identifier: str
    kind: StringKind
    value: bytes | str  # bytes for TEXT, raw body str for HEX, pattern str for REGEX
    regex_flags: str
    modifiers: tuple[Modifier, ...]
    pos: Pos

    def has_modifier(self, name: str) -> bool:
        return any(m.name == name for m in self.modifiers)

    @property
    def is_anonymous(self) -> bool:
        return self.identifier == "$"


MetaValue = str | int | bool


@dataclass(frozen=True, slots=True)
class MetaEntry:
    key: str
    value: MetaValue
    pos: Pos


@dataclass(slots=True)
class Rule:
    name: str
    is_private: bool
    is_global: bool
    tags: tuple[str, ...]
    meta: tuple[MetaEntry, ...]
    strings: tuple[StringDef, ...]
    condition: Expr
    pos: Pos
    end_line: int
    start_offset: int
    end_offset: int
    condition_pos: Pos
    source_path: str = ""
    suppressions: frozenset[str] = field(default_factory=frozenset)

    def meta_values(self, key: str) -> list[MetaValue]:
        return [m.value for m in self.meta if m.key == key]

    def first_meta(self, key: str) -> MetaValue | None:
        values = self.meta_values(key)
        return values[0] if values else None


@dataclass(frozen=True, slots=True)
class Import:
    module: str
    pos: Pos


@dataclass(frozen=True, slots=True)
class Include:
    path: str
    pos: Pos


@dataclass(slots=True)
class RuleFile:
    path: str
    source: str
    imports: tuple[Import, ...]
    includes: tuple[Include, ...]
    rules: tuple[Rule, ...]
    file_suppressions: frozenset[str] = field(default_factory=frozenset)
