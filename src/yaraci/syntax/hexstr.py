"""Parser for the body of YARA hex strings (``{ 4D 5A ?? [2-4] ( 90 | CC ) ~00 }``).

The resulting element tree supports two analyses: canonical rendering (for the
differ) and extraction of fixed-byte runs (for atom-quality estimation).
"""

from __future__ import annotations

from dataclasses import dataclass

from yaraci.errors import YaraciError

_HEX = "0123456789ABCDEF"


class HexStringError(YaraciError):
    """The hex string body is malformed."""


@dataclass(frozen=True, slots=True)
class HexByte:
    """One byte position. ``mask`` is 0xFF for a fixed byte, 0x00 for ``??``."""

    value: int
    mask: int
    negated: bool = False

    @property
    def is_fixed(self) -> bool:
        return self.mask == 0xFF and not self.negated

    def render(self) -> str:
        hi = _HEX[self.value >> 4] if self.mask & 0xF0 else "?"
        lo = _HEX[self.value & 0x0F] if self.mask & 0x0F else "?"
        return ("~" if self.negated else "") + hi + lo


@dataclass(frozen=True, slots=True)
class HexJump:
    low: int
    high: int | None  # None = unbounded

    def render(self) -> str:
        if self.high is None:
            return f"[{self.low}-]" if self.low else "[-]"
        if self.low == self.high:
            return f"[{self.low}]"
        return f"[{self.low}-{self.high}]"


@dataclass(frozen=True, slots=True)
class HexAlt:
    branches: tuple[tuple[HexElement, ...], ...]

    def render(self) -> str:
        return "( " + " | ".join(render_elements(b) for b in self.branches) + " )"


HexElement = HexByte | HexJump | HexAlt


class _HexParser:
    def __init__(self, body: str) -> None:
        self.s = "".join(body.split()).upper()
        self.i = 0

    def _peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def parse(self) -> tuple[HexElement, ...]:
        seq = self._sequence(top=True)
        if self.i != len(self.s):
            raise HexStringError(f"unexpected {self._peek()!r} in hex string")
        return seq

    def _sequence(self, top: bool) -> tuple[HexElement, ...]:
        items: list[HexElement] = []
        while self.i < len(self.s):
            ch = self._peek()
            if ch in "|)":
                if top:
                    raise HexStringError(f"unexpected {ch!r} outside alternative")
                break
            if ch == "[":
                items.append(self._jump())
            elif ch == "(":
                items.append(self._alt())
            else:
                items.append(self._byte())
        return tuple(items)

    def _byte(self) -> HexByte:
        negated = False
        if self._peek() == "~":
            negated = True
            self.i += 1
        pair = self.s[self.i : self.i + 2]
        if len(pair) != 2 or any(c not in _HEX + "?" for c in pair):
            raise HexStringError(f"invalid hex byte {pair!r}")
        self.i += 2
        value = mask = 0
        for shift, ch in ((4, pair[0]), (0, pair[1])):
            if ch != "?":
                value |= _HEX.index(ch) << shift
                mask |= 0xF << shift
        return HexByte(value, mask, negated)

    def _jump(self) -> HexJump:
        end = self.s.find("]", self.i)
        if end == -1:
            raise HexStringError("unterminated jump")
        inner = self.s[self.i + 1 : end]
        self.i = end + 1
        try:
            if "-" not in inner:
                n = int(inner)
                return HexJump(n, n)
            low_s, high_s = inner.split("-", 1)
            low = int(low_s) if low_s else 0
            high = int(high_s) if high_s else None
        except ValueError:
            raise HexStringError(f"invalid jump [{inner}]") from None
        if high is not None and high < low:
            raise HexStringError(f"jump [{inner}] has high < low")
        return HexJump(low, high)

    def _alt(self) -> HexAlt:
        self.i += 1  # (
        branches = [self._sequence(top=False)]
        while self._peek() == "|":
            self.i += 1
            branches.append(self._sequence(top=False))
        if self._peek() != ")":
            raise HexStringError("unterminated alternative")
        self.i += 1
        return HexAlt(tuple(branches))


def parse_hex(body: str) -> tuple[HexElement, ...]:
    """Parse a hex-string body (without the surrounding braces)."""
    return _HexParser(body).parse()


def render_elements(elements: tuple[HexElement, ...]) -> str:
    return " ".join(e.render() for e in elements)


def fixed_runs(elements: tuple[HexElement, ...]) -> list[bytes]:
    """Return maximal runs of fixed bytes, the raw material for atoms.

    Alternatives contribute the *weakest* branch's best run, since the scanner
    must find an atom for every branch.
    """
    runs: list[bytes] = []
    current = bytearray()
    for el in elements:
        if isinstance(el, HexByte) and el.is_fixed:
            current.append(el.value)
            continue
        if current:
            runs.append(bytes(current))
            current = bytearray()
        if isinstance(el, HexAlt):
            branch_best = [max(fixed_runs(b), key=len, default=b"") for b in el.branches]
            weakest = min(branch_best, key=len, default=b"")
            if weakest:
                runs.append(weakest)
    if current:
        runs.append(bytes(current))
    return runs


def has_unbounded_jump(elements: tuple[HexElement, ...]) -> bool:
    for el in elements:
        if isinstance(el, HexJump) and el.high is None:
            return True
        if isinstance(el, HexAlt) and any(has_unbounded_jump(b) for b in el.branches):
            return True
    return False
