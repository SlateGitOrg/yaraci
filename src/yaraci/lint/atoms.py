"""Atom-quality estimation for YARA strings.

YARA engines do not search for whole patterns. They extract short fixed byte
sequences ("atoms", at most 4 bytes) from every pattern, feed them to an
Aho-Corasick automaton, and only verify the full pattern where an atom hits. A
pattern whose best atom is short or made of very common bytes produces many
candidate hits and slows the whole scan.

This module scores atoms with a heuristic *modelled on* libyara's
``yr_atoms_heuristic_quality`` (it is not byte-for-byte identical):

* each fixed byte scores 20; ASCII letters 18 (common in text); the very common
  bytes ``00 20 90 CC FF`` score 12;
* an atom whose bytes are all identical has its score halved;
* ``nocase`` reduces letters to 14 (each letter doubles the atom variants);
* ``wide`` interleaves zero bytes before atoms are chosen;
* ``xor`` and ``base64`` variants subtract 15 (many encoded variants).

The score of a string is the score of its best atom window. Complexity is
``O(n)`` in the pattern length.
"""

from __future__ import annotations

from dataclasses import dataclass

from yaraci.syntax import ast
from yaraci.syntax.hexstr import HexStringError, fixed_runs, parse_hex

ATOM_LEN = 4
_COMMON = frozenset({0x00, 0x20, 0x90, 0xCC, 0xFF})
_VARIANT_PENALTY = 15


@dataclass(frozen=True, slots=True)
class AtomEstimate:
    atom: bytes
    quality: int


def _byte_score(byte: int, nocase: bool) -> int:
    if byte in _COMMON:
        return 12
    if 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
        return 14 if nocase else 18
    return 20


def atom_quality(atom: bytes, nocase: bool = False) -> int:
    """Score a single atom (up to 4 bytes)."""
    if not atom:
        return 0
    score = sum(_byte_score(b, nocase) for b in atom)
    if len(set(atom)) == 1 and len(atom) > 1:
        score //= 2
    return score


def best_atom(runs: list[bytes], nocase: bool = False) -> AtomEstimate:
    """Best-scoring window of up to :data:`ATOM_LEN` bytes across ``runs``."""
    best = AtomEstimate(b"", 0)
    for run in runs:
        width = min(ATOM_LEN, len(run))
        for start in range(len(run) - width + 1):
            window = run[start : start + width]
            quality = atom_quality(window, nocase)
            if quality > best.quality:
                best = AtomEstimate(window, quality)
    return best


_REGEX_CLASS_ESCAPES = frozenset("dDwWsSbB")
_SIMPLE_ESCAPES = {"n": 0x0A, "t": 0x09, "r": 0x0D, "f": 0x0C, "v": 0x0B}


def _regex_branch_runs(branch: str) -> list[bytes]:  # noqa: PLR0912, PLR0915 - regex scanner state machine
    runs: list[bytes] = []
    current = bytearray()

    def flush() -> None:
        nonlocal current
        if current:
            runs.append(bytes(current))
        current = bytearray()

    i = 0
    while i < len(branch):
        ch = branch[i]
        literal: int | None = None
        if ch == "\\" and i + 1 < len(branch):
            nxt = branch[i + 1]
            if nxt == "x" and i + 3 < len(branch):
                try:
                    literal = int(branch[i + 2 : i + 4], 16)
                    i += 4
                except ValueError:
                    i += 2
            elif nxt in _REGEX_CLASS_ESCAPES:
                i += 2
            else:
                literal = _SIMPLE_ESCAPES.get(nxt, ord(nxt) & 0xFF)
                i += 2
        elif ch == "[":
            i = _class_end(branch, i)
        elif ch == "(":
            depth, j = 0, i
            while j < len(branch):
                if branch[j] == "\\":
                    j += 2
                    continue
                depth += {"(": 1, ")": -1}.get(branch[j], 0)
                j += 1
                if depth == 0:
                    break
            i = j
        elif ch in ".^$":
            i += 1
        else:
            literal = ord(ch) & 0xFF
            i += 1
        if literal is None:
            flush()
            i = _skip_quantifier(branch, i)
            continue
        quant = branch[i] if i < len(branch) else ""
        if quant in ("?", "*") or (quant == "{" and branch[i + 1 : i + 2] == "0"):
            flush()  # the literal is optional: it cannot be part of an atom
            i = _skip_quantifier(branch, i)
        elif quant in ("+", "{"):
            current.append(literal)  # at least one copy is mandatory, but the run ends here
            flush()
            i = _skip_quantifier(branch, i)
        else:
            current.append(literal)
    flush()
    return runs


def _class_end(pattern: str, i: int) -> int:
    """Index just past the character class opening at ``i`` (escapes and a leading ``]`` honoured)."""
    j = i + 1
    if j < len(pattern) and pattern[j] == "^":
        j += 1
    if j < len(pattern) and pattern[j] == "]":
        j += 1
    while j < len(pattern):
        if pattern[j] == "\\":
            j += 2
            continue
        if pattern[j] == "]":
            return j + 1
        j += 1
    return len(pattern)


def _skip_quantifier(pattern: str, i: int) -> int:
    """Skip a quantifier (``*``, ``+``, ``?``, ``{m,n}``, plus a lazy ``?``) at ``i``."""
    if i < len(pattern) and pattern[i] in "*+?":
        i += 1
    elif i < len(pattern) and pattern[i] == "{":
        end = pattern.find("}", i)
        i = len(pattern) if end == -1 else end + 1
    else:
        return i
    return i + 1 if i < len(pattern) and pattern[i] == "?" else i


def _split_top_level(pattern: str) -> list[str]:
    branches, depth, start, i = [], 0, 0, 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _class_end(pattern, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            branches.append(pattern[start:i])
            start = i + 1
        i += 1
    branches.append(pattern[start:])
    return branches


def regex_literal_runs(pattern: str) -> list[list[bytes]]:
    """Literal byte runs per top-level alternative of a regex."""
    return [_regex_branch_runs(b) for b in _split_top_level(pattern)]


def _widen(run: bytes) -> bytes:
    return b"".join(bytes((b, 0)) for b in run)


def estimate(sdef: ast.StringDef) -> AtomEstimate:
    """Estimate the best atom of a string definition, honouring its modifiers."""
    nocase = sdef.has_modifier("nocase") or "i" in sdef.regex_flags
    branches: list[list[bytes]]
    if sdef.kind is ast.StringKind.TEXT:
        assert isinstance(sdef.value, bytes)
        branches = [[sdef.value]]
    elif sdef.kind is ast.StringKind.HEX:
        assert isinstance(sdef.value, str)
        try:
            branches = [fixed_runs(parse_hex(sdef.value))]
        except HexStringError:
            return AtomEstimate(b"", 0)
    else:
        assert isinstance(sdef.value, str)
        branches = regex_literal_runs(sdef.value)
    if sdef.has_modifier("wide"):
        wide = [[_widen(r) for r in runs] for runs in branches]
        branches = wide + branches if sdef.has_modifier("ascii") else wide
    # Every alternative needs its own atom: the weakest branch bounds the string.
    estimates = [best_atom(runs, nocase) for runs in branches]
    result = min(estimates, key=lambda e: e.quality)
    if sdef.has_modifier("xor") or sdef.has_modifier("base64") or sdef.has_modifier("base64wide"):
        result = AtomEstimate(result.atom, max(0, result.quality - _VARIANT_PENALTY))
    return result
