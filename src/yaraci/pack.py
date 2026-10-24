"""Rule-pack discovery, parsing and per-rule source isolation.

A *pack* is a directory with a ``yaraci.toml`` and one or more rule directories.
All rule files compile into one namespace, so rules may reference each other.

Isolating one rule (for per-rule profiling and for the differ) requires its
dependency closure: every rule its condition references, transitively, plus all
``global`` rules (which gate every rule in the namespace). The closure is a BFS
over the reference graph, ``O(R + E)``, emitted in pack order because YARA
requires declaration before use.
"""

from __future__ import annotations

import fnmatch
import heapq
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from yaraci.config import Config, load_config
from yaraci.engine import SourceUnit
from yaraci.errors import PackError, SyntaxParseError
from yaraci.syntax import ast, parse_source
from yaraci.syntax.walk import free_identifiers, rule_set_patterns

log = logging.getLogger(__name__)

RULE_SUFFIXES = (".yar", ".yara")


@dataclass(slots=True)
class PackRule:
    """A parsed rule together with its file, pack position and direct dependencies."""

    rule: ast.Rule
    file: ast.RuleFile
    index: int
    deps: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.rule.name

    @property
    def path(self) -> str:
        return self.file.path

    @property
    def source_text(self) -> str:
        return self.file.source[self.rule.start_offset : self.rule.end_offset]


@dataclass(slots=True)
class RulePack:
    root: Path
    config: Config
    files: list[ast.RuleFile] = field(default_factory=list)
    units: list[SourceUnit] = field(default_factory=list)
    parse_errors: list[SyntaxParseError] = field(default_factory=list)
    rules: list[PackRule] = field(default_factory=list)
    by_name: dict[str, PackRule] = field(default_factory=dict)

    @property
    def public_rules(self) -> list[PackRule]:
        return [r for r in self.rules if not r.rule.is_private]

    def get(self, name: str) -> PackRule:
        try:
            return self.by_name[name]
        except KeyError:
            raise PackError(f"no rule named {name!r} in pack") from None

    def closure(self, name: str) -> list[PackRule]:
        """The rule ``name`` plus every rule it depends on, in pack order."""
        start = self.get(name)
        seen: dict[str, PackRule] = {start.name: start}
        queue = deque([start])
        for rule in self.rules:
            if rule.rule.is_global and rule.name not in seen:
                seen[rule.name] = rule
                queue.append(rule)
        while queue:
            current = queue.popleft()
            for dep in current.deps:
                target = self.by_name.get(dep)
                if target is not None and dep not in seen:
                    seen[dep] = target
                    queue.append(target)
        return sorted(seen.values(), key=lambda r: r.index)

    def isolated_unit(self, name: str) -> SourceUnit:
        """A compilable source containing only ``name`` and its dependency closure."""
        members = self.closure(name)
        imports: dict[str, None] = {}
        for member in members:
            for imp in member.file.imports:
                imports[imp.module] = None
        header = "".join(f'import "{module}"\n' for module in imports)
        body = "\n\n".join(m.source_text for m in members)
        return SourceUnit(path=f"{self.get(name).path}#{name}", text=header + body)

    def dependents(self, name: str) -> list[str]:
        """Rules whose condition references ``name`` directly."""
        return [r.name for r in self.rules if name in r.deps]

    def units_without(self, name: str) -> list[SourceUnit]:
        """Pack sources with rule ``name`` blanked out (line numbers preserved)."""
        target = self.get(name)
        out = []
        for unit in self.units:
            if unit.path != target.path:
                out.append(unit)
                continue
            start, end = target.rule.start_offset, target.rule.end_offset
            removed = unit.text[start:end]
            blank = "".join("\n" if ch == "\n" else " " for ch in removed)
            out.append(SourceUnit(unit.path, unit.text[:start] + blank + unit.text[end:]))
        return out


def _discover(cfg: Config) -> list[Path]:
    found: list[Path] = []
    for entry in cfg.pack.rules:
        target = cfg.resolve(entry)
        if target.is_file():
            found.append(target)
        elif target.is_dir():
            found.extend(p for p in target.rglob("*") if p.is_file() and p.suffix in RULE_SUFFIXES)
        else:
            raise PackError(f"rule path does not exist: {entry}")
    unique = sorted(set(found), key=lambda p: p.as_posix())
    if not unique:
        raise PackError(f"no {'/'.join(RULE_SUFFIXES)} files found under {cfg.pack.rules}")
    return unique


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _direct_deps(rule: ast.Rule, known: list[str]) -> tuple[str, ...]:
    """Rules referenced by ``rule``'s condition among the ``known`` pack rules."""
    names = set(known)
    deps = {name for name in free_identifiers(rule.condition) if name in names}
    for pattern in rule_set_patterns(rule.condition):
        deps.update(fnmatch.filter(known, pattern) if pattern.endswith("*") else [pattern])
    deps &= names
    deps.discard(rule.name)
    return tuple(sorted(deps))


def order_files(files: list[ast.RuleFile]) -> list[ast.RuleFile]:
    """Order files so that rules are declared before files that reference them.

    YARA resolves rule references at declaration time, so a pack whose helper
    rules live in ``filetypes.yar`` must compile that file before
    ``binaries.yar`` even though it sorts later. This is Kahn's algorithm over
    the file-level reference graph with a path-ordered ready queue, giving a
    deterministic ``O((F + E) log F)`` order. Files caught in a reference cycle
    keep path order (the engine then reports the real error).
    """
    owner = {r.name: idx for idx, f in enumerate(files) for r in f.rules}
    edges: dict[int, set[int]] = {i: set() for i in range(len(files))}
    indegree = [0] * len(files)
    for idx, rf in enumerate(files):
        for rule in rf.rules:
            for dep in _direct_deps(rule, list(owner)):
                src = owner[dep]
                if src != idx and idx not in edges[src]:
                    edges[src].add(idx)
                    indegree[idx] += 1
    ready = [i for i in range(len(files)) if indegree[i] == 0]
    heapq.heapify(ready)
    ordered: list[int] = []
    while ready:
        current = heapq.heappop(ready)
        ordered.append(current)
        for nxt in sorted(edges[current]):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                heapq.heappush(ready, nxt)
    ordered += [i for i in range(len(files)) if i not in set(ordered)]
    return [files[i] for i in ordered]


def load_pack_from_config(cfg: Config) -> RulePack:
    """Discover, read, parse and dependency-order every rule file named by ``cfg``."""
    pack = RulePack(root=cfg.root, config=cfg)
    raw: dict[str, str] = {}
    parsed_files: list[ast.RuleFile] = []
    for path in _discover(cfg):
        display = _display_path(path, cfg.root)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PackError(f"cannot read {display}: {exc}") from None
        raw[display] = text
        try:
            parsed_files.append(parse_source(text, display))
        except SyntaxParseError as exc:
            log.warning("parse failed: %s", exc)
            pack.parse_errors.append(exc)
    pack.files = order_files(parsed_files)
    # Unparseable files go last: their dependencies are unknown.
    ordered_paths = [f.path for f in pack.files] + [p for p in raw if p not in {f.path for f in pack.files}]
    pack.units = [SourceUnit(p, raw[p]) for p in ordered_paths]
    known = [r.name for f in pack.files for r in f.rules]
    for parsed in pack.files:
        for rule in parsed.rules:
            entry = PackRule(rule, parsed, len(pack.rules), _direct_deps(rule, known))
            pack.rules.append(entry)
            pack.by_name.setdefault(rule.name, entry)
    log.info("loaded %d rules from %d files", len(pack.rules), len(pack.units))
    return pack


def load_pack(pack_dir: Path, config_path: Path | None = None) -> RulePack:
    """Load the pack rooted at ``pack_dir`` (reads ``yaraci.toml`` if present)."""
    if not pack_dir.is_dir():
        raise PackError(f"pack directory not found: {pack_dir}")
    return load_pack_from_config(load_config(pack_dir, config_path))
