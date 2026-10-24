"""Typed configuration loaded from a pack's ``yaraci.toml``.

Every key has a default, so an empty file (or no file) is valid. Unknown keys
are rejected: a typo such as ``max_fps = 0`` silently disabling a gate is worse
than a loud error.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from yaraci.errors import ConfigError

CONFIG_NAME = "yaraci.toml"
SEVERITIES = ("error", "warning", "info")
GRADES = ("A", "B", "C", "D", "F")


@dataclass(slots=True)
class PackConfig:
    name: str = ""
    rules: list[str] = field(default_factory=lambda: ["rules"])
    fixtures: str = "fixtures"
    engine: str = "yara-x"
    scan_timeout_s: int = 10


@dataclass(slots=True)
class LintConfig:
    disable: list[str] = field(default_factory=list)
    severity: dict[str, str] = field(default_factory=dict)
    name_pattern: str = r"^[A-Z][A-Za-z0-9]*(_[A-Za-z0-9]+)+$"
    name_prefixes: list[str] = field(default_factory=list)
    max_name_length: int = 64
    required_meta: list[str] = field(default_factory=lambda: ["author", "description", "date"])
    recommended_meta: list[str] = field(default_factory=lambda: ["reference"])
    severity_values: list[str] = field(default_factory=lambda: ["low", "medium", "high", "critical"])
    max_strings: int = 40
    min_atom_quality: int = 45


@dataclass(slots=True)
class GoodwareConfig:
    dirs: list[str] = field(default_factory=list)
    fetched_dir: str = ".cache/goodware"
    fetched: bool = True
    system: bool = False
    system_paths: list[str] = field(default_factory=lambda: ["/bin/*", "/usr/bin/*", "/usr/sbin/*"])
    system_max_files: int = 200
    max_file_size: int = 16 * 1024 * 1024
    expand_archives: bool = True
    allowlist: str = "fp-allowlist.toml"


@dataclass(slots=True)
class ProfileConfig:
    corpus: list[str] = field(default_factory=list)
    repeat: int = 5
    max_corpus_bytes: int = 64 * 1024 * 1024
    budget_us_per_mb: float = 50_000.0
    slow_ratio: float = 4.0
    slow_z: float = 3.5
    noise_floor_us_per_mb: float = 200.0


@dataclass(slots=True)
class GateConfig:
    lint_fail_on: str = "error"
    fail_on_untested: bool = True
    fail_on_tp: bool = True
    max_fp: int = 0
    fail_on_slow: bool = True
    fail_on_compile_warnings: bool = False
    min_grade: str = ""


@dataclass(slots=True)
class Config:
    root: Path = field(default_factory=Path.cwd)
    pack: PackConfig = field(default_factory=PackConfig)
    lint: LintConfig = field(default_factory=LintConfig)
    goodware: GoodwareConfig = field(default_factory=GoodwareConfig)
    profile: ProfileConfig = field(default_factory=ProfileConfig)
    gate: GateConfig = field(default_factory=GateConfig)

    def resolve(self, relative: str) -> Path:
        """Resolve a config-relative path."""
        path = Path(relative)
        return path if path.is_absolute() else self.root / path


_SECTIONS: dict[str, type] = {
    "pack": PackConfig,
    "lint": LintConfig,
    "goodware": GoodwareConfig,
    "profile": ProfileConfig,
    "gate": GateConfig,
}


def _check_type(section: str, key: str, value: Any, default: Any) -> Any:
    where = f"[{section}].{key}"
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be a boolean")
    elif isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be an integer")
    elif isinstance(default, float):
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"{where} must be a number")
        value = float(value)
    elif isinstance(default, str):
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string")
    elif isinstance(default, list):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings")
    elif isinstance(default, dict) and (
        not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values())
    ):
        raise ConfigError(f"{where} must be a table of strings")
    return value


def _build_section(name: str, cls: type, raw: Any) -> Any:
    if not isinstance(raw, dict):
        raise ConfigError(f"[{name}] must be a table")
    instance = cls()
    known = {f.name for f in fields(cls)}
    for key, value in raw.items():
        if key not in known:
            raise ConfigError(f"unknown key [{name}].{key}")
        setattr(instance, key, _check_type(name, key, value, getattr(instance, key)))
    return instance


def _validate(cfg: Config) -> None:
    if cfg.pack.engine not in ("yara-x", "libyara"):
        raise ConfigError(f"[pack].engine must be 'yara-x' or 'libyara', not {cfg.pack.engine!r}")
    for code, sev in cfg.lint.severity.items():
        if sev not in SEVERITIES:
            raise ConfigError(f"[lint].severity.{code} must be one of {', '.join(SEVERITIES)}")
    try:
        re.compile(cfg.lint.name_pattern)
    except re.error as exc:
        raise ConfigError(f"[lint].name_pattern is not a valid regex: {exc}") from None
    if cfg.gate.lint_fail_on not in (*SEVERITIES, "never"):
        raise ConfigError("[gate].lint_fail_on must be error, warning, info or never")
    if cfg.gate.min_grade and cfg.gate.min_grade not in GRADES:
        raise ConfigError(f"[gate].min_grade must be one of {', '.join(GRADES)} or empty")
    positives = {
        "[pack].scan_timeout_s": cfg.pack.scan_timeout_s,
        "[profile].repeat": cfg.profile.repeat,
        "[profile].slow_ratio": cfg.profile.slow_ratio,
        "[goodware].max_file_size": cfg.goodware.max_file_size,
    }
    for key, value in positives.items():
        if value <= 0:
            raise ConfigError(f"{key} must be positive")
    if cfg.gate.max_fp < 0:
        raise ConfigError("[gate].max_fp must be >= 0")


def parse_config(data: dict[str, Any], root: Path) -> Config:
    """Build a validated :class:`Config` from parsed TOML ``data``."""
    cfg = Config(root=root)
    for key, raw in data.items():
        if key not in _SECTIONS:
            raise ConfigError(f"unknown section [{key}]")
        setattr(cfg, key, _build_section(key, _SECTIONS[key], raw))
    _validate(cfg)
    return cfg


def load_config(pack_dir: Path, explicit: Path | None = None) -> Config:
    """Load ``yaraci.toml`` from ``explicit`` or ``pack_dir``; defaults if absent."""
    path = explicit or pack_dir / CONFIG_NAME
    if not path.exists():
        if explicit is not None:
            raise ConfigError(f"config file not found: {explicit}")
        return parse_config({}, pack_dir)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return parse_config(data, path.parent)
