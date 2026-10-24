"""Configuration parsing and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraci.config import load_config, parse_config
from yaraci.errors import ConfigError


def test_defaults_without_file(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.pack.engine == "yara-x"
    assert cfg.gate.max_fp == 0
    assert cfg.resolve("rules") == tmp_path / "rules"
    assert cfg.resolve("/abs") == Path("/abs")


def test_loads_and_coerces(tmp_path: Path) -> None:
    (tmp_path / "yaraci.toml").write_text(
        '[pack]\nengine = "libyara"\n[profile]\nslow_ratio = 3\n[gate]\nmin_grade = "B"\n'
        '[lint]\nseverity = { YC301 = "error" }\n'
    )
    cfg = load_config(tmp_path)
    assert cfg.pack.engine == "libyara"
    assert cfg.profile.slow_ratio == 3.0
    assert cfg.gate.min_grade == "B"


@pytest.mark.parametrize(
    "data",
    [
        {"bogus": {}},
        {"pack": []},
        {"pack": {"nope": 1}},
        {"pack": {"engine": "clamav"}},
        {"pack": {"scan_timeout_s": "10"}},
        {"pack": {"scan_timeout_s": True}},
        {"pack": {"scan_timeout_s": 0}},
        {"pack": {"rules": "rules"}},
        {"pack": {"name": 5}},
        {"gate": {"fail_on_slow": 1}},
        {"gate": {"lint_fail_on": "fatal"}},
        {"gate": {"min_grade": "Z"}},
        {"gate": {"max_fp": -1}},
        {"lint": {"severity": {"YC301": "fatal"}}},
        {"lint": {"severity": ["x"]}},
        {"lint": {"name_pattern": "("}},
        {"profile": {"slow_ratio": "x"}},
        {"profile": {"repeat": 0}},
    ],
)
def test_invalid_configs(tmp_path: Path, data: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(ConfigError):
        parse_config(data, tmp_path)


def test_bad_toml_and_missing_explicit(tmp_path: Path) -> None:
    (tmp_path / "yaraci.toml").write_text("[pack\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)
    with pytest.raises(ConfigError):
        load_config(tmp_path, tmp_path / "missing.toml")
