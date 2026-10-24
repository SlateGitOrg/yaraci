"""Pack discovery, dependency ordering and per-rule isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import PackFactory, rule
from yaraci.engine import get_backend
from yaraci.errors import PackError
from yaraci.pack import load_pack, order_files
from yaraci.syntax import parse_source

HELPER = rule("INFO_Helper", "condition: uint16(0) == 0x5A4D", prefix="private ")
USER = rule("SUSP_User", 'strings: $a = "evilstring" condition: INFO_Helper and $a')
GLOBAL = rule("INFO_Global", "condition: filesize < 10MB", prefix="global ")


def test_files_are_ordered_by_dependency(make_pack: PackFactory) -> None:
    pack = make_pack({"a_user.yar": USER, "z_helper.yar": HELPER})
    assert [f.path for f in pack.files] == ["rules/z_helper.yar", "rules/a_user.yar"]
    assert [u.path for u in pack.units] == ["rules/z_helper.yar", "rules/a_user.yar"]
    get_backend("yara-x").compile(pack.units)
    assert pack.get("SUSP_User").deps == ("INFO_Helper",)
    assert pack.dependents("INFO_Helper") == ["SUSP_User"]


def test_order_files_cycle_keeps_path_order() -> None:
    a = parse_source(rule("A_One", "condition: B_Two"), "a.yar")
    b = parse_source(rule("B_Two", "condition: A_One"), "b.yar")
    assert [f.path for f in order_files([a, b])] == ["a.yar", "b.yar"]


def test_closure_and_isolated_unit(make_pack: PackFactory) -> None:
    other = rule("SUSP_Other", 'strings: $a = "unrelated1" condition: $a')
    pack = make_pack({"r.yar": 'import "pe"\n' + HELPER + GLOBAL + USER + other})
    closure = [r.name for r in pack.closure("SUSP_User")]
    assert closure == ["INFO_Helper", "INFO_Global", "SUSP_User"]
    unit = pack.isolated_unit("SUSP_User")
    assert unit.text.startswith('import "pe"\n')
    assert "SUSP_Other" not in unit.text
    compiled = get_backend("yara-x").compile([unit]).rules
    assert "SUSP_User" in compiled.scan(b"MZ evilstring").rule_names
    assert "SUSP_User" not in compiled.scan(b"evilstring").rule_names


def test_rule_set_wildcards_are_dependencies(make_pack: PackFactory) -> None:
    src = (
        rule("SUSP_Part_A", 'strings: $a = "evilstringA" condition: $a')
        + rule("SUSP_Part_B", 'strings: $a = "evilstringB" condition: $a')
        + rule("SUSP_Combo", "condition: 2 of (SUSP_Part_*)")
    )
    pack = make_pack({"r.yar": src})
    assert pack.get("SUSP_Combo").deps == ("SUSP_Part_A", "SUSP_Part_B")


def test_units_without_blanks_rule_preserving_lines(make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": HELPER + USER + rule("SUSP_Last", 'strings: $a = "zzzzzz" condition: $a')})
    units = pack.units_without("SUSP_Last")
    assert "SUSP_Last" not in units[0].text
    assert units[0].text.count("\n") == pack.units[0].text.count("\n")
    get_backend("yara-x").compile(units)


def test_unparseable_file_is_kept_for_engine(make_pack: PackFactory) -> None:
    pack = make_pack({"good.yar": USER + HELPER, "bad.yar": "rule {"})
    assert len(pack.parse_errors) == 1
    assert pack.units[-1].path == "rules/bad.yar"


def test_pack_errors(tmp_path: Path, make_pack: PackFactory) -> None:
    with pytest.raises(PackError):
        load_pack(tmp_path / "nope")
    empty = tmp_path / "empty"
    (empty / "rules").mkdir(parents=True)
    with pytest.raises(PackError):
        load_pack(empty)
    pack = make_pack({"r.yar": USER + HELPER})
    with pytest.raises(PackError):
        pack.get("Missing")
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "yaraci.toml").write_text('[pack]\nrules = ["missing"]\n')
    with pytest.raises(PackError):
        load_pack(tmp_path / "cfg")


def test_single_file_rules_entry_and_bad_encoding(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    (root / "one.yar").write_text(USER + HELPER)
    (root / "yaraci.toml").write_text('[pack]\nrules = ["one.yar"]\n')
    assert len(load_pack(root).rules) == 2
    (root / "one.yar").write_bytes(b"\xff\xfe rule")
    with pytest.raises(PackError):
        load_pack(root)
