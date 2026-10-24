"""Structural and impact diffs between pack versions."""

from __future__ import annotations

from pathlib import Path

from conftest import GOODWARE, TODAY, rule
from yaraci.corpus import CorpusBuilder
from yaraci.diff import ChangeKind, impact_diff, structural_diff
from yaraci.engine import get_backend
from yaraci.pack import RulePack, load_pack
from yaraci.parity import check_parity

BASE = {
    "SUSP_Same": rule("SUSP_Same", 'strings: $a = "samestring" condition: $a'),
    "SUSP_Cosmetic": rule("SUSP_Cosmetic", 'strings: $a = "cosmetic1" condition: $a and filesize < 0x100'),
    "SUSP_Meta": rule("SUSP_Meta", 'strings: $a = "metastring" condition: $a'),
    "SUSP_Logic": rule("SUSP_Logic", 'strings: $a = "logicstr" $b = "logicstr2" condition: any of them'),
    "SUSP_OldName": rule("SUSP_OldName", 'strings: $a = "renamedstr" condition: $a'),
    "SUSP_Gone": rule("SUSP_Gone", 'strings: $a = "gonestring" condition: $a'),
}


def _write(root: Path, rules: dict[str, str], fixtures: dict[str, bytes]) -> RulePack:
    (root / "rules").mkdir(parents=True)
    (root / "rules" / "r.yar").write_text("".join(rules.values()))
    for rel, data in fixtures.items():
        path = root / "fixtures" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return load_pack(root)


def _packs(tmp_path: Path) -> tuple[RulePack, RulePack]:
    old = _write(
        tmp_path / "old",
        BASE,
        {
            "SUSP_Logic/match/l.txt": b"logicstr",
            "SUSP_Gone/match/g.txt": b"gonestring",
            "SUSP_Same/nomatch/n.txt": b"nothing here",
        },
    )
    new_rules = dict(BASE)
    new_rules["SUSP_Cosmetic"] = (
        '// reformatted\nrule SUSP_Cosmetic {\n meta: author = "t" description = "A sufficiently descriptive '
        'sentence" date = "2026-01-02" reference = "https://example.org/r"\n strings:\n  $a = "cosmetic1"\n'
        " condition:\n  ($a and filesize < 256)\n}\n"
    )
    new_rules["SUSP_Meta"] = rule(
        "SUSP_Meta",
        'strings: $a = "metastring" condition: $a',
        meta='author = "someone else" date = "2026-02-02"',
    )
    new_rules["SUSP_Logic"] = rule(
        "SUSP_Logic", 'strings: $a = "logicstr" $b = "logicstr3" condition: $a and $b'
    )
    del new_rules["SUSP_OldName"]
    new_rules["SUSP_NewName"] = rule("SUSP_NewName", 'strings: $a = "renamedstr" condition: $a')
    del new_rules["SUSP_Gone"]
    new_rules["SUSP_Added"] = rule("SUSP_Added", 'strings: $a = "nothing" condition: $a')
    new = _write(tmp_path / "new", new_rules, {"SUSP_Logic/match/l.txt": b"logicstr"})
    return old, new


def test_structural_classification(tmp_path: Path) -> None:
    old, new = _packs(tmp_path)
    kinds = {c.name: c.kind for c in structural_diff(old, new)}
    assert kinds == {
        "SUSP_Same": ChangeKind.UNCHANGED,
        "SUSP_Cosmetic": ChangeKind.COSMETIC,
        "SUSP_Meta": ChangeKind.METADATA,
        "SUSP_Logic": ChangeKind.MODIFIED,
        "SUSP_NewName": ChangeKind.RENAMED,
        "SUSP_Added": ChangeKind.ADDED,
        "SUSP_Gone": ChangeKind.REMOVED,
    }
    changes = {c.name: c for c in structural_diff(old, new)}
    assert changes["SUSP_NewName"].old_name == "SUSP_OldName"
    details = "\n".join(changes["SUSP_Logic"].details)
    assert 'string changed $b: "logicstr2" -> "logicstr3"' in details
    assert "condition: any of them -> $a and $b" in details
    assert "meta changed: author, date, description, reference" in "\n".join(changes["SUSP_Meta"].details)


def test_flags_tags_and_string_set_changes(tmp_path: Path) -> None:
    old = _write(tmp_path / "o", {"a": 'rule SUSP_X : t1 { strings: $a = "xxxxxxxx" condition: $a }'}, {})
    new = _write(
        tmp_path / "n",
        {"a": 'private rule SUSP_X : t2 { strings: $b = "yyyyyyyy" $ = "zzzzzzzz" condition: any of them }'},
        {},
    )
    details = structural_diff(old, new)[0].details
    text = "\n".join(details)
    assert "flags: private=False->True" in text
    assert "tags: ['t1'] -> ['t2']" in text
    assert "string added $b" in text
    assert "string removed $a" in text


def test_impact_classifies_fp_and_tp(tmp_path: Path) -> None:
    old, new = _packs(tmp_path)
    goodware = CorpusBuilder()
    goodware.add_bytes("good/readme.txt", b"says nothing", "bundled")
    goodware.add_bytes("good/log.txt", b"logicstr logicstr3", "bundled")
    report = impact_diff(old, new, get_backend("yara-x"), goodware)
    impacts = {i.rule: i for i in report.impacts}
    assert impacts["SUSP_Added"].new_fp == ["good/readme.txt"]
    assert impacts["SUSP_Logic"].lost_tp == ["fixtures/SUSP_Logic/match/l.txt"]
    assert impacts["SUSP_Logic"].old_matches == 2
    assert impacts["SUSP_Gone (removed)"].lost_tp == ["fixtures/SUSP_Gone/match/g.txt"]
    assert impacts["SUSP_NewName"].old_name == "SUSP_OldName"
    # n.txt is a *SUSP_Same* negative; SUSP_Added matching it is a change, not a fixture violation.
    assert report.new_fp == 1
    assert "fixtures/SUSP_Same/nomatch/n.txt" in impacts["SUSP_Added"].gained
    assert report.lost_tp == 1
    assert report.removed_coverage == 1
    assert report.counts()["unchanged"] == 1


def test_examples_diff_and_parity() -> None:
    old = load_pack(Path(__file__).resolve().parent.parent / "examples" / "pack-v1")
    new = load_pack(Path(__file__).resolve().parent.parent / "examples" / "pack-v2")
    goodware = CorpusBuilder()
    goodware.add_tree(GOODWARE, "bundled")
    report = impact_diff(old, new, get_backend("yara-x"), goodware)
    assert report.new_fp == 4
    assert report.lost_tp == 1
    assert report.counts() == {"modified": 2, "renamed": 1, "added": 3, "removed": 1, "unchanged": 6}
    parity = check_parity(old, get_backend("libyara"), get_backend("yara-x"), goodware.samples)
    assert parity.consistent
    assert TODAY.year == 2026


def test_parity_detects_divergence_and_compile_errors(tmp_path: Path) -> None:
    # YARA-X rejects this rule (unreferenced $b with a non-anonymous name is fine in both; use a
    # construct only libyara accepts: a duplicated string modifier).
    pack = _write(
        tmp_path / "p", {"a": 'rule SUSP_Dup { strings: $a = "abcdefgh" wide wide condition: $a }'}, {}
    )
    report = check_parity(pack, get_backend("libyara"), get_backend("yara-x"), [])
    assert report.compile_errors
    assert not report.consistent
