"""JUnit, SARIF, JSON, Markdown and text renderers over real check results."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import date

import pytest

from conftest import TODAY, PackFactory, rule
from yaraci.corpus import CorpusBuilder
from yaraci.diff import impact_diff
from yaraci.engine import get_backend
from yaraci.pack import RulePack
from yaraci.parity import ParityReport
from yaraci.pipeline import CheckOptions, CheckResult, run_check
from yaraci.profiling import ProfileReport, RuleProfile
from yaraci.report import (
    build_sarif,
    check_dict,
    diff_dict,
    render_check,
    render_check_markdown,
    render_diff,
    render_diff_markdown,
    render_parity,
    write_junit,
    write_sarif,
)
from yaraci.report.junit import _clean
from yaraci.report.model import code_info, display_path


@pytest.fixture
def v2_result(v2: RulePack) -> CheckResult:
    result = run_check(v2, get_backend("yara-x"), CheckOptions(stages=("lint", "tp", "fp"), today=TODAY))
    result.profile = ProfileReport(
        "yara-x",
        "1",
        3,
        300,
        1,
        rules=[
            RuleProfile("SUSP_Generic_LongBase64Blob", 5.0, 9000.0, "x", 1.0, slow=True, reason="outlier"),
            RuleProfile("test_rule", 0.0, 0.0, error="isolation failed"),
            RuleProfile("PUA_PE_Packer_UPX", 1.0, 2.0, "y", 0.5),
        ],
    )
    return result


def test_sarif_structure(v2_result: CheckResult) -> None:
    doc = build_sarif(v2_result)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_ids = {r["ruleId"] for r in run["results"]}
    assert result_ids <= rule_ids
    assert {"YC201", "YC403", "YC601", "YC602", "YC701", "YC801", "YC901"} <= result_ids
    for res in run["results"]:
        assert res["level"] in {"error", "warning", "note"}
        assert res["message"]["text"]
        if "locations" in res:
            loc = res["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uri"].endswith(".yar")
            assert loc["region"]["startLine"] >= 1
    fingerprints = [r["partialFingerprints"]["yaraciFinding/v1"] for r in run["results"]]
    assert len(fingerprints) == len(set(fingerprints))
    assert json.loads(write_sarif(v2_result)) == doc


def test_junit_structure(v2_result: CheckResult) -> None:
    root = ET.fromstring(write_junit(v2_result))
    suites = {s.get("name"): s for s in root.findall("testsuite")}
    assert set(suites) == {"yaraci.lint", "yaraci.tp", "yaraci.fp", "yaraci.perf"}
    total = sum(int(s.get("tests", "0")) for s in suites.values())
    assert int(root.get("tests", "0")) == total
    tp_fail = [c.get("name") for c in suites["yaraci.tp"].iter("testcase") if c.find("failure") is not None]
    assert "PUA_PE_Packer_UPX/match/packed.exe.bin" in tp_fail
    assert "test_rule/coverage" in tp_fail
    fp_fail = [
        str(c.get("name")) for c in suites["yaraci.fp"].iter("testcase") if c.find("failure") is not None
    ]
    assert sorted(fp_fail) == ["MAL_RansomNote_Generic", "SUSP_Generic_LongBase64Blob", "SUSP_SH_PipeToShell"]
    assert suites["yaraci.perf"].get("skipped") == "1"
    assert _clean("a\x00b") == "a?b"


def test_text_markdown_and_json(v2_result: CheckResult) -> None:
    text = render_check(v2_result, verbose=True)
    assert "GATE     FAIL" in text
    assert "SUSP_Generic_LongBase64Blob" in text
    assert "isolation failed" in text
    md = render_check_markdown(v2_result)
    assert md.startswith("## yaraci: lab-pack - FAIL")
    assert "| F |" in md
    doc = check_dict(v2_result)
    assert doc["gate"]["passed"] is False
    assert doc["profile"]["rules"][0]["slow"] is True
    json.dumps(doc)


def test_diff_and_parity_renderers(v1: RulePack, v2: RulePack) -> None:
    report = impact_diff(v1, v2, get_backend("yara-x"), CorpusBuilder())
    text = render_diff(report)
    assert "renamed   MAL_ELF_CoinMiner_Stratum -> MAL_ELF_Miner_Stratum" in text
    assert "LOST TP: fixtures/PUA_PE_Packer_UPX/match/packed.exe.bin" in text
    md = render_diff_markdown(report)
    assert "| renamed | `MAL_ELF_CoinMiner_Stratum` -> `MAL_ELF_Miner_Stratum` |" in md
    assert diff_dict(report)["lost_tp"] == 1
    parity = ParityReport(("libyara", "yara-x"), 2, {}, {"R": ["a"]}, {"S": ["b"]})
    out = render_parity(parity)
    assert "R: only libyara matched a" in out
    assert "2 divergent" in out
    bad = render_parity(ParityReport(("libyara", "yara-x"), 0, {"yara-x": "boom"}))
    assert "failed to compile: boom" in bad


def test_lint_only_pack_renders(make_pack: PackFactory) -> None:
    pack = make_pack(
        {"r.yar": rule("SUSP_Only", 'strings: $a = "evilstring" condition: $a')},
        config='[gate]\nlint_fail_on = "never"\n',
    )
    result = run_check(pack, get_backend("libyara"), CheckOptions(stages=("lint",), today=date(2026, 1, 1)))
    assert result.gate.passed
    root = ET.fromstring(write_junit(result))
    assert [s.get("name") for s in root.findall("testsuite")] == ["yaraci.lint"]
    assert "COMPILE  ok" in render_check(result)


def test_code_info_and_paths(v1: RulePack) -> None:
    assert code_info("YC301")[0] == "weak-atom"
    assert code_info("YC701")[0] == "goodware-match"
    assert display_path(v1.root, None) is None
    shown = display_path(v1.root, "rules/notes.yar")
    assert shown is not None
    assert shown.endswith("examples/pack-v1/rules/notes.yar")
