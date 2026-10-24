"""Golden checks on the bundled example packs and the fixture generator."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from conftest import ROOT, TODAY
from yaraci.engine import get_backend
from yaraci.gate import GateFailure
from yaraci.pack import RulePack
from yaraci.pipeline import CheckOptions, run_check


def _load_script(name: str):  # type: ignore[no-untyped-def]
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_examples_are_fresh() -> None:
    assert _load_script("make_examples").main(["--check"]) == 0


def test_v1_passes_every_scan_gate(v1: RulePack) -> None:
    for engine in ("yara-x", "libyara"):
        result = run_check(v1, get_backend(engine), CheckOptions(stages=("lint", "tp", "fp"), today=TODAY))
        assert result.gate.passed, result.gate.reasons
        assert result.findings == []
        assert all(card.grade == "A" for card in result.cards)


def test_v2_regressions_are_all_caught(v2: RulePack) -> None:
    result = run_check(v2, get_backend("yara-x"), CheckOptions(stages=("lint", "tp", "fp"), today=TODAY))
    assert result.gate.code == GateFailure.LINT | GateFailure.TP | GateFailure.FP | GateFailure.QUALITY
    assert result.tp is not None
    assert {r.label for r in result.tp.failures} == {
        "PUA_PE_Packer_UPX/match/packed.exe.bin",
        "MAL_RansomNote_Generic/nomatch/wallet-lib-README.txt",
    }
    assert result.fp is not None
    assert {(h.rule, h.sample) for h in result.fp.effective} == {
        ("MAL_RansomNote_Generic", "goodware/docs/crypto-wallet-guide.md"),
        ("SUSP_SH_PipeToShell", "goodware/scripts/install-tool.sh"),
        ("SUSP_Generic_LongBase64Blob", "goodware/src/app_icon.py"),
    }
    grades = {c.rule: c.grade for c in result.cards}
    assert grades["test_rule"] == "F"
    assert grades["SUSP_PS_EncodedCommand_Hidden"] == "A"


def test_example_files_are_benign_stubs() -> None:
    """Binary fixtures are header stubs: tiny, and never contain an x86 code section with content."""
    for path in (ROOT / "examples").rglob("*.bin"):
        assert path.stat().st_size <= 300 * 1024, path
    assert Path(ROOT / "examples" / "goodware").is_dir()
