"""CLI commands end to end, including exit codes."""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import PACK_V1, PACK_V2, PackFactory, rule
from yaraci.cli import main
from yaraci.gate import EXIT_USAGE

FAST_STAGES = "lint,tp,fp"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_check_v1_passes_with_reports(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    junit, sarif, js, md = (tmp_path / n for n in ("j.xml", "s.sarif", "r.json", "r.md"))
    code, out = run(
        capsys,
        "check",
        str(PACK_V1),
        "--stages",
        FAST_STAGES,
        "--junit",
        str(junit),
        "--sarif",
        str(sarif),
        "--json",
        str(js),
        "--markdown",
        str(md),
    )
    assert code == 0, out
    assert "GATE     PASS (exit 0)" in out
    assert ET.parse(junit).getroot().get("failures") == "0"
    assert json.loads(sarif.read_text())["runs"][0]["results"] == []
    assert json.loads(js.read_text())["gate"]["passed"] is True
    assert "PASS" in md.read_text()


def test_check_v2_fails_with_bitmask(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "check", str(PACK_V2), "--stages", FAST_STAGES, "--engine", "libyara")
    assert code == 1 | 2 | 4 | 16
    assert "GATE     FAIL (exit 23)" in out
    code, out = run(capsys, "check", str(PACK_V2), "--stages", "lint", "--format", "json")
    assert json.loads(out)["gate"]["exit_code"] == code == 1
    code, out = run(capsys, "check", str(PACK_V2), "--stages", "lint", "--format", "markdown")
    assert out.startswith("## yaraci")


def test_check_with_profile_flags_slow_rule(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "check", str(PACK_V2), "--stages", "profile", "--repeat", "1")
    assert code & 8
    assert "SUSP_Generic_LongBase64Blob" in out.split("SLOW")[0]


def test_lint_test_fp_commands(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out = run(capsys, "lint", str(PACK_V2), "--sarif", str(tmp_path / "l.sarif"))
    assert code == 1
    assert "YC403" in out
    code, out = run(capsys, "lint", str(PACK_V2), "--fail-on", "never", "--format", "json")
    assert code == 0
    assert json.loads(out)["blocking"] == 0
    code, out = run(capsys, "test", str(PACK_V2), "--junit", str(tmp_path / "t.xml"))
    assert code == 2
    assert "FAIL PUA_PE_Packer_UPX/match/packed.exe.bin" in out
    code, out = run(capsys, "test", str(PACK_V1), "--format", "json")
    assert code == 0
    assert json.loads(out)["untested"] == []
    code, out = run(capsys, "fp", str(PACK_V2), "--junit", str(tmp_path / "f.xml"))
    assert code == 4
    assert "goodware/src/app_icon.py" in out
    code, out = run(capsys, "fp", str(PACK_V1), "--format", "json")
    assert code == 0
    assert json.loads(out)["hits"] == []


def test_profile_command(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out_file = tmp_path / "p.json"
    code, out = run(
        capsys,
        "profile",
        str(PACK_V2),
        "--repeat",
        "1",
        "--rule",
        "SUSP_Generic_LongBase64Blob",
        "--rule",
        "PUA_PE_Packer_UPX",
        "--output",
        str(out_file),
    )
    assert "SUSP_Generic_LongBase64Blob" in out
    assert len(json.loads(out_file.read_text())["rules"]) == 2
    code, out = run(
        capsys,
        "profile",
        str(PACK_V1),
        "--repeat",
        "1",
        "--format",
        "json",
        "--corpus",
        str(PACK_V1 / "fixtures"),
    )
    assert json.loads(out)["samples"] == 17
    assert code in (0, 8)


def test_diff_command(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out = run(capsys, "diff", str(PACK_V1), str(PACK_V2), "--output", str(tmp_path / "d.md"))
    assert code == 2 | 4
    assert "verdict: 4 new FP, 1 lost TP" in out
    assert (tmp_path / "d.md").read_text().startswith("## yaraci rule-set diff")
    code, out = run(
        capsys,
        "diff",
        str(PACK_V1),
        str(PACK_V2),
        "--fail-on",
        "none",
        "--format",
        "json",
        "--output",
        str(tmp_path / "d.json"),
    )
    assert code == 0
    assert json.loads(out)["new_fp"] == 4
    code, out = run(capsys, "diff", str(PACK_V1), str(PACK_V1), "--format", "markdown")
    assert code == 0
    assert "0 new false positive" in out


def test_parity_command(capsys: pytest.CaptureFixture[str], make_pack: PackFactory) -> None:
    code, out = run(capsys, "parity", str(PACK_V1))
    assert code == 0
    assert "consistent" in out
    code, out = run(capsys, "parity", str(PACK_V1), "--format", "json", "--corpus", str(PACK_V1 / "fixtures"))
    assert json.loads(out)["consistent"] is True
    bad = make_pack({"r.yar": 'rule SUSP_Dup { strings: $a = "abcdefgh" wide wide condition: $a }'})
    code, _ = run(capsys, "parity", str(bad.root), "--corpus", str(bad.root))
    assert code == 32


def test_compile_failure_paths(capsys: pytest.CaptureFixture[str], make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": rule("SUSP_Bad", "condition: nope")})
    code, out = run(capsys, "check", str(pack.root), "--stages", "lint,tp")
    assert code & 32
    assert "COMPILE  FAILED" in out
    assert run(capsys, "lint", str(pack.root))[0] == 1 | 32
    assert run(capsys, "test", str(pack.root))[0] == 32
    assert run(capsys, "fp", str(pack.root))[0] == 32


def test_explain(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "explain")
    assert code == 0
    assert "YC301" in out
    assert "YC801" in out
    code, out = run(capsys, "explain", "yc403")
    assert "Why:" in out
    code, out = run(capsys, "explain", "YC701")
    assert "goodware" in out
    assert run(capsys, "explain", "YC000")[0] == EXIT_USAGE


def test_fetch_goodware(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = tmp_path / "x.whl"
    src.write_bytes(b"abc")
    manifest = tmp_path / "m.toml"
    digest = hashlib.sha256(b"abc").hexdigest()
    manifest.write_text(
        f'[[package]]\nname="x"\nversion="1"\nurl="{src.as_uri()}"\nsha256="{digest}"\nlicense="MIT"\n'
        f'[[package]]\nname="y"\nversion="1"\nurl="{(tmp_path / "missing.whl").as_uri()}"\nsha256="{digest}"\n'
        'license="MIT"\n'
    )
    code, out = run(capsys, "fetch-goodware", "--manifest", str(manifest), "--dest", str(tmp_path / "c"))
    assert code == 1
    assert "downloaded x.whl" in out
    assert "FAILED" in out


def test_usage_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["check", str(tmp_path / "missing")]) == EXIT_USAGE
    assert "pack directory not found" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["check", str(PACK_V1), "--stages", "bogus"])
    assert main(["-v", "check", str(PACK_V1), "--stages", "lint"]) == 0
