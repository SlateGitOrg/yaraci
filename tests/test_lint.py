"""Every lint check fires on a bad rule and stays quiet on a good one."""

from __future__ import annotations

import pytest

from conftest import TODAY, PackFactory, rule
from yaraci.engine import get_backend
from yaraci.lint import SPECS, Severity, lint_pack

GOOD = rule("SUSP_Good_Rule", 'strings: $a = "evilstring" condition: $a')


def codes_for(make_pack: PackFactory, source: str, config: str = "") -> list[str]:
    pack = make_pack({"r.yar": source}, config=config)
    return [f.code for f in lint_pack(pack, today=TODAY)]


def test_good_rule_is_clean(make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": GOOD})
    assert lint_pack(pack, today=TODAY, backend=get_backend("yara-x")) == []


@pytest.mark.parametrize(
    ("code", "source", "config"),
    [
        ("YC101", rule("badname", 'strings: $a = "evilstring" condition: $a'), ""),
        ("YC102", rule("SUSP_" + "X" * 70, 'strings: $a = "evilstring" condition: $a'), ""),
        (
            "YC104",
            rule("FOO_Bar", 'strings: $a = "evilstring" condition: $a'),
            '[lint]\nname_prefixes = ["MAL"]',
        ),
        (
            "YC105",
            'rule SUSP_T : BadTag dup dup { meta: author = "t" description = "A sufficiently descriptive '
            'sentence" date = "2026-01-02" strings: $a = "evilstring" condition: $a }',
            "",
        ),
        ("YC201", rule("SUSP_NoMeta", 'strings: $a = "evilstring" condition: $a', meta=""), ""),
        (
            "YC202",
            rule("SUSP_Rec", 'strings: $a = "evilstring" condition: $a'),
            '[lint]\nrecommended_meta = ["hash"]',
        ),
        (
            "YC203",
            rule(
                "SUSP_D",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "12/1/2020"',
            ),
            "",
        ),
        (
            "YC203",
            rule(
                "SUSP_D",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-02-30"',
            ),
            "",
        ),
        (
            "YC203",
            rule(
                "SUSP_D",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2099-01-01"',
            ),
            "",
        ),
        (
            "YC203",
            rule(
                "SUSP_D",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = 20200101',
            ),
            "",
        ),
        (
            "YC204",
            rule(
                "SUSP_H",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
                'sha256 = "abc"',
            ),
            "",
        ),
        (
            "YC205",
            rule(
                "SUSP_R",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
                'reference = "internal wiki"',
            ),
            "",
        ),
        (
            "YC206",
            rule(
                "SUSP_Dup",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" author = "u" description = "A sufficiently descriptive sentence" '
                'date = "2026-01-02"',
            ),
            "",
        ),
        (
            "YC207",
            rule(
                "SUSP_Desc",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "short" date = "2026-01-02"',
            ),
            "",
        ),
        (
            "YC207",
            rule(
                "SUSP_Desc_Rule_Name_Long",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "SUSP desc rule name long" date = "2026-01-02"',
            ),
            "",
        ),
        (
            "YC208",
            rule(
                "SUSP_Score",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
                'score = "high"',
            ),
            "",
        ),
        (
            "YC208",
            rule(
                "SUSP_Score",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
                "score = 900",
            ),
            "",
        ),
        (
            "YC208",
            rule(
                "SUSP_Sev",
                'strings: $a = "evilstring" condition: $a',
                meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
                'severity = "urgent"',
            ),
            "",
        ),
        ("YC301", rule("SUSP_Weak", 'strings: $a = "MZ" condition: $a'), ""),
        ("YC301", rule("SUSP_Weak", "strings: $a = { 00 00 00 00 } condition: $a"), ""),
        ("YC301", rule("SUSP_Weak", "strings: $a = /[a-z]{30,40}/ condition: $a"), ""),
        ("YC302", rule("SUSP_Re", "strings: $a = /evilstring.*payload/ condition: $a"), ""),
        ("YC302", rule("SUSP_Re", "strings: $a = /.*evilstring/ condition: $a"), ""),
        ("YC302", rule("SUSP_Re", "strings: $a = /evilstring[^x]+payload/ condition: $a"), ""),
        (
            "YC303",
            rule("SUSP_Dup", 'strings: $a = "evilstring" $b = "evilstring" condition: any of them'),
            "",
        ),
        ("YC304", rule("SUSP_Nc", 'strings: $a = "12345678" nocase condition: $a'), ""),
        ("YC305", rule("SUSP_Ascii", 'strings: $a = "evilstring" ascii condition: $a'), ""),
        ("YC306", rule("SUSP_Jump", "strings: $a = { 4D 5A 90 00 [-] 50 45 00 00 } condition: $a"), ""),
        ("YC306", rule("SUSP_Jump", "strings: $a = { 4D 5A ZZ } condition: $a"), ""),
        (
            "YC307",
            rule("SUSP_Many", 'strings: $a = "evilstring1" $b = "evilstring2" condition: any of them'),
            "[lint]\nmax_strings = 1",
        ),
        ("YC308", rule("SUSP_Xor", 'strings: $a = "evil" xor condition: $a'), ""),
        ("YC309", rule("SUSP_Low", 'strings: $a = "AAAAAAAAAAAA" condition: $a'), ""),
        ("YC309", rule("SUSP_Low", "strings: $a = { 41 41 41 41 41 41 } condition: $a"), ""),
        ("YC401", rule("SUSP_True", "condition: true"), ""),
        ("YC401", rule("SUSP_Size", "condition: filesize < 100"), ""),
        ("YC401", rule("SUSP_False", "condition: false"), ""),
        (
            "YC402",
            rule("SUSP_Of", 'strings: $a = "evilstring" $b = "payloadxx" condition: 3 of ($a, $b)'),
            "",
        ),
        ("YC402", rule("SUSP_Of", 'strings: $a = "evilstring" condition: any of ($z*)'), ""),
        ("YC402", rule("SUSP_Of", 'strings: $a = "evilstring" condition: 150% of them'), ""),
        ("YC402", rule("SUSP_Of", 'strings: $a = "evilstring" condition: for 2 of ($a) : ($ at 0)'), ""),
        (
            "YC403",
            rule("SUSP_Fs", 'strings: $a = "evilstring" condition: $a and filesize > 2MB and filesize < 1MB'),
            "",
        ),
        (
            "YC403",
            rule(
                "SUSP_Fs", 'strings: $a = "evilstring" condition: $a and 100 > filesize and filesize == 200'
            ),
            "",
        ),
        (
            "YC404",
            'import "pe"\n'
            + rule("SUSP_Pe", 'strings: $a = "evilstring" condition: $a and pe.number_of_sections > 2'),
            "",
        ),
        (
            "YC405",
            'import "math"\n'
            + rule("SUSP_Ent", 'strings: $a = "evilstring" condition: $a and math.entropy(0, filesize) > 7'),
            "",
        ),
        (
            "YC406",
            rule(
                "SUSP_Loop",
                'strings: $a = "evilstring" condition: for any i in (0..filesize) : (uint8(i) == 1) and $a',
            ),
            "",
        ),
        (
            "YC406",
            rule(
                "SUSP_Loop",
                'strings: $a = "evilstring" condition: for any i in (0..20000) : (uint8(i) == 1) and $a',
            ),
            "",
        ),
        ("YC407", rule("SUSP_Rng", 'strings: $a = "evilstring" condition: $a in (0..filesize)'), ""),
        (
            "YC408",
            'import "math"\n'
            + rule(
                "SUSP_Ord",
                'strings: $a = "evilstring" condition: for any i in (1..#a) : (@a[i] > 5) and filesize < 1MB',
            ),
            "",
        ),
        ("YC409", rule("SUSP_Mz", 'strings: $mz = "MZ" $a = "evilstring" condition: $mz at 0 and $a'), ""),
        (
            "YC409",
            rule("SUSP_Mz", 'strings: $mz = { 4D 5A } $a = "evilstring" condition: $mz at 0 and $a'),
            "",
        ),
    ],
)
def test_check_fires(make_pack: PackFactory, code: str, source: str, config: str) -> None:
    assert code in codes_for(make_pack, source, config)


@pytest.mark.parametrize(
    ("code", "source"),
    [
        ("YC401", "global rule G { condition: filesize < 10MB }\n" + GOOD),
        ("YC402", rule("SUSP_Of", 'strings: $a = "evilstring" $b = "payloadxx" condition: 2 of them')),
        ("YC402", rule("SUSP_Of", 'strings: $a = "evilstring" condition: 100% of them')),
        (
            "YC403",
            rule("SUSP_Fs", 'strings: $a = "evilstring" condition: $a and filesize > 1MB and filesize < 2MB'),
        ),
        (
            "YC404",
            'import "pe"\n'
            + rule(
                "SUSP_Pe",
                'strings: $a = "evilstring" condition: uint16(0) == 0x5A4D and pe.number_of_sections > 2 and $a',
            ),
        ),
        (
            "YC405",
            'import "math"\n'
            + rule(
                "SUSP_Ent",
                'strings: $a = "evilstring" condition: filesize < 1MB and $a and math.entropy(0, filesize) > 7',
            ),
        ),
        (
            "YC406",
            rule(
                "SUSP_Loop",
                'strings: $a = "evilstring" condition: for any i in (0..10) : (uint8(i) == 1) and $a',
            ),
        ),
        ("YC201", rule("SUSP_Priv", "condition: uint16(0) == 0x5A4D", meta="", prefix="private ")),
        ("YC302", rule("SUSP_Re", r"strings: $a = /evilstring\s*payload/ condition: $a")),
        ("YC301", rule("SUSP_Strong", 'strings: $a = "evilstring" wide ascii condition: $a')),
    ],
)
def test_check_quiet(make_pack: PackFactory, code: str, source: str) -> None:
    assert code not in codes_for(make_pack, source)


def test_duplicate_rule_names_and_parse_errors(make_pack: PackFactory) -> None:
    pack = make_pack(
        {
            "a.yar": GOOD,
            "b.yar": GOOD,
            "broken.yar": "rule {",
            "inc.yar": 'include "a.yar"\n' + rule("SUSP_Other", 'strings: $a = "evilstringz" condition: $a'),
        }
    )
    found = lint_pack(pack, today=TODAY)
    codes = {f.code for f in found}
    assert {"YC103", "YC001", "YC002"} <= codes
    parse = next(f for f in found if f.code == "YC001")
    assert parse.path == "rules/broken.yar"


def test_engine_findings_are_attributed(make_pack: PackFactory) -> None:
    src = rule("SUSP_Slow", "strings: $a = { 00 00 } condition: $a") + rule("SUSP_Bad", "condition: nope")
    pack = make_pack({"r.yar": src})
    for engine in ("yara-x", "libyara"):
        found = lint_pack(pack, today=TODAY, backend=get_backend(engine))
        errors = [f for f in found if f.code == "YC501"]
        assert errors, engine
        assert errors[0].rule == "SUSP_Bad"
        assert errors[0].path == "rules/r.yar"


def test_engine_warning_attributed(make_pack: PackFactory) -> None:
    pack = make_pack({"r.yar": rule("SUSP_Slow", "strings: $a = { 00 00 } condition: $a")})
    found = lint_pack(pack, today=TODAY, backend=get_backend("yara-x"))
    warning = next(f for f in found if f.code == "YC502")
    assert warning.rule == "SUSP_Slow"
    assert "slow" in warning.message


def test_suppressions_and_policy(make_pack: PackFactory) -> None:
    src = (
        "// yaraci:ignore YC101\n"
        + rule("lowercase_name", 'strings: $a = "MZ" condition: $a')
        + rule(
            "SUSP_Meta",
            'strings: $a = "MZ" condition: $a',
            meta='author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
            'yaraci_ignore = "YC301"',
        )
    )
    pack = make_pack({"r.yar": src}, config='[lint]\ndisable = ["YC309"]\nseverity = { YC301 = "error" }')
    found = lint_pack(pack, today=TODAY)
    assert not any(f.code == "YC101" for f in found)
    weak = [f for f in found if f.code == "YC301"]
    assert [f.rule for f in weak] == ["lowercase_name"]
    assert weak[0].severity is Severity.ERROR


def test_file_level_suppression(make_pack: PackFactory) -> None:
    src = "/* yaraci:ignore-file YC301, YC101 */\n" + rule("bad", 'strings: $a = "MZ" condition: $a')
    codes = codes_for(make_pack, src)
    assert "YC301" not in codes
    assert "YC101" not in codes


def test_unknown_codes_in_config_are_logged(make_pack: PackFactory, caplog: pytest.LogCaptureFixture) -> None:
    pack = make_pack({"r.yar": GOOD}, config='[lint]\ndisable = ["YC999"]')
    lint_pack(pack, today=TODAY)
    assert "YC999" in caplog.text


def test_every_spec_is_documented() -> None:
    for spec in SPECS.values():
        assert spec.summary.endswith(".")
        assert len(spec.rationale) > 20
        assert spec.code.startswith("YC")
