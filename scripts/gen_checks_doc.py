"""Generate docs/CHECKS.md from the check registry so the catalogue never drifts.

uv run python scripts/gen_checks_doc.py           # rewrite docs/CHECKS.md
uv run python scripts/gen_checks_doc.py --check   # exit 1 if it is stale
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from yaraci.lint import SPECS
from yaraci.report.model import STAGE_CODES

TARGET = Path(__file__).resolve().parent.parent / "docs" / "CHECKS.md"


def render() -> str:
    lines = [
        "# Check catalogue",
        "",
        "Generated from the registry by `scripts/gen_checks_doc.py`; `make check` fails if it is stale.",
        "Suppress a check for one rule with `// yaraci:ignore YC301` (on the line before or inside the",
        'rule) or `meta: yaraci_ignore = "YC301"`; for a whole file with `// yaraci:ignore-file YC301`;',
        'for the pack with `[lint] disable = ["YC301"]`. Change a severity with',
        '`[lint] severity = { YC301 = "error" }`. `yaraci explain YC301` prints one entry.',
        "",
        "## Static and engine checks",
        "",
        "| Code | Name | Category | Default | What it means |",
        "|---|---|---|---|---|",
    ]
    for spec in sorted(SPECS.values(), key=lambda s: s.code):
        lines.append(
            f"| {spec.code} | `{spec.name}` | {spec.category} | {spec.severity.label} | {spec.summary} |"
        )
    lines += ["", "## Scan-stage results (reported in SARIF/JUnit alongside lint findings)", ""]
    lines += ["| Code | Name | Default | What it means |", "|---|---|---|---|"]
    for stage in STAGE_CODES.values():
        lines.append(f"| {stage.code} | `{stage.name}` | {stage.severity.label} | {stage.summary} |")
    lines += ["", "## Rationale", ""]
    for spec in sorted(SPECS.values(), key=lambda s: s.code):
        lines += [f"### {spec.code} {spec.name}", "", spec.rationale, ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/CHECKS.md")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        if not TARGET.exists() or TARGET.read_text() != text:
            print("docs/CHECKS.md is stale; run scripts/gen_checks_doc.py")
            return 1
        return 0
    TARGET.write_text(text)
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
