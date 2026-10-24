"""Offline end-to-end demo against the bundled example packs (``make demo``).

1. ``check`` the clean v1 pack: every gate passes (exit 0).
2. ``check`` the regressed v2 pack: lint, TP, FP, performance and quality gates
   all fail, and the exit code is the bitmask of the failing gates.
3. ``diff`` v1 -> v2: structural changes plus match impact (new FP / lost TP).
4. ``parity``: libyara and YARA-X agree on v1.

Reports (JUnit, SARIF, JSON, Markdown) are written to ``out/``. If the pinned
OSS goodware has been fetched (``make goodware``) it is included automatically;
nothing here touches the network.
"""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
V1, V2 = "examples/pack-v1", "examples/pack-v2"


def yaraci(*args: str) -> int:
    print(f"\n$ yaraci {' '.join(args)}", flush=True)
    proc = subprocess.run([sys.executable, "-m", "yaraci", *args], cwd=ROOT, check=False)
    print(f"[exit {proc.returncode}]", flush=True)
    return proc.returncode


def describe_artifacts(prefix: str) -> None:
    junit = ET.parse(OUT / prefix / "junit.xml").getroot()  # noqa: S314 - file this demo just wrote
    sarif = json.loads((OUT / prefix / "results.sarif").read_text())
    print(
        f"  {prefix}: junit.xml {junit.get('tests')} tests / {junit.get('failures')} failures; "
        f"results.sarif {len(sarif['runs'][0]['results'])} results; report.json; summary.md"
    )


def main() -> int:
    OUT.mkdir(exist_ok=True)
    fetched = ROOT / ".cache" / "goodware"
    print("yaraci demo - offline, bundled fixtures only")
    state = "present, included" if fetched.is_dir() else "absent (run make goodware to add)"
    print(f"fetched OSS goodware: {state}")
    expectations: list[tuple[str, bool]] = []

    def check(pack: str, name: str) -> int:
        return yaraci(
            "check", pack, "--repeat", "3",
            "--junit", f"out/{name}/junit.xml", "--sarif", f"out/{name}/results.sarif",
            "--json", f"out/{name}/report.json", "--markdown", f"out/{name}/summary.md",
        )  # fmt: skip

    code = check(V1, "v1")
    expectations.append(("v1 passes every gate", code == 0))
    code = check(V2, "v2")
    expectations.append(("v2 fails lint+TP+FP+perf+quality gates (exit 31)", code == 1 | 2 | 4 | 8 | 16))
    code = yaraci("diff", V1, V2, "--output", "out/diff.md")
    expectations.append(("diff v1->v2 flags new FP and lost TP (exit 6)", code == 2 | 4))
    code = yaraci("parity", V1)
    expectations.append(("libyara and YARA-X agree on v1", code == 0))

    print("\nartifacts written to out/:")
    describe_artifacts("v1")
    describe_artifacts("v2")
    print("  diff.md (Markdown diff for a pull-request comment)")
    print("\ndemo expectations:")
    for label, ok in expectations:
        print(f"  [{'ok' if ok else 'UNEXPECTED'}] {label}")
    return 0 if all(ok for _, ok in expectations) else 1


if __name__ == "__main__":
    sys.exit(main())
