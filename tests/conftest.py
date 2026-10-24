"""Shared test helpers: throwaway rule packs and paths to the bundled examples."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest

from yaraci.pack import RulePack, load_pack

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
PACK_V1 = EXAMPLES / "pack-v1"
PACK_V2 = EXAMPLES / "pack-v2"
GOODWARE = EXAMPLES / "goodware"
TODAY = date(2026, 10, 24)

GOOD_META = (
    'author = "t" description = "A sufficiently descriptive sentence" date = "2026-01-02" '
    'reference = "https://example.org/r"'
)

PackFactory = Callable[..., RulePack]


@pytest.fixture
def make_pack(tmp_path: Path) -> PackFactory:
    """Create a pack on disk: ``make_pack({"a.yar": src}, fixtures={...}, config="...")``."""

    def factory(
        rules: dict[str, str],
        fixtures: dict[str, bytes] | None = None,
        config: str = "",
        goodware: dict[str, bytes] | None = None,
    ) -> RulePack:
        root = tmp_path / "pack"
        (root / "rules").mkdir(parents=True, exist_ok=True)
        for name, text in rules.items():
            path = root / "rules" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        for rel, data in (fixtures or {}).items():
            path = root / "fixtures" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        if goodware is not None:
            for rel, data in goodware.items():
                path = root / "goodware" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            config = '[goodware]\ndirs = ["goodware"]\nfetched = false\n' + config
        (root / "yaraci.toml").write_text(config, encoding="utf-8")
        return load_pack(root)

    return factory


def rule(name: str, body: str, meta: str = GOOD_META, prefix: str = "") -> str:
    """Render a rule with good metadata unless overridden."""
    meta_block = f"meta: {meta} " if meta else ""
    return f"{prefix}rule {name} {{ {meta_block}{body} }}\n"


@pytest.fixture
def v1() -> RulePack:
    return load_pack(PACK_V1)


@pytest.fixture
def v2() -> RulePack:
    return load_pack(PACK_V2)
