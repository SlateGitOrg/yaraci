"""Goodware manifest, verified fetching, corpus assembly and the FP allowlist."""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import pytest

from conftest import TODAY
from yaraci.config import parse_config
from yaraci.errors import ConfigError, CorpusError
from yaraci.goodware import build_goodware_corpus, fetch_packages, load_allowlist, load_manifest

ROOT = Path(__file__).resolve().parent.parent


def _manifest(tmp_path: Path, url: str, digest: str) -> Path:
    path = tmp_path / "m.toml"
    path.write_text(
        f'[[package]]\nname = "x"\nversion = "1"\nurl = "{url}"\nsha256 = "{digest}"\nlicense = "MIT"\n'
    )
    return path


def test_repo_manifest_is_valid() -> None:
    packages = load_manifest(ROOT / "goodware" / "oss-manifest.toml")
    assert len(packages) >= 5
    assert all(p.url.startswith("https://") for p in packages)
    assert all(p.filename.endswith(".whl") for p in packages)


def test_fetch_verifies_and_caches(tmp_path: Path) -> None:
    src = tmp_path / "pkg.whl"
    src.write_bytes(b"wheel bytes")
    good = hashlib.sha256(b"wheel bytes").hexdigest()
    dest = tmp_path / "cache"
    packages = load_manifest(_manifest(tmp_path, src.as_uri(), good))
    first = fetch_packages(packages, dest)
    assert first.downloaded == ["pkg.whl"]
    assert (dest / "pkg.whl").read_bytes() == b"wheel bytes"
    second = fetch_packages(packages, dest)
    assert second.cached == ["pkg.whl"]


def test_fetch_rejects_hash_mismatch_and_missing(tmp_path: Path) -> None:
    src = tmp_path / "pkg.whl"
    src.write_bytes(b"tampered")
    dest = tmp_path / "cache"
    report = fetch_packages(load_manifest(_manifest(tmp_path, src.as_uri(), "0" * 64)), dest)
    assert "mismatch" in report.failed[0]
    assert not (dest / "pkg.whl").exists()
    assert not (dest / "pkg.whl.part").exists()
    missing = (tmp_path / "gone.whl").as_uri()
    report = fetch_packages(load_manifest(_manifest(tmp_path, missing, "0" * 64)), dest)
    assert report.failed


@pytest.mark.parametrize(
    "body",
    [
        '[[package]]\nname = "x"\n',
        '[[package]]\nname="x"\nversion="1"\nurl="https://a/b.whl"\nsha256="zz"\nlicense="MIT"\n',
        '[[package]]\nname="x"\nversion="1"\nurl="http://a/b.whl"\nsha256="'
        + "0" * 64
        + '"\nlicense="MIT"\n',
        "not toml [",
    ],
)
def test_bad_manifests(tmp_path: Path, body: str) -> None:
    path = tmp_path / "m.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_manifest(path)


def test_corpus_sources(tmp_path: Path) -> None:
    (tmp_path / "bundled").mkdir()
    (tmp_path / "bundled" / "a.txt").write_text("a")
    (tmp_path / ".cache").mkdir()
    (tmp_path / ".cache" / "b.txt").write_text("b")
    (tmp_path / "extra").mkdir()
    (tmp_path / "extra" / "c.txt").write_text("c")
    (tmp_path / "sys").mkdir()
    (tmp_path / "sys" / "tool").write_text("d")
    cfg = parse_config(
        {
            "goodware": {
                "dirs": ["bundled"],
                "fetched_dir": ".cache",
                "system_paths": [str(tmp_path / "sys" / "*")],
            }
        },
        tmp_path,
    )
    corpus = build_goodware_corpus(cfg, include_system=True, extra_dirs=[tmp_path / "extra"])
    origins = sorted(s.origin for s in corpus.samples)
    assert origins == ["bundled", "bundled", "fetched", "system"]
    cfg.goodware.dirs = ["missing"]
    with pytest.raises(CorpusError):
        build_goodware_corpus(cfg)
    cfg.goodware.dirs = []
    with pytest.raises(CorpusError):
        build_goodware_corpus(cfg, extra_dirs=[tmp_path / "nope"])
    cfg.goodware.fetched_dir = "absent"
    assert build_goodware_corpus(cfg).samples == []


def test_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "allow.toml"
    assert load_allowlist(path, TODAY).active == []
    digest = "a" * 64
    path.write_text(
        f'[[allow]]\nrule = "R"\nsha256 = "{digest.upper()}"\nreason = "vendor updater"\nexpires = 2027-01-01\n'
        f'[[allow]]\nrule = "R"\nsha256 = "{"b" * 64}"\nreason = "old"\nexpires = 2020-01-01\n'
    )
    allow = load_allowlist(path, TODAY)
    assert allow.allows("R", digest) is not None
    assert allow.allows("R", "b" * 64) is None
    assert allow.allows("Other", digest) is None
    assert [e.expires for e in allow.expired] == [date(2020, 1, 1)]


@pytest.mark.parametrize(
    "body",
    [
        '[[allow]]\nrule = "R"\n',
        '[[allow]]\nrule="R"\nsha256="' + "a" * 64 + '"\nreason="x"\nexpires="2027-01-01"\n',
        '[[allow]]\nrule="R"\nsha256="abc"\nreason="x"\nexpires=2027-01-01\n',
        '[[allow]]\nrule="R"\nsha256="' + "a" * 64 + '"\nreason=" "\nexpires=2027-01-01\n',
        "[[allow]\n",
    ],
)
def test_bad_allowlists(tmp_path: Path, body: str) -> None:
    path = tmp_path / "allow.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_allowlist(path, TODAY)
