"""Corpus loading: dedup, archives, limits and symlink safety."""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

from yaraci.corpus import CorpusBuilder, CorpusStats, Limits, expand_archive, expand_globs, iter_files


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        zf.writestr("dir/", b"")
    return buf.getvalue()


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    return buf.getvalue()


def test_tree_dedup_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a.txt").write_bytes(b"same")
    (tmp_path / "d" / "b.txt").write_bytes(b"same")
    (tmp_path / "d" / "c.txt").write_bytes(b"different")
    os.symlink(tmp_path / "d" / "c.txt", tmp_path / "d" / "link.txt")
    builder = CorpusBuilder()
    builder.add_tree(tmp_path / "d", "bundled")
    assert [s.name for s in builder.samples] == ["d/a.txt", "d/c.txt"]
    assert builder.stats.duplicates == 1
    assert builder.aliases[builder.samples[0].sha256] == ["d/b.txt"]
    assert builder.total_bytes == len(b"same") + len(b"different")
    assert list(iter_files(tmp_path / "d" / "link.txt")) == []
    assert list(iter_files(tmp_path / "missing")) == []
    assert list(iter_files(tmp_path / "d" / "a.txt")) == [tmp_path / "d" / "a.txt"]


def test_large_and_unreadable_files_skipped(tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 100)
    builder = CorpusBuilder(limits=Limits(max_file_size=10))
    builder.add_path(big, "big.bin", "t")
    builder.add_path(tmp_path / "missing", "missing", "t")
    assert builder.samples == []
    assert builder.stats.skipped_large == 1
    assert builder.stats.skipped_special == 1


def test_zip_and_tar_members_expanded(tmp_path: Path) -> None:
    builder = CorpusBuilder()
    builder.add_bytes("pkg.whl", _zip({"pkg/a.py": b"print(1)", "pkg/b.py": b"print(2)"}), "fetched")
    builder.add_bytes("src.tar.gz", _tar({"src/x.c": b"int main;"}), "fetched")
    names = [s.name for s in builder.samples]
    assert "pkg.whl!pkg/a.py" in names
    assert "src.tar.gz!src/x.c" in names
    assert all(s.origin == "fetched" for s in builder.samples)
    assert builder.stats.archive_members == 3


def test_archive_limits_and_corruption() -> None:
    stats = CorpusStats()
    data = _zip({f"m{i}": bytes([i]) * 50 for i in range(5)})
    small = Limits(max_members=2, max_member_size=100)
    assert len(list(expand_archive("x.zip", data, small, stats))) == 2
    assert "budget" in stats.archive_errors[-1]
    tiny = Limits(max_member_size=10)
    assert list(expand_archive("x.zip", data, tiny, stats)) == []
    assert stats.skipped_large == 5
    tar_stats = CorpusStats()
    tar = _tar({f"t{i}": b"y" * 50 for i in range(3)})
    assert len(list(expand_archive("x.tgz", tar, Limits(max_members=1), tar_stats))) == 1
    assert list(expand_archive("x.tar.gz", tar, Limits(max_member_size=10), tar_stats)) == []
    bad = CorpusStats()
    assert list(expand_archive("broken.zip", b"not a zip", Limits(), bad)) == []
    assert bad.archive_errors
    assert list(expand_archive("plain.txt", b"text", Limits(), bad)) == []


def test_archive_expansion_can_be_disabled() -> None:
    builder = CorpusBuilder(limits=Limits(expand_archives=False))
    builder.add_bytes("pkg.zip", _zip({"a": b"1"}), "t")
    assert len(builder.samples) == 1


def test_expand_globs(tmp_path: Path) -> None:
    for name in ("a", "b", "c"):
        (tmp_path / name).write_bytes(name.encode())
    (tmp_path / "sub").mkdir()
    found = expand_globs([str(tmp_path / "*")], max_files=2)
    assert [p.name for p in found] == ["a", "b"]
    assert expand_globs([str(tmp_path / "nothing*")], 5) == []


def test_nested_archives_expanded_one_level_only() -> None:
    inner = _zip({"deep.txt": b"deep"})
    mid = _zip({"inner.zip": inner, "mid.txt": b"mid"})
    outer = _zip({"mid.zip": mid, "nested.tar.gz": _tar({"t.txt": b"t"})})
    builder = CorpusBuilder()
    builder.add_bytes("outer.zip", outer, "contributed")
    names = sorted(s.name for s in builder.samples)
    assert names == ["outer.zip", "outer.zip!mid.zip", "outer.zip!nested.tar.gz"]
    assert builder.stats.archive_members == 2
    assert not any(name.count("!") > 1 for name in names)


def test_zip_of_zips_bomb_is_bounded() -> None:
    # The review reproduction: an 8x8 zip-of-zips of 4 MiB compressible leaves.
    def deflated(members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buf.getvalue()

    leaf = b"\0" * (4 * 1024 * 1024)
    mids = {f"m{i}.zip": deflated({f"leaf{j}.bin": leaf + bytes([i, j]) for j in range(8)}) for i in range(8)}
    bomb = deflated(mids)
    builder = CorpusBuilder()
    builder.add_bytes("bomb.zip", bomb, "contributed")
    assert len(builder.samples) == 1 + len(mids)
    assert builder.total_bytes <= len(bomb) + Limits().max_archive_total


def test_expansion_budget_is_corpus_wide() -> None:
    limits = Limits(max_archive_total=1_000, max_expanded_total=250)
    builder = CorpusBuilder(limits=limits)
    for i in range(4):
        builder.add_bytes(f"a{i}.zip", _zip({f"m{i}-{j}": bytes([i, j]) * 25 for j in range(3)}), "t")
    members = [s for s in builder.samples if "!" in s.name]
    assert sum(s.size for s in members) <= 250
    assert len(members) == 5
    assert any("corpus-wide" in err for err in builder.stats.archive_errors)


def test_expand_archive_honours_caller_budget() -> None:
    data = _zip({f"m{i}": bytes([i]) * 50 for i in range(5)})
    stats = CorpusStats()
    assert len(list(expand_archive("x.zip", data, Limits(), stats, budget=120))) == 2
    assert stats.skipped_large == 3
    assert len(list(expand_archive("x.zip", data, Limits(max_archive_total=100), stats, budget=10_000))) == 2
    assert "budget" in stats.archive_errors[-1]
