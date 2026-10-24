"""Corpus loading: directories, glob lists and archives, deduplicated by content.

Corpora are untrusted input (goodware downloaded from the internet, system
binaries, contributed fixtures), so the loader is defensive:

* symlinks and non-regular files are skipped (no loops, no escaping the corpus);
* files above ``max_file_size`` are skipped, never truncated (a truncated file
  would produce misleading match results);
* archives (zip/wheel/jar, tar/tar.gz) are expanded one level deep, in memory,
  with per-member and per-archive byte budgets that are enforced on the bytes
  actually read, not on the sizes the archive header claims (zip-bomb guard);
* identical content is scanned once (SHA-256 dedup), recording every name.
"""

from __future__ import annotations

import glob
import hashlib
import io
import logging
import tarfile
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

log = logging.getLogger(__name__)

ZIP_SUFFIXES = (".zip", ".whl", ".jar", ".nupkg", ".egg")
TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")


@dataclass(frozen=True, slots=True)
class Sample:
    """One scannable blob of bytes."""

    name: str
    data: bytes
    sha256: str
    origin: str

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class Limits:
    max_file_size: int = 16 * 1024 * 1024
    max_members: int = 2_000
    max_member_size: int = 8 * 1024 * 1024
    max_archive_total: int = 64 * 1024 * 1024
    expand_archives: bool = True


@dataclass(slots=True)
class CorpusStats:
    files_seen: int = 0
    skipped_large: int = 0
    skipped_special: int = 0
    duplicates: int = 0
    archive_members: int = 0
    archive_errors: list[str] = field(default_factory=list)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_files(root: Path) -> Iterator[Path]:
    """Regular files under ``root`` (or ``root`` itself), sorted, never following symlinks."""
    if root.is_symlink():
        return
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        if path.is_symlink() or not path.is_file():
            continue
        yield path


def expand_globs(patterns: Iterable[str], max_files: int) -> list[Path]:
    """Expand glob patterns (e.g. ``/usr/bin/*``) to at most ``max_files`` regular files."""
    found: list[Path] = []
    for pattern in patterns:
        for match in sorted(glob.glob(pattern)):
            path = Path(match)
            if path.is_symlink() or not path.is_file():
                continue
            found.append(path)
            if len(found) >= max_files:
                return found
    return found


def _is_zip(name: str) -> bool:
    return name.lower().endswith(ZIP_SUFFIXES)


def _is_tar(name: str) -> bool:
    return name.lower().endswith(TAR_SUFFIXES)


def _read_bounded(stream: IO[bytes], limit: int) -> bytes | None:
    """Read at most ``limit`` bytes; ``None`` if the member is larger (header sizes can lie)."""
    data = stream.read(limit + 1)
    return None if len(data) > limit else data


def expand_archive(name: str, data: bytes, limits: Limits, stats: CorpusStats) -> Iterator[tuple[str, bytes]]:
    """Yield ``(member_name, bytes)`` for regular members of a zip or tar archive."""
    budget = limits.max_archive_total
    count = 0
    try:
        if _is_zip(name):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if count >= limits.max_members or budget <= 0:
                        stats.archive_errors.append(f"{name}: member/byte budget exhausted")
                        return
                    with zf.open(info) as fh:
                        blob = _read_bounded(fh, min(limits.max_member_size, budget))
                    if blob is None:
                        stats.skipped_large += 1
                        continue
                    count += 1
                    budget -= len(blob)
                    yield f"{name}!{info.filename}", blob
        elif _is_tar(name):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for member in tf:
                    if not member.isreg():
                        continue
                    if count >= limits.max_members or budget <= 0:
                        stats.archive_errors.append(f"{name}: member/byte budget exhausted")
                        return
                    member_fh = tf.extractfile(member)
                    limit = min(limits.max_member_size, budget)
                    blob = _read_bounded(member_fh, limit) if member_fh else None
                    if blob is None:
                        stats.skipped_large += 1
                        continue
                    count += 1
                    budget -= len(blob)
                    yield f"{name}!{member.name}", blob
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError) as exc:
        stats.archive_errors.append(f"{name}: {exc}")


@dataclass(slots=True)
class CorpusBuilder:
    """Accumulates samples from several sources with global SHA-256 deduplication."""

    limits: Limits = field(default_factory=Limits)
    stats: CorpusStats = field(default_factory=CorpusStats)
    samples: list[Sample] = field(default_factory=list)
    aliases: dict[str, list[str]] = field(default_factory=dict)
    _index: dict[str, int] = field(default_factory=dict)

    def add_bytes(self, name: str, data: bytes, origin: str) -> Sample | None:
        digest = sha256(data)
        if digest in self._index:
            self.stats.duplicates += 1
            self.aliases.setdefault(digest, []).append(name)
            return None
        sample = Sample(name, data, digest, origin)
        self._index[digest] = len(self.samples)
        self.samples.append(sample)
        if self.limits.expand_archives and (_is_zip(name) or _is_tar(name)):
            for member, blob in expand_archive(name, data, self.limits, self.stats):
                self.stats.archive_members += 1
                self.add_bytes(member, blob, origin)
        return sample

    def add_path(self, path: Path, display: str, origin: str) -> None:
        self.stats.files_seen += 1
        try:
            size = path.stat().st_size
            if size > self.limits.max_file_size:
                self.stats.skipped_large += 1
                log.debug("skip large file %s (%d bytes)", display, size)
                return
            data = path.read_bytes()
        except OSError as exc:
            self.stats.skipped_special += 1
            log.debug("skip unreadable %s: %s", display, exc)
            return
        self.add_bytes(display, data, origin)

    def add_tree(self, root: Path, origin: str, display_root: Path | None = None) -> None:
        base = display_root or (root if root.is_dir() else root.parent)
        for path in iter_files(root):
            try:
                display = path.relative_to(base).as_posix()
            except ValueError:
                display = path.as_posix()
            prefix = base.name + "/" if display_root is None else ""
            self.add_path(path, prefix + display, origin)

    @property
    def total_bytes(self) -> int:
        return sum(s.size for s in self.samples)
