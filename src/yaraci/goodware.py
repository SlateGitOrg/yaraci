"""Goodware corpus assembly, pinned package fetching and the FP allowlist.

Three goodware sources feed false-positive testing:

1. **bundled** directories listed in ``[goodware].dirs`` (committed benign files);
2. **fetched** open-source packages from a pinned manifest, verified by SHA-256
   and cached under ``[goodware].fetched_dir`` (only used when present, so
   offline runs still work);
3. **system** binaries matched by ``[goodware].system_paths`` globs (opt-in,
   machine-specific, therefore never part of the reproducible gate by default).
"""

from __future__ import annotations

import hashlib
import logging
import re
import tomllib
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from yaraci.config import Config
from yaraci.corpus import CorpusBuilder, Limits, expand_globs
from yaraci.errors import ConfigError, CorpusError

log = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_SCHEMES = frozenset({"https", "file"})
_CHUNK = 64 * 1024


# --------------------------------------------------------------------------- manifest
@dataclass(frozen=True, slots=True)
class Package:
    name: str
    version: str
    url: str
    sha256: str
    license: str

    @property
    def filename(self) -> str:
        return Path(urlparse(self.url).path).name


def load_manifest(path: Path) -> list[Package]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read goodware manifest {path}: {exc}") from None
    packages = []
    for idx, raw in enumerate(data.get("package", [])):
        try:
            pkg = Package(
                name=str(raw["name"]),
                version=str(raw["version"]),
                url=str(raw["url"]),
                sha256=str(raw["sha256"]).lower(),
                license=str(raw["license"]),
            )
        except KeyError as exc:
            raise ConfigError(f"{path}: package #{idx + 1} is missing {exc}") from None
        if not _SHA_RE.match(pkg.sha256):
            raise ConfigError(f"{path}: package {pkg.name} has an invalid sha256")
        if urlparse(pkg.url).scheme not in _ALLOWED_SCHEMES:
            raise ConfigError(f"{path}: package {pkg.name} must use an https:// (or file://) URL")
        packages.append(pkg)
    return packages


@dataclass(slots=True)
class FetchReport:
    downloaded: list[str] = field(default_factory=list)
    cached: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_packages(packages: list[Package], dest: Path, timeout_s: float = 30.0) -> FetchReport:
    """Download every package into ``dest``, verifying SHA-256; idempotent.

    A file is written to ``<name>.part`` and renamed only after its hash
    matches, so an interrupted or tampered download never enters the corpus.
    """
    dest.mkdir(parents=True, exist_ok=True)
    report = FetchReport()
    for pkg in packages:
        target = dest / pkg.filename
        if target.exists() and _file_sha256(target) == pkg.sha256:
            report.cached.append(pkg.filename)
            continue
        part = target.with_name(target.name + ".part")
        digest = hashlib.sha256()
        try:
            with urllib.request.urlopen(pkg.url, timeout=timeout_s) as resp, part.open("wb") as out:  # noqa: S310 - scheme validated in load_manifest
                for chunk in iter(lambda: resp.read(_CHUNK), b""):
                    digest.update(chunk)
                    out.write(chunk)
        except OSError as exc:
            part.unlink(missing_ok=True)
            report.failed.append(f"{pkg.filename}: {exc}")
            continue
        if digest.hexdigest() != pkg.sha256:
            part.unlink(missing_ok=True)
            report.failed.append(f"{pkg.filename}: sha256 mismatch (got {digest.hexdigest()})")
            continue
        part.replace(target)
        report.downloaded.append(pkg.filename)
    return report


# --------------------------------------------------------------------------- corpus
def limits_for(cfg: Config) -> Limits:
    return Limits(max_file_size=cfg.goodware.max_file_size, expand_archives=cfg.goodware.expand_archives)


def build_goodware_corpus(
    cfg: Config, include_system: bool | None = None, extra_dirs: list[Path] | None = None
) -> CorpusBuilder:
    """Assemble the goodware corpus described by ``cfg`` (plus ``extra_dirs``)."""
    builder = CorpusBuilder(limits=limits_for(cfg))
    for entry in cfg.goodware.dirs:
        path = cfg.resolve(entry)
        if not path.exists():
            raise CorpusError(f"goodware directory not found: {entry}")
        builder.add_tree(path, "bundled")
    for path in extra_dirs or []:
        if not path.exists():
            raise CorpusError(f"goodware path not found: {path}")
        builder.add_tree(path, "bundled")
    fetched = cfg.resolve(cfg.goodware.fetched_dir)
    if cfg.goodware.fetched and fetched.is_dir():
        builder.add_tree(fetched, "fetched")
    elif cfg.goodware.fetched:
        log.info("fetched goodware not present at %s (run `make goodware`)", fetched)
    system = cfg.goodware.system if include_system is None else include_system
    if system:
        for path in expand_globs(cfg.goodware.system_paths, cfg.goodware.system_max_files):
            builder.add_path(path, path.as_posix(), "system")
    return builder


# --------------------------------------------------------------------------- allowlist
@dataclass(frozen=True, slots=True)
class AllowEntry:
    rule: str
    sha256: str
    reason: str
    expires: date


@dataclass(slots=True)
class Allowlist:
    active: list[AllowEntry] = field(default_factory=list)
    expired: list[AllowEntry] = field(default_factory=list)

    def allows(self, rule: str, digest: str) -> AllowEntry | None:
        for entry in self.active:
            if entry.rule == rule and entry.sha256 == digest:
                return entry
        return None


def load_allowlist(path: Path, today: date) -> Allowlist:
    """Load accepted false positives; entries past ``expires`` stop applying."""
    result = Allowlist()
    if not path.exists():
        return result
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    for idx, raw in enumerate(data.get("allow", [])):
        where = f"{path.name} entry #{idx + 1}"
        try:
            rule, digest, reason, expires = raw["rule"], raw["sha256"], raw["reason"], raw["expires"]
        except KeyError as exc:
            raise ConfigError(f"{where} is missing {exc}") from None
        if not isinstance(expires, date):
            raise ConfigError(f"{where}: expires must be a TOML date (YYYY-MM-DD)")
        if not _SHA_RE.match(str(digest).lower()):
            raise ConfigError(f"{where}: sha256 must be 64 hex characters")
        if not str(reason).strip():
            raise ConfigError(f"{where}: reason must not be empty")
        entry = AllowEntry(str(rule), str(digest).lower(), str(reason), expires)
        (result.active if expires >= today else result.expired).append(entry)
    return result
