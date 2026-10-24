"""Exception hierarchy for yaraci.

Every error raised deliberately by yaraci derives from :class:`YaraciError` so the
CLI can map it to a stable exit code instead of a traceback.
"""

from __future__ import annotations


class YaraciError(Exception):
    """Base class for all expected, user-facing failures."""


class ConfigError(YaraciError):
    """The configuration file or a command-line option is invalid."""


class SyntaxParseError(YaraciError):
    """A YARA source file could not be parsed by the yaraci front-end."""

    def __init__(self, message: str, path: str, line: int, column: int) -> None:
        super().__init__(f"{path}:{line}:{column}: {message}")
        self.message = message
        self.path = path
        self.line = line
        self.column = column


class PackError(YaraciError):
    """A rule pack is structurally unusable (missing directory, no rules, ...)."""


class EngineError(YaraciError):
    """The YARA engine failed to compile or scan."""


class CorpusError(YaraciError):
    """A corpus source could not be read or verified."""
