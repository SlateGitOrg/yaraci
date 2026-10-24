"""Output writers: console text, Markdown, JSON, JUnit XML and SARIF 2.1.0."""

from yaraci.report.jsonout import check_dict, diff_dict, dumps, parity_dict, profile_dict
from yaraci.report.junit import write_junit
from yaraci.report.sarif import build_sarif, write_sarif
from yaraci.report.text import (
    render_check,
    render_check_markdown,
    render_diff,
    render_diff_markdown,
    render_findings,
    render_parity,
    render_profile,
)

__all__ = [
    "build_sarif",
    "check_dict",
    "diff_dict",
    "dumps",
    "parity_dict",
    "profile_dict",
    "render_check",
    "render_check_markdown",
    "render_diff",
    "render_diff_markdown",
    "render_findings",
    "render_parity",
    "render_profile",
    "write_junit",
    "write_sarif",
]
