"""JUnit XML writer: one test suite per stage so CI test tabs show rule health."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from yaraci.lint import Finding, Severity
from yaraci.pipeline import CheckResult

_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def _clean(text: str) -> str:
    return _INVALID_XML.sub("?", text)


class _Suite:
    def __init__(self, parent: ET.Element, name: str) -> None:
        self.el = ET.SubElement(parent, "testsuite", name=name)
        self.name = name
        self.tests = self.failures = self.skipped = 0
        self.time = 0.0

    def case(
        self,
        name: str,
        classname: str,
        failure: str | None = None,
        detail: str = "",
        output: str = "",
        seconds: float = 0.0,
        skipped: str | None = None,
    ) -> None:
        tc = ET.SubElement(self.el, "testcase", name=_clean(name), classname=classname, time=f"{seconds:.6f}")
        self.tests += 1
        self.time += seconds
        if failure is not None:
            self.failures += 1
            node = ET.SubElement(tc, "failure", message=_clean(failure))
            node.text = _clean(detail or failure)
        elif skipped is not None:
            self.skipped += 1
            ET.SubElement(tc, "skipped", message=_clean(skipped))
        if output:
            ET.SubElement(tc, "system-out").text = _clean(output)

    def close(self) -> None:
        self.el.set("tests", str(self.tests))
        self.el.set("failures", str(self.failures))
        self.el.set("errors", "0")
        self.el.set("skipped", str(self.skipped))
        self.el.set("time", f"{self.time:.6f}")


def _lint_suite(root: ET.Element, result: CheckResult) -> _Suite:
    suite = _Suite(root, "yaraci.lint")
    gate = result.pack.config.gate.lint_fail_on
    threshold = Severity.ERROR + 1 if gate == "never" else Severity.parse(gate)
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_rule[f.rule or f.path or "<pack>"].append(f)
    for pr in result.pack.rules:
        by_rule.setdefault(pr.name, [])
    for name in sorted(by_rule):
        found = by_rule[name]
        lines = [f"{f.severity.label} {f.code} line {f.line}: {f.message}" for f in found]
        blocking = [f for f in found if f.severity >= threshold]
        failure = f"{len(blocking)} blocking finding(s)" if blocking else None
        suite.case(name, "yaraci.lint", failure, "\n".join(lines), "" if blocking else "\n".join(lines))
    return suite


def _tp_suite(root: ET.Element, result: CheckResult) -> _Suite:
    suite = _Suite(root, "yaraci.tp")
    assert result.tp is not None
    for res in result.tp.results:
        message = None
        if not res.passed:
            want = "match" if res.case.expect_match else "not match"
            message = "scan timed out" if res.timed_out else f"expected {res.case.rule} to {want}"
        others = f"also matched: {', '.join(res.other_rules)}" if res.other_rules else ""
        suite.case(res.label, f"yaraci.tp.{res.case.rule}", message, output=others)
    for name in result.tp.untested:
        suite.case(f"{name}/coverage", f"yaraci.tp.{name}", "no match fixture")
    return suite


def _fp_suite(root: ET.Element, result: CheckResult) -> _Suite:
    suite = _Suite(root, "yaraci.fp")
    assert result.fp is not None
    hits = defaultdict(list)
    for hit in result.fp.hits:
        hits[hit.rule].append(hit)
    for pr in result.pack.public_rules:
        mine = hits.get(pr.name, [])
        blocking = [h for h in mine if h.allowed_by is None]
        allowed = [f"allowlisted: {h.sample} ({h.allowed_by.reason})" for h in mine if h.allowed_by]
        failure = f"{len(blocking)} goodware match(es)" if blocking else None
        detail = "\n".join(f"{h.sample} [{h.origin}] sha256={h.sha256}" for h in blocking)
        suite.case(pr.name, "yaraci.fp", failure, detail, "\n".join(allowed))
    return suite


def _perf_suite(root: ET.Element, result: CheckResult) -> _Suite:
    suite = _Suite(root, "yaraci.perf")
    assert result.profile is not None
    for prof in sorted(result.profile.rules, key=lambda r: r.rule):
        if prof.error:
            suite.case(prof.rule, "yaraci.perf", skipped=prof.error)
            continue
        info = f"{prof.us_per_mb:,.1f} us/MiB; slowest sample {prof.slowest_sample}"
        failure = f"slow rule: {prof.reason}" if prof.slow else None
        suite.case(prof.rule, "yaraci.perf", failure, info, info, seconds=prof.net_us / 1e6)
    return suite


def build_junit(result: CheckResult) -> ET.Element:
    root = ET.Element("testsuites", name=f"yaraci {Path(result.pack.root).name}")
    suites = [_lint_suite(root, result)]
    if result.tp is not None:
        suites.append(_tp_suite(root, result))
    if result.fp is not None:
        suites.append(_fp_suite(root, result))
    if result.profile is not None:
        suites.append(_perf_suite(root, result))
    for s in suites:
        s.close()
    root.set("tests", str(sum(s.tests for s in suites)))
    root.set("failures", str(sum(s.failures for s in suites)))
    root.set("time", f"{sum(s.time for s in suites):.6f}")
    return root


def write_junit(result: CheckResult) -> str:
    root = build_junit(result)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
