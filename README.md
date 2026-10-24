# yaraci

**A CI harness for YARA rule quality.** yaraci lints rules, proves each rule fires
on its own fixtures, scans goodware for false positives, profiles every rule's
scan cost, diffs two versions of a rule set by *what they match*, and turns all
of it into one exit code plus JUnit and SARIF reports.

```
$ yaraci check examples/pack-v2
...
GATE     FAIL (exit 31)
  - 4 lint finding(s) at or above 'error'
  - 2 fixture expectation(s) failed
  - 2 rule(s) without a match fixture
  - 3 goodware match(es) (max 0)
  - slow rule(s): SUSP_Generic_LongBase64Blob, test_rule
  - 3 rule(s) graded below C
```

## Why

Detection rules ship like code but are rarely tested like code. The failure modes
are quiet: a rule "simplified" in review starts alerting on a crypto library's
README; a string added under `all of them` means the rule never fires again; a
regex with no literal anchor makes the *whole* rule set scan about 100x slower
(v2 in the benchmark below adds one such regex). None of these are compile errors, so a
syntax-only check passes and the regression ships.

yaraci treats a rule pack the way a test runner treats a codebase:

| Question | Stage | Evidence |
|---|---|---|
| Is it well-formed and triageable? | `lint` | 35 check codes: naming, metadata, string atoms, condition anti-patterns, engine diagnostics |
| Does it fire? | `test` | every public rule ships `fixtures/<Rule>/match/` (and optional `nomatch/` near-misses) |
| Does it stay quiet on benign software? | `fp` | bundled goodware, pinned SHA-256-verified PyPI wheels, opt-in system binaries |
| Is it cheap? | `profile` | per-rule scan time over a corpus, robust (median/MAD) slow-rule detection |
| What did this change do? | `diff` | structural diff + new false positives / lost true positives between two pack versions |
| Does it behave the same on both engines? | `parity` | libyara vs YARA-X match sets |

**Who it is for:** detection engineers and SOC teams who keep YARA rules in git
and want pull requests gated on behaviour, not just syntax.

## Architecture

```mermaid
flowchart LR
    R[rules/*.yar] --> P[parser + RulePack<br/>topological file order]
    P --> L[lint<br/>35 checks]
    P --> E[engine<br/>YARA-X / libyara]
    F[fixtures/] --> T[TP tests]
    G[goodware<br/>bundled, fetched, system] --> FP[FP scan]
    E --> T & FP & PR[profiler]
    L & T & FP & PR --> Q[scorecards] --> GATE[gate<br/>exit bitmask]
    GATE --> OUT[text / Markdown / JSON<br/>JUnit / SARIF]
    P --> D[diff old vs new] --> OUT
```

Details, algorithms and complexity: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
The scoring model: [docs/QUALITY_MODEL.md](docs/QUALITY_MODEL.md).
Every check: [docs/CHECKS.md](docs/CHECKS.md). Threats: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
make check          # format-check, ruff, mypy --strict, 255 tests with coverage gate
make demo           # offline end-to-end run on the example packs (writes out/)
make goodware       # optional: fetch 7 pinned PyPI wheels as extra goodware (network)

uv run yaraci check examples/pack-v1 --junit out/junit.xml --sarif out/results.sarif
uv run yaraci diff examples/pack-v1 examples/pack-v2 --output out/diff.md
uv run yaraci explain YC403
```

### Pack layout

```
my-pack/
  yaraci.toml                 # policy (all keys optional)
  rules/*.yar                 # compiled together, ordered by rule dependencies
  fixtures/<RuleName>/match/  # every file MUST match RuleName
  fixtures/<RuleName>/nomatch/# no file may match RuleName
  fp-allowlist.toml           # accepted FPs: rule + sha256 + reason + expiry
```

```toml
[pack]
engine = "yara-x"            # or "libyara"
[lint]
name_prefixes = ["MAL", "SUSP", "PUA", "HKTL", "INFO"]
required_meta = ["author", "description", "date"]
[goodware]
dirs = ["../goodware"]
[gate]
lint_fail_on = "error"
max_fp = 0
fail_on_slow = true
min_grade = "C"
```

Suppress a finding in source with `// yaraci:ignore YC301` or `meta: yaraci_ignore = "YC301"`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | every gate passed |
| 1 / 2 / 4 / 8 / 16 | lint / true-positive / false-positive / performance / quality gate failed (OR-ed together) |
| 32 | the rule set does not compile (scan stages skipped) |
| 64 / 70 | usage or configuration error / internal error (not bitmasks) |

`yaraci diff` uses 4 for new false positives and 2 for lost true positives.

### In a rules repository's CI

```yaml
- run: uv run yaraci check rules-pack --junit out/junit.xml --sarif out/results.sarif --markdown out/summary.md
- run: cat out/summary.md >> "$GITHUB_STEP_SUMMARY"
  if: always()
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: out/results.sarif, category: yaraci }
- run: uv run yaraci diff base-pack rules-pack --output out/diff.md   # on pull requests
```

This repository's own workflow (`.github/workflows/ci.yml`) runs `make check`,
`make demo`, and a dogfooding job that gates `examples/pack-v1` and uploads SARIF.
It has not run yet: the repository has not been pushed.

## Demo

`make demo` checks a clean pack (v1), a deliberately regressed revision (v2),
diffs them and runs engine parity. Excerpt from a real run in a fresh clone
(no fetched goodware; `...` marks elided lines, run `make demo` for the full output):

```
$ yaraci check examples/pack-v1 --repeat 3 --junit out/v1/junit.xml --sarif out/v1/results.sarif ...
yaraci check lab-pack: 10 rule(s) in 4 file(s), engine yara-x 1.22.0
LINT     0 error, 0 warning, 0 info
COMPILE  ok
TP       17 fixture(s): 17 passed, 0 failed; untested: none
FP       19 goodware sample(s) (1.45 MiB; bundled 19; 0 archive member(s)): 0 match(es), 0 allowlisted
PROFILE  isolated, 36 sample(s) / 1.45 MiB x3 on yara-x 1.22.0
  full pack: 716 us/MiB above baseline (1,089 MiB/s overall); median rule: 2.2 us/MiB
  ...
GATE     PASS (exit 0)

$ yaraci check examples/pack-v2 ...
LINT     4 error, 6 warning, 4 info
  warning YC301 rules/generic.yar:9 [SUSP_Generic_LongBase64Blob] $b64 has weak atom [none] (quality 0 < 45)
  warning YC502 rules/generic.yar:9 [SUSP_Generic_LongBase64Blob] [slow_pattern] slow pattern: this pattern may slow down the scan
  error   YC201 rules/generic.yar:14 [test_rule] missing required meta key 'author'
  error   YC403 rules/generic.yar:18 [test_rule] filesize must be >= 2097153 and <= 1048575: unsatisfiable
  warning YC301 rules/scripts.yar:66 [SUSP_SH_PipeToShell] $pipe has weak atom [73 68] (quality 36 < 45)
  ...
TP       16 fixture(s): 14 passed, 2 failed; untested: SUSP_Generic_LongBase64Blob, test_rule
  FAIL MAL_RansomNote_Generic/nomatch/wallet-lib-README.txt: expected to not match
  FAIL PUA_PE_Packer_UPX/match/packed.exe.bin: expected to match
FP       19 goodware sample(s) (1.45 MiB; bundled 19; 0 archive member(s)): 3 match(es), 0 allowlisted
  FP   MAL_RansomNote_Generic <- goodware/docs/crypto-wallet-guide.md [bundled] ($cue1, $cue2, $cue3, $cue4)
  FP   SUSP_SH_PipeToShell <- goodware/scripts/install-tool.sh [bundled] ($pipe)
  FP   SUSP_Generic_LongBase64Blob <- goodware/src/app_icon.py [bundled] ($b64)
PROFILE  isolated, 35 sample(s) / 1.45 MiB x3 on yara-x 1.22.0
  full pack: 27,508 us/MiB above baseline (36 MiB/s overall); median rule: 4.6 us/MiB
  rule                                       us/MiB  x median  slowest sample
  SUSP_Generic_LongBase64Blob              27,102.7    5830.9  goodware/src/app_icon.py  SLOW
  test_rule                                   544.1     117.1  goodware/blobs/log-text.txt  SLOW
  ...
SCORECARD
  F  15  test_rule  -40 lint ({'warning': 3, 'error': 4, 'info': 3}); -25 no match fixture; -20 slow: 117.1x pack median (robust z=91.3)
  F  24  SUSP_Generic_LongBase64Blob  -11 lint ({'info': 1, 'warning': 2}); -25 no match fixture; -20 1 goodware match(es); -20 slow: 5830.9x pack median (robust z=4584.6)
  D  40  MAL_RansomNote_Generic  -40 1 failing fixture(s); -20 1 goodware match(es)
  C  60  PUA_PE_Packer_UPX  -40 1 failing fixture(s)
  B  75  SUSP_SH_PipeToShell  -5 lint ({'warning': 1}); -20 1 goodware match(es)
  ...
GATE     FAIL (exit 31)

$ yaraci diff examples/pack-v1 examples/pack-v2 --output out/diff.md
yaraci diff: 3 added, 1 removed, 1 renamed, 2 modified, 6 unchanged
  modified  PUA_PE_Packer_UPX
      string added $ver = /UPX [0-9]\.[0-9]{2}/
      string removed $s1 = "UPX1"
  renamed   MAL_ELF_CoinMiner_Stratum -> MAL_ELF_Miner_Stratum
  modified  MAL_RansomNote_Generic
      condition: filesize < 65536 and any of ($claim*) and 2 of ($cue*) -> filesize < 65536 and 3 of them
  ...
impact (matches old -> new; only rules whose matches changed):
  PUA_PE_Packer_UPX: 1 -> 0
      LOST TP: fixtures/PUA_PE_Packer_UPX/match/packed.exe.bin
  MAL_RansomNote_Generic: 1 -> 3
      NEW FP: goodware/docs/crypto-wallet-guide.md
      NEW FP: fixtures/MAL_RansomNote_Generic/nomatch/wallet-lib-README.txt
  ...
verdict: 4 new FP, 1 lost TP, 1 fixture(s) uncovered by removed rules
[exit 6]

$ yaraci parity examples/pack-v1
yaraci parity: libyara vs yara-x over 36 sample(s)
verdict: consistent

artifacts written to out/:
  v1: junit.xml 44 tests / 0 failures; results.sarif 0 results; report.json; summary.md
  v2: junit.xml 51 tests / 10 failures; results.sarif 26 results; report.json; summary.md
```

The example rules detect *synthetic, benign* lab artifacts (header stubs and
harmless scripts generated by `scripts/make_examples.py`); see [DATA.md](DATA.md).

## Benchmarks and evaluation

All numbers below come from committed commands; rerun them to reproduce.

**Tests and coverage** — `make test` (`uv run pytest --cov=yaraci --cov-fail-under=80`):
255 tests (unit, Hypothesis property tests, golden example-pack tests, CLI
end-to-end), **97.15 % coverage (lines + branches)** of `src/yaraci`.

**Profiling benchmark** — `make bench` writes [bench/RESULTS.md](bench/RESULTS.md)
and `bench/results.json` from a seeded, in-memory 9 MiB synthetic corpus. Highlights
from the committed run (Apple-silicon laptop shared with other jobs):

| Measurement | YARA-X 1.22.0 | libyara 4.5.4 |
|---|---:|---:|
| v1 pack throughput | 1,401.7 MiB/s | 294.0 MiB/s |
| v2 pack throughput (one regex with no literal atom added) | 13.0 MiB/s | 9.4 MiB/s |
| `SUSP_Generic_LongBase64Blob` cost (isolated) | 77,089 us/MiB | 104,216 us/MiB |
| PowerShell rule before / after anchoring its regexes | 709.2 / 144.4 us/MiB | 1,431.2 / 1,459.0 us/MiB |
| v1 rules flagged slow in any of 3 runs | none | 2 (`MAL_Doc_OLE_AutoOpenShell`, `MAL_RansomNote_Generic`) |

The PowerShell row is a real finding from building this project: the profiler
flagged the original v1 rule, anchoring its regexes on a leading `\s` made it
~4.9x cheaper on YARA-X, and the same edit made no difference on libyara. The
last row is why slow-rule verdicts are per engine (see Limitations).

**False positives on real goodware** — after `make goodware`, on this machine:

```
$ uv run yaraci fp examples/pack-v1 --system
FP       310 goodware sample(s) (58.48 MiB; bundled 19, fetched 135, system 156; 134 archive member(s)): 0 match(es), 0 allowlisted
$ uv run yaraci fp examples/pack-v2 --system
FP       310 goodware sample(s) (58.48 MiB; bundled 19, fetched 135, system 156; 134 archive member(s)): 6 match(es), 0 allowlisted
  FP   SUSP_Generic_LongBase64Blob <- /bin/ksh [system] ($b64)
  FP   SUSP_Generic_LongBase64Blob <- /usr/bin/afscexpand [system] ($b64)
  FP   SUSP_Generic_LongBase64Blob <- /usr/bin/assetutil [system] ($b64)
  ... (plus the 3 bundled-goodware FPs shown in the demo)
```

The system-binary set depends on the machine (macOS here), so these counts are
not portable; the bundled and fetched sources are.

**Engine parity** — `uv run yaraci parity examples/pack-v2 --corpus examples/goodware --corpus .cache/goodware --corpus examples/pack-v2/fixtures`:
consistent over 170 samples.

## Design decisions

The full list with trade-offs is in [DECISIONS.md](DECISIONS.md). The load-bearing ones:

* **Own parser, engine as authority.** Neither binding exposes rule structure, so
  yaraci parses YARA itself for static analysis, but validity is always decided
  by the real engine (YC501), and unparseable files are still compiled and scanned.
* **Fixtures by convention, scanned with the whole pack.** Tests exercise rules as
  deployed (helper and global rules included).
* **Isolation profiling with a strong-atom baseline, minimum of k repeats, median/MAD
  outliers.** Cheap, explainable, robust to one pathological rule; leave-one-out is
  available for interaction effects.
* **Behaviour outranks style in scoring.** One false positive costs more than a
  rule can lose to lint.
* **Bitmask exit codes.** One CI run reports every failing gate.

## Limitations

* **Synthetic evaluation data.** Example rules, fixtures, bundled goodware and the
  benchmark corpus are all generated for this project. They demonstrate the
  mechanics; they say nothing about detection rates on real malware, and the
  bundled goodware (19 files) is far too small to establish real FP rates. Real
  FP evidence needs `make goodware`, `--system` and, in practice, a much larger
  curated goodware set than the 7 pinned wheels.
* **Timing is noisy and engine specific.** Profiles were taken on a laptop shared
  with other builds. Min-of-k and a noise floor reduce flakiness but do not remove
  it; small costs (< 200 us/MiB) are not meaningful. libyara and YARA-X rank rules
  differently (see the benchmark), and only the configured engine gates.
* **Isolation hides interactions.** The v1 pack costs 716 us/MiB above baseline
  as a whole while no single isolated rule costs more than ~5 us/MiB: atoms and
  automaton effects only appear together. `--method leave-one-out` measures
  interactions but is noisy when one rule dominates the pack.
* **Static atom quality is an estimate.** It is modelled on libyara's heuristic,
  does not replicate either engine's atom selection, and the regex literal
  extractor ignores alternation inside groups (weakest-branch analysis is only
  done at the top level).
* **Parser coverage.** The front-end handles the YARA 4.x / YARA-X surface used
  in typical packs (including `with`, `for..of`, `for..in`, rule sets, string
  modifiers with arguments) but not `include`, external variables declared via
  the CLI, or YARA-X-only syntax added after 1.22.
* **Scoring weights are heuristics** chosen by hand, not fitted to outcome data.
* **Fixture convention is per rule.** A sample that should match several rules
  must be duplicated into each rule's directory.
* **CI not yet executed** (repository not pushed); `make check` passes locally from
  a fresh clone.

## Roadmap

* Grouped-alternation atom analysis and a calibration study of the atom heuristic
  against YARA-X's own atom selection.
* Fixture manifests (one sample, many expected rules) alongside the directory convention.
* Per-rule profiling against large real goodware sets with sampling, and a
  persistent baseline so the profiler can gate on *regressions* in cost.
* A YARA-X module-output-aware lint family (e.g. PE fields used on non-PE fixtures).
* Rule-coverage reporting per MITRE ATT&CK technique from `reference` metadata.

## License

MIT, see [LICENSE](LICENSE).
