# The rule-quality model

A YARA rule is a small program with three jobs: fire on the thing it describes,
stay silent on everything else, and do both cheaply enough to run on every file.
yaraci measures each job separately and then folds the evidence into one
scorecard per rule, so a reviewer can see *why* a rule is weak, not just that it is.

## Dimensions and evidence

| Dimension | Question | Evidence (stage) | Failure signal |
|---|---|---|---|
| **Validity** | Does the pack compile in the engine we deploy? | engine compile (`YC501`, `YC502`) | compile error stops all scan stages (gate bit 32) |
| **Hygiene** | Can an analyst triage an alert from this rule, and will it age well? | static lint (`YC1xx` naming, `YC2xx` metadata, `YC3xx` strings, `YC4xx` condition) | findings at or above `[gate].lint_fail_on` (bit 1) |
| **Coverage** | Is there proof the rule fires at all? | `fixtures/<Rule>/match/` exists | untested rule (bit 2 when `fail_on_untested`) |
| **Accuracy** | Does it fire on its positives and stay silent on its curated near-misses? | TP stage over `match/` and `nomatch/` | failing fixture (bit 2) |
| **Precision** | Does it stay silent on benign software? | FP stage over bundled, fetched and (opt-in) system goodware | goodware match not in the allowlist (bit 4) |
| **Cost** | Does it slow the pack down? | per-rule profiler | slow outlier or over budget (bit 8) |

Static checks are *predictions* (a weak atom will probably be slow, an
unsatisfiable filesize interval certainly never matches); scan stages are
*measurements*. Where both exist, the measurement wins: YC301 is a warning, a
slow verdict from the profiler is a gate.

## Scorecard

Each rule starts at 100 and loses points:

| Evidence | Deduction | Cap |
|---|---|---|
| lint error / warning / info attributed to the rule | 15 / 5 / 1 each | 40 total |
| no `match` fixture (public rules only) | 25 | |
| one or more failing fixtures (public rules only) | 40 | |
| goodware matches (not allowlisted) | 20 per sample | 60 |
| profiler verdict "slow" | 20 | |

Grades: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, **F** below 40.
`[gate].min_grade` turns the grade into a gate (bit 16).

The weights encode one policy decision: *behavioural evidence outranks style*.
A single false positive (−20) or a failing fixture (−40) costs more than a rule
can lose to lint (capped at −40 only when it is riddled with errors), so a
well-formatted rule that alerts on `certifi` can never outrank a scruffy rule
that does its job. The weights are a documented heuristic, not a calibrated
model; they live in `src/yaraci/quality.py` as named constants.

Private helper rules are scored only on hygiene and cost: they never alert on
their own, so coverage and precision are measured through the rules that use them.

## Worked example (from `make demo`)

```
F  15  test_rule  -40 lint (4 errors, 3 warnings, 3 info); -25 no match fixture; -20 slow
F  24  SUSP_Generic_LongBase64Blob  -11 lint; -25 no match fixture; -20 1 goodware match; -20 slow
D  40  MAL_RansomNote_Generic  -40 1 failing fixture; -20 1 goodware match
C  60  PUA_PE_Packer_UPX  -40 1 failing fixture
B  75  SUSP_SH_PipeToShell  -5 lint; -20 1 goodware match
```

* `MAL_RansomNote_Generic` was "simplified" from `any of ($claim*) and 2 of ($cue*)`
  to `3 of them`; it now fires on a wallet library README (a curated `nomatch`
  fixture) and on a crypto guide in the goodware corpus. Lint cannot see this;
  the TP and FP stages can.
* `PUA_PE_Packer_UPX` gained a version-banner string under `all of them`; the
  packed-PE fixture has no banner, so the rule silently lost its true positive.
* `SUSP_SH_PipeToShell` detects `curl ... | sh`, which is also the standard install
  one-liner of many developer tools; it fires on a benign installer.

## Regression model for rule changes

`yaraci diff OLD NEW` applies the same evidence to a *change*: both versions scan
the union of both packs' fixtures plus the goodware corpus, and every per-rule
change in match sets is classified as a new FP (goodware or `nomatch` fixture),
a fixed FP, a lost TP (`match` fixture of a rule that still exists), a gained TP,
or coverage removed together with a deleted rule. New FPs and lost TPs are the
diff gate (exit bits 4 and 2).
