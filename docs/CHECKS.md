# Check catalogue

Generated from the registry by `scripts/gen_checks_doc.py`; `make check` fails if it is stale.
Suppress a check for one rule with `// yaraci:ignore YC301` (on the line before or inside the
rule) or `meta: yaraci_ignore = "YC301"`; for a whole file with `// yaraci:ignore-file YC301`;
for the pack with `[lint] disable = ["YC301"]`. Change a severity with
`[lint] severity = { YC301 = "error" }`. `yaraci explain YC301` prints one entry.

## Static and engine checks

| Code | Name | Category | Default | What it means |
|---|---|---|---|---|
| YC001 | `parse-error` | syntax | error | The yaraci front-end could not parse the file, so static checks were skipped for it. |
| YC002 | `include-directive` | syntax | error | include directives are not supported inside a pack. |
| YC101 | `rule-name-format` | naming | warning | Rule name does not match the configured naming pattern. |
| YC102 | `rule-name-length` | naming | warning | Rule name is longer than the configured maximum. |
| YC103 | `duplicate-rule-name` | naming | error | Two rules in the pack share a name. |
| YC104 | `rule-name-prefix` | naming | warning | Rule name does not start with an approved category prefix. |
| YC105 | `tag-format` | naming | info | Tag is not lower_snake_case or is repeated. |
| YC201 | `missing-required-meta` | metadata | error | A metadata key required by the pack policy is missing. |
| YC202 | `missing-recommended-meta` | metadata | info | A recommended metadata key is missing. |
| YC203 | `invalid-date` | metadata | warning | A date meta value is not an ISO-8601 calendar date or lies in the future. |
| YC204 | `invalid-hash` | metadata | error | A hash meta value is not a hex digest of the expected length. |
| YC205 | `invalid-reference` | metadata | warning | A reference meta value is not an http(s) URL. |
| YC206 | `duplicate-meta-key` | metadata | info | A single-valued metadata key appears more than once. |
| YC207 | `weak-description` | metadata | warning | The description is too short or merely repeats the rule name. |
| YC208 | `meta-type` | metadata | warning | A typed metadata value has the wrong type or an out-of-vocabulary value. |
| YC301 | `weak-atom` | strings | warning | The string's best atom is short or made of common bytes, so it pre-filters poorly. |
| YC302 | `regex-unbounded-repetition` | strings | warning | A regular expression uses an unbounded wildcard repetition (.*, .+, [^x]*, {n,}). |
| YC303 | `duplicate-string` | strings | warning | Two strings in the same rule have identical value and modifiers. |
| YC304 | `useless-nocase` | strings | info | nocase is applied to a string that contains no letters. |
| YC305 | `redundant-ascii` | strings | info | ascii is specified without wide; ascii is already the default. |
| YC306 | `hex-unbounded-jump` | strings | warning | A hex string contains an unbounded jump ([-] or [n-]). |
| YC307 | `too-many-strings` | strings | info | The rule defines more strings than the configured maximum. |
| YC308 | `short-variant-string` | strings | warning | xor/base64 is applied to a string shorter than 8 bytes. |
| YC309 | `low-entropy-string` | strings | warning | The string is a single repeated byte. |
| YC401 | `unconstrained-condition` | condition | error | The condition never inspects file content, so the rule matches (nearly) every file. |
| YC402 | `impossible-quantifier` | condition | error | An 'N of (set)' requires more members than the set contains (or the set is empty). |
| YC403 | `contradictory-filesize` | condition | error | The filesize constraints in the top-level conjunction cannot all hold. |
| YC404 | `module-without-magic` | condition | info | A file-format module is used without a cheap magic-bytes check. |
| YC405 | `whole-file-function` | condition | warning | A hash/math function runs over the whole file without a filesize upper bound. |
| YC406 | `expensive-loop` | condition | warning | A for-loop iterates over a range bounded by filesize or larger than 10,000. |
| YC407 | `redundant-range` | condition | info | 'in (0..filesize)' restricts nothing. |
| YC408 | `cheap-checks-last` | condition | info | A cheap filesize/magic check comes after an expensive loop or whole-file function. |
| YC409 | `magic-via-string` | condition | info | A short string is matched 'at 0' to test a file magic. |
| YC501 | `compile-error` | engine | error | The YARA engine rejected the rule set. |
| YC502 | `compile-warning` | engine | warning | The YARA engine emitted a warning (slow pattern, invariant expression, ...). |

## Scan-stage results (reported in SARIF/JUnit alongside lint findings)

| Code | Name | Default | What it means |
|---|---|---|---|
| YC601 | `fixture-failed` | error | A fixture expectation did not hold. |
| YC602 | `untested-rule` | error | A public rule has no match fixture. |
| YC603 | `orphan-fixtures` | warning | A fixture directory names no rule. |
| YC701 | `goodware-match` | error | The rule matched a goodware sample. |
| YC702 | `expired-allowlist` | warning | An FP allowlist entry has expired. |
| YC801 | `slow-rule` | error | The rule is a scan-time outlier. |
| YC901 | `low-quality-grade` | error | The rule's quality grade is below the minimum. |

## Rationale

### YC001 parse-error

The engine compile result (YC501) is authoritative for validity; a YC001 without a YC501 indicates syntax the yaraci parser does not support yet.

### YC002 include-directive

Packs are discovered from directories; includes would compile files twice and make per-rule isolation ambiguous.

### YC101 rule-name-format

Consistent names (Category_Family_Detail) make alerts self-describing and let triage route detections by prefix without opening the rule.

### YC102 rule-name-length

Very long names are truncated in SIEM columns and alert titles.

### YC103 duplicate-rule-name

All files compile into one namespace; duplicates fail compilation or shadow each other.

### YC104 rule-name-prefix

A controlled prefix vocabulary (MAL, SUSP, HKTL, ...) encodes alert intent and severity.

### YC105 tag-format

Tags are matched literally by downstream filters; inconsistent case splits one tag into many.

### YC201 missing-required-meta

Detections without author/description/date cannot be triaged, owned or aged out.

### YC202 missing-recommended-meta

References and sample hashes let reviewers verify the detection logic.

### YC203 invalid-date

Rule age drives review and retirement; unparseable dates break that automation.

### YC204 invalid-hash

Sample hashes are pivots into threat-intel platforms; a malformed hash silently breaks them.

### YC205 invalid-reference

References are followed by analysts; free text belongs in description.

### YC206 duplicate-meta-key

Tools that read meta into a dict keep only one value, so the duplicate is silently lost.

### YC207 weak-description

The description is what an analyst reads in the alert; it must say what was detected.

### YC208 meta-type

score/version are compared numerically and severity is mapped to alert priority downstream.

### YC301 weak-atom

Engines search for <=4-byte atoms and verify full patterns only on atom hits. A weak atom (e.g. 'MZ', 00 00 00 00, a regex with no literal run) causes verification on most offsets of every file and slows the whole rule set, not just this rule.

### YC302 regex-unbounded-repetition

Unbounded repetition lets one atom hit trigger verification across the rest of the file (quadratic in the worst case). Use a bounded quantifier such as .{0,64}.

### YC303 duplicate-string

Duplicates double the atoms and verification work and usually indicate a copy-paste error.

### YC304 useless-nocase

The modifier has no effect and suggests the author misunderstood the pattern.

### YC305 redundant-ascii

Redundant modifiers add noise to reviews and diffs.

### YC306 hex-unbounded-jump

Unbounded jumps make verification scan to the end of the file from every atom hit.

### YC307 too-many-strings

Very large string lists are hard to review and often hide dead or overlapping patterns.

### YC308 short-variant-string

Each modifier multiplies the atom set (xor: up to 256 variants); short inputs give near-random atoms that hit everywhere.

### YC309 low-entropy-string

Runs such as 'AAAAAAAA' or 00 00 00 00 occur in padding and compressed data of benign files.

### YC401 unconstrained-condition

A rule such as 'condition: true' or 'condition: filesize < 1MB' alerts on all goodware. Only global rules (which act as filters) may be content-free.

### YC402 impossible-quantifier

The expression is always false, so the rule (or that branch) silently never fires.

### YC403 contradictory-filesize

Interval analysis proves the condition is unsatisfiable, e.g. 'filesize > 100KB and filesize < 50KB'.

### YC404 module-without-magic

Guarding with uint16(0) == 0x5A4D (or similar) documents intent and short-circuits module evaluation on files of the wrong format.

### YC405 whole-file-function

math.entropy(0, filesize) and hash.*(0, filesize) are O(filesize) per scanned file; on large goodware they dominate scan time. Bound filesize first.

### YC406 expensive-loop

Per-byte loops execute the body once per byte of every scanned file.

### YC407 redundant-range

The whole file is the default search range; the clause only adds evaluation cost.

### YC408 cheap-checks-last

'and' short-circuits left to right; putting cheap guards first skips the expensive term for most files.

### YC409 magic-via-string

uint16(0) == 0x5A4D is evaluated without atoms or verification; '$mz at 0' needs both.

### YC501 compile-error

Nothing else can be trusted until the pack compiles.

### YC502 compile-warning

Engine warnings come from the compiler's own analysis and usually indicate real cost or logic issues.
