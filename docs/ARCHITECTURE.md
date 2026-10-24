# Architecture

yaraci is a pipeline over one data structure, the **RulePack**: parsed rule files
in dependency order, plus the raw source units the engine compiles. Every stage
reads the pack, produces a typed report, and the gate turns reports into an exit
code. Nothing in a stage mutates the pack.

```mermaid
flowchart TD
    subgraph frontend[Front-end]
        LEX[syntax/lexer.py] --> PAR[syntax/parser.py] --> AST[syntax/ast.py]
        HEX[syntax/hexstr.py] -.-> AST
        AST --> UNP[syntax/unparse.py]
        AST --> WALK[syntax/walk.py]
    end
    CFG[config.py yaraci.toml] --> PACK
    AST --> PACK[pack.py RulePack: discovery, topo order, closures]
    PACK --> LINT[lint/ 35 check codes + atoms.py]
    PACK --> ENG[engine/ yara-x | libyara]
    ENG --> LINT
    CORP[corpus.py + goodware.py] --> FP
    PACK --> TP[testing.py fixtures]
    ENG --> TP
    ENG --> FP[fp.py goodware scan + allowlist]
    ENG --> PROF[profiling.py isolated / leave-one-out]
    LINT --> Q[quality.py scorecards]
    TP --> Q
    FP --> Q
    PROF --> Q
    Q --> GATE[gate.py bitmask]
    PACK --> DIFF[diff.py structural + impact]
    ENG --> DIFF
    ENG --> PAR2[parity.py libyara vs yara-x]
    GATE --> REP[report/ text, Markdown, JSON, JUnit, SARIF]
    DIFF --> REP
    CLI[cli.py] --> PIPE[pipeline.py run_check]
    PIPE -.-> GATE
    CLI --> DIFF
    CLI --> PAR2
```

## Module map

| Module | Responsibility |
|---|---|
| `syntax/lexer.py` | Context-sensitive tokenizer (hex strings after `=`, regexes after `=`/`matches`), comments kept for suppressions |
| `syntax/parser.py` | Recursive descent: imports, includes, rule modifiers, tags, meta, strings + modifiers, full condition grammar |
| `syntax/ast.py` | Frozen dataclasses for every node, with source positions |
| `syntax/hexstr.py` | Hex-string sub-grammar: bytes with nibble masks, `~` negation, jumps, alternatives |
| `syntax/unparse.py` | Canonical printer used for diffs and messages |
| `syntax/walk.py` | Iterative traversal, free identifiers, rule-set patterns, string-set expansion |
| `config.py` | Strict, typed `yaraci.toml` loader (unknown keys are errors) |
| `pack.py` | Discovery, topological file order, dependency closures, per-rule isolation, leave-one-out sources |
| `engine/` | `Backend` protocol; YARA-X and libyara adapters with diagnostics mapped back to files |
| `lint/` | Check registry: 30 per-rule checks in four families plus 5 pack/engine codes, atom-quality estimator, policy (disable, severity, suppressions) |
| `corpus.py` | Bounded, symlink-safe, archive-aware, SHA-256-deduplicated corpus builder |
| `goodware.py` | Pinned manifest, verified fetching with retries, corpus assembly, FP allowlist |
| `testing.py` / `fp.py` | TP fixture convention and goodware FP scanning |
| `profiling.py` | Per-rule timing, robust slow-rule classification |
| `quality.py` / `gate.py` | Scorecards and the exit-code bitmask |
| `diff.py` / `parity.py` | Version-to-version and engine-to-engine comparisons |
| `report/` | Renderers; `report/model.py` maps scan-stage results onto codes so SARIF/JUnit see one issue list |
| `pipeline.py` / `cli.py` | Orchestration and the command line |

## Key algorithms

### Parsing (`syntax/`)

The lexer resolves YARA's two context-sensitive tokens with one token of
look-behind: `{` after `=` opens a hex string; `/` after `=` or `matches` opens a
regular expression (YARA spells division `\`, so `/` is otherwise invalid). The
parser is precedence climbing over YARA's levels (`or` < `and` < `not` <
comparison < `|` < `^` < `&` < shifts < additive < multiplicative < unary <
postfix). Note that YARA, unlike C, binds bitwise operators tighter than
comparisons; the canonical printer adds clarifying parentheses there so that
`unparse(parse(unparse(e))) == unparse(e)` (property-tested with Hypothesis).
Complexity: `O(n)` in source length.

### Dependency order and isolation (`pack.py`)

Rules may reference rules declared earlier. Files are ordered with Kahn's
algorithm over the file-level reference graph, using a min-heap on path for a
deterministic order: `O((F + E) log F)`. For a single rule, the closure is a BFS
over direct references plus every `global` rule (globals gate all rules in a
namespace, so leaving them out would change behaviour): `O(R + E)`. The isolated
source is the file imports followed by the closure in pack order.

### Atom quality (`lint/atoms.py`)

Engines search for at most 4-byte *atoms* with Aho-Corasick and verify the full
pattern only where an atom hits. yaraci extracts fixed byte runs (text bytes,
fixed hex bytes, regex literal runs — quantifier-aware: a literal followed by `?`
or `*` is optional and cannot be part of an atom), widens them for `wide`, and
scores every 4-byte window. For alternatives, every branch needs its own atom,
so the weakest branch bounds the string. `O(pattern length)`.

### Condition analyses (`lint/checks_condition.py`)

* *Constraint detection* walks the AST looking for any node that reads content
  (string references, calls, module fields, rule references).
* *Set cardinality* expands each `N of (set)` against the rule's string
  identifiers (or earlier rule names) and compares with the quantifier
  (`all` = size, `any` = 1, percentages rounded up).
* *Filesize interval analysis* folds every `filesize <op> constant` term of the
  top-level `and` chain into `[lo, hi]`; `lo > hi` proves the condition
  unsatisfiable. Property-tested against brute force over 0..1001.

### Profiling (`profiling.py`)

```
for rule in pack:                         # R rules
    compiled = compile(closure(rule))
    for sample in corpus:                 # F samples
        t = min over k repeats of scan(sample)        # one-sided noise -> minimum
        net += max(0, t - baseline[sample])
    us_per_mib = net / corpus_MiB
classify: median/MAD over rules; slow if over budget, or ratio >= 4 and
          robust z >= 3.5 and above the noise floor
```

`O(R * F * k)` scans; memory is the corpus (bounded by `max_corpus_bytes`).
The baseline is a rule with one never-matching, strong-atom pattern, so the cost
of the engine's pattern-scan pass is not charged to every rule. Leave-one-out
mode instead times `full pack - rule`, capturing interaction effects at the cost
of compiling the pack once per rule.

### Diffing (`diff.py`)

Each rule reduces to a *logic key* (flags, sorted tags, canonical strings by
identifier, canonical condition) and a *meta key*; comparing keys yields
modified / metadata / cosmetic / unchanged. Renames pair removed and added rules
with equal logic keys (1:1, name order). Impact scanning compiles both versions
once and scans the union corpus once per version (`O(samples)` scans), then
classifies every per-rule flip as new/fixed FP (goodware or `nomatch` fixture)
or lost/gained TP (`match` fixture), following renames.

## Error handling and logging

All expected failures derive from `YaraciError` (`ConfigError`, `PackError`,
`SyntaxParseError`, `EngineError`, `CorpusError`) and map to exit 64; anything
else maps to 70 with the traceback available under `-v`. Engine compile errors
are not exceptions at the CLI level: they become YC501 findings and gate bit 32,
so a broken pack still produces SARIF/JUnit output. Modules log through
`logging.getLogger(__name__)`; `-v` enables debug output on stderr, keeping
stdout for reports.

## Extending

* **New lint check**: write a generator `(ctx, pack_rule) -> Iterator[Hit]` in a
  `lint/checks_*.py` module and decorate it with `@check(code, name, category,
  severity, summary=..., rationale=...)`; it is registered, documented by
  `scripts/gen_checks_doc.py`, explainable with `yaraci explain`, and emitted in
  SARIF automatically.
* **New engine**: implement the `Backend` protocol (`name`, `version`,
  `compile(units) -> CompileResult` whose `rules.scan(bytes) -> ScanOutcome`).
