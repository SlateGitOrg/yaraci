# Threat model

yaraci is a **defensive** quality tool for detection engineers. It reads YARA rules
and scans benign corpora on the machine that runs it. It does not contact any host
except PyPI when `make goodware` / `yaraci fetch-goodware` is run explicitly, it
ships no malware, and nothing in it executes scanned content.

## Assets

* The CI runner and developer workstation (CPU, memory, disk).
* The integrity of the gate verdict (a regression must not pass silently).
* The goodware cache (must contain exactly the pinned packages).

## Trust boundaries and threats

| Input | Who controls it | Threat | Mitigation |
|---|---|---|---|
| Rule files in a pull request | any contributor | Pathological rule (regex with no atoms, per-byte loops) used to exhaust CI time | Engine scan timeout per sample (`[pack].scan_timeout_s`, default 10 s), profiler reports timeouts as slow; YC301/YC302/YC406 flag the patterns statically |
| Rule files | contributor | Rule that silently never matches or matches everything (logic error, unsatisfiable filesize, `N of` larger than its set) | YC401, YC402, YC403; TP fixtures fail; diff reports lost TPs |
| Rule files | contributor | Suppressing findings to sneak a weak rule through | Suppressions are explicit in source (`yaraci:ignore`) and visible in review; FP allowlist entries need a reason and expire |
| Fixtures and goodware directories | contributor | Symlink pointing outside the repo (e.g. to `~/.ssh`) to exfiltrate content into CI logs | Symlinks and non-regular files are never followed or read |
| Archives in the goodware corpus | upstream package authors / network attacker | Zip/tar bomb, member-size lies, path traversal | Exactly one level of in-memory expansion (members that are archives are scanned as opaque blobs, never expanded), per-member (8 MiB), per-archive (64 MiB) and corpus-wide (256 MiB) byte budgets enforced on bytes actually read, member-count cap; members are never written to disk, so names cannot traverse. Regression-tested with a nested zip-of-zips bomb |
| Downloaded goodware | network attacker / compromised mirror | Tampered package entering the corpus | HTTPS-only manifest (or `file://` for tests), SHA-256 pinned per file, write-to-`.part` then rename only on hash match, no hash-mismatch retry |
| Report consumers (SARIF/JUnit viewers) | contributor via sample names/messages | Markup injection into CI UIs | XML built with ElementTree (escaped), invalid XML characters replaced, JSON via `json.dumps` |
| `yaraci.toml` | maintainer | Typo silently disabling a gate (`max_fps = 0`) | Unknown keys and wrong types are rejected with an error (exit 64) |

## Out of scope

* Malicious YARA *engines* (yara-x / yara-python wheels are trusted dependencies,
  pinned in `uv.lock`).
* Evasion research: yaraci does not generate samples designed to bypass rules.
* Scanning live systems or third-party infrastructure: the system-binary source only
  reads local files matched by configured globs, opt-in.
