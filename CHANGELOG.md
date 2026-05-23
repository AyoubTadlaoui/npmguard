# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.6] - 2026-05-23

### Added
- `SecurityHolding` signal. When npm removes a package, almost always after malware, it republishes the name as an `X.Y.Z-security` placeholder. npmguard now flags any resolved version ending in `-security` as a block-tier signal, with no network lookup required.

### Changed
- OSV malware matching is now version-aware. A `MAL-*` advisory matched to the resolved version blocks it. For a prerelease resolved version (such as a `-security` takedown stub), where OSV's semver matching wrongly excludes the version from open-ended advisory ranges, npmguard also honors a package-level malware advisory. A normal version is never labelled malicious for an advisory that only affects other, since-removed versions, so a legitimate package that was compromised in a now-removed version is not flagged at its clean current version.

### Fixed
- Confirmed-malicious packages whose resolved version is an npm `-security` placeholder (for example `lodahs`) were scored warn instead of block. They now block, via both the security-holding signal and the OSV malware lookup.

## [0.1.5] - 2026-05-23

### Added
- `npmguard hook`: a deterministic Claude Code PreToolUse gate. Run `npmguard hook install` and Claude Code screens every `npm install` the agent runs before lifecycle scripts fire, denying confirmed-malicious or block-tier packages. The hook runs in Claude Code's harness, not the model, so the model cannot skip it. Claude Code only for now; Cursor and Codex stay on the advisory MCP path.

### Changed
- README rewritten in first person, leading with the AI-agent threat, with verified MCP setup for Claude Code, Cursor, and Codex.
- New hero demo: a real Claude Code session stopped from installing a malicious typosquat.

## [0.1.4] — 2026-05-21

### Added

- **`ReleaseAnomaly` signal — the first piece of the v0.2 release-anomaly
  engine.** Most maintainer-takeover incidents ship a release that is almost
  identical to the previous one but quietly adds an install hook or a new
  dependency. This signal diffs the resolved version against its immediate
  predecessor (chosen by publish time, preferring the prior *stable* release)
  and flags the takeover fingerprint:
  - a **newly-added** `preinstall`/`install`/`postinstall` script not present
    in the previous release (+70 — block-tier on its own; see Fixed below);
  - an obfuscated, high-entropy base64/hex payload embedded in an install-time
    script body (+30) — gated on length **and** Shannon entropy so ordinary
    commands like `node-gyp rebuild` don't trip it;
  - a new top-level dependency absent from the previous release (+25);
  - over-50% dependency-count growth, gated on a meaningful base count (+15).

  The previous version's `scripts`/`dependencies` already arrive in the
  packument fetched for the resolved version, so the signal adds **no** extra
  network round-trip. Adding the signal rotates the cache's signal-set hash, so
  pre-existing cached verdicts are recomputed automatically.

### Fixed

- **Shared HTTP client; 16 MiB response-body cap.** All registry and OSV
  fetches now share a single `Arc<Client>` built in the engine, rather than
  each signal allocating its own. A 16 MiB per-response size limit is enforced
  to prevent a malicious or oversized packument from exhausting heap memory.

- **GitHub JSON parse errors logged instead of silently zeroing repo-health.**
  A malformed or unexpected GitHub API response previously swallowed the error
  and returned empty signals, masking problems in CI and making the score
  silently optimistic for packages whose repo URL triggered a parse failure.

- **Lifecycle and release-anomaly signals no longer double-count a
  newly-added install script.** A takeover release that adds a fresh
  `preinstall`/`install`/`postinstall` was previously scored by both the
  `lifecycle` signal (+30) and the `release_anomaly` signal (+40), inflating
  the composite score by 30 points beyond what either signal warranted alone.
  The `lifecycle` signal is now suppressed when every present lifecycle script
  is newly added in this release and `release_anomaly` already covers the
  addition.

- **Newly-added install script re-weighted to block-tier (40 → 70) to
  preserve v0.1.3 detection.** Removing the double-count dropped the
  effective score for a takeover-with-added-script release from 70 (block) to
  40 (warn). The `release_anomaly` sub-signal for a newly-added install script
  is now weighted at 70, so it reaches the block threshold on its own and
  the de-dup carries no detection regression.

- **Panic (process abort) on a multibyte deprecation message.** The
  `Deprecated` signal truncated long messages with `&msg[..120]` — a byte slice
  that panics when byte 120 lands inside a multibyte UTF-8 character. The
  `deprecated` field is attacker-controlled registry JSON, so a crafted package
  could abort `npmguard check` (and, under the release build's `panic =
  "abort"`, the whole process). Truncation is now char-boundary safe.

- **MCP returned `internal_error` for an unknown package name.** A missing
  *version* of an existing package already mapped to JSON-RPC `-32602`
  (invalid params) in v0.1.3, but a missing *package* (registry `404`) still
  surfaced as `-32603` (internal error) — a client input problem reported as a
  server fault. Both now map to `invalid_params`.

- **OSV severity under-scored real CVEs.** `severity_rank` parsed the CVSS field
  as a leading number, but OSV stores it as a vector string
  (`CVSS:3.1/AV:N/...`), so genuine critical advisories whose only severity was a
  CVSS vector collapsed to the 5-point "unknown" floor. npmguard now computes the
  CVSS v3.x base score from the vector (no new dependency; dependency-free
  calculator validated against canonical spec vectors) and buckets on the real
  score, while still accepting a bare numeric score and the GHSA
  `database_specific.severity` fallback.

## [0.1.3] — 2026-05-20

### Fixed

- **MCP `install_package` recommendation contradicted its own signals.** An
  `ok` verdict that still carried sub-threshold signals (e.g. a deprecated
  package, a sole maintainer) reported "No significant risk signals detected"
  while simultaneously listing those signals. The `ok` recommendation is now
  signal-aware: with zero signals it reads "Safe to install. No risk signals
  detected."; with signals below the warning threshold it reports the count and
  states they are below the threshold.

- **Unknown or pinned-but-missing versions returned an opaque internal error.**
  Requesting a version absent from the registry packument (e.g. a
  since-unpublished release) surfaced as JSON-RPC `-32603` (internal error). It
  now returns `-32602` (invalid params) with a clear "package or version not
  found" message — a client input problem, reported as one.

### Documentation

- macOS may quarantine release archives downloaded through a browser; the
  install section now documents clearing it with
  `xattr -dr com.apple.quarantine`.

## [0.1.2] — 2026-05-18

### Fixed

- **`--no-color` was a silent no-op.** The flag set
  `owo_colors::set_override(false)`, but `set_override` only gates
  `if_supports_color`-style conditional calls — bare `.bold()` / `.red()` /
  `.green()` etc. always emit ANSI escape codes regardless. Output piped
  to a log file or processed by another tool ended up full of
  `^[[1m...^[[0m` sequences even with `--no-color`.

  Replaced the bare colorize calls with a small `color` module that gates
  all styling on a single decision made at startup. Three signals
  collapse it: the `--no-color` flag, the standard `NO_COLOR` env var
  (https://no-color.org), and whether stdout is a TTY. Pipes now produce
  clean text by default; the explicit flag and env var both work as
  documented.

## [0.1.1] — 2026-05-18

### Fixed

- **Verdict cache was write-only.** `VerdictCache::put` was being called but
  `VerdictCache::get` was never invoked from either the CLI or the MCP server,
  so every `npmguard check` re-hit the registry, OSV.dev, and the GitHub API
  even when the same verdict was sitting on disk. Wiring the read path makes
  the second call to the same package ~5× faster (1.9s → 0.36s on a cold
  registry-only fetch).

### Changed

- `RiskEngine::evaluate` is now a convenience wrapper around two new methods:
  `fetch_metadata(pkg) -> PackageMetadata` and
  `evaluate_from_metadata(pkg, meta) -> RiskVerdict`. The split lets callers
  consult a cache between the two steps without double-fetching the registry.
- `RiskVerdict` gained a `published_at: Option<DateTime<Utc>>` field,
  populated from the registry packument's `time` map. Cache TTLs use it to
  pick a shorter window (24h) for newly-published versions and a longer
  one (7d) for stable packages.
- `VerdictCache::get` simplified — no longer requires the caller to pass
  `published_at`; the cache reads it from the stored row when picking a
  TTL. The SQLite schema bumped to `PRAGMA user_version = 2`; pre-existing
  caches from v0.1.0 are dropped and recreated on first open (verdicts are
  regenerable, so a clean slate beats migration gymnastics for this cache).
- README headline tightened to *"a native pre-install risk gate for npm
  packages, with an MCP tool for AI coding agents"*. Added an explicit
  status note that v0.1 is a risk checker + verdict gate, **not** a real
  npm wrapper, installer, or sandbox (those land in v0.2).

### Added

- Two new TTL-policy tests in `npmguard-cache`:
  - `fresh_package_uses_short_ttl_and_expires_quickly`
  - `stable_package_uses_long_ttl_and_survives`

## [0.1.0] — 2026-05-18

First public release. A native pre-install risk gate for npm packages, with an
MCP tool for AI coding agents.

### Added

- **Risk engine** with 8 parallel signal fetchers: lifecycle scripts, package
  age, maintainer churn (dormant-package resurrection), sole maintainer,
  deprecated, typosquat (Damerau-Levenshtein), OSV.dev advisories with `MAL-*`
  malware-namespace escalation, GitHub repo health.
- **CLI** (`npmguard check|install`) with three verdicts (`ok` / `warn` /
  `block`), TTY-aware prompting, JSON output mode.
- **MCP server** (`rmcp`, stdio transport) exposing `install_package` so
  Claude Code / Cursor / Codex can route through the same gate.
- **SQLite verdict cache** at `~/.cache/npmguard/verdicts.db` keyed by signal
  set hash — present in v0.1.0 but the read path is wired in v0.1.1.
- Cross-platform release pipeline (macOS x86_64+arm64, Linux x86_64+arm64,
  Windows x86_64) via GitHub Actions matrix + SHA256SUMS.txt.

[0.1.5]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.5
[0.1.4]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.4
[0.1.3]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.3
[0.1.2]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.2
[0.1.1]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.0
