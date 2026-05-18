# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

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
  Claude Code / Cursor / Windsurf can route through the same gate.
- **SQLite verdict cache** at `~/.cache/npmguard/verdicts.db` keyed by signal
  set hash — present in v0.1.0 but the read path is wired in v0.1.1.
- Cross-platform release pipeline (macOS x86_64+arm64, Linux x86_64+arm64,
  Windows x86_64) via GitHub Actions matrix + SHA256SUMS.txt.

[0.1.2]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.2
[0.1.1]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.0
